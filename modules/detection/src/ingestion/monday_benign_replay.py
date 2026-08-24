"""One-shot deterministic Zeek PCAP replay for MB2 (Monday Benign).

The MB2 runner reuses the generic, already-verified parts of the frozen M2
runner by inheritance -- input selection, input integrity verification, staging,
Zeek log validation, operational-log retention, and atomic publication -- and
replaces only two things:

1. ``_compose_command``, so the Compose **service and profile are always**
   ``zeek-replay-mb`` and the frozen M2 service can never be invoked;
2. ``replay``, so the published artifact is a ``MondayBenignReplayRunReport``
   carrying MB coordinates and the Compose service actually used.

It additionally adds an enforcement that does not exist in the M2 runner:
``_verify_compose_pairing`` parses ``docker-compose.yml`` and proves that the
container's ``/output`` bind mount resolves to the same MB2 tree that the host
staging directory lives in. Before this, the specification-to-service pairing
was documented in a Compose comment but unenforced (index risk R10); a mismatch
would have made Zeek write logs into the wrong tree.

``modules/detection/src/ingestion/zeek_replay.py`` is imported and subclassed,
never modified. No M chain artifact is read, written, or re-identified.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path, PurePosixPath
import shutil
from typing import Any, Final

import yaml

from modules.detection.src.ingestion.zeek_replay import (
    CommandExecutor,
    ZeekReplayError,
    ZeekReplayRunner,
    _default_executor,
)
from modules.detection.src.lineage.monday_benign_replay import (
    BoundMondayBenignReplaySpecification,
    bind_monday_benign_replay_specification,
    load_monday_benign_replay_specification,
)
from modules.detection.src.lineage.dataset_freeze import load_dataset_freeze_manifest
from modules.detection.src.schemas.monday_benign_replay import (
    M2_COMPOSE_SERVICE,
    M2_FROZEN_OUTPUT_ROOT,
    MB2_COMPOSE_PROFILE,
    MB2_COMPOSE_SERVICE,
    MB2_OUTPUT_ROOT,
    MB2_SPECIFICATION_RELATIVE_PATH,
    MONDAY_OUTPUT_PARTITION,
    MondayBenignReplayRunReport,
    monday_partition_name,
)


MB2_REPORT_FILE_NAME: Final[str] = "replay_run.json"
MB2_REPORT_VERSION: Final[str] = "1.0.0"


class MondayBenignReplayError(ZeekReplayError):
    """Raised when MB2 replay cannot produce a validated immutable partition."""


def _normalize_compose_host_path(value: str) -> str:
    """Return a repository-relative POSIX path for a Compose bind source."""
    text = value.replace("\\", "/").strip()
    while text.startswith("./"):
        text = text[2:]
    return text.rstrip("/")


def _compose_bind_mounts(service: dict[str, Any]) -> tuple[tuple[str, str, bool], ...]:
    """Return ``(host_path, container_target, read_only)`` for each bind mount."""
    mounts: list[tuple[str, str, bool]] = []
    for entry in service.get("volumes", ()) or ():
        if isinstance(entry, str):
            parts = entry.split(":")
            if len(parts) < 2:
                continue
            # Windows sources such as C:/x are not used by this repository, but
            # guard against a drive letter being mistaken for a separator.
            if len(parts[0]) == 1 and len(parts) >= 3:
                host, target = f"{parts[0]}:{parts[1]}", parts[2]
                flags = parts[3:]
            else:
                host, target = parts[0], parts[1]
                flags = parts[2:]
            mounts.append(
                (
                    _normalize_compose_host_path(host),
                    target.rstrip("/") or "/",
                    "ro" in flags,
                )
            )
        elif isinstance(entry, dict):
            source = entry.get("source")
            target = entry.get("target")
            if not isinstance(source, str) or not isinstance(target, str):
                continue
            mounts.append(
                (
                    _normalize_compose_host_path(source),
                    target.rstrip("/") or "/",
                    bool(entry.get("read_only", False)),
                )
            )
    return tuple(mounts)


def _write_mb2_report(report: MondayBenignReplayRunReport, path: Path) -> None:
    """Create the MB2 report exactly once, durably, and never overwrite."""
    payload = (
        json.dumps(
            report.model_dump(mode="json"),
            sort_keys=True,
            indent=2,
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")
    with path.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


class MondayBenignReplayRunner(ZeekReplayRunner):
    """Execute the Monday capture through the isolated MB2 Compose service."""

    @classmethod
    def from_repository(  # type: ignore[override]
        cls,
        repository_root: str | Path,
        specification_path: str | Path = MB2_SPECIFICATION_RELATIVE_PATH,
        *,
        executor: CommandExecutor = _default_executor,
    ) -> "MondayBenignReplayRunner":
        """Load, bind, and guard an MB2 runner rooted at one repository."""
        root = Path(repository_root).resolve(strict=True)
        specification = load_monday_benign_replay_specification(
            root / specification_path
        )
        manifest = load_dataset_freeze_manifest(root / specification.m1_manifest_path)
        bound = bind_monday_benign_replay_specification(specification, manifest)
        compose_file = root / "docker-compose.yml"
        if not compose_file.is_file():
            raise FileNotFoundError(f"Compose file not found: {compose_file}")
        runner = cls(root, bound, compose_file, executor)
        runner._verify_output_root()
        return runner

    @property
    def mb2_bound(self) -> BoundMondayBenignReplaySpecification:
        """Return the bound MB2 specification with its concrete type."""
        bound = self.bound
        if not isinstance(bound, BoundMondayBenignReplaySpecification):
            raise MondayBenignReplayError(
                "MB2 runner requires a BoundMondayBenignReplaySpecification; "
                "an M2 binding can never drive the MB2 track"
            )
        return bound

    def _verify_output_root(self) -> str:
        """Reject any specification not rooted exactly at the MB2 tree."""
        output_root = self.mb2_bound.specification.output.output_root
        if output_root == M2_FROZEN_OUTPUT_ROOT or output_root.startswith(
            M2_FROZEN_OUTPUT_ROOT.rstrip("/") + "/"
        ):
            raise MondayBenignReplayError(
                "MB2 refuses a specification whose output_root is inside the "
                f"frozen M2 tree: {output_root}"
            )
        if output_root != MB2_OUTPUT_ROOT:
            raise MondayBenignReplayError(
                f"MB2 output_root must be exactly {MB2_OUTPUT_ROOT}, "
                f"got {output_root}"
            )
        return output_root

    def _verify_compose_pairing(self) -> None:
        """Prove the MB service's /output is the MB2 tree, and /input is ro."""
        output_root = self._verify_output_root()
        try:
            document = yaml.safe_load(
                self.compose_file.read_text(encoding="utf-8")
            )
        except (OSError, yaml.YAMLError) as exc:
            raise MondayBenignReplayError(
                f"MB2 cannot parse the Compose file: {self.compose_file}"
            ) from exc
        if not isinstance(document, dict):
            raise MondayBenignReplayError("Compose document root must be a mapping")
        services = document.get("services")
        if not isinstance(services, dict) or MB2_COMPOSE_SERVICE not in services:
            raise MondayBenignReplayError(
                f"Compose file declares no {MB2_COMPOSE_SERVICE} service"
            )
        service = services[MB2_COMPOSE_SERVICE]
        if not isinstance(service, dict):
            raise MondayBenignReplayError(
                f"{MB2_COMPOSE_SERVICE} service definition must be a mapping"
            )

        profiles = service.get("profiles") or ()
        if MB2_COMPOSE_PROFILE not in tuple(profiles):
            raise MondayBenignReplayError(
                f"{MB2_COMPOSE_SERVICE} must declare profile "
                f"{MB2_COMPOSE_PROFILE}"
            )

        mounts = _compose_bind_mounts(service)
        output_mounts = tuple(item for item in mounts if item[1] == "/output")
        if len(output_mounts) != 1:
            raise MondayBenignReplayError(
                f"{MB2_COMPOSE_SERVICE} must declare exactly one /output mount"
            )
        host_output, _, output_read_only = output_mounts[0]
        if output_read_only:
            raise MondayBenignReplayError("MB2 /output mount cannot be read-only")
        if host_output == M2_FROZEN_OUTPUT_ROOT or host_output.startswith(
            M2_FROZEN_OUTPUT_ROOT.rstrip("/") + "/"
        ):
            raise MondayBenignReplayError(
                f"{MB2_COMPOSE_SERVICE} /output resolves inside the frozen M2 "
                f"tree: {host_output}"
            )
        if host_output != output_root:
            raise MondayBenignReplayError(
                "MB2 specification/service mismatch: specification output_root "
                f"is {output_root} but {MB2_COMPOSE_SERVICE} mounts "
                f"{host_output} at /output"
            )

        input_mounts = tuple(item for item in mounts if item[1] == "/input")
        if len(input_mounts) != 1:
            raise MondayBenignReplayError(
                f"{MB2_COMPOSE_SERVICE} must declare exactly one /input mount"
            )
        if not input_mounts[0][2]:
            raise MondayBenignReplayError(
                "MB2 /input mount must be read-only so the PCAP cannot be written"
            )

    def _evidence(self, relative_path: str):  # type: ignore[override]
        """Select the bound Monday capture, raising an MB-typed error."""
        try:
            return super()._evidence(relative_path)
        except MondayBenignReplayError:
            raise
        except ZeekReplayError as exc:
            raise MondayBenignReplayError(str(exc)) from exc

    def _compose_command(
        self,
        zeek_command: tuple[str, ...],
        staging_name: str,
    ) -> tuple[str, ...]:
        """Build the Compose invocation, always targeting the MB2 service."""
        command = (
            "docker",
            "compose",
            "--file",
            str(self.compose_file),
            "--profile",
            MB2_COMPOSE_PROFILE,
            "run",
            "--rm",
            "--no-deps",
            "-T",
            "--workdir",
            f"/output/{staging_name}",
            MB2_COMPOSE_SERVICE,
            *zeek_command,
        )
        if M2_COMPOSE_SERVICE in command:
            raise MondayBenignReplayError(
                "MB2 command may never reference the frozen M2 service"
            )
        return command

    def replay(  # type: ignore[override]
        self,
        relative_path: str,
    ) -> MondayBenignReplayRunReport:
        """Replay the Monday PCAP and atomically publish validated MB2 logs."""
        bound = self.mb2_bound
        specification = bound.specification
        self._verify_compose_pairing()

        evidence = self._evidence(relative_path)
        try:
            self._verify_input(evidence)
        except MondayBenignReplayError:
            raise
        except ZeekReplayError as exc:
            raise MondayBenignReplayError(str(exc)) from exc

        partition = monday_partition_name(evidence)
        if partition != MONDAY_OUTPUT_PARTITION:
            raise MondayBenignReplayError(
                f"MB2 partition must be {MONDAY_OUTPUT_PARTITION}, got {partition}"
            )

        output_root = self.repository_root / PurePosixPath(
            specification.output.output_root
        )
        final = output_root / partition
        staging = output_root / f".{partition}.staging"
        if final.exists() or staging.exists():
            raise MondayBenignReplayError(
                f"MB2 replay output already exists for partition: {partition}"
            )

        output_root.mkdir(parents=True, exist_ok=True)
        staging.mkdir()
        zeek_command = self._zeek_command(evidence)
        compose_command = self._compose_command(zeek_command, staging.name)
        started_at = datetime.now(timezone.utc)
        try:
            completed = self.executor(compose_command, self.repository_root)
            if completed.returncode != 0:
                raise MondayBenignReplayError(
                    "Zeek container failed with exit code "
                    f"{completed.returncode}: {completed.stderr.strip()}"
                )
            logs = self._validate_logs(staging)
            self._retain_operational_logs(
                staging,
                logs,
                specification.output.operational_log_directory,
            )
            report = MondayBenignReplayRunReport(
                report_version=MB2_REPORT_VERSION,
                verification_status="verified",
                track="monday_benign",
                specification_sha256=bound.specification_sha256,
                m1_manifest_sha256=bound.m1_manifest_sha256,
                input=evidence,
                runtime=specification.runtime,
                output_root=specification.output.output_root,
                output_partition=partition,
                compose_service=MB2_COMPOSE_SERVICE,
                compose_profile=MB2_COMPOSE_PROFILE,
                command=zeek_command,
                required_logs=specification.output.required_logs,
                excluded_operational_logs=(
                    specification.output.excluded_operational_logs
                ),
                operational_log_directory=(
                    specification.output.operational_log_directory
                ),
                logs=logs,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
            )
            _write_mb2_report(report, staging / MB2_REPORT_FILE_NAME)
            staging.rename(final)
            return report
        except BaseException:
            if staging.exists():
                shutil.rmtree(staging)
            raise
