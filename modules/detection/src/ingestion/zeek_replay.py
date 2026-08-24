"""One-shot deterministic Zeek PCAP replay for M2.

The runner consumes the frozen M2 specification, executes only the opt-in
``zeek-replay`` Compose service, validates sensor logs without parsing them into
canonical events, and atomically publishes immutable per-PCAP output.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
from typing import TypeAlias

from modules.detection.src.lineage import (
    BoundZeekReplaySpecification,
    bind_zeek_replay_specification,
    load_dataset_freeze_manifest,
    load_zeek_replay_specification,
)
from modules.detection.src.schemas import (
    PcapEvidenceFile,
    ZeekLogArtifact,
    ZeekReplayRunReport,
)


CommandExecutor: TypeAlias = Callable[
    [tuple[str, ...], Path],
    subprocess.CompletedProcess[str],
]


class ZeekReplayError(RuntimeError):
    """Raised when replay cannot produce a validated immutable partition."""


def _default_executor(
    command: tuple[str, ...],
    cwd: Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


def _sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_report(report: ZeekReplayRunReport, path: Path) -> None:
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


def _partition_name(evidence: PcapEvidenceFile) -> str:
    stem = PurePosixPath(evidence.relative_path).stem
    return f"{evidence.capture_date.isoformat()}_{stem}"


@dataclass(frozen=True, slots=True)
class ZeekReplayRunner:
    """Execute one selected PCAP under a bound immutable replay specification."""

    repository_root: Path
    bound: BoundZeekReplaySpecification
    compose_file: Path
    executor: CommandExecutor = _default_executor

    @classmethod
    def from_repository(
        cls,
        repository_root: str | Path,
        specification_path: str | Path = "datasets/manifests/cicids2017_zeek_replay.yaml",
        *,
        executor: CommandExecutor = _default_executor,
    ) -> "ZeekReplayRunner":
        root = Path(repository_root).resolve(strict=True)
        specification = load_zeek_replay_specification(root / specification_path)
        manifest = load_dataset_freeze_manifest(
            root / specification.m1_manifest_path
        )
        bound = bind_zeek_replay_specification(specification, manifest)
        compose_file = root / "docker-compose.yml"
        if not compose_file.is_file():
            raise FileNotFoundError(f"Compose file not found: {compose_file}")
        return cls(root, bound, compose_file, executor)

    def _evidence(self, relative_path: str) -> PcapEvidenceFile:
        matches = tuple(
            item
            for item in self.bound.specification.inputs
            if item.relative_path == relative_path
        )
        if len(matches) != 1:
            raise ZeekReplayError(
                f"PCAP is not selected by the replay specification: {relative_path}"
            )
        return matches[0]

    def _verify_input(self, evidence: PcapEvidenceFile) -> Path:
        path = self.repository_root / "datasets" / "cicids2017" / "pcap"
        path = path.joinpath(*PurePosixPath(evidence.relative_path).parts)
        if not path.is_file() or path.is_symlink():
            raise ZeekReplayError(f"selected PCAP is not a regular file: {path}")
        if path.stat().st_size != evidence.size_bytes:
            raise ZeekReplayError(f"selected PCAP size does not match M1: {path}")
        if _sha256_file(path) != evidence.sha256:
            raise ZeekReplayError(f"selected PCAP SHA-256 does not match M1: {path}")
        return path

    def _zeek_command(self, evidence: PcapEvidenceFile) -> tuple[str, ...]:
        container_path = f"/input/{evidence.relative_path}"
        return tuple(
            container_path if item == "{pcap}" else item
            for item in self.bound.specification.determinism.command_template
        )

    def _compose_command(
        self,
        zeek_command: tuple[str, ...],
        staging_name: str,
    ) -> tuple[str, ...]:
        return (
            "docker",
            "compose",
            "--file",
            str(self.compose_file),
            "--profile",
            "zeek-replay",
            "run",
            "--rm",
            "--no-deps",
            "-T",
            "--workdir",
            f"/output/{staging_name}",
            "zeek-replay",
            *zeek_command,
        )

    def _validate_logs(self, staging: Path) -> tuple[ZeekLogArtifact, ...]:
        artifacts: list[ZeekLogArtifact] = []
        output_policy = self.bound.specification.output
        operational_names = set(output_policy.excluded_operational_logs)
        for path in sorted(staging.glob("*.log"), key=lambda item: item.name):
            if not path.is_file() or path.is_symlink():
                raise ZeekReplayError(f"invalid Zeek log artifact: {path.name}")
            record_count = 0
            with path.open("r", encoding="utf-8") as stream:
                for line_number, line in enumerate(stream, start=1):
                    if not line.strip():
                        raise ZeekReplayError(
                            f"blank JSON line in {path.name}:{line_number}"
                        )
                    try:
                        value = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise ZeekReplayError(
                            f"invalid JSON in {path.name}:{line_number}"
                        ) from exc
                    if not isinstance(value, dict):
                        raise ZeekReplayError(
                            f"non-object JSON in {path.name}:{line_number}"
                        )
                    record_count += 1
            artifacts.append(
                ZeekLogArtifact(
                    log_name=path.name,
                    classification=(
                        "operational_runtime"
                        if path.name in operational_names
                        else "canonical_telemetry"
                    ),
                    size_bytes=path.stat().st_size,
                    sha256=_sha256_file(path),
                    record_count=record_count,
                )
            )

        names = {item.log_name for item in artifacts}
        missing = set(output_policy.required_logs) - names
        if missing:
            raise ZeekReplayError(f"required Zeek logs missing: {sorted(missing)}")
        for artifact in artifacts:
            if (
                artifact.log_name in output_policy.required_logs
                and artifact.record_count == 0
            ):
                raise ZeekReplayError(
                    f"required Zeek log is empty: {artifact.log_name}"
                )
        return tuple(artifacts)

    @staticmethod
    def _retain_operational_logs(
        staging: Path,
        artifacts: tuple[ZeekLogArtifact, ...],
        directory_name: str,
    ) -> None:
        operational = tuple(
            item
            for item in artifacts
            if item.classification == "operational_runtime"
        )
        if not operational:
            return
        destination = staging / directory_name
        destination.mkdir()
        for artifact in operational:
            (staging / artifact.log_name).replace(destination / artifact.log_name)

    def replay(self, relative_path: str) -> ZeekReplayRunReport:
        """Replay one selected PCAP and atomically publish validated logs."""
        evidence = self._evidence(relative_path)
        self._verify_input(evidence)
        specification = self.bound.specification
        output_root = self.repository_root / specification.output.output_root
        partition = _partition_name(evidence)
        final = output_root / partition
        staging = output_root / f".{partition}.staging"
        if final.exists() or staging.exists():
            raise ZeekReplayError(
                f"replay output already exists for partition: {partition}"
            )

        output_root.mkdir(parents=True, exist_ok=True)
        staging.mkdir()
        zeek_command = self._zeek_command(evidence)
        compose_command = self._compose_command(zeek_command, staging.name)
        try:
            completed = self.executor(compose_command, self.repository_root)
            if completed.returncode != 0:
                raise ZeekReplayError(
                    "Zeek container failed with exit code "
                    f"{completed.returncode}: {completed.stderr.strip()}"
                )
            logs = self._validate_logs(staging)
            self._retain_operational_logs(
                staging,
                logs,
                specification.output.operational_log_directory,
            )
            report = ZeekReplayRunReport(
                report_version="1.0.0",
                verification_status="verified",
                specification_sha256=self.bound.specification_sha256,
                m1_manifest_sha256=self.bound.m1_manifest_sha256,
                input=evidence,
                runtime=specification.runtime,
                output_partition=partition,
                command=zeek_command,
                required_logs=specification.output.required_logs,
                excluded_operational_logs=(
                    specification.output.excluded_operational_logs
                ),
                operational_log_directory=(
                    specification.output.operational_log_directory
                ),
                logs=logs,
            )
            _write_report(report, staging / "replay_run.json")
            staging.rename(final)
            return report
        except BaseException:
            if staging.exists():
                shutil.rmtree(staging)
            raise
