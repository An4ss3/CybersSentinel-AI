"""Deterministic Zeek replay for TH2 (Thursday track).

This module is the TH-track counterpart of
``modules/detection/src/ingestion/monday_benign_replay.py``. It reuses the frozen
``ZeekReplayRunner`` by inheritance -- input selection, M1 integrity
verification, staging, Zeek log validation, operational-log retention, and atomic
publication are inherited unchanged -- and overrides exactly two things:

1. ``_compose_command``, so the Compose **service and profile are always**
   ``zeek-replay-th``, never the frozen ``zeek-replay`` (M2) or
   ``zeek-replay-mb`` (MB2) services;
2. ``from_repository``, so the runner is bound to the TH2 specification and
   refuses to start unless the Compose pairing is proven.

``_verify_compose_pairing`` parses ``docker-compose.yml`` and proves that the
``zeek-replay-th`` service declares its own profile and binds its ``/output`` to
the very directory the TH2 specification declares as ``output.output_root``. The
base runner computes the staging path from the specification, not from the
Compose file, so an unverified pairing could silently write Zeek logs into the
frozen M2 or MB2 tree. This check makes that impossible.

Nothing in M2, MB2 or their specifications is read for mutation or written. The
Thursday PCAP is opened in binary read mode only, by the inherited integrity
check.
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any, Final

import yaml

from modules.detection.src.ingestion.zeek_replay import (
    CommandExecutor,
    ZeekReplayRunner,
    _default_executor,
)
from modules.detection.src.lineage import (
    bind_zeek_replay_specification,
    load_dataset_freeze_manifest,
    load_zeek_replay_specification,
)


#: The TH2 Compose service and profile. Never the M2 or MB2 ones.
TH2_COMPOSE_SERVICE: Final[str] = "zeek-replay-th"
TH2_COMPOSE_PROFILE: Final[str] = "zeek-replay-th"

#: Frozen services this runner must never invoke.
FORBIDDEN_COMPOSE_SERVICES: Final[frozenset[str]] = frozenset(
    {"zeek-replay", "zeek-replay-mb"}
)

TH2_SPECIFICATION_RELATIVE_PATH: Final[str] = (
    "datasets/manifests/thursday_zeek_replay.yaml"
)
TH2_OUTPUT_ROOT: Final[str] = "artifacts/canonical/cicids2017/th2/zeek-8.0.9"

#: Output roots that belong to frozen tracks and must never receive TH logs.
FROZEN_OUTPUT_ROOTS: Final[frozenset[str]] = frozenset(
    {
        "artifacts/canonical/cicids2017/m2/zeek-8.0.9",
        "artifacts/canonical/cicids2017/mb2/zeek-8.0.9",
    }
)

THURSDAY_PCAP_RELATIVE_PATH: Final[str] = "Thursday-WorkingHours.pcap"


class ThursdayReplayError(RuntimeError):
    """Raised when the TH2 replay cannot be proven correctly paired."""


def _normalize_compose_host_path(value: str) -> str:
    """Return a repository-relative POSIX path for a Compose bind source."""
    text = value.strip()
    if text.startswith("./"):
        text = text[2:]
    return PurePosixPath(text.replace("\\", "/")).as_posix().rstrip("/")


def _compose_output_bind(service: dict[str, Any]) -> str:
    """Return the repository-relative host path bound to ``/output``."""
    volumes = service.get("volumes")
    if not isinstance(volumes, list):
        raise ThursdayReplayError(
            f"{TH2_COMPOSE_SERVICE} declares no volume list"
        )
    for entry in volumes:
        if isinstance(entry, str):
            parts = entry.split(":")
            if len(parts) >= 2 and parts[1] == "/output":
                return _normalize_compose_host_path(parts[0])
        elif isinstance(entry, dict):
            if entry.get("target") == "/output":
                return _normalize_compose_host_path(str(entry.get("source", "")))
    raise ThursdayReplayError(
        f"{TH2_COMPOSE_SERVICE} binds no host directory to /output"
    )


class ThursdayReplayRunner(ZeekReplayRunner):
    """Execute the Thursday capture through the isolated TH2 Compose service."""

    @classmethod
    def from_repository(  # type: ignore[override]
        cls,
        repository_root: str | Path,
        specification_path: str | Path = TH2_SPECIFICATION_RELATIVE_PATH,
        *,
        executor: CommandExecutor = _default_executor,
    ) -> "ThursdayReplayRunner":
        """Bind the TH2 specification and prove the Compose pairing."""
        root = Path(repository_root).resolve(strict=True)
        specification = load_zeek_replay_specification(root / specification_path)

        declared_root = specification.output.output_root
        if declared_root in FROZEN_OUTPUT_ROOTS:
            raise ThursdayReplayError(
                "TH2 specification points at a frozen output root: "
                f"{declared_root}"
            )
        if declared_root != TH2_OUTPUT_ROOT:
            raise ThursdayReplayError(
                f"TH2 output_root must be {TH2_OUTPUT_ROOT}, got {declared_root}"
            )

        manifest = load_dataset_freeze_manifest(root / specification.m1_manifest_path)
        bound = bind_zeek_replay_specification(specification, manifest)

        compose_file = root / "docker-compose.yml"
        if not compose_file.is_file():
            raise FileNotFoundError(f"Compose file not found: {compose_file}")
        runner = cls(root, bound, compose_file, executor)
        runner._verify_compose_pairing()
        return runner

    def _verify_compose_pairing(self) -> None:
        """Prove the TH service exists, is profile-gated, and targets TH2."""
        try:
            document = yaml.safe_load(self.compose_file.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ThursdayReplayError(
                f"TH2 cannot parse the Compose file: {self.compose_file}"
            ) from exc
        if not isinstance(document, dict):
            raise ThursdayReplayError("Compose document root must be a mapping")

        services = document.get("services")
        if not isinstance(services, dict) or TH2_COMPOSE_SERVICE not in services:
            raise ThursdayReplayError(
                f"Compose file declares no {TH2_COMPOSE_SERVICE} service"
            )
        service = services[TH2_COMPOSE_SERVICE]
        if not isinstance(service, dict):
            raise ThursdayReplayError(
                f"{TH2_COMPOSE_SERVICE} service definition must be a mapping"
            )

        profiles = service.get("profiles") or ()
        if TH2_COMPOSE_PROFILE not in tuple(profiles):
            raise ThursdayReplayError(
                f"{TH2_COMPOSE_SERVICE} must declare profile "
                f"{TH2_COMPOSE_PROFILE!r} so an ordinary 'up' never starts it"
            )

        image = str(service.get("image", ""))
        expected_digest = self.bound.specification.runtime.image_index_digest
        if expected_digest not in image:
            raise ThursdayReplayError(
                f"{TH2_COMPOSE_SERVICE} image is not pinned to the ratified "
                f"digest {expected_digest}"
            )

        bound_output = _compose_output_bind(service)
        declared_output = self.bound.specification.output.output_root
        if bound_output != declared_output:
            raise ThursdayReplayError(
                f"{TH2_COMPOSE_SERVICE} binds /output to {bound_output!r} but the "
                f"TH2 specification declares {declared_output!r}"
            )
        if bound_output in FROZEN_OUTPUT_ROOTS:
            raise ThursdayReplayError(
                f"{TH2_COMPOSE_SERVICE} would write into a frozen tree: "
                f"{bound_output}"
            )

    def _compose_command(
        self,
        zeek_command: tuple[str, ...],
        staging_name: str,
    ) -> tuple[str, ...]:
        """Return the Compose command, always bound to the TH2 service."""
        if TH2_COMPOSE_SERVICE in FORBIDDEN_COMPOSE_SERVICES:
            raise ThursdayReplayError("TH2 service name collides with a frozen one")
        return (
            "docker",
            "compose",
            "--file",
            str(self.compose_file),
            "--profile",
            TH2_COMPOSE_PROFILE,
            "run",
            "--rm",
            "--no-deps",
            "-T",
            "--workdir",
            f"/output/{staging_name}",
            TH2_COMPOSE_SERVICE,
            *zeek_command,
        )


def replay_thursday(
    repository_root: str | Path,
    *,
    specification_path: str | Path = TH2_SPECIFICATION_RELATIVE_PATH,
    executor: CommandExecutor = _default_executor,
) -> Any:
    """Replay the single Thursday capture and return the published run report."""
    runner = ThursdayReplayRunner.from_repository(
        repository_root,
        specification_path,
        executor=executor,
    )
    return runner.replay(THURSDAY_PCAP_RELATIVE_PATH)


__all__ = [
    "TH2_COMPOSE_PROFILE",
    "TH2_COMPOSE_SERVICE",
    "TH2_OUTPUT_ROOT",
    "TH2_SPECIFICATION_RELATIVE_PATH",
    "ThursdayReplayError",
    "ThursdayReplayRunner",
    "replay_thursday",
]
