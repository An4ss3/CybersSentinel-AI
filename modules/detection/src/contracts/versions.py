"""Version contracts for canonical events and feature windows.

Schema, event, and feature contracts use conservative semantic compatibility:
a consumer may read an older or equal minor version within the same major
version.  Sensor versions require exact equality because extractor bug fixes or
configuration changes can alter observed values and create train/serve skew.
"""
from __future__ import annotations

from dataclasses import dataclass

from .base import StrictModel, VersionString


class VersionContract(StrictModel):
    """The four mandatory versions carried by every canonical payload."""

    schema_version: VersionString
    event_version: VersionString
    feature_version: VersionString
    sensor_version: VersionString


class VersionedModel(StrictModel):
    """Base for payloads whose version fields must be present at the top level."""

    schema_version: VersionString
    event_version: VersionString
    feature_version: VersionString
    sensor_version: VersionString

    def version_contract(self) -> VersionContract:
        """Return the payload versions as a standalone compatibility contract."""
        return VersionContract(
            schema_version=self.schema_version,
            event_version=self.event_version,
            feature_version=self.feature_version,
            sensor_version=self.sensor_version,
        )


@dataclass(frozen=True, slots=True)
class VersionCompatibilityError(ValueError):
    """Raised when a producer payload is unsafe for a declared consumer."""

    incompatibilities: tuple[str, ...]

    def __str__(self) -> str:
        return "incompatible version contract: " + "; ".join(self.incompatibilities)


def _parts(version: str) -> tuple[int, int, int]:
    return tuple(int(part) for part in version.split("."))  # type: ignore[return-value]


def _is_backward_compatible(produced: str, supported: str) -> bool:
    produced_major, produced_minor, _ = _parts(produced)
    supported_major, supported_minor, _ = _parts(supported)
    return produced_major == supported_major and produced_minor <= supported_minor


def compatibility_issues(
    produced: VersionContract,
    supported: VersionContract,
) -> tuple[str, ...]:
    """Return deterministic reasons a producer contract cannot be consumed.

    Patch differences are compatible for schema/event/feature contracts because
    patches may not change their public structure. Sensor versions remain exact.
    """
    issues: list[str] = []
    for field_name in ("schema_version", "event_version", "feature_version"):
        actual = getattr(produced, field_name)
        expected = getattr(supported, field_name)
        if not _is_backward_compatible(actual, expected):
            issues.append(f"{field_name} produced={actual} supported={expected}")

    if produced.sensor_version != supported.sensor_version:
        issues.append(
            "sensor_version requires exact match "
            f"produced={produced.sensor_version} supported={supported.sensor_version}"
        )
    return tuple(issues)


def ensure_compatible(
    produced: VersionContract,
    supported: VersionContract,
) -> None:
    """Raise :class:`VersionCompatibilityError` for an unsafe contract."""
    issues = compatibility_issues(produced, supported)
    if issues:
        raise VersionCompatibilityError(issues)
