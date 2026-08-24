"""Strict primitives shared by every CyberSentinel canonical data contract.

This module centralizes validation so ingestion, offline dataset construction, and
future streaming inference cannot silently diverge.  Step 1 found permissive
numeric coercion, silent zero filling, and missing schema checks; the strict base
below deliberately rejects those conditions instead of repairing data invisibly.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    IPvAnyAddress,
    StringConstraints,
)


_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$"
_VERSION_PATTERN = r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"

StrictIdentifier = Annotated[
    str,
    StringConstraints(min_length=1, max_length=128, pattern=_IDENTIFIER_PATTERN),
]
NonEmptyText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=2048, pattern=r".*\S.*"),
]
VersionString = Annotated[
    str,
    StringConstraints(min_length=5, max_length=32, pattern=_VERSION_PATTERN),
]
NonNegativeInt = Annotated[int, Field(ge=0)]
PositiveInt = Annotated[int, Field(gt=0)]
PortNumber = Annotated[int, Field(ge=0, le=65535)]


def _require_ip_representation(
    value: str | IPv4Address | IPv6Address,
) -> str | IPv4Address | IPv6Address:
    """Allow canonical text or typed addresses, never integer IP coercion."""
    if not isinstance(value, (str, IPv4Address, IPv6Address)):
        raise ValueError("IP address must be a string or IPv4Address/IPv6Address")
    return value


StrictIpAddress = Annotated[
    IPvAnyAddress,
    BeforeValidator(_require_ip_representation),
]

Probability = Annotated[float, Field(ge=0.0, le=1.0, allow_inf_nan=False)]
FiniteFloat = Annotated[float, Field(allow_inf_nan=False)]


def _require_utc(value: datetime) -> datetime:
    """Reject naive or non-UTC timestamps without silently converting them."""
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("timestamp must be timezone-aware UTC")
    return value


UtcDateTime = Annotated[datetime, AfterValidator(_require_utc)]


class StrictModel(BaseModel):
    """Immutable base that rejects coercion, unknown fields, and non-finite data."""

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        validate_default=True,
        revalidate_instances="always",
        allow_inf_nan=False,
        protected_namespaces=(),
    )
