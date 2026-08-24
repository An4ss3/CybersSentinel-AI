"""Public validation and versioning contracts for the IDS data foundation.

Contracts are independent of sensor parsing and model code.  Central ownership
prevents the unversioned, implicit assumptions identified in the CICIDS pipeline
from being duplicated across future ingestion, training, and serving layers.
"""
from .base import (
    FiniteFloat,
    NonEmptyText,
    NonNegativeInt,
    PortNumber,
    PositiveInt,
    Probability,
    StrictIdentifier,
    StrictIpAddress,
    StrictModel,
    UtcDateTime,
    VersionString,
)
from .versions import (
    VersionCompatibilityError,
    VersionContract,
    VersionedModel,
    compatibility_issues,
    ensure_compatible,
)

__all__ = [
    "FiniteFloat",
    "NonEmptyText",
    "NonNegativeInt",
    "PortNumber",
    "PositiveInt",
    "Probability",
    "StrictIdentifier",
    "StrictIpAddress",
    "StrictModel",
    "UtcDateTime",
    "VersionCompatibilityError",
    "VersionContract",
    "VersionString",
    "VersionedModel",
    "compatibility_issues",
    "ensure_compatible",
]
