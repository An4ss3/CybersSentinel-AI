"""M4 canonical event persistence boundary.

M4 persists the canonical events that frozen M3 v2 hashed and discarded. This
package never modifies, reopens, or regenerates any M3 v2 file or artifact; it
reuses the frozen M3 v2 contracts and private helpers by import only.

Module set:
- ``schema_v2.sql``            dedicated ``m4_canonical`` PostgreSQL schema DDL
- ``report_verification_v2``   seven-point frozen M3 v2 report verification gate
- ``run_report_v2``            M4 materialization report contract
- ``db``                       PostgreSQL connection helper (Phase 2)
- ``materialization_v2``       canonical event + rejection materialization adapter (Phase 2)
- ``report_publication_v2``    M4 report builder + immutable publisher (Phase 3)
"""
from .db import ensure_m4_schema, get_connection, pg_settings
from .materialization_v2 import (
    M4DuplicateVerifiedRunError,
    M4MaterializationError,
    MaterializationOutcome,
    ZeekConnMaterializationAdapterV2,
)
from .report_publication_v2 import (
    CANONICAL_M4_V2_REPORT_RELATIVE_PATH,
    M4ReportBuildError,
    build_materialization_report_v2,
    derive_verification_status,
    write_immutable_materialization_report_v2,
)
from .report_verification_v2 import (
    FROZEN_M3_V2_IDENTITY,
    M3ReportVerificationError,
    VerifiedM3Report,
    verify_frozen_m3_v2_report,
)
from .run_report_v2 import (
    M4MaterializationReportV2,
    M4PartitionMaterializationCountsV2,
)

__all__ = [
    "CANONICAL_M4_V2_REPORT_RELATIVE_PATH",
    "FROZEN_M3_V2_IDENTITY",
    "M3ReportVerificationError",
    "M4DuplicateVerifiedRunError",
    "M4MaterializationError",
    "M4MaterializationReportV2",
    "M4PartitionMaterializationCountsV2",
    "M4ReportBuildError",
    "MaterializationOutcome",
    "VerifiedM3Report",
    "ZeekConnMaterializationAdapterV2",
    "build_materialization_report_v2",
    "derive_verification_status",
    "ensure_m4_schema",
    "get_connection",
    "pg_settings",
    "verify_frozen_m3_v2_report",
    "write_immutable_materialization_report_v2",
]
