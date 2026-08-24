"""Preserved M3 v1 abstract conn.log-to-FlowEnd normalization boundary.

The concrete v1 implementation remains in a private submodule.  This v1-typed
interface is not the unimplemented M3 v2 FlowEndV2 normalization boundary.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from modules.detection.src.ingestion.adapters import RawSensorRecord
from modules.detection.src.schemas import FlowEnd
from modules.detection.src.schemas.zeek_normalization import (
    ZeekNormalizationContext,
    ZeekNormalizationSpecification,
)


class ZeekConnFlowEndNormalizer(ABC):
    """Normalize one v1 protocol-accepted conn record."""

    @abstractmethod
    def normalize_conn(
        self,
        record: RawSensorRecord,
        context: ZeekNormalizationContext,
        specification: ZeekNormalizationSpecification,
    ) -> FlowEnd:
        """Return one validated FlowEnd or raise an explicit rejection."""
