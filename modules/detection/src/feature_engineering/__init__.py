"""Contract boundary for future causal behavioural feature engineering.

Only :class:`FeatureWindow` is exposed in Phase 1.  Window construction, state,
watermarks, and attack-specific features belong to a later approved phase; this
prevents premature logic from bypassing the versioned and traceable contract.
"""
from modules.detection.src.schemas import FeatureWindow

__all__ = ["FeatureWindow"]
