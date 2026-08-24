"""Canonical normalization package boundary.

The stable package export is the abstract EventNormalizer.  Concrete
implementations (M3 v1 normalizer/runner and M3 v2 normalizer/runner) live
in private submodules and are not publicly exported from this package.
"""
from .base import EventNormalizer

__all__ = ["EventNormalizer"]
