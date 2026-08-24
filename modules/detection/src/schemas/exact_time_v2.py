"""Exact fixed-scale temporal primitives for M3 v2.

Canonical values are nonnegative DECIMAL(38,22) seconds serialized as strings
with exactly 22 fractional digits. Arithmetic uses unscaled integers only.
"""
from __future__ import annotations

from decimal import Decimal
from typing import Annotated, TypeAlias

from pydantic import StringConstraints


DECIMAL_PRECISION = 38
DECIMAL_SCALE = 22
UNSCALED_FACTOR = 10**DECIMAL_SCALE
MAX_UNSCALED = 10**DECIMAL_PRECISION - 1
MAX_INTEGER_DIGITS = DECIMAL_PRECISION - DECIMAL_SCALE

ExactDecimalSeconds22: TypeAlias = Annotated[
    str,
    StringConstraints(
        pattern=r"^(0|[1-9][0-9]{0,15})\.[0-9]{22}$",
        min_length=24,
        max_length=39,
    ),
]


class ExactDecimalConversionError(ValueError):
    """A value cannot be represented exactly as nonnegative DECIMAL(38,22)."""


def decimal_to_unscaled(value: Decimal | int) -> int:
    """Convert without rounding, truncation, float use, or Decimal arithmetic."""
    if type(value) is int:
        if value < 0 or value >= 10**MAX_INTEGER_DIGITS:
            raise ExactDecimalConversionError("integer seconds exceed DECIMAL(38,22)")
        return value * UNSCALED_FACTOR
    if type(value) is not Decimal:
        raise ExactDecimalConversionError("value must be an exact Decimal or integer")
    if not value.is_finite():
        raise ExactDecimalConversionError("value must be finite")
    sign, digits, exponent = value.as_tuple()
    if sign:
        raise ExactDecimalConversionError("value must be nonnegative")
    coefficient = 0
    for digit in digits:
        coefficient = coefficient * 10 + digit
    if coefficient == 0:
        return 0
    scaled_exponent = exponent + DECIMAL_SCALE
    if scaled_exponent >= 0:
        if len(digits) + scaled_exponent > DECIMAL_PRECISION:
            raise ExactDecimalConversionError("value exceeds DECIMAL(38,22) precision")
        unscaled = coefficient * (10**scaled_exponent)
    else:
        divisor_digits = -scaled_exponent
        if divisor_digits > len(digits):
            raise ExactDecimalConversionError("value has nonzero precision beyond scale 22")
        divisor = 10**divisor_digits
        if coefficient % divisor:
            raise ExactDecimalConversionError("value has nonzero precision beyond scale 22")
        unscaled = coefficient // divisor
    if unscaled > MAX_UNSCALED:
        raise ExactDecimalConversionError("value exceeds DECIMAL(38,22) precision")
    return unscaled


def canonical_seconds_from_unscaled(value: int) -> ExactDecimalSeconds22:
    """Serialize one valid unscaled integer with exactly 22 fractional digits."""
    if type(value) is not int or value < 0 or value > MAX_UNSCALED:
        raise ExactDecimalConversionError("unscaled value is outside DECIMAL(38,22)")
    whole, fractional = divmod(value, UNSCALED_FACTOR)
    return f"{whole}.{fractional:022d}"


def canonical_seconds(value: Decimal | int) -> ExactDecimalSeconds22:
    """Convert an exact source number to canonical fixed-scale text."""
    return canonical_seconds_from_unscaled(decimal_to_unscaled(value))


def unscaled_from_canonical(value: ExactDecimalSeconds22) -> int:
    """Parse canonical fixed-scale text using integer operations only."""
    whole, fractional = value.split(".", 1)
    return int(whole) * UNSCALED_FACTOR + int(fractional)
