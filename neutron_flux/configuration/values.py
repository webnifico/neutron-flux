from __future__ import annotations

import math
from typing import Any

from ..errors import SuiteError


def pacing_scale(value: Any, key: str) -> float:
    """Validate both operator input and restored execution settings."""
    if value is None:
        return 1.0
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise SuiteError(f"{key} must be a finite number between 0 and 10") from exc
    if isinstance(value, bool) or not math.isfinite(number) or not 0 <= number <= 10:
        raise SuiteError(f"{key} must be a finite number between 0 and 10")
    return number
