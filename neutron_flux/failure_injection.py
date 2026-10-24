from __future__ import annotations

from .config import Config
from .errors import SuiteError


def inject_failure(config: Config, point: str) -> None:
    """Raise a deterministic test-only failure at a named execution point.

    The setting is available only through ``testing.failure_injection`` in the
    optional configuration file. A comma-separated list is accepted so live
    certification can exercise several independent cleanup paths without adding
    operational CLI flags.
    """
    configured = {
        item.strip()
        for item in str(config.failure_injection or "").split(",")
        if item.strip()
    }
    if point in configured or "*" in configured:
        raise SuiteError(f"Injected failure at {point}")
