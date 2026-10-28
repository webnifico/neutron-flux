from __future__ import annotations

import ast
import datetime as dt
import hashlib
import json
import re
from typing import Any

from .errors import SuiteError


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_utc(value: dt.datetime | None = None) -> str:
    return (
        (value or utc_now()).isoformat(timespec="microseconds").replace("+00:00", "Z")
    )


def scalar(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    text = value.strip()
    if text in {"", "None", "null", "<none>"}:
        return None
    if text.lower() in {"true", "yes"}:
        return True
    if text.lower() in {"false", "no"}:
        return False
    if re.fullmatch(r"-?\d+", text):
        try:
            return int(text)
        except ValueError:
            pass
    if text.startswith(("[", "{")):
        for parser in (json.loads, ast.literal_eval):
            try:
                candidate = text.replace("'", '"') if parser is json.loads else text
                return parser(candidate)
            except (ValueError, TypeError, SyntaxError, json.JSONDecodeError):
                continue
    return value


def normalized_map(data: dict[str, Any]) -> dict[str, Any]:
    return {
        re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_"): scalar(value)
        for key, value in data.items()
    }


def pick(data: dict[str, Any], *names: str, default: Any = None) -> Any:
    normalized = normalized_map(data)
    for name in names:
        key = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
        if key in normalized:
            return normalized[key]
    return default


def nova_task_state_cleared(data: dict[str, Any]) -> bool | None:
    """Prove Nova's task is clear without coercing malformed API values.

    JSON null and textual null markers are clear. A visible, nonempty task
    string is busy; a hidden field or any other native type is unverified.
    Normalize field names without ``scalar`` so the original value's type
    remains available for this evidence check.
    """
    fields = {
        re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_"): value
        for key, value in data.items()
    }
    for key in ("os_ext_sts_task_state", "task_state"):
        if key not in fields:
            continue
        value = fields[key]
        if value is None:
            return True
        if not isinstance(value, str):
            return None
        return value.strip().lower() in {"", "none", "null", "<none>"}
    return None


def optional_text(value: Any) -> str | None:
    """Return a normalized non-empty string, never the literal ``"None"``.

    OpenStackClient payloads are not always consistent: missing values may be
    JSON null, an empty string, or textual null markers.  Resource identifiers
    must be validated before they are tracked or passed back to OpenStack.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in {"none", "null", "<none>"}:
        return None
    return text


def required_text(
    data: dict[str, Any],
    *names: str,
    context: str,
) -> str:
    """Extract a required non-empty text field from a structured payload."""
    value = optional_text(pick(data, *names, default=None))
    if value is None:
        labels = ", ".join(names)
        raise SuiteError(f"{context} returned no usable {labels}")
    return value


def list_value(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        text = value.strip()
        if not text or text in {"None", "[]"}:
            return []
        for parser in (json.loads, ast.literal_eval):
            try:
                candidate = text.replace("'", '"') if parser is json.loads else text
                parsed = parser(candidate)
                if isinstance(parsed, list):
                    return parsed
            except (ValueError, TypeError, SyntaxError, json.JSONDecodeError):
                continue
        if text.startswith("[") and text.endswith("]"):
            text = text[1:-1]
        return [part.strip().strip("'\"") for part in text.split(",") if part.strip()]
    return [value]


def safe_name(value: str, limit: int = 63) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-.")
    return cleaned[:limit] or "unnamed"


def unique_safe_name(value: str, limit: int = 63, *, digest_length: int = 8) -> str:
    """Return a bounded readable name without truncation collisions.

    Plain ``safe_name`` intentionally truncates.  That is suitable for cosmetic
    labels, but not for parallel resource namespaces where distinguishing text
    may appear near the end of the value.  Preserve the normal spelling when it
    fits; otherwise retain a readable prefix and append a deterministic digest
    of the complete normalized value.
    """
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-.") or "unnamed"
    if len(cleaned) <= limit:
        return cleaned
    digest_length = max(4, min(digest_length, max(4, limit - 2)))
    digest = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()[:digest_length]
    prefix_length = limit - digest_length - 1
    if prefix_length <= 0:
        return digest[:limit]
    prefix = cleaned[:prefix_length].rstrip("-.") or cleaned[:prefix_length]
    return f"{prefix}-{digest}"[:limit]


def validate_run_id(value: Any, *, key: str = "run ID") -> str:
    """Validate an on-disk run namespace without silently rewriting it.

    Run IDs are used as directory names and as report identities.  Cosmetic
    sanitization is unsafe here because two different operator inputs could be
    rewritten to the same directory, while path separators would allow state
    and reports to escape the configured report root.
    """
    if isinstance(value, (dict, list, tuple, set)) or value is None:
        raise SuiteError(f"{key} must be a scalar string")
    text = str(value).strip()
    if not text:
        raise SuiteError(f"{key} must not be empty")
    if len(text) > 128:
        raise SuiteError(f"{key} must be at most 128 characters")
    if text in {".", ".."} or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", text):
        raise SuiteError(
            f"{key} may contain only letters, numbers, period, underscore, and "
            "hyphen, and must begin with a letter, number, or underscore"
        )
    return text
