from __future__ import annotations

import hashlib
import json
import os
import pathlib
from collections.abc import Mapping
from typing import Any

from .errors import CloudOperationBlockedError, SuiteError
from .results_io import append_text
from .utils import iso_utc

_SCOPE_KEYS = (
    "OS_CLOUD",
    "OS_AUTH_URL",
    "OS_PROJECT_ID",
    "OS_PROJECT_NAME",
    "OS_PROJECT_DOMAIN_ID",
    "OS_PROJECT_DOMAIN_NAME",
    "OS_REGION_NAME",
    "OS_INTERFACE",
)
_TERMINAL_RESOLUTIONS = frozenset(
    {"SUCCEEDED", "FAILED_RETRYABLE", "FAILED_FINAL", "COMMAND_REJECTED"}
)
_UNRESOLVED = frozenset({"PREPARED", "SUBMITTING", "IN_PROGRESS", "AMBIGUOUS"})


def cloud_operation_scope() -> dict[str, str]:
    """Return a non-secret identity for the OpenStack target of this process."""
    return {
        key: value.strip()
        for key in _SCOPE_KEYS
        if (value := os.getenv(key)) and value.strip()
    }


def cloud_operation_scope_fingerprint(scope: Mapping[str, str] | None = None) -> str:
    normalized = dict(
        sorted((scope if scope is not None else cloud_operation_scope()).items())
    )
    encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def append_operation_resolution(
    path: pathlib.Path,
    record: Mapping[str, Any],
    *,
    outcome: str,
    evidence: Mapping[str, Any],
    message: str,
) -> dict[str, Any]:
    normalized_outcome = str(outcome).strip().upper()
    if normalized_outcome not in _TERMINAL_RESOLUTIONS:
        raise SuiteError(
            "Cloud operation resolution must be one of: "
            + ", ".join(sorted(_TERMINAL_RESOLUTIONS))
        )
    prior = str(record.get("outcome") or "")
    if prior not in _UNRESOLVED:
        raise CloudOperationBlockedError(
            f"Cloud operation {record.get('operation_id')} is already terminal: {prior}"
        )
    resolution_message = str(message or "").strip()
    if not resolution_message:
        raise SuiteError("Cloud operation reconciliation requires a non-empty message")
    accepted: bool | None
    if normalized_outcome == "SUCCEEDED":
        accepted = True
    elif normalized_outcome == "COMMAND_REJECTED":
        accepted = False
    else:
        accepted = record.get("accepted")
    payload = {
        **dict(record),
        "schema_version": 1,
        "timestamp": iso_utc(),
        "record_type": "operation",
        "outcome": normalized_outcome,
        "accepted": accepted,
        "message": resolution_message,
        "evidence": dict(evidence),
        "reconciled_from_outcome": prior,
        "reconciled_journal": str(path),
    }
    append_text(
        path,
        json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n",
    )
    return payload


__all__ = [
    "append_operation_resolution",
    "cloud_operation_scope",
    "cloud_operation_scope_fingerprint",
]
