"""Preserve resolved execution settings across immutable plans and resume."""

from __future__ import annotations

import copy
import dataclasses
from typing import TYPE_CHECKING, Any

from ..errors import SuiteError
from ..operation_compat import canonical_operation_fields

if TYPE_CHECKING:
    from ..config import Config

# These identify the current invocation or its output rather than the workload.
# Reporting flags remain overridable when executing an approved/resumed plan.
_INVOCATION_FIELDS = {
    "action",
    "keep_resources",
    "auto_cleanup_on_failure",
    "repeat_index",
    "repeat_root_id",
    "repeat_next_id",
    "repeat_exit_code",
    "prefix",
    "report_dir",
    "config_path",  # Ignored provenance from retired file-based input.
    "config_overrides",
    "volume_size_configured",
    "manifest",
    "selected_run_id",
    "approved_plan_path",
    "resume_run_id",
    "list_tests",
    "input_sources",
    "config_warnings",
    "cleanup_orphans",
    "cleanup_dry_run",
    "cleanup_assume_yes",
    "cleanup_include_active",
    "orphan_grace_minutes",
    "html_report_enabled",
    "junit_report_enabled",
    "evidence_enabled",
}


def execution_settings(config: Config) -> dict[str, Any]:
    return {
        field.name: copy.deepcopy(getattr(config, field.name))
        for field in dataclasses.fields(config)
        if field.name not in _INVOCATION_FIELDS
    }


def restore_execution_settings(config: Config, snapshot: Any) -> None:
    # Earlier release plans lack this section and retain their legacy hydration.
    if snapshot is None:
        return
    if not isinstance(snapshot, dict):
        raise SuiteError("Immutable execution_settings must be a mapping")
    snapshot = canonical_operation_fields(snapshot)
    unknown = set(snapshot) - set(execution_settings(config)) - _INVOCATION_FIELDS
    if unknown:
        raise SuiteError(
            "Unknown immutable execution setting(s): " + ", ".join(sorted(unknown))
        )
    for key, value in snapshot.items():
        if key in _INVOCATION_FIELDS:
            continue
        if key == "target_host_pairs":
            value = [tuple(pair) for pair in value]
        setattr(config, key, copy.deepcopy(value))


def validate_saved_execution(snapshot: dict[str, Any]) -> None:
    """Reject retired execution contracts instead of resuming with new semantics."""
    if str(snapshot.get("access_mode") or "admin").strip().lower() != "admin":
        raise SuiteError(
            "This saved run uses a retired project execution contract. "
            "Start a new run with administrator credentials; cleanup remains available."
        )
