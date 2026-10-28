"""Read older release vocabulary without changing cloud-operation safety."""

from __future__ import annotations

import pathlib
import re
from typing import Any

from .errors import SuiteError

# Disk identities remain interoperable with an older process during an upgrade.
LEGACY_JOURNAL = "mutations.jsonl"
JOURNAL = "cloud-operations.jsonl"
_LEGACY_LOCK_PREFIX = "mutation-"
_FIELD_ALIASES = {
    "mutations": "cloud_operations",
    "mutation": "cloud_operation",
    "mutation_gap_scale": "operation_gap_scale",
    "pacing.mutation_gap_scale": "pacing.operation_gap_scale",
    "mutation_outcome": "cloud_operation_outcome",
    "mutation_performed": "cloud_operation_performed",
    "lifecycle_mutation_performed": "lifecycle_cloud_operation_performed",
    "unresolved_mutations": "unresolved_cloud_operations",
}


def canonical_operation_fields(value: Any, *, share_unchanged: bool = False) -> Any:
    """Translate known field names; retain IDs, evidence values and commands."""
    if isinstance(value, list):
        converted_rows = [
            canonical_operation_fields(item, share_unchanged=share_unchanged)
            for item in value
        ]
        if share_unchanged and all(
            a is b for a, b in zip(value, converted_rows, strict=True)
        ):
            return value
        return converted_rows
    if not isinstance(value, dict):
        return value
    for old, new in _FIELD_ALIASES.items():
        if old in value and new in value:
            raise SuiteError(f"Conflicting legacy and current fields: {old}, {new}")
    converted = {
        _FIELD_ALIASES.get(key, key): canonical_operation_fields(
            item, share_unchanged=share_unchanged
        )
        for key, item in value.items()
    }
    if (
        share_unchanged
        and value.keys() == converted.keys()
        and all(value[key] is item for key, item in converted.items())
    ):
        return value
    return converted


def normalize_operation_record(record: dict[str, Any]) -> dict[str, Any]:
    """Canonicalize control fields while retaining recorded identity/evidence."""
    output = dict(record)
    if output.get("kind") == "router-mutation":
        output["kind"] = "router-cloud-operation"
    conflicts = output.get("conflicts")
    if isinstance(conflicts, (list, tuple)):
        output["conflicts"] = [
            "all-cloud-operations" if item == "all-dataplane-mutations" else item
            for item in conflicts
        ]
    return output


def operation_journal_path(run_dir: pathlib.Path) -> pathlib.Path:
    """Append to the original journal on recovery; never fork its history."""
    current, legacy = run_dir / JOURNAL, run_dir / LEGACY_JOURNAL
    if run_dir.is_symlink() or current.is_symlink() or legacy.is_symlink():
        raise SuiteError(
            f"Cloud operation journal must not be a symbolic link: {run_dir}"
        )
    if current.exists() and legacy.exists():
        raise SuiteError(f"Multiple cloud operation journals in one run: {run_dir}")
    return legacy if legacy.exists() else current


def operation_journal_paths(runs_dir: pathlib.Path) -> list[pathlib.Path]:
    directories = {
        path.parent
        for name in (JOURNAL, LEGACY_JOURNAL)
        for path in runs_dir.glob(f"*/{name}")
    }
    return [operation_journal_path(directory) for directory in sorted(directories)]


def scope_lock_filename(scope: str) -> str:
    # A new name would allow simultaneous old/new processes in the same cloud.
    return f"{_LEGACY_LOCK_PREFIX}{scope}.lock"


def operation_display_text(value: str) -> str:
    """Update prose in historical views without rewriting IDs or evidence files."""
    return re.sub(
        r"(?<![\w-])mutations?(?![\w-])",
        lambda match: (
            ("Cloud operation" if match[0][0].isupper() else "cloud operation")
            + ("s" if match[0].lower().endswith("s") else "")
        ),
        value,
        flags=re.IGNORECASE,
    )


def canonical_operation_event_type(value: str) -> str:
    """Retain historical transactions in the rendered lifecycle timeline."""
    return {
        "mutation-transaction-start": "cloud-operation-transaction-start",
        "mutation-transaction-finish": "cloud-operation-transaction-finish",
    }.get(value, value)


def canonical_operation_descriptions(supplied: Any, generated: Any) -> Any:
    """Accept renamed prose only when it exactly matches the generated contract."""
    if isinstance(supplied, dict) and isinstance(generated, dict):
        output = dict(supplied)
        for key, value in supplied.items():
            expected = generated.get(key)
            if (
                key == "description"
                and isinstance(value, str)
                and isinstance(expected, str)
            ):
                if operation_display_text(value) == expected:
                    output[key] = expected
            elif key in generated:
                output[key] = canonical_operation_descriptions(value, expected)
        return output
    if (
        isinstance(supplied, list)
        and isinstance(generated, list)
        and len(supplied) == len(generated)
    ):
        return [
            canonical_operation_descriptions(a, b)
            for a, b in zip(supplied, generated, strict=True)
        ]
    return supplied
