from __future__ import annotations

import json
import math
import os
import pathlib
import re
import tempfile
from collections import Counter
from collections.abc import Iterable
from typing import Any

from .constants import RESULT_STATUSES
from .errors import SuiteError
from .logical_results import (
    CHECK_OUTCOME_PRIORITY,
    CHECK_OUTCOME_STATUSES,
    logical_results,
    recorded_check_outcome,
)
from .operation_compat import canonical_operation_fields
from .operator_explanations import (
    explain_result,
    explanation_lines,
    lifecycle_explanations,
    needs_attention,
    operator_overview,
)
from .reporting_components.attention_summary import (
    attention_summary,
    attention_summary_lines,
)
from .reporting_components.operator_context import contextual_results
from .result_contract import normalize_result_record, typed_verdict
from .test_names import execution_name

_FINAL_STATUSES = {
    "PASS",
    "PASS WITH WARNINGS",
    "FAIL",
    "ERROR",
    "SETUP FAILED",
    "PARTIAL",
    "INTERRUPTED",
    "CANCELLED",
    "INCOMPLETE",
    "CLEANUP INCOMPLETE",
}


def atomic_write_text(path: pathlib.Path, content: str) -> pathlib.Path:
    """Replace a text artifact without following child symlinks or sharing temp names."""
    if path.parent.is_symlink():
        raise SuiteError(
            f"Output artifact parent must not be a symbolic link: {path.parent}"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise SuiteError(
            f"Output artifact parent must not be a symbolic link: {path.parent}"
        )
    if path.is_symlink():
        raise SuiteError(f"Output artifact must not be a symbolic link: {path}")
    temporary: pathlib.Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = pathlib.Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
    except OSError as exc:
        raise SuiteError(f"Could not write output artifact {path}: {exc}") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return path


def append_text(path: pathlib.Path, content: str) -> pathlib.Path:
    """Append to a journal without following a replaced child symlink."""
    if path.parent.is_symlink():
        raise SuiteError(
            f"Output journal parent must not be a symbolic link: {path.parent}"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise SuiteError(
            f"Output journal parent must not be a symbolic link: {path.parent}"
        )
    if path.is_symlink():
        raise SuiteError(f"Output journal must not be a symbolic link: {path}")
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise SuiteError(f"Could not append output journal {path}: {exc}") from exc
    return path


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON numeric constant {value!r}")


def _nonnegative_integer(value: Any, *, field: str, source: pathlib.Path) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SuiteError(
            f"Results file field {field} must be a non-negative integer: {source}"
        )
    return value


def _validate_summary(
    payload: dict[str, Any],
    *,
    source: pathlib.Path,
) -> None:
    summary = payload.get("summary")
    if summary is None:
        return
    counts = summary.get("counts")
    if counts is not None:
        if not isinstance(counts, dict):
            raise SuiteError(
                f"Results file field summary.counts must be an object: {source}"
            )
        normalized: Counter[str] = Counter()
        for raw_status, raw_count in counts.items():
            status = str(raw_status).strip().upper()
            if status not in RESULT_STATUSES:
                raise SuiteError(
                    f"Results file summary.counts has invalid status {status!r}: {source}"
                )
            normalized[status] += _nonnegative_integer(
                raw_count,
                field=f"summary.counts.{raw_status}",
                source=source,
            )
        actual = Counter(item["status"] for item in payload["results"])
        if normalized != actual:
            raise SuiteError(
                "Results file summary.counts does not match the result rows: "
                f"expected {dict(actual)}, found {dict(normalized)}: {source}"
            )
        summary["counts"] = dict(normalized)
    if "total_results" in summary:
        total = _nonnegative_integer(
            summary["total_results"],
            field="summary.total_results",
            source=source,
        )
        if total != len(payload["results"]):
            raise SuiteError(
                f"Results file summary.total_results is {total}, but "
                f"{len(payload['results'])} rows are present: {source}"
            )
    for field in ("performance", "performance_summary", "categories"):
        value = summary.get(field)
        if value is not None and not isinstance(value, dict):
            raise SuiteError(
                f"Results file field summary.{field} must be an object: {source}"
            )


def _validate_cleanup(payload: dict[str, Any], *, source: pathlib.Path) -> None:
    cleanup = payload.get("cleanup")
    if cleanup is None:
        return
    for field in ("attempted", "complete"):
        value = cleanup.get(field)
        if value is not None and not isinstance(value, bool):
            raise SuiteError(
                f"Results file field cleanup.{field} must be boolean or null: {source}"
            )
    for field in ("deleted", "adopted_orphans"):
        if field in cleanup:
            _nonnegative_integer(
                cleanup[field],
                field=f"cleanup.{field}",
                source=source,
            )
    for field in ("leftovers", "errors", "delayed_groups"):
        value = cleanup.get(field)
        if value is not None and not isinstance(value, list):
            raise SuiteError(
                f"Results file field cleanup.{field} must be an array: {source}"
            )


def _validate_cloud_operations(
    payload: dict[str, Any], *, source: pathlib.Path
) -> None:
    cloud_operations = payload.get("cloud_operations")
    if cloud_operations is None:
        return
    if not isinstance(cloud_operations, dict):
        raise SuiteError(
            f"Results file field cloud operations must be an object: {source}"
        )
    for field in (
        "operations",
        "unresolved_operation_ids",
        "quarantined_hosts",
        "external_unresolved_operations",
    ):
        value = cloud_operations.get(field)
        if value is not None and not isinstance(value, list):
            raise SuiteError(
                f"Results file field cloud_operations.{field} must be an array: {source}"
            )
    for field in ("quarantined_resources", "hosts"):
        value = cloud_operations.get(field)
        if value is not None and not isinstance(value, dict):
            raise SuiteError(
                f"Results file field cloud_operations.{field} must be an object: {source}"
            )
    if "unresolved_count" in cloud_operations:
        expected = _nonnegative_integer(
            cloud_operations["unresolved_count"],
            field="cloud_operations.unresolved_count",
            source=source,
        )
        identifiers = cloud_operations.get("unresolved_operation_ids")
        if isinstance(identifiers, list) and expected != len(identifiers):
            raise SuiteError(
                "Results file cloud_operations.unresolved_count does not match "
                f"unresolved_operation_ids: {source}"
            )


def _normalize_result_row(
    item: dict[str, Any],
    *,
    index: int,
    source: pathlib.Path,
) -> None:
    test_id = str(item.get("test_id") or "").strip()
    if not test_id:
        raise SuiteError(f"Results file entry {index} has no test_id: {source}")
    item["test_id"] = test_id
    status = str(item.get("status") or "").strip().upper()
    if status not in RESULT_STATUSES:
        raise SuiteError(
            f"Results file entry {index} has invalid status {status!r}: {source}"
        )
    item["status"] = status
    details = item.get("details")
    if details is not None and not isinstance(details, dict):
        raise SuiteError(
            f"Results file entry {index} details must be an object: {source}"
        )
    if "duration_ms" in item:
        duration = item["duration_ms"]
        if (
            isinstance(duration, bool)
            or not isinstance(duration, (int, float))
            or not math.isfinite(float(duration))
            or float(duration) < 0.0
        ):
            raise SuiteError(
                f"Results file entry {index} duration_ms must be a finite "
                f"non-negative number: {source}"
            )
    try:
        normalized = normalize_result_record(item)
    except (TypeError, ValueError) as exc:
        raise SuiteError(
            f"Results file entry {index} has an invalid typed network contract: "
            f"{exc}: {source}"
        ) from exc
    item.clear()
    item.update(normalized)


def _validate_check_ledger(payload: dict[str, Any], *, source: pathlib.Path) -> None:
    ledger = payload.get("planned_check_ledger")
    if ledger is None or ledger == []:
        return
    if not isinstance(ledger, list):
        raise SuiteError(
            f"Results file planned_check_ledger must be an array: {source}"
        )
    by_id = {row["test_id"]: row for row in payload["results"]}
    identities: set[str] = set()
    bound: dict[str, list[dict[str, Any]]] = {}
    for row in payload["results"]:
        details = row.get("details") or {}
        identity = details.get("planned_check_id")
        if identity is not None and (not isinstance(identity, str) or not identity):
            raise SuiteError(
                f"Results file has an invalid evidence check binding: {source}"
            )
        if details.get("check_sample") is not None and not isinstance(
            details["check_sample"], bool
        ):
            raise SuiteError(
                f"Results file evidence check_sample must be boolean: {source}"
            )
        if identity:
            bound.setdefault(identity, []).append(row)
    for check in ledger:
        if (
            not isinstance(check, dict)
            or not isinstance(check.get("id"), str)
            or not check["id"]
        ):
            raise SuiteError(
                f"Results file has an invalid planned check identity: {source}"
            )
        identity = check["id"]
        if identity in identities:
            raise SuiteError(
                f"Results file has duplicate planned check {identity!r}: {source}"
            )
        identities.add(identity)
        outcome = check.get("outcome")
        if not isinstance(outcome, str) or outcome not in CHECK_OUTCOME_STATUSES:
            raise SuiteError(
                f"Results file has invalid check outcome {outcome!r}: {source}"
            )
        evidence_ids = check.get("evidence_ids", [])
        if (
            not isinstance(evidence_ids, list)
            or any(
                not isinstance(item, str) or item not in by_id for item in evidence_ids
            )
            or len(set(evidence_ids)) != len(evidence_ids)
        ):
            raise SuiteError(
                f"Results file check {identity!r} has invalid evidence references: {source}"
            )
        if any(
            (by_id[item].get("details") or {}).get("planned_check_id")
            not in {None, identity}
            for item in evidence_ids
        ):
            raise SuiteError(
                f"Results file check {identity!r} contradicts evidence bindings: {source}"
            )
        if not {row["test_id"] for row in bound.get(identity, [])}.issubset(
            evidence_ids
        ):
            raise SuiteError(
                f"Results file check {identity!r} omits bound evidence: {source}"
            )
        primary = [
            by_id[item]
            for item in evidence_ids
            if (by_id[item].get("details") or {}).get("check_sample") is not True
        ]
        result_id = check.get("result_id")
        if result_id is not None and not isinstance(result_id, str):
            raise SuiteError(
                f"Results file check {identity!r} has an invalid result reference: {source}"
            )
        if primary:
            expected = min(
                (recorded_check_outcome(row) for row in primary),
                key=CHECK_OUTCOME_PRIORITY.__getitem__,
            )
            if result_id not in {row["test_id"] for row in primary} or (
                outcome != expected
                or recorded_check_outcome(by_id[result_id]) != expected
            ):
                raise SuiteError(
                    f"Results file check {identity!r} contradicts terminal evidence: {source}"
                )
        elif result_id is not None or outcome in {
            "FAILED",
            "ERROR",
            "UNVERIFIED",
        }:
            raise SuiteError(
                f"Results file check {identity!r} lacks terminal evidence: {source}"
            )
        elif outcome == "PASSED" and not isinstance(check.get("reason"), str):
            raise SuiteError(
                f"Results file check {identity!r} lacks its recorded assessment: {source}"
            )
    if set(bound) - identities:
        raise SuiteError(f"Results file has evidence for an unplanned check: {source}")
    plan = payload.get("plan")
    if plan is not None and not isinstance(plan, dict):
        raise SuiteError(f"Results file plan must be an object: {source}")
    planned = (plan or {}).get("checks") or []
    if not isinstance(planned, list):
        raise SuiteError(f"Results file plan.checks must be an array: {source}")
    if planned and identities != {
        row.get("id") for row in planned if isinstance(row, dict)
    }:
        raise SuiteError(
            f"Results file planned check ledger differs from the approved inventory: {source}"
        )


def _validate_final_status(payload: dict[str, Any], *, source: pathlib.Path) -> None:
    final_status = payload["run"]["final_status"]
    results = (
        logical_results(payload)
        if payload.get("planned_check_ledger")
        else payload["results"]
    )
    verdicts = Counter(typed_verdict(item) for item in results)
    tool_errors = any(
        typed_verdict(item) == "ERROR"
        and (item.get("details") or {}).get("tool_failure")
        for item in payload["results"]
    )
    cleanup = payload.get("cleanup") or {}
    setup_failures = payload.get("setup_failures") or []
    top_error = payload.get("error")
    bad_rows = verdicts.get("FAIL", 0) + verdicts.get("ERROR", 0) + tool_errors
    warning_rows = sum(
        verdicts.get(item, 0)
        for item in (
            "UNVERIFIED",
            "BLOCKED",
            "INAPPLICABLE",
            "NOT_RUN",
        )
    )
    performance_warnings = any(
        item["status"] == "PASS"
        and (item.get("details") or {}).get("health") in {"warning", "critical"}
        for item in logical_results(payload)
    )
    passing_observations = any(
        item.get("status") == "PASS" and needs_attention(item)
        for item in logical_results(payload)
    )
    if final_status == "PASS" and (
        bad_rows or warning_rows or performance_warnings or setup_failures or top_error
    ):
        raise SuiteError(
            f"Results file final status PASS contradicts its findings: {source}"
        )
    if final_status == "PASS WITH WARNINGS" and (
        bad_rows or setup_failures or top_error
    ):
        raise SuiteError(
            "Results file final status PASS WITH WARNINGS contradicts a failure "
            f"or execution error: {source}"
        )
    if final_status == "PASS WITH WARNINGS" and not (
        warning_rows or performance_warnings or passing_observations
    ):
        raise SuiteError(
            "Results file final status PASS WITH WARNINGS has no warning or "
            f"unexecuted result evidence: {source}"
        )
    if final_status == "PARTIAL" and not setup_failures:
        raise SuiteError(
            f"Results file final status PARTIAL requires setup-failure evidence: {source}"
        )
    if final_status == "CLEANUP INCOMPLETE" and cleanup.get("complete") is not False:
        raise SuiteError(
            "Results file final status CLEANUP INCOMPLETE requires "
            f"cleanup.complete=false: {source}"
        )
    if cleanup.get("complete") is False and final_status != "CLEANUP INCOMPLETE":
        raise SuiteError(
            f"Results file with incomplete cleanup must use CLEANUP INCOMPLETE: {source}"
        )


def load_results(path: str | pathlib.Path) -> dict[str, Any]:
    source = pathlib.Path(path).expanduser().resolve()
    if not source.is_file():
        raise SuiteError(f"Results file does not exist: {source}")
    try:
        payload = json.loads(
            source.read_text(encoding="utf-8"),
            parse_constant=_reject_json_constant,
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise SuiteError(f"Could not read results file {source}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SuiteError(f"Results file root must be an object: {source}")
    payload = canonical_operation_fields(payload)
    schema = payload.get("schema_version")
    if schema != 1:
        raise SuiteError(
            f"Unsupported results schema {schema!r} in {source}; expected schema 1"
        )
    if not isinstance(payload.get("run"), dict) or not isinstance(
        payload.get("results"), list
    ):
        raise SuiteError(f"Results file lacks required run/results fields: {source}")
    run_id = str((payload.get("run") or {}).get("run_id") or "").strip()
    if not run_id:
        raise SuiteError(f"Results file has no run.run_id: {source}")
    final_status = (
        str((payload.get("run") or {}).get("final_status") or "").strip().upper()
    )
    if final_status not in _FINAL_STATUSES:
        raise SuiteError(
            f"Results file has invalid run.final_status {final_status!r}: {source}"
        )
    payload["run"]["run_id"] = run_id
    payload["run"]["final_status"] = final_status
    for field in ("summary", "cleanup"):
        value = payload.get(field)
        if value is not None and not isinstance(value, dict):
            raise SuiteError(f"Results file field {field} must be an object: {source}")
    invalid_rows = [
        index
        for index, item in enumerate(payload.get("results") or [])
        if not isinstance(item, dict)
    ]
    if invalid_rows:
        raise SuiteError(
            f"Results file contains non-object result entries at indexes "
            f"{invalid_rows[:5]}: {source}"
        )
    seen_test_ids: set[str] = set()
    for index, item in enumerate(payload.get("results") or []):
        _normalize_result_row(item, index=index, source=source)
        test_id = item["test_id"]
        if test_id in seen_test_ids:
            raise SuiteError(
                f"Results file contains duplicate test_id {test_id!r}: {source}"
            )
        seen_test_ids.add(test_id)
    summary = payload.setdefault("summary", {})
    summary.setdefault(
        "counts", dict(Counter(item["status"] for item in payload["results"]))
    )
    summary.setdefault("total_results", len(payload["results"]))
    performance = payload.get("performance")
    if performance is not None and not isinstance(performance, (list, dict)):
        raise SuiteError(
            f"Results file field performance must be an array or compact index object: {source}"
        )
    for field in ("resources", "events", "setup_failures"):
        value = payload.get(field)
        if value is not None and not isinstance(value, list):
            raise SuiteError(f"Results file field {field} must be an array: {source}")
    _validate_summary(payload, source=source)
    _validate_cleanup(payload, source=source)
    _validate_cloud_operations(payload, source=source)
    _validate_check_ledger(payload, source=source)
    _validate_final_status(payload, source=source)
    return payload


def output_directory(
    value: str | pathlib.Path | None,
    *,
    default: pathlib.Path,
) -> pathlib.Path:
    raw = pathlib.Path(value).expanduser() if value else default.expanduser()
    path = raw if raw.is_absolute() else pathlib.Path.cwd() / raw
    if path.is_symlink():
        raise SuiteError(f"Output directory must not be a symbolic link: {path}")
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise SuiteError(f"Could not prepare output directory {path}: {exc}") from exc
    if path.is_symlink():
        raise SuiteError(f"Output directory must not be a symbolic link: {path}")
    return path


def _counted(count: int, singular: str, plural: str | None = None) -> str:
    return f"{count} {singular if count == 1 else plural or singular + 's'}"


def _cleanup_scope_accounting_note(cleanup: dict[str, Any]) -> str | None:
    zones = cleanup.get("zones") or {}
    scoped = {
        str(scope): int((summary or {}).get("adopted_orphans") or 0)
        for scope, summary in zones.items()
        if int((summary or {}).get("adopted_orphans") or 0) > 0
    }
    if not scoped:
        return None
    scoped_total = sum(scoped.values())
    run_total = int(cleanup.get("adopted_orphans") or 0)
    scopes = ", ".join(f"{scope}={count}" for scope, count in sorted(scoped.items()))
    return (
        "Scoped cleanup summaries report "
        f"{_counted(scoped_total, 'adopted orphan record')} ({scopes}), while run-level "
        f"adopted_orphans={run_total}. This is a tool cleanup ownership/accounting "
        "anomaly, not a cloud-network failure."
    )


_TEXT_EVIDENCE_OMIT_KEYS = {
    "metrics",
    "raw_measurement",
    "raw_measurements",
    "raw_samples",
    "samples",
    "stdout",
    "stderr",
    "command_output",
    "server_output",
    "client_output",
    "iperf_json",
    "iperf_results",
    "measurement_payload",
    "measurement_payloads",
    "result_object",
    "result_objects",
}


def _omit_text_evidence_key(key: object) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    return (
        normalized in _TEXT_EVIDENCE_OMIT_KEYS
        or normalized.startswith("raw_")
        or normalized.endswith("_raw")
        or normalized.endswith("_samples")
        or normalized.endswith("_stdout")
        or normalized.endswith("_stderr")
    )


def _compact_text_evidence_value(value: Any, *, depth: int = 0) -> Any:
    if depth >= 4:
        if isinstance(value, dict):
            return {"summary": f"{len(value)} nested fields omitted"}
        if isinstance(value, (list, tuple, set)):
            return [f"{len(value)} nested items omitted"]
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        omitted: list[str] = []
        for raw_key, item in value.items():
            key = str(raw_key)
            if _omit_text_evidence_key(key):
                omitted.append(key)
                continue
            if len(output) >= 24:
                omitted.append(key)
                continue
            output[key] = _compact_text_evidence_value(item, depth=depth + 1)
        if omitted:
            output["_canonical_fields_omitted"] = len(omitted)
        return output
    if isinstance(value, (list, tuple, set)):
        rows = list(value)
        compact = [
            _compact_text_evidence_value(item, depth=depth + 1) for item in rows[:10]
        ]
        if len(rows) > 10:
            compact.append(f"{len(rows) - 10} additional items omitted")
        return compact
    if isinstance(value, str) and len(value) > 600:
        return value[:597].rstrip() + "..."
    return value


def _render_text_evidence(details: dict[str, Any], *, maximum: int = 2200) -> str:
    compact = _compact_text_evidence_value(details)
    rendered = json.dumps(compact, sort_keys=True, allow_nan=False)
    if len(rendered) <= maximum:
        return rendered
    return rendered[: maximum - 3].rstrip() + "..."


def render_results_text(payload: dict[str, Any]) -> str:
    # Display-only plan enrichment supplies timing/actions recorded in the
    # original plan without changing the source records or historical verdicts.
    results = contextual_results(payload)
    presentation = {**payload, "results": results}
    tests = logical_results(presentation)
    run = payload.get("run") or {}
    summary = payload.get("summary") or {}
    counts = (
        Counter(str(item.get("status") or "UNKNOWN") for item in tests)
        if tests
        else Counter(summary.get("counts") or {})
    )
    lines = [
        "NEUTRON FLUX RESULT REPORT",
        "=" * 100,
        f"Run ID: {run.get('run_id', 'unknown')}",
        f"Final status: {run.get('final_status', 'unknown')}",
        f"Started: {run.get('started_at', 'unknown')}",
        f"Finished: {run.get('finished_at', 'unknown')}",
        f"Tool version: {payload.get('tool_version', 'unknown')}",
        "",
        "TEST RESULTS",
        "-" * 100,
    ]
    for status in (
        "PASS",
        "FAIL",
        "ERROR",
        "UNVERIFIED",
        "BLOCKED_BY_SETUP_ERROR",
        "BLOCKED_BY_PREREQUISITE",
        "NOT_RUN_CANCELLED",
        "SKIP",
        "NOT_APPLICABLE",
    ):
        label = {
            "PASS": "Passed",
            "FAIL": "Failed",
            "ERROR": "Execution errors",
            "UNVERIFIED": "Could not verify",
            "BLOCKED_BY_SETUP_ERROR": "Did not run: setup error",
            "BLOCKED_BY_PREREQUISITE": "Did not run: prerequisite",
            "NOT_RUN_CANCELLED": "Did not run: cancelled",
            "SKIP": "Skipped: unsupported",
            "NOT_APPLICABLE": "Not applicable",
        }[status]
        lines.append(f"{label:<28} {counts.get(status, 0):>8}")
    lines.append(f"{'Total tests':<28} {sum(counts.values()):>8}")
    lines.extend(attention_summary_lines(attention_summary(presentation)))
    logical_record_ids = {row.get("test_id") for row in tests}
    saved_record_ids = {row.get("test_id") for row in results}
    derived_planned_rows = sum(
        row.get("test_id") not in saved_record_ids for row in tests
    )
    if derived_planned_rows:
        lines.append(
            f"Planned status rows without an individual saved result record: {derived_planned_rows}; "
            "these statuses come from the check inventory and recorded prerequisites, "
            "not additional executed probes."
        )
    supporting_count = sum(
        row.get("test_id") not in logical_record_ids for row in results
    )
    if supporting_count:
        record_counts = Counter(
            str(item.get("status") or "UNKNOWN") for item in results
        )
        lines.extend(
            [
                f"Supporting or retry records: {supporting_count}; these are evidence for the tests above, not additional tests.",
                f"Total saved result records: {len(results)}.",
                "Technical record counts: "
                + ", ".join(
                    f"{status} {count}"
                    for status, count in sorted(record_counts.items())
                )
                + ". A failing test and its failing supporting sample may both appear in these record counts.",
            ]
        )
    performance = summary.get("performance_summary") or summary.get("performance") or {}
    meaningful_performance = bool(
        performance
        and (
            int(performance.get("paths") or 0) > 0
            or any(
                value not in (None, "", [], {}, 0, 0.0)
                for key, value in performance.items()
                if key
                not in {
                    "paths",
                    "warning_results",
                    "mtu_mismatch_paths",
                    "tcp_retransmission_summary_scope",
                }
            )
        )
    )
    if meaningful_performance:
        lines.extend(["", "PERFORMANCE SUMMARY", "-" * 100])
        lines.append(
            "These measurements summarize the recorded network paths across the run. "
            "The individual results below identify each path, VM placement and test condition."
        )
        performance_labels = {
            "paths": ("Network paths measured", ""),
            "warning_results": ("Measurements with advisory conditions", ""),
            "excluded_udp_samples": (
                "UDP samples excluded from network-loss comparison",
                "",
            ),
            "mtu_mismatch_paths": (
                "Paths with an advertised/observed MTU difference",
                "",
            ),
            "highest_single_stream_mbps": (
                "Highest TCP transfer rate with one connection",
                "Mbps",
            ),
            "lowest_single_stream_mbps": (
                "Lowest TCP transfer rate with one connection",
                "Mbps",
            ),
            "best_concurrent_mbps": (
                "Highest combined TCP rate with concurrent connections",
                "Mbps",
            ),
            "lowest_concurrent_fairness": ("Lowest concurrent-flow fairness score", ""),
            "highest_idle_p95_ms": (
                "Largest idle round-trip delay at the 95th percentile",
                "ms",
            ),
            "worst_loaded_latency_ratio": (
                "Largest loaded/idle round-trip delay ratio",
                "times",
            ),
            "worst_repeatability_variation_pct": (
                "Greatest variation between repeated TCP transfers",
                "%",
            ),
            "worst_directional_asymmetry_pct": (
                "Greatest difference between traffic directions",
                "%",
            ),
            "worst_tcp_retransmissions": (
                "Largest TCP retransmission count in one measurement window",
                "",
            ),
            "tcp_retransmission_summary_scope": ("TCP retransmission count scope", ""),
            "best_udp_mbps": ("Highest UDP receive rate", "Mbps"),
            "best_udp_pps": ("Highest UDP receive packet rate", "packets/second"),
            "worst_udp_loss_pct": (
                "Highest UDP application-delivery loss among usable samples",
                "%",
            ),
            "worst_endpoint_limited_udp_loss_pct": (
                "Highest UDP loss in samples limited by the VMs",
                "%",
            ),
            "worst_udp_jitter_ms": ("Highest UDP receive timing variation", "ms"),
        }
        for key, value in sorted(performance.items()):
            if value is None or key in {
                "worst_tcp_retransmission_window",
                "worst_tcp_retransmission_window_description",
            }:
                continue
            label, unit = performance_labels.get(
                key, (key.replace("_", " ").capitalize(), "")
            )
            number = (
                f"{value:,.2f}".rstrip("0").rstrip(".")
                if isinstance(value, float)
                else str(value)
            )
            lines.append(f"{label}: {number}" + (f" {unit}" if unit else ""))
            if key == "worst_tcp_retransmissions":
                context = performance.get("worst_tcp_retransmission_window_description")
                if context:
                    lines.append(f"TCP measurement window: {context}")
    blocked_statuses = {"BLOCKED_BY_SETUP_ERROR", "BLOCKED_BY_PREREQUISITE"}
    blocked = [
        item
        for item in tests
        if str(item.get("status") or "").upper() in blocked_statuses
    ]
    cancelled = [
        item
        for item in tests
        if str(item.get("status") or "").upper() == "NOT_RUN_CANCELLED"
    ]
    setup_failures = payload.get("setup_failures") or []
    lines.extend(["", "WHY RESULTS NEED ATTENTION", "-" * 100])
    for group in operator_overview(presentation)["groups"]:
        lines.append(f"{group['count']} — {group['label']}")
    for issue in lifecycle_explanations(payload):
        lines.extend(
            [
                issue["headline"],
                issue["what_happened"],
                "Next check: " + issue["next_check"],
            ]
        )
    findings = [
        item
        for item in tests
        if needs_attention(item)
        and item.get("status") in {"PASS", "FAIL", "ERROR", "UNVERIFIED"}
        and not (item.get("details") or {}).get("tool_failure")
    ]
    lines.extend(["", "NEEDS ATTENTION", "-" * 100])
    if not findings:
        if setup_failures:
            lines.append(
                "No executed network contract failed, errored, or remained "
                f"unverified. {_counted(len(setup_failures), 'Neutron Flux setup/tool failure')} "
                "blocked coverage; see TOOL OR SETUP FAILURES below."
            )
        elif blocked:
            lines.append(
                "No executed network contract failed, errored, or remained "
                f"unverified. {_counted(len(blocked), 'validation')} did not run; see "
                "BLOCKED COVERAGE below."
            )
        elif cancelled:
            cancelled_count = len(cancelled)
            lines.append(
                "No executed network contract failed, errored, or remained "
                f"unverified. {_counted(cancelled_count, 'planned validation')} "
                f"{'was' if cancelled_count == 1 else 'were'} cancelled before execution."
            )
        else:
            lines.append(
                "No failures, errors, unverified results, or performance warnings."
            )
    else:
        for item in findings:
            story = explain_result(item)
            health = (item.get("details") or {}).get("health")
            status = (
                "PASS WITH WARNING"
                if item.get("status") == "PASS"
                and health == "warning"
                and story.get("kind") != "migration-interruption-observation"
                else str(item.get("status") or "UNKNOWN")
            )
            lines.extend(
                [
                    f"[{status}] {execution_name(item)}",
                    "  Actual result: "
                    + str(story["observed"]).replace("\n", "\n    "),
                    "  Review note: "
                    + str(story["headline"]).rstrip(".")
                    + ". "
                    + str(story["why_this_status"]),
                ]
            )
            lines.extend(
                f"  Advisory: {value}"
                for value in story["warnings"]
                if value not in story["observed"]
            )
            if story.get("interruption_observations"):
                lines.append(
                    "  [OBSERVATION] Above tolerance: "
                    + "; ".join(story["interruption_observations"])
                )
                lines.append(f"  {story['interruption_tolerance_note']}")
            lines.append("")

    def blocked_zone(item: dict[str, Any]) -> str:
        details = item.get("details") or {}
        for key in (
            "availability_zone",
            "source_availability_zone",
            "destination_availability_zone",
        ):
            value = str(details.get(key) or "").strip()
            if value:
                return value
        scope = str(details.get("execution_scope") or "").strip()
        if scope.startswith("az-") and len(scope) > 3:
            return scope[3:]
        match = re.match(
            r"^AZ-(.+?)-(?:CONTROL|SAME|PROJECT|STATIC|PERF|EGRESS|FIP|MTU|ROUTE|SECURITY|SERVER|SNAT|SOURCE|PLACEMENT|CONCURRENT)(?:-|$)",
            str(item.get("test_id") or ""),
            re.IGNORECASE,
        )
        return match.group(1).lower() if match else "run scope"

    if blocked:
        healthy_controller_zones = {
            blocked_zone(item)
            for item in results
            if str(item.get("status") or "").upper() == "PASS"
            and (
                str(item.get("scenario") or "").lower() == "controller readiness"
                or str(item.get("category") or "").lower()
                in {"control", "controller-bootstrap"}
            )
        }
        grouped_blocked = Counter(
            (
                blocked_zone(item),
                str(item.get("status") or "UNKNOWN").upper(),
                str((item.get("details") or {}).get("root_setup_result_id") or ""),
            )
            for item in blocked
        )
        lines.extend(["", "BLOCKED COVERAGE", "-" * 100])
        for (zone, status, root_result_id), count in sorted(grouped_blocked.items()):
            if status == "BLOCKED_BY_SETUP_ERROR" and zone in healthy_controller_zones:
                reason = (
                    "the run-wide orchestrator stopped after this zone's controller "
                    "was already healthy"
                )
            elif status == "BLOCKED_BY_SETUP_ERROR":
                reason = "controller or lane setup did not complete"
            else:
                reason = "a prerequisite did not complete"
            root = f"; root={root_result_id}" if root_result_id else ""
            lines.append(
                f"{zone}: {_counted(count, 'downstream validation')} not run "
                f"because {reason}{root}"
            )

    if setup_failures:
        lines.extend(["", "TOOL OR SETUP FAILURES", "-" * 100])
        for item in setup_failures:
            lines.append(f"- {item.get('message') or 'Unknown setup failure'}")

    lines.extend(["", "DETAILED RESULTS", "-" * 100])
    compact_blocked = len(blocked) > 20
    saved_record_ids = {item.get("test_id") for item in results}
    detailed_results = [
        *results,
        *(row for row in tests if row.get("test_id") not in saved_record_ids),
    ]
    for item in detailed_results:
        if (
            compact_blocked
            and str(item.get("status") or "").upper() in blocked_statuses
        ):
            continue
        lines.append("")
        sample = (
            "Supporting sample "
            if (item.get("details") or {}).get("check_sample")
            else ""
        )
        lines.append(f"{sample}[{item.get('status')}] {execution_name(item)}")
        lines.extend(explanation_lines(item))
        details = item.get("details") or {}
        lines.append(f"  Technical reference: {item.get('test_id')}")
        if details:
            lines.append(
                "  Full recorded evidence: results.json -> "
                f"results[test_id={item.get('test_id')!r}].details"
            )
    if compact_blocked:
        lines.append(
            f"[{len(blocked)} BLOCKED RESULTS OMITTED] See BLOCKED COVERAGE above and results.json for the complete per-validation ledger."
        )
    cleanup = payload.get("cleanup") or {}
    lines.extend(
        [
            "",
            "CLEANUP",
            "-" * 100,
            f"Attempted: {cleanup.get('attempted')}",
            f"Complete: {cleanup.get('complete')}",
            f"Explicit delete operations completed: {cleanup.get('deleted', 0)}",
            f"Adopted orphans (run scope): {cleanup.get('adopted_orphans', 0)}",
            f"Unresolved cleanup or verification issues: {len(cleanup.get('leftovers') or [])}",
            f"Errors: {len(cleanup.get('errors') or [])}",
        ]
    )
    unresolved_resources = sum(
        1
        for resource in payload.get("resources") or []
        if str(resource.get("cleanup_state") or "").upper() not in {"DELETED", "ABSENT"}
    )
    lines.append(
        "Tracked resource records needing cleanup or verification: "
        f"{unresolved_resources}"
    )
    if payload.get("resources"):
        lines.append(
            "Tracked resource records marked absent or deleted: "
            f"{len(payload['resources']) - unresolved_resources}; "
            "includes resources removed automatically or already absent."
        )
    if cleanup.get("leftovers"):
        lines.append(
            "Unresolved issues include verification errors and may not represent "
            "distinct resources confirmed present."
        )
    cleanup_accounting_note = _cleanup_scope_accounting_note(cleanup)
    if cleanup_accounting_note:
        lines.append(f"Accounting note: {cleanup_accounting_note}")
    lines.append("")
    return "\n".join(lines)


def result_files(paths: Iterable[str | pathlib.Path]) -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for raw in paths:
        path = pathlib.Path(raw).expanduser()
        if path.is_dir():
            files.extend(sorted(path.glob("**/results.json")))
        else:
            files.append(path)
    resolved: list[pathlib.Path] = []
    seen: set[pathlib.Path] = set()
    for item in files:
        absolute = item.resolve()
        if absolute in seen:
            continue
        seen.add(absolute)
        resolved.append(absolute)
    return resolved


__all__ = [
    "atomic_write_text",
    "load_results",
    "output_directory",
    "render_results_text",
    "result_files",
]
