"""Bind evidence to approved checks and retain explainable conditional outcomes."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from typing import Any

from .errors import SuiteError
from .results_io import atomic_write_text


def root_reporter(reporter: Any) -> Any:
    return vars(reporter).get("parent", reporter)


def _resolutions(reporter: Any) -> dict[str, Any]:
    reporter = root_reporter(reporter)
    cached = getattr(reporter, "_check_resolutions", None)
    if cached is not None:
        return cached
    cached = {}
    path = getattr(reporter, "run_dir", None)
    if path is not None and getattr(
        getattr(reporter, "config", None), "resume_run_id", None
    ):
        path = path / "check-outcomes.json"
        if path.is_symlink():
            raise SuiteError(f"Check outcomes must not be a symbolic link: {path}")
        if path.exists():
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("expected an object")
                cached = {
                    key: value
                    for key, value in payload.items()
                    if value["outcome"] not in {"CANCELLED", "NEVER_RAN", "BLOCKED"}
                }
            except (OSError, ValueError, KeyError, TypeError) as exc:
                raise SuiteError(f"Invalid saved check outcomes: {exc}") from exc
    reporter._check_resolutions = cached
    return cached


def evidence_bindings(reporter: Any) -> dict[str, dict[str, Any]]:
    reporter = root_reporter(reporter)
    plan = getattr(reporter, "plan", None)
    if plan is None or not getattr(plan, "checks", None):
        return {}
    return {spec.id: spec.metadata for spec in plan.tests}


def validate_check_bindings(plan: Any) -> None:
    checks = getattr(plan, "checks", None)
    if not isinstance(checks, list) or not checks:
        return
    if not all(
        isinstance(row, dict)
        and isinstance(row.get("id"), str)
        and row["id"]
        and isinstance(row.get("condition"), str)
        for row in checks
    ):
        raise SuiteError("Invalid complete check inventory")
    known = {row["id"] for row in checks}
    if len(known) != len(checks):
        raise SuiteError("Duplicate identities in the complete check inventory")
    for spec in plan.tests:
        identity = spec.metadata.get("planned_check_id")
        if identity not in known:
            raise SuiteError(
                f"Unplanned check {spec.id}: no binding to the approved check inventory; "
                "execution stopped before this check could run"
            )


def result_binding(
    reporter: Any, test_id: str, details: dict[str, Any] | None = None
) -> dict[str, Any]:
    reporter = root_reporter(reporter)
    plan = getattr(reporter, "plan", None)
    if plan is None or not getattr(plan, "checks", None):
        return {}
    cache = getattr(reporter, "_check_binding_cache", None)
    if cache is None:
        cache = evidence_bindings(reporter)
        reporter._check_binding_cache = cache
    metadata = cache.get(test_id)
    if metadata is None:
        diagnostic = details or {}
        identity = diagnostic.get("planned_check_id")
        if (
            diagnostic.get("root_lane_error") is True
            and diagnostic.get("tool_failure") is True
            and diagnostic.get("check_sample") is True
            and identity in {row["id"] for row in plan.checks}
        ):
            return {"planned_check_id": identity, "check_sample": True}
        raise SuiteError(f"Unplanned result {test_id}: missing approved check binding")
    return {
        key: metadata[key]
        for key in ("planned_check_id", "check_sample")
        if key in metadata
    }


def _result_outcome(item: Any) -> str:
    if (item.details or {}).get("coverage_outcome") == "NEVER_RAN":
        return "CANCELLED" if item.status == "NOT_RUN_CANCELLED" else "BLOCKED"
    if item.status == "PASS":
        return "PASSED"
    if item.status == "ERROR":
        return "ERROR"
    if item.status == "FAIL":
        return "FAILED"
    if item.status == "NOT_APPLICABLE":
        return "INAPPLICABLE"
    if item.status == "NOT_RUN_CANCELLED":
        return "CANCELLED"
    if item.status.startswith("BLOCKED") or item.status == "SKIP":
        return "BLOCKED"
    # An unavailable migration destination is a prerequisite failure, not a
    # dataplane observation. Preserve the raw UNVERIFIED evidence separately.
    if item.observed in {
        "placement-unavailable",
        "not-run",
        "baseline-unavailable",
        "functional-baseline-unavailable",
        "fresh-functional-baseline-unavailable",
        "placement-hidden",
    }:
        return "BLOCKED"
    return "UNVERIFIED"


def check_ledger(reporter: Any) -> list[dict[str, Any]]:
    reporter = root_reporter(reporter)
    plan = getattr(reporter, "plan", None)
    checks = getattr(plan, "checks", None)
    if not isinstance(checks, list) or not checks:
        return []
    with reporter._lock:
        return _locked_check_ledger(reporter, checks)


def _locked_check_ledger(
    reporter: Any, checks: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    resolutions = _resolutions(reporter)
    evidence: dict[str, list[Any]] = defaultdict(list)
    samples: dict[str, list[str]] = defaultdict(list)
    bindings = getattr(reporter, "_check_binding_cache", None)
    if bindings is None:
        bindings = evidence_bindings(reporter)
        reporter._check_binding_cache = bindings
    for result in reporter.results:
        metadata = {**bindings.get(result.test_id, {}), **(result.details or {})}
        identity = metadata.get("planned_check_id")
        if identity and metadata.get("check_sample"):
            samples[identity].append(result.test_id)
        elif identity:
            evidence[identity].append(result)
    output = []
    priority = {
        "ERROR": -1,
        "FAILED": 0,
        "UNVERIFIED": 1,
        "BLOCKED": 2,
        "CANCELLED": 3,
        "INAPPLICABLE": 4,
        "PASSED": 5,
    }
    for check in checks:
        identity = check["id"]
        rows = evidence.get(identity, [])
        resolution = resolutions.get(identity)
        if rows:
            chosen = min(rows, key=lambda row: priority[_result_outcome(row)])
            outcome, reason = _result_outcome(chosen), chosen.message
            result_id = chosen.test_id
        elif resolution:
            outcome, reason = resolution["outcome"], resolution["reason"]
            result_id = None
        else:
            outcome, reason, result_id = "PENDING", check["condition"], None
        output.append(
            {
                **check,
                "test_id": identity,
                "phase": check["stage"],
                "category": check.get("category", check["kind"]),
                "outcome": outcome,
                "reason": reason,
                "result_id": result_id,
                "evidence_ids": [row.test_id for row in rows]
                + samples.get(identity, []),
            }
        )
    return output


def resolve_checks(
    reporter: Any,
    resolutions: dict[str, tuple[str, str]],
    *,
    replace_existing: bool = False,
) -> None:
    reporter = root_reporter(reporter)
    if not getattr(getattr(reporter, "plan", None), "checks", None) or not resolutions:
        return
    with reporter._lock:
        known = {row["id"]: row for row in reporter.plan.checks}
        current = {row["id"]: row for row in check_ledger(reporter)}
        saved = _resolutions(reporter)
        changed = []
        for identity, (outcome, reason) in resolutions.items():
            if identity not in known:
                raise SuiteError(f"Cannot resolve unplanned check {identity}")
            if current[identity]["outcome"] != "PENDING" and not replace_existing:
                continue
            saved[identity] = {"outcome": outcome, "reason": reason}
            changed.append(identity)
        if not changed:
            return
        atomic_write_text(
            reporter.run_dir / "check-outcomes.json",
            json.dumps(saved, sort_keys=True, indent=2) + "\n",
        )
        for identity in changed:
            row = saved[identity]
            label = {"PASSED": "PASS", "INAPPLICABLE": "NOT APPLICABLE"}.get(
                row["outcome"], row["outcome"]
            )
            reporter.logger.log(
                f"[{label}] {known[identity]['title']} — {row['reason']}"
            )
        reporter.logger.log(check_progress_text(check_progress(reporter)))


def finish_checks(
    reporter: Any, identities: set[str], *, reason: str, outcome: str = "BLOCKED"
) -> None:
    """Close unmet branches using the most specific failed prerequisite."""
    if not identities:
        return
    rows = {row["id"]: row for row in check_ledger(reporter)}
    resolutions = {}
    for identity in rows:
        if identity not in identities:
            continue
        row = rows.get(identity)
        if not row or row["outcome"] != "PENDING":
            continue
        failed = [
            rows[item]
            for item in row["prerequisites"]
            if item in rows and rows[item]["outcome"] not in {"PASSED", "PENDING"}
        ]
        explanation = reason
        if failed:
            first = failed[0]
            # Descendants inherit the root blocker once, not an ever-growing
            # concatenation of every prerequisite title along the chain.
            inherited = str(first["reason"])
            explanation = (
                inherited
                if inherited.startswith("Blocked by ")
                else f"Blocked by {first['title']}: {inherited}"
            )
        resolutions[identity] = (outcome, explanation)
        # Following checks can now inherit this reason through their prerequisite.
        rows[identity] = {**row, "outcome": outcome, "reason": explanation}
    resolve_checks(reporter, resolutions)


def finalize_checks(reporter: Any) -> None:
    if getattr(reporter, "action", None) != "run":
        return
    rows = check_ledger(reporter)
    if not rows:
        return
    if reporter.interrupted:
        reason = (
            f"Run cancelled: {reporter.cancellation_reason or 'operator cancellation'}"
        )
        outcome = "CANCELLED"
    elif reporter.error or reporter.setup_failed:
        reason = f"Run stopped before this check: {reporter.error or 'resource setup failed'}"
        outcome = "BLOCKED"
    else:
        reason = "Required execution condition was not reached"
        outcome = "BLOCKED"
    finish_checks(reporter, {row["id"] for row in rows}, reason=reason, outcome=outcome)


def check_progress(reporter: Any) -> dict[str, Any]:
    rows = check_ledger(reporter)
    counts = Counter(row["outcome"] for row in rows)
    completed = len(rows) - counts["PENDING"]
    executed = sum(counts[key] for key in ("PASSED", "FAILED", "ERROR", "UNVERIFIED"))
    return {
        "schema_version": 3,
        "scope": "complete-plan",
        "planned": len(rows),
        "planned_recorded": completed,
        "planned_executed": executed,
        "planned_not_run": completed - executed,
        "known": len(rows),
        "pending": counts["PENDING"],
        "recorded": completed,
        "executed": executed,
        "not_run": completed - executed,
        "outcomes": dict(counts),
        "plan_available": True,
        "total_can_grow": False,
    }


def check_progress_text(progress: dict[str, Any]) -> str:
    outcomes = progress["outcomes"]
    text = (
        f"Progress: {progress['planned_recorded']}/{progress['planned']} | "
        f"Passed: {outcomes.get('PASSED', 0)} | Failed: {outcomes.get('FAILED', 0)} | "
        f"Blocked: {outcomes.get('BLOCKED', 0)}"
    )
    for key, label in (
        ("ERROR", "Errors"),
        ("UNVERIFIED", "Unverified"),
        ("INAPPLICABLE", "Not applicable"),
        ("CANCELLED", "Cancelled"),
    ):
        if outcomes.get(key):
            text += f" | {label}: {outcomes[key]}"
    return text
