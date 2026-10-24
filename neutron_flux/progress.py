"""Complete planned-check progress, with legacy checkpoint compatibility."""

from __future__ import annotations

from typing import Any

_EXECUTED = frozenset({"PASS", "FAIL", "UNVERIFIED", "ERROR"})


def planned_test_ids(plan: Any) -> frozenset[str] | None:
    if plan is None:
        return None
    specs = tuple(getattr(plan, "tests", []) or [])
    if not all(hasattr(item, "id") for item in specs):
        return None
    return frozenset(item.id for item in specs)


def reporter_progress(reporter: Any) -> dict[str, Any]:
    """Freeze the original plan before results or runtime specs can enlarge it.

    The approved contract retains the original IDs across resume. Reporters
    without a contract freeze their plan at its first save/progress update.
    Do not freeze an unavailable plan during preflight heartbeats.
    """
    from .check_ledger import check_progress, root_reporter

    root = root_reporter(reporter)
    if getattr(getattr(root, "plan", None), "checks", None):
        return check_progress(root)
    planned = getattr(reporter, "_progress_plan_ids", None)
    if planned is None:
        contract = getattr(reporter, "plan_contract", None) or {}
        original = contract.get("plan")
        if isinstance(original, dict) and isinstance(original.get("tests"), list):
            specs = original["tests"]
            if all(
                isinstance(item, dict) and isinstance(item.get("id"), str)
                for item in specs
            ):
                planned = frozenset(item["id"] for item in specs)
        else:
            planned = planned_test_ids(getattr(reporter, "plan", None))
        if planned is not None:
            reporter._progress_plan_ids = planned
    return test_progress(
        getattr(reporter, "plan", None), reporter.results, planned_ids=planned
    )


def test_progress(
    plan: Any,
    results: Any,
    *,
    planned_ids: frozenset[str] | None = None,
) -> dict[str, Any]:
    rows = {item.test_id: item for item in tuple(results)}
    recorded = set(rows)
    planned = planned_ids if planned_ids is not None else planned_test_ids(plan)
    initial = planned or frozenset()
    runtime = planned_test_ids(plan) or frozenset()
    executed = {
        test_id
        for test_id, item in rows.items()
        if item.status in _EXECUTED
        and (getattr(item, "details", None) or {}).get("coverage_outcome")
        != "NEVER_RAN"
    }
    completed = initial & recorded
    return {
        "schema_version": 2,
        "scope": "initial-plan",
        "planned": len(initial),
        "planned_recorded": len(completed),
        "planned_executed": len(initial & executed),
        "planned_not_run": len(completed - executed),
        "additional_recorded": len(recorded - initial) if planned is not None else 0,
        "additional_pending": len(runtime - initial - recorded),
        "recorded": len(recorded),
        # Retain the old keys for consumers; 'known' now aliases the fixed plan.
        "known": len(initial),
        "pending": len(initial - recorded),
        "executed": len(executed),
        "not_run": len(recorded - executed),
        "plan_available": planned is not None,
        "total_can_grow": False,
    }


def progress_text(progress: dict[str, Any]) -> str:
    recorded = int(progress.get("recorded", 0))
    if not progress.get("plan_available"):
        return f"Test progress: {recorded} results recorded; plan not available"
    if progress.get("schema_version") == 3:
        from .check_ledger import check_progress_text

        return check_progress_text(progress)
    if progress.get("schema_version") != 2:
        return (
            f"Test progress: {recorded} results recorded; "
            "fixed planned total unavailable in this older checkpoint"
        )
    text = (
        f"Test progress: {int(progress['planned_recorded'])}/{int(progress['planned'])} "
        f"planned checks recorded ({int(progress['planned_executed'])} executed, "
        f"{int(progress['planned_not_run'])} not run)"
    )
    additional = int(progress["additional_recorded"])
    pending = int(progress["additional_pending"])
    if additional or pending:
        text += f"; additional results: {additional}"
        if pending:
            text += f"; additional checks pending: {pending}"
    return text
