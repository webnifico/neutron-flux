"""Select logical check outcomes without counting supporting evidence twice."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .result_contract import typed_verdict

CHECK_OUTCOME_PRIORITY = {
    "ERROR": 0,
    "FAILED": 1,
    "UNVERIFIED": 2,
    "BLOCKED": 3,
    "CANCELLED": 4,
    "INAPPLICABLE": 5,
    "PASSED": 6,
}
CHECK_OUTCOME_STATUSES = {
    "PASSED": "PASS",
    "FAILED": "FAIL",
    "ERROR": "ERROR",
    "UNVERIFIED": "UNVERIFIED",
    "INAPPLICABLE": "NOT_APPLICABLE",
    "CANCELLED": "NOT_RUN_CANCELLED",
    "BLOCKED": "BLOCKED_BY_PREREQUISITE",
    "PENDING": "BLOCKED_BY_PREREQUISITE",
}


def grades_execution(row: Mapping[str, Any] | Any) -> bool:
    """Grade terminal evidence and explicit tool errors, preserving raw retries."""
    details = (
        row.get("details")
        if isinstance(row, Mapping)
        else getattr(row, "details", None)
    ) or {}
    status = (
        row.get("status") if isinstance(row, Mapping) else getattr(row, "status", None)
    )
    return details.get("check_sample") is not True or (
        (status == "ERROR" or typed_verdict(row) == "ERROR")
        and bool(details.get("tool_failure"))
    )


def recorded_check_outcome(row: Mapping[str, Any]) -> str:
    """Grade terminal evidence using the complete check inventory's semantics."""
    details = row.get("details") or {}
    status = row.get("status")
    if details.get("coverage_outcome") == "NEVER_RAN":
        return "CANCELLED" if status == "NOT_RUN_CANCELLED" else "BLOCKED"
    explicit = {
        "PASS": "PASSED",
        "ERROR": "ERROR",
        "FAIL": "FAILED",
        "NOT_APPLICABLE": "INAPPLICABLE",
        "NOT_RUN_CANCELLED": "CANCELLED",
        "SKIP": "BLOCKED",
        "BLOCKED_BY_SETUP_ERROR": "BLOCKED",
        "BLOCKED_BY_PREREQUISITE": "BLOCKED",
    }
    if status in explicit:
        return explicit[status]
    if row.get("observed") in {
        "placement-unavailable",
        "not-run",
        "baseline-unavailable",
        "functional-baseline-unavailable",
        "fresh-functional-baseline-unavailable",
        "placement-hidden",
    }:
        return "BLOCKED"
    return "UNVERIFIED"


def unrecorded_check_result(check: Mapping[str, Any]) -> dict[str, Any]:
    """Present a recorded resolution without inventing executed probe evidence."""
    identity = check["id"]
    category = str(check.get("category") or "coverage")
    categories = {
        "performance": "network-performance",
        "migration": "compute-placement",
    }
    return {
        "test_id": identity,
        "result_id": identity,
        "display_name": check.get("title") or identity,
        "category": categories.get(str(check.get("kind") or ""), category),
        "status": CHECK_OUTCOME_STATUSES.get(
            str(check.get("outcome") or ""), "UNVERIFIED"
        ),
        "family": check.get("family"),
        "expected": check.get("condition"),
        "observed": "resolution-recorded"
        if check.get("outcome") == "PASSED"
        else "not-run",
        "message": check.get("reason")
        or check.get("condition")
        or "No terminal evidence was recorded",
        "authoritative": False,
        "phase": check.get("stage"),
        "reporting_context": {
            key: check[key]
            for key in (
                "measurement",
                "pair_placement",
                "pair_scope_id",
                "host_qualification_cycle",
                "requested_source_host",
                "requested_destination_host",
            )
            if check.get(key) is not None
        },
        "details": {
            "planned_check_id": identity,
            "coverage_outcome": check.get("outcome"),
            "resolution_only": True,
        },
    }


def logical_results(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw_rows = payload.get("results")
    rows = (
        [row for row in raw_rows if isinstance(row, dict)]
        if isinstance(raw_rows, list)
        else []
    )
    ledger = payload.get("planned_check_ledger")
    ledger = ledger if isinstance(ledger, list) else []
    aliases = {
        evidence_id: check["id"]
        for check in ledger
        if isinstance(check, dict) and check.get("id")
        for evidence_id in [check.get("result_id"), *(check.get("evidence_ids") or [])]
        if evidence_id
    }
    selected: dict[str, dict[str, Any]] = {}
    for row in rows:
        details = row.get("details")
        details = details if isinstance(details, dict) else {}
        if details.get("check_sample") is True:
            continue
        raw_identity = row.get("test_id") or row.get("result_id")
        identity = str(
            details.get("planned_check_id")
            or aliases.get(raw_identity)
            or raw_identity
            or ""
        )
        if not identity:
            # Do not drop malformed legacy evidence or invent a shared identity.
            identity = f"unidentified-{id(row)}"
        prior = selected.get(identity)
        if (
            prior is None
            or CHECK_OUTCOME_PRIORITY[recorded_check_outcome(row)]
            < CHECK_OUTCOME_PRIORITY[recorded_check_outcome(prior)]
        ):
            selected[identity] = row
    output: list[dict[str, Any]] = []
    for check in ledger:
        if not isinstance(check, dict) or not check.get("id"):
            continue
        selected_row = selected.pop(str(check["id"]), None)
        if selected_row is None:
            selected_row = unrecorded_check_result(check)
        elif check.get("outcome") == "BLOCKED" and not str(
            selected_row.get("status")
        ).startswith("BLOCKED"):
            selected_row = {
                **selected_row,
                "recorded_status": selected_row.get("status"),
                "status": "BLOCKED_BY_PREREQUISITE",
            }
            # The raw contract still describes the recorded UNVERIFIED row.
            # A presentation of its logical prerequisite outcome needs its own
            # contract rather than a contradictory inherited verdict.
            selected_row.pop("contract", None)
            selected_row.pop("path_signature", None)
            selected_row.pop("operator_explanation", None)
        output.append(selected_row)
    return [*output, *selected.values()]
