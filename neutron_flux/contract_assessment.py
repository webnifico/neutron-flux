from __future__ import annotations

from typing import Any

_PASS_STATUSES = {"PASS"}
_FAIL_STATUSES = {"FAIL"}
_BLOCKED_STATUSES = {
    "BLOCKED_BY_SETUP_ERROR",
    "BLOCKED_BY_PREREQUISITE",
    "NOT_RUN_CANCELLED",
}


def _contract_outcome(status: str) -> str:
    if status in _PASS_STATUSES:
        return "met"
    if status in _FAIL_STATUSES:
        return "violated"
    if status == "ERROR":
        return "not-evaluated"
    if status == "NOT_APPLICABLE":
        return "not-applicable"
    if status in _BLOCKED_STATUSES:
        return "not-evaluated"
    return "unverified"


def _execution_outcome(status: str) -> str:
    if status in {"PASS", "FAIL", "UNVERIFIED"}:
        return "completed"
    if status == "ERROR":
        return "execution-error"
    if status == "NOT_APPLICABLE":
        return "not-applicable"
    return "not-completed"


def _path_health(status: str) -> str:
    if status == "PASS":
        return "contract-met"
    if status == "FAIL":
        return "contract-violated"
    if status == "ERROR":
        return "not-assessed-execution-error"
    if status == "NOT_APPLICABLE":
        return "not-applicable"
    return "not-authoritatively-assessed"


def build_contract_assessment(
    *,
    status: str,
    expected: str | None,
    observed: str | None,
    authoritative: bool | None,
    details: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build the standard operator evidence envelope for every result."""

    evidence = details or {}
    mechanism = evidence.get("mechanism_assessment")
    if mechanism is None:
        mtu = evidence.get("mtu_contract")
        if isinstance(mtu, dict):
            mechanism = {
                "name": "mtu-path-protection",
                "status": mtu.get("mechanism_status")
                or mtu.get("pmtud_status")
                or "not-separately-assessed",
            }
    execution = evidence.get("execution")
    if not isinstance(execution, dict):
        execution = {"status": _execution_outcome(status)}
    path_health = evidence.get("path_health")
    if not isinstance(path_health, dict):
        path_health = {"status": _path_health(status)}
    attribution = evidence.get("attribution")
    if not isinstance(attribution, dict):
        attribution = {
            "scope": evidence.get("placement_scope") or "result",
            "confidence": (
                "authoritative-observation" if authoritative is True else "limited"
            ),
        }
    return {
        "contract": {
            "expected": expected,
            "observed": observed,
            "outcome": _contract_outcome(status),
        },
        "observation": {
            "status": "recorded" if observed is not None else "not-recorded",
            "value": observed,
        },
        "authority": {
            "authoritative": bool(authoritative),
            "classification": (
                "authoritative"
                if authoritative is True
                else "non-authoritative"
                if authoritative is False
                else "not-declared"
            ),
        },
        "mechanism": mechanism or {"status": "not-separately-assessed"},
        "execution": execution,
        "path_health": path_health,
        "attribution": attribution,
    }


def with_contract_assessment(
    details: dict[str, Any] | None,
    *,
    status: str,
    expected: str | None,
    observed: str | None,
    authoritative: bool | None,
) -> dict[str, Any]:
    enriched = dict(details or {})
    generated = build_contract_assessment(
        status=status,
        expected=expected,
        observed=observed,
        authoritative=authoritative,
        details=enriched,
    )
    supplied = enriched.get("assessment")
    if supplied is not None:
        if not isinstance(supplied, dict):
            raise ValueError("Result assessment must be an object")
        supplied_contract = supplied.get("contract")
        if not isinstance(supplied_contract, dict):
            raise ValueError("Result assessment.contract must be an object")
        supplied_outcome = supplied_contract.get("outcome")
        generated_outcome = generated["contract"]["outcome"]
        if supplied_outcome != generated_outcome:
            raise ValueError(
                "Result status contradicts assessment contract outcome: "
                f"status={status!r}, outcome={supplied_outcome!r}, "
                f"expected_outcome={generated_outcome!r}"
            )
    else:
        enriched["assessment"] = generated
    return enriched


__all__ = ["build_contract_assessment", "with_contract_assessment"]
