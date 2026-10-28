from __future__ import annotations

from typing import Any

from .models import Plan, TestResult, TestSpec
from .result_contract import typed_verdict


def _outcome(result: TestResult | None) -> str:
    if result is None:
        return "NEVER_RAN"
    if (result.details or {}).get("coverage_outcome") == "NEVER_RAN":
        return "NEVER_RAN"
    verdict = typed_verdict(result)
    if verdict == "PASS":
        return "PASSED"
    if verdict in {"FAIL", "ERROR"}:
        return "FAILED"
    if verdict == "INAPPLICABLE":
        return "INAPPLICABLE"
    if verdict == "NOT_RUN":
        return "NEVER_RAN"
    if verdict == "UNVERIFIED":
        return "OBSERVED" if result.expected == "observation" else "INCONCLUSIVE"
    return "BLOCKED"


def materialize_missing_results(reporter: Any, plan: Plan | None) -> int:
    """Create an explainable terminal record for every unaccounted-for run test."""

    if plan is None or reporter.action != "run":
        return 0
    recorded = 0
    for spec in plan.tests:
        # A few compatibility callers use opaque placeholders when they only
        # need a planned-count summary. Those are not executable plan rows.
        if not hasattr(spec, "id"):
            continue
        if reporter.has_result(spec.id):
            continue
        if reporter.interrupted:
            status = "NOT_RUN_CANCELLED"
            message = (
                "The run ended before this planned validation started: "
                f"{reporter.cancellation_reason or 'operator cancellation'}"
            )
        elif reporter.setup_failed or reporter.error:
            status = "BLOCKED_BY_SETUP_ERROR"
            message = (
                "The run ended before this planned validation started because "
                f"setup or execution failed: {reporter.error or 'see setup failures'}"
            )
        else:
            status = "BLOCKED_BY_PREREQUISITE"
            message = (
                "The executor produced no terminal record for this planned "
                "validation; it is recorded explicitly as never run"
            )
        reporter.result(
            spec.id,
            spec.category,
            status,
            message,
            family=spec.family,
            expected=spec.expectation,
            observed="not-run",
            authoritative=False,
            details={
                **dict(spec.metadata or {}),
                "dependencies": list(spec.dependencies),
                "coverage_outcome": "NEVER_RAN",
                "reason_authority": "neutron-flux execution ledger",
            },
            display_name=spec.display_name,
            scenario=spec.scenario,
        )
        recorded += 1
    return recorded


def build_coverage_ledger(
    plan: Plan | None,
    results: list[TestResult],
    *,
    completed_pair_cycles: set[str] | None = None,
) -> list[dict[str, Any]]:
    result_by_id = {result.test_id: result for result in results}
    rows: list[dict[str, Any]] = []
    if plan is not None:
        for spec in plan.tests:
            if not hasattr(spec, "id"):
                continue
            result = result_by_id.get(spec.id)
            rows.append(
                {
                    "kind": "test",
                    "id": spec.id,
                    "category": spec.category,
                    "phase": spec.phase,
                    "family": spec.family,
                    "dependencies": list(spec.dependencies),
                    "outcome": _outcome(result),
                    "status": result.status if result is not None else None,
                    "reason": (
                        result.message
                        if result is not None
                        else "No terminal result was recorded"
                    ),
                    "result_id": result.test_id if result is not None else None,
                }
            )
        qualification = plan.host_qualification
        completed = completed_pair_cycles or set()
        scopes: dict[str, list[TestSpec]] = {}
        for spec in plan.tests:
            scope = getattr(spec, "metadata", {}).get("pair_scope_id")
            if scope:
                scopes.setdefault(str(scope), []).append(spec)
        if scopes:
            for scope, specs in scopes.items():
                outcomes = [_outcome(result_by_id.get(spec.id)) for spec in specs]
                outcome = next(
                    (
                        value
                        for value in (
                            "FAILED",
                            "NEVER_RAN",
                            "BLOCKED",
                            "INCONCLUSIVE",
                            "OBSERVED",
                        )
                        if value in outcomes
                    ),
                    "INAPPLICABLE"
                    if all(value == "INAPPLICABLE" for value in outcomes)
                    else "PASSED",
                )
                metadata = specs[0].metadata
                rows.append(
                    {
                        "kind": "host-pair-placement",
                        "id": scope,
                        "category": "host-qualification",
                        "phase": "host-qualification",
                        "family": None,
                        "dependencies": sorted(
                            {item for spec in specs for item in spec.dependencies}
                        ),
                        "outcome": outcome,
                        "status": outcome,
                        "complete": all(spec.id in result_by_id for spec in specs),
                        "reason": "Aggregated from the actual planned test verdicts",
                        "result_id": None,
                        "host_pair_id": metadata["host_qualification_pair_id"],
                        "source_host": metadata["requested_source_host"],
                        "destination_host": metadata["requested_destination_host"],
                        "placement": metadata["pair_placement"],
                        "cycle": metadata["host_qualification_cycle"],
                    }
                )
            return rows
        if qualification is not None:
            qualification_groups = sorted(
                {
                    spec.dependencies[0]
                    for spec in plan.tests
                    if hasattr(spec, "dependencies")
                    and len(spec.dependencies) == 1
                    and spec.phase != "host-qualification"
                    and spec.expectation == "reachable"
                    and spec.operation in {"probe", "mtu-scenario"}
                    and any(
                        group.id == spec.dependencies[0] and group.kind == "provider"
                        for group in plan.provider_groups
                    )
                }
            )
            for pair in qualification.pairs:
                topology_groups = (
                    qualification_groups
                    if pair.eligible and qualification_groups
                    else ["no-topology"]
                )
                for cycle in range(1, qualification.cycles + 1):
                    for group_id in topology_groups:
                        unit_id = f"{group_id}:{pair.pair_id}:C{cycle}"
                        if not pair.eligible:
                            outcome = "BLOCKED"
                            reason = " | ".join(pair.blockers) or "Pair is not eligible"
                        elif unit_id in completed:
                            outcome = "COMPLETED"
                            reason = (
                                "Topology/pair/cycle execution reached a durable "
                                "terminal checkpoint"
                            )
                        else:
                            outcome = "NEVER_RAN"
                            reason = (
                                "Topology/pair/cycle did not reach a durable "
                                "terminal checkpoint"
                            )
                        rows.append(
                            {
                                "kind": "host-pair-cycle",
                                "id": unit_id,
                                "category": "host-qualification",
                                "phase": "host-qualification",
                                "family": None,
                                "dependencies": [group_id],
                                "outcome": outcome,
                                "status": pair.status,
                                "reason": reason,
                                "result_id": None,
                                "host_pair_id": pair.pair_id,
                                "topology_group_id": group_id,
                                "source_host": pair.source_host,
                                "destination_host": pair.destination_host,
                                "cycle": cycle,
                            }
                        )
    return rows


__all__ = ["build_coverage_ledger", "materialize_missing_results"]
