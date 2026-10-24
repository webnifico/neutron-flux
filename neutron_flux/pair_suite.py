"""Execute the complete planned network suite within each selected host pair."""

from __future__ import annotations

import dataclasses
import hashlib
from collections import defaultdict
from typing import Any

from .cancellation import raise_if_cancelled
from .check_resume import conditional_pending
from .errors import SetupFailureError, SuiteError
from .executor import AdaptiveExecutor
from .models import Plan, PlannedGroup, TestSpec
from .network_contract import PROVIDER_NETWORK, canonical_group_kind
from .pair_executor import PairScopeExecutor as PairScopeExecutor
from .pair_executor import _remap as _remap


def _provider_scope(lane: Plan) -> tuple[Any, ...] | None:
    if (
        not lane.tests
        or not lane.groups
        or any(
            canonical_group_kind(group.kind) != PROVIDER_NETWORK
            for group in lane.groups
        )
    ):
        return None
    if any(
        spec.operation.startswith("fip-") or spec.metadata.get("require_floating_ip")
        for spec in lane.tests
    ):
        return None
    scope = lane.tests[0].metadata
    return tuple(
        scope.get(key)
        for key in (
            "host_qualification_pair_id",
            "host_qualification_cycle",
            "requested_source_host",
            "requested_destination_host",
            "qualification_profile",
            "inventory_fingerprint",
        )
    )


def provider_handoff_group(current: Plan, following: Plan) -> str | None:
    """Find one unchanged provider topology within the exact same pair/cycle."""
    scope = _provider_scope(current)
    if scope is None or scope != _provider_scope(following):
        return None
    before = {group.id: group for group in current.groups}
    after = {group.id: group for group in following.groups}
    shared = before.keys() & after.keys()
    if len(shared) != 1:
        return None
    group_id = next(iter(shared))
    fields = (
        "network_id",
        "subnet_ids",
        "families",
        "segment_id",
        "physical_network",
        "relationship",
    )
    if any(
        getattr(before[group_id], field) != getattr(after[group_id], field)
        for field in fields
    ):
        return None
    return group_id


def provider_reuse_lanes(lanes: list[Plan], config: Any) -> list[Plan]:
    """Move only independent provider lifetimes to share one verified endpoint."""
    if (
        config.resume_run_id
        or config.selective_run
        or (config.performance_enabled and config.performance_max_paths > 0)
    ):
        return lanes
    owners = {spec.id: index for index, lane in enumerate(lanes) for spec in lane.tests}
    independent = {
        id(lane)
        for index, lane in enumerate(lanes)
        if _provider_scope(lane) is not None
        and all(
            owners.get(required, index) == index
            for spec in lane.tests
            for required in [*spec.requires, *spec.requires_pass]
        )
    }
    pending = list(lanes)
    ordered: list[Plan] = []
    while pending:
        selected = pending[0]
        if ordered and id(ordered[-1]) in independent:
            selected = next(
                (
                    lane
                    for lane in pending
                    if id(lane) in independent
                    and provider_handoff_group(ordered[-1], lane) is not None
                ),
                selected,
            )
        ordered.append(selected)
        pending.remove(selected)
    return ordered


def is_pair_suite(plan: Plan) -> bool:
    return any(spec.metadata.get("pair_scope_id") for spec in plan.tests)


def expand_pair_suite(plan: Plan, *, coordinated: bool = True) -> Plan:
    """Materialize all host placements before approval, boot, or selection.

    Control setup remains run-wide. Each network spec and its prerequisites
    retain their original meaning, with a deterministic scope and group map.
    """
    qualification = plan.host_qualification
    if qualification is None or is_pair_suite(plan):
        return plan
    controls = [spec for spec in plan.tests if spec.scenario == "Controller readiness"]
    network_specs = [spec for spec in plan.tests if spec not in controls]
    providers: list[PlannedGroup] = []
    tenants: list[PlannedGroup] = []
    tests = list(controls)
    for pair in qualification.pairs:
        # Slots are fixed before approval. Their actual host relation is resolved
        # from verified endpoints at runtime, never by an extra normalization move.
        placements = [("initial", pair.source_host, pair.destination_host)]
        if not pair.same_host:
            placements.append(("opposite", pair.source_host, pair.source_host))
        zone_by_host = {
            pair.source_host: pair.source_availability_zone,
            pair.destination_host: pair.destination_availability_zone,
        }
        for cycle in range(1, qualification.cycles + 1):
            for placement, first, second in placements:
                scope = f"{pair.pair_id}-C{cycle}-{placement.upper()}"
                token = hashlib.sha256(scope.encode()).hexdigest()[:16]
                group_map = {
                    group.id: f"{group.id}@pair-{token}" for group in plan.groups
                }
                test_map = {spec.id: f"{scope}-{spec.id}" for spec in network_specs}
                metadata = {
                    "pair_scope_id": scope,
                    "pair_placement": placement,
                    "pair_placement_policy": "initial-opposite-v1",
                    "pair_selected_host_zones": dict(zone_by_host),
                    "pair_initial_host_hints": [
                        pair.source_host,
                        pair.destination_host,
                    ],
                    "host_qualification": True,
                    "host_qualification_pair_id": pair.pair_id,
                    "host_qualification_cycle": cycle,
                    "host_qualification_total_cycles": qualification.cycles,
                    "qualification_profile": qualification.profile,
                    "qualification_strategy": qualification.strategy,
                    "requested_source_host": pair.source_host,
                    "requested_destination_host": pair.destination_host,
                    "pair_scope_hosts": [first, second],
                    "pair_scope_zones": [zone_by_host[first], zone_by_host[second]],
                    "pair_scope_blockers": list(pair.blockers),
                    "pair_scope_eligible": pair.eligible,
                    "same_host": first == second,
                    "same_availability_zone": zone_by_host[first]
                    == zone_by_host[second],
                    "inventory_fingerprint": qualification.inventory_fingerprint,
                }
                for group in plan.groups:
                    clone = dataclasses.replace(
                        group,
                        id=group_map[group.id],
                        metadata={
                            **_remap(group.metadata, group_map),
                            **metadata,
                            "base_group_id": group.id,
                            "target_hosts": {"A": first, "B": second},
                            "target_availability_zones": {
                                "A": zone_by_host[first],
                                "B": zone_by_host[second],
                            },
                        },
                    )
                    (providers if group in plan.provider_groups else tenants).append(
                        clone
                    )
                for spec in network_specs:
                    # Reciprocal traffic must share a batch and host assignment.
                    # Its source/destination fields still preserve direction.
                    tests.append(
                        dataclasses.replace(
                            spec,
                            id=test_map[spec.id],
                            dependencies=[group_map[item] for item in spec.dependencies]
                            if spec.phase != "cross"
                            else sorted(group_map[item] for item in spec.dependencies),
                            source_group_id=group_map.get(
                                spec.source_group_id, spec.source_group_id
                            )
                            if spec.source_group_id is not None
                            else None,
                            destination_group_id=group_map.get(
                                spec.destination_group_id, spec.destination_group_id
                            )
                            if spec.destination_group_id is not None
                            else None,
                            requires=[
                                test_map.get(item, item) for item in spec.requires
                            ],
                            requires_pass=[
                                test_map.get(item, item) for item in spec.requires_pass
                            ],
                            metadata={
                                **_remap(spec.metadata, {**group_map, **test_map}),
                                **metadata,
                                "base_test_id": spec.id,
                            },
                        )
                    )
    warnings = [
        *plan.warnings,
        "Host selectors constrain every network-test VM. Each topology tests its "
        "verified initial placement, then the opposite relation after one endpoint "
        "transition. There is no third placement. The probe controller is shared.",
    ]
    expanded = dataclasses.replace(
        plan,
        provider_groups=providers,
        tenant_groups=tenants,
        tests=tests,
        warnings=warnings,
    )

    from .pair_workflow import coordinate_pair_plan

    return coordinate_pair_plan(expanded)


def pair_scope_plans(plan: Plan) -> list[Plan]:
    scopes: dict[str, list[TestSpec]] = defaultdict(list)
    for spec in plan.tests:
        scope = spec.metadata.get("pair_scope_id")
        if scope:
            scopes[str(scope)].append(spec)
    output = []
    for specs in scopes.values():
        group_ids = {item for spec in specs for item in spec.dependencies}
        output.append(
            dataclasses.replace(
                plan,
                tests=list(specs),
                provider_groups=[
                    group for group in plan.provider_groups if group.id in group_ids
                ],
                tenant_groups=[
                    group for group in plan.tenant_groups if group.id in group_ids
                ],
            )
        )
    return output


def estimate_pair_suite(planner: Any, plan: Plan) -> None:
    """Budget only the current initial/opposite topology lifetimes."""
    from .pair_workflow import estimate_coordinated_pair_suite

    validate_pair_execution_plan(plan)
    estimate_coordinated_pair_suite(planner, plan)


def validate_pair_execution_plan(plan: Plan) -> None:
    """Reject old/mixed contracts before any endpoint or controller is created."""
    if plan.host_qualification is not None and not is_pair_suite(plan):
        raise SuiteError(
            "Host-pair plan is not expanded under the current placement policy; "
            "start a fresh run"
        )
    if any(
        spec.metadata.get("pair_scope_id")
        and (
            spec.metadata.get("pair_placement_policy") != "initial-opposite-v1"
            or not spec.metadata.get("coordinated_pair")
            or spec.metadata.get("pair_placement") not in {"initial", "opposite"}
        )
        for spec in plan.tests
    ):
        raise SuiteError(
            "Legacy host-pair placement plan cannot be resumed under the "
            "two-placement policy; start a fresh run"
        )


def run_pair_suite(
    config: Any,
    plan: Plan,
    builder: Any,
    reporter: Any,
    cleanup: Any,
    state_store: Any,
    checkpoint: Any,
) -> None:
    from .pair_workflow import CoordinatedPairExecutor, workflow_plans

    validate_pair_execution_plan(plan)
    lanes = provider_reuse_lanes(workflow_plans(plan), config)
    performance_sessions: dict[str, Any] = {}
    retained_owner = None
    try:
        for index, lane in enumerate(lanes):
            raise_if_cancelled()
            scope = lane.tests[0].metadata
            reporter.logger.section(
                f"Full network suite: {scope['requested_source_host']} ↔ {scope['requested_destination_host']} · {scope['pair_placement']} · cycle {scope['host_qualification_cycle']}"
            )
            lane_config = (
                dataclasses.replace(
                    config, performance_enabled=False, fabric_scale_enabled=False
                )
                if scope["qualification_profile"] == "connectivity"
                else config
            )
            executor = CoordinatedPairExecutor(
                lane_config, lane, builder, reporter, cleanup, state_store, checkpoint
            )
            executor.performance_sessions = performance_sessions
            if retained_owner is not None:
                previous_owner = retained_owner
                executor.active = previous_owner.active
                executor.provider_handoff_group_ids = set(executor.active)
                # Publish cleanup ownership before detaching the old owner so
                # interruption during the transfer still releases every endpoint.
                retained_owner = executor
                previous_owner.active = {}
            if not scope["pair_scope_eligible"]:
                executor._mark_specs_unavailable(
                    lane.tests,
                    " | ".join(scope["pair_scope_blockers"])
                    or "Requested hosts are ineligible",
                    blocked=True,
                )
                executor._release_all()
                retained_owner = None
                executor._refresh_checkpoint()
                continue
            if all(
                reporter.has_result(spec.id) for spec in lane.tests
            ) and not conditional_pending(reporter, lane.tests, include_load=False):
                executor._release_all()
                retained_owner = None
                continue
            if (
                index + 1 < len(lanes)
                and not config.resume_run_id
                and not config.selective_run
            ):
                following = lanes[index + 1]
                if following.tests[0].metadata["pair_scope_eligible"] and not all(
                    reporter.has_result(spec.id) for spec in following.tests
                ):
                    executor.handoff_group_id = provider_handoff_group(lane, following)
            # Own this executor before it can retain resources or be interrupted.
            retained_owner = executor
            try:
                executor.run()
            except SetupFailureError as exc:
                reporter.logger.log(str(exc), "ERROR")
            retained_owner = executor if executor.active else None
    finally:
        if retained_owner is not None:
            retained_owner._release_all()
    if config.fabric_scale_enabled and not config.selective_run:
        from .check_ledger import check_ledger
        from .concurrent_load import ConcurrentLoadRunner

        load_outcomes = {row["id"]: row["outcome"] for row in check_ledger(reporter)}
        for lane in pair_scope_plans(plan):
            if (
                lane.tests[0].metadata["qualification_profile"] == "connectivity"
                or not lane.tests[0].metadata["pair_scope_eligible"]
            ):
                continue
            load_ids = {
                s.metadata.get("check_bindings", {}).get("load") for s in lane.tests
            }
            if not any(
                load_outcomes.get(identity) == "PENDING"
                for identity in load_ids
                if identity
            ):
                continue
            executor = PairScopeExecutor(
                config, lane, builder, reporter, cleanup, state_store, checkpoint
            )
            for group in lane.groups:
                executor._set_hosts(group.id, executor._hosts_for(("A", "B")))
            lane.provider_groups = [executor.groups[g.id] for g in lane.provider_groups]
            lane.tenant_groups = [executor.groups[g.id] for g in lane.tenant_groups]
            with executor.performance_lock:
                ConcurrentLoadRunner(executor).run()
    # One global reconciliation includes the controller and every placement.
    AdaptiveExecutor(
        config, plan, builder, reporter, cleanup, state_store, checkpoint
    )._validate_plan_consistency()
    executed = [
        item
        for item in reporter.results
        if item.scenario != "Controller readiness"
        and item.status in {"PASS", "FAIL", "ERROR", "UNVERIFIED"}
    ]
    if not executed:
        raise SetupFailureError(
            "No network validation executed in any requested host-pair placement"
        )
