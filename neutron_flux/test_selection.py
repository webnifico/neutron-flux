from __future__ import annotations

import dataclasses
import difflib
from collections import defaultdict

from .check_plan import migration_baseline_specs
from .errors import SuiteError
from .models import Plan, TestSpec

_CONTROL_SCENARIO = "Controller readiness"
_STATEFUL_SCENARIO_OPERATIONS = frozenset(
    {
        "security-allow",
        "security-restore",
        "server-stop",
        "server-start",
        "static-route-install",
        "static-route-withdraw",
        "static-route-restore",
    }
)


def _same_stateful_scope(first: TestSpec, second: TestSpec) -> bool:
    return bool(
        first.scenario
        and first.scenario == second.scenario
        and first.family == second.family
        and tuple(first.dependencies) == tuple(second.dependencies)
        and first.metadata.get("pair_scope_id") == second.metadata.get("pair_scope_id")
    )


def select_plan_tests(
    plan: Plan, requested_ids: list[str], *, include_derived: bool = False
) -> Plan:
    """Return an exact, dependency-complete, resource-pruned execution plan.

    In an explicitly zoned plan, a base planner ID resolves to every concrete
    per-zone or cross-zone instance in the selected zone scope. A concrete
    zoned ID continues to select only that exact instance.
    """

    requested = list(dict.fromkeys(str(item).strip() for item in requested_ids))
    if not requested or any(not item for item in requested):
        raise SuiteError("Saved test selection requires one or more non-empty test IDs")
    by_id = {item.id: item for item in plan.tests}
    selectable = {
        item.id: item for item in plan.tests if item.scenario != _CONTROL_SCENARIO
    }

    resolved_requested: list[str] = []
    unknown: list[str] = []
    for requested_id in requested:
        if requested_id in selectable:
            resolved_requested.append(requested_id)
            continue
        scoped_matches = [
            item.id
            for item in selectable.values()
            if str((item.metadata or {}).get("base_test_id") or "") == requested_id
        ]
        if scoped_matches:
            resolved_requested.extend(scoped_matches)
        else:
            unknown.append(requested_id)
    resolved_requested = list(dict.fromkeys(resolved_requested))

    if unknown:
        aliases = {
            str((item.metadata or {}).get("base_test_id") or "")
            for item in selectable.values()
            if str((item.metadata or {}).get("base_test_id") or "")
        }
        candidates = sorted(set(selectable) | aliases)
        details: list[str] = []
        for item in unknown:
            matches = difflib.get_close_matches(item, candidates, n=3, cutoff=0.45)
            suffix = f"; closest: {', '.join(matches)}" if matches else ""
            if item in by_id and by_id[item].scenario == _CONTROL_SCENARIO:
                suffix = "; controller checks are included automatically"
            details.append(f"{item}{suffix}")
        raise SuiteError("Unknown or non-selectable test ID(s): " + " | ".join(details))

    selected = set(resolved_requested)
    automatic: set[str] = set()
    derived_transition_ids: set[str] = set()

    if include_derived:
        # Exact base IDs in a coordinated host-pair plan resolve to the same
        # path in initial and opposite placement slots. Retain the single
        # pre-planned transition between those selected placements and add
        # the authoritative ICMP/TCP/UDP baseline needed to make migration
        # eligible.  Concrete IDs that select only one placement remain
        # concrete and never widen to another placement.
        selected_specs = [by_id[item_id] for item_id in selected]
        batch_placements: dict[str, set[str]] = defaultdict(set)
        for item in selected_specs:
            batch = str((item.metadata or {}).get("workflow_batch") or "")
            placement = str((item.metadata or {}).get("pair_placement") or "")
            if batch and placement and item.operation != "pair-transition":
                batch_placements[batch].add(placement)

        for transition in plan.tests:
            if transition.operation != "pair-transition":
                continue
            metadata = transition.metadata or {}
            batch = str(metadata.get("workflow_batch") or "")
            destination = str(metadata.get("pair_placement") or "")
            source = str(metadata.get("transition_from") or "")
            placements = batch_placements.get(batch, set())
            if not batch or source not in placements or destination not in placements:
                continue
            if transition.id not in selected:
                selected.add(transition.id)
                automatic.add(transition.id)
                derived_transition_ids.add(transition.id)
            for baseline in plan.tests:
                baseline_meta = baseline.metadata or {}
                if (
                    bool(migration_baseline_specs([baseline]))
                    and baseline_meta.get("workflow_batch") == batch
                    and baseline_meta.get("pair_placement") == source
                ):
                    if baseline.id not in selected:
                        selected.add(baseline.id)
                        automatic.add(baseline.id)

    queue = list(selected)
    while queue:
        current_id = queue.pop(0)
        current = by_id[current_id]
        additions = (
            []
            if current.id in derived_transition_ids
            else [*current.requires, *current.requires_pass]
        )
        if (
            include_derived
            and current.operation == "probe"
            and current.protocol == "tcp"
            and current.expectation == "reachable"
        ):
            # Bidirectional measurements require a freshly executed reverse TCP
            # baseline. Match concrete groups/sides so this cannot widen scope
            # to another pair, placement, cycle, family or subnet.
            additions.extend(
                item.id
                for item in plan.tests
                if item.operation == "probe"
                and item.protocol == "tcp"
                and item.expectation == "reachable"
                and item.authoritative
                and item.metadata.get("pair_scope_id")
                == current.metadata.get("pair_scope_id")
                and item.family == current.family
                and item.source_group_id == current.destination_group_id
                and item.destination_group_id == current.source_group_id
                and item.source_side == current.destination_side
                and item.destination_side == current.source_side
                and item.source_subnet_id == current.destination_subnet_id
                and item.destination_subnet_id == current.source_subnet_id
            )
        if current.operation in _STATEFUL_SCENARIO_OPERATIONS or (
            current.category == "router-static-routing"
            and current.operation != "static-route-baseline"
        ):
            additions.extend(
                item.id for item in plan.tests if _same_stateful_scope(current, item)
            )
        if current.operation == "fip-withdraw":
            additions.extend(
                item.id
                for item in plan.tests
                if _same_stateful_scope(current, item)
                and item.operation == "fip-return"
            )
        for dependency_id in additions:
            if dependency_id not in by_id:
                raise SuiteError(
                    f"Test {current.id} requires missing planned test {dependency_id}"
                )
            if dependency_id not in selected:
                selected.add(dependency_id)
                automatic.add(dependency_id)
                queue.append(dependency_id)

    for item in plan.tests:
        if item.scenario == _CONTROL_SCENARIO and item.id not in selected:
            selected.add(item.id)
            automatic.add(item.id)

    tests = [
        (
            dataclasses.replace(
                item,
                requires=[value for value in item.requires if value in selected],
                requires_pass=[
                    value for value in item.requires_pass if value in selected
                ],
            )
            if item.id in derived_transition_ids
            else item
        )
        for item in plan.tests
        if item.id in selected
    ]
    group_ids = {dependency for item in tests for dependency in item.dependencies}
    provider_groups = [item for item in plan.provider_groups if item.id in group_ids]
    tenant_groups = [item for item in plan.tenant_groups if item.id in group_ids]
    warnings = list(plan.warnings)
    warnings.append(
        "Exact test selection includes applicable performance and migration checks; concurrent load stays disabled"
        if include_derived
        else "Exact test selection suppresses derived performance, concurrent-load, "
        "placement, and migration phases; only selected checks, automatic "
        "controller setup, and cloud-operation-safe prerequisites execute"
    )
    if resolved_requested != requested:
        warnings.append(
            "Saved base test IDs were expanded to concrete tests in the selected "
            "availability-zone or host-pair scope"
        )
    return dataclasses.replace(
        plan,
        provider_groups=provider_groups,
        tenant_groups=tenant_groups,
        tests=tests,
        warnings=warnings,
        host_qualification=(
            plan.host_qualification
            if any(item.metadata.get("pair_scope_id") for item in tests)
            else None
        ),
        selection_mode="exact",
        requested_test_ids=requested,
        automatically_included_test_ids=[
            item.id for item in tests if item.id in automatic
        ],
    )


__all__ = ["select_plan_tests"]
