from __future__ import annotations

import dataclasses
from collections import Counter
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.coverage_ledger import _outcome, build_coverage_ledger
from neutron_flux.errors import SuiteError
from neutron_flux.executor import AdaptiveExecutor
from neutron_flux.host_qualification import HostQualificationPlanner
from neutron_flux.models import RuntimeGroup
from neutron_flux.pair_suite import (
    PairScopeExecutor,
    estimate_pair_suite,
    expand_pair_suite,
    pair_scope_plans,
)
from neutron_flux.planning import Planner
from neutron_flux.test_selection import select_plan_tests

from ._shared import build_plan, endpoint
from .test_host_qualification import _Inventory, _service


def full_plan(config_factory, discovery, tmp_path, **settings):
    settings = {
        "target_host_pairs": [("hyper001", "hyper002"), ("hyper003", "hyper004")],
        **settings,
    }
    config = config_factory(**settings)
    base = build_plan(config, discovery, tmp_path)
    inventory = _Inventory(
        [_service(f"hyper00{index}", "az1") for index in range(1, 5)]
    )
    base.host_qualification = HostQualificationPlanner(
        config, discovery, base, inventory, mock.Mock()
    ).build()
    return config, base, expand_pair_suite(base)


@pytest.mark.parametrize("cycles", [1, 2])
def test_every_test_and_prerequisite_has_all_requested_placements(
    config_factory, discovery_fixture, tmp_path, cycles
):
    _, base, expanded = full_plan(
        config_factory, discovery_fixture, tmp_path, qualification_cycles=cycles
    )
    lanes = pair_scope_plans(expanded)
    assert len(lanes) == 4 * cycles
    originals = [spec for spec in base.tests if spec.scenario != "Controller readiness"]
    ids = {spec.id for spec in expanded.tests}
    assert len(ids) == len(expanded.tests)
    assert Counter(spec.operation for spec in originals) == Counter(
        spec.operation for spec in lanes[0].tests
    )
    assert [
        spec for spec in expanded.tests if spec.scenario == "Controller readiness"
    ] == [spec for spec in base.tests if spec.scenario == "Controller readiness"]
    observed = []
    for lane in lanes:
        assert Counter(
            spec.metadata["base_test_id"]
            for spec in lane.tests
            if spec.operation != "pair-transition"
        ) == Counter(spec.id for spec in originals)
        groups = {group.id for group in lane.groups}
        for spec in lane.tests:
            assert set(spec.dependencies) <= groups
            assert set(spec.requires + spec.requires_pass) <= ids
            assert spec.source_group_id is None or spec.source_group_id in groups
            assert (
                spec.destination_group_id is None or spec.destination_group_id in groups
            )
        observed.append(tuple(lane.tests[0].metadata["pair_scope_hosts"]))
    assert set(observed) == {
        ("hyper001", "hyper001"),
        ("hyper001", "hyper002"),
        ("hyper003", "hyper003"),
        ("hyper003", "hyper004"),
    }
    assert expand_pair_suite(expanded) is expanded
    assert all("pair_scope_id" not in spec.metadata for spec in base.tests)


def test_exact_and_base_selection_keep_scopes_and_prerequisites(
    config_factory, discovery_fixture, tmp_path
):
    _, _, plan = full_plan(config_factory, discovery_fixture, tmp_path)
    lane = pair_scope_plans(plan)[0]
    spec = next(spec for spec in lane.tests if spec.operation == "security-restore")
    selected = select_plan_tests(plan, [spec.id])
    assert selected.host_qualification is plan.host_qualification
    assert len(pair_scope_plans(selected)) == 1
    assert {spec.operation for spec in selected.tests} >= {
        "security-deny",
        "security-allow",
        "security-restore",
    }
    assert (
        len(pair_scope_plans(select_plan_tests(plan, [spec.metadata["base_test_id"]])))
        == 4
    )


def test_scope_estimates_sum_work_and_bound_peak_resources(
    config_factory, discovery_fixture, tmp_path
):
    config, _, plan = full_plan(
        config_factory,
        discovery_fixture,
        tmp_path,
        compute_host_connectivity_enabled=False,
    )
    planner = Planner(config, discovery_fixture, mock.Mock())
    from neutron_flux.pair_workflow import workflow_plans

    workflows = workflow_plans(plan)
    estimate_pair_suite(planner, plan)
    assert plan.estimated["topology_lifetimes"] == len(workflows)
    assert plan.estimated["endpoint_vm_boots"] == 3 * len(workflows)
    assert plan.estimated["endpoint_recreations"] == len(workflows)
    assert plan.estimated["targeted_migrations_maximum"] == 0
    assert plan.estimated["peak_endpoint_instances"] == 2
    assert plan.estimated["functional_test_results"] == len(plan.tests)
    assert plan.estimated["host_pair_placement_suites"] == 4


def executor_for(lane, config):
    reporter = mock.Mock()
    reporter.plan = dataclasses.replace(lane, tests=list(lane.tests))
    reporter.results = []
    builder = mock.Mock()
    builder.runtime_groups = []
    builder.group_failures = {}
    return PairScopeExecutor(
        config, lane, builder, reporter, mock.Mock(), mock.Mock(), mock.Mock()
    )


def test_cross_topology_rebuilds_retained_endpoint_on_wrong_pair_member(
    config_factory, discovery_fixture, tmp_path
):
    config, _, plan = full_plan(config_factory, discovery_fixture, tmp_path)
    lane = pair_scope_plans(plan)[0]
    executor = executor_for(lane, config)
    spec = next(spec for spec in lane.tests if len(spec.dependencies) == 2)
    first, second = spec.dependencies
    ep = dataclasses.replace(endpoint(), side="A", host="hyper001")
    executor.active[second] = RuntimeGroup(
        executor.groups[second], "net", "network", [], None, [ep], None, {}
    )

    def release(group_id):
        executor.active.pop(group_id)

    executor._release = mock.Mock(side_effect=release)
    with mock.patch.object(AdaptiveExecutor, "_ensure"):
        executor._ensure((first, second))
    executor._release.assert_called_once_with(second)
    assert executor.groups[first].metadata["target_hosts"] == {"A": "hyper001"}
    assert executor.groups[second].metadata["target_hosts"] == {"A": "hyper002"}


def test_wrong_host_cannot_be_accepted_and_current_binding_is_verified(
    config_factory, discovery_fixture, tmp_path
):
    config, _, plan = full_plan(config_factory, discovery_fixture, tmp_path)
    lane = pair_scope_plans(plan)[0]
    executor = executor_for(lane, config)
    group = lane.groups[0]
    ep = dataclasses.replace(
        endpoint(), side="A", host="hyper003", availability_zone="az1"
    )
    runtime = RuntimeGroup(group, "net", "network", [], None, [ep], None, {})
    with pytest.raises(SuiteError, match="placement mismatch"):
        executor._verify_runtime(runtime)
    ep.host = "hyper001"
    executor._verify_runtime(runtime)
    assert (
        executor.builder.verify_server_placement.call_args.kwargs["expected_host"]
        == "hyper001"
    )
    assert (
        executor.builder.verify_server_placement.call_args.kwargs["stable_observations"]
        == 2
    )


@pytest.mark.parametrize(
    "placement,strategy,profile,enabled",
    [
        ("initial", "rolling", "full", False),
        ("opposite", "rolling", "full", False),
        ("opposite", "stable", "full", False),
        ("opposite", "rolling", "connectivity", False),
        ("initial", "stable", "full", False),
    ],
)
def test_coordinated_slots_never_add_an_independent_migration(
    config_factory, discovery_fixture, tmp_path, placement, strategy, profile, enabled
):
    config, _, plan = full_plan(config_factory, discovery_fixture, tmp_path)
    lane = next(
        lane
        for lane in pair_scope_plans(plan)
        if lane.tests[0].metadata["pair_placement"] == placement
    )
    executor = executor_for(lane, config)
    executor.scope.update(
        qualification_strategy=strategy, qualification_profile=profile
    )
    executor.builder.cloud_operation_coordinator = None
    executor._placement_endpoints = mock.Mock(return_value=(endpoint(), endpoint()))
    executor._run_compute_placement_validation = mock.Mock()
    executor._run_placement_validation_serialized(
        lane.tests, mock.Mock(), dependencies=(lane.groups[0].id,)
    )
    assert executor._run_compute_placement_validation.called is enabled


@pytest.mark.parametrize(
    "status,expected,outcome",
    [
        ("UNVERIFIED", "observation", "OBSERVED"),
        ("UNVERIFIED", "reachable", "INCONCLUSIVE"),
        ("BLOCKED_BY_PREREQUISITE", "reachable", "BLOCKED"),
        ("FAIL", "reachable", "FAILED"),
        ("PASS", "reachable", "PASSED"),
    ],
)
def test_ledger_preserves_execution_and_verdict(status, expected, outcome):
    result = SimpleNamespace(status=status, expected=expected, details={})
    assert _outcome(result) == outcome


def test_completed_scope_never_hides_a_failed_test(
    config_factory, discovery_fixture, tmp_path
):
    _, _, plan = full_plan(config_factory, discovery_fixture, tmp_path)
    lane = pair_scope_plans(plan)[0]
    results = [
        SimpleNamespace(
            test_id=spec.id,
            status="PASS",
            expected=spec.expectation,
            details={},
            message="measured",
        )
        for spec in lane.tests
    ]
    results[-1].status = "FAIL"
    row = next(
        row
        for row in build_coverage_ledger(lane, results)
        if row["kind"] == "host-pair-placement"
    )
    assert row["complete"] is True
    assert row["outcome"] == "FAILED"


def test_resume_keeps_completed_evidence_and_rechecks_partial_scope(
    config_factory, discovery_fixture, tmp_path
):
    config, _, plan = full_plan(
        config_factory, discovery_fixture, tmp_path, resume_run_id="resume-me"
    )
    lane = pair_scope_plans(plan)[0]
    executor = executor_for(lane, config)
    completed = {lane.tests[0].id}
    executor.reporter.has_result = lambda test_id: test_id in completed
    executor.checkpoint = SimpleNamespace(metadata={})
    executor._refresh_checkpoint = mock.Mock()
    executor.prepare_resume()
    assert completed == {lane.tests[-1].id}  # Original evidence remains in the plan.
    clones = [
        spec
        for spec in lane.tests
        if spec.metadata.get("resume_recheck") and spec.id.endswith("RECHECK-1")
    ]
    assert len(clones) == 1
    assert clones[0].metadata["source_spec_id"] in completed
    assert clones[0].id in {spec.id for spec in executor.reporter.plan.tests}
    assert (
        executor.checkpoint.metadata["pair_resume_attempts"][
            executor.scope["pair_scope_id"]
        ]
        == 1
    )


def test_full_executor_simulation_never_uses_a_host_outside_each_requested_pair(
    config_factory, discovery_fixture, tmp_path
):
    from neutron_flux.engine import TestEngine
    from neutron_flux.pair_suite import run_pair_suite

    config, _, plan = full_plan(
        config_factory,
        discovery_fixture,
        tmp_path,
        performance_enabled=False,
        compute_host_connectivity_enabled=False,
    )
    recorded = {}
    reporter = mock.Mock()
    reporter.plan = plan
    reporter.results = []
    reporter.has_result = lambda test_id: test_id in recorded
    reporter.get_result = lambda test_id: recorded.get(test_id)
    builder = mock.Mock()
    builder.runtime_groups = []
    builder.group_failures = {}
    builder.cloud_operation_coordinator = None
    builder.probe_service.active_count = 0
    builder.group_failure_reason = lambda _id: None
    cleanup = mock.Mock()
    cleanup.cleanup_group.return_value = True
    cleanup.cleanup_group_side.return_value = True
    peak = []

    def build(group, *, sides):
        endpoints = [
            dataclasses.replace(
                endpoint(side=side),
                server_id=f"{group.id}-{side}-{len(recorded)}",
                host=group.metadata["target_hosts"][side],
                availability_zone="az1",
            )
            for side in sides
        ]
        return RuntimeGroup(
            group,
            "net",
            "network",
            [],
            None,
            endpoints,
            None,
            {},
        )

    builder.build_group.side_effect = build

    def build_side(runtime, group, side):
        ep = build(group, sides=(side,)).endpoints[0]
        runtime.endpoints.append(ep)
        return ep

    builder.build_group_side.side_effect = build_side

    def record(spec):
        result = SimpleNamespace(
            test_id=spec.id, status="PASS", scenario=spec.scenario, details={}
        )
        recorded[spec.id] = result
        reporter.results.append(result)

    for spec in plan.tests:
        if spec.scenario == "Controller readiness":
            record(spec)

    def execute(specs):
        for spec in specs:
            if spec.id in recorded:
                continue
            assert all(
                required in recorded
                for required in [*spec.requires, *spec.requires_pass]
            )
            allowed = {
                spec.metadata["requested_source_host"],
                spec.metadata["requested_destination_host"],
            }
            active = [
                ep for runtime in builder.runtime_groups for ep in runtime.endpoints
            ]
            peak.append(len(active))
            assert {ep.host for ep in active} <= allowed
            if spec.metadata.get("same_host"):
                assert {ep.host for ep in active} == {
                    spec.metadata["pair_scope_hosts"][0]
                }
            record(spec)

    def record_result(identity, category, status, message, **kwargs):
        spec = next(s for s in plan.tests if s.id == identity)
        record(spec)
        recorded[identity].status = status
        recorded[identity].details = kwargs.get("details", {})

    reporter.result.side_effect = record_result
    engine = mock.Mock()
    engine.run_specs.side_effect = execute
    checkpoint = SimpleNamespace(metadata={})
    parallel_probe = TestEngine.parallel_probe
    with mock.patch(
        "neutron_flux.pair_workflow.TestEngine", return_value=engine
    ) as engine_factory:
        engine_factory.parallel_probe = parallel_probe
        run_pair_suite(
            config, plan, builder, reporter, cleanup, mock.Mock(), checkpoint
        )
    assert set(recorded) == {spec.id for spec in plan.tests}
    assert max(peak) == 2
    assert builder.runtime_groups == []
    assert cleanup.cleanup_group.call_count > len(plan.groups)


def test_derived_selection_includes_reverse_tcp_without_widening_pair_scope(
    config_factory, discovery_fixture, tmp_path
):
    config, _, plan = full_plan(
        config_factory, discovery_fixture, tmp_path, include_derived_tests=True
    )
    spec = next(
        spec
        for spec in pair_scope_plans(plan)[2].tests
        if spec.operation == "probe"
        and spec.protocol == "tcp"
        and spec.expectation == "reachable"
    )
    config.test_ids = [spec.id]
    selected = select_plan_tests(plan, [spec.id], include_derived=True)
    network = [row for row in selected.tests if row.operation == "probe"]
    assert len(network) == 2
    assert len({row.metadata["pair_scope_id"] for row in network}) == 1
    assert {(row.source_side, row.destination_side) for row in network} == {
        ("A", "B"),
        ("B", "A"),
    }
    planner = Planner(config, discovery_fixture, mock.Mock())
    estimate_pair_suite(planner, selected)
    assert selected.estimated["performance_paths_selected"] > 0


def test_reciprocal_cross_network_tests_share_placement_and_performance_batch(
    config_factory, discovery_fixture, tmp_path
):
    from neutron_flux.performance import PerformanceRunner

    config, _, plan = full_plan(config_factory, discovery_fixture, tmp_path)
    lane = pair_scope_plans(plan)[0]
    cross = [
        spec
        for spec in lane.tests
        if spec.phase == "cross"
        and spec.operation == "probe"
        and spec.protocol == "tcp"
    ]
    matched = []
    for first in cross:
        for second in cross:
            if first.family == second.family and all(
                getattr(first, a) == getattr(second, b)
                and getattr(first, b) == getattr(second, a)
                for a, b in (
                    ("source_group_id", "destination_group_id"),
                    ("source_side", "destination_side"),
                    ("source_subnet_id", "destination_subnet_id"),
                )
            ):
                assert first.dependencies == second.dependencies
                matched = [first, second]
    assert matched
    # This models an explicit routing contract permitting both directions.
    permitted = [
        dataclasses.replace(spec, expectation="reachable", authoritative=True)
        for spec in matched
    ]
    reporter = mock.Mock()
    reporter.scope = ""
    reporter.get_result = lambda _id: SimpleNamespace(status="PASS")
    runner = PerformanceRunner(config, mock.Mock(), reporter, mock.Mock())
    runner._resolve_endpoints = lambda _path: (
        SimpleNamespace(server_id="source"),
        SimpleNamespace(server_id="destination"),
        "192.0.2.1",
        "192.0.2.2",
        None,
    )
    measurements = runner.plan_specs(permitted, stage="cross-topology")
    assert len(measurements) == 7
    assert all(
        spec.metadata["directions"] == ["forward", "reverse"] for spec in measurements
    )
