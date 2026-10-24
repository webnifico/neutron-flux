"""Resume, placement, resource ownership and report evidence integrity."""

from __future__ import annotations

import copy
import dataclasses
from collections import Counter, defaultdict
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.pair_workflow import CoordinatedPairExecutor, workflow_plans
from neutron_flux.reporting import Reporter, ResourceTracker
from neutron_flux.resource_naming import ResourceNameRegistry
from neutron_flux.test_selection import select_plan_tests

from .test_host_pair_workflow import planned
from .test_performance_and_html import _endpoint


def test_second_resume_has_one_execution_per_planned_check(
    config_factory, discovery_fixture
):
    config = config_factory(
        action="run",
        target_host_pairs=[("hyper001", "hyper002")],
        performance_enabled=False,
    )
    plan = planned(config, discovery_fixture)
    reporter = Reporter(config, "resume-twice")
    reporter.plan = plan
    reporter.save_plan()
    config.resume_run_id = reporter.run_id
    try:
        for attempt in range(3):
            first = next(s for s in plan.tests if not reporter.has_result(s.id))
            reporter.result(
                first.id, first.category, "PASS", "completed before interruption"
            )
            executor = CoordinatedPairExecutor(
                config,
                workflow_plans(plan)[0],
                mock.Mock(),
                reporter,
                mock.Mock(),
                mock.Mock(),
                mock.Mock(),
            )
            executor._refresh_checkpoint = lambda: None
            executor.prepare_resume()
            identities = [s.metadata["planned_check_id"] for s in executor.plan.tests]
            assert len(identities) == len(set(identities)) == 13, (
                attempt,
                Counter(identities),
            )
            assert len(plan.checks) == 13
    finally:
        reporter.logger.close()


@pytest.mark.parametrize("completed_all", [False, True])
def test_resume_runs_fresh_baseline_before_pending_performance(
    config_factory, discovery_fixture, monkeypatch, completed_all
):
    from neutron_flux.check_ledger import check_ledger
    from neutron_flux.engine import TestEngine
    from neutron_flux.performance import PerformanceRunner

    config = config_factory(
        action="run",
        target_host_pairs=[("hyper001", "hyper002")],
        performance_enabled=True,
    )
    plan = planned(config, discovery_fixture)
    approved_checks = copy.deepcopy(plan.checks)
    initial = [
        spec
        for spec in workflow_plans(plan)[0].tests
        if spec.metadata["pair_placement"] == "initial"
    ]
    completed = initial if completed_all else initial[:3]
    pending_ids = {spec.id for spec in initial if spec not in completed}
    stale = dataclasses.replace(
        initial[0],
        id=f"{initial[0].id}-RESUME-1",
        metadata={
            **initial[0].metadata,
            "resume_recheck": True,
            "source_spec_id": initial[0].id,
        },
    )
    plan.tests.append(stale)
    reporter = Reporter(config, "resume-pending-performance")
    reporter.plan = plan
    reporter.save_plan()
    try:
        for spec in completed:
            reporter.result(
                spec.id,
                spec.category,
                "PASS",
                "previous generation",
                emit_console=False,
            )
        historical = {
            spec.id: dataclasses.asdict(reporter.get_result(spec.id))
            for spec in completed
        }
        config.resume_run_id = reporter.run_id
        builder = SimpleNamespace(
            runtime_groups=[], ssh_endpoint=mock.Mock(), ssh_controller=mock.Mock()
        )
        executor = CoordinatedPairExecutor(
            config,
            workflow_plans(plan)[0],
            builder,
            reporter,
            mock.Mock(),
            mock.Mock(),
            mock.Mock(),
        )
        executor._refresh_checkpoint = lambda: None
        executor.prepare_resume()
        replay = [
            spec
            for spec in executor.plan.tests
            if spec.metadata["pair_placement"] == "initial"
        ]
        assert {spec.id for spec in replay} == pending_ids | {
            f"{spec.id}-RESUME-2" for spec in completed
        }
        assert reporter.get_result(stale.id).status == "BLOCKED_BY_SETUP_ERROR"
        assert reporter.get_result(stale.id).details["check_sample"] is True
        assert all(not reporter.has_result(spec.id) for spec in replay)
        assert all(not spec.metadata.get("check_sample") for spec in replay)

        engine = TestEngine(config, discovery_fixture, builder, reporter)
        executed = set()

        def observe(spec):
            executed.add(spec.id)
            reporter.result(
                spec.id, spec.category, "PASS", "fresh generation", emit_console=False
            )

        monkeypatch.setattr(engine, "_run_spec", observe)
        engine.run_specs(replay)
        assert executed == {spec.id for spec in replay}

        runner = PerformanceRunner(config, builder, reporter, engine)
        monkeypatch.setattr(
            runner,
            "_resolve_endpoints",
            lambda _path: (
                SimpleNamespace(server_id="fresh-A"),
                SimpleNamespace(server_id="fresh-B"),
            ),
        )
        measurements = runner.plan_specs(replay, stage="group-local")
        assert len(measurements) == len(runner.MEASUREMENTS)
        performance_ids = {
            identity
            for spec in replay
            for identity in spec.metadata.get("check_bindings", {})
            .get("performance", {})
            .get("group-local", {})
            .values()
        }
        assert {
            spec.metadata["planned_check_id"] for spec in measurements
        } == performance_ids
        assert all(
            row["outcome"] == "PENDING"
            for row in check_ledger(reporter)
            if row["id"] in performance_ids
        )
        assert all(
            dataclasses.asdict(reporter.get_result(identity)) == result
            for identity, result in historical.items()
        )
        assert plan.checks == approved_checks
    finally:
        reporter.logger.close()


@pytest.mark.parametrize("stateful", [False, True])
def test_exact_selection_stays_in_requested_placement(
    config_factory, discovery_fixture, stateful
):
    config = config_factory(target_host_pairs=[("hyper001", "hyper002")])
    plan = planned(config, discovery_fixture)
    if stateful:
        for spec in plan.tests:
            if spec.operation == "probe":
                spec.operation = (
                    "server-stop" if spec.source_side == "A" else "server-start"
                )
                spec.scenario = "Server lifecycle"
    first = next(
        s
        for s in plan.tests
        if s.protocol == "tcp" and s.operation != "pair-transition"
    )
    selected = select_plan_tests(plan, [first.id], include_derived=True)
    assert {s.metadata.get("pair_scope_id") for s in selected.tests} == {
        first.metadata["pair_scope_id"]
    }


def test_side_cleanup_includes_legacy_fip_attached_to_owned_port(config_factory):
    from neutron_flux.cleanup import CleanupManager

    config = config_factory()
    reporter = Reporter(config, "side-fip")
    tracker = ResourceTracker(reporter)
    tracker.add("port", "test-A", "port A", group_id="g", endpoint_side="A")
    tracker.add("floating_ip", "fip-A", "fip A", parent_id="test-A", group_id="g")
    tracker.add("floating_ip", "fip-B", "fip B", parent_id="test-B", group_id="g")
    manager = CleanupManager(mock.Mock(), reporter, tracker, config)
    deleted = []
    manager.osc.exists = lambda kind, identity: identity not in deleted

    def delete(record):
        deleted.append(record.id)
        tracker.mark_deleted(record, "deleted")

    manager._delete_floating_ip = manager._delete_port = delete
    try:
        assert manager.cleanup_group_side("g", "A")
        assert deleted == ["fip-A", "test-A"]
    finally:
        reporter.logger.close()


def test_rotation_forgets_old_endpoint_fip_state():
    executor = object.__new__(CoordinatedPairExecutor)
    endpoint = _endpoint("old", "A", "192.0.2.1", "host1")
    runtime = SimpleNamespace(
        endpoints=[endpoint],
        fips={endpoint.label: {"id": "old-fip"}},
        metadata={"pending_floating_ips": {endpoint.label: {"id": "pending-fip"}}},
    )
    executor.active = {"g": runtime}
    executor.groups = {"g": mock.Mock()}
    executor.cleanup_manager = SimpleNamespace(cleanup_group_side=lambda *_: True)

    def build(*args, **kwargs):
        assert endpoint.label not in runtime.fips
        assert endpoint.label not in runtime.metadata["pending_floating_ips"]

    executor.builder = SimpleNamespace(
        stop_endpoint_probe=lambda *_: None, build_group_side=build
    )
    executor._refresh_checkpoint = lambda: None
    executor._rotate("g", endpoint)


@pytest.mark.parametrize("eligible", [False, True])
def test_resume_with_only_load_pending_does_not_repeat_topologies(
    config_factory, discovery_fixture, monkeypatch, eligible
):
    from neutron_flux.check_ledger import resolve_checks
    from neutron_flux.pair_executor import PairScopeExecutor
    from neutron_flux.pair_suite import run_pair_suite

    config = config_factory(
        action="run",
        target_host_pairs=[("hyper001", "hyper002")],
        performance_enabled=False,
        fabric_scale_enabled=True,
    )
    plan = planned(config, discovery_fixture)
    reporter = Reporter(config, "load-only-resume")
    reporter.plan = plan
    reporter.save_plan()
    config.resume_run_id = reporter.run_id
    loads = []
    load_rows = {row["id"]: row for row in plan.checks if row["kind"] == "load"}

    def load(executor):
        scope = executor.scope
        loads.append(scope["pair_scope_id"])
        identity = next(
            s.metadata["check_bindings"]["load"]
            for s in executor.plan.tests
            if s.metadata.get("check_bindings", {}).get("load")
        )
        assert load_rows[identity]["pair_scope_id"] == scope["pair_scope_id"]
        assert all(
            list(g.metadata["target_hosts"].values()) == scope["pair_scope_hosts"]
            for g in executor.plan.groups
        )
        resolve_checks(reporter, {identity: ("PASSED", "previous network work reused")})
        return SimpleNamespace(run=lambda: None)

    monkeypatch.setattr("neutron_flux.concurrent_load.ConcurrentLoadRunner", load)
    monkeypatch.setattr(PairScopeExecutor, "_refresh_checkpoint", lambda _: None)
    monkeypatch.setattr(
        CoordinatedPairExecutor,
        "run",
        lambda _: pytest.fail("Completed topology replayed for pending load only"),
    )
    try:
        for spec in plan.tests:
            spec.metadata["pair_scope_eligible"] = eligible
            reporter.result(
                spec.id, spec.category, "PASS", "completed previous process"
            )
        run_pair_suite(
            config, plan, mock.Mock(), reporter, mock.Mock(), mock.Mock(), mock.Mock()
        )
        assert len(loads) == (2 if eligible else 0)
        assert len(set(loads)) == len(loads)
    finally:
        reporter.logger.close()


def test_migration_inventory_cancellation_propagates(config_factory):
    from neutron_flux.errors import RunCancelledError
    from neutron_flux.runtime.migration_validation import MigrationValidationMixin

    builder = MigrationValidationMixin()
    builder.config = config_factory()
    builder._json_with_transient_retry = mock.Mock(
        side_effect=RunCancelledError("cancelled during migration observation")
    )
    with pytest.raises(RunCancelledError):
        builder._migration_rows("server")


def test_boot_budget_counts_topologies_without_safe_migration_protocols(
    config_factory, discovery_fixture
):
    from neutron_flux.pair_suite import estimate_pair_suite
    from neutron_flux.planning import Planner

    config = config_factory(
        target_host_pairs=[("hyper001", "hyper002")], performance_enabled=False
    )
    plan = planned(config, discovery_fixture)
    for spec in plan.tests:
        if spec.protocol == "udp":
            spec.authoritative = False
    estimate_pair_suite(Planner(config, discovery_fixture, mock.Mock()), plan)
    assert plan.estimated["endpoint_vm_boots"] == 3
    assert plan.estimated["endpoint_recreations"] == 1
    assert plan.estimated["targeted_migrations_maximum"] == 0


@pytest.mark.parametrize("shared", [False, True])
def test_evidence_transport_preserves_reserved_keys_at_every_depth(shared):
    from neutron_flux.reporting_components.evidence_pool import pool_evidence

    from .evidence import expand_evidence

    payload = {
        "evidence_pool": {"original": 7},
        "nested": {"evidence_pool": ["original"], "$neutron_flux_evidence": 19},
        "literal": {"$neutron_flux_evidence": 0},
    }
    if shared:
        payload.update(a="large" * 100, b="large" * 100)
    assert expand_evidence(pool_evidence(payload)) == payload


def test_report_links_resolve_supporting_evidence_to_parent_check(
    config_factory, discovery_fixture
):
    from neutron_flux.reporting_components.html import build_run_payload
    from neutron_flux.reporting_components.report_payload import build_report_payload
    from neutron_flux.utils import utc_now

    config = config_factory(
        action="run",
        target_host_pairs=[("hyper001", "hyper002")],
        performance_enabled=False,
    )
    plan = planned(config, discovery_fixture)
    first = plan.tests[0]
    sample = dataclasses.replace(
        first, id="sample-only-path", metadata={**first.metadata, "check_sample": True}
    )
    plan.tests.append(sample)
    reporter = Reporter(config, "sample-links")
    reporter.plan = plan
    reporter.save_plan()
    try:
        for spec in (first, sample):
            reporter.result(
                spec.id,
                spec.category,
                "PASS",
                "reachable",
                expected="reachable",
                observed="reachable",
            )
        payload = build_run_payload(
            reporter,
            final_status="UNVERIFIED",
            finished=utc_now(),
            counts=Counter(r.status for r in reporter.results),
        )
        payload["dashboard"]["paths"] = [
            {"path_id": "sample-path", "result_ids": [sample.id]}
        ]
        payload["dashboard"]["findings"] = [
            {
                "finding_id": "sample-finding",
                "root_key": "execution",
                "result_ids": [sample.id],
                "result_count": 1,
            }
        ]
        report = build_report_payload(payload)["dashboard"]
        visible = {r["result_id"] for r in report["results"]}
        assert report["paths"][0]["result_ids"] == [first.id]
        assert set(report["findings"][0]["result_ids"]) <= visible
        assert report["findings"][0]["result_ids"] == [first.id]
        assert sample.id in report["evidence_entries"]
    finally:
        reporter.logger.close()


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("selection", ["full", "transition", "egress", "resume"])
@pytest.mark.parametrize("migration_mode", ["cold-only", "live-only"])
def test_full_planner_workflow_uses_each_placement_and_retains_subnets(
    config_factory,
    discovery_fixture,
    tmp_path,
    monkeypatch,
    enabled,
    selection,
    migration_mode,
):
    from neutron_flux.check_ledger import check_ledger
    from neutron_flux.check_plan import build_check_plan
    from neutron_flux.models import ComputeHostInfo, MigrationResult, RuntimeGroup
    from neutron_flux.pair_executor import PairScopeExecutor
    from neutron_flux.pair_suite import run_pair_suite
    from neutron_flux.pair_workflow import coordinate_pair_plan
    from neutron_flux.runtime.topology import TopologyRuntimeMixin

    from .test_full_pair_suite import full_plan

    config, _, plan = full_plan(
        config_factory,
        discovery_fixture,
        tmp_path,
        action="run",
        performance_enabled=False,
        compute_host_connectivity_enabled=enabled,
        migration_mode=migration_mode,
        live_migration_continuity=False,
        **({"target_host_pairs": [("hyper001", "hyper002")]} if enabled else {}),
    )
    plan = coordinate_pair_plan(plan)
    selected = None
    if selection == "resume":
        plan = workflow_plans(plan)[0]
    elif selection != "full":
        selected = next(
            s
            for s in plan.tests
            if s.operation
            == ("pair-transition" if selection == "transition" else "egress")
            and s.metadata["pair_placement"] == "opposite"
        )
        config.test_ids = [selected.id]
        plan = select_plan_tests(plan, config.test_ids)
    build_check_plan(plan, config)
    reporter = Reporter(config, "full-coordinated")
    reporter.plan = plan
    reporter.save_plan()
    builder = SimpleNamespace(
        discovery=discovery_fixture,
        runtime_groups=[],
        group_failures={},
        group_failure_reason=lambda _: None,
        cloud_operation_coordinator=None,
        reporter=reporter,
        verify_server_placement=lambda *a, **k: None,
        stop_group_probes=lambda *_: None,
        stop_endpoint_probe=lambda *_: None,
    )
    counts = Counter()
    stages = defaultdict(list)
    floating_generations = {}
    interrupt_after = None

    def endpoints(group, network, subnets, *, sides, generation):
        assert network and subnets
        assert all(subnet.startswith(network) for subnet in subnets)
        output = []
        for side in sides:
            counts["boots"] += 1
            ep = _endpoint(
                str(counts["boots"]),
                side,
                "192.0.2.1",
                group.metadata["target_hosts"][side],
            )
            ep.availability_zone = "az1"
            output.append(ep)
        return output

    def build(group, *, sides):
        generation = builder.allocate_group_generation(group.id)
        counts["topologies"] += 1
        networks = {side: f"network-{counts['topologies']}-{side}" for side in sides}
        subnets = {side: networks[side] + "-subnet" for side in sides}
        eps = [
            ep
            for side in sides
            for ep in endpoints(
                group,
                networks[side],
                [subnets[side]],
                sides=(side,),
                generation=generation,
            )
        ]
        return RuntimeGroup(
            group,
            networks[sides[0]],
            "network",
            list(subnets.values()),
            None,
            eps,
            None,
            {},
            metadata={"network_ids": networks, "side_subnet_ids": subnets},
        )

    builder.allocate_group_generation = ResourceNameRegistry(
        "nflux-workflow-generations"
    ).allocate_group_generation
    builder.build_group = build
    builder._create_endpoints = endpoints
    builder.build_group_side = lambda *a, **k: TopologyRuntimeMixin.build_group_side(
        builder, *a, **k
    )
    cleanup = SimpleNamespace(
        cleanup_group=lambda _: True, cleanup_group_side=lambda *_: True
    )

    builder.select_compute_migration_targets = lambda moving, peer, **kw: (
        [
            ComputeHostInfo(f"hyper00{i}", "az1", True, True)
            for i in range(1, 5)
            if f"hyper00{i}" != moving.host
        ],
        "eligible",
    )

    def migrate(moving, target):
        counts["migrations"] += 1
        source = moving.host
        moving.host = target.host
        return MigrationResult(
            moving.server_id,
            source,
            target.host,
            "az1",
            "az1",
            True,
            False,
            True,
            endpoint_ready=True,
            guest_marker_verified=True,
            migration_record_verified=True,
            task_state_cleared=True,
            details={
                "migration_mode": "live" if migration_mode == "live-only" else "cold"
            },
        )

    builder.cold_migrate_endpoint = migrate
    builder.live_migrate_endpoint = lambda moving, target, stationary: migrate(
        moving, target
    )

    def execute(specs):
        nonlocal interrupt_after
        for spec in specs:
            if reporter.has_result(spec.id):
                continue
            assert all(
                reporter.has_result(i) for i in [*spec.requires, *spec.requires_pass]
            )
            active = {runtime.plan.id: runtime for runtime in builder.runtime_groups}
            assert sum(len(r.endpoints) for r in active.values()) <= 2
            for group_id in spec.dependencies:
                assert group_id in active
            hosts = [ep.host for r in active.values() for ep in r.endpoints]
            if not spec.metadata.get("supplemental"):
                assert sorted(hosts) == sorted(spec.metadata["pair_scope_hosts"])
                key = spec.metadata["workflow_batch"]
                if enabled and spec.operation in {"fip-peer", "fip-baseline"}:
                    generation = sorted(
                        ep.server_id for r in active.values() for ep in r.endpoints
                    )
                    assert (
                        floating_generations.setdefault(key, generation) == generation
                    )
                stage = spec.metadata["pair_placement"]
                if not stages[key] or stages[key][-1] != stage:
                    stages[key].append(stage)
            reporter.result(
                spec.id,
                spec.category,
                "PASS",
                "offline observed placement",
                observed="reachable",
            )
            if interrupt_after is not None:
                interrupt_after -= 1
                if interrupt_after == 0:
                    from neutron_flux.errors import RunCancelledError

                    raise RunCancelledError("offline interruption")

    monkeypatch.setattr(
        "neutron_flux.pair_workflow.TestEngine",
        lambda *_: SimpleNamespace(run_specs=execute),
    )
    monkeypatch.setattr(PairScopeExecutor, "_refresh_checkpoint", lambda _: None)
    monkeypatch.setattr(
        "neutron_flux.execution.placement_migration.time.sleep", lambda _: None
    )
    try:
        for spec in plan.tests:
            if spec.scenario == "Controller readiness":
                reporter.result(spec.id, spec.category, "PASS", "ready")
        approved = len(plan.checks)
        if selection == "resume":
            import json

            from neutron_flux.errors import RunCancelledError
            from neutron_flux.plan_contract import plan_from_dict

            for limit in (3, 4):
                interrupt_after = limit
                with pytest.raises(RunCancelledError):
                    run_pair_suite(
                        config,
                        plan,
                        builder,
                        reporter,
                        cleanup,
                        mock.Mock(),
                        mock.Mock(),
                    )
                assert not builder.runtime_groups
                reporter.save_plan()
                plan = plan_from_dict(json.loads(reporter.plan_path.read_text()))
                reporter.logger.close()
                config.resume_run_id = reporter.run_id
                reporter = Reporter(config, reporter.run_id, load_existing=True)
                reporter.plan = plan
                builder.reporter = reporter
            interrupt_after = None
            counts.clear()
            stages.clear()
        run_pair_suite(
            config, plan, builder, reporter, cleanup, mock.Mock(), mock.Mock()
        )
        if selection == "full":
            assert len(stages) == len(workflow_plans(plan)) > 10
            assert all(order == ["initial", "opposite"] for order in stages.values())
            assert counts["boots"] + counts["migrations"] == 3 * len(stages)
        elif selection == "resume":
            assert len(stages) == 1
            assert list(stages.values()) == [["initial", "opposite"]]
            assert counts["boots"] + counts["migrations"] == 3
        elif selection == "transition":
            assert (
                reporter.get_result(selected.id).observed
                == "requested-placement-verified"
            )
            assert counts["migrations"] == int(enabled)
            assert counts["boots"] == (2 if enabled else 3)
        else:
            assert list(stages.values()) == [["opposite"]]
            assert counts["migrations"] == 0
            assert counts["boots"] == 2
        assert len(plan.checks) == approved
        assert all(row["outcome"] == "PASSED" for row in check_ledger(reporter))
        assert not builder.runtime_groups
    finally:
        reporter.logger.close()
