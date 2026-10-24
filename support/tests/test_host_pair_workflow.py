"""Exercise the actual coordinator against an instrumented offline cloud boundary."""

from __future__ import annotations

import dataclasses
from collections import Counter
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.check_ledger import check_ledger, check_progress
from neutron_flux.check_plan import build_check_plan
from neutron_flux.host_qualification import HostQualificationPlanner
from neutron_flux.models import ComputeHostInfo, MigrationResult, RuntimeGroup
from neutron_flux.pair_suite import expand_pair_suite
from neutron_flux.pair_workflow import CoordinatedPairExecutor, workflow_plans
from neutron_flux.reporting import Reporter
from neutron_flux.runtime.migration_validation import MigrationValidationMixin

from .test_host_qualification import _Inventory, _service
from .test_performance_and_html import _endpoint
from .test_planned_check_inventory import network_plan


def planned(config, discovery, cross=False):
    plan = network_plan()
    if cross:
        plan.provider_groups.append(
            dataclasses.replace(plan.provider_groups[0], id="h", label="h")
        )
        for spec in plan.tests:
            reverse = spec.source_side == "B"
            spec.phase = "cross"
            spec.dependencies = ["g", "h"]
            spec.source_group_id = "h" if reverse else "g"
            spec.destination_group_id = "g" if reverse else "h"
            spec.source_side = spec.destination_side = "A"
    plan.host_qualification = HostQualificationPlanner(
        config,
        discovery,
        plan,
        _Inventory([_service("hyper001", "az1"), _service("hyper002", "az1")]),
        mock.Mock(),
    ).build()
    plan = expand_pair_suite(plan, coordinated=True)
    build_check_plan(plan, config)
    return plan


@pytest.mark.parametrize("fault", [None, "ambiguous", "unsafe", "readiness"])
@pytest.mark.parametrize("cross", [False, True])
@pytest.mark.parametrize(
    "initial_hosts",
    [
        ("hyper001", "hyper001"),
        ("hyper001", "hyper002"),
        ("hyper002", "hyper002"),
        ("hyper002", "hyper001"),
    ],
)
@pytest.mark.parametrize(
    "mode,enabled,expected_boots",
    [("live-only", True, 2), ("cold-only", True, 2), ("live-only", False, 3)],
)
def test_coordinated_lifetime_fixed_plan_exact_hosts(
    config_factory,
    discovery_fixture,
    monkeypatch,
    mode,
    enabled,
    expected_boots,
    cross,
    fault,
    initial_hosts,
):
    config = config_factory(
        action="run",
        target_host_pairs=[("hyper001", "hyper002")],
        migration_mode=mode,
        compute_host_connectivity_enabled=enabled,
        performance_enabled=False,
        live_migration_continuity=False,
    )
    plan = planned(config, discovery_fixture, cross=cross)
    reporter = Reporter(config, "coordinated-lifetime")
    reporter.plan = plan
    reporter.save_plan()
    counters = Counter()
    placements = []
    resources = []
    builder = SimpleNamespace(
        discovery=discovery_fixture,
        runtime_groups=[],
        group_failures={},
        cloud_operation_coordinator=None,
        group_failure_reason=lambda _: None,
    )

    def boot(group, side):
        counters["boot"] += 1
        return _endpoint(
            str(counters["boot"]),
            side,
            "192.0.2." + str(10 + counters["boot"]),
            initial_hosts[counters["boot"] - 1]
            if counters["boot"] <= 2
            else group.metadata["target_hosts"][side],
        )

    def build(group, *, sides):
        counters["topology"] += 1
        endpoints = [boot(group, s) for s in sides]
        for ep in endpoints:
            ep.availability_zone = "az1"
        runtime = RuntimeGroup(
            group, "network", "network", ["subnet"], None, endpoints, None, {}
        )
        resources.append(runtime)
        return runtime

    def build_side(runtime, group, side, **kw):
        endpoint = boot(group, side)
        endpoint.availability_zone = "az1"
        runtime.endpoints.append(endpoint)
        return endpoint

    builder.build_group = build
    builder.build_group_side = build_side
    builder.stop_group_probes = lambda *args: None
    builder.stop_endpoint_probe = lambda *args: None
    builder.verify_server_placement = lambda *args, **kwargs: None

    def targets(moving, peer, **kw):
        return [
            ComputeHostInfo(host, "az1", True, True)
            for host in ("hyper001", "hyper002", "unrequested")
            if host != moving.host
        ], "eligible"

    builder.select_compute_migration_targets = targets

    def migrate(moving, target, peer=None):
        counters["migration"] += 1
        if fault == "ambiguous":
            from neutron_flux.errors import AmbiguousCloudOperationError

            raise AmbiguousCloudOperationError("Command acceptance is unknown")
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
            fault != "unsafe",
            endpoint_ready=fault != "readiness",
            details={"migration_mode": "live" if peer else "cold"},
        )

    builder.live_migrate_endpoint = migrate
    builder.cold_migrate_endpoint = migrate

    def emit(specs):
        for spec in specs:
            if reporter.has_result(spec.id):
                continue
            endpoints = [e for r in builder.runtime_groups for e in r.endpoints]
            assert len(endpoints) <= 2
            if not spec.metadata.get("supplemental"):
                placements.append(tuple(e.host for e in endpoints))
            reporter.result(
                spec.id,
                spec.category,
                "PASS",
                "reachable",
                expected=spec.expectation,
                observed="reachable",
                authoritative=True,
                display_name=spec.display_name,
                scenario=spec.scenario,
            )

    monkeypatch.setattr(
        "neutron_flux.pair_workflow.TestEngine",
        lambda *args: SimpleNamespace(run_specs=emit),
    )
    monkeypatch.setattr(
        "neutron_flux.execution.placement_migration.time.sleep", lambda _: None
    )
    cleanup = SimpleNamespace(
        cleanup_group=lambda _: True, cleanup_group_side=lambda *args: True
    )
    executor = CoordinatedPairExecutor(
        config,
        workflow_plans(plan)[0],
        builder,
        reporter,
        cleanup,
        mock.Mock(),
        mock.Mock(),
    )
    executor._refresh_checkpoint = lambda: None
    original = [row.copy() for row in plan.checks]
    try:
        executor.run()
        if fault in {"ambiguous", "unsafe"} and enabled:
            assert counters["migration"] == 1
            assert counters["boot"] == 2
            assert placements == [initial_hosts] * 6
            assert (
                check_progress(reporter)["planned"]
                == check_progress(reporter)["planned_recorded"]
                == 13
            )
            outcomes = Counter(row["outcome"] for row in check_ledger(reporter))
            assert outcomes["BLOCKED"] == 6
            assert outcomes["ERROR" if fault == "ambiguous" else "FAILED"] == 1
            assert plan.checks == original
            return
        assert counters["topology"] == (2 if cross else 1)
        assert counters["boot"] == expected_boots
        assert counters["migration"] == (1 if enabled else 0)
        opposite = (
            (initial_hosts[0], initial_hosts[0])
            if initial_hosts[0] != initial_hosts[1]
            else (
                initial_hosts[0],
                "hyper002" if initial_hosts[0] == "hyper001" else "hyper001",
            )
        )
        assert placements == [initial_hosts] * 6 + [opposite] * 6
        assert sum(a != b for a, b in zip(initial_hosts, opposite, strict=True)) == 1
        assert plan.checks == original
        assert check_progress(reporter)["planned"] == 13
        assert check_progress(reporter)["planned_recorded"] == 13
        if fault == "readiness" and enabled:
            assert Counter(row["outcome"] for row in check_ledger(reporter)) == {
                "PASSED": 12,
                "FAILED": 1,
            }
        else:
            assert all(row["outcome"] == "PASSED" for row in check_ledger(reporter))
        assert all(reporter.has_result(spec.id) for spec in plan.tests)
    finally:
        reporter.logger.close()


def test_performance_keeps_exactly_two_distinct_placements(
    config_factory, discovery_fixture
):
    config = config_factory(target_host_pairs=[("hyper001", "hyper002")])
    plan = planned(config, discovery_fixture)
    assert len(plan.groups) == 1
    assert Counter(row["kind"] for row in plan.checks) == {
        "network": 12,
        "migration": 1,
        "performance": 14,
    }
    transitions = [s for s in plan.tests if s.operation == "pair-transition"]
    assert [s.metadata["pair_placement"] for s in transitions] == ["opposite"]
    assert not any(row["stage"] == "post-live-migration" for row in plan.checks)


@pytest.mark.parametrize("terminal,expected", [("completed", True), ("error", False)])
def test_nova_record_converges_without_premature_failure(
    monkeypatch, terminal, expected
):
    instance = MigrationValidationMixin()
    instance.config = SimpleNamespace(resource_timeout=10)
    rows = iter(
        [
            (
                False,
                "Nova migration record validation failed: status=running",
                {"status": "running"},
            ),
            (expected, None if expected else "migration failed", {"status": terminal}),
        ]
    )
    instance._observe_nova_migration_record = lambda *args, **kwargs: next(rows)
    monkeypatch.setattr(
        "neutron_flux.runtime.migration_validation.time.sleep", lambda _: None
    )
    value, error, details = instance._verify_nova_migration_record(
        None, "a", "b", {"old"}
    )
    assert value is expected
    assert len(details["validation_observations"]) == 2


def test_dual_stack_stop_start_shares_two_cloud_writes(config_factory):
    from neutron_flux.engine_handlers.registry import bind_operations

    from .test_engine_handlers import _engine, _probe, _spec

    engine, _, _, _, records = _engine(config_factory)
    engine.operations = bind_operations(engine)
    engine.reporter = mock.Mock()
    results = {}
    engine.reporter.has_result = lambda identity: identity in results
    engine.reporter.get_result = results.get
    original_record = engine._record

    def record(spec, probe, *args, **kwargs):
        results[spec.id] = SimpleNamespace(status="PASS")
        original_record(spec, probe, *args, **kwargs)

    engine._record = record
    engine.probes.endpoint.return_value = _probe(True)
    engine.builder.osc.run.return_value = SimpleNamespace(
        returncode=0, stdout="", stderr=""
    )
    engine.builder._wait_for_status = mock.Mock()
    engine.builder._wait_for_ssh = mock.Mock(return_value=True)
    engine.builder.reconfigure_endpoint = mock.Mock()
    engine._wait_endpoint_state.side_effect = lambda *args, **kwargs: _probe(
        kwargs["expected"]
    )
    specs = [
        dataclasses.replace(
            _spec(op, category="server-lifecycle"), id=f"{op}-{family}", family=family
        )
        for family in (4, 6)
        for op in ("server-stop", "server-start")
    ]
    engine.run_specs(specs)
    assert [call.args[:2] for call in engine.builder.osc.run.call_args_list] == [
        ("server", "stop"),
        ("server", "start"),
    ]
    assert len(records) == 4
    assert {spec.family for spec, *_ in records} == {4, 6}
    assert [args.args[3] for args in engine._wait_endpoint_state.call_args_list] == [
        4,
        6,
        4,
        6,
    ]


def test_complete_report_has_unrun_checks_and_nested_samples(
    config_factory, discovery_fixture
):
    from neutron_flux.check_ledger import finalize_checks
    from neutron_flux.reporting_components.html import build_run_payload
    from neutron_flux.reporting_components.report_payload import build_report_payload
    from neutron_flux.utils import utc_now

    config = config_factory(
        action="run",
        target_host_pairs=[("hyper001", "hyper002")],
        performance_enabled=False,
    )
    plan = planned(config, discovery_fixture)
    reporter = Reporter(config, "complete-report")
    reporter.plan = plan
    reporter.save_plan()
    first = plan.tests[0]
    sample = dataclasses.replace(
        first,
        id=first.id + "-sample",
        metadata={**first.metadata, "check_sample": True},
    )
    plan.tests.append(sample)
    reporter.save_plan()
    try:
        reporter.result(
            first.id,
            first.category,
            "PASS",
            "reachable",
            expected=first.expectation,
            observed="reachable",
        )
        reporter.result(
            sample.id,
            sample.category,
            "PASS",
            "supporting sample",
            expected=sample.expectation,
            observed="reachable",
        )
        finalize_checks(reporter)
        payload = build_run_payload(
            reporter,
            final_status="UNVERIFIED",
            finished=utc_now(),
            counts=Counter(r.status for r in reporter.results),
        )
        report = build_report_payload(payload)
        assert report["check_inventory_complete"] is True
        assert len(report["dashboard"]["results"]) == 13
        assert report["dashboard"]["results"][0]["related_evidence_ids"] == [sample.id]
        assert len(report["dashboard"]["evidence_entries"]) == 1
        assert Counter(r["status"] for r in report["dashboard"]["results"]) == {
            "PASS": 1,
            "BLOCKED_BY_PREREQUISITE": 12,
        }
    finally:
        reporter.logger.close()


def test_evidence_pool_roundtrip_preserves_literal_marker():
    from neutron_flux.reporting_components.evidence_pool import pool_evidence

    from .evidence import expand_evidence

    payload = {
        "a": "a" * 300,
        "b": "a" * 300,
        "literal": {"$neutron_flux_evidence": 17},
    }
    encoded = pool_evidence(payload)
    assert expand_evidence(encoded) == payload


def test_coordinated_estimates_match_initial_boots(config_factory, discovery_fixture):
    from neutron_flux.pair_suite import estimate_pair_suite
    from neutron_flux.planning import Planner

    config = config_factory(
        target_host_pairs=[("hyper001", "hyper002")], performance_enabled=False
    )
    plan = planned(config, discovery_fixture)
    estimate_pair_suite(Planner(config, discovery_fixture, mock.Mock()), plan)
    assert plan.estimated["topology_lifetimes"] == 1
    assert plan.estimated["endpoint_vm_boots"] == 2
    assert plan.estimated["targeted_migrations_maximum"] == 1


def test_deleted_network_cannot_poison_later_topology():
    from neutron_flux.runtime.availability import AvailabilityRuntimeMixin

    builder = AvailabilityRuntimeMixin()
    builder.config = SimpleNamespace(resource_timeout=30)

    def resource(identity, group, status=None):
        return SimpleNamespace(
            resource_type="network",
            id=identity,
            delete_status=status,
            metadata={"group_id": group},
        )

    builder.reporter = SimpleNamespace(
        resources=[
            resource("old", "failed", "deleted"),
            resource("other", "other"),
            resource("new", "current"),
        ]
    )
    builder.pending_neutron_az_validation = {
        f"network:{identity}": {} for identity in ("old", "other", "new")
    }
    builder.osc = SimpleNamespace(json=mock.Mock(return_value={}))
    builder._validate_created_resource_zone = mock.Mock()
    builder._refresh_neutron_placements("current")
    assert "network:old" not in builder.pending_neutron_az_validation
    assert builder.osc.json.call_args.args[:3] == ("network", "show", "new")
    assert builder.osc.json.call_count == 1


def test_running_record_at_deadline_is_unverified(monkeypatch):
    instance = MigrationValidationMixin()
    instance.config = SimpleNamespace(resource_timeout=0)
    instance._observe_nova_migration_record = lambda *args, **kwargs: (
        False,
        "Nova migration record validation failed: status=running",
        {"status": "running"},
    )
    result, message, row = instance._verify_nova_migration_record(
        None, "a", "b", {"old"}
    )
    assert result is None and "terminal state" in message
    assert row["status"] == "running"


def test_cancelled_migration_propagates_without_retry(config_factory):
    from neutron_flux.errors import RunCancelledError
    from neutron_flux.execution.placement_migration import PlacementMigrationMixin

    executor = PlacementMigrationMixin()
    executor.logger = mock.Mock()
    executor.builder = SimpleNamespace(
        cloud_operation_coordinator=None,
        live_migrate_endpoint=mock.Mock(
            side_effect=RunCancelledError("operator cancelled")
        ),
    )
    moving = _endpoint("a", "A", "192.0.2.1", "a")
    peer = _endpoint("b", "B", "192.0.2.2", "b")
    with pytest.raises(RunCancelledError):
        executor._execute_migration_attempts(
            [(moving, peer, ComputeHostInfo("b", "az1", True, True))],
            migration_kind="live",
        )
    assert executor.builder.live_migrate_endpoint.call_count == 1


def test_resume_keeps_approved_checks_and_refreshes_completed_baselines(
    config_factory, discovery_fixture
):
    config = config_factory(
        action="run",
        target_host_pairs=[("hyper001", "hyper002")],
        performance_enabled=False,
    )
    plan = planned(config, discovery_fixture)
    reporter = Reporter(config, "resume-workflow")
    reporter.plan = plan
    reporter.save_plan()
    first = plan.tests[0]
    reporter.result(
        first.id,
        first.category,
        "PASS",
        "original generation",
        expected=first.expectation,
        observed="reachable",
    )
    config.resume_run_id = reporter.run_id
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
    try:
        approved = [r.copy() for r in plan.checks]
        executor.prepare_resume()
        replay = next(
            s
            for s in executor.plan.tests
            if s.metadata.get("source_spec_id") == first.id
        )
        assert replay.id != first.id
        assert replay.metadata["planned_check_id"] == first.id
        assert len(plan.checks) == 13 and plan.checks == approved
        assert reporter.has_result(first.id)
        assert len(executor.plan.tests) == 13
    finally:
        reporter.logger.close()


def test_failed_supporting_sample_does_not_override_terminal_check(config_factory):
    from neutron_flux.check_plan import build_check_plan

    config = config_factory(
        action="run", performance_enabled=False, compute_host_connectivity_enabled=False
    )
    plan = network_plan()
    build_check_plan(plan, config)
    sample = dataclasses.replace(
        plan.tests[0],
        id="failed-attempt",
        metadata={**plan.tests[0].metadata, "check_sample": True},
    )
    plan.tests.append(sample)
    reporter = Reporter(config, "sample-outcome")
    reporter.plan = plan
    reporter.cleanup_summary = {"complete": True}
    reporter.save_plan()
    try:
        reporter.result(
            sample.id,
            sample.category,
            "FAIL",
            "An intermediate attempt failed",
            expected="reachable",
            observed="blocked",
            authoritative=True,
        )
        for spec in plan.tests[:-1]:
            reporter.result(
                spec.id,
                spec.category,
                "PASS",
                "Terminal assessment passed",
                expected="reachable",
                observed="reachable",
                authoritative=True,
            )
        assert reporter.finalize(0) == 0
        assert "6 passed, 0 failed" in reporter._overall_result_line(
            "PASS", Counter(item.status for item in reporter.results)
        )
        from neutron_flux.reporting_components.dashboard_model import _incident_source

        assert not _incident_source(
            {"status": "FAIL", "details": {"check_sample": True}}
        )
        assert check_progress(reporter)["outcomes"] == {"PASSED": 6}
    finally:
        reporter.logger.close()
