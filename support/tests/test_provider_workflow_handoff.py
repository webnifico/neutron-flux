"""Reuse one verified provider VM without adding placement stages or quota."""

from __future__ import annotations

import dataclasses
from collections import Counter
from contextlib import nullcontext
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.check_ledger import check_ledger
from neutron_flux.check_plan import build_check_plan
from neutron_flux.errors import (
    ControllerUnavailableError,
    RunCancelledError,
    SuiteError,
)
from neutron_flux.executor import AdaptiveExecutor
from neutron_flux.host_qualification import HostQualificationPlanner
from neutron_flux.models import ComputeHostInfo, MigrationResult, RuntimeGroup
from neutron_flux.pair_suite import (
    expand_pair_suite,
    provider_handoff_group,
    provider_reuse_lanes,
    run_pair_suite,
)
from neutron_flux.pair_workflow import CoordinatedPairExecutor, workflow_plans
from neutron_flux.reporting import Reporter

from .test_host_qualification import _Inventory, _service
from .test_performance_and_html import _endpoint
from .test_planned_check_inventory import fake_measurements, network_plan


def _plan(config, discovery):
    plan = network_plan(("public", "mail"))
    # A provider cross-network lifetime has one A role from each network.
    cross = []
    for spec in plan.tests[:6]:
        reverse = spec.source_side == "B"
        cross.append(
            dataclasses.replace(
                spec,
                id=f"cross-{spec.id}",
                phase="cross",
                dependencies=["public", "mail"],
                source_group_id="mail" if reverse else "public",
                destination_group_id="public" if reverse else "mail",
                source_side="A",
                destination_side="A",
            )
        )
    plan.tests.extend(cross)
    plan.host_qualification = HostQualificationPlanner(
        config,
        discovery,
        plan,
        _Inventory([_service("compute-a", "az1"), _service("compute-b", "az1")]),
        mock.Mock(),
    ).build()
    plan = expand_pair_suite(plan, coordinated=True)
    build_check_plan(plan, config)
    return plan


@pytest.mark.parametrize(
    "handoff_read_error,performance_enabled",
    [(None, False), ("placement", False), ("probe-service", False), (None, True)],
)
def test_provider_chain_keeps_all_checks_and_one_move_per_lifetime(
    config_factory,
    discovery_fixture,
    monkeypatch,
    handoff_read_error,
    performance_enabled,
):
    config = config_factory(
        action="run",
        target_host_pairs=[("compute-a", "compute-b")],
        migration_mode="live-only",
        compute_host_connectivity_enabled=True,
        performance_enabled=performance_enabled,
        live_migration_continuity=False,
    )
    plan = _plan(config, discovery_fixture)
    checks = [row.copy() for row in plan.checks]
    lanes = workflow_plans(plan)
    ordered = provider_reuse_lanes(lanes, config)
    assert [len(lane.groups) for lane in ordered] == [1, 2, 1]
    assert {spec.id for lane in ordered for spec in lane.tests} == {
        spec.id for spec in plan.tests
    }
    reporter = Reporter(config, "provider-handoff")
    reporter.plan = plan
    reporter.save_plan()
    counts = Counter()
    alive = {}
    placements = []
    migrations = []
    retained_measurements = []
    summary = {
        "unresolved_count": 0,
        "quarantined_resources": {},
        "quarantined_hosts": [],
        # Historical completed migrations must not force a return migration.
        "operations": [{"kind": "migration", "outcome": "SUCCEEDED"}],
    }
    builder = SimpleNamespace(
        discovery=discovery_fixture,
        runtime_groups=[],
        group_failures={},
        group_failure_reason=lambda _: None,
        cloud_operation_coordinator=SimpleNamespace(
            transaction=lambda *args, **kwargs: nullcontext(),
            cloud_operation_summary=lambda: summary,
            annotate_current_transaction=lambda **kwargs: None,
            current_transaction_records=lambda: [],
        ),
        probe_service=SimpleNamespace(is_running=lambda _: True),
        _stable_existing_probe_service=lambda _: (True, {}),
        stop_group_probes=lambda *args: None,
        stop_endpoint_probe=lambda *args: None,
        verify_server_placement=lambda *args, **kwargs: None,
    )
    retaining = False
    retain = CoordinatedPairExecutor._retain_provider_endpoint

    def retain_with_read_failure(executor):
        nonlocal retaining
        retaining = True
        try:
            retained = retain(executor)
            if retained and performance_enabled:
                measurements = [
                    spec
                    for spec in executor.plan.tests
                    if spec.category == "network-performance"
                ]
                assert len(measurements) == 14
                assert all(
                    reporter.get_result(spec.id).status == "PASS"
                    for spec in measurements
                )
                retained_measurements.append({spec.id for spec in measurements})
            return retained
        finally:
            retaining = False

    def verify_placement(*args, **kwargs):
        if retaining and handoff_read_error == "placement":
            raise SuiteError("Final provider placement readback is unavailable")

    def verify_probe(_endpoint):
        if handoff_read_error == "probe-service":
            raise SuiteError("Final provider probe readback is unavailable")
        return True, {}

    builder.verify_server_placement = verify_placement
    builder._stable_existing_probe_service = verify_probe
    monkeypatch.setattr(
        CoordinatedPairExecutor,
        "_retain_provider_endpoint",
        retain_with_read_failure,
    )

    def boot(group, side):
        counts["boot"] += 1
        endpoint = _endpoint(
            str(counts["boot"]),
            side,
            f"192.0.2.{10 + counts['boot']}",
            group.metadata["target_hosts"][side],
        )
        endpoint.availability_zone = "az1"
        alive[endpoint.server_id] = (group.id, side)
        counts["peak"] = max(counts["peak"], len(alive))
        assert len(alive) <= 2
        return endpoint

    def build(group, *, sides):
        counts["topology"] += 1
        runtime = RuntimeGroup(
            group,
            "network",
            "network",
            ["subnet"],
            None,
            [boot(group, side) for side in sides],
            None,
            {},
        )
        return runtime

    def build_side(runtime, group, side):
        counts["side"] += 1
        runtime.endpoints.append(boot(group, side))
        runtime.plan = group
        return runtime.endpoints[-1]

    builder.build_group = build
    builder.build_group_side = build_side
    builder.select_compute_migration_targets = lambda moving, peer, **kwargs: (
        [
            ComputeHostInfo(host, "az1", True, True)
            for host in ("compute-a", "compute-b")
            if host != moving.host
        ],
        "eligible",
    )

    def migrate(moving, target, peer=None):
        counts["migration"] += 1
        source = moving.host
        moving.host = target.host
        migrations.append((moving.server_id, source, target.host))
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
            details={"migration_mode": "live"},
        )

    builder.live_migrate_endpoint = migrate
    builder.cold_migrate_endpoint = migrate

    def cleanup_group(group_id):
        for server_id, (owner, _side) in list(alive.items()):
            if owner == group_id:
                alive.pop(server_id)
        return True

    def cleanup_side(group_id, side):
        for server_id, (owner, role) in list(alive.items()):
            if (owner, role) == (group_id, side):
                alive.pop(server_id)
        return True

    cleanup = SimpleNamespace(
        cleanup_group=cleanup_group,
        cleanup_group_side=cleanup_side,
    )

    def emit(specs):
        for spec in specs:
            if reporter.has_result(spec.id):
                continue
            endpoints = [ep for r in builder.runtime_groups for ep in r.endpoints]
            assert len(endpoints) == 2
            assert len({ep.server_id for ep in endpoints}) == 2
            if not spec.metadata.get("supplemental"):
                placements.append(
                    (
                        spec.metadata["workflow_batch"],
                        spec.metadata["pair_placement"],
                        tuple(ep.host for ep in endpoints),
                    )
                )
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

    def endpoint_address(group_id, side, subnet_id):
        runtime = next(
            runtime for runtime in builder.runtime_groups if runtime.plan.id == group_id
        )
        endpoint = runtime.endpoint(side)
        return endpoint, endpoint.fixed_ips[subnet_id]

    monkeypatch.setattr(
        "neutron_flux.pair_workflow.TestEngine",
        lambda *args: SimpleNamespace(
            run_specs=emit,
            lifecycle={},
            _endpoint_address=endpoint_address,
            _network_mtu=lambda _: 1500,
        ),
    )
    if performance_enabled:
        # Keep planning, prerequisite selection, reservation binding, measurement
        # isolation and recording real; replace the guest traffic boundary only.
        fake_measurements(monkeypatch)
    monkeypatch.setattr(
        "neutron_flux.execution.placement_migration.time.sleep", lambda _: None
    )
    monkeypatch.setattr(AdaptiveExecutor, "_refresh_checkpoint", lambda _: None)
    monkeypatch.setattr(AdaptiveExecutor, "_validate_plan_consistency", lambda _: None)
    try:
        run_pair_suite(
            config, plan, builder, reporter, cleanup, mock.Mock(), mock.Mock()
        )
        if handoff_read_error is None:
            assert counts == {
                "boot": 4,
                "topology": 2,
                "side": 1,
                "migration": 3,
                "peak": 2,
            }
        else:
            # Each failed optional readback releases the completed lifetime.
            # All three independent lifetimes still run using fresh endpoints.
            assert counts == {
                "boot": 6,
                "topology": 4,
                "migration": 3,
                "peak": 2,
            }
            declines = [
                event
                for event in reporter.events
                if event.get("type") == "provider-endpoint-reuse-declined"
            ]
            assert len(declines) == 2
            assert all(
                event.get("details", {}).get("readback_stage") == handoff_read_error
                for event in declines
            )
        assert len(migrations) == 3
        assert not alive
        assert not builder.runtime_groups
        assert plan.checks == checks
        assert len(checks) == (81 if performance_enabled else 39)
        assert all(row["outcome"] == "PASSED" for row in check_ledger(reporter))
        if performance_enabled:
            reserved = [row for row in checks if row["kind"] == "performance"]
            completed = [
                row for row in check_ledger(reporter) if row["kind"] == "performance"
            ]
            assert len(reserved) == len(completed) == 42
            assert {row["id"] for row in completed} == {row["id"] for row in reserved}
            assert len(retained_measurements) == 2
            assert len(set.union(*retained_measurements)) == 28
            assert (
                sum(
                    event["details"]["selected_paths"]
                    for event in reporter.events
                    if event["type"] == "performance-coverage"
                )
                == 6
            )
        for lane in ordered:
            batch = lane.tests[0].metadata["workflow_batch"]
            before = {
                hosts
                for identity, stage, hosts in placements
                if identity == batch and stage == "initial"
            }
            after = {
                hosts
                for identity, stage, hosts in placements
                if identity == batch and stage == "opposite"
            }
            assert len(before) == len(after) == 1
            initial, opposite = next(iter(before)), next(iter(after))
            assert (initial[0] == initial[1]) != (opposite[0] == opposite[1])
    finally:
        reporter.logger.close()


@pytest.mark.parametrize(
    "barrier", ["resume", "selective", "performance", "prerequisite"]
)
def test_provider_reordering_respects_selection_and_dependencies(
    config_factory, discovery_fixture, barrier
):
    config = config_factory(
        target_host_pairs=[("compute-a", "compute-b")],
        performance_enabled=False,
    )
    plan = _plan(config, discovery_fixture)
    lanes = workflow_plans(plan)
    if barrier == "resume":
        config.resume_run_id = "prior-run"
    elif barrier == "selective":
        config.test_ids = [plan.tests[0].id]
    elif barrier == "performance":
        config.performance_enabled = True
        config.performance_max_paths = 1
    else:
        lanes[-1].tests[0].requires_pass = [lanes[1].tests[0].id]
    assert provider_reuse_lanes(lanes, config) == lanes


def test_provider_handoff_rejects_changed_scope_or_topology(
    config_factory, discovery_fixture
):
    config = config_factory(target_host_pairs=[("compute-a", "compute-b")])
    lanes = workflow_plans(_plan(config, discovery_fixture))
    assert provider_handoff_group(lanes[0], lanes[-1]) is not None
    changed = dataclasses.replace(
        lanes[-1],
        provider_groups=[
            dataclasses.replace(group, network_id="changed")
            for group in lanes[-1].groups
        ],
    )
    assert provider_handoff_group(lanes[0], changed) is None
    lanes[-1].tests[0].metadata = {
        **lanes[-1].tests[0].metadata,
        "host_qualification_cycle": 2,
    }
    assert provider_handoff_group(lanes[0], lanes[-1]) is None


@pytest.mark.parametrize(
    "barrier",
    [
        "failed",
        "missing",
        "fip",
        "pending-fip",
        "unresolved",
        "resource-quarantine",
        "host-quarantine",
        "read-only",
        "probe-stopped",
        "probe-unready",
    ],
)
def test_provider_retention_fails_closed(barrier):
    from .test_endpoint_parallel_setup import _endpoint as endpoint
    from .test_endpoint_parallel_setup import _group, _runtime

    executor = CoordinatedPairExecutor.__new__(CoordinatedPairExecutor)
    runtime = _runtime(_group("public"))
    runtime.endpoints = [endpoint("public")]
    executor.active = {"public": runtime}
    executor.handoff_group_id = "public"
    executor.plan = SimpleNamespace(tests=[SimpleNamespace(id="check")])
    result = SimpleNamespace(status="FAIL" if barrier == "failed" else "PASS")
    executor.reporter = SimpleNamespace(
        get_result=lambda _: None if barrier == "missing" else result,
        event=mock.Mock(),
    )
    summary = {
        "unresolved_count": int(barrier == "unresolved"),
        "quarantined_resources": {"server": "operation"}
        if barrier == "resource-quarantine"
        else {},
        "quarantined_hosts": ["compute-a"] if barrier == "host-quarantine" else [],
    }
    executor.builder = SimpleNamespace(
        cloud_operation_coordinator=SimpleNamespace(
            cloud_operation_summary=lambda: summary
        ),
        probe_service=SimpleNamespace(is_running=lambda _: barrier != "probe-stopped"),
        _stable_existing_probe_service=lambda _: (barrier != "probe-unready", {}),
    )
    executor._verify_runtime = mock.Mock()
    executor._release = mock.Mock()
    executor._refresh_checkpoint = mock.Mock()
    if barrier == "fip":
        runtime.fips["vm"] = "198.51.100.20"
    elif barrier == "pending-fip":
        runtime.metadata["pending_floating_ips"] = {"vm": "allocation"}
    elif barrier == "read-only":
        executor._post_transition_read_only = True
    assert executor._retain_provider_endpoint() is False
    assert executor.active == {"public": runtime}
    executor._release.assert_not_called()
    executor.reporter.event.assert_not_called()


@pytest.mark.parametrize("stage", ["placement", "probe-service"])
@pytest.mark.parametrize("error_type", [RunCancelledError, ControllerUnavailableError])
def test_provider_retention_preserves_fatal_readback_errors(stage, error_type):
    from .test_endpoint_parallel_setup import _endpoint as endpoint
    from .test_endpoint_parallel_setup import _group, _runtime

    executor = CoordinatedPairExecutor.__new__(CoordinatedPairExecutor)
    runtime = _runtime(_group("public"))
    runtime.endpoints = [endpoint("public")]
    executor.active = {"public": runtime}
    executor.handoff_group_id = "public"
    executor.plan = SimpleNamespace(tests=[SimpleNamespace(id="check")])
    executor.reporter = SimpleNamespace(
        get_result=lambda _: SimpleNamespace(status="PASS"), event=mock.Mock()
    )
    executor.builder = SimpleNamespace(
        cloud_operation_coordinator=SimpleNamespace(cloud_operation_summary=lambda: {}),
        probe_service=SimpleNamespace(is_running=lambda _: True),
        _stable_existing_probe_service=mock.Mock(return_value=(True, {})),
    )
    executor._verify_runtime = mock.Mock()
    read = (
        executor._verify_runtime
        if stage == "placement"
        else executor.builder._stable_existing_probe_service
    )
    read.side_effect = error_type("Fatal readback failure")
    with pytest.raises(error_type, match="Fatal readback failure"):
        executor._retain_provider_endpoint()
    assert executor.active == {"public": runtime}
    executor.reporter.event.assert_not_called()


@pytest.mark.parametrize(
    "exit_path",
    [
        "error",
        "interrupt-after-retention",
        "cancel-between-lanes",
        "ineligible",
        "already-complete",
    ],
)
def test_suite_releases_retained_ownership_on_every_exit(
    config_factory, discovery_fixture, monkeypatch, exit_path
):
    from neutron_flux.errors import RunCancelledError

    from .test_endpoint_parallel_setup import _runtime

    config = config_factory(
        target_host_pairs=[("compute-a", "compute-b")],
        performance_enabled=False,
    )
    plan = _plan(config, discovery_fixture)
    lanes = provider_reuse_lanes(workflow_plans(plan), config)
    following_ids = {spec.id for spec in lanes[1].tests}
    if exit_path == "ineligible":
        for spec in lanes[1].tests:
            spec.metadata["pair_scope_eligible"] = False
    calls = Counter()
    owners = []
    released = []
    reporter = SimpleNamespace(
        logger=mock.Mock(),
        results=[SimpleNamespace(scenario="Network", status="PASS")],
        has_result=lambda identity: (
            exit_path == "already-complete" and identity in following_ids
        ),
    )

    def execute(executor):
        calls["run"] += 1
        if calls["run"] == 1:
            runtime = _runtime(executor.plan.groups[0])
            executor.active = {runtime.plan.id: runtime}
            owners.append(executor)
            if exit_path == "interrupt-after-retention":
                raise KeyboardInterrupt("interrupted after retaining provider endpoint")
        elif exit_path == "error":
            assert executor.active
            raise ValueError("unexpected lane failure")
        else:
            release(executor)

    def release(executor):
        released.extend(executor.active)
        executor.active.clear()

    def cancellation():
        calls["cancel-check"] += 1
        if exit_path == "cancel-between-lanes" and calls["cancel-check"] == 2:
            raise RunCancelledError("cancelled between topology lifetimes")

    monkeypatch.setattr(CoordinatedPairExecutor, "run", execute)
    monkeypatch.setattr(CoordinatedPairExecutor, "_release_all", release)
    monkeypatch.setattr(CoordinatedPairExecutor, "_refresh_checkpoint", lambda _: None)
    monkeypatch.setattr(
        CoordinatedPairExecutor, "_mark_specs_unavailable", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(AdaptiveExecutor, "_refresh_checkpoint", lambda _: None)
    monkeypatch.setattr(AdaptiveExecutor, "_validate_plan_consistency", lambda _: None)
    monkeypatch.setattr("neutron_flux.pair_suite.raise_if_cancelled", cancellation)
    monkeypatch.setattr(
        "neutron_flux.pair_suite.conditional_pending", lambda *args, **kwargs: False
    )
    expected = {
        "error": ValueError,
        "interrupt-after-retention": KeyboardInterrupt,
        "cancel-between-lanes": RunCancelledError,
    }.get(exit_path)
    if expected is not None:
        with pytest.raises(expected):
            run_pair_suite(
                config,
                plan,
                SimpleNamespace(),
                reporter,
                mock.Mock(),
                mock.Mock(),
                mock.Mock(),
            )
    else:
        run_pair_suite(
            config,
            plan,
            SimpleNamespace(),
            reporter,
            mock.Mock(),
            mock.Mock(),
            mock.Mock(),
        )
    assert len(released) == 1
    assert all(not owner.active for owner in owners)


def test_suite_releases_provider_when_interrupted_during_ownership_transfer(
    config_factory, discovery_fixture, monkeypatch
):
    from .test_endpoint_parallel_setup import _runtime

    config = config_factory(
        target_host_pairs=[("compute-a", "compute-b")],
        performance_enabled=False,
    )
    plan = _plan(config, discovery_fixture)
    reporter = SimpleNamespace(
        logger=mock.Mock(), results=[], has_result=lambda _: False
    )
    owners = []
    released = []
    calls = Counter()
    initialize = CoordinatedPairExecutor.__init__

    def track_owner(executor, *args, **kwargs):
        initialize(executor, *args, **kwargs)
        owners.append(executor)

    def execute(executor):
        calls["run"] += 1
        assert calls["run"] == 1
        runtime = _runtime(executor.plan.groups[0])
        runtime.endpoints = runtime.endpoints[:1]
        executor.active = {runtime.plan.id: runtime}

    def release(executor):
        released.extend(executor.active)
        executor.active.clear()

    def interrupt_after_clearing_owner(executor, name, value):
        previous = getattr(executor, name, None)
        object.__setattr__(executor, name, value)
        if name == "active" and previous and value == {}:
            calls["interrupt"] += 1
            raise KeyboardInterrupt("interrupted during provider ownership transfer")

    monkeypatch.setattr(CoordinatedPairExecutor, "__init__", track_owner)
    monkeypatch.setattr(CoordinatedPairExecutor, "run", execute)
    monkeypatch.setattr(CoordinatedPairExecutor, "_release_all", release)
    monkeypatch.setattr(
        CoordinatedPairExecutor,
        "__setattr__",
        interrupt_after_clearing_owner,
    )
    with pytest.raises(KeyboardInterrupt, match="during provider ownership transfer"):
        run_pair_suite(
            config,
            plan,
            SimpleNamespace(),
            reporter,
            mock.Mock(),
            mock.Mock(),
            mock.Mock(),
        )
    assert calls == {"run": 1, "interrupt": 1}
    assert len(owners) == 2
    assert released == [owners[0].plan.groups[0].id]
    assert all(not owner.active for owner in owners)
