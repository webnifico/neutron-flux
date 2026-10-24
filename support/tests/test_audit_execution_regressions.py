"""Integration regressions for independent execution-audit findings.

Cloud creation and packet I/O are instrumented boundaries. The production
planner, coordinator, engine, lifecycle state, migration selection, policy,
logical ledger and report recorder execute without verdict mocks.
"""

from __future__ import annotations

from collections import Counter
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.check_ledger import check_ledger, check_progress
from neutron_flux.check_plan import (
    build_check_plan,
    endpoint_sides,
    migration_batch_eligible,
)
from neutron_flux.engine import TestEngine as Engine
from neutron_flux.host_qualification import HostQualificationPlanner
from neutron_flux.models import (
    ComputeHostInfo,
    MigrationResult,
    ProbeResult,
    RuntimeGroup,
)
from neutron_flux.network_contract import TWO_ROUTER_STATIC_ROUTING
from neutron_flux.pair_suite import expand_pair_suite
from neutron_flux.pair_workflow import CoordinatedPairExecutor, workflow_plans
from neutron_flux.path_evidence import data_route_evidence
from neutron_flux.reporting import Reporter

from ._evidence import complete_continuity, data_route
from ._shared import build_plan
from .test_host_qualification import _Inventory, _service
from .test_performance_and_html import _endpoint


@pytest.mark.parametrize("ip_family", [4, 6])
@pytest.mark.parametrize("initial_relation", ["intra", "inter"])
def test_real_static_route_workflow_runs_all_directions_and_migrates_without_recreation(
    config_factory,
    discovery_fixture,
    tmp_path,
    monkeypatch,
    ip_family,
    initial_relation,
):
    config = config_factory(
        action="run",
        target_host_pairs=[("hyper001", "hyper002")],
        migration_mode="live-only",
        live_migration_continuity=False,
        performance_enabled=False,
        convergence_interval=0,
        convergence_timeout=1,
        quiet_period_scale=0,
        operation_gap_scale=0,
    )
    plan = build_plan(config, discovery_fixture, tmp_path)
    group = next(
        g
        for g in plan.groups
        if g.kind == TWO_ROUTER_STATIC_ROUTING and g.families == [ip_family]
    )
    plan.provider_groups = []
    plan.tenant_groups = [group]
    plan.tests = [s for s in plan.tests if s.dependencies == [group.id]]
    plan.checks = []
    plan.host_qualification = HostQualificationPlanner(
        config,
        discovery_fixture,
        plan,
        _Inventory([_service("hyper001", "az1"), _service("hyper002", "az1")]),
        mock.Mock(),
    ).build()
    plan = expand_pair_suite(plan, coordinated=True)
    build_check_plan(plan, config)
    reporter = Reporter(config, "static-route-real-engine")
    reporter.plan = plan
    reporter.save_plan()
    calls, migrations = [], []
    counts = Counter()
    builder = SimpleNamespace(
        discovery=discovery_fixture,
        runtime_groups=[],
        group_failures={},
        cloud_operation_coordinator=None,
        group_failure_reason=lambda _: None,
        ssh_endpoint=mock.Mock(),
        ssh_controller=mock.Mock(),
        inspect_endpoint_route=data_route,
    )

    def build(group, *, sides):
        counts["topologies"] += 1
        endpoints = []
        for side in sides:
            counts["boots"] += 1
            address = (
                ("10.42.0.10" if side == "A" else "10.43.0.10")
                if ip_family == 4
                else ("fd42:1::10" if side == "A" else "fd42:2::10")
            )
            host = (
                "hyper001"
                if initial_relation == "intra"
                else group.metadata["target_hosts"][side]
            )
            ep = _endpoint(side, side, address, host)
            ep.fixed_ips = {"subnet-" + side: next(iter(ep.fixed_ips.values()))}
            endpoints.append(ep)
        return RuntimeGroup(
            group,
            "network",
            "network",
            ["subnet-A", "subnet-B"],
            "router-a",
            endpoints,
            False,
            {},
            metadata={
                "side_subnet_ids": {"A": "subnet-A", "B": "subnet-B"},
                "routes_installed": False,
            },
        )

    builder.build_group = build
    builder.build_group_side = mock.Mock(
        side_effect=AssertionError("unexpected endpoint recreation")
    )
    builder.stop_group_probes = lambda *a: None
    builder.stop_endpoint_probe = lambda *a: None
    builder._existing_probe_service_ready = lambda *_: (
        True,
        {"listeners": {"4": {"tcp": True, "udp": True, "instance_id": "live-service"}}},
    )

    def routes(runtime, *, enabled):
        runtime.metadata["routes_installed"] = enabled
        calls.append(("routes", enabled))

    def one_route(runtime, *, side, enabled):
        runtime.metadata["routes_installed"] = enabled
        calls.append(("one-route", side, enabled))

    builder.set_static_routes = routes
    builder.set_one_static_route = one_route

    def packet(protocol, source, source_ip, destination_ip, family, **_kwargs):
        runtime = builder.runtime_groups[0]
        assert source_ip in source.fixed_ips.values()
        target = next(
            ep for ep in runtime.endpoints if destination_ip in ep.fixed_ips.values()
        )
        assert source.server_id != target.server_id and family == ip_family
        assert source.availability_zone == target.availability_zone == "az1"
        enabled = runtime.metadata["routes_installed"]
        calls.append(
            (
                "packet",
                protocol,
                source.side,
                target.side,
                enabled,
                source.host,
                target.host,
            )
        )
        return ProbeResult(
            "reachable" if enabled else "blocked",
            enabled,
            1,
            1,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
        )

    monkeypatch.setattr(
        "neutron_flux.engine.ProbeRegistry", lambda _: SimpleNamespace(endpoint=packet)
    )
    monkeypatch.setattr(
        "neutron_flux.execution.placement_migration.time.sleep", lambda _: None
    )
    builder.select_compute_migration_targets = lambda moving, peer, **_: (
        [
            ComputeHostInfo(host, "az1", True, True)
            for host in ("hyper001", "hyper002")
            if host != moving.host
        ],
        "eligible",
    )

    def migrate(moving, target, peer=None):
        assert moving.availability_zone == target.availability_zone == "az1"
        previous = moving.host
        migrations.append((moving.side, previous, target.host))
        moving.host = target.host
        return MigrationResult(
            moving.server_id,
            previous,
            target.host,
            "az1",
            "az1",
            True,
            False,
            True,
            details={"migration_mode": "live"},
        )

    builder.live_migrate_endpoint = migrate
    builder.cold_migrate_endpoint = mock.Mock(
        side_effect=AssertionError("unexpected fallback")
    )
    builder.verify_server_placement = lambda *a, **kw: None
    cleanup = SimpleNamespace(
        cleanup_group=lambda _: True, cleanup_group_side=lambda *a: True
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
    try:
        original = [dict(row) for row in plan.checks]
        executor.run()
        assert counts == {"topologies": 1, "boots": 2}
        initial = (
            ("hyper001", "hyper001")
            if initial_relation == "intra"
            else ("hyper001", "hyper002")
        )
        opposite = (
            ("hyper001", "hyper002")
            if initial_relation == "intra"
            else ("hyper001", "hyper001")
        )
        assert migrations == [("B", initial[1], opposite[1])]
        assert builder.build_group_side.call_count == 0
        ordinary = [
            row
            for row in reporter.results
            if row.details.get("operation") == "probe"
            and row.category == "router-static-routing"
        ]
        assert ordinary and all(
            row.details["probe"]["attempts"] > 0 for row in ordinary
        )
        assert all(row["outcome"] == "PASSED" for row in check_ledger(reporter)), [
            row for row in reporter.results if row.status != "PASS"
        ]
        for placement in [initial, opposite]:
            observed = {
                (row[1], row[2], row[3])
                for row in calls
                if row[0] == "packet"
                and row[4]
                and (row[5], row[6]) in {placement, placement[::-1]}
            }
            assert observed == {
                (protocol, a, b)
                for protocol in ("icmp", "tcp", "udp")
                for a, b in (("A", "B"), ("B", "A"))
            }
        assert plan.checks == original
        progress = check_progress(reporter)
        assert progress["planned_recorded"] == progress["planned"]
    finally:
        reporter.logger.close()


@pytest.mark.parametrize(
    "fault,verified",
    [
        (None, True),
        ("management", False),
        ("missing-inventory", None),
        ("wrong-mac", False),
        ("wrong-source", False),
        ("wrong-address", False),
    ],
)
def test_data_port_proof_is_fail_closed(fault, verified):
    ep = _endpoint("source", "A", "192.0.2.10", "compute")
    route = data_route(ep, "192.0.2.10", "192.0.2.20", 4)
    if fault == "management":
        route["device"] = "ens3"
    if fault == "missing-inventory":
        route.pop("interfaces")
    if fault == "wrong-mac":
        route["interfaces"][1]["address"] = "ff:ff:ff:ff:ff:ff"
    if fault == "wrong-source":
        route["source"] = ep.management_ip
    if fault == "wrong-address":
        route["interfaces"][1]["addr_info"] = []
    assert (
        data_route_evidence(ep, "192.0.2.10", "192.0.2.20", route)["verified"]
        is verified
    )


@pytest.mark.parametrize("no_pools", [False, True])
def test_ipv4_external_selection_preserves_internal_dual_stack_and_every_fip_owner(
    config_factory,
    discovery_fixture,
    tmp_path,
    no_pools,
):
    from .test_self_service_discovery import _selected_networks

    discovery = _selected_networks(discovery_fixture, "n3")
    if no_pools:
        discovery.pools = []
    config = config_factory(
        external_networks=["Public3"],
        migration_mode="live-preferred",
        performance_enabled=False,
    )
    plan = build_plan(config, discovery, tmp_path)
    internal = [
        g
        for g in plan.groups
        if g.kind in {"one-router-project-networks", TWO_ROUTER_STATIC_ROUTING}
    ]
    assert {family for group in internal for family in group.families} == {4, 6}
    assert not any(
        s.family == 6 and s.operation in {"egress", "fip-baseline", "fip-peer"}
        for s in plan.tests
    )
    if no_pools:
        assert all(group.metadata.get("generated_subnet_cidrs") for group in internal)
    peers = [
        g
        for g in plan.groups
        if g.metadata.get("fip_peer_for") and not g.metadata.get("snat_source_for")
    ]
    assert peers
    for group in peers:
        hairpins = [
            s
            for s in plan.tests
            if s.operation == "fip-peer"
            and s.source_group_id == s.destination_group_id == group.id
        ]
        assert {s.protocol for s in hairpins} == {"icmp", "tcp", "udp"}
        assert len(hairpins) == 3
        assert all(
            sum(len(sides) for _, sides in endpoint_sides(s)) == 2 for s in hairpins
        )
        assert all(s.source_side == s.destination_side == "A" for s in hairpins)
    build_check_plan(plan, config)
    for spec in plan.tests:
        if (
            spec.category == "project-provider-connectivity"
            and spec.authoritative
            and spec.expectation == "reachable"
        ):
            assert migration_batch_eligible([spec])
            assert spec.metadata.get("check_bindings", {}).get("post-migration"), (
                spec.metadata
            )


@pytest.mark.parametrize(
    "fault",
    [
        "udp-dead",
        "icmp-unrecovered",
        "receiver-missing",
        "receiver-short",
        "wrong-session",
        "missing-terminal",
        "wrong-counts",
    ],
)
def test_continuity_never_passes_independent_loss_or_incomplete_evidence(fault):
    from neutron_flux.execution.placement_migration import PlacementMigrationMixin

    evidence = complete_continuity()
    if fault == "udp-dead":
        evidence = complete_continuity(udp_loss=100)
    if fault == "icmp-unrecovered":
        evidence = complete_continuity(icmp_loss=90, recovered=False, outage=22)
    if fault == "receiver-missing":
        evidence["tcp"].pop("server_result")
    if fault == "receiver-short":
        evidence["tcp"]["server_result"]["bytes"] -= 1
    if fault == "wrong-session":
        evidence["udp"]["response"]["session_id"] += 1
    if fault == "missing-terminal":
        evidence["tcp"]["terminal"] = False
    if fault == "wrong-counts":
        evidence["icmp"]["raw_samples"][-1]["ok"] = False
    status, _, _, _ = PlacementMigrationMixin._live_continuity_verdict(evidence)
    assert status in {"FAIL", "UNVERIFIED"}


@pytest.mark.parametrize("fault", [None, "management", "missing-route", "zero-attempt"])
def test_actual_recorder_labels_self_path_and_rejects_management_pass(
    config_factory, fault
):
    from neutron_flux.models import Plan
    from neutron_flux.policy import PolicyEvaluator

    from .test_engine_handlers import _runtime_group, _spec

    ep = _endpoint("self", "A", "192.0.2.10", "compute1")
    runtime = _runtime_group("source", [ep])
    spec = _spec("fip-peer", category="floating-ip-peer", protocol="tcp")
    spec.source_group_id = spec.destination_group_id = "source"
    spec.source_side = spec.destination_side = "A"
    spec.dependencies = ["source"]
    spec.display_name = "Own floating-IP hairpin — inter-compute — inter"
    spec.metadata.update(
        compute_placement="inter-compute",
        pair_placement="inter",
        nat_path="self-hairpin",
    )
    config = config_factory(
        action="run", performance_enabled=False, compute_host_connectivity_enabled=False
    )
    plan = Plan([], [runtime.plan], {}, [], tests=[spec])
    build_check_plan(plan, config)
    reporter = Reporter(config, "self-route-proof")
    reporter.plan = plan
    reporter.save_plan()
    route = data_route(ep, "192.0.2.10", "198.51.100.10", 4)
    if fault == "management":
        route["device"] = "ens3"
    if fault == "missing-route":
        route = None
    engine = Engine.__new__(Engine)
    engine.builder = SimpleNamespace(
        runtime_groups=[runtime], inspect_endpoint_route=lambda *a: route
    )
    engine._runtime_groups = (runtime,)
    engine.policy = PolicyEvaluator()
    engine.diagnostics = SimpleNamespace(collect=lambda *a: (None, {}))
    engine.reporter = reporter
    probe = ProbeResult(
        "inconclusive" if fault == "zero-attempt" else "reachable",
        fault != "zero-attempt",
        1,
        0 if fault == "zero-attempt" else 1,
        source_ip="192.0.2.10",
        destination_ip="198.51.100.10",
        protocol="tcp",
    )
    try:
        engine._record(spec, probe, ep, ep)
        row = reporter.results[-1]
        assert row.details["packet_path_placement"] == "self"
        assert row.details["pair_placement"] == "self"
        assert row.details["topology_placement_context"]["pair_placement"] == "inter"
        assert "inter-compute" not in row.display_name
        assert (
            row.status
            == {
                None: "PASS",
                "management": "ERROR",
                "missing-route": "UNVERIFIED",
                "zero-attempt": "UNVERIFIED",
            }[fault]
        )
        if fault == "zero-attempt":
            assert row.details["coverage_outcome"] == "NEVER_RAN"
            assert check_progress(reporter)["executed"] == 0
    finally:
        reporter.logger.close()


def test_data_port_proof_accepts_equivalent_ipv6_notation():
    ep = _endpoint("source", "A", "FD00:0000:0000:0000:0000:0000:0000:0010", "compute")
    route = data_route(ep, "fd00::10", "fd00::20", 6)
    route["interfaces"][1]["addr_info"] = [{"local": "fd00::10"}]
    assert data_route_evidence(ep, "fd00::10", "fd00::20", route)["verified"] is True


def test_unready_continuity_never_submits_live_migration(config_factory):
    from neutron_flux.errors import UnverifiableMigrationError
    from neutron_flux.resources import ResourceBuilder

    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory(migration_mode="live-preferred")
    builder.cloud_operation_coordinator = None
    builder.osc = mock.Mock()
    builder._record_migration_destination = mock.Mock()
    builder._pre_migration_control_plane_barrier = mock.Mock()
    builder._capture_endpoint_migration_state = mock.Mock(return_value={})
    builder._start_live_continuity = mock.Mock(
        return_value={"available": False, "reason": "receiver unavailable"}
    )
    moving = _endpoint("moving", "B", "192.0.2.20", "compute1")
    peer = _endpoint("peer", "A", "192.0.2.10", "compute1")
    target = ComputeHostInfo("compute2", "az1", True, True)
    with pytest.raises(UnverifiableMigrationError, match="not submitted.*continuity"):
        builder._live_migrate_endpoint_once(moving, target, peer)
    builder.osc.assert_not_called()
    assert builder.osc.mock_calls == []
    assert "_live_continuity_state" not in moving.metadata


@pytest.mark.parametrize(
    "field,value",
    [
        ("port_id", "wrong-port"),
        ("fixed_ip_address", "10.255.0.1"),
        ("floating_ip_address", "198.51.100.99"),
        ("matched", False),
    ],
)
def test_fip_mapping_boolean_does_not_replace_exact_association_fields(
    config_factory,
    discovery_fixture,
    tmp_path,
    field,
    value,
):
    from neutron_flux.errors import SuiteError

    from .test_floating_ip_matrix import _matrix_engine

    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    engine, spec, source, target, _ = _matrix_engine(plan)
    mapping = engine.builder.wait_floating_ip_association(
        engine.groups[spec.source_group_id].fips[source.label]["id"]
    )
    mapping[field] = value
    engine.builder.wait_floating_ip_association.return_value = mapping
    with pytest.raises(SuiteError, match="mapping could not be verified"):
        engine._run_fip_peer(spec)
    engine.probes.tcp.endpoint_peer_identity.assert_not_called()
