from __future__ import annotations

import copy
from collections import defaultdict
from types import MethodType, SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.check_ledger import check_ledger
from neutron_flux.check_plan import (
    batch_key,
    build_check_plan,
    migration_baseline_specs,
    migration_readback_specs,
)
from neutron_flux.engine import TestEngine as Engine
from neutron_flux.errors import SuiteError
from neutron_flux.executor import AdaptiveExecutor
from neutron_flux.models import ComputeHostInfo, MigrationResult, ProbeResult
from neutron_flux.reporting import Reporter
from neutron_flux.resources import ResourceBuilder
from neutron_flux.runtime.live_migration import LiveMigrationRuntimeMixin
from neutron_flux.test_selection import select_plan_tests

from ._evidence import attestation_boundary, data_route
from ._shared import build_plan, completed
from .test_floating_ip_matrix import _matrix_engine


@pytest.fixture(autouse=True)
def guest_icmp_capture_boundary(monkeypatch):
    monkeypatch.setattr(
        "neutron_flux.engine_handlers.floating_ip_peer.attested_icmp",
        attestation_boundary,
    )


def test_translation_inventory_separates_snat_from_preserved_fip_mappings(
    config_factory,
    discovery_fixture,
    tmp_path,
):
    config = config_factory(performance_enabled=False, migration_mode="live-only")
    plan = build_plan(config, discovery_fixture, tmp_path)
    build_check_plan(plan, config)
    batches = defaultdict(list)
    for spec in plan.tests:
        if spec.phase == "cross":
            batches[batch_key(spec)].append(spec)
    for specs in batches.values():
        if any(s.metadata.get("require_no_floating_ip") for s in specs):
            assert {s.protocol for s in migration_baseline_specs(specs)} == {
                "icmp",
                "tcp",
                "udp",
            }
            assert all(s.metadata["check_bindings"]["post-migration"] for s in specs)
        if any(s.operation.startswith("fip-") for s in specs):
            assert not any(s.metadata.get("require_no_floating_ip") for s in specs)
            assert {s.protocol for s in migration_baseline_specs(specs)} == {
                "icmp",
                "tcp",
                "udp",
            }
            for spec in migration_readback_specs(specs):
                assert spec.metadata["check_bindings"]["post-migration"]
                assert spec.metadata["check_bindings"]["placement"]["MIGRATION"]
            assert not any(
                s.operation in {"fip-withdraw", "fip-return"}
                for s in migration_readback_specs(specs)
            )
    assert all(
        s.metadata["check_bindings"].get("post-migration")
        for s in plan.tests
        if s.operation == "fip-peer"
    )


@pytest.mark.parametrize(
    "mode", ["same-router", "self-hairpin", "different-routers", "snat-to-floating-ip"]
)
@pytest.mark.parametrize("failure", [None, "before", "after"])
def test_real_peer_matrix_runs_before_and_after_live_migration(
    config_factory,
    discovery_fixture,
    tmp_path,
    monkeypatch,
    mode,
    failure,
):
    config = config_factory(
        action="run",
        performance_enabled=False,
        migration_mode="live-only",
        live_migration_continuity=False,
    )
    plan = build_plan(config, discovery_fixture, tmp_path)
    fixture, anchor, _, _, _ = _matrix_engine(
        plan,
        "same-router" if mode == "self-hairpin" else mode,
    )
    specs = [s for s in plan.tests if batch_key(s) == batch_key(anchor)]
    plan.tests = list(specs)
    build_check_plan(plan, config)
    reporter = Reporter(config, "fip-migration")
    reporter.plan = plan
    # Keep the real result and check ledgers without rewriting the plan per sample.
    reporter.save_plan = lambda: setattr(reporter, "_check_binding_cache", None)
    builder = fixture.builder
    builder.ssh_endpoint = builder.ssh_controller = mock.Mock()
    builder.inspect_endpoint_route = data_route
    builder.ensure_group_fips = MethodType(ResourceBuilder.ensure_group_fips, builder)
    builder._create_group_fips = mock.Mock(
        side_effect=AssertionError("must preserve allocation")
    )
    builder.cloud_operation_coordinator = SimpleNamespace(
        annotate_current_transaction=lambda **_: None
    )
    builder.select_compute_migration_target = lambda *_args, **_kw: (
        ComputeHostInfo("compute1", "az1", True, True),
        "eligible",
    )
    endpoints = [ep for runtime in builder.runtime_groups for ep in runtime.endpoints]
    for index, ep in enumerate(endpoints):
        ep.host, ep.availability_zone = f"compute{index + 1}", "az1"
    allocations = {
        fip["address"]: (runtime, ep)
        for runtime in builder.runtime_groups
        for ep in runtime.endpoints
        for fip in [runtime.fips.get(ep.label)]
        if fip
    }
    original = copy.deepcopy([runtime.fips for runtime in builder.runtime_groups])
    original_ids = [ep.server_id for ep in endpoints]
    phase = {"initial": True, "migrated": False}
    calls = []

    def probe(protocol, source, source_ip, target_ip, family):
        assert family == 4 and source_ip == source.fixed_ips["fixed"]
        runtime, target = allocations[target_ip]
        current_mode = (
            "snat-to-floating-ip"
            if mode == "snat-to-floating-ip"
            else "self-hairpin"
            if source is target
            else ("same-router" if source in runtime.endpoints else "different-routers")
        )
        broken = (
            protocol == "udp"
            and current_mode == mode
            and (
                (failure == "before" and not phase["initial"])
                or (failure == "after" and phase["migrated"])
            )
        )
        calls.append(
            (phase["migrated"], source.server_id, target.server_id, protocol, target_ip)
        )
        source_fip = next(
            (address for address, (_r, ep) in allocations.items() if ep is source),
            "192.0.2.254",
        )
        return ProbeResult(
            "blocked" if broken else "reachable",
            not broken,
            1,
            1,
            source_ip=source_ip,
            destination_ip=target_ip,
            protocol=protocol,
            diagnostics={
                "observer_probe_id": target.server_id,
                "observer_instance_id": "process",
                "observer_local_ip": target.fixed_ips["fixed"],
                "observed_peer_ip": source_fip,
            },
        )

    def migrate(moving, target, stationary):
        assert moving.server_id in original_ids and stationary.server_id in original_ids
        before = moving.host
        moving.host = target.host
        phase["migrated"] = True
        return MigrationResult(
            moving.server_id,
            before,
            target.host,
            "az1",
            "az1",
            True,
            False,
            True,
            endpoint_ready=True,
            guest_marker_verified=True,
            task_state_cleared=True,
            migration_record_verified=True,
            details={"migration_mode": "live"},
        )

    builder.live_migrate_endpoint = mock.Mock(side_effect=migrate)
    builder.cold_migrate_endpoint = mock.Mock(side_effect=AssertionError("live-only"))
    engine = Engine(config, discovery_fixture, builder, reporter)
    engine.probes = SimpleNamespace(
        endpoint=probe,
        icmp=SimpleNamespace(endpoint=lambda *args, **kw: probe("icmp", *args)),
        tcp=SimpleNamespace(endpoint_peer_identity=lambda *args: probe("tcp", *args)),
        udp=SimpleNamespace(endpoint_peer_identity=lambda *args: probe("udp", *args)),
    )
    engine.diagnostics = SimpleNamespace(collect=lambda *_: (None, {}))
    executor = AdaptiveExecutor.__new__(AdaptiveExecutor)
    executor.config, executor.plan, executor.reporter = config, plan, reporter
    executor.logger, executor.builder = reporter.logger, builder
    executor.active = {r.plan.id: r for r in builder.runtime_groups}
    executor._refresh_checkpoint = lambda: None
    executor._run_performance = lambda *_args, **_kw: None
    monkeypatch.setattr(
        "neutron_flux.execution.placement_migration.time.sleep", lambda _: None
    )
    try:
        engine.run_specs(specs)
        assert all(reporter.get_result(s.id).status == "PASS" for s in specs)
        phase["initial"] = False
        executor._run_compute_placement_validation(
            specs, engine, dependencies=tuple(anchor.dependencies)
        )
        assert builder.live_migrate_endpoint.call_count == (
            0 if failure == "before" else 1
        )
        assert [runtime.fips for runtime in builder.runtime_groups] == original
        assert [ep.server_id for ep in endpoints] == original_ids
        builder._create_group_fips.assert_not_called()
        builder.cold_migrate_endpoint.assert_not_called()
        post = [
            s
            for s in plan.tests
            if s.metadata.get("source_spec_id") in {s.id for s in specs}
        ]
        if failure == "before":
            assert not post and not any(call[0] for call in calls)
        else:
            assert len(post) == len(specs)
            for spec in post:
                expected = (
                    "FAIL"
                    if failure == "after"
                    and spec.protocol == "udp"
                    and spec.metadata["nat_path"] == mode
                    else "PASS"
                )
                assert reporter.get_result(spec.id).status == expected
            assert sum(call[0] for call in calls) == len(specs)
        assert all(row["outcome"] != "PENDING" for row in check_ledger(reporter))
    finally:
        reporter.logger.close()


@pytest.mark.parametrize(
    "change", ["deleted", "address", "id", "server", "port", "fixed", "router"]
)
def test_migration_cannot_heal_a_replaced_mapping(
    config_factory,
    discovery_fixture,
    tmp_path,
    change,
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    engine, _, source, _, _ = _matrix_engine(plan)
    runtime = next(r for r in engine.builder.runtime_groups if source in r.endpoints)
    builder = engine.builder
    builder._create_group_fips = mock.Mock()
    ResourceBuilder.ensure_group_fips(builder, runtime)
    if change == "deleted":
        runtime.fips.clear()
    elif change in {"address", "id"}:
        runtime.fips[source.label][change] = "replacement"
    elif change == "server":
        source.server_id = "replacement"
    elif change == "port":
        source.test_port_id = "replacement"
    elif change == "fixed":
        source.fixed_ips["fixed"] = "10.128.0.99"
    else:
        runtime.router_id = "replacement"
    with pytest.raises(SuiteError, match="refusing to replace or repair"):
        ResourceBuilder.ensure_group_fips(builder, runtime)
    builder._create_group_fips.assert_not_called()


def test_continuity_targets_fip_instead_of_unrouted_private_ip(
    config_factory,
    discovery_fixture,
    tmp_path,
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    engine, _, source, target, _ = _matrix_engine(plan)
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.ssh_endpoint = mock.Mock(
        return_value=completed(stdout="123\t/tmp/continuity\n")
    )
    for runtime in engine.builder.runtime_groups:
        ResourceBuilder.ensure_group_fips(engine.builder, runtime)
    builder.inspect_endpoint_route = data_route
    state = LiveMigrationRuntimeMixin._start_live_continuity(builder, source, target)
    assert state["available"] and state["address_mode"] == "floating-ip"
    assert state["source_ip"] == source.fixed_ips["fixed"]
    assert state["destination_ip"] == target.metadata["floating_ip_identity"]["address"]
    assert state["destination_ip"] not in target.fixed_ips.values()
    assert source.fixed_ips["fixed"] in builder.ssh_endpoint.call_args.args[1]


@pytest.mark.parametrize("mapping", ["existing", "missing", "replaced"])
def test_read_only_post_migration_fip_probe_cannot_allocate_or_repair_mapping(
    config_factory, discovery_fixture, tmp_path, mapping
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    engine, _, source, _, _ = _matrix_engine(plan)
    runtime = next(r for r in engine.builder.runtime_groups if source in r.endpoints)
    builder = engine.builder
    builder._create_group_fips = mock.Mock(
        side_effect=AssertionError("readback allocation")
    )
    builder.ensure_group_fips = MethodType(ResourceBuilder.ensure_group_fips, builder)
    builder.ensure_group_fips(runtime)
    engine.post_migration_read_only = True
    if mapping == "missing":
        runtime.fips.clear()
        source.metadata.pop("floating_ip_identity")
    elif mapping == "replaced":
        runtime.fips[source.label]["address"] = "replacement"
    if mapping == "existing":
        evidence = engine._peer_fip(
            runtime, source, source.side, source.fixed_ips["fixed"]
        )
        assert evidence["server_id"] == source.server_id
    else:
        with pytest.raises(SuiteError):
            engine._peer_fip(runtime, source, source.side, source.fixed_ips["fixed"])
    builder._create_group_fips.assert_not_called()


def test_selected_fip_path_keeps_live_transition_protocol_baselines(
    config_factory,
    discovery_fixture,
    tmp_path,
):
    from neutron_flux.pair_workflow import coordinate_pair_plan

    from .test_full_pair_suite import full_plan

    _, _, plan = full_plan(
        config_factory, discovery_fixture, tmp_path, performance_enabled=False
    )
    plan = coordinate_pair_plan(plan)
    anchor = next(
        s for s in plan.tests if s.operation == "fip-peer" and s.protocol == "tcp"
    )
    selected = select_plan_tests(
        plan, [anchor.metadata["base_test_id"]], include_derived=True
    )
    transitions = [s for s in selected.tests if s.operation == "pair-transition"]
    assert len(transitions) == len({s.metadata["workflow_batch"] for s in transitions})
    for transition in transitions:
        previous = [
            s
            for s in selected.tests
            if s.metadata.get("pair_placement")
            == transition.metadata["transition_from"]
        ]
        assert {s.protocol for s in migration_baseline_specs(previous)} == {
            "icmp",
            "tcp",
            "udp",
        }


def test_snat_continuity_still_originates_from_private_vm_when_it_moves(
    config_factory,
    discovery_fixture,
    tmp_path,
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    fixture, _, private, provider, _ = _matrix_engine(plan)
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.runtime_groups = fixture.builder.runtime_groups
    builder.capture_router_state = fixture.builder.capture_router_state
    builder._gateway_info = fixture.builder._gateway_info
    public_group = next(r for r in builder.runtime_groups if provider in r.endpoints)
    public_group.plan.kind = "provider"
    builder.ssh_endpoint = mock.Mock(
        return_value=completed(stdout="123\t/tmp/continuity\n")
    )
    builder.inspect_endpoint_route = data_route
    state = builder._start_live_continuity(provider, private)
    assert state["available"] and state["source_ip"] == private.fixed_ips["fixed"]
    assert state["destination_ip"] == provider.fixed_ips["fixed"]
    assert state["observer_server_id"] == private.server_id
    assert builder.ssh_endpoint.call_args.args[0] is private
    builder.ssh_endpoint.return_value = completed(stdout="{}")
    builder._stop_live_continuity(provider, state)
    assert builder.ssh_endpoint.call_args.args[0] is private


def test_dnat_readback_rejects_a_changed_api_association(config_factory):
    from ._evidence import configure_translation_target
    from .test_engine_handlers import _engine, _spec

    engine, _, target, groups, _ = _engine(config_factory)
    groups["target"].fips[target.label] = {"id": "original", "address": "192.0.2.99"}
    configure_translation_target(engine, groups["target"], target)
    engine.builder.wait_floating_ip_association.return_value = {"matched": False}
    with pytest.raises(SuiteError, match="Floating-IP mapping could not be verified"):
        engine._run_fip_baseline(_spec("fip-baseline", category="floating-ip"))
    engine.probes.endpoint.assert_not_called()
    engine.probes.runner_fip.run.assert_not_called()
    engine.builder.wait_floating_ip_association.assert_called_once_with(
        "original",
        expected_port_id=target.test_port_id,
        expected_fixed_ip="192.0.2.20",
    )
