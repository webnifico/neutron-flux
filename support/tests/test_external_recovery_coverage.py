"""Plan and execute external recovery assertions at an offline cloud boundary."""

from __future__ import annotations

import dataclasses
import subprocess
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.check_plan import build_check_plan
from neutron_flux.engine import TestEngine as FluxTestEngine
from neutron_flux.executor import AdaptiveExecutor
from neutron_flux.models import Plan, ProbeResult, RuntimeGroup
from neutron_flux.pair_workflow import workflow_plans
from neutron_flux.reporting import Reporter

from ._shared import build_plan, endpoint
from .test_full_pair_suite import full_plan


@pytest.fixture
def external_cloud(config_factory, discovery_fixture, tmp_path):
    config = config_factory(
        action="run",
        external_networks=["Public1"],
        ipv4_targets=["1.1.1.1"],
        ipv6_targets=["2606:4700:4700::1111"],
        performance_enabled=False,
        migration_mode="live-only",
        live_migration_continuity=False,
        convergence_interval=0,
    )
    base = build_plan(config, discovery_fixture, tmp_path)
    group = next(g for g in base.provider_groups if g.network_id == "n1")
    specs = [
        s
        for s in base.tests
        if s.dependencies == [group.id]
        and s.operation in {"probe", "egress", "server-stop", "server-start"}
    ]
    plan = Plan([group], [], {}, [], tests=specs)
    build_check_plan(plan, config)
    reporter = Reporter(config, "external-recovery")
    reporter.plan = plan
    reporter.save_plan()
    endpoints = {
        side: dataclasses.replace(
            endpoint(side, side),
            fixed_ips={
                "s1v4": f"172.20.0.{10 + index}",
                "s1v6": f"fdbf:9ed6:2194:b040::{10 + index}",
            },
            host=f"compute{index + 1}",
        )
        for index, side in enumerate(("A", "B"))
    }
    runtime = RuntimeGroup(
        group,
        "n1",
        "Public1",
        group.subnet_ids,
        None,
        list(endpoints.values()),
        None,
        {},
    )
    state = SimpleNamespace(
        active=True, restarted=False, fail_external=False, calls=[], operations=[]
    )

    def route(source, source_ip, destination_ip, family):
        return {
            "returncode": 0,
            "device": "ens4",
            "source": source_ip,
            "interfaces": [
                {
                    "ifname": "ens4",
                    "address": source.test_mac,
                    "addr_info": [{"local": ip} for ip in source.fixed_ips.values()],
                }
            ],
        }

    def probe(protocol, source, source_ip, destination_ip, family, **kwargs):
        state.calls.append((source.side, source.host, destination_ip, state.restarted))
        external = destination_ip in {*config.ipv4_targets, *config.ipv6_targets}
        success = state.active and not (external and state.fail_external)
        return ProbeResult(
            outcome="reachable" if success else "blocked",
            success=success,
            elapsed_ms=1,
            attempts=1,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
        )

    def operation(*args, **kwargs):
        state.operations.append(args[:3])
        assert args[0] == "server" and args[2] == endpoints["B"].server_id
        state.active = args[1] == "start"
        state.restarted = state.restarted or state.active
        return subprocess.CompletedProcess(args, 0, "", "")

    builder = SimpleNamespace(
        runtime_groups=[runtime],
        ssh_endpoint=mock.Mock(),
        ssh_controller=mock.Mock(),
        inspect_endpoint_route=route,
        osc=SimpleNamespace(run=operation),
        _wait_for_status=mock.Mock(),
        _wait_for_ssh=mock.Mock(return_value=True),
        reconfigure_endpoint=mock.Mock(),
    )
    engine = FluxTestEngine(config, discovery_fixture, builder, reporter)
    engine.probes = SimpleNamespace(endpoint=probe)
    engine.diagnostics = SimpleNamespace(collect=lambda *args: (None, {}))
    executor = AdaptiveExecutor.__new__(AdaptiveExecutor)
    executor.config, executor.plan, executor.reporter = config, plan, reporter
    executor.logger = reporter.logger
    executor.builder = builder
    executor.active = {group.id: runtime}
    executor._refresh_checkpoint = lambda: None
    executor._placement_check_bindings = specs[0].metadata["check_bindings"][
        "placement"
    ]
    yield SimpleNamespace(
        config=config,
        group=group,
        specs=specs,
        plan=plan,
        reporter=reporter,
        engine=engine,
        executor=executor,
        endpoints=endpoints,
        state=state,
    )
    reporter.logger.close()


def test_external_recovery_runs_from_restarted_vm_and_catches_egress_only_failure(
    external_cloud,
):
    cloud = external_cloud
    selected = [
        s
        for s in cloud.specs
        if s.operation in {"egress", "server-stop", "server-start"}
    ]
    original = [s for s in selected if s.operation == "egress" and not s.requires_pass]
    cloud.engine.run_specs(original)
    assert all(cloud.reporter.get_result(s.id).status == "PASS" for s in original)
    cloud.state.fail_external = True
    cloud.engine.run_specs(selected)
    recoveries = [s for s in selected if s.metadata.get("server_start_recovery")]
    assert {s.family for s in recoveries} == {4, 6}
    assert all(cloud.reporter.get_result(s.id).status == "FAIL" for s in recoveries)
    assert all(
        cloud.reporter.get_result(s.id).status == "PASS"
        for s in selected
        if s.operation == "server-start"
    )
    assert [args[1] for args in cloud.state.operations] == ["stop", "start"]
    external_calls = [
        c for c in cloud.state.calls if c[2] in {"1.1.1.1", "2606:4700:4700::1111"}
    ]
    assert len(external_calls) == 4
    assert all(side == "B" for side, _, _, _ in external_calls)
    assert [restarted for _, _, _, restarted in external_calls] == [
        False,
        False,
        True,
        True,
    ]


def test_generic_executor_keeps_external_recovery_on_started_vm_generation(
    external_cloud, monkeypatch
):
    cloud = external_cloud
    cloud.config.compute_host_connectivity_enabled = False
    builder = cloud.engine.builder
    builder.discovery = cloud.engine.discovery
    builder.group_failures = {}
    builder.stop_group_probes = mock.Mock()
    generations = []

    def boot(group, *, sides):
        generation = len(generations) + 1
        members = [
            dataclasses.replace(
                cloud.endpoints[side],
                server_id=cloud.endpoints[side].server_id
                if generation == 1
                else f"server-{side}-generation-{generation}",
            )
            for side in sides
        ]
        runtime = RuntimeGroup(
            group, "n1", "Public1", group.subnet_ids, None, members, None, {}
        )
        generations.append(runtime)
        return runtime

    builder.build_group = boot

    class BoundaryEngine(FluxTestEngine):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            # Replace packet I/O only; runtime selection, dispatch, lifecycle
            # control, policy and result recording remain production code.
            self.probes = cloud.engine.probes
            self.diagnostics = cloud.engine.diagnostics

    monkeypatch.setattr("neutron_flux.executor.TestEngine", BoundaryEngine)
    cleanup = SimpleNamespace(cleanup_group=mock.Mock(return_value=True))
    executor = AdaptiveExecutor(
        cloud.config,
        cloud.plan,
        builder,
        cloud.reporter,
        cleanup,
        mock.Mock(),
        SimpleNamespace(),
    )
    executor._refresh_checkpoint = lambda: None
    executor.run()
    assert executor.group_loads == len(generations) == 1
    assert [args[1] for args in cloud.state.operations] == ["stop", "start"]
    for family in (4, 6):
        records = [
            cloud.reporter.get_result(s.id)
            for s in cloud.specs
            if s.family == family and s.operation in {"egress", "server-start"}
        ]
        assert len(records) == 3
        assert {r.status for r in records} == {"PASS"}
        subjects = {
            r.details["destination_server_id"]
            if r.details["operation"] == "server-start"
            else r.details["source_server_id"]
            for r in records
        }
        assert subjects == {cloud.endpoints["B"].server_id}


def test_fresh_barrier_rechecks_external_targets_and_blocks_external_only_failure(
    external_cloud,
):
    cloud = external_cloud
    selected = [s for s in cloud.specs if s.operation in {"probe", "egress"}]
    cloud.engine.run_specs([s for s in selected if not s.requires_pass])
    cloud.state.fail_external = True
    accepted = cloud.executor._pre_migration_functional_barrier(
        selected,
        cloud.engine,
        dependencies=(cloud.group.id,),
        source=cloud.endpoints["A"],
        destination=cloud.endpoints["B"],
        current_relation="inter-compute",
        submission_number=1,
        migration_kind="live",
    )
    assert accepted is False
    fresh = [
        s
        for s in cloud.plan.tests
        if s.metadata.get("pre_migration_functional_barrier")
    ]
    external = [s for s in fresh if s.operation == "egress"]
    assert len(external) == 2  # Each family refreshed once, not its recovery duplicate.
    assert all(cloud.reporter.get_result(s.id).status == "FAIL" for s in external)
    assert all(
        cloud.reporter.get_result(s.id).status == "PASS"
        for s in fresh
        if s.operation == "probe"
    )
    assessment = cloud.reporter.results[-1]
    assert assessment.observed == "fresh-functional-baseline-failed"
    assert assessment.details["lifecycle_cloud_operation_performed"] is False
    assert not cloud.state.operations


def test_external_icmp_cannot_replace_missing_peer_icmp_migration_baseline(
    external_cloud,
):
    cloud = external_cloud
    selected = [
        s
        for s in cloud.specs
        if s.operation == "egress" or (s.operation == "probe" and s.protocol != "icmp")
    ]
    accepted = cloud.executor._pre_migration_functional_barrier(
        selected,
        cloud.engine,
        dependencies=(cloud.group.id,),
        source=cloud.endpoints["A"],
        destination=cloud.endpoints["B"],
        current_relation="inter-compute",
        submission_number=1,
        migration_kind="live",
    )
    assert accepted is False
    assert cloud.reporter.results[-1].details["missing_protocols"] == ["icmp"]
    assert not cloud.state.calls


def test_external_target_is_probed_from_vm_at_its_new_host(external_cloud):
    cloud = external_cloud
    initial = next(
        s for s in cloud.specs if s.operation == "egress" and not s.requires_pass
    )
    cloud.engine.run_specs([initial])
    cloud.endpoints["B"].host = "compute1"
    cloud.state.fail_external = True
    post = cloud.executor._placement_probe_specs(
        [initial],
        relation="intra-compute",
        source=cloud.endpoints["A"],
        destination=cloud.endpoints["B"],
    )
    cloud.executor._append_runtime_specs(post)
    cloud.engine.run_specs(post)
    assert cloud.reporter.get_result(initial.id).status == "PASS"
    result = cloud.reporter.get_result(post[0].id)
    assert result.status == "FAIL"
    assert result.details["source_server_id"] == cloud.endpoints["B"].server_id
    assert result.details["source_compute_host"] == "compute1"
    assert [(side, host) for side, host, _, _ in cloud.state.calls] == [
        ("B", "compute2"),
        ("B", "compute1"),
    ]


def test_both_separate_router_hairpin_owners_share_one_transition_and_lifetime(
    config_factory, discovery_fixture, tmp_path
):
    _, _, plan = full_plan(
        config_factory,
        discovery_fixture,
        tmp_path,
        target_host_pairs=[("hyper001", "hyper002")],
        performance_enabled=False,
    )
    lanes = [
        lane
        for lane in workflow_plans(plan)
        if any(s.metadata.get("nat_path") == "different-routers" for s in lane.tests)
    ]
    assert lanes
    for lane in lanes:
        assert len(lane.groups) == 2
        assert sum(s.operation == "pair-transition" for s in lane.tests) == 1
        for placement in ("initial", "opposite"):
            own = [
                s
                for s in lane.tests
                if s.metadata.get("pair_placement") == placement
                and s.metadata.get("nat_path") == "self-hairpin"
            ]
            assert {(s.source_group_id, s.protocol) for s in own} == {
                (g.id, protocol)
                for g in lane.groups
                for protocol in ("icmp", "tcp", "udp")
            }
            assert all(s.source_group_id == s.destination_group_id for s in own)
