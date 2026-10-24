"""Reciprocal assertions share one physical topology and one placement move."""

from __future__ import annotations

import copy
import dataclasses
from collections import Counter
from contextlib import nullcontext
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.check_ledger import check_ledger
from neutron_flux.check_plan import batch_key, build_check_plan, cross_batch_key
from neutron_flux.engine import TestEngine as Engine
from neutron_flux.executor import AdaptiveExecutor
from neutron_flux.host_qualification import HostQualificationPlanner
from neutron_flux.models import (
    ComputeHostInfo,
    MigrationResult,
    Plan,
    ProbeResult,
    RuntimeGroup,
)
from neutron_flux.pair_suite import expand_pair_suite
from neutron_flux.pair_workflow import workflow_plans
from neutron_flux.performance import PerformanceRunner, PerformanceSession
from neutron_flux.reporting import Reporter

from ._evidence import data_route
from ._shared import build_plan, endpoint
from .test_host_qualification import _Inventory, _service


def provider_pair(config, discovery, tmp_path):
    full = build_plan(config, discovery, tmp_path)
    groups = [
        group for group in full.provider_groups if group.network_id in {"n1", "n2"}
    ]
    identities = {group.id for group in groups}
    specs = [
        spec
        for spec in full.tests
        if spec.category == "provider-network-connectivity"
        and set(spec.dependencies) == identities
    ]
    assert len(specs) == 6
    # This is the production planner's order, unlike older hand-built fixtures.
    assert len({tuple(spec.dependencies) for spec in specs}) == 2
    return Plan(groups, [], {}, [], tests=specs)


def test_planner_reserves_one_transition_for_reciprocal_provider_routes(
    config_factory, discovery_fixture, tmp_path
):
    config = config_factory(performance_enabled=False, migration_mode="live-only")
    plan = provider_pair(config, discovery_fixture, tmp_path)
    original = copy.deepcopy(plan.tests)
    assert len({cross_batch_key(spec) for spec in plan.tests}) == 1
    assert len({batch_key(spec) for spec in plan.tests}) == 1
    build_check_plan(plan, config)
    controls = [spec.metadata["check_bindings"]["placement"] for spec in plan.tests]
    assert all(control == controls[0] for control in controls)
    assert sum(check["id"] == controls[0]["MIGRATION"] for check in plan.checks) == 1
    readbacks = [
        spec.metadata["check_bindings"]["post-migration"] for spec in plan.tests
    ]
    assert len(set(readbacks)) == 6
    for before, after in zip(original, plan.tests, strict=True):
        assert dataclasses.replace(after, metadata=before.metadata) == before
    assert {(spec.protocol, spec.family) for spec in plan.tests} == {
        (protocol, 6) for protocol in ("icmp", "tcp", "udp")
    }


def test_reciprocal_provider_performance_has_one_bidirectional_path_per_placement(
    config_factory, discovery_fixture, tmp_path
):
    config = config_factory(
        action="run", performance_enabled=True, migration_mode="live-only"
    )
    plan = provider_pair(config, discovery_fixture, tmp_path)
    build_check_plan(plan, config)
    assert sum(check["kind"] == "performance" for check in plan.checks) == 14
    reporter = Reporter(config, "reciprocal-performance")
    reporter.plan = plan
    reporter.save_plan()
    members = {
        group.id: dataclasses.replace(
            endpoint(group.id), fixed_ips={"runtime": f"2001:db8::{index + 10}"}
        )
        for index, group in enumerate(plan.groups)
    }
    engine = SimpleNamespace(
        lifecycle={},
        _endpoint_address=lambda group, side, subnet: (
            members[group],
            members[group].fixed_ips["runtime"],
        ),
    )
    executor = object.__new__(AdaptiveExecutor)
    executor.plan, executor.reporter = plan, reporter
    executor._refresh_checkpoint = lambda: None
    original = list(plan.tests)
    source, destination = members.values()
    post = executor._placement_probe_specs(
        original, relation="intra-compute", source=source, destination=destination
    )
    executor._append_runtime_specs(post)
    session = PerformanceSession()
    try:
        for specs, stage in (
            (original, "cross-topology"),
            (post, "post-live-migration"),
        ):
            for spec in specs:
                reporter.result(
                    spec.id,
                    spec.category,
                    "PASS",
                    "Packet boundary succeeded",
                    authoritative=True,
                )
            runner = PerformanceRunner(
                config, SimpleNamespace(), reporter, engine, session=session
            )
            measurements = runner.plan_specs(specs, stage=stage)
            assert len(measurements) == 7
            assert (
                len(
                    {
                        measurement.metadata["planned_check_id"]
                        for measurement in measurements
                    }
                )
                == 7
            )
            paths = {
                runner._planned[measurement.id].path_id: runner._planned[measurement.id]
                for measurement in measurements
            }
            assert len(paths) == 1
            assert next(iter(paths.values())).directions == ("forward", "reverse")
        assert session.selected_by_stage == {
            "cross-topology": 1,
            "post-live-migration": 1,
        }
    finally:
        reporter.logger.close()


@pytest.mark.parametrize(
    "initial_hosts", [("compute1", "compute1"), ("compute2", "compute1")]
)
def test_adaptive_provider_pair_probes_both_directions_at_exactly_two_placements(
    config_factory, discovery_fixture, tmp_path, monkeypatch, initial_hosts
):
    config = config_factory(
        action="run",
        performance_enabled=False,
        migration_mode="live-only",
        live_migration_continuity=False,
    )
    plan = provider_pair(config, discovery_fixture, tmp_path)
    build_check_plan(plan, config)
    approved = copy.deepcopy(plan.checks)
    reporter = Reporter(config, "reciprocal-provider")
    reporter.plan = plan
    reporter.save_plan()
    runtimes = []
    for index, group in enumerate(sorted(plan.groups, key=lambda group: group.id)):
        subnet = next(
            subnet.id
            for subnet in discovery_fixture.subnets
            if subnet.id in group.subnet_ids and subnet.ip_version == 6
        )
        member = dataclasses.replace(
            endpoint(group.id),
            fixed_ips={subnet: f"2001:db8:{index + 1}::10"},
            host=initial_hosts[index],
        )
        runtimes.append(
            RuntimeGroup(
                group,
                group.network_id,
                group.label,
                group.subnet_ids,
                None,
                [member],
                None,
                {},
            )
        )
    migrations, packets = [], []

    def send(protocol, source, source_ip, destination_ip, family, **kwargs):
        packets.append(
            (
                protocol,
                source.server_id,
                destination_ip,
                tuple(runtime.endpoints[0].host for runtime in runtimes),
            )
        )
        return ProbeResult(
            "reachable",
            True,
            1,
            1,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
        )

    def migrate(moving, target, peer):
        migrations.append((moving.server_id, moving.host, target.host))
        previous = moving.host
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

    builder = SimpleNamespace(
        discovery=discovery_fixture,
        runtime_groups=runtimes,
        group_failures={},
        ssh_endpoint=mock.Mock(),
        ssh_controller=mock.Mock(),
        inspect_endpoint_route=data_route,
        cloud_operation_coordinator=SimpleNamespace(
            transaction=lambda *args, **kwargs: nullcontext(),
            annotate_current_transaction=lambda **kwargs: None,
        ),
        select_compute_migration_target=lambda moving, peer, *, desired_relation: (
            ComputeHostInfo(
                peer.host if desired_relation == "same" else "compute2",
                "az1",
                True,
                True,
            ),
            "eligible",
        ),
        live_migrate_endpoint=migrate,
    )

    class PacketBoundaryEngine(Engine):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.probes = SimpleNamespace(endpoint=send)
            self.diagnostics = SimpleNamespace(collect=lambda *args: (None, {}))

    monkeypatch.setattr("neutron_flux.executor.TestEngine", PacketBoundaryEngine)
    executor = AdaptiveExecutor(
        config, plan, builder, reporter, mock.Mock(), mock.Mock(), SimpleNamespace()
    )
    executor.active = {runtime.plan.id: runtime for runtime in runtimes}
    executor._refresh_checkpoint = lambda: None
    executor._checkpoint = lambda **kwargs: None
    try:
        executor._run_cross_phase()
        assert len(migrations) == 1
        assert executor.group_loads == 0
        opposite = (
            initial_hosts[0],
            initial_hosts[0] if initial_hosts[0] != initial_hosts[1] else "compute2",
        )
        assert Counter(packet[3] for packet in packets) == {
            initial_hosts: 12,  # Ordinary matrix plus its fresh submission barrier.
            opposite: 6,
        }
        for hosts in (initial_hosts, opposite):
            assert {
                (protocol, source)
                for protocol, source, _, placement in packets
                if placement == hosts
            } == {
                (protocol, runtime.endpoints[0].server_id)
                for protocol in ("icmp", "tcp", "udp")
                for runtime in runtimes
            }
        assert plan.checks == approved
        assert {row["outcome"] for row in check_ledger(reporter)} == {"PASSED"}
        assert all(row.status == "PASS" for row in reporter.results)
        readbacks = [
            spec
            for spec in plan.tests
            if spec.metadata.get("source_spec_id")
            and not spec.metadata.get("pre_migration_functional_barrier")
        ]
        assert len(readbacks) == 6
        assert len({spec.metadata["planned_check_id"] for spec in readbacks}) == 6
        for spec in readbacks:
            source_host = (
                executor.active[spec.source_group_id].endpoint(spec.source_side).host
            )
            destination_host = (
                executor.active[spec.destination_group_id]
                .endpoint(spec.destination_side)
                .host
            )
            assert f"[{source_host} -> {destination_host}]" in spec.display_name
            assert spec.metadata["source_compute_host"] == source_host
            assert spec.metadata["destination_compute_host"] == destination_host
    finally:
        reporter.logger.close()


@pytest.mark.parametrize(
    "metadata",
    [{}, {"require_floating_ip": True}, {"source_without_floating_ip": True}],
)
def test_scope_and_topology_state_survive_canonical_grouping(
    config_factory, discovery_fixture, tmp_path, metadata
):
    config = config_factory(
        target_host_pairs=[("hyper001", "hyper002")], performance_enabled=False
    )
    plan = provider_pair(config, discovery_fixture, tmp_path)
    anchor = plan.tests[0]
    equivalent = dataclasses.replace(
        anchor,
        dependencies=list(reversed(anchor.dependencies)),
        source_group_id=anchor.destination_group_id,
        destination_group_id=anchor.source_group_id,
        metadata=metadata,
    )
    forward = dataclasses.replace(anchor, metadata=metadata)
    if metadata.get("source_without_floating_ip"):
        assert cross_batch_key(forward) != cross_batch_key(equivalent)
    else:
        assert cross_batch_key(forward) == cross_batch_key(equivalent)
    for changed in (
        dataclasses.replace(forward, source_side="B"),
        dataclasses.replace(
            forward, dependencies=[item + "@other-az" for item in forward.dependencies]
        ),
        dataclasses.replace(
            forward,
            metadata={
                **metadata,
                "coordinated_pair": True,
                "pair_scope_id": "other-pair",
            },
        ),
    ):
        assert batch_key(forward) != batch_key(changed)
    plan.host_qualification = HostQualificationPlanner(
        config,
        discovery_fixture,
        plan,
        _Inventory([_service("hyper001", "az1"), _service("hyper002", "az1")]),
        mock.Mock(),
    ).build()
    coordinated = expand_pair_suite(plan)
    assert len(workflow_plans(coordinated)) == 1
    lane = workflow_plans(coordinated)[0]
    assert sum(spec.operation == "pair-transition" for spec in lane.tests) == 1
    for placement in ("initial", "opposite"):
        assert (
            len(
                [
                    spec
                    for spec in lane.tests
                    if spec.operation == "probe"
                    and spec.metadata["pair_placement"] == placement
                ]
            )
            == 6
        )


def test_coordinated_source_without_fip_is_not_joined_to_mapping_required_state(
    config_factory, discovery_fixture, tmp_path
):
    config = config_factory(
        target_host_pairs=[("hyper001", "hyper002")], performance_enabled=False
    )
    plan = provider_pair(config, discovery_fixture, tmp_path)
    plan.tests = [
        dataclasses.replace(spec, id=spec.id + "-" + state, metadata={key: True})
        for state, key in (
            ("snat", "source_without_floating_ip"),
            ("fip", "require_floating_ip"),
        )
        for spec in plan.tests
    ]
    plan.host_qualification = HostQualificationPlanner(
        config,
        discovery_fixture,
        plan,
        _Inventory([_service("hyper001", "az1"), _service("hyper002", "az1")]),
        mock.Mock(),
    ).build()
    coordinated = expand_pair_suite(plan)
    lanes = workflow_plans(coordinated)
    assert (
        len(lanes) == 3
    )  # FIP mappings share both directions; each SNAT source is distinct.
    for lane in lanes:
        checks = [spec for spec in lane.tests if spec.operation == "probe"]
        assert all(spec.metadata.get("require_floating_ip") for spec in checks) or all(
            spec.metadata.get("source_without_floating_ip") for spec in checks
        )
        assert sum(spec.operation == "pair-transition" for spec in lane.tests) == 1
