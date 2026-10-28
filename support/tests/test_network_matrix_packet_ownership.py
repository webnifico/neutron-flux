"""Audit declared paths against packet endpoints and bounded execution lanes."""

from __future__ import annotations

import copy
import ipaddress
from collections import Counter
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.check_plan import build_check_plan, endpoint_sides
from neutron_flux.engine import TestEngine as FluxTestEngine
from neutron_flux.errors import UnsupportedTopologyError
from neutron_flux.host_qualification import HostQualificationPlanner
from neutron_flux.models import (
    ProbeResult,
    RuntimeGroup,
    ZoneCapability,
    ZoneExecutionPlan,
)
from neutron_flux.multi_zone import aggregate_plan
from neutron_flux.network_contract import ONE_ROUTER_KINDS, STATIC_ROUTING_KINDS
from neutron_flux.pair_suite import expand_pair_suite
from neutron_flux.pair_workflow import workflow_plans
from neutron_flux.planning import Planner

from .test_host_qualification import _Inventory, _service
from .test_performance_and_html import _endpoint


def _selected_discovery(discovery, networks):
    selected = copy.deepcopy(discovery)
    selected.networks = [item for item in selected.networks if item.id in networks]
    selected.subnets = [
        item for item in selected.subnets if item.network_id in networks
    ]
    selected.occupied_cidrs = [item.cidr for item in selected.subnets]
    return selected


def _assert_reference_integrity(plan, discovery):
    ids = {spec.id for spec in plan.tests}
    groups = {group.id: group for group in plan.groups}
    assert len(ids) == len(plan.tests)
    for spec in plan.tests:
        assert set(spec.requires + spec.requires_pass) <= ids
        assert set(spec.dependencies) <= groups.keys()
        for group_id, subnet_id in (
            (spec.source_group_id, spec.source_subnet_id),
            (spec.destination_group_id, spec.destination_subnet_id),
        ):
            if group_id is None:
                continue
            group = groups[group_id]
            assert group_id in spec.dependencies
            assert spec.family in group.families
            if group.kind == "provider" and subnet_id:
                assert subnet_id in group.subnet_ids
                assert discovery.subnet(subnet_id).ip_version == spec.family
        if spec.operation.startswith("fip-"):
            assert spec.family == 4
    # A prerequisite graph must terminate without depending on a later cycle.
    pending = {spec.id: set(spec.requires + spec.requires_pass) for spec in plan.tests}
    completed = set()
    while pending:
        ready = {
            identity
            for identity, requirements in pending.items()
            if requirements <= completed
        }
        assert ready, pending
        completed.update(ready)
        pending = {
            identity: requirements
            for identity, requirements in pending.items()
            if identity not in ready
        }


def _runtime_groups(plan, discovery):
    runtimes = []
    for index, group in enumerate(plan.groups):
        subnet_ids = group.subnet_ids or [f"data-{index}"]
        internal = group.kind in ONE_ROUTER_KINDS | STATIC_ROUTING_KINDS
        if internal:
            subnet_ids = [f"data-{index}-A", f"data-{index}-B"]
        endpoints = []
        for side_index, side in enumerate(("A", "B")):
            endpoint = _endpoint(
                f"{group.id}:{side}", side, "192.0.2.10", f"compute-{side_index}"
            )
            endpoint.fixed_ips = {}
            for subnet_index, subnet in enumerate(subnet_ids):
                if internal and not subnet.endswith(side):
                    continue
                family = (
                    discovery.subnet(subnet).ip_version
                    if group.kind == "provider"
                    else group.families[0]
                )
                address = (
                    str(
                        ipaddress.ip_network(discovery.subnet(subnet).cidr)[
                            10 + side_index
                        ]
                    )
                    if group.kind == "provider"
                    else f"10.{index}.0.{10 + side_index}"
                    if family == 4
                    else f"fd00:{index:x}:{subnet_index:x}::{10 + side_index:x}"
                )
                endpoint.fixed_ips[subnet] = address
            endpoints.append(endpoint)
        runtimes.append(
            RuntimeGroup(
                group,
                f"network-{index}",
                group.label,
                subnet_ids,
                f"router-{index}",
                endpoints,
                True,
                {},
                metadata={
                    "side_subnet_ids": dict(zip(("A", "B"), subnet_ids, strict=True))
                }
                if internal
                else {},
            )
        )
    return runtimes


@pytest.mark.parametrize(
    "discovery_name,networks",
    [
        ("discovery_fixture", ["n1"]),
        ("discovery_fixture", ["n3"]),
        ("discovery_fixture", ["n1", "n2", "n3"]),
        ("routed_discovery", ["routed"]),
    ],
)
def test_fixed_packet_paths_use_declared_guest_data_addresses_and_families(
    config_factory, request, discovery_name, networks
):
    discovery = _selected_discovery(request.getfixturevalue(discovery_name), networks)
    config = config_factory(
        ipv4_targets=["203.0.113.10"],
        ipv6_targets=["2001:db8::10"],
        ipv4_targets_configured=True,
        ipv6_targets_configured=True,
    )
    plan = Planner(config, discovery, mock.Mock()).build()
    _assert_reference_integrity(plan, discovery)
    runtimes = _runtime_groups(plan, discovery)
    by_id = {runtime.plan.id: runtime for runtime in runtimes}
    engine = object.__new__(FluxTestEngine)
    engine._runtime_groups = tuple(runtimes)
    engine.builder = SimpleNamespace(runtime_groups=runtimes)
    engine.lifecycle = {
        f"static-route:{group.id}": {"routes_installed": True}
        for group in plan.groups
        if group.kind in STATIC_ROUTING_KINDS
    }
    engine._record = mock.Mock()
    engine.probes = mock.Mock()
    engine.probes.endpoint.return_value = ProbeResult("reachable", True, 1, 1)
    engine._destination_tcp_attestation = mock.Mock(return_value=None)
    tested = Counter()
    for spec in plan.tests:
        if spec.operation != "probe":
            continue
        engine._run_endpoint_probe(spec)
        protocol, source, source_ip, destination_ip, family = (
            engine.probes.endpoint.call_args.args
        )
        source_endpoint = by_id[spec.source_group_id].endpoint(spec.source_side)
        destination_endpoint = by_id[spec.destination_group_id].endpoint(
            spec.destination_side
        )
        assert source is source_endpoint
        assert source_ip in source_endpoint.fixed_ips.values()
        assert destination_ip in destination_endpoint.fixed_ips.values()
        assert source_ip != source_endpoint.management_ip
        assert destination_ip != destination_endpoint.management_ip
        assert ipaddress.ip_address(source_ip).version == spec.family == family
        assert ipaddress.ip_address(destination_ip).version == family
        assert protocol == spec.protocol
        recorded = engine._record.call_args.args
        assert recorded[2] is source_endpoint
        assert recorded[3] is destination_endpoint
        tested[spec.category] += 1
    assert {
        "same-subnet",
        "project-network-routing",
        "router-static-routing",
        "source-nat-connectivity",
    } <= tested.keys()
    if len(networks) > 1:
        assert tested["provider-network-connectivity"]
    if discovery_name == "routed_discovery":
        routed = [spec for spec in plan.tests if spec.category == "routed-provider"]
        assert len(routed) == 6
        assert {
            (spec.source_subnet_id, spec.destination_subnet_id, spec.protocol)
            for spec in routed
        } == {
            (source, destination, protocol)
            for source, destination in (("ra", "rb"), ("rb", "ra"))
            for protocol in ("icmp", "tcp", "udp")
        }
        assert all(
            spec.expectation == "reachable" and spec.authoritative for spec in routed
        )
    for spec in plan.tests:
        if spec.operation == "egress":
            group = plan.group(spec.source_group_id)
            if group.kind == "provider":
                assert spec.family in group.families
            assert ipaddress.ip_address(spec.metadata["target"]).version == spec.family
    if networks == ["n3"]:
        assert not any(
            spec.operation == "egress" and spec.family == 6 for spec in plan.tests
        )
        assert any(
            item["resource"] == "External IPv6 reachability"
            and "No eligible selected provider or project-network path"
            in item["reason"]
            for item in plan.skipped
        )


@pytest.mark.parametrize("pair_count,cycles", [(1, 1), (2, 1), (3, 3)])
def test_network_paths_scale_without_extra_placement_or_endpoint_combinations(
    config_factory, discovery_fixture, pair_count, cycles
):
    pairs = [(f"host-{index}-A", f"host-{index}-B") for index in range(pair_count)]
    config = config_factory(
        target_host_pairs=pairs + [(b, a) for a, b in pairs],
        qualification_cycles=cycles,
        fabric_scale_enabled=True,
        fabric_scale_pairs=[1, 2, 4],
        performance_max_paths=0,
    )
    base = Planner(config, discovery_fixture, mock.Mock()).build()
    base.host_qualification = HostQualificationPlanner(
        config,
        discovery_fixture,
        base,
        _Inventory(
            [
                _service(host, f"az-{index % 2}")
                for index, pair in enumerate(pairs)
                for host in pair
            ]
        ),
        mock.Mock(),
    ).build()
    plan = expand_pair_suite(base)
    build_check_plan(plan, config)
    _assert_reference_integrity(plan, discovery_fixture)
    assert len(base.host_qualification.pairs) == pair_count
    inventory_before = [check["id"] for check in plan.checks]
    covered = Counter()
    for lane in workflow_plans(plan):
        initial = [
            spec for spec in lane.tests if spec.metadata["pair_placement"] == "initial"
        ]
        opposite = [
            spec
            for spec in lane.tests
            if spec.metadata["pair_placement"] == "opposite"
            and spec.operation != "pair-transition"
        ]
        assert {spec.metadata["base_test_id"] for spec in initial} == {
            spec.metadata["base_test_id"] for spec in opposite
        }
        assert sum(spec.operation == "pair-transition" for spec in lane.tests) == 1
        assert {spec.metadata["pair_placement"] for spec in lane.tests} == {
            "initial",
            "opposite",
        }
        if initial[0].phase == "intra":
            assert len(initial[0].dependencies) == 1
        else:
            assert sum(len(sides) for _, sides in endpoint_sides(initial[0])) == 2
        for spec in initial:
            covered[spec.metadata["base_test_id"]] += 1
    expected = {
        spec.id for spec in base.tests if spec.scenario != "Controller readiness"
    }
    assert set(covered) == expected
    assert set(covered.values()) == {pair_count * cycles}
    assert [check["id"] for check in plan.checks] == inventory_before


@pytest.mark.parametrize("zone_count", [1, 2, 3])
def test_per_zone_and_cross_zone_paths_preserve_family_and_prerequisite_contracts(
    config_factory, discovery_fixture, zone_count
):
    config = config_factory(ipv6_targets=["2001:db8::10"], ipv6_targets_configured=True)
    base = Planner(config, discovery_fixture, mock.Mock()).build()
    zones = [f"az-{index}" for index in range(zone_count)]
    scope = ZoneExecutionPlan(
        zones,
        "per-zone" if zone_count == 1 else "both",
        {
            zone: ZoneCapability(zone, [f"{zone}-A", f"{zone}-B"], 2, None, {})
            for zone in zones
        },
        True,
        zone_count,
    )
    plan = aggregate_plan(base, scope, config)
    build_check_plan(plan, config)
    _assert_reference_integrity(plan, discovery_fixture)
    for zone in zones:
        local = [
            spec
            for spec in plan.tests
            if spec.metadata.get("availability_zone") == zone
        ]
        assert {spec.metadata["base_test_id"] for spec in local} == {
            spec.id for spec in base.tests
        }
    for spec in plan.tests:
        if spec.phase == "cross-zone":
            assert (
                spec.metadata["source_availability_zone"]
                != spec.metadata["destination_availability_zone"]
            )
            assert len(spec.dependencies) == 2
            assert spec.source_side == spec.destination_side == "A"
            assert len({group for group, _ in endpoint_sides(spec)}) == 2


def test_ipv6_only_provider_selection_has_an_explicit_control_path_failure(
    config_factory, discovery_fixture
):
    discovery = _selected_discovery(discovery_fixture, ["n2"])
    with pytest.raises(UnsupportedTopologyError, match="IPv4 runner control path"):
        Planner(
            config_factory(ipv6_targets=["2001:db8::10"]), discovery, mock.Mock()
        ).build()


def test_floating_ip_packets_bind_owned_private_sources_and_target_mappings(
    config_factory, discovery_fixture
):
    config = config_factory()
    plan = Planner(config, discovery_fixture, mock.Mock()).build()
    runtimes = _runtime_groups(plan, discovery_fixture)
    by_id = {runtime.plan.id: runtime for runtime in runtimes}
    for runtime in runtimes:
        if runtime.plan.floating_subnet_id:
            runtime.metadata["floating_ip_fixed_subnet_id"] = runtime.subnet_ids[0]
    builder = SimpleNamespace(
        runtime_groups=runtimes,
        osc=mock.Mock(),
        capture_router_state=mock.Mock(
            return_value={
                "external_gateway_info": {
                    "enable_snat": True,
                    "external_fixed_ips": [{"ip_address": "198.51.100.1"}],
                }
            }
        ),
        _gateway_info=lambda gateway: gateway,
        inspect_endpoint_route=mock.Mock(return_value={"dev": "data-interface"}),
    )
    builder.osc.json.return_value = []
    mappings = {}

    def ensure_fip(runtime, side="A"):
        endpoint = runtime.endpoint(side)
        if endpoint.server_id not in mappings:
            external = ipaddress.ip_network(
                discovery_fixture.subnet(runtime.plan.floating_subnet_id).cidr
            )
            address = str(external[100 + len(mappings)])
            mappings[endpoint.server_id] = {
                "id": f"fip-{endpoint.server_id}",
                "address": address,
                "port_id": endpoint.test_port_id,
                "private_ip": next(iter(endpoint.fixed_ips.values())),
            }
        runtime.fips[endpoint.label] = dict(mappings[endpoint.server_id])

    def association(fip_id, expected_port_id, expected_fixed_ip):
        mapping = next(item for item in mappings.values() if item["id"] == fip_id)
        return {
            "matched": True,
            "port_id": mapping["port_id"],
            "fixed_ip_address": mapping["private_ip"],
            "floating_ip_address": mapping["address"],
        }

    builder.ensure_group_fips = mock.Mock(side_effect=ensure_fip)
    builder.wait_floating_ip_association = mock.Mock(side_effect=association)
    engine = object.__new__(FluxTestEngine)
    engine.config = config
    engine._runtime_groups = tuple(runtimes)
    engine.builder = builder
    engine.lifecycle = {}
    engine._record = mock.Mock()
    engine._verified_fip_probe = mock.Mock(
        return_value=ProbeResult("reachable", True, 1, 1)
    )
    engine.probes = mock.Mock()
    engine.probes.runner_fip.run.return_value = (
        ProbeResult("reachable", True, 1, 1, source_ip="203.0.113.10"),
        False,
    )
    modes = set()
    for spec in plan.tests:
        if spec.operation not in {"fip-peer", "fip-baseline"}:
            continue
        if spec.operation == "fip-peer":
            engine._run_fip_peer(spec)
            modes.add(spec.metadata["nat_path"])
        else:
            engine._run_fip_baseline(spec)
            assert spec.authoritative is True
        protocol, source, source_ip, destination_fip, destination, destination_ip = (
            engine._verified_fip_probe.call_args.args
        )
        source_endpoint = by_id[spec.source_group_id].endpoint(spec.source_side)
        destination_endpoint = by_id[spec.destination_group_id].endpoint(
            spec.destination_side
        )
        assert protocol == spec.protocol
        assert source is source_endpoint
        assert source_ip in source_endpoint.fixed_ips.values()
        assert source_ip != source_endpoint.management_ip
        assert destination is destination_endpoint
        assert destination_ip in destination_endpoint.fixed_ips.values()
        assert destination_fip == mappings[destination_endpoint.server_id]["address"]
        assert destination_fip != destination_ip
        expected_sources = engine._verified_fip_probe.call_args.kwargs.get(
            "expected_source_ips"
        )
        if spec.operation == "fip-baseline":
            assert expected_sources == {source_ip}
        elif spec.metadata["nat_path"] == "different-routers":
            assert expected_sources == {mappings[source_endpoint.server_id]["address"]}
        elif spec.metadata["nat_path"] == "snat-to-floating-ip":
            assert expected_sources == {"198.51.100.1"}
            assert source_endpoint.server_id not in mappings
    assert modes == {
        "same-router",
        "different-routers",
        "self-hairpin",
        "snat-to-floating-ip",
    }
