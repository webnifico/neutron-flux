from __future__ import annotations

import ast
import ipaddress
import json
import socket
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.check_plan import (
    batch_key,
    build_check_plan,
    endpoint_sides,
    migration_baseline_specs,
    migration_probe_spec,
)
from neutron_flux.errors import SuiteError
from neutron_flux.executor import AdaptiveExecutor
from neutron_flux.network_contract import (
    ONE_ROUTER_PROJECT_NETWORKS,
    TWO_ROUTER_STATIC_ROUTING,
)
from neutron_flux.policy import PolicyEvaluator
from neutron_flux.reporting_components.summary import SummaryRendererMixin
from neutron_flux.resource_naming import resource_name_registry
from neutron_flux.resources import ResourceBuilder
from neutron_flux.test_names import address_path_lines, execution_name
from neutron_flux.translation_safety import (
    floating_ip_target_sides,
    validate_plan_translation_safety,
)

from ._shared import build_plan, endpoint
from .test_floating_ip_matrix import _matrix_engine


def test_text_summary_counts_a_failed_migration_once_with_supporting_samples():
    renderer = object.__new__(SummaryRendererMixin)
    renderer.plan = SimpleNamespace(checks=[{"id": "transition"}])
    main = SimpleNamespace(
        category="compute-placement",
        status="FAIL",
        details={"availability_zone": "az1"},
    )
    sample = SimpleNamespace(
        category="compute-placement",
        status="FAIL",
        details={"availability_zone": "az1", "check_sample": True},
    )
    renderer.results = [sample, main]
    assert renderer._primary_summary_results() == [main]
    assert renderer._category_summary()["compute-placement"]["FAIL"] == 1
    renderer.plan = None
    assert renderer._category_summary()["compute-placement"]["FAIL"] == 2


def test_static_route_migration_rechecks_every_direction_without_reinstalling(
    config_factory, discovery_fixture, tmp_path
):
    config = config_factory(performance_enabled=False, migration_mode="live-only")
    plan = build_plan(config, discovery_fixture, tmp_path)
    build_check_plan(plan, config)
    executor = object.__new__(AdaptiveExecutor)
    for group in plan.groups:
        if group.kind != TWO_ROUTER_STATIC_ROUTING:
            continue
        specs = [s for s in plan.tests if s.dependencies == [group.id]]
        before = [migration_probe_spec(s) for s in migration_baseline_specs(specs)]
        after = executor._placement_probe_specs(
            specs,
            relation="intra-compute",
            source=endpoint("src", "A"),
            destination=endpoint("dst", "B"),
        )
        expected = {
            (a, b, p)
            for a, b in (("A", "B"), ("B", "A"))
            for p in ("icmp", "tcp", "udp")
        }
        for probes in (before, after):
            assert {
                (s.source_side, s.destination_side, s.protocol) for s in probes
            } == expected
            assert all(s.operation == "probe" for s in probes)
        installed = next(s for s in specs if s.operation == "static-route-install")
        replacement = next(
            s for s in after if s.metadata["source_spec_id"] == installed.id
        )
        assert (
            replacement.metadata["planned_check_id"]
            == installed.metadata["check_bindings"]["post-migration"]
        )
        assert "static-route connectivity" in replacement.display_name
        assert installed.operation == "static-route-install"


def test_selected_providers_have_complete_routing_matrix(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(
        config_factory(performance_enabled=False), discovery_fixture, tmp_path
    )
    actual = {
        (s.source_group_id, s.destination_group_id, s.family, s.protocol)
        for s in plan.tests
        if s.category in {"provider-network-connectivity", "routed-provider"}
    }
    expected = {
        (a.id, b.id, family, protocol)
        for a in plan.provider_groups
        for b in plan.provider_groups
        if a.id != b.id
        for family in set(a.families) & set(b.families)
        for protocol in ("icmp", "tcp", "udp")
    }
    assert actual == expected
    assert all(
        s.authoritative and s.expectation == "reachable"
        for s in plan.tests
        if s.category in {"provider-network-connectivity", "routed-provider"}
    )
    semantic = [
        (
            s.operation,
            s.source_group_id,
            s.destination_group_id,
            s.source_side,
            s.destination_side,
            s.source_subnet_id,
            s.destination_subnet_id,
            s.family,
            s.protocol,
            s.phase,
            tuple(sorted(s.dependencies)),
            s.metadata.get("nat_path"),
        )
        for s in plan.tests
        if s.operation in {"probe", "fip-peer", "fip-baseline"}
    ]
    assert len(semantic) == len(set(semantic))


def test_internal_fixed_routing_without_pools_reserves_disjoint_prefixes(
    config_factory, discovery_fixture, tmp_path
):
    discovery_fixture.pools = []
    discovery_fixture.occupied_cidrs.extend(["10.240.0.0/24", "fd42:4e46:100::/64"])
    plan = build_plan(
        config_factory(performance_enabled=False), discovery_fixture, tmp_path
    )
    groups = [
        g
        for g in plan.groups
        if g.kind in {ONE_ROUTER_PROJECT_NETWORKS, TWO_ROUTER_STATIC_ROUTING}
    ]
    assert {(g.kind, tuple(g.families)) for g in groups} == {
        (kind, (family,))
        for kind in (ONE_ROUTER_PROJECT_NETWORKS, TWO_ROUTER_STATIC_ROUTING)
        for family in (4, 6)
    }
    allocated = [
        ipaddress.ip_network(cidr)
        for g in groups
        for cidr in g.metadata["generated_subnet_cidrs"].values()
    ]
    assert len(allocated) == 10
    occupied = [ipaddress.ip_network(cidr) for cidr in discovery_fixture.occupied_cidrs]
    assert all(
        not a.overlaps(b)
        for index, a in enumerate(allocated)
        for b in allocated[index + 1 :] + occupied
        if a.version == b.version
    )
    for group in groups:
        assert not group.pool_id and not group.floating_subnet_id
        reachable = [
            s
            for s in plan.tests
            if s.dependencies == [group.id]
            and s.expectation == "reachable"
            and s.protocol in {"icmp", "tcp", "udp"}
        ]
        assert {(s.source_side, s.destination_side, s.protocol) for s in reachable} >= {
            (a, b, p)
            for a, b in (("A", "B"), ("B", "A"))
            for p in ("icmp", "tcp", "udp")
        }
        builder = object.__new__(ResourceBuilder)
        builder.name_prefix = "nflux-fixed-routing"
        builder.resource_name_registry = resource_name_registry(builder.name_prefix)
        builder.run_tag = "neutron-flux-fixed-routing"
        builder.tracker = mock.Mock()
        builder._availability_zone_hint_args = mock.Mock(return_value=[])
        builder._validate_created_resource_zone = mock.Mock()
        for side, cidr in group.metadata["generated_subnet_cidrs"].items():
            builder.osc = mock.Mock()
            builder.osc.json.side_effect = [
                {"id": "network"},
                {"id": "subnet", "cidr": cidr, "gateway_ip": None},
            ]
            builder._create_generated_tenant_network(
                group, generation=1, suffix=side, no_gateway=side == "transit"
            )
            command = builder.osc.json.call_args.args
            assert command[command.index("--subnet-range") + 1] == cidr
            assert "--subnet-pool" not in command
            assert ("--gateway" in command) == (side == "transit")


@pytest.mark.parametrize(
    "defect",
    [
        None,
        "fip-attached",
        "snat-disabled",
        "gateway-unknown",
        "wrong-observed-source",
        "mapping-mismatch",
    ],
)
def test_snat_to_fip_requires_actual_source_and_destination_evidence(
    config_factory, discovery_fixture, tmp_path, defect
):
    plan = build_plan(
        config_factory(performance_enabled=False), discovery_fixture, tmp_path
    )
    engine, spec, source, target, probe = _matrix_engine(plan, "snat-to-floating-ip")
    source_group = engine.groups[spec.source_group_id]
    assert source_group.fips == {}
    assert floating_ip_target_sides(spec) == {spec.destination_group_id: {"A"}}
    assert len(endpoint_sides(spec)) == 2
    assert not any(
        other.source_group_id == spec.source_group_id
        and not other.metadata.get("source_without_floating_ip")
        for other in plan.tests
    )
    assert all(
        batch_key(other) != batch_key(spec)
        for other in plan.tests
        if other.operation == "fip-peer"
        and not other.metadata.get("source_without_floating_ip")
    )
    validate_plan_translation_safety(plan)
    if defect == "fip-attached":
        engine.builder.osc.json.return_value = [{"ID": "unexpected-fip"}]
    elif defect in {"snat-disabled", "gateway-unknown"}:
        engine.builder.capture_router_state = lambda _: {
            "external_gateway_info": {
                "enable_snat": defect != "snat-disabled",
                "external_fixed_ips": [],
            }
        }
    elif defect == "mapping-mismatch":
        engine.builder.wait_floating_ip_association.return_value = {"matched": False}
    elif defect == "wrong-observed-source":
        probe.diagnostics["observed_peer_ip"] = source.fixed_ips["fixed"]
    if defect in {
        "fip-attached",
        "snat-disabled",
        "gateway-unknown",
        "mapping-mismatch",
    }:
        with pytest.raises(SuiteError):
            engine._run_fip_peer(spec)
        engine.probes.tcp.endpoint_peer_identity.assert_not_called()
    else:
        engine._run_fip_peer(spec)
        assert PolicyEvaluator().evaluate(spec, probe).status == (
            "FAIL" if defect else "PASS"
        )
        assert probe.diagnostics["source_router_snat"]["no_floating_ip_verified"]
        assert probe.diagnostics["source_floating_ip"] is None
        engine.builder.ensure_group_fips.assert_called_once_with(
            engine.groups[spec.destination_group_id], side="A"
        )
    engine.builder.osc.json.assert_called_once_with(
        "floating", "ip", "list", "--port", source.test_port_id
    )


def test_address_display_uses_mapping_evidence_and_preserves_execution_context(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(
        config_factory(performance_enabled=False), discovery_fixture, tmp_path
    )
    engine, spec, source, target, probe = _matrix_engine(plan)
    # The fixture returns the real allocation identity, including its address.
    engine._run_fip_peer(spec)
    path = engine._address_evidence(spec, probe, source, target)
    assert path["source"]["probe_address"] == source.fixed_ips["fixed"]
    assert path["destination"]["probe_address"] != path["destination"]["fixed_ip"]
    assert path["source"]["floating_ip_status"] == "verified attached"
    assert path["destination"]["floating_ip_status"] == "verified attached"
    lines = " ".join(address_path_lines({"address_path": path}))
    assert "fixed" in lines and "floating" in lines and "probe" in lines
    assert "Source seen by destination" in lines
    label = execution_name(
        {
            "display_name": spec.display_name + " — pre-migration safety round 1/1",
            "family": 4,
            "details": {"protocol": "tcp", "compute_placement": "inter-host"},
        }
    )
    assert "Before migration" in label
    assert "IPv4" in label
    assert "peer's floating IP" in label
    # A displayed planner suffix is not evidence of actual VM placement.
    assert "inter-host" not in label
    assert "A to A" not in label


@pytest.mark.parametrize("failure", [None, "reset", "wrong-byte-count", "ack-timeout"])
def test_continuity_keeps_one_socket_through_partial_writes_and_stalls(
    config_factory, failure
):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory()
    code = builder._live_continuity_code(
        source_ip="192.0.2.1",
        destination_ip="192.0.2.2",
        family=4,
        stop_path="stop",
        result_path="result",
        maximum_seconds=30,
    )
    worker = next(
        node
        for node in ast.parse(code).body
        if isinstance(node, ast.FunctionDef) and node.name == "tcp_worker"
    )
    clock = SimpleNamespace(now=0.0)
    received = bytearray()
    timeouts = 24
    replies = bytearray(b"READY\n")
    sock = mock.Mock()
    sock.getsockname.return_value = ("192.0.2.1", 32000)
    sock.getpeername.return_value = ("192.0.2.2", 18080)

    def send(data):
        nonlocal timeouts
        # Accepted bytes must never reappear after a partial write or timeout.
        assert len(data) == 16384 - len(received)
        if len(received) == 1024 and timeouts:
            clock.now += 0.25
            timeouts -= 1
            if failure == "reset":
                raise ConnectionResetError("reset by peer")
            raise TimeoutError("temporary write stall")
        accepted = min(len(data), 1024)
        received.extend(data[:accepted])
        return accepted

    def shutdown(_):
        replies.extend(
            b"RESULT "
            + json.dumps(
                {"bytes": len(received) + (1 if failure == "wrong-byte-count" else 0)}
            ).encode()
            + b"\n"
        )

    def recv(size):
        if failure == "ack-timeout" and received:
            clock.now += 0.25
            raise TimeoutError("no final response")
        chunk = bytes(replies[:size])
        del replies[:size]
        return chunk

    sock.send.side_effect, sock.recv.side_effect, sock.shutdown.side_effect = (
        send,
        recv,
        shutdown,
    )
    factory = mock.Mock(return_value=sock)
    state = {"connected": False, "survived": False, "bytes_sent": 0, "error": None}
    namespace = {
        "json": json,
        "socket": SimpleNamespace(
            socket=factory,
            SOCK_STREAM=socket.SOCK_STREAM,
            SHUT_WR=socket.SHUT_WR,
            timeout=socket.timeout,
        ),
        "time": SimpleNamespace(monotonic=lambda: clock.now),
        "FAMILY": socket.AF_INET,
        "SOURCE": "192.0.2.1",
        "DESTINATION": "192.0.2.2",
        "TCP_PORT": 18080,
        "MAXIMUM": 30,
        "TOKEN": "0123456789abcdef0123456789abcdef",
        "EXPECTED_PROBE_ID": None,
        "EXPECTED_FIXED_IP": None,
        "EXPECTED_SOURCE_IPS": None,
        "READINESS_TIMEOUT": 10.0,
        "ACK_TIMEOUT": 15.0,
        "MAX_RESPONSE_BYTES": 1_048_576,
        "started": 0,
        "tcp": state,
        "stop": mock.Mock(),
        "should_stop": lambda: len(received) >= 16384,
    }
    exec(
        compile(
            ast.Module(body=[worker], type_ignores=[]), "continuity-worker", "exec"
        ),
        namespace,
    )
    namespace["tcp_worker"]()
    factory.assert_called_once()
    sock.connect.assert_called_once()
    sock.close.assert_called_once()
    assert state["survived"] is (failure is None)
    if failure != "reset":
        assert received == b"x" * 16384
        assert state["bytes_sent"] == 16384
        assert clock.now >= 6.0
    if failure is None:
        assert len(state["write_stalls"]) == 1
        assert state["write_stalls"][0]["duration_s"] >= 5.0
    elif failure == "ack-timeout":
        assert state["failure_kind"] == "acknowledgement-timeout"
        assert clock.now <= 22.0
    else:
        assert state["error"]
