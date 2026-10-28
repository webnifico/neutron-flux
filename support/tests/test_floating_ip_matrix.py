from __future__ import annotations

import shlex
import socket
import subprocess
import sys
import threading
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.check_plan import endpoint_sides
from neutron_flux.engine import TestEngine as Engine
from neutron_flux.errors import SuiteError
from neutron_flux.models import ProbeResult, RuntimeGroup
from neutron_flux.network_contract import PRIVATE_TRANSLATION_PROJECT_NETWORK
from neutron_flux.policy import PolicyEvaluator
from neutron_flux.probe_service import ProbeServiceManager
from neutron_flux.probes import ProbeContext, TCPProbe, UDPProbe
from neutron_flux.translation_safety import (
    validate_plan_translation_safety,
    validate_runtime_floating_ip_target,
)

from ._evidence import association_reader, attestation_boundary
from ._shared import build_plan, endpoint


@pytest.fixture(autouse=True)
def guest_icmp_capture_boundary(monkeypatch):
    # The complete capture transport is exercised by test_audit_socket_regressions.
    monkeypatch.setattr(
        "neutron_flux.engine_handlers.floating_ip_peer.attested_icmp",
        attestation_boundary,
    )


@pytest.fixture
def matrix_plan(config_factory, discovery_fixture, tmp_path):
    return build_plan(
        config_factory(performance_enabled=False), discovery_fixture, tmp_path
    )


def test_matrix_has_bounded_explicit_bidirectional_nat_contracts(matrix_plan):
    specs = [s for s in matrix_plan.tests if s.operation == "fip-peer"]
    bases = [
        g
        for g in matrix_plan.groups
        if g.kind == PRIVATE_TRANSLATION_PROJECT_NETWORK
        and not g.metadata.get("fip_peer_for")
    ]
    assert specs and len(specs) == 27 * len(bases)
    assert len({s.id for s in matrix_plan.tests}) == len(matrix_plan.tests)
    assert all(s.expectation != "observation" for s in matrix_plan.tests)
    for group in bases:
        same = [
            s
            for s in specs
            if s.source_group_id == group.id and s.destination_group_id == group.id
        ]
        assert {(s.source_side, s.destination_side, s.protocol) for s in same} == {
            (a, b, protocol)
            for a in ("A", "B")
            for b in ("A", "B")
            for protocol in ("icmp", "tcp", "udp")
        }
        separate = [
            s
            for s in specs
            if s.metadata["nat_path"] == "different-routers"
            and group.id in s.dependencies
        ]
        assert len(separate) == 6
        assert len({tuple(s.dependencies) for s in separate}) == 1
        assert {s.source_group_id for s in separate} == set(separate[0].dependencies)
        owners = set(separate[0].dependencies)
        hairpins = [
            s
            for s in specs
            if s.metadata["nat_path"] == "self-hairpin"
            and set(s.dependencies) == owners
        ]
        assert len(hairpins) == 6
        assert {(s.source_group_id, s.protocol) for s in hairpins} == {
            (owner, protocol) for owner in owners for protocol in ("icmp", "tcp", "udp")
        }
        assert all(s.source_group_id == s.destination_group_id for s in hairpins)
    assert all(
        s.authoritative and s.family == 4 and s.expectation == "reachable"
        for s in specs
    )
    assert matrix_plan.estimated["peak_floating_ips"] == 3
    assert matrix_plan.estimated["peak_created_routers"] >= 2
    assert matrix_plan.estimated["peak_endpoint_instances"] == 2


@pytest.mark.parametrize("defect", ["pool", "external", "mode", "side", "expectation"])
def test_unsafe_matrix_is_rejected_before_execution(matrix_plan, defect):
    spec = next(
        s
        for s in matrix_plan.tests
        if s.operation == "fip-peer" and s.metadata["nat_path"] == "different-routers"
    )
    group = next(g for g in matrix_plan.groups if g.id == spec.destination_group_id)
    if defect == "pool":
        group.pool_id = "pool"
    elif defect == "external":
        group.external_network_id = "another-network"
    elif defect == "mode":
        spec.metadata["nat_path"] = "same-router"
    elif defect == "side":
        spec.destination_side = "C"
    else:
        spec.expectation = "observation"
    with pytest.raises(SuiteError):
        validate_plan_translation_safety(matrix_plan)


def _matrix_engine(plan, mode="different-routers", protocol="tcp"):
    spec = next(
        s
        for s in plan.tests
        if s.operation == "fip-peer"
        and s.metadata["nat_path"] == mode
        and s.protocol == protocol
    )
    groups = {}
    number = 0
    for group_id, sides in endpoint_sides(spec):
        group = next(g for g in plan.groups if g.id == group_id)
        endpoints, fips = [], {}
        for side in sorted(sides):
            number += 1
            ep = endpoint(f"vm-{number}", side)
            ep.fixed_ips = {"fixed": f"10.128.{number}.10"}
            endpoints.append(ep)
            fips[ep.label] = {
                "id": f"fip-{number}",
                "address": f"192.0.2.{number}",
                "port_id": ep.test_port_id,
            }
        if (
            spec.metadata.get("source_without_floating_ip")
            and group_id == spec.source_group_id
        ):
            fips = {}
        groups[group_id] = RuntimeGroup(
            plan=group,
            network_id=f"net-{number}",
            network_name=group.label,
            subnet_ids=["fixed"],
            router_id=f"router-{number}",
            endpoints=endpoints,
            source_nat_enabled=True,
            fips=fips,
            metadata={"floating_ip_fixed_subnet_id": "fixed"},
        )
    source = groups[spec.source_group_id].endpoint(spec.source_side)
    target = groups[spec.destination_group_id].endpoint(spec.destination_side)
    source_fip = (
        groups[spec.source_group_id]
        .fips.get(source.label, {})
        .get("address", "192.0.2.254")
    )
    target_fip = groups[spec.destination_group_id].fips[target.label]["address"]
    result = ProbeResult(
        "reachable",
        True,
        1,
        1,
        source_ip=source.fixed_ips["fixed"],
        destination_ip=target_fip,
        protocol=protocol,
        diagnostics={
            "observer_probe_id": target.server_id,
            "observer_instance_id": "process",
            "observer_local_ip": target.fixed_ips["fixed"],
            "observed_peer_ip": source_fip,
        },
    )
    engine = object.__new__(Engine)
    engine._runtime_groups = tuple(groups.values())
    engine.builder = SimpleNamespace(
        runtime_groups=list(groups.values()),
        osc=SimpleNamespace(json=mock.Mock(return_value=[])),
        capture_router_state=lambda _: {
            "external_gateway_info": {
                "enable_snat": True,
                "external_fixed_ips": [{"ip_address": "192.0.2.254"}],
            }
        },
        _gateway_info=lambda value: value,
        ensure_group_fips=mock.Mock(),
        wait_floating_ip_association=association_reader(groups.values()),
        _launch_probe_process=mock.Mock(),
        _existing_probe_service_ready=mock.Mock(
            return_value=(
                True,
                {
                    "listeners": {
                        "4": {"tcp": True, "udp": True, "instance_id": "process"}
                    }
                },
            )
        ),
    )
    engine.probes = SimpleNamespace(
        endpoint=mock.Mock(return_value=result),
        icmp=SimpleNamespace(endpoint=mock.Mock(return_value=result)),
        tcp=SimpleNamespace(endpoint_peer_identity=mock.Mock(return_value=result)),
        udp=SimpleNamespace(endpoint_peer_identity=mock.Mock(return_value=result)),
    )
    engine._record = mock.Mock()
    return engine, spec, source, target, result


@pytest.mark.parametrize(
    "mode", ["same-router", "self-hairpin", "different-routers", "snat-to-floating-ip"]
)
@pytest.mark.parametrize("protocol", ["icmp", "tcp", "udp"])
def test_matrix_executes_from_private_interface_to_verified_fip(
    matrix_plan, mode, protocol
):
    engine, spec, source, target, result = _matrix_engine(matrix_plan, mode, protocol)
    engine._run_fip_peer(spec)
    if protocol == "icmp":
        engine.probes.icmp.endpoint.assert_called_once_with(
            source,
            source.fixed_ips["fixed"],
            result.destination_ip,
            4,
            payload_token="1234567890abcdef1234567890abcdef",
        )
    else:
        getattr(engine.probes, protocol).endpoint_peer_identity.assert_called_once_with(
            source, source.fixed_ips["fixed"], result.destination_ip, 4
        )
    assert PolicyEvaluator().evaluate(spec, result).status == "PASS"
    assert result.diagnostics["nat_path"] == mode
    for call in engine.builder.wait_floating_ip_association.call_args_list:
        assert call.kwargs["expected_port_id"] in {
            source.test_port_id,
            target.test_port_id,
        }
    assert engine.builder.ensure_group_fips.call_count == (
        1 if mode in {"self-hairpin", "snat-to-floating-ip"} else 2
    )
    engine._record.assert_called_once()


@pytest.mark.parametrize(
    "defect", ["wrong-vm", "wrong-process", "wrong-source", "timeout"]
)
def test_known_matrix_failures_are_fail_not_unverified(matrix_plan, defect):
    engine, spec, _source, _target, result = _matrix_engine(matrix_plan)
    if defect == "wrong-vm":
        result.diagnostics["observer_probe_id"] = "wrong"
    elif defect == "wrong-process":
        result.diagnostics["observer_instance_id"] = "wrong"
    elif defect == "wrong-source":
        result.diagnostics["observed_peer_ip"] = "10.128.0.2"
    else:
        result.outcome, result.success = "blocked", False
    engine._run_fip_peer(spec)
    assert PolicyEvaluator().evaluate(spec, result).status == "FAIL"


@pytest.mark.parametrize("defect", ["association", "listener", "router", "side"])
def test_invalid_setup_never_becomes_a_dataplane_failure(matrix_plan, defect):
    engine, spec, _source, _target, _result = _matrix_engine(matrix_plan)
    if defect == "association":
        engine.builder.wait_floating_ip_association.return_value = {"matched": False}
    elif defect == "listener":
        engine.builder._existing_probe_service_ready.return_value = (False, {})
    elif defect == "router":
        engine.groups[spec.destination_group_id].router_id = None
    else:
        engine.groups[spec.source_group_id].plan.metadata[
            "floating_ip_endpoint_sides"
        ] = ["B"]
    with pytest.raises(SuiteError):
        engine._run_fip_peer(spec)
    engine.probes.tcp.endpoint_peer_identity.assert_not_called()


def test_side_b_requires_explicit_plan_permission(matrix_plan):
    engine, spec, _source, _target, _result = _matrix_engine(matrix_plan, "same-router")
    group = engine.groups[spec.source_group_id]
    assert validate_runtime_floating_ip_target(group, "B") == ("B", "fixed")
    group.plan.metadata.pop("floating_ip_endpoint_sides")
    with pytest.raises(SuiteError, match="explicitly allowed"):
        validate_runtime_floating_ip_target(group, "B")


def test_udp_peer_protocol_reports_real_identity_and_bound_source():
    target = endpoint("udp-target")
    namespace = {"__name__": "probe_test"}
    code = ProbeServiceManager(18080, 18081)._server_code(target)
    # Load the actual generated service helpers without starting its listener loop.
    prefix = code[: code.index("\ntry:\n    jobs = []")]
    exec(compile(prefix, "probe-service", "exec"), namespace)
    # Use production socket preparation, including required packet-info capture.
    with namespace["prepare_socket"](socket.AF_INET, socket.SOCK_DGRAM, 0) as listener:
        port = listener.getsockname()[1]
        failure = []

        def serve():
            try:
                namespace["udp_loop"](listener)
            except OSError:
                pass
            except (ValueError, RuntimeError, TypeError, NameError) as exc:
                failure.append(exc)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        probe = UDPProbe(
            ProbeContext(
                endpoint_executor=lambda _endpoint, command: subprocess.run(
                    [sys.executable, "-c", shlex.split(command)[2]],
                    capture_output=True,
                    text=True,
                    timeout=10,
                ),
                controller_executor=mock.Mock(),
                tcp_port=18080,
                udp_port=port,
            )
        )
        result = probe.endpoint_peer_identity(target, "127.0.0.1", "127.0.0.1", 4)
        assert result.success, (result.stdout, result.stderr, failure)
        assert result.diagnostics["observer_probe_id"] == target.server_id
        assert result.diagnostics["observer_instance_id"] == namespace["INSTANCE_ID"]
        assert result.diagnostics["observed_peer_ip"] == "127.0.0.1"
    thread.join(timeout=2)
    assert not failure


def test_peer_probe_code_compiles_for_both_protocols():
    for datagram in (False, True):
        code = TCPProbe._peer_identity_attempt_code(
            "10.0.0.2", "192.0.2.2", 4, 18080, "token", datagram=datagram
        )
        compile(code, "peer-probe", "exec")


def test_listener_readback_failure_retains_attempted_probe(matrix_plan):
    engine, spec, _source, _target, result = _matrix_engine(matrix_plan)
    health = engine.builder._existing_probe_service_ready.return_value
    engine.builder._existing_probe_service_ready.side_effect = [
        health,
        SuiteError("SSH timeout"),
    ]
    result.command, result.stdout = "python3 attempted-probe", "peer reply"
    engine._run_fip_peer(spec)
    assert PolicyEvaluator().evaluate(spec, result).status == "ERROR"
    assert result.command == "python3 attempted-probe"
    assert result.stdout == "peer reply"
    assert (
        "SSH timeout"
        in result.diagnostics["destination_listener_after"]["inspection_error"]
    )
