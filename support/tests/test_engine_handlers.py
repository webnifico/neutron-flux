from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.engine import TestEngine as FluxTestEngine
from neutron_flux.engine_state import LifecycleStateStore
from neutron_flux.errors import SuiteError
from neutron_flux.models import Endpoint, PlannedGroup, ProbeResult, RuntimeGroup
from neutron_flux.models import TestSpec as FluxTestSpec


def _probe(success: bool, outcome: str | None = None, **kwargs) -> ProbeResult:
    return ProbeResult(
        outcome=outcome or ("reachable" if success else "blocked"),
        success=success,
        elapsed_ms=5,
        attempts=1,
        **kwargs,
    )


def _endpoint(label: str, side: str, address: str) -> Endpoint:
    return Endpoint(
        label=label,
        server_id=f"server-{label}",
        server_name=f"server-{label}",
        management_port_id=f"mgmt-{label}",
        management_ip="10.254.0.10" if side == "A" else "10.254.0.11",
        test_port_id=f"port-{label}",
        test_mac="fa:16:3e:00:00:01",
        fixed_ips={"subnet": address},
        host="compute-1" if side == "A" else "compute-2",
        availability_zone="az1",
        volume_id=None,
        side=side,
        metadata={"data_security_group_id": f"sg-{side.lower()}"},
    )


def _runtime_group(
    group_id: str,
    endpoints: list[Endpoint],
    *,
    router_id: str | None = None,
    kind: str = "tenant",
) -> RuntimeGroup:
    plan = PlannedGroup(
        group_id,
        kind,
        group_id,
        "network-id",
        "network-name",
        ["subnet"],
        [4],
    )
    return RuntimeGroup(
        plan=plan,
        network_id="network-id",
        network_name="network-name",
        subnet_ids=["subnet"],
        router_id=router_id,
        endpoints=endpoints,
        source_nat_enabled=False,
        fips={},
    )


def _spec(
    operation: str, *, category: str = "lifecycle", protocol: str = "tcp"
) -> FluxTestSpec:
    return FluxTestSpec(
        id=f"TEST-{operation}",
        category=category,
        operation=operation,
        family=4,
        expectation="reachable",
        expectation_reason="test",
        authoritative=True,
        dependencies=["source", "target"],
        source_group_id="source",
        destination_group_id="target",
        source_side="A",
        destination_side="B",
        source_subnet_id="subnet",
        destination_subnet_id="subnet",
        protocol=protocol,
    )


def _engine(config_factory):
    source = _endpoint("source", "A", "192.0.2.10")
    target = _endpoint("target", "B", "192.0.2.20")
    groups = {
        "source": _runtime_group("source", [source], kind="provider"),
        "target": _runtime_group("target", [target], router_id="router-id"),
    }
    records: list[
        tuple[FluxTestSpec, ProbeResult, Endpoint | None, Endpoint | None, dict]
    ] = []
    engine = object.__new__(FluxTestEngine)
    engine.config = config_factory(convergence_timeout=1, convergence_interval=0)
    engine.lifecycle = LifecycleStateStore()
    engine.logger = mock.Mock()
    engine.builder = SimpleNamespace(
        controller=None,
        controller_probe_sources={},
        controller_probe_subnets={},
        security_control_ports={4: 42000},
        security_control_matching_rules={4: []},
        test_sg_ids={"A": "sg-a", "B": "sg-b"},
        ensure_group_fips=mock.Mock(),
        wait_floating_ip_association=mock.Mock(return_value={"matched": True}),
        osc=SimpleNamespace(run=mock.Mock()),
    )
    engine.probes = SimpleNamespace(
        endpoint=mock.Mock(return_value=_probe(True)),
        controller=mock.Mock(return_value=_probe(True)),
        tcp=SimpleNamespace(
            endpoint=mock.Mock(return_value=_probe(True)),
            endpoint_port=mock.Mock(return_value=_probe(False)),
            endpoint_peer_identity=mock.Mock(return_value=_probe(True)),
        ),
        runner_fip=SimpleNamespace(run=mock.Mock(return_value=(_probe(True), True))),
    )
    engine._group = lambda group_id: groups[group_id]
    engine._endpoint_address = lambda group_id, side, subnet_id: (
        (source, "192.0.2.10") if group_id == "source" else (target, "192.0.2.20")
    )
    engine._network_mtu = mock.Mock(return_value=1450)
    engine._record = lambda spec, probe, src, dst, **kwargs: records.append(
        (spec, probe, src, dst, kwargs)
    )
    engine._wait_endpoint_state = mock.Mock(return_value=_probe(True))
    engine._wait_stable_endpoint_state = mock.Mock(return_value=_probe(True))
    return engine, source, target, groups, records


def test_endpoint_handlers_cover_normal_and_unverified_extra_route(config_factory):
    engine, source, target, groups, records = _engine(config_factory)
    spec = _spec("probe", category="same-subnet", protocol="icmp")
    engine._run_endpoint_probe(spec)
    engine.probes.endpoint.assert_called_once_with(
        "icmp", source, "192.0.2.10", "192.0.2.20", 4, network_mtu=None
    )
    engine._network_mtu.assert_not_called()
    assert records[-1][1].success is True

    spec = _spec("probe", category="router-extra-route", protocol="icmp")
    engine._run_endpoint_probe(spec)
    assert records[-1][1].outcome == "inconclusive"
    assert spec.authoritative is False
    assert spec.metadata["authority_required"] is True


def test_controller_and_egress_handlers_cover_error_and_success(config_factory):
    engine, source, target, groups, records = _engine(config_factory)
    spec = _spec("controller-probe", category="provider", protocol="icmp")
    engine._run_controller_probe(spec)
    assert records[-1][1].outcome == "error"

    engine.builder.controller = source
    engine.builder.controller_probe_sources[4] = "198.51.100.10"
    engine.builder.controller_probe_subnets[4] = "subnet"
    engine._run_controller_probe(spec)
    engine.probes.controller.assert_called_once_with(
        "icmp", "198.51.100.10", "192.0.2.20", 4
    )
    assert spec.expectation == "reachable"

    egress = _spec("egress", category="egress", protocol="icmp")
    engine._run_egress(egress)
    assert records[-1][1].outcome == "error"
    egress.metadata["target"] = "1.1.1.1"
    engine._run_egress(egress)
    assert records[-1][1].diagnostics["external_target"] == "1.1.1.1"


def test_tcp_control_probe_requires_and_uses_destination_port(config_factory):
    engine, source, target, groups, records = _engine(config_factory)
    with pytest.raises(SuiteError, match="destination port"):
        engine._execute_endpoint_probe(
            source, "192.0.2.10", "192.0.2.20", 4, "tcp-control"
        )
    result = engine._execute_endpoint_probe(
        source,
        "192.0.2.10",
        "192.0.2.20",
        4,
        "tcp-control",
        destination_port=42000,
    )
    assert result.outcome == "blocked"
    engine.probes.tcp.endpoint_port.assert_called_once_with(
        source, "192.0.2.10", "192.0.2.20", 4, 42000
    )


def test_security_deny_handles_disabled_port_security(config_factory):
    engine, source, target, groups, records = _engine(config_factory)
    target.port_security_enabled = False
    spec = _spec("security-deny", category="security-group")
    engine._run_security_deny(spec)
    assert spec.expectation == "not-applicable"
    assert engine.lifecycle["security:target:4"]["not_applicable"] is True
    assert records[-1][1].diagnostics["port_security_enabled"] is False


def test_security_deny_marks_existing_rule_unverified(config_factory):
    engine, source, target, groups, records = _engine(config_factory)
    engine.builder.security_group_allows_port = mock.Mock(
        return_value=(True, [{"id": "broad-rule"}])
    )
    spec = _spec("security-deny", category="security-group")
    engine._run_security_deny(spec)
    assert spec.authoritative is False
    assert records[-1][1].outcome == "inconclusive"
    assert engine.lifecycle["security:target:4"]["authoritative_port"] is False


def test_security_allow_and_restore_apply_exact_temporary_rule(config_factory):
    engine, source, target, groups, records = _engine(config_factory)
    engine.builder.security_group_allows_port = mock.Mock(return_value=(False, []))
    engine.builder.add_temporary_security_rule = mock.Mock(return_value="rule-id")
    engine.builder.delete_security_rule = mock.Mock()
    deny = _spec("security-deny", category="security-group")
    engine._run_security_deny(deny)

    allow = _spec("security-allow", category="security-group")
    engine._run_security_allow(allow)
    state = engine.lifecycle["security:target:4"]
    assert state["temporary_rule_id"] == "rule-id"
    engine.builder.add_temporary_security_rule.assert_called_once()

    restore = _spec("security-restore", category="security-group")
    engine._run_security_restore(restore)
    engine.builder.delete_security_rule.assert_called_once_with("rule-id", "sg-b")
    assert state["temporary_rule_id"] is None


def test_security_allow_and_restore_degrade_without_isolated_transition(config_factory):
    engine, source, target, groups, records = _engine(config_factory)
    key = "security:target:4"
    engine.lifecycle[key] = {
        "matching_rules": [{"id": "existing"}],
        "authoritative_port": False,
        "temporary_rule_id": None,
    }
    allow = _spec("security-allow", category="security-group")
    engine._run_security_allow(allow)
    assert records[-1][1].outcome == "inconclusive"
    restore = _spec("security-restore", category="security-group")
    engine._run_security_restore(restore)
    assert records[-1][1].outcome == "inconclusive"


def _fip_state(source: Endpoint, target: Endpoint) -> dict:
    return {
        "id": "fip-id",
        "address": "203.0.113.10",
        "port_id": target.test_port_id,
        "fixed_ip": "192.0.2.20",
        "source": source,
        "source_ip": "192.0.2.10",
        "target": target,
        "runner": True,
        "target_external_cidr": "203.0.113.0/24",
        "baseline": True,
        "baseline_outcome": "reachable",
        "authoritative": True,
        "detached": False,
        "detach_requested": False,
        "detach_confirmed": False,
    }


def test_fip_runner_default_route_does_not_establish_routing_authority(config_factory):
    from ._evidence import configure_translation_target

    engine, source, target, groups, records = _engine(config_factory)
    groups["target"].fips[target.label] = {"id": "fip-id", "address": "203.0.113.10"}
    configure_translation_target(engine, groups["target"], target)
    engine.builder.ensure_group_fips = mock.Mock()
    engine._address = lambda group, endpoint, subnet: "192.0.2.20"
    spec = _spec("fip-baseline", category="floating-ip")
    spec.metadata["target_external_cidr"] = "203.0.113.0/24"
    engine._run_fip_baseline(spec)
    state = engine.lifecycle["fip:target"]
    assert state["baseline"] is True
    assert state["authoritative"] is False
    assert spec.expectation == "observation"
    assert records[-1][1].diagnostics["fip_observer_mode"] == "runner"


def test_fip_withdraw_and_return_restore_after_unconfirmed_detach(config_factory):
    engine, source, target, groups, records = _engine(config_factory)
    engine.lifecycle["fip:target"] = _fip_state(source, target)
    engine.builder.osc.run.return_value = SimpleNamespace(
        returncode=0, stdout="", stderr=""
    )
    engine.builder.wait_floating_ip_association = mock.Mock(
        side_effect=[
            {"matched": False, "attempts": 2},
            {
                "matched": True,
                "attempts": 1,
                "port_id": target.test_port_id,
                "fixed_ip_address": "192.0.2.20",
                "floating_ip_address": "203.0.113.10",
            },
        ]
    )
    engine._wait_fip_state = mock.Mock(return_value=_probe(True))

    withdraw = _spec("fip-withdraw", category="floating-ip")
    engine._run_fip_withdraw(withdraw)
    state = engine.lifecycle["fip:target"]
    assert state["detach_requested"] is True
    assert records[-1][1].outcome == "error"

    restore = _spec("fip-return", category="floating-ip")
    engine._run_fip_return(restore)
    assert state["detach_requested"] is False
    assert records[-1][1].success is True
    assert records[-1][1].diagnostics["detach_confirmed_before_restore"] is False


def test_fip_lifecycle_degrades_when_baseline_or_cloud_operation_is_missing(
    config_factory,
):
    engine, source, target, groups, records = _engine(config_factory)
    state = _fip_state(source, target)
    state["authoritative"] = False
    engine.lifecycle["fip:target"] = state
    engine._run_fip_withdraw(_spec("fip-withdraw", category="floating-ip"))
    assert records[-1][1].outcome == "inconclusive"

    state["authoritative"] = True
    state["detach_requested"] = False
    engine._run_fip_return(_spec("fip-return", category="floating-ip"))
    assert records[-1][1].outcome == "inconclusive"


def test_extra_route_full_transition_and_degraded_paths(config_factory):
    engine, source, target, groups, records = _engine(config_factory)
    runtime = groups["target"]
    engine.builder.set_extra_routes = mock.Mock()
    engine.builder.set_one_extra_route = mock.Mock()

    baseline = _spec(
        "extra-route-baseline", category="router-extra-route", protocol="icmp"
    )
    engine._wait_endpoint_state.return_value = _probe(False)
    engine._run_extra_route_baseline(baseline)
    state = engine.lifecycle["extra-route:target"]
    assert state["baseline_blocked"] is True

    add = _spec("extra-route-add", category="router-extra-route", protocol="icmp")
    engine._wait_endpoint_state.return_value = _probe(True)
    engine._run_extra_route_add(add)
    assert state["routes_installed"] is True

    engine.probes.endpoint.return_value = _probe(True)
    remove = _spec("extra-route-remove", category="router-extra-route", protocol="icmp")
    remove.metadata["route_side"] = "A"
    engine._wait_endpoint_state.return_value = _probe(False)
    engine._run_extra_route_remove(remove)
    assert state["removed_route_side"] == "A"

    restore = _spec(
        "extra-route-restore", category="router-extra-route", protocol="icmp"
    )
    engine._wait_endpoint_state.return_value = _probe(True)
    engine._run_extra_route_restore(restore)
    assert runtime.metadata["routes_installed"] is True
    assert records[-1][1].success is True

    state["removed_route_side"] = None
    engine._run_extra_route_restore(restore)
    assert records[-1][1].outcome == "inconclusive"


def test_extra_route_add_and_remove_require_valid_baselines(config_factory):
    engine, source, target, groups, records = _engine(config_factory)
    engine.lifecycle["extra-route:target"] = {
        "baseline_blocked": False,
        "routes_installed": False,
        "route_setup_error": "failed",
    }
    engine._run_extra_route_add(
        _spec("extra-route-add", category="router-extra-route", protocol="icmp")
    )
    assert records[-1][1].outcome == "inconclusive"
    engine._run_extra_route_remove(
        _spec("extra-route-remove", category="router-extra-route", protocol="icmp")
    )
    assert records[-1][1].diagnostics["route_setup_error"] == "failed"


def test_router_interface_lifecycle_full_transition(config_factory):
    engine, source, target, groups, records = _engine(config_factory)
    engine.probes.endpoint.return_value = _probe(True)
    engine.builder.osc.run.return_value = SimpleNamespace(
        returncode=0, stdout="", stderr=""
    )
    engine.builder.wait_router_interface = mock.Mock(return_value={"matched": True})
    engine._wait_endpoint_state.return_value = _probe(False)

    withdraw = _spec("router-withdraw", category="router-interface", protocol="icmp")
    engine._run_router_withdraw(withdraw)
    state = engine.lifecycle["router:target"]
    assert state["cloud_operation_performed"] is True

    engine._wait_endpoint_state.return_value = _probe(True)
    restore = _spec("router-return", category="router-interface", protocol="icmp")
    engine._run_router_return(restore)
    assert records[-1][1].success is True
    assert engine.builder.osc.run.call_count == 2


def test_router_interface_lifecycle_skips_cloud_operation_without_baseline(
    config_factory,
):
    engine, source, target, groups, records = _engine(config_factory)
    engine.probes.endpoint.return_value = _probe(False)
    withdraw = _spec("router-withdraw", category="router-interface", protocol="icmp")
    engine._run_router_withdraw(withdraw)
    assert engine.lifecycle["router:target"]["cloud_operation_performed"] is False
    engine._run_router_return(_spec("router-return", category="router-interface"))
    assert records[-1][1].outcome == "inconclusive"
    engine.builder.osc.run.assert_not_called()


def test_server_lifecycle_full_transition(config_factory):
    engine, source, target, groups, records = _engine(config_factory)
    engine.probes.endpoint.return_value = _probe(True)
    engine.builder.osc.run.return_value = SimpleNamespace(
        returncode=0, stdout="", stderr=""
    )
    engine.builder._wait_for_status = mock.Mock()
    engine.builder._wait_for_ssh = mock.Mock(return_value=True)
    engine.builder.reconfigure_endpoint = mock.Mock()
    engine._wait_endpoint_state.return_value = _probe(False)

    stop = _spec("server-stop", category="server-lifecycle", protocol="tcp")
    engine._run_server_stop(stop)
    state = engine.lifecycle["server:target:B"]
    assert state["cloud_operation_performed"] is True

    engine._wait_endpoint_state.return_value = _probe(True)
    start = _spec("server-start", category="server-lifecycle", protocol="tcp")
    engine._run_server_start(start)
    engine.builder._wait_for_ssh.assert_called_once()
    engine.builder.reconfigure_endpoint.assert_called_once_with(target)
    assert records[-1][1].success is True


def test_server_lifecycle_skips_stop_and_start_without_reachable_baseline(
    config_factory,
):
    engine, source, target, groups, records = _engine(config_factory)
    engine.probes.endpoint.return_value = _probe(False)
    engine._run_server_stop(_spec("server-stop", category="server-lifecycle"))
    assert engine.lifecycle["server:target:B"]["cloud_operation_performed"] is False
    engine._run_server_start(_spec("server-start", category="server-lifecycle"))
    assert records[-1][1].outcome == "inconclusive"
    engine.builder.osc.run.assert_not_called()


def test_router_source_nat_cloud_operation_handler_is_not_registered():
    from neutron_flux.engine_handlers.registry import OPERATION_METHODS

    assert "source-nat-observe" not in OPERATION_METHODS
    assert not hasattr(FluxTestEngine, "_run_source_nat")
