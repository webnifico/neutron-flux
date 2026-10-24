from __future__ import annotations

import dataclasses
import json
import subprocess
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.errors import SuiteError
from neutron_flux.models import ProbeResult
from neutron_flux.probes import ProbeContext, TCPProbe
from neutron_flux.test_selection import select_plan_tests

from ._shared import build_plan, endpoint
from .test_engine_handlers import _engine, _spec
from .test_measurement_integrity import _packet_size_spec


def _completed(returncode: int, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess(["probe"], returncode, stdout, stderr)


def _mtu_spec():
    identity = _packet_size_spec()
    return dataclasses.replace(
        identity,
        id="SAMPLE-FIP-EGRESS-MTU",
        category="floating-ip-egress-mtu",
        operation="fip-egress-mtu",
        expectation="mtu-behavior-assessed",
        protocol="icmp",
        metadata={
            **identity.metadata,
            "source_address_test_id": identity.id,
        },
        requires_pass=[identity.id],
    )


def _fragmentation_spec():
    mtu = _mtu_spec()
    return dataclasses.replace(
        mtu,
        id="SAMPLE-FIP-EGRESS-FRAGMENTATION",
        category="floating-ip-egress-fragmentation",
        operation="fip-egress-fragmentation",
        expectation="fragmentation-behaviour-classified",
        metadata={
            **mtu.metadata,
            "mtu_test_id": mtu.id,
        },
        requires_pass=[mtu.id],
    )


def _ready_packet_profile(engine, provider, project, groups) -> None:
    groups["target"].source_nat_enabled = True
    provider.metadata["probe_service"] = {"ready": True, "tcp_port": 18080}
    engine.builder.capture_router_state = mock.Mock(
        return_value={
            "external_gateway_info": {
                "enable_snat": True,
                "external_fixed_ips": [{"ip_address": "203.0.113.1"}],
            }
        }
    )

    def ensure_group_fips(runtime):
        runtime.fips[project.label] = {
            "id": "fip-id",
            "address": "203.0.113.10",
            "port_id": project.test_port_id,
            "fixed_ip": "192.0.2.20",
        }

    engine.builder.ensure_group_fips = mock.Mock(side_effect=ensure_group_fips)
    engine.probes.tcp.endpoint_peer_identity.return_value = ProbeResult(
        outcome="reachable",
        success=True,
        elapsed_ms=5,
        attempts=1,
        diagnostics={"observed_peer_ip": "203.0.113.10"},
    )
    engine._network_mtu = lambda group: 1500
    engine._endpoint_json = mock.Mock(
        side_effect=[
            {"discovery_confidence": "expected-confirmed", "discovered_mtu": 1500},
            {},
            {"capability": "not-required", "tested_packet_size": 1500},
            {},
        ]
    )


def test_all_fip_egress_profiles_are_independent_from_ingress(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    stages = [
        item
        for item in plan.tests
        if item.operation
        in {
            "fip-egress-source-address",
            "fip-egress-mtu",
            "fip-egress-fragmentation",
        }
    ]

    assert stages
    assert all("execution_policy" not in item.metadata for item in stages)
    by_group: dict[str, list] = {}
    for stage in stages:
        by_group.setdefault(str(stage.source_group_id), []).append(stage)
    for group_stages in by_group.values():
        by_operation = {item.operation: item for item in group_stages}
        assert set(by_operation) == {
            "fip-egress-source-address",
            "fip-egress-mtu",
            "fip-egress-fragmentation",
        }
        identity = by_operation["fip-egress-source-address"]
        mtu = by_operation["fip-egress-mtu"]
        fragmentation = by_operation["fip-egress-fragmentation"]
        assert identity.requires_pass == []
        assert mtu.requires_pass == [identity.id]
        assert fragmentation.requires_pass == [mtu.id]

        selected = select_plan_tests(plan, [identity.id])
        assert {item.id for item in selected.tests} == {
            "CONTROL-OBSERVATION-PORTS",
            "CONTROL-SSH",
            identity.id,
        }
        selected_identity = next(
            item for item in selected.tests if item.id == identity.id
        )
        assert "explicit_execution_authorized" not in selected_identity.metadata

        selected = select_plan_tests(plan, [fragmentation.id])
        assert {identity.id, mtu.id, fragmentation.id} <= {
            item.id for item in selected.tests
        }
        assert all(
            "explicit_execution_authorized" not in item.metadata
            for item in selected.tests
        )


def test_exact_egress_profile_creates_its_own_fip_and_runs(
    config_factory,
):
    engine, provider, project, groups, _records = _engine(config_factory)
    _ready_packet_profile(engine, provider, project, groups)
    recorded: list[tuple[tuple, dict]] = []
    engine.reporter = SimpleNamespace(
        result=lambda *args, **kwargs: recorded.append((args, kwargs))
    )
    engine.diagnostics = SimpleNamespace(collect=mock.Mock())

    engine._run_fip_egress_source_address(_packet_size_spec())

    args, kwargs = recorded[-1]
    assert args[2] == "PASS"
    assert kwargs["details"]["floating_ip"] == "203.0.113.10"
    assert kwargs["details"]["floating_ip_created_for_test"] is True
    assert kwargs["details"]["translation_matches_expected_identity"] is True
    engine.builder.ensure_group_fips.assert_called_once_with(groups["target"])
    engine.probes.tcp.endpoint_peer_identity.assert_called_once()


@pytest.mark.parametrize("ensure", [False, True])
def test_outbound_profiles_reject_a_stale_floating_ip_mapping(config_factory, ensure):
    engine, provider, project, groups, _records = _engine(config_factory)
    _ready_packet_profile(engine, provider, project, groups)
    engine.builder.ensure_group_fips(groups["target"])
    engine.builder.wait_floating_ip_association.return_value = {"matched": False}
    with pytest.raises(SuiteError, match="not associated with the source"):
        engine._fip_egress_context(_packet_size_spec(), ensure_floating_ip=ensure)
    engine._endpoint_json.assert_not_called()
    engine.probes.tcp.endpoint_peer_identity.assert_not_called()


def test_egress_tcp_failure_stops_before_packet_size_probes(
    config_factory,
):
    engine, provider, project, groups, _records = _engine(config_factory)
    _ready_packet_profile(engine, provider, project, groups)
    engine.probes.tcp.endpoint_peer_identity.return_value = ProbeResult(
        outcome="blocked",
        success=False,
        elapsed_ms=5000,
        attempts=1,
        diagnostics={
            "failure_phase": "connect",
            "stopped_after_first_pre_handshake_failure": True,
        },
    )
    recorded: list[tuple[tuple, dict]] = []
    engine.reporter = SimpleNamespace(
        result=lambda *args, **kwargs: recorded.append((args, kwargs))
    )
    engine.diagnostics = SimpleNamespace(collect=mock.Mock(return_value=(None, {})))

    engine._run_fip_egress_source_address(_packet_size_spec())

    args, kwargs = recorded[-1]
    assert args[2] == "FAIL"
    assert kwargs["observed"] == "floating-ip-outbound-tcp-connection-failed"
    engine._endpoint_json.assert_not_called()


def test_standard_run_executes_fip_egress_source_address(config_factory):
    engine, _provider, _project, _groups, _records = _engine(config_factory)
    recorded: list[tuple[tuple, dict]] = []
    engine.reporter = SimpleNamespace(
        result=lambda *args, **kwargs: recorded.append((args, kwargs))
    )
    spec = _packet_size_spec()
    operation = mock.Mock()
    engine.operations = {spec.operation: operation}

    engine._run_spec(spec)

    operation.assert_called_once_with(spec)
    assert recorded == []


@pytest.mark.parametrize("path_mtu", [1500, 1442])
def test_mtu_and_fragmentation_are_separate_results(config_factory, path_mtu):
    engine, provider, project, groups, _records = _engine(config_factory)
    _ready_packet_profile(engine, provider, project, groups)
    engine.builder.ensure_group_fips(groups["target"])
    engine._network_mtu = lambda group: 9000 if group == "target" else 1500
    recorded: list[tuple[tuple, dict]] = []
    engine.reporter = SimpleNamespace(
        result=lambda *args, **kwargs: recorded.append((args, kwargs))
    )
    engine._endpoint_json = mock.Mock(
        return_value={
            "reachable": True,
            "discovery_confidence": "expected-confirmed"
            if path_mtu == 1500
            else "confirmed-lower-boundary",
            "discovered_mtu": path_mtu,
            "expected_probe_classification": "success"
            if path_mtu == 1500
            else "packet-too-big",
            "reported_path_mtu": path_mtu,
            "path_boundary_confirmed": True,
        }
    )

    engine._run_fip_egress_mtu(_mtu_spec())

    mtu_args, mtu_kwargs = recorded[-1]
    assert mtu_args[2] == "PASS"
    assert mtu_kwargs["observed"] == (
        "advertised-mtu-contract-met"
        if path_mtu == 1500
        else "path-mtu-below-advertised"
    )
    if path_mtu == 1442:
        assert mtu_kwargs["details"]["health"] == "warning"
        assert "1442" in mtu_args[3] and "1500" in mtu_args[3]
    assert mtu_kwargs["details"]["expected_no_fragment_path_mtu"] == 1500
    assert "fragmentation_profile" not in mtu_kwargs["details"]
    mtu_result = SimpleNamespace(status="PASS", details=mtu_kwargs["details"])

    engine.reporter = SimpleNamespace(
        result=lambda *args, **kwargs: recorded.append((args, kwargs)),
        get_result=lambda test_id: mtu_result if test_id == _mtu_spec().id else None,
    )
    engine._network_router_backend_evidence = mock.Mock(return_value={})
    engine._endpoint_json = mock.Mock(
        side_effect=[
            {},
            {
                "family": 4,
                "source_mtu": 9000,
                "path_mtu": 1500,
                "tested_packet_size": 9000,
                "applicable": True,
                "capability": "supported",
                "fragmentation_permitted": {"counts": {"success": 3}},
                "source_fragment_counters": {
                    "before": {},
                    "after_permitted": {},
                },
            },
            {},
        ]
    )

    engine._run_fip_egress_fragmentation(_fragmentation_spec())

    fragmentation_args, fragmentation_kwargs = recorded[-1]
    assert fragmentation_args[2] == "PASS"
    assert fragmentation_kwargs["details"]["fragmentation_profile"]["capability"] == (
        "supported"
    )
    assert fragmentation_kwargs["details"]["mtu_test_id"] == _mtu_spec().id


def test_peer_identity_connect_failure_uses_one_flow():
    diagnostics = {
        "connected": False,
        "failure_phase": "connect",
        "error_type": "TimeoutError",
        "error": "timed out",
    }
    executor = mock.Mock(
        return_value=_completed(
            4,
            "NFLUX_TCP_PEER " + json.dumps(diagnostics, separators=(",", ":")),
        )
    )
    probe = TCPProbe(
        ProbeContext(
            endpoint_executor=lambda _endpoint, command: executor(command),
            controller_executor=executor,
            tcp_port=18080,
            udp_port=18081,
        )
    )

    result = probe.endpoint_peer_identity(
        endpoint("source", "A"), "192.0.2.10", "192.0.2.20", 4
    )

    assert result.outcome == "blocked"
    assert result.attempts == 1
    assert executor.call_count == 1
    assert result.diagnostics["stopped_after_first_pre_handshake_failure"] is True


def test_fip_failure_message_separates_failure_from_authority(
    config_factory,
):
    from ._evidence import configure_translation_target

    engine, _source, target, groups, records = _engine(config_factory)
    groups["target"].fips[target.label] = {
        "id": "fip-id",
        "address": "203.0.113.10",
    }
    configure_translation_target(engine, groups["target"], target)
    engine.builder.ensure_group_fips = mock.Mock()
    engine._address = lambda _group, _endpoint, _subnet: "192.0.2.20"
    engine.probes.runner_fip.run.return_value = (
        ProbeResult(
            outcome="blocked",
            success=False,
            elapsed_ms=5000,
            attempts=1,
            source_ip="10.0.3.107",
            destination_ip="203.0.113.10",
            protocol="tcp",
            diagnostics={"destination_port": 18080},
        ),
        True,
    )
    spec = _spec("fip-baseline", category="floating-ip")
    spec.metadata["target_external_cidr"] = "203.0.113.0/24"

    engine._run_fip_baseline(spec)

    recorded_spec, probe, _source, _target, kwargs = records[-1]
    assert recorded_spec.expectation == "observation"
    assert not recorded_spec.authoritative
    assert "upstream routing policy is unknown" in recorded_spec.expectation_reason
    assert kwargs["message"] is None
    assert probe.diagnostics["external_ingress_observation"]["outcome"] == "blocked"


def test_snat_profile_keeps_lower_mtu_advisory(config_factory):
    engine, provider, project, groups, _records = _engine(config_factory)
    _ready_packet_profile(engine, provider, project, groups)
    engine.probes.tcp.endpoint_peer_identity.return_value.diagnostics[
        "observed_peer_ip"
    ] = "203.0.113.1"
    engine._endpoint_json = mock.Mock(
        return_value={
            "reachable": True,
            "discovered_mtu": 1442,
            "discovery_confidence": "confirmed-lower-boundary",
            "expected_probe_classification": "packet-too-big",
            "reported_path_mtu": 1442,
            "path_boundary_confirmed": True,
        }
    )
    engine._network_router_backend_evidence = mock.Mock(return_value={})
    recorded = []
    engine.reporter = SimpleNamespace(
        result=lambda *args, **kwargs: recorded.append((args, kwargs))
    )
    spec = dataclasses.replace(
        _packet_size_spec(),
        operation="snat-packet-size-profile",
        category="source-nat-packet-size",
        expectation="profile-complete",
        metadata={
            "egress_translation_mode": "router-source-nat",
            "require_no_floating_ip": True,
        },
    )
    engine._run_snat_packet_size_profile(spec)
    args, kwargs = recorded[-1]
    assert args[2] == "PASS"
    assert kwargs["observed"] == "path-mtu-below-advertised"
    assert kwargs["details"]["health"] == "warning"
    assert "1442" in args[3] and "1500" in args[3]
