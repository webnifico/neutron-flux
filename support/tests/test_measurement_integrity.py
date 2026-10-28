from __future__ import annotations

import copy
import json
import subprocess
import time
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.comparison import _performance_metrics
from neutron_flux.concurrent_load import ConcurrentLoadRunner
from neutron_flux.engine_handlers.packet_size import PacketSizeProfileHandlerMixin
from neutron_flux.execution.placement_migration import PlacementMigrationMixin
from neutron_flux.models import ProbeResult
from neutron_flux.models import TestSpec as FluxTestSpec
from neutron_flux.mtu_contract import (
    classify_mtu_contract_probe,
    confirmed_no_fragment_path_mtu,
    local_mtu_constraint,
)
from neutron_flux.offline_reports import _apply_current_offline_interpretations
from neutron_flux.performance import PerformanceRunner
from neutron_flux.performance_results import _performance_result_summary
from neutron_flux.probe_service import ProbeServiceManager
from neutron_flux.probes import ProbeContext, TCPProbe
from neutron_flux.reporting_components.dashboard_model import _measurement_summary
from neutron_flux.reporting_components.html import _performance_summary
from neutron_flux.resources import ResourceBuilder
from neutron_flux.result_contract import normalize_result_record, packet_size_accounting
from neutron_flux.result_contract_compatibility import (
    _legacy_component_contracts,
    _legacy_packet_size_accounting,
    _legacy_packet_size_context,
    openstack_objects,
)

from ._shared import endpoint
from .test_engine_handlers import _engine


def _completed(returncode: int, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess(["probe"], returncode, stdout, stderr)


def _tcp_stdout(*, connected: bool, phase: str | None = None) -> str:
    return "NFLUX_TCP " + json.dumps(
        {
            "connected": connected,
            "token_sent": connected,
            "echo_received": phase is None,
            "echo_validated": phase is None,
            "failure_phase": phase,
            "error_type": "TimeoutError" if phase else None,
            "error": "timed out" if phase else None,
        },
        separators=(",", ":"),
    )


def _packet_size_spec() -> FluxTestSpec:
    return FluxTestSpec(
        id="SAMPLE-FIP-EGRESS-SOURCE-ADDRESS",
        category="floating-ip-egress-source-address",
        operation="fip-egress-source-address",
        family=4,
        expectation="provider-observes-floating-ip",
        expectation_reason="verify the outbound floating-IP source address",
        authoritative=True,
        dependencies=["target", "source"],
        source_group_id="target",
        destination_group_id="source",
        source_side="B",
        destination_side="A",
        source_subnet_id="subnet",
        destination_subnet_id="subnet",
        protocol="tcp",
        metadata={
            "egress_translation_mode": "floating-ip-egress",
            "require_floating_ip": True,
        },
    )


def _contract_result(*, details: dict | None = None) -> dict:
    return {
        "test_id": "SAMPLE-CONTRACT-COMPATIBILITY",
        "display_name": "Contract compatibility",
        "category": "network",
        "scenario": "Contract compatibility",
        "status": "PASS",
        "family": 4,
        "source": "az1/source (192.0.2.10)",
        "destination": "az1/destination (192.0.2.11)",
        "message": "The selected path was reachable.",
        "details": details or {},
        "expected": "reachable",
        "observed": "reachable",
        "authoritative": True,
    }


def _cached_pmtu_result() -> dict:
    classified = classify_mtu_contract_probe(
        {
            "reachable": True,
            "discovered_mtu": 1424,
            "discovery_confidence": "confirmed-lower-boundary",
            "expected_probe_classification": "local-mtu-rejected",
            "path_boundary_confirmed": False,
            "local_mtu_evidence": {
                "selected_interface": "ens4",
                "source_interface_mtu": 1500,
                "route": {"metrics": [{"mtu": 1424}]},
            },
            "pmtud_status": "protective-local-route-pmtu-enforcement",
            "fragmentation": {"capability": "unverified"},
            "client_mss": 1372,
            "server_mss": 1372,
        },
        expected_mtu=1500,
        contract_authoritative=True,
    )
    return {
        "test_id": "SAMPLE-CACHED-PMTU-COMPATIBILITY-MTU-MSS",
        "display_name": "Path MTU, PMTUD, and TCP MSS",
        "category": "network-performance",
        "scenario": "Network path performance",
        "status": "UNVERIFIED",
        "family": 4,
        "source": "az1/source (192.0.2.10)",
        "destination": "az1/destination (192.0.2.11)",
        "message": "A cached route PMTU constrained the source locally.",
        "details": {
            "performance": True,
            "measurement": "mtu-mss",
            "health": "unverified",
            "thresholds_enforced": False,
            "metrics": {
                "expected_mtu": 1500,
                "contract_authoritative": True,
                "forward": classified,
            },
        },
        "expected": "packet-size-contract-assessed",
        "observed": "packet-size-contract-unverified",
        "authoritative": True,
    }


def test_sender_limited_udp_is_unverified_and_extrema_keep_context():
    runner = object.__new__(PerformanceRunner)
    runner.config = SimpleNamespace(
        performance_udp_sender_achievement_threshold_pct=90.0,
        performance_udp_loss_threshold_pct=1.0,
        performance_udp_reordering_threshold_pct=0.1,
    )
    metrics = {
        "forward": [
            {
                "requested_mbps": 50,
                "sender_mbps": 20,
                "receiver_goodput_mbps": 20,
                "sender_achievement_pct": 40.0,
                "delivery_pct": 100.0,
                "load_valid": False,
                "loss_pct": 0.0,
                "jitter_ms": 0.02,
                "pps": 19000,
                "packet_size": 128,
            },
            {
                "requested_mbps": 10,
                "sender_mbps": 10,
                "receiver_goodput_mbps": 9.5,
                "sender_achievement_pct": 100.0,
                "delivery_pct": 95.0,
                "load_valid": True,
                "loss_pct": 5.0,
                "jitter_ms": 0.30,
                "pps": 980,
                "packet_size": 1200,
            },
        ],
        "reverse": [],
    }

    assert runner._udp_health(metrics) == "unverified"
    summary = _performance_result_summary("udp", metrics)
    assert (
        "application loss 5.00% (forward, 10 Mbit/s requested, 1200-byte datagrams)"
        in summary
    )
    assert (
        "jitter 0.300 ms (forward, 10 Mbit/s requested, 1200-byte datagrams)" in summary
    )
    assert (
        "minimum sender achievement 40.0% (forward, 50 Mbit/s requested, 128-byte datagrams)"
        in summary
    )


def test_concurrent_load_keeps_icmp_udp_and_pair_context_separate():
    pairs = [
        {
            "pair_index": 1,
            "source_host": "compute1",
            "destination_host": "compute2",
            "placement": "cross-compute",
            "source_availability_zone": "az1",
            "destination_availability_zone": "az1",
        },
        {
            "pair_index": 2,
            "source_host": "compute3",
            "destination_host": "compute4",
            "placement": "cross-compute",
            "source_availability_zone": "az1",
            "destination_availability_zone": "az1",
        },
    ]
    runs = [
        {
            "aggregate_mbps": 1800.0,
            "median_pair_mbps": 900.0,
            "slowest_pair_mbps": 850.0,
            "fairness": 0.99,
            "idle_latency_by_pair": [
                {"pair_index": 1, "p95_ms": 0.5, "loss_pct": 0.0},
                {"pair_index": 2, "p95_ms": 0.6, "loss_pct": 0.0},
            ],
            "loaded_latency_by_pair": [
                {"pair_index": 1, "p95_ms": 1.0, "loss_pct": 2.0},
                {"pair_index": 2, "p95_ms": 1.2, "loss_pct": 0.0},
            ],
            "loaded_latency_ratios_by_pair": [
                {"pair_index": 1, "ratio": 2.0},
                {"pair_index": 2, "ratio": 2.0},
            ],
            "loaded_udp_by_pair": [
                {
                    "pair_index": 1,
                    "loss_pct": 0.0,
                    "jitter_ms": 0.1,
                    "requested_mbps": 50,
                    "packet_size": 128,
                    "sender_achievement_pct": 50.0,
                    "sender_achievement_threshold_pct": 90.0,
                    "load_valid": False,
                },
                {
                    "pair_index": 2,
                    "loss_pct": 4.0,
                    "jitter_ms": 0.4,
                    "requested_mbps": 10,
                    "packet_size": 1200,
                    "sender_achievement_pct": 100.0,
                    "load_valid": True,
                },
            ],
            "loaded_tcp_aggregate_mbps": 1600.0,
            "retransmissions": 2,
            "loaded_retransmissions": 3,
        }
    ]

    summary = ConcurrentLoadRunner._summarize_level(2, pairs, runs)

    assert summary["maximum_loaded_icmp_loss_pct"] == 2.0
    assert summary["maximum_loaded_udp_application_loss_pct"] == 4.0
    assert "maximum_loaded_loss_pct" not in summary
    assert summary["worst_loaded_icmp_context"]["pair_index"] == 1
    assert summary["worst_loaded_udp_loss_context"]["pair_index"] == 2
    assert summary["udp_sender_limited_samples"] == 1
    assert summary["minimum_udp_sender_achievement_pct"] == 50.0


def test_tcp_fresh_flow_confirmation_distinguishes_transient_failure():
    responses = iter(
        [
            _completed(
                1, _tcp_stdout(connected=True, phase="receive-echo"), "timed out"
            ),
            _completed(0, _tcp_stdout(connected=True)),
            _completed(0, _tcp_stdout(connected=True)),
        ]
    )
    probe = TCPProbe(
        ProbeContext(
            endpoint_executor=lambda _endpoint, _command: next(responses),
            controller_executor=lambda _command: next(responses),
            tcp_port=18080,
            udp_port=18081,
        )
    )

    result = probe.endpoint(endpoint(), "192.0.2.10", "192.0.2.20", 4)

    assert result.outcome == "inconclusive"
    assert result.attempts == 3
    assert result.diagnostics["confirmation_attempts"] == 2
    assert result.diagnostics["transient_first_attempt_failure"] is True
    assert (
        result.diagnostics["attempt_evidence"][0]["diagnostics"]["failure_phase"]
        == "receive-echo"
    )


def test_tcp_connect_failure_stops_after_first_flow():
    response = _completed(
        1,
        _tcp_stdout(connected=False, phase="connect"),
        "TimeoutError: timed out",
    )
    executor = mock.Mock(return_value=response)
    probe = TCPProbe(
        ProbeContext(
            endpoint_executor=lambda _endpoint, command: executor(command),
            controller_executor=executor,
            tcp_port=18080,
            udp_port=18081,
        )
    )

    result = probe.endpoint(endpoint(), "192.0.2.10", "192.0.2.20", 4)

    assert result.outcome == "blocked"
    assert result.attempts == 1
    assert executor.call_count == 1
    assert result.diagnostics["stopped_after_first_pre_handshake_failure"] is True
    assert all(
        row["diagnostics"]["failure_phase"] == "connect"
        for row in result.diagnostics["attempt_evidence"]
    )


def test_live_continuity_observes_declared_loss_limit_when_migration_succeeds():
    from ._evidence import complete_continuity

    continuity = complete_continuity(icmp_loss=1.0, icmp_limit=0.0)
    status, observed, message, details = (
        PlacementMigrationMixin._live_continuity_verdict(continuity)
    )
    assert status == "PASS"
    assert observed == "traffic-continuity-measured"
    assert "ICMP failed observations 1.00% exceeded 0.00%" in message
    assert details["continuity_failure_reasons"] == []
    assert details["interruption_observations"] == details["tolerance_failure_reasons"]
    assert details["migration_outcomes"]["interruption_tolerance"] == "OBSERVATION"
    assert details["health"] == "warning"
    assert not details["continuity_advisories"]


def test_live_continuity_finalization_time_does_not_inflate_sample_contract(
    config_factory,
):
    payload = {
        "duration_s": 20.0,
        "observation_duration_s": 1.0,
        "sample_interval_s": 0.25,
        "probe_deadline_s": 0.20,
        "readiness": {"ready": True},
        "icmp": [
            {
                "sequence": index,
                "scheduled_t": index * 0.25,
                "ok": True,
                "late_by_s": 0.0,
            }
            for index in range(4)
        ],
        "tcp": {"connected": True, "survived": True},
        "udp": {"sent": 10, "response": {"loss_pct": 0.0}},
    }
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder.ssh_endpoint = mock.Mock(return_value=_completed(0, json.dumps(payload)))
    state = {
        "available": True,
        "stop_path": "/tmp/stop",
        "result_path": "/tmp/result",
        "error_path": "/tmp/error",
        "pid": "123",
        "started_at": time.monotonic() - 1.0,
    }

    result = builder._stop_live_continuity(endpoint(), state)

    assert result["duration_s"] == 20.0
    assert result["observation_duration_s"] == 1.0
    assert result["expected_icmp_samples"] == 3
    assert result["sampling_complete"] is True
    assert result["full_migration_window"] is True


def test_live_continuity_rejects_duplicate_or_missing_sequence_evidence(
    config_factory,
):
    payload = {
        "duration_s": 1.0,
        "observation_duration_s": 1.0,
        "sample_interval_s": 0.25,
        "probe_deadline_s": 0.20,
        "readiness": {"ready": True},
        "icmp": [
            {"sequence": 0, "scheduled_t": 0.0, "ok": True, "late_by_s": 0.0},
            {"sequence": 0, "scheduled_t": 0.25, "ok": True, "late_by_s": 0.0},
            {"sequence": 2, "scheduled_t": 0.50, "ok": True, "late_by_s": 0.0},
            {"sequence": 3, "scheduled_t": 0.75, "ok": True, "late_by_s": 0.0},
        ],
        "tcp": {"connected": True, "survived": True},
        "udp": {"sent": 10, "response": {"loss_pct": 0.0}},
    }
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder.ssh_endpoint = mock.Mock(return_value=_completed(0, json.dumps(payload)))
    state = {
        "available": True,
        "stop_path": "/tmp/stop",
        "result_path": "/tmp/result",
        "error_path": "/tmp/error",
        "pid": "123",
        "started_at": time.monotonic() - 1.0,
    }

    result = builder._stop_live_continuity(endpoint(), state)

    assert result["sampling_complete"] is False
    assert any("sequence evidence" in row for row in result["warnings"])


def test_cached_route_pmtu_is_never_exported_as_confirmed_path_mtu():
    classified = classify_mtu_contract_probe(
        {
            "reachable": True,
            "discovered_mtu": 1424,
            "discovery_confidence": "confirmed-lower-boundary",
            "expected_probe_classification": "local-mtu-rejected",
            "path_boundary_confirmed": False,
            "local_mtu_evidence": {
                "selected_interface": "ens4",
                "source_interface_mtu": 1500,
                "route": {"metrics": [{"mtu": 1424}]},
            },
        },
        expected_mtu=1500,
        contract_authoritative=True,
    )

    assert classified["advertised_mtu_contract_status"] == "unverified"
    assert classified["local_constraint_classification"] == "cached-route-pmtu"
    assert confirmed_no_fragment_path_mtu(classified) is None
    assert local_mtu_constraint(classified) == (1424, "cached-route-pmtu")

    result = {
        "status": "UNVERIFIED",
        "details": {
            "measurement": "mtu-mss",
            "metrics": {"expected_mtu": 1500, "forward": classified},
        },
    }
    dashboard = _measurement_summary(result)
    assert dashboard is not None
    assert dashboard["values"]["forward_discovered_mtu"] is None
    assert dashboard["values"]["forward_local_constraint_mtu"] == 1424.0
    assert _performance_metrics(result)["forward_discovered_mtu"][0] is None

    accounting = packet_size_accounting(result["details"], family=4)
    direction = accounting["directions"]["forward"]
    assert direction["confirmed_no_fragment_ip_packet_bytes"] is None
    assert direction["local_constraint_ip_packet_bytes"] == 1424
    assert "confirmed no-fragment path MTU 1424" not in _performance_result_summary(
        "mtu-mss", result["details"]["metrics"]
    )

    summary = _performance_summary([result])
    assert summary["mtu_mismatch_paths"] == 0


def test_post_migration_cached_pmtu_remains_a_local_constraint(monkeypatch):
    runner = object.__new__(PerformanceRunner)
    runner.config = SimpleNamespace(convergence_interval=0)
    path = SimpleNamespace(
        plan=SimpleNamespace(stage="post-live-migration-intra-compute", family=4),
        expected_mtu=1500,
        mtu_contract={"authoritative": True},
    )
    raw = {
        "reachable": True,
        "discovered_mtu": 1424,
        "discovery_confidence": "confirmed-lower-boundary",
        "expected_probe_classification": "local-mtu-rejected",
        "path_boundary_confirmed": False,
        "local_mtu_evidence": {
            "selected_interface": "ens4",
            "source_interface_mtu": 1500,
            "route": {"metrics": [{"mtu": 1424}]},
        },
    }
    initial = classify_mtu_contract_probe(
        raw,
        expected_mtu=1500,
        contract_authoritative=True,
    )
    runner._mtu_probe = mock.Mock(return_value=raw)
    monkeypatch.setattr(
        "neutron_flux.performance_measurements.time.sleep",
        lambda _seconds: None,
    )

    settled = runner._post_migration_mtu_settlement(
        path,
        initial,
        source=endpoint(),
        source_ip="192.0.2.10",
        destination_ip="192.0.2.11",
    )

    persistence = settled["post_migration_persistence"]
    assert persistence["classification"] == "persistent-cached-route-pmtu"
    assert persistence["initial_observed_mtu"] == 1424
    assert persistence["settled_observed_mtu"] == 1424
    assert persistence["initial_boundary_mtu"] is None
    assert persistence["settled_boundary_mtu"] is None
    assert persistence["initial_local_constraint"] == "cached-route-pmtu"


def test_udp_receiver_drop_telemetry_declares_shared_counter_scope():
    code = ProbeServiceManager(18080, 18081)._server_code(endpoint())

    assert "receiver_kernel_udp_counter_scope" in code
    assert "receiver_socket_rxq_overflow_scope" in code
    assert "shared-probe-socket-cumulative-delta" in code
    assert "shared-receiver-socket-and-guest-wide-kernel-counters" in code
    assert "/proc/net/snmp6" in code


def test_provider_observer_control_failure_is_unverified_and_skips_project_profile(
    config_factory,
):
    engine, provider, project, groups, _records = _engine(config_factory)
    groups["target"].source_nat_enabled = True
    groups["target"].fips[project.label] = {
        "id": "fip-id",
        "address": "203.0.113.10",
    }
    engine.lifecycle["fip:target"] = {"address": "203.0.113.10"}
    engine.builder.capture_router_state = mock.Mock(
        return_value={
            "external_gateway_info": {
                "enable_snat": True,
                "external_fixed_ips": [{"ip_address": "203.0.113.1"}],
            }
        }
    )
    provider.metadata["probe_service"] = {"ready": True, "tcp_port": 18080}
    alternate = copy.deepcopy(provider)
    alternate.server_id = "server-provider-control"
    alternate.label = "provider-control"
    alternate.fixed_ips = {"subnet": "192.0.2.11"}
    alternate.side = "B"
    groups["source"].endpoints.append(alternate)

    def endpoint_address(group_id, side, _subnet_id):
        if group_id == "source":
            return (
                (alternate, "192.0.2.11") if side == "B" else (provider, "192.0.2.10")
            )
        return project, "192.0.2.20"

    engine._endpoint_address = endpoint_address
    engine.probes.tcp.endpoint_port.return_value = ProbeResult(
        outcome="blocked",
        success=False,
        elapsed_ms=5,
        attempts=3,
        stderr="timed out",
    )
    engine._endpoint_json = mock.Mock()
    engine.diagnostics = SimpleNamespace(collect=mock.Mock())
    recorded: list[tuple[tuple, dict]] = []
    engine.reporter = SimpleNamespace(
        result=lambda *args, **kwargs: recorded.append((args, kwargs))
    )

    engine._run_fip_egress_source_address(_packet_size_spec())

    args, kwargs = recorded[-1]
    assert args[2] == "UNVERIFIED"
    assert kwargs["observed"] == "provider-observer-control-failed"
    assert engine.probes.tcp.endpoint_port.call_count == 1
    engine.probes.tcp.endpoint_peer_identity.assert_not_called()
    engine._endpoint_json.assert_not_called()


def test_floating_ip_restore_uses_openstack_readback_not_command_rc(
    config_factory,
):
    engine, _provider, _project, _groups, _records = _engine(config_factory)
    engine.builder.osc.run.side_effect = [
        _completed(1, stderr="CLI returned non-zero after request"),
        _completed(1, stderr="CLI returned non-zero after request"),
    ]
    engine.builder.wait_floating_ip_association = mock.Mock(
        side_effect=[
            {"matched": True, "port_id": None},
            {
                "matched": True,
                "port_id": "port-id",
                "fixed_ip_address": "192.0.2.20",
            },
        ]
    )
    state = {
        "id": "fip-id",
        "address": "203.0.113.10",
        "port_id": "port-id",
        "fixed_ip": "192.0.2.20",
    }

    cloud_operation = PacketSizeProfileHandlerMixin._detach_floating_ip_for_profile(
        engine, state
    )
    assert cloud_operation["detach_command_returncode"] == 1
    assert cloud_operation["detached"] is True

    PacketSizeProfileHandlerMixin._restore_floating_ip_after_profile(
        engine, cloud_operation
    )
    assert cloud_operation["restore_command_returncode"] == 1
    assert cloud_operation["restored"] is True


def test_legacy_combined_loaded_loss_is_udp_fallback_only():
    summary = _performance_summary(
        [
            {
                "status": "PASS",
                "details": {
                    "measurement": "concurrent-path-load",
                    "metrics": {
                        "levels": [
                            {
                                "pairs": 2,
                                "maximum_loaded_loss_pct": 7.5,
                            }
                        ]
                    },
                },
            }
        ]
    )

    assert summary["concurrent_load_worst_loaded_udp_application_loss_pct"] == 7.5
    assert summary["concurrent_load_worst_loaded_icmp_loss_pct"] is None


def test_historical_openstack_evidence_path_is_canonicalized_only_for_same_object():
    details = {
        "network_id": "network-id",
        "nested": {"network_id": "network-id"},
    }
    baseline = normalize_result_record(_contract_result(details=details))
    supplied = _contract_result(details=copy.deepcopy(details))
    supplied["contract"] = copy.deepcopy(baseline["contract"])
    generated_path = supplied["contract"]["expectation"]["openstack_objects"][0][
        "evidence_path"
    ]
    alternate_path = (
        "details.nested.network_id"
        if generated_path == "details.network_id"
        else "details.network_id"
    )
    supplied["contract"]["expectation"]["openstack_objects"][0]["evidence_path"] = (
        alternate_path
    )

    assert normalize_result_record(supplied) == baseline

    arbitrary = copy.deepcopy(supplied)
    arbitrary["contract"]["expectation"]["openstack_objects"][0]["evidence_path"] = (
        "details.unrelated.network_id"
    )
    with pytest.raises(ValueError, match="openstack_objects.*contradicts"):
        normalize_result_record(arbitrary)

    changed_id = copy.deepcopy(supplied)
    changed_id["contract"]["expectation"]["openstack_objects"][0]["id"] = (
        "different-network-id"
    )
    with pytest.raises(ValueError, match="openstack_objects.*contradicts"):
        normalize_result_record(changed_id)


def test_openstack_object_projection_is_deterministic_across_mapping_order():
    first = {
        "network_id": "network-id",
        "router_id": "router-id",
        "nested": {"network_id": "network-id"},
    }
    second = {
        "nested": {"network_id": "network-id"},
        "router_id": "router-id",
        "network_id": "network-id",
    }

    assert openstack_objects(first) == openstack_objects(second)


def test_exact_legacy_cached_pmtu_contract_is_upgraded_without_accepting_overrides():
    item = _cached_pmtu_result()
    baseline = normalize_result_record(item)
    legacy = copy.deepcopy(item)
    legacy["contract"] = copy.deepcopy(baseline["contract"])
    legacy["contract"]["components"] = _legacy_component_contracts(
        contract_type=baseline["contract"]["type"],
        status=item["status"],
        details=item["details"],
        family=4,
    )
    legacy["contract"]["packet_size"] = _legacy_packet_size_accounting(
        item["details"], family=4
    )
    legacy["path_signature"] = copy.deepcopy(baseline["path_signature"])
    legacy["path_signature"]["context"]["packet_size"] = _legacy_packet_size_context(
        item["details"], family=4
    )

    assert legacy["contract"]["packet_size"] != baseline["contract"]["packet_size"]
    assert normalize_result_record(legacy) == baseline

    override = copy.deepcopy(baseline)
    override["contract"]["packet_size"]["directions"]["forward"][
        "local_constraint_ip_packet_bytes"
    ] = 1400
    with pytest.raises(ValueError, match="contract.*contradicts"):
        normalize_result_record(override)


@pytest.mark.parametrize(
    ("measurement", "expected", "observed", "legacy_description"),
    [
        (
            "udp",
            "udp-quality-profile-recorded",
            "udp-quality-profile-measured",
            "Record offered and achieved UDP rate, packet rate, loss, jitter, "
            "duplicates, and reordering for every requested packet size and direction.",
        ),
        (
            "asymmetry",
            "directional-balance-assessed",
            "directional-balance-measured",
            "Compare forward and reverse throughput, latency, and UDP loss without "
            "assuming that directional differences identify an infrastructure cause.",
        ),
    ],
)
def test_exact_legacy_expectation_descriptions_are_upgraded_only_when_known(
    measurement, expected, observed, legacy_description
):
    item = _contract_result(
        details={
            "performance": True,
            "measurement": measurement,
            "health": "good",
            "metrics": {},
        }
    )
    item.update(
        {
            "category": "network-performance",
            "expected": expected,
            "observed": observed,
            "message": "Historical measurement evidence was recorded.",
        }
    )
    baseline = normalize_result_record(item)
    historical = copy.deepcopy(item)
    historical["contract"] = copy.deepcopy(baseline["contract"])
    historical["contract"]["expectation"]["description"] = legacy_description

    assert normalize_result_record(historical) == baseline

    tampered = copy.deepcopy(historical)
    tampered["contract"]["expectation"]["description"] = (
        "Operator-supplied replacement description."
    )
    with pytest.raises(ValueError, match="expectation.description.*contradicts"):
        normalize_result_record(tampered)


def test_offline_report_preserves_historical_verdict_but_relabels_cached_pmtu():
    item = _cached_pmtu_result()
    item["status"] = "FAIL"
    item["observed"] = "packet-size-contract-violated"
    item["message"] = (
        "forward confirmed no-fragment MTU 1424 bytes; advertised MTU contract failed"
    )
    forward = item["details"]["metrics"]["forward"]
    forward["discovery_confidence"] = "confirmed-lower-boundary"
    forward["path_boundary_confirmed"] = False
    payload = {"results": [normalize_result_record(item)]}

    _apply_current_offline_interpretations(payload)

    result = payload["results"][0]
    assert result["status"] == "FAIL"
    assert "Historical FAIL verdict retained" in result["message"]
    assert "Current interpretation (UNVERIFIED)" in result["message"]
    assert "cached route PMTU 1424 bytes" in result["message"]
    assert "current path boundary unverified" in result["message"]
    assert result["details"]["offline_interpretation"]["verdict_rewritten"] is False


def test_offline_interpretation_does_not_rewrite_current_udp_semantics():
    item = _contract_result(
        details={
            "performance": True,
            "measurement": "udp",
            "health": "good",
            "metrics": {
                "forward": [
                    {
                        "requested_mbps": 10.0,
                        "sender_mbps": 10.0,
                        "receiver_goodput_mbps": 10.0,
                        "sender_achievement_pct": 100.0,
                        "delivery_pct": 100.0,
                        "loss_pct": 0.0,
                        "jitter_ms": 0.1,
                        "pps": 1000,
                        "packet_size": 1200,
                    }
                ],
                "reverse": [],
            },
        }
    )
    item.update(
        {
            "category": "network-performance",
            "expected": "udp-quality-profile-recorded",
            "observed": "udp-quality-profile-measured",
            "message": (
                "application loss 0.00% (forward, 10 Mbit/s requested, "
                "1200-byte datagrams)"
            ),
        }
    )
    normalized = normalize_result_record(item)
    payload = {"results": [copy.deepcopy(normalized)]}

    _apply_current_offline_interpretations(payload)

    assert payload["results"] == [normalized]
