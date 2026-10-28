from __future__ import annotations

import contextlib
import dataclasses
import io
import json
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

from neutron_flux.models import ProbeResult
from neutron_flux.models import TestSpec as FluxTestSpec
from neutron_flux.mtu_contract import (
    classify_mtu_contract_probe,
    confirmed_fragmentation_path_mtu,
    confirmed_no_fragment_path_mtu,
)
from neutron_flux.mtu_probes import (
    BOUNDARY_RESULT_MARKER,
    boundary_probe_code,
    fragmentation_probe_code,
    parse_boundary_result,
    performance_probe_code,
)
from neutron_flux.performance import PerformanceRunner
from neutron_flux.policy import PolicyEvaluator


def _fake_subprocess(run):
    module = types.ModuleType("subprocess")
    module.PIPE = object()
    module.run = run
    return module


def _execute_generated(code: str, run) -> dict:
    original = sys.modules.get("subprocess")
    sys.modules["subprocess"] = _fake_subprocess(run)
    output = io.StringIO()
    try:
        with contextlib.redirect_stdout(output):
            exec(code, {})
    finally:
        if original is None:
            sys.modules.pop("subprocess", None)
        else:
            sys.modules["subprocess"] = original
    return parse_boundary_result(output.getvalue()) or json.loads(
        output.getvalue().splitlines()[-1]
    )


def _completed(returncode=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def _captured_mtu_feedback():
    return json.loads(
        (Path(__file__).parent / "fixtures/mtu_packet_too_big.json").read_text()
    )


@pytest.mark.parametrize("family", [4, 6])
def test_fresh_packet_too_big_then_cached_rejections_confirms_lower_boundary(
    family, config_factory
):
    captured = _captured_mtu_feedback()
    header = 28 if family == 4 else 48
    fresh = True

    def run(command, **_kwargs):
        nonlocal fresh
        assert command[0] == "ping"
        payload = int(command[command.index("-s") + 1])
        if payload + header <= 1442:
            return _completed(0, "1 packets transmitted, 1 received, 0% packet loss")
        if fresh:
            fresh = False
            if family == 4:
                return _completed(**captured["first_trial"])
            return _completed(
                1, "From 2001:db8::20 icmp_seq=1 Packet too big: mtu=1442\n"
            )
        return _completed(**captured["cached_trial"])

    result = _execute_generated(
        performance_probe_code("192.0.2.10", "192.0.2.20", family, 1500), run
    )
    assert result["expected_probe_classification"] == "packet-too-big"
    assert result["expected_trials"]["counts"] == {
        "packet-too-big": 1,
        "local-mtu-rejected": 2,
    }
    assert result["reported_path_mtu"] == result["discovered_mtu"] == 1442
    assert result["path_boundary_confirmed"] is True
    assert result["local_mtu_rejected"] is False
    assert result["packet_transmitted_at_expected_size"] is True
    classified = classify_mtu_contract_probe(
        result, expected_mtu=1500, contract_authoritative=True
    )
    assert classified["advertised_mtu_contract_status"] == "failed"
    assert classified["pmtud_status"] == "packet-too-big-received"
    assert confirmed_no_fragment_path_mtu(classified) == 1442
    assert confirmed_fragmentation_path_mtu(classified, 1500) == 1442
    assert (
        PerformanceRunner._mtu_health(
            {"forward": classified, "contract_authoritative": True}, 1500
        )
        == "warning"
    )

    # Exercise result recording as well as health classification: the measured
    # lower boundary must not become a failed validation at the reporting layer.
    from .test_mtu_fragmentation import _path

    runner = object.__new__(PerformanceRunner)
    runner.config = config_factory(action="run")
    recorded = []
    runner.reporter = SimpleNamespace(
        result=lambda *args, **kwargs: recorded.append((args, kwargs))
    )
    spec = FluxTestSpec(
        "MTU-OBSERVATION",
        "network-performance",
        "performance-mtu-mss",
        family,
        "packet-size-contract-assessed",
        "measure packet-size behavior",
        True,
        [],
        metadata={"performance_measurement": "mtu-mss"},
    )
    metrics = {
        "expected_mtu": 1500,
        "contract_authoritative": True,
        "forward": classified,
        "reverse": classified,
    }
    path = _path()
    path = dataclasses.replace(path, plan=dataclasses.replace(path.plan, family=family))
    runner._record_measurement(
        spec,
        path,
        {"health": runner._mtu_health(metrics, 1500), "metrics": metrics},
        started=0,
    )
    args, kwargs = recorded[-1]
    assert args[2] == "PASS"
    assert kwargs["details"]["health"] == "warning"
    assert "1442" in args[3] and "1500" in args[3]
    assert (
        kwargs["details"]["metrics"]["forward"]["advertised_mtu_contract_status"]
        == "failed"
    )


def test_boundary_preserves_network_feedback_before_local_sendmsg_error():
    captured = _captured_mtu_feedback()
    result = _execute_generated(
        boundary_probe_code("192.0.2.10", "192.0.2.20", 4, 1472),
        lambda *_args, **_kwargs: _completed(
            1, captured["first_trial"]["stdout"], captured["cached_trial"]["stderr"]
        ),
    )
    assert result["classification"] == "packet-too-big"
    assert result["packet_transmitted"] is True
    assert result["packet_too_big_feedback"][0]["mtu"] == 1442
    assert result["local_mtu_evidence"] is None


def test_packet_too_big_contract_failure_does_not_invent_exact_boundary():
    result = classify_mtu_contract_probe(
        {
            "expected_probe_classification": "packet-too-big",
            "reported_path_mtu": 1442,
            "discovery_confidence": "unstable",
            "discovered_mtu": None,
        },
        expected_mtu=1500,
        contract_authoritative=True,
    )
    assert result["advertised_mtu_contract_status"] == "failed"
    assert confirmed_no_fragment_path_mtu(result) is None
    assert confirmed_fragmentation_path_mtu(result, 1500) is None
    assert (
        "exact no-fragment path boundary remains unverified"
        in result["pmtud_explanation"]
    )
    assert (
        PerformanceRunner._mtu_health(
            {"forward": result, "contract_authoritative": True}, 1500
        )
        == "unverified"
    )
    unverified = classify_mtu_contract_probe(
        result, expected_mtu=1500, contract_authoritative=False
    )
    assert unverified["advertised_mtu_contract_status"] == "unverified"


def test_fragmentation_is_unknown_when_path_boundary_is_unknown():
    def run(*_args, **_kwargs):
        raise AssertionError(
            "An unconfirmed path boundary must not trigger packet probes"
        )

    result = _execute_generated(
        fragmentation_probe_code("192.0.2.10", "192.0.2.20", 4, 1500, None), run
    )
    assert result["capability"] == "unverified"
    assert result["applicable"] is None
    assert result["path_mtu"] is None
    assert "unknown" in result["reason"]


def test_boundary_probe_classifies_local_emsgsize_and_collects_evidence():
    def run(command, **_kwargs):
        if command[0] == "ping":
            return _completed(1, "", "ping: sendmsg: Message too long")
        if command[:5] == ["ip", "-4", "-j", "route", "get"]:
            return _completed(
                0,
                json.dumps(
                    [
                        {
                            "dst": "192.0.2.20",
                            "dev": "ens4",
                            "prefsrc": "192.0.2.10",
                            "mtu": 1424,
                        }
                    ]
                ),
            )
        if command[:4] == ["ip", "-j", "link", "show"]:
            return _completed(0, json.dumps([{"ifname": "ens4", "mtu": 1500}]))
        if command[:4] == ["ip", "-j", "address", "show"]:
            return _completed(
                0,
                json.dumps(
                    [
                        {
                            "ifname": "ens4",
                            "addr_info": [{"local": "192.0.2.10", "prefixlen": 24}],
                        }
                    ]
                ),
            )
        raise AssertionError(command)

    code = boundary_probe_code("192.0.2.10", "192.0.2.20", 4, 1472)
    original = sys.modules.get("subprocess")
    sys.modules["subprocess"] = _fake_subprocess(run)
    output = io.StringIO()
    try:
        with contextlib.redirect_stdout(output):
            exec(code, {})
    finally:
        if original is None:
            sys.modules.pop("subprocess", None)
        else:
            sys.modules["subprocess"] = original
    parsed = parse_boundary_result(output.getvalue())
    assert parsed is not None
    assert parsed["classification"] == "local-mtu-rejected"
    assert parsed["packet_transmitted"] is False
    evidence = parsed["local_mtu_evidence"]
    assert evidence["selected_interface"] == "ens4"
    assert evidence["source_interface_mtu"] == 1500
    assert evidence["route_mtu"] == 1424
    assert BOUNDARY_RESULT_MARKER in output.getvalue()


def test_expected_mtu_success_wins_without_binary_search():
    def run(command, **_kwargs):
        payload = int(command[command.index("-s") + 1])
        if payload <= 1472:
            return _completed(0, "1 packets transmitted, 1 received, 0% packet loss")
        return _completed(1, "", "ping: sendmsg: Message too long")

    result = _execute_generated(
        performance_probe_code("192.0.2.10", "192.0.2.20", 4, 1500), run
    )
    assert result["discovered_mtu"] == 1500
    assert result["discovery_confidence"] == "expected-confirmed"
    assert result["boundary_confirmed"] is True
    assert result["expected_size_reachable"] is True
    assert result["above_expected_reachable"] is False
    assert result["candidate_probes"] == []


def test_local_route_pmtu_is_not_a_confirmed_path_boundary():
    def run(command, **_kwargs):
        if command[0] == "ping":
            payload = int(command[command.index("-s") + 1])
            if payload <= 1396:
                return _completed(
                    0, "1 packets transmitted, 1 received, 0% packet loss"
                )
            return _completed(1, "", "ping: sendmsg: Message too long")
        if command[:5] == ["ip", "-4", "-j", "route", "get"]:
            return _completed(0, json.dumps([{"dev": "ens4", "mtu": 1424}]))
        if command[:4] == ["ip", "-j", "link", "show"]:
            return _completed(0, json.dumps([{"ifname": "ens4", "mtu": 1500}]))
        if command[:4] == ["ip", "-j", "address", "show"]:
            return _completed(0, json.dumps([{"ifname": "ens4", "addr_info": []}]))
        raise AssertionError(command)

    result = _execute_generated(
        performance_probe_code("192.0.2.10", "192.0.2.20", 4, 1500), run
    )
    assert result["discovered_payload"] == 1396
    assert result["discovered_mtu"] == 1424
    assert result["discovery_confidence"] == "cached-route-pmtu"
    assert result["expected_probe_classification"] == "local-mtu-rejected"
    assert result["boundary_confirmed"] is False
    assert result["path_boundary_confirmed"] is False
    assert result["local_boundary_confirmed"] is True
    assert result["local_constraint_classification"] == "cached-route-pmtu"
    confirmations = {
        (item["confirmation"], item["payload"], item["classification"])
        for item in result["candidate_probes"]
        if "confirmation" in item
    }
    assert ("lower", 1396, "success") in confirmations
    assert ("upper", 1397, "local-mtu-rejected") in confirmations


def test_mixed_expected_probe_is_unverified_not_exact_mtu(config_factory, tmp_path):
    expected_calls = 0

    def run(command, **_kwargs):
        nonlocal expected_calls
        payload = int(command[command.index("-s") + 1])
        if payload == 1472:
            expected_calls += 1
            if expected_calls == 2:
                return _completed(
                    1, "1 packets transmitted, 0 received, 100% packet loss"
                )
        return _completed(0, "1 packets transmitted, 1 received, 0% packet loss")

    result = _execute_generated(
        performance_probe_code("192.0.2.10", "192.0.2.20", 4, 1500), run
    )
    assert result["expected_probe_classification"] == "mixed"
    assert result["discovered_mtu"] is None
    assert result["discovery_confidence"] == "unstable"

    config = config_factory(action="run", report_dir=tmp_path / "reports")
    runner = PerformanceRunner(
        config, SimpleNamespace(), SimpleNamespace(), SimpleNamespace()
    )
    result.update(expected_max_mss=None, client_mss=None, server_mss=None)
    assert runner._mtu_health({"forward": result}, 1500) == "unverified"


def test_cached_route_pmtu_is_unverified_without_claiming_path_failure(
    config_factory, tmp_path
):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    runner = PerformanceRunner(
        config, SimpleNamespace(), SimpleNamespace(), SimpleNamespace()
    )
    item = {
        "reachable": True,
        "discovered_mtu": None,
        "discovery_confidence": "unstable",
        "discovery_reason": "candidate boundary was mixed",
        "expected_probe_classification": "local-mtu-rejected",
        "expected_max_mss": None,
        "client_mss": None,
        "server_mss": None,
        "local_mtu_evidence": {
            "selected_interface": "ens4",
            "source_interface_mtu": 1500,
            "route_mtu": 1424,
        },
    }
    assert runner._mtu_health({"forward": item}, 1500) == "unverified"
    reasons = runner._warning_reasons(
        "mtu-mss", {"expected_mtu": 1500, "forward": item}, "unverified"
    )
    assert any("cached per-destination route PMTU" in reason for reason in reasons)
    assert any(
        "current path MTU was not independently confirmed" in reason
        for reason in reasons
    )
    assert not any("advertised MTU contract failed" in reason for reason in reasons)


def test_udp_reordering_uses_percentage_and_context(config_factory, tmp_path):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    runner = PerformanceRunner(
        config, SimpleNamespace(), SimpleNamespace(), SimpleNamespace()
    )
    below = {
        "forward": [
            {
                "loss_pct": 0.0,
                "duplicates": 0,
                "out_of_order": 15,
                "received": 48821,
                "offered_mbps": 50,
                "packet_size": 128,
            }
        ],
        "reverse": [],
    }
    assert runner._udp_health(below) == "good"

    above = {
        "forward": [],
        "reverse": [
            {
                "loss_pct": 0.0,
                "duplicates": 0,
                "out_of_order": 15,
                "received": 10000,
                "offered_mbps": 50,
                "packet_size": 128,
            }
        ],
    }
    assert runner._udp_health(above) == "warning"
    reasons = runner._warning_reasons("udp", above, "warning")
    assert reasons == [
        "reverse UDP at 50 Mbit/s with 128-byte packets received 15 of 10000 "
        "unique packets out of order (0.150%), above advisory threshold 0.100%"
    ]


def test_policy_preserves_local_mtu_outcome_for_expected_rejection():
    spec = FluxTestSpec(
        id="MTU-LOCAL-LIMIT",
        category="mtu",
        operation="endpoint-probe",
        source_group_id="g",
        destination_group_id="g",
        source_side="A",
        destination_side="B",
        source_subnet_id="s",
        destination_subnet_id="s",
        family=4,
        protocol="mtu+1",
        expectation="blocked",
        expectation_reason="guest rejects oversized packet",
        authoritative=True,
        dependencies=[],
    )
    probe = ProbeResult(
        outcome="local-mtu-rejected",
        success=False,
        elapsed_ms=1,
        attempts=2,
        protocol="mtu+1",
    )
    decision = PolicyEvaluator().evaluate(spec, probe)
    assert decision.status == "PASS"
    assert decision.observed == "local-mtu-rejected"
