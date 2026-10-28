from __future__ import annotations

import dataclasses

import pytest

from neutron_flux.operator_explanations import explain_result
from neutron_flux.test_names import test_name as name_for_test

from .test_performance_and_html import _resolved_path
from .test_udp_receiver import _measurement, _runner


@pytest.mark.parametrize("family", [4, 6])
def test_udp_comparison_remeasures_both_directions_at_one_sustainable_rate(
    config_factory, family
):
    runner = _runner(config_factory)
    runner.config.performance_udp_rates_mbps = [10]
    path = _resolved_path()
    path = dataclasses.replace(path, plan=dataclasses.replace(path.plan, family=family))
    calls = []

    def measure(_ep, source, _destination, _family, rate, size, **_kw):
        calls.append((source, rate, size))
        ceiling = 5 if source == path.forward_source_ip else 2
        return _measurement(rate, limited=rate > ceiling)

    runner._udp_measurement = measure
    metrics = runner._udp_matrix(path)
    comparison = metrics["comparison"]
    assert comparison["incomplete_profiles"] == 0
    assert {row["requested_mbps"] for row in comparison["forward"]} == {2}
    assert {row["requested_mbps"] for row in comparison["reverse"]} == {2}
    assert any(
        row["requested_mbps"] == 5 and row["calibration_selected"]
        for row in metrics["forward"]
    )
    assert (
        len(calls)
        <= 2
        * comparison["requested_profiles"]
        * runner.config.performance_udp_calibration_max_attempts
        * 2
    )
    tcp = {"streams": {"1": {"median_mbps": 100}}}
    result = runner._asymmetry(
        tcp, tcp, {"forward": {"p95_ms": 1}, "reverse": {"p95_ms": 1}}, metrics
    )
    assert (
        result["health"]
        == result["tcp_health"]
        == result["latency_health"]
        == result["udp_health"]
        == "good"
    )


def test_incomplete_udp_never_erases_valid_tcp_and_latency_conclusions(config_factory):
    runner = _runner(config_factory)
    runner.config.performance_udp_rates_mbps = [10]
    runner._udp_measurement = lambda *_args, **_kw: {"mbps": 0, "loss_pct": 0}
    metrics = runner._udp_matrix(_resolved_path())
    assert (
        metrics["comparison"]["incomplete_profiles"]
        == metrics["comparison"]["requested_profiles"]
    )
    tcp = {"streams": {"1": {"median_mbps": 100}}}
    result = runner._asymmetry(
        tcp, tcp, {"forward": {"p95_ms": 1}, "reverse": {"p95_ms": 1}}, metrics
    )
    assert result["health"] == result["udp_health"] == "unverified"
    assert result["tcp_health"] == result["latency_health"] == "good"


def test_passing_advisory_is_visible_without_changing_verdict():
    result = {
        "status": "PASS",
        "message": "reachable",
        "details": {"warning_reasons": ["A transient interruption recovered."]},
    }
    story = explain_result(result)
    assert story["attention"] is True
    assert story["warnings"] == result["details"]["warning_reasons"]
    assert result["status"] == "PASS"


@pytest.mark.parametrize(
    "title,expected",
    [
        (
            "Floating-IP outbound source-address verification through Public1",
            "Verify outbound traffic uses the floating IP",
        ),
        (
            "Representative stop test VM and verify service loss — project A",
            "Verify TCP service stops when the VM stops",
        ),
        (
            "Representative start test VM and verify service recovery — project B",
            "Verify TCP service returns when the VM starts",
        ),
    ],
)
def test_shared_names_describe_actions_not_endpoints(title, expected):
    assert name_for_test({"display_name": title}) == expected
