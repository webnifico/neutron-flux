"""Human measurement and advisory summaries, including older evidence formats."""

from __future__ import annotations

import copy

import pytest

from neutron_flux.operator_explanations import explain_result, operator_overview
from support.tests.test_operator_reporting import _readable_flow
from support.tests.test_report_workflow import _payload
from support.tests.test_translated_migration_reporting import _observation_pass


def _udp_quality_sample(**overrides):
    return {
        "packet_size": 128,
        "configured_rate_mbps": 10,
        "offered_mbps": 10,
        "sender_mbps": 9.99,
        "receiver_goodput_mbps": 9.98,
        "pps": 9746.5,
        "jitter_ms": 0.007,
        "loss_pct": 0.0,
        "out_of_order": 0,
        "load_valid": True,
        "endpoint_limited": False,
        "calibration_selected": True,
        **overrides,
    }


def test_udp_primary_result_has_rate_packet_size_loss_goodput_jitter_and_packet_rate():
    result = _readable_flow(
        "", "network-performance", "profile-recorded", "profile-measured"
    )
    result["details"].update(
        measurement="udp",
        thresholds_enforced=False,
        metrics={
            "forward": [_udp_quality_sample()],
            "reverse": [
                _udp_quality_sample(
                    offered_mbps=5, receiver_goodput_mbps=4.98, pps=4880
                )
            ],
        },
    )
    story = explain_result(result)
    assert (
        "Source → destination, UDP payload size 128 bytes, test rate 10 Mbps"
        in story["observed"]
    )
    assert "receiver delivered 9.98 Mbps at 9,746.5 packets/s" in story["observed"]
    assert "packet arrival timing 0.007 ms" in story["observed"]
    assert "application loss 0 %" in story["observed"]
    assert "reduced from requested 10 Mbps" in story["observed"]
    assert "Destination → source" in story["observed"]
    assert "Observation:" not in story["observed"]


@pytest.mark.parametrize(
    "health,has_warning", [("good", True), ("warning", True), ("good", False)]
)
def test_receiver_limit_is_primary_context_and_never_hidden_by_zero_loss(
    health, has_warning
):
    result = _readable_flow(
        "", "network-performance", "profile-recorded", "profile-measured"
    )
    result["details"].update(
        measurement="udp",
        health=health,
        thresholds_enforced=False,
        warning_reasons=[
            "UDP reverse 10 Mbit/s with 128-byte datagrams was endpoint-limited (receiver-overload); calibrated sustainable rate 5 Mbit/s; endpoint-limited samples were excluded from network-loss grading"
        ],
        metrics={
            "reverse": [
                _udp_quality_sample(
                    endpoint_limited=True,
                    load_valid=False,
                    calibration_selected=False,
                    endpoint_limit_reason="receiver-overload",
                    loss_pct=0.5,
                ),
                _udp_quality_sample(offered_mbps=5, receiver_goodput_mbps=5, pps=4883),
            ]
        },
    )
    if not has_warning:
        result["details"]["warning_reasons"] = []
    original = copy.deepcopy(result)
    story = explain_result(result)
    assert "receiving VM could not sustain the requested rate" in story["headline"]
    assert (
        "Destination → source, UDP payload size 128 bytes at 10 Mbps"
        in story["observed"]
    )
    assert "source VM could not keep up" in story["observed"]
    assert "usable retry ran at 5 Mbps" in story["observed"]
    assert (
        "limited attempt was excluded from the network-loss assessment"
        in story["observed"]
    )
    assert "Only usable-rate measurements" in story["why_this_status"]
    assert "result remains PASS" in story["why_this_status"]
    assert story["kind"] == "measurement-rate-limited"
    assert "receiver-overload" not in story["observed"]
    assert result == original


def test_out_of_order_warning_keeps_its_observed_count_and_advisory_limit_primary():
    result = _readable_flow(
        "", "network-performance", "profile-recorded", "profile-measured"
    )
    result["details"].update(
        measurement="udp",
        health="warning",
        thresholds_enforced=False,
        warning_reasons=[
            "forward UDP at 10 Mbit/s with 128-byte packets received 246 of 29297 unique packets out of order (0.840%), above advisory threshold 0.100%"
        ],
        metrics={
            "forward": [_udp_quality_sample(out_of_order=246, out_of_order_pct=0.84)]
        },
    )
    story = explain_result(result)
    assert "out of order above the advisory tolerance" in story["headline"]
    assert "246 of 29297" in story["observed"]
    assert "0.840%" in story["observed"] and "0.100%" in story["observed"]
    assert "source → destination" in story["observed"]
    assert "advisory under this check's recorded policy" in story["why_this_status"]
    assert "VM-limited" not in story["why_this_status"]


def test_latency_loss_advisory_is_primary_even_when_delay_values_look_good():
    result = _readable_flow(
        "", "network-performance", "profile-recorded", "profile-measured"
    )
    result["details"].update(
        measurement="latency",
        health="warning",
        thresholds_enforced=False,
        warning_reasons=["latency probes observed up to 5.00% packet loss"],
        metrics={
            "idle": {"forward": {"p95_ms": 0.8, "loss_pct": 5}},
            "loaded": {"forward": {"p95_ms": 0.5, "loss_pct": 0}},
        },
    )
    story = explain_result(result)
    assert "Some ping replies were missing" in story["headline"]
    assert "Ping replies were missing for up to 5.00% of requests" in story["observed"]
    assert "0.5 ms" in story["observed"]
    assert "result remains PASS" in story["why_this_status"]


def test_attention_overview_does_not_label_mixed_measurements_from_first_udp_row():
    udp = _readable_flow(
        "", "network-performance", "profile-recorded", "profile-measured"
    )
    udp["details"].update(
        measurement="udp",
        health="warning",
        warning_reasons=[
            "forward packets arrived out of order above advisory threshold"
        ],
        metrics={},
    )
    latency = copy.deepcopy(udp)
    latency["test_id"] = "LATENCY-ATTENTION"
    latency["details"].update(
        measurement="latency",
        warning_reasons=["latency probes observed up to 5.00% packet loss"],
    )
    overview = operator_overview({"results": [udp, latency]})
    assert overview["groups"][0]["count"] == 2
    assert (
        overview["groups"][0]["label"]
        == "Measurements completed with advisory observations"
    )


@pytest.mark.parametrize("origin", [50, None])
def test_udp_retry_rate_never_borrows_another_configured_load(origin):
    limited = _udp_quality_sample(
        configured_rate_mbps=origin,
        offered_mbps=50,
        endpoint_limited=True,
        load_valid=False,
        calibration_selected=False,
        endpoint_limit_reason="receiver-overload",
    )
    result = _readable_flow(
        "", "network-performance", "profile-recorded", "profile-measured"
    )
    result["details"].update(
        measurement="udp",
        health="good",
        warning_reasons=["An endpoint-limited UDP attempt was excluded"],
        metrics={"forward": [limited, _udp_quality_sample(offered_mbps=5)]},
    )
    story = explain_result(result)
    assert "50 Mbps" in story["observed"]
    assert "usable retry ran at 5 Mbps" not in story["observed"]


def test_sender_limit_names_the_sending_vm_and_the_rate_it_actually_generated():
    result = _readable_flow(
        "", "network-performance", "profile-recorded", "profile-measured"
    )
    result["details"].update(
        measurement="udp",
        health="good",
        thresholds_enforced=False,
        warning_reasons=["A sender endpoint-limited UDP attempt was excluded"],
        metrics={
            "forward": [
                _udp_quality_sample(
                    endpoint_limited=True,
                    load_valid=False,
                    calibration_selected=False,
                    endpoint_limit_reason="sender-rate-not-achieved",
                    sender_mbps=2.25,
                ),
                _udp_quality_sample(offered_mbps=2),
            ]
        },
    )
    story = explain_result(result)
    assert "sending VM could not generate the requested rate" in story["headline"]
    assert (
        "source VM could not generate the requested traffic rate" in story["observed"]
    )
    assert "it generated 2.25 Mbps" in story["observed"]
    assert "usable retry ran at 2 Mbps" in story["observed"]
    assert "network-loss assessment" in story["observed"]


def test_legacy_achieved_udp_rate_is_not_relabelled_as_receiver_goodput():
    result = _readable_flow(
        "", "network-performance", "profile-recorded", "profile-measured"
    )
    result["details"].update(
        measurement="udp",
        thresholds_enforced=False,
        metrics={
            "forward": [
                {
                    "packet_size": 1200,
                    "loss_pct": 0.5,
                    "jitter_ms": 0.8,
                    "achieved_mbps": 98.0,
                }
            ]
        },
    )
    original = copy.deepcopy(result)
    story = explain_result(result)
    assert "Source → destination" in story["observed"]
    assert "UDP payload size 1,200 bytes" in story["observed"]
    assert "achieved rate 98 Mbps" in story["observed"]
    assert "receiver delivered 98 Mbps" not in story["observed"]
    assert "0.8 ms" in story["observed"]
    assert result == original


@pytest.mark.parametrize(
    "status", ["NOT_RUN_CANCELLED", "BLOCKED_BY_SETUP_ERROR", "SKIP", "NOT_APPLICABLE"]
)
def test_unrun_primary_prose_never_repeats_a_retained_positive_contract(status):
    result = copy.deepcopy(_payload()["results"][0])
    result["status"] = status
    result["message"] = "TCP reached the destination and echoed the test token"
    original = copy.deepcopy(result)
    story = explain_result(result)
    assert "reached the destination" not in story["observed"]
    assert "echoed" not in story["why_this_status"]
    assert (
        "did not run" in story["observed"]
        or "No traffic probe ran" in story["observed"]
    )
    assert story["recorded_message"] == result["message"]
    assert result == original


def test_cancelled_migration_does_not_reuse_retained_successful_continuity_as_execution():
    result = _observation_pass()
    result["status"] = "NOT_RUN_CANCELLED"
    original = copy.deepcopy(result)
    story = explain_result(result)
    assert "did not run" in story["observed"]
    assert "TCP connection stayed established" not in story["observed"]
    assert "traffic recovered after the move" not in story["what_happened"]
    assert not story.get("interruption_observations")
    assert "run was cancelled" in story["why_this_status"]
    assert result == original
