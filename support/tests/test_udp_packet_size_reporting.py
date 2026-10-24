from __future__ import annotations

import copy

import pytest

from neutron_flux.operator_explanations import explain_result
from neutron_flux.reporting_components.dashboard_findings import finding_measurements
from neutron_flux.reporting_components.dashboard_udp_model import udp_measurement_values
from neutron_flux.reporting_components.html import _performance_summary


@pytest.mark.parametrize("capacity_limited", [False, True])
def test_unsupported_packet_sizes_are_separate_from_endpoint_capacity(capacity_limited):
    samples = [
        {
            "packet_size": 128,
            "loss_pct": 0.0,
            "load_valid": True,
            "received": 100,
            "sent": 100,
        },
        {
            "packet_size": 1452,
            "packet_size_supported": False,
            "load_valid": False,
            "endpoint_limited": False,
            "loss_pct": 99.0,
            "size_status": "local-pmtu-rejection",
            "kernel_path_mtu": 1442,
        },
    ]
    if capacity_limited:
        samples.append(
            {
                "packet_size": 128,
                "endpoint_limited": True,
                "load_valid": False,
                "loss_pct": 12.0,
            }
        )
    metrics = {"forward": samples}
    row = {
        "status": "UNVERIFIED",
        "details": {"measurement": "udp", "metrics": metrics},
    }
    original = copy.deepcopy(row)
    expected_capacity_loss = 12.0 if capacity_limited else None
    values = udp_measurement_values(metrics)
    assert values["forward_loss_pct"] == 0.0
    assert values["forward_excluded_samples"] == 1 + int(capacity_limited)
    assert values["forward_endpoint_limited_loss_pct"] == expected_capacity_loss
    summary = _performance_summary([row])
    assert summary["worst_udp_loss_pct"] == 0.0
    assert summary["worst_endpoint_limited_udp_loss_pct"] == expected_capacity_loss
    facts = {fact["label"]: fact["value"] for fact in finding_measurements([row])}
    assert facts["Worst across affected UDP tests"] == "0.000%"
    if capacity_limited:
        assert facts["Excluded endpoint-limited UDP loss"] == "12.000%"
    else:
        assert "Excluded endpoint-limited UDP loss" not in facts
    assert row == original


def test_unsupported_packet_size_is_not_a_successful_udp_calibration():
    result = {
        "status": "PASS",
        "details": {
            "measurement": "udp",
            "metrics": {
                "forward": [
                    {
                        "packet_size": 1452,
                        "packet_size_supported": False,
                        "configured_rate_mbps": 10,
                        "offered_mbps": 5,
                    }
                ]
            },
        },
    }
    assert explain_result(result)["udp_rate_calibrated"] is False


@pytest.mark.parametrize("sample", [{}, {"sent": 100}, {"received": 100}])
def test_unmarked_missing_receiver_metrics_do_not_invent_zero_measurements(sample):
    metrics = {"forward": [sample]}
    row = {
        "status": "UNVERIFIED",
        "details": {"measurement": "udp", "metrics": metrics},
    }
    values = udp_measurement_values(metrics)
    assert values["forward_excluded_samples"] == 1
    for key in (
        "loss_pct",
        "jitter_ms",
        "reordering_pct",
        "reordering_count",
        "received",
    ):
        assert values.get("forward_" + key) is None
    summary = _performance_summary([row])
    assert summary["worst_udp_loss_pct"] is None
    assert summary["worst_udp_jitter_ms"] is None
    assert summary["best_udp_mbps"] is None
    assert summary["best_udp_pps"] is None
    facts = {fact["label"]: fact["value"] for fact in finding_measurements([row])}
    assert "Worst across affected UDP tests" not in facts


@pytest.mark.parametrize("loss", [0.0, 2.0])
def test_legacy_loss_only_record_does_not_invent_jitter_counts_or_reordering(loss):
    metrics = {"forward": [{"loss_pct": loss}]}
    row = {"status": "PASS", "details": {"measurement": "udp", "metrics": metrics}}
    original = copy.deepcopy(row)
    values = udp_measurement_values(metrics)
    assert values["forward_excluded_samples"] == 0
    assert values["forward_loss_pct"] == loss
    for key in (
        "jitter_ms",
        "reordering_pct",
        "reordering_count",
        "received",
        "sample_rate_mbps",
        "sample_packet_size",
    ):
        assert values["forward_" + key] is None
    summary = _performance_summary([row])
    assert summary["worst_udp_loss_pct"] == loss
    assert summary["worst_udp_jitter_ms"] is None
    assert summary["best_udp_mbps"] is None
    assert summary["best_udp_pps"] is None
    facts = {fact["label"]: fact["value"] for fact in finding_measurements([row])}
    assert facts["Worst across affected UDP tests"] == f"{loss:.3f}%"
    assert row == original


@pytest.mark.parametrize("explicit_percentage", [False, True])
def test_recorded_zero_jitter_and_reordering_remain_real_zero(explicit_percentage):
    sample = {
        "loss_pct": 0.0,
        "sent": 100,
        "received": 100,
        "jitter_ms": 0.0,
        "out_of_order": 0,
        "mbps": 1.0,
        "pps": 100.0,
        "offered_mbps": 1.0,
        "packet_size": 1200,
    }
    if explicit_percentage:
        sample["out_of_order_pct"] = 0.0
    metrics = {"forward": [sample]}
    values = udp_measurement_values(metrics)
    assert values["forward_loss_pct"] == 0.0
    assert values["forward_jitter_ms"] == 0.0
    assert values["forward_reordering_pct"] == 0.0
    assert values["forward_reordering_count"] == 0
    assert values["forward_received"] == 100
    assert values["forward_sample_rate_mbps"] == 1.0
    summary = _performance_summary(
        [{"details": {"measurement": "udp", "metrics": metrics}}]
    )
    assert summary["worst_udp_jitter_ms"] == 0.0


@pytest.mark.parametrize(
    "partial,percentage,count,received",
    [
        ({"out_of_order_pct": 0.0}, 0.0, None, None),
        ({"out_of_order": 0}, None, 0, None),
        ({"received": 100}, None, None, 100),
        ({"out_of_order": 0, "received": 0}, None, 0, 0),
        ({"out_of_order": 2, "received": 100}, 2.0, 2, 100),
    ],
)
def test_reordering_projection_requires_recorded_percentage_or_a_real_denominator(
    partial, percentage, count, received
):
    values = udp_measurement_values({"forward": [{"loss_pct": 0.0, **partial}]})
    assert values["forward_reordering_pct"] == percentage
    assert values["forward_reordering_count"] == count
    assert values["forward_received"] == received


@pytest.mark.parametrize("invalid", [True, float("inf"), float("nan")])
def test_invalid_excluded_loss_is_not_displayed_as_a_numeric_fact(invalid):
    sample = {"endpoint_limited": True, "loss_pct": invalid}
    metrics = {"forward": [sample]}
    row = {"details": {"measurement": "udp", "metrics": metrics}}
    assert udp_measurement_values(metrics)["forward_endpoint_limited_loss_pct"] is None
    assert _performance_summary([row])["worst_endpoint_limited_udp_loss_pct"] is None
    assert not any(
        fact["label"] == "Excluded endpoint-limited UDP loss"
        for fact in finding_measurements([row])
    )
