"""Malformed receiver evidence must never become a successful UDP measurement."""

from __future__ import annotations

import copy
import json
from types import SimpleNamespace

import pytest

from neutron_flux.errors import MeasurementExecutionError
from neutron_flux.measurement_programs import udp_client_code
from neutron_flux.performance import PerformanceRunner
from neutron_flux.performance_metrics import udp_sample_assessable, udp_statistics_error
from neutron_flux.reporting_components.dashboard_udp_model import udp_measurement_values

from ._shared import endpoint
from .test_udp_pmtu_rejection import _execute_client, _PMTUSocket


def _valid_statistics():
    return {
        "session_id": 123,
        "sent": 100,
        "received": 100,
        "lost": 0,
        "loss_pct": 0.0,
        "mbps": 10.0,
        "pps": 9765.625,
        "jitter_ms": 0.0,
        "duplicates": 0,
        "out_of_order": 0,
        "out_of_order_pct": 0.0,
    }


class _ChangedReply(_PMTUSocket):
    def __init__(self, change):
        super().__init__(size_limit=65535)
        self.change = change

    def recv(self, size):
        response = json.loads(super().recv(size)[4:])
        self.change(response)
        return b"NFR1" + json.dumps(response).encode()


def _runner():
    runner = object.__new__(PerformanceRunner)
    runner.config = SimpleNamespace(
        performance_duration_seconds=1,
        udp_port=18081,
        performance_udp_loss_threshold_pct=1.0,
        performance_udp_reordering_threshold_pct=0.1,
        performance_udp_sender_achievement_threshold_pct=90.0,
    )
    return runner


@pytest.mark.parametrize(
    "field",
    ["received", "loss_pct", "mbps", "pps", "jitter_ms", "duplicates", "out_of_order"],
)
def test_actual_client_rejects_missing_receiver_statistics(field):
    with pytest.raises(ValueError, match="missing UDP statistic"):
        _execute_client(
            udp_client_code("192.0.2.1", "192.0.2.2", 4, 18081, 0.01, 10, 128),
            _ChangedReply(lambda response: response.pop(field)),
        )


@pytest.mark.parametrize(
    "field",
    ["received", "loss_pct", "mbps", "pps", "jitter_ms", "duplicates", "out_of_order"],
)
@pytest.mark.parametrize(
    "value", [True, "0", -1, float("nan"), float("inf"), -float("inf"), 10**1000]
)
def test_actual_client_rejects_non_numeric_or_invalid_statistics(field, value):
    with pytest.raises(ValueError, match="UDP"):
        _execute_client(
            udp_client_code("192.0.2.1", "192.0.2.2", 4, 18081, 0.01, 10, 128),
            _ChangedReply(lambda response: response.update({field: value})),
        )


@pytest.mark.parametrize(
    "change",
    [
        {"received": 101},
        {"received": 99},
        {"lost": 1},
        {"loss_pct": 100.1},
        {"out_of_order": 101},
        {"out_of_order_pct": 1.0},
        {"application_received": 99},
        {"socket_dequeued": 99},
        {"wire_received": 99},
        {"mbps": 0.0},
        {"pps": 0.0},
    ],
)
def test_inconsistent_receiver_statistics_are_not_assessable(change):
    sample = {**_valid_statistics(), **change}
    assert udp_statistics_error(sample, require_complete=True)
    assert not udp_sample_assessable(sample)
    assert _runner()._udp_health({"forward": [sample]}) == "unverified"
    assert "forward_loss_pct" not in udp_measurement_values({"forward": [sample]})


def test_actual_client_does_not_accept_session_and_sender_count_as_delivery_evidence():
    def remove_statistics(response):
        for field in list(response):
            if field not in {"session_id", "sent"}:
                response.pop(field)

    with pytest.raises(ValueError, match="missing UDP statistic"):
        _execute_client(
            udp_client_code("192.0.2.1", "192.0.2.2", 4, 18081, 0.01, 10, 128),
            _ChangedReply(remove_statistics),
        )


def test_performance_ingress_rejects_incomplete_reply_even_if_command_returns_json():
    runner = _runner()
    runner._run_json_with_transient_retry = lambda *_args, **_kwargs: {
        "sent": 1,
        "session_id": 1,
    }
    with pytest.raises(MeasurementExecutionError, match="missing UDP statistic"):
        runner._udp_measurement(endpoint(), "192.0.2.1", "192.0.2.2", 4, 10, 128)


def test_current_schema_and_historical_invalid_values_cannot_report_zero_loss():
    incomplete = {"session_id": 1, "sent": 1, "control_statistics_available": True}
    malformed = {**_valid_statistics(), "loss_pct": float("nan"), "mbps": float("nan")}
    for sample in (incomplete, malformed):
        before = copy.deepcopy(sample)
        assert not udp_sample_assessable(sample)
        assert _runner()._udp_health({"forward": [sample]}) == "unverified"
        assert "forward_loss_pct" not in udp_measurement_values({"forward": [sample]})
        assert sample.keys() == before.keys()
    # A malformed selected profile cannot be hidden by a healthy sibling.
    assert (
        _runner()._udp_health({"forward": [_valid_statistics(), incomplete]})
        == "unverified"
    )


@pytest.mark.parametrize(
    "received,duplicates,reordered", [(0, 0, 0), (50, 20, 10), (100, 50, 30)]
)
def test_real_loss_duplicates_and_reordering_remain_valid_evidence(
    received, duplicates, reordered
):
    sample = {
        **_valid_statistics(),
        "received": received,
        "application_received": received,
        "lost": 100 - received,
        "loss_pct": float(100 - received),
        "mbps": received / 10,
        "pps": received * 97.65625,
        "duplicates": duplicates,
        "socket_dequeued": received + duplicates,
        "wire_received": received + duplicates,
        "out_of_order": reordered,
        "out_of_order_pct": reordered * 100.0 / received if received else 0.0,
        "control_statistics_available": True,
    }
    assert udp_statistics_error(sample, require_complete=True) is None
    assert udp_sample_assessable(sample)
    assert _runner()._udp_health({"forward": [sample]}) == (
        "critical" if not received else "warning"
    )


def test_pmtu_fallback_without_statistics_remains_excluded():
    sample = {
        "packet_size_supported": False,
        "control_statistics_available": False,
        "sent": 0,
        "session_id": 1,
    }
    assert not udp_sample_assessable(sample)
    assert _runner()._udp_health({"forward": [sample]}) == "unverified"


@pytest.mark.parametrize("sample", [{}, {"session_id": 1, "sent": 98}])
def test_unmarked_legacy_sample_without_recorded_loss_cannot_invent_zero_loss(sample):
    assert not udp_sample_assessable(sample)
    assert _runner()._udp_health({"forward": [sample]}) == "unverified"
    assert "forward_loss_pct" not in udp_measurement_values({"forward": [sample]})


@pytest.mark.parametrize("current_schema", [False, True])
def test_zero_sent_statistics_do_not_establish_successful_udp_delivery(current_schema):
    sample = {
        **_valid_statistics(),
        "sent": 0,
        "received": 0,
        "mbps": 0.0,
        "pps": 0.0,
    }
    if current_schema:
        sample["control_statistics_available"] = True
    assert udp_statistics_error(sample, require_complete=True) is None
    assert not udp_sample_assessable(sample)
    assert _runner()._udp_health({"forward": [sample]}) == "unverified"
    assert "forward_loss_pct" not in udp_measurement_values({"forward": [sample]})


@pytest.mark.parametrize("current_schema", [False, True])
def test_positive_sent_zero_loss_remains_successful_udp_delivery(current_schema):
    sample = _valid_statistics()
    if current_schema:
        sample["control_statistics_available"] = True
    assert udp_sample_assessable(sample)
    assert _runner()._udp_health({"forward": [sample]}) == "good"
    assert udp_measurement_values({"forward": [sample]})["forward_loss_pct"] == 0.0
