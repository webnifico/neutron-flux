from __future__ import annotations

import copy
import math

import pytest

from neutron_flux.offline_reports import _refresh_udp_summary
from neutron_flux.reporting_components.html import _performance_summary, render_html
from neutron_flux.results_io import render_results_text
from support.tests.test_offline_reports_and_concurrent_load import _payload
from support.tests.test_summary_wording import _function, _run_javascript


def _sample(count=10, *, seconds=3.1, streams=1):
    return {
        "retransmissions": count,
        "elapsed_s": seconds,
        "streams": streams,
        "mbps": 2500.0,
    }


def _row(measurement="tcp-throughput", metrics=None):
    return {
        "test_id": f"PERF-{measurement}",
        "status": "PASS",
        "details": {
            "measurement": measurement,
            "metrics": metrics or {},
            "path": {
                "path_id": "PATH-6",
                "source_label": "vm-a",
                "destination_label": "vm-b",
                "family": 6,
                "stage": "post-live-migration",
                "placement": "cross-compute",
            },
        },
    }


def _throughput_rows():
    return [
        _row(
            metrics={
                "forward": {
                    "warmup": _sample(999999),
                    "repeats": [_sample(40), _sample(60)],
                    "streams": {
                        "1": {
                            "total_retransmissions": 100,
                            "runs": [_sample(40), _sample(60)],
                            "warmup_sample": _sample(999999),
                        },
                        "4": {
                            "total_retransmissions": 90,
                            "runs": [_sample(90, streams=4)],
                        },
                    },
                },
                "reverse": {
                    "streams": {"1": {"runs": [_sample(80)]}},
                },
                "bidirectional": {
                    "forward_sample": _sample(70),
                    "reverse_sample": _sample(85),
                },
            }
        )
    ]


def test_peak_selects_individual_multistream_window_without_summing_or_warmups():
    rows = _throughput_rows()
    original = copy.deepcopy(rows)
    summary = _performance_summary(rows)
    assert rows == original
    assert summary["worst_tcp_retransmissions"] == 90
    window = summary["worst_tcp_retransmission_window"]
    assert window["streams"] == 4
    assert window["elapsed_s"] == 3.1
    assert window["condition"] == "throughput"
    assert window["family"] == 6
    assert window["stage"] == "post-live-migration"
    assert (
        "4 concurrent TCP connections; 3.100 s"
        in summary["worst_tcp_retransmission_window_description"]
    )


def test_latency_load_is_included_with_duration_and_actual_direction():
    rows = _throughput_rows()
    rows.append(
        _row(
            "latency",
            {
                "loaded": {
                    "reverse": {
                        "load_sample": _sample(200, seconds=7.25, streams=4),
                        "load_streams": 4,
                    }
                }
            },
        )
    )
    summary = _performance_summary(rows)
    assert summary["worst_tcp_retransmissions"] == 200
    window = summary["worst_tcp_retransmission_window"]
    assert window["source"] == "vm-b"
    assert window["destination"] == "vm-a"
    assert window["condition"] == "latency load"
    assert window["elapsed_s"] == 7.25
    assert window["mbps"] == 2500.0
    assert window["result_id"] == "PERF-latency"


def test_bidirectional_windows_remain_separate():
    row = _row(
        metrics={
            "bidirectional": {
                "forward_sample": _sample(70),
                "reverse_sample": _sample(85),
            }
        }
    )
    summary = _performance_summary([row])
    assert summary["worst_tcp_retransmissions"] == 85
    assert summary["worst_tcp_retransmission_window"]["direction"] == "reverse"
    assert summary["worst_tcp_retransmission_window"]["condition"] == (
        "bidirectional throughput"
    )


@pytest.mark.parametrize("measurement", ["concurrent-path-load", "fabric-scale"])
def test_concurrent_pair_peak_uses_one_window_and_preserves_pair_repeat_context(
    measurement,
):
    peak = {
        **_sample(500, seconds=7.5, streams=4),
        "direction": "reverse",
        "condition": "concurrent VM-pair throughput",
        "source_label": "pair-b",
        "destination_label": "pair-a",
        "pair_index": 3,
        "family": 4,
    }
    row = _row(
        measurement,
        {
            "levels": [
                {
                    "pairs_used": 4,
                    "total_retransmissions": 99999,
                    "total_loaded_retransmissions": 99999,
                    "runs": [
                        {"retransmissions": 9999, "tcp_windows": [_sample(300)]},
                        {"retransmissions": 9999, "tcp_windows": [peak]},
                    ],
                }
            ],
        },
    )
    summary = _performance_summary([row])
    assert summary["worst_tcp_retransmissions"] == 500
    window = summary["worst_tcp_retransmission_window"]
    assert window["source"] == "pair-b"
    assert window["destination"] == "pair-a"
    assert window["concurrent_run"] == 2
    assert window["concurrent_pairs"] == 4
    assert window["pair_index"] == 3
    assert window["family"] == 4
    assert window["elapsed_s"] == 7.5
    assert (
        "VM pair 3; 4 simultaneous VM pairs; repeat 2"
        in summary["worst_tcp_retransmission_window_description"]
    )


@pytest.mark.parametrize(
    "count", [None, False, True, -1, math.nan, math.inf, "20", 0.5, 10**1000]
)
def test_missing_or_invalid_counters_are_not_reported_as_zero(count):
    summary = _performance_summary(
        [_row(metrics={"bidirectional": {"forward_sample": _sample(count)}})]
    )
    assert summary["worst_tcp_retransmissions"] is None
    assert summary["worst_tcp_retransmission_window"] is None


@pytest.mark.parametrize("counters", [None, "1", [None, 0], [1, -1], [], [1], [1, 1]])
def test_partial_or_inconsistent_per_stream_counters_are_not_a_complete_count(counters):
    sample = {**_sample(1, streams=2), "stream_retransmissions": counters}
    summary = _performance_summary(
        [_row(metrics={"bidirectional": {"forward_sample": sample}})]
    )
    assert summary["worst_tcp_retransmissions"] is None


def test_recorded_zero_is_preserved_when_all_stream_counters_are_zero():
    sample = {**_sample(0, streams=2), "stream_retransmissions": [0, 0]}
    summary = _performance_summary(
        [_row(metrics={"bidirectional": {"forward_sample": sample}})]
    )
    assert summary["worst_tcp_retransmissions"] == 0
    assert summary["worst_tcp_retransmission_window"]["streams"] == 2


def test_aggregate_only_legacy_data_cannot_supply_an_individual_window():
    row = _row(metrics={"forward": {"streams": {"1": {"total_retransmissions": 1234}}}})
    assert _performance_summary([row])["worst_tcp_retransmissions"] is None
    row["details"]["metrics"]["forward"]["streams"]["1"]["total_retransmissions"] = 0
    assert _performance_summary([row])["worst_tcp_retransmissions"] is None


def test_missing_duration_is_explicit_instead_of_using_configuration_or_total_time():
    sample = {"retransmissions": 20}
    row = _row(metrics={"forward": {"streams": {"1": {"runs": [sample]}}}})
    summary = _performance_summary([row])
    assert summary["worst_tcp_retransmissions"] == 20
    assert summary["worst_tcp_retransmission_window"]["elapsed_s"] is None
    assert (
        "duration not recorded"
        in summary["worst_tcp_retransmission_window_description"]
    )


def test_refresh_corrects_legacy_summary_and_preserves_recorded_verdicts():
    payload = _payload("tcp-refresh", status="FAIL")
    original = copy.deepcopy(payload["results"])
    payload["summary"]["performance"]["worst_tcp_retransmissions"] = 12345
    _refresh_udp_summary(payload)
    assert payload["results"] == original
    assert payload["summary"]["performance"]["worst_tcp_retransmissions"] is None
    assert payload["run"]["final_status"] == "FAIL"


def test_text_summary_prints_window_context_instead_of_a_raw_dictionary():
    payload = _payload("tcp-context")
    payload["summary"]["performance"] = _performance_summary(_throughput_rows())
    text = render_results_text(payload)
    assert "Largest TCP retransmission count in one measurement window: 90" in text
    assert "TCP measurement window: throughput; forward; IPv6" in text
    assert "4 concurrent TCP connections; 3.100 s; 2500.0 Mbps; vm-a → vm-b" in text
    assert "'retransmissions':" not in text
    assert "are not a loss rate" in text


def test_html_summary_shows_actual_window_context_and_explicit_missing_state():
    result = _run_javascript(
        _function("renderPerformance")
        + r"""
const D={summary:{performance:{worst_tcp_retransmissions:200,
 worst_tcp_retransmission_window_description:'latency load; reverse; IPv6; 4 connections; 7.250 s'}},configuration:{}},environment={},M={};
renderPerformance();
const recorded=nodes.performanceSummary.innerHTML;
D.summary.performance.worst_tcp_retransmissions=null;
D.summary.performance.worst_tcp_retransmission_window_description=null;
renderPerformance();
console.log(JSON.stringify({recorded,missing:nodes.performanceSummary.innerHTML}));
"""
    )
    assert (
        "Most TCP retransmissions in one window</span><strong>200" in result["recorded"]
    )
    assert "latency load; reverse; IPv6; 4 connections; 7.250 s" in result["recorded"]
    assert (
        "Most TCP retransmissions in one window</span><strong>Not recorded"
        in result["missing"]
    )
    assert "complete retransmission counters" in result["missing"]
    assert "not a packet-loss rate" in render_html(_payload("tcp-definition"))
