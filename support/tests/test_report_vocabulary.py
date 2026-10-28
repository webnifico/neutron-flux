from __future__ import annotations

import copy
import json
from collections import Counter
from pathlib import Path

import pytest

from neutron_flux.models import TestResult as ResultRecord
from neutron_flux.reporting_components.attention_summary import (
    attention_summary,
    attention_summary_parts,
)
from neutron_flux.reporting_components.report_payload import _suite_label
from neutron_flux.reporting_components.summary import SummaryRendererMixin
from neutron_flux.results_io import render_results_text
from neutron_flux.terminology import category_label


@pytest.mark.parametrize(
    ("category", "label"),
    [
        ("floating-ip", "Floating-IP connectivity"),
        ("floating-ip-lifecycle", "Floating-IP lifecycle"),
        ("floating-ip-peer", "Floating-IP peer and hairpin connectivity"),
        ("source-nat-connectivity", "Router source-NAT connectivity"),
        ("source-nat-packet-size", "Router source-NAT packet size"),
        ("source-nat-setting", "Router SNAT setting lifecycle"),
        ("provider-network-connectivity", "Provider network connectivity"),
    ],
)
def test_html_and_text_use_readable_shared_category_names(category, label):
    assert category_label(category) == label
    assert _suite_label(category) == label
    assert SummaryRendererMixin._category_label(category) == label


def _row(identity, category, details):
    return {
        "test_id": identity,
        "category": category,
        "status": "PASS",
        "family": 4,
        "source": None,
        "destination": None,
        "message": "Recorded check completed",
        "started_at": "2026-10-15T00:00:00Z",
        "duration_ms": 0,
        "details": details,
    }


def _attention_payload():
    capture = json.loads(
        (
            Path(__file__).with_name("fixtures")
            / "captured_translated_migration_interruptions.json"
        ).read_text()
    )["windows"][0]
    continuity = copy.deepcopy(capture["continuity"])
    continuity.update(
        migration_outcomes={
            **capture["outcomes"],
            "interruption_tolerance": "OBSERVATION",
        },
        interruption_observations=capture["reasons"],
        tolerance_failure_reasons=capture["reasons"],
        transport_failure_reasons=[],
    )
    rows = [
        _row(
            f"MIGRATION-{index}",
            "compute-placement",
            {
                "transitions": [
                    {
                        "confirmed": True,
                        "continuity_assessment": copy.deepcopy(continuity),
                    }
                ]
            },
        )
        for index in range(4)
    ]
    rows.extend(
        _row(
            f"UDP-{index}",
            "network-performance",
            {
                "measurement": "udp",
                "health": "good",
                "metrics": {
                    "forward": [
                        {
                            "packet_size": 128,
                            "configured_rate_mbps": 10,
                            "offered_mbps": 10,
                            "sender_mbps": 8,
                            "endpoint_limited": True,
                            "endpoint_limit_reason": "sender-underachievement",
                        },
                        {
                            "packet_size": 128,
                            "configured_rate_mbps": 10,
                            "offered_mbps": 5,
                            "endpoint_limited": False,
                            "loss_pct": 0,
                        },
                    ]
                },
            },
        )
        for index in range(13)
    )
    rows.extend(
        _row(
            f"PERFORMANCE-{index}",
            "network-performance",
            {
                "measurement": "latency",
                "health": "warning",
                "warning_reasons": ["Some ping replies were missing"],
            },
        )
        for index in range(11)
    )
    for row in list(rows):
        sample = copy.deepcopy(row)
        sample["test_id"] += "-SUPPORTING"
        sample["details"]["check_sample"] = True
        rows.append(sample)
    return {"results": rows, "run": {"final_status": "PASS WITH WARNINGS"}}


def test_attention_counts_separate_migration_calibration_and_performance():
    payload = _attention_payload()
    original = copy.deepcopy(payload)
    assert attention_summary(payload) == {
        "migration_observations": 4,
        "udp_calibrations": 13,
        "performance_warnings": 11,
    }
    assert payload == original


def test_regenerated_text_separately_counts_logical_advisory_conditions():
    payload = _attention_payload()
    original = copy.deepcopy(payload)
    text = render_results_text(payload)
    assert "Migration interruption observations: 4" in text
    assert "UDP measurements with rate calibration: 13" in text
    assert "Performance measurements with advisory warnings: 11" in text
    assert payload == original


def test_live_summary_uses_the_same_separate_counts():
    class Summary(SummaryRendererMixin):
        plan = None
        action = "run"

        def __init__(self, rows):
            self.results = [ResultRecord(**row) for row in rows]

        def _primary_summary_results(self):
            return [
                item for item in self.results if not item.details.get("check_sample")
            ]

    summary = Summary(_attention_payload()["results"])
    line = summary._overall_result_line("PASS WITH WARNINGS", Counter(PASS=28))
    assert "4 migration interruption observations" in line
    assert "13 calibrated UDP measurements" in line
    assert "11 performance measurement warnings" in line


def test_historical_failed_migrations_remain_failed_not_new_pass_observations():
    payload = _attention_payload()
    payload["results"][0]["status"] = "FAIL"
    assert attention_summary(payload)["migration_observations"] == 3
    assert payload["results"][0]["status"] == "FAIL"


def test_calibrated_udp_with_another_advisory_counts_both_conditions_once():
    row = copy.deepcopy(
        next(
            row for row in _attention_payload()["results"] if row["test_id"] == "UDP-0"
        )
    )
    row["details"].update(
        health="warning",
        warning_reasons=[
            "UDP packets arrived out of order above the advisory tolerance"
        ],
    )
    original = copy.deepcopy(row)
    counts = attention_summary({"results": [row]})
    assert counts == {"udp_calibrations": 1, "performance_warnings": 1}
    text = render_results_text({"results": [row]})
    assert "UDP measurements with rate calibration: 1" in text
    assert "Performance measurements with advisory warnings: 1" in text
    assert row == original


def test_current_calibration_flag_overrides_legacy_story_kind():
    row = _row("UDP-NOT-CALIBRATED", "network-performance", {})
    row["operator_explanation"] = {
        "kind": "measurement-rate-limited",
        "udp_rate_calibrated": False,
    }
    assert attention_summary({"results": [row]})["udp_calibrations"] == 0
    del row["operator_explanation"]["udp_rate_calibrated"]
    assert attention_summary({"results": [row]})["udp_calibrations"] == 1


def test_mtu_advisory_is_preserved_separately_from_performance_warnings():
    payload = {
        "results": [
            _row(
                "MTU-ADVISORY",
                "mtu",
                {"health": "warning", "advertised_mtu": 1500, "observed_mtu": 1442},
            )
        ]
    }
    counts = attention_summary(payload)
    assert counts == {"other_measurement_warnings": 1}
    assert attention_summary_parts(counts) == [
        "1 measurement warning outside performance tests"
    ]
    assert "Other measurements with advisory warnings: 1" in render_results_text(
        payload
    )


@pytest.mark.parametrize("count", [1, 2])
def test_attention_headline_counts_use_singular_and_plural(count):
    suffix = "" if count == 1 else "s"
    assert attention_summary_parts(
        Counter(
            migration_observations=count,
            udp_calibrations=count,
            performance_warnings=count,
            other_measurement_warnings=count,
        )
    ) == [
        f"{count} migration interruption observation{suffix}",
        f"{count} calibrated UDP measurement{suffix}",
        f"{count} performance measurement warning{suffix}",
        f"{count} measurement warning{suffix} outside performance tests",
    ]
