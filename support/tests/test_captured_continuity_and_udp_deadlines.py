"""Replay supplied migration measurements under the current outcome policy.

Inputs retain the actual probe times, receiver bitmap and migration evidence.
Historical recorded verdicts remain in the fixture and are not rewritten.
"""

from __future__ import annotations

import json
from collections import Counter
from copy import deepcopy
from pathlib import Path

import pytest

from neutron_flux.execution.placement_migration import PlacementMigrationMixin
from neutron_flux.logical_results import logical_results
from neutron_flux.operator_explanations import explain_result, explanation_lines

CAPTURE = json.loads(
    (
        Path(__file__).with_name("fixtures")
        / "captured_continuity_and_udp_deadlines.json"
    ).read_text()
)


@pytest.mark.parametrize("record", CAPTURE["windows"], ids=lambda row: row["check_id"])
def test_captured_accepted_moves_pass_with_independent_interruption_observations(
    record,
):
    original = deepcopy(record["continuity"])
    status, _, message, assessment = PlacementMigrationMixin._live_continuity_verdict(
        original
    )
    assert original == record["continuity"]
    assert status == "PASS"
    expected = deepcopy(record["recorded_outcomes"])
    if record["status"] == "FAIL":
        expected["interruption_tolerance"] = "OBSERVATION"
    assert assessment["migration_outcomes"] == expected
    assert assessment["evidence_complete"] is True
    assert assessment["phase_evidence_complete"] is True
    assert assessment["receiver_delivery_verified"] is True
    assert not assessment["transport_failure_reasons"]
    assert assessment["evaluated_thresholds"] == {
        "icmp_loss_pct": 1.0,
        "udp_loss_pct": 1.0,
        "outage_lower_bound_s": 1.0,
    }
    assert "ICMP failed observations" in message
    assert assessment["continuity_failure_reasons"] == []
    if record["status"] == "FAIL":
        assert assessment["interruption_observations"]
        assert assessment["health"] == "warning"
        samples = original["icmp"]["raw_samples"]
        failed = [sample for sample in samples if sample["ok"] is False]
        assert failed and all(sample["timed_out"] is True for sample in failed)
        story = explain_result(
            {"status": status, "category": "compute-placement", "details": assessment}
        )
        assert story["kind"] == "migration-interruption-observation"
        assert {
            "label": "ICMP probe deadline expirations",
            "value": str(len(failed)),
        } in story["facts"]
        assert {"label": "ICMP probe deadline (seconds)", "value": "0.2"} in story[
            "facts"
        ]
        assert "does not distinguish packet loss" in " ".join(story["limitations"])


def test_post_migration_timeouts_are_visible_when_udp_delivered_every_datagram():
    record = next(
        row
        for row in CAPTURE["windows"]
        if row["check_id"] == "PAIR-TRANSITION-67d9af23e60d40d2-same-b"
    )
    status, _, message, assessment = PlacementMigrationMixin._live_continuity_verdict(
        record["continuity"]
    )
    assert status == "PASS"
    assert assessment["migration_outcomes"]["interruption_tolerance"] == "OBSERVATION"
    assert assessment["udp"]["protected_measurement"]["lost"] == 0
    story = explain_result(
        {"status": status, "message": message, "details": assessment}
    )
    assert {"label": "Migration ICMP failed observations", "value": "9/370"} in story[
        "facts"
    ]
    assert {
        "label": "Post-migration ICMP failed observations",
        "value": "26/1098",
    } in story["facts"]
    assert assessment["migration_outcomes"]["tcp_session"] == "PASS"
    assert assessment["migration_outcomes"]["traffic_recovery"] == "PASS"


def test_actual_udp_peer_timeout_is_not_reported_as_a_tcp_connection():
    result = deepcopy(CAPTURE["udp_failure"])
    original = deepcopy(result)
    story = explain_result(result)
    assert story["headline"] == "Waiting for the peer reply timed out"
    assert {"label": "UDP socket peer selected", "value": "Yes"} in story["facts"]
    assert not any(
        row["label"] == "TCP connection established" for row in story["facts"]
    )
    assert {"label": "Request sent", "value": "Yes"} in story["facts"]
    assert {"label": "Response received", "value": "No"} in story["facts"]
    assert "Capture this flow at both VMs" in story["next_check"]
    assert "later listener snapshots alone" in story["next_check"]
    rendered = "\n".join(explanation_lines(result))
    assert "UDP socket peer selected: Yes" in rendered
    assert "TCP connection established" not in rendered
    assert "later snapshot, not a packet trace" in rendered
    assert result == original and result["status"] == "FAIL"


def test_real_run_counts_eight_logical_failures_once():
    payload = deepcopy(CAPTURE["accounting"])
    original = deepcopy(payload)
    assert Counter(row["status"] for row in payload["results"]) == {
        "PASS": 746,
        "FAIL": 15,
    }
    rows = logical_results(payload)
    assert len(rows) == 533
    assert Counter(row["status"] for row in rows) == {"PASS": 525, "FAIL": 8}
    assert (
        sum(
            row["category"] == "compute-placement" and row["status"] == "FAIL"
            for row in rows
        )
        == 7
    )
    assert payload == original
