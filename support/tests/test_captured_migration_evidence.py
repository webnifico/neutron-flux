"""Regressions from the supplied live run, not model-shaped happy paths.

The fixture retains exact measured values and false/unknown Nova evidence.
It does not turn an old run into a newly phase-attested or completed run.
"""

from __future__ import annotations

import json
from collections import Counter
from copy import deepcopy
from pathlib import Path

import pytest

from neutron_flux.continuity_phases import (
    continuity_outage_bounds,
    partition_continuity,
)
from neutron_flux.execution.placement_migration import PlacementMigrationMixin
from neutron_flux.logical_results import logical_results
from neutron_flux.operator_explanations import operator_overview

FIXTURES = Path(__file__).with_name("fixtures")
RECORDS = json.loads((FIXTURES / "captured_migration_windows.json").read_text())[
    "records"
]


@pytest.mark.parametrize("record", RECORDS, ids=lambda record: record["check_id"])
def test_real_captured_measurements_do_not_promote_missing_completion_proof(record):
    value = deepcopy(record["continuity"])
    status, _, _, details = PlacementMigrationMixin._live_continuity_verdict(value)
    assert value == record["continuity"]
    # These historical proofs omit port/volume/marker/readiness verification.
    # Successful TCP cannot replace the missing supplied completion evidence.
    assert status == "UNVERIFIED"
    assert details["evidence_complete"] is False
    assert details["interruption_observations"] == []
    assert details["receiver_delivery_verified"] is True
    assert details["tcp"]["survived"] is True
    assert details["tcp"]["bytes_sent"] == details["tcp"]["server_result"]["bytes"] > 0
    if record["logical_outcome"] == "FAIL":
        assert details["tolerance_failure_reasons"]
        assert not details["transport_failure_reasons"]
    assert details["continuity_failure_reasons"] == []
    if value["migration_succeeded"] is None:
        assert details["migration_succeeded"] is None
        assert details["evidence_complete"] is False
        assert details["migration_outcomes"]["migration_completion"] == "UNVERIFIED"
        assert details["interruption_observations"] == []


def test_captured_startup_failures_have_separate_attribution_not_deleted_evidence():
    startup_runs = []
    for record in RECORDS:
        value = record["continuity"]
        result = partition_continuity(
            {
                "readiness": value["readiness"],
                "observation_duration_s": value["observation_duration_s"],
                "icmp": value["icmp"]["raw_samples"],
                "udp": value["udp"],
            },
            {"phase_markers_required": True},
            continuity_outage_bounds,
            sample_interval_s=0.25,
        )
        assert result["icmp_partition_verified"] is True
        # Old reports lack UDP timing/bitmap and actual submission timestamps.
        assert result["verified"] is False
        assert result["udp_partition_verified"] is False
        assert result["markers_verified"] is False
        start, protected = result["phases"]["startup"], result["phases"]["protected"]
        assert (
            start["icmp"]["samples"] + protected["icmp"]["samples"]
            == value["icmp"]["samples"]
        )
        assert (
            start["icmp"]["lost"] + protected["icmp"]["lost"] == value["icmp"]["lost"]
        )
        assert result["raw_icmp_observations"] == value["icmp"]["raw_samples"]
        if start["icmp"]["lost"]:
            startup_runs.append((start["icmp"]["lost"], protected["icmp"]["lost"]))
            assert protected["icmp"]["outage"]["outage_lower_bound_s"] > 1.0
    assert sorted(startup_runs) == [(12, 21), (18, 23)]


def test_actual_supporting_rows_do_not_double_logical_failure_counts():
    payload = json.loads((FIXTURES / "captured_logical_accounting.json").read_text())
    original = deepcopy(payload)
    raw_counts = Counter(row["status"] for row in payload["results"])
    assert raw_counts["FAIL"] == 14 and raw_counts["UNVERIFIED"] == 14
    selected = logical_results(payload)
    counts = Counter(row["status"] for row in selected)
    assert len(selected) == 533
    assert counts == {"PASS": 519, "FAIL": 7, "UNVERIFIED": 7}
    overview = operator_overview(payload)
    statuses = Counter()
    for group in overview["groups"]:
        statuses.update(group["statuses"])
    assert statuses["FAIL"] == 7 and statuses["UNVERIFIED"] == 7
    assert overview["supporting_evidence_rows"] == len(payload["results"]) - 533
    assert payload == original


def test_legacy_partial_or_duplicate_rows_do_not_lose_stronger_evidence():
    rows = [
        {
            "test_id": "primary",
            "status": "FAIL",
            "details": {"planned_check_id": "check"},
        },
        {
            "test_id": "primary",
            "status": "PASS",
            "details": {"planned_check_id": "check"},
        },
        {
            "test_id": "sample",
            "status": "FAIL",
            "details": {"planned_check_id": "check", "check_sample": True},
        },
    ]
    assert logical_results({"results": rows}) == [rows[0]]


def test_ledger_alias_does_not_override_a_confirmed_failure_with_duplicate_pass():
    rows = [
        {
            "test_id": "primary",
            "status": "FAIL",
            "details": {"planned_check_id": "check"},
        },
        {
            "test_id": "primary",
            "status": "PASS",
            "details": {"planned_check_id": "check"},
        },
    ]
    assert logical_results(
        {
            "results": rows,
            "planned_check_ledger": [
                {"id": "check", "result_id": "primary", "outcome": "FAILED"},
            ],
        }
    ) == [rows[0]]


@pytest.mark.parametrize("value", [None, False, "", 4, []])
def test_malformed_legacy_details_dont_crash_or_drop_the_outcome(value):
    row = {"test_id": "legacy", "status": "FAIL", "details": value}
    assert logical_results({"results": [row]}) == [row]
