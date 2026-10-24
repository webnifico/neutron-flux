"""Retain historical migration verdicts while explaining the current policy."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from collections import Counter
from copy import deepcopy
from pathlib import Path

import pytest

from neutron_flux.junit_report import build_junit
from neutron_flux.logical_results import logical_results
from neutron_flux.offline_reports import (
    _apply_current_offline_interpretations,
    _current_migration_policy_interpretation,
    regenerate,
)
from neutron_flux.replay_plan import build_replay_plan
from neutron_flux.result_contract import normalize_result_record

CAPTURE = json.loads(
    (
        Path(__file__).with_name("fixtures")
        / "captured_translated_migration_interruptions.json"
    ).read_text()
)


def _historical_result(record, *, shape="transition"):
    assessment = deepcopy(record["continuity"])
    assessment.update(
        migration_outcomes=deepcopy(record["outcomes"]),
        tolerance_failure_reasons=list(record["reasons"]),
        transport_failure_reasons=[],
        continuity_failure_reasons=list(record["reasons"]),
    )
    details = (
        {"transitions": [{"confirmed": True, "continuity_assessment": assessment}]}
        if shape == "transition"
        else assessment
    )
    return normalize_result_record(
        {
            "test_id": record["check_id"],
            "category": "compute-placement",
            "status": "FAIL",
            "expected": "placement-achieved",
            "observed": "migration-assessed",
            "message": "Placement completed; interruption tolerance=FAIL",
            "details": details,
            "authoritative": True,
        }
    )


@pytest.mark.parametrize("shape", ["direct", "transition"])
@pytest.mark.parametrize("record", CAPTURE["windows"], ids=lambda row: row["check_id"])
def test_historical_tolerance_failure_gets_separate_current_policy_observation(
    record, shape
):
    item = _historical_result(record, shape=shape)
    original = deepcopy(item)
    annotation = _current_migration_policy_interpretation(item)
    assert annotation is not None
    assert annotation["recorded_status"] == "FAIL"
    assert annotation["current_policy_status"] == "PASS"
    assert annotation["interruption_tolerance"] == "OBSERVATION"
    assert len(annotation["interruption_observations"]) == 3
    assert "zero customer downtime" in annotation["interruption_tolerance_note"]
    assert annotation["recorded_verdict_rewritten"] is False
    assert item == original

    payload = {"results": [item], "run": {"final_status": "FAIL"}}
    _apply_current_offline_interpretations(payload)
    result = payload["results"][0]
    assert result["status"] == result["contract"]["verdict"]["state"] == "FAIL"
    assert result["path_signature"] == original["path_signature"]
    assert (
        result["details"]["migration_policy_interpretation"]["original_message"]
        == (original["message"])
    )
    assert "Historical FAIL verdict retained" in result["message"]
    assert "PASS + OBSERVATION" in result["message"]
    for key, value in original["details"].items():
        assert result["details"][key] == value
    assert "offline_interpretation" not in result["details"]
    assert payload["run"]["final_status"] == "FAIL"
    once = deepcopy(payload)
    _apply_current_offline_interpretations(payload)
    assert payload == once


@pytest.mark.parametrize(
    "change",
    [
        "tcp-failed",
        "tcp-evidence-missing",
        "placement-unverified",
        "completion-failed",
        "recovery-failed",
        "mixed-assessments",
        "transition-unconfirmed",
        "malformed-outcomes",
        "other-recorded-failure",
    ],
)
def test_other_failures_and_unverified_evidence_get_no_current_policy_pass(change):
    item = _historical_result(CAPTURE["windows"][0])
    transition = item["details"]["transitions"][0]
    assessment = transition["continuity_assessment"]
    if change == "tcp-failed":
        assessment["tcp"].update(survived=False, error="connection reset")
    elif change == "tcp-evidence-missing":
        assessment["tcp"].pop("server_result")
    elif change == "placement-unverified":
        assessment["completion_assessment"]["checks"].pop("placement_verified")
        assessment.pop("migration_completion_evidence")
    elif change == "completion-failed":
        assessment["migration_succeeded"] = False
    elif change == "recovery-failed":
        assessment["connectivity_recovered"] = False
        assessment["icmp"].update(recovered=False)
        assessment["udp"]["response"]["received"] = 0
    elif change == "mixed-assessments":
        failed = deepcopy(transition)
        failed["continuity_assessment"]["tcp"].update(survived=False)
        item["details"]["transitions"].append(failed)
    elif change == "malformed-outcomes":
        assessment["migration_outcomes"] = "PASS"
    elif change == "other-recorded-failure":
        assessment["continuity_failure_reasons"].append(
            "Another migration check failed"
        )
    else:
        transition["confirmed"] = False
    assert _current_migration_policy_interpretation(item) is None


@pytest.mark.parametrize(
    "check",
    [
        "task_state_cleared",
        "port_binding_verified",
        "endpoint_ready",
        "guest_marker_verified",
        "migration_record_verified",
        "volume_attachment_verified",
        "placement_verified",
    ],
)
@pytest.mark.parametrize("value", [False, None])
def test_conflicting_transition_completion_gate_prevents_current_policy_pass(
    check, value
):
    item = _historical_result(CAPTURE["windows"][0])
    item["details"]["transitions"][0][check] = value
    assert _current_migration_policy_interpretation(item) is None


def test_historical_annotations_preserve_counts_junit_and_retry_candidates(tmp_path):
    item = _historical_result(CAPTURE["windows"][0])
    sample = normalize_result_record(
        {
            "test_id": "MIGRATION-SUPPORT-SAMPLE",
            "category": "compute-placement",
            "status": "FAIL",
            "message": "Recorded migration continuity exceeded tolerance",
            "expected": "placement-achieved",
            "observed": "migration-assessed",
            "details": {
                "check_sample": True,
                "transition_check_id": item["test_id"],
                "planned_check_id": item["test_id"],
            },
        }
    )
    payload = {
        "schema_version": 1,
        "tool": "neutron-flux",
        "tool_version": "1.0.0 (prerelease)",
        "run": {
            "run_id": "historical-migration",
            "action": "run",
            "final_status": "FAIL",
        },
        "configuration": {},
        "cleanup": {"complete": True},
        "results": [sample, item],
    }
    before_targets = [
        case["target_result_id"] for case in build_replay_plan(payload)["cases"]
    ]
    source = tmp_path / "results.json"
    source.write_text(json.dumps(payload))
    original_bytes = source.read_bytes()
    _apply_current_offline_interpretations(payload)
    assert Counter(row["status"] for row in payload["results"]) == {"FAIL": 2}
    assert Counter(row["status"] for row in logical_results(payload)) == {"FAIL": 1}
    assert payload["run"]["final_status"] == "FAIL"
    assert all(
        row["details"]["migration_policy_interpretation"]["recorded_verdict_rewritten"]
        is False
        for row in payload["results"]
    )
    assert [
        case["target_result_id"] for case in build_replay_plan(payload)["cases"]
    ] == before_targets
    junit = ET.fromstring(build_junit(payload))
    # The two historical FAIL records remain canonical evidence for one failed
    # logical migration; the supporting sample is not a second CI test case.
    assert junit.attrib["tests"] == "1"
    assert junit.attrib["failures"] == "1"
    assert [case.attrib["name"] for case in junit.findall("testcase")] == [
        item["test_id"]
    ]
    assert junit.attrib["errors"] == junit.attrib["skipped"] == "0"

    written = regenerate(source, destination=tmp_path / "review", html=False)
    assert source.read_bytes() == original_bytes
    assert "PASS + OBSERVATION" in written["text"].read_text()
    assert "zero customer downtime" in written["text"].read_text()
    regenerated_junit = ET.fromstring(written["junit"].read_text())
    assert regenerated_junit.attrib["tests"] == "1"
    assert regenerated_junit.attrib["failures"] == "1"
    assert "Supporting sample [FAIL]" in written["text"].read_text()
    assert "Total saved result records: 2." in written["text"].read_text()
    assert [
        case["target_result_id"]
        for case in json.loads(written["replay_plan_json"].read_text())["cases"]
    ] == before_targets


@pytest.mark.parametrize(
    "own_evidence", ["failed", "unverified", "malformed", "nested-assessment"]
)
def test_linked_sample_with_own_failed_or_unknown_evidence_does_not_inherit_pass(
    own_evidence,
):
    parent = _historical_result(CAPTURE["windows"][0])
    continuity = deepcopy(parent["details"]["transitions"][0]["continuity_assessment"])
    if own_evidence == "failed":
        continuity["tcp"].update(survived=False, error="connection reset")
    elif own_evidence == "unverified":
        continuity["tcp"].pop("server_result")
    elif own_evidence == "malformed":
        continuity = None
    else:
        continuity["tcp"].update(survived=False, error="connection reset")
    sample = {
        "test_id": "MIGRATION-SUPPORT-WITH-OWN-EVIDENCE",
        "category": "compute-placement",
        "status": "FAIL",
        "message": "This sample has separate failed or incomplete continuity evidence",
        "expected": "placement-achieved",
        "observed": "migration-assessed",
        "details": {
            "check_sample": True,
            "transition_check_id": parent["test_id"],
            "continuity": continuity,
        },
    }
    if own_evidence == "nested-assessment":
        sample["details"]["assessment"] = {
            "continuity_assessment": sample["details"].pop("continuity")
        }
    original = deepcopy(sample)
    payload = {"results": [sample, parent]}
    _apply_current_offline_interpretations(payload)
    assert "migration_policy_interpretation" in parent["details"]
    assert "migration_policy_interpretation" not in sample["details"]
    assert sample == original
