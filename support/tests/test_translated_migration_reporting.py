"""Replay supplied translated-path interruptions and expected isolation phases."""

from __future__ import annotations

import json
from collections import Counter
from copy import deepcopy
from pathlib import Path

import pytest

from neutron_flux.constants import MIGRATION_DOWNTIME_TOLERANCE_NOTE
from neutron_flux.execution.placement_migration import PlacementMigrationMixin
from neutron_flux.logical_results import logical_results
from neutron_flux.operator_explanations import explain_result, explanation_lines
from neutron_flux.reporting_components.dashboard_model import build_dashboard_model
from neutron_flux.reporting_components.html import render_html
from neutron_flux.result_contract import normalize_result_record
from support.tests.test_report_workflow import _embedded_payload, _payload

CAPTURE = json.loads(
    (
        Path(__file__).with_name("fixtures")
        / "captured_translated_migration_interruptions.json"
    ).read_text()
)


@pytest.mark.parametrize("record", CAPTURE["windows"], ids=lambda row: row["check_id"])
def test_captured_interruptions_keep_measurements_as_tolerance_observations(record):
    original = deepcopy(record["continuity"])
    status, _, message, assessment = PlacementMigrationMixin._live_continuity_verdict(
        original
    )
    assert original == record["continuity"]
    assert record["status"] == "FAIL"
    assert status == "PASS"
    assert assessment["migration_outcomes"] == {
        **record["outcomes"],
        "interruption_tolerance": "OBSERVATION",
    }
    assert assessment["evidence_complete"] is True
    assert assessment["phase_evidence_complete"] is True
    assert assessment["receiver_delivery_verified"] is True
    assert not assessment["transport_failure_reasons"]
    assert assessment["evaluated_thresholds"] == {
        "icmp_loss_pct": 1.0,
        "udp_loss_pct": 1.0,
        "outage_lower_bound_s": 1.0,
    }
    assert len(assessment["tolerance_failure_reasons"]) == 3
    assert (
        assessment["interruption_observations"]
        == assessment["tolerance_failure_reasons"]
    )
    assert assessment["interruption_tolerance_note"] == (
        MIGRATION_DOWNTIME_TOLERANCE_NOTE
    )
    assert "sampled failed-observation span" in message
    assert "confirmed outage" not in message
    phases = assessment["phase_evidence"]["phases"]
    for protocol in ("icmp", "udp"):
        assert phases["migration"][protocol]["lost"] > 0
        assert phases["post_migration"][protocol]["lost"] == 0
    result = {
        "test_id": record["check_id"],
        "category": "compute-placement",
        "status": status,
        "message": message,
        "details": {"transitions": [{"continuity_assessment": assessment}]},
    }
    story = explain_result(result)
    assert story["kind"] == "migration-interruption-observation"
    assert all(
        reason in story["what_happened"]
        for reason in assessment["tolerance_failure_reasons"]
    )
    assert "continuous physical outage" in " ".join(story["limitations"])
    for phase in ("Migration", "Post-migration"):
        assert any(
            row["label"] == f"{phase} UDP datagrams not delivered"
            for row in story["facts"]
        )


def _recorded_failure(record):
    assessment = deepcopy(record["continuity"])
    assessment.update(
        migration_outcomes=deepcopy(record["outcomes"]),
        tolerance_failure_reasons=deepcopy(record["reasons"]),
        transport_failure_reasons=[],
    )
    return {
        "test_id": record["check_id"],
        "category": "compute-placement",
        "status": "FAIL",
        "expected": "placement-achieved",
        "observed": "migration-assessed",
        "message": "placement verified; VM placement=PASS; interruption tolerance=FAIL",
        "details": {"transitions": [{"continuity_assessment": assessment}]},
    }


def _observation_pass():
    result = _recorded_failure(CAPTURE["windows"][0])
    result["status"] = "PASS"
    result["expected"] = "requested-placement-verified"
    result["observed"] = "requested-placement-verified"
    result["message"] = "Migration completed and traffic recovered"
    assessment = result["details"]["transitions"][0]["continuity_assessment"]
    assessment["migration_outcomes"]["interruption_tolerance"] = "OBSERVATION"
    assessment["interruption_observations"] = [
        reason.replace("ICMP loss", "ICMP failed observations").replace(
            "confirmed outage lower bound", "sampled failed-observation span"
        )
        for reason in assessment["tolerance_failure_reasons"]
    ]
    assessment["interruption_tolerance_note"] = MIGRATION_DOWNTIME_TOLERANCE_NOTE
    assessment["health"] = "good"
    return result


@pytest.mark.parametrize("shape", ["transitions", "continuity", "direct"])
def test_observation_pass_retains_pass_with_warning_emphasis(shape):
    result = _observation_pass()
    assessment = result["details"]["transitions"][0]["continuity_assessment"]
    if shape != "transitions":
        result["details"] = assessment if shape == "direct" else {shape: assessment}
    original = deepcopy(result)
    story = explain_result(result)
    assert story["kind"] == "migration-interruption-observation"
    assert story["attention"] is True
    assert story["interruption_tolerance_note"] == MIGRATION_DOWNTIME_TOLERANCE_NOTE
    lines = "\n".join(explanation_lines(result))
    assert "[OBSERVATION] Above tolerance" in lines
    assert MIGRATION_DOWNTIME_TOLERANCE_NOTE in lines
    payload = _payload()
    payload["results"] = [result]
    model = build_dashboard_model(payload)
    assert model["findings"] == []
    assert model["summary"]["result_counts"] == {"PASS": 1}
    html = render_html(payload)
    row = _embedded_payload(html)["dashboard"]["results"][0]
    assert row["status"] == "PASS"
    assert row["severity"] == "warning"
    assert "[OBSERVATION]" in row["message"]
    assert row["operator_explanation"]["interruption_observations"]
    assert result == original


@pytest.mark.parametrize(
    "component",
    ["vm_placement", "migration_completion", "tcp_session", "traffic_recovery"],
)
@pytest.mark.parametrize("component_status", ["FAIL", "UNVERIFIED"])
@pytest.mark.parametrize("reverse", [False, True])
def test_mixed_observation_components_do_not_claim_successful_migration(
    component, component_status, reverse
):
    result = _observation_pass()
    mixed = deepcopy(result["details"]["transitions"][0])
    mixed["continuity_assessment"]["migration_outcomes"][component] = component_status
    result["details"]["transitions"].append(mixed)
    if reverse:
        result["details"]["transitions"].reverse()
    story = explain_result(result)
    assert story["kind"] != "migration-interruption-observation"
    assert "TCP session and traffic recovery passed" not in story["why_this_status"]


def test_historical_current_policy_annotation_keeps_recorded_failure():
    result = _recorded_failure(CAPTURE["windows"][0])
    result["details"]["migration_policy_interpretation"] = {
        "recorded_status": "FAIL",
        "current_policy_status": "PASS",
        "interruption_tolerance": "OBSERVATION",
        "interruption_observations": deepcopy(CAPTURE["windows"][0]["reasons"]),
        "interruption_tolerance_note": MIGRATION_DOWNTIME_TOLERANCE_NOTE,
        "recorded_verdict_rewritten": False,
    }
    original = deepcopy(result)
    story = explain_result(result)
    assert story["kind"] == "interruption-tolerance-exceeded"
    assert "Historical FAIL retained" in story["what_happened"]
    assert story["current_policy_interruption_observations"]
    payload = _payload()
    payload["results"] = [result]
    model = build_dashboard_model(payload)
    assert model["summary"]["result_counts"] == {"FAIL": 1}
    assert model["findings"][0]["root_key"] == "migration-interruption"
    assert result == original


def test_historical_report_exposes_failure_cause_without_rewriting_evidence():
    payload = _payload()
    payload["results"] = [_recorded_failure(row) for row in CAPTURE["windows"]]
    payload["run"]["final_status"] = "FAIL"
    original = deepcopy(payload)
    model = build_dashboard_model(payload)
    assert len(model["findings"]) == 1
    finding = model["findings"][0]
    assert finding["root_key"] == "migration-interruption"
    assert finding["title"] == "Traffic recovered; interruption exceeded tolerance"
    assert "2 migration checks exceeded interruption limits" in finding["summary"]
    assert len(finding["measurements"]) == 2
    report = _embedded_payload(render_html(payload))
    for test in report["dashboard"]["results"]:
        assert test["status"] == "FAIL"
        assert "ICMP failed observations" in test["message"]
        assert "UDP application-delivery loss" in test["message"]
        assert "sampled failed-observation span" in test["message"]
        assert "confirmed outage" not in test["message"]
    assert payload == original


@pytest.mark.parametrize(
    "component",
    ["vm_placement", "migration_completion", "tcp_session", "traffic_recovery"],
)
@pytest.mark.parametrize("status", ["FAIL", "UNVERIFIED"])
def test_missing_or_failed_components_are_not_described_as_successful(
    component, status
):
    result = _recorded_failure(CAPTURE["windows"][0])
    result["details"]["transitions"][0]["continuity_assessment"]["migration_outcomes"][
        component
    ] = status
    assert explain_result(result)["kind"] != "interruption-tolerance-exceeded"


@pytest.mark.parametrize(
    "component",
    ["vm_placement", "migration_completion", "tcp_session", "traffic_recovery"],
)
@pytest.mark.parametrize("status", ["FAIL", "UNVERIFIED"])
@pytest.mark.parametrize("reverse", [False, True])
def test_mixed_transition_components_keep_generic_failure_story(
    component, status, reverse
):
    result = _recorded_failure(CAPTURE["windows"][0])
    mixed = deepcopy(result["details"]["transitions"][0])
    mixed["continuity_assessment"]["migration_outcomes"][component] = status
    result["details"]["transitions"].append(mixed)
    if reverse:
        result["details"]["transitions"].reverse()
    original = deepcopy(result)
    story = explain_result(result)
    assert story["kind"] == "check-failed"
    assert "established TCP session passed" not in story["why_this_status"]
    assert result == original


@pytest.mark.parametrize("reverse", [False, True])
def test_transport_failure_in_any_assessment_prevents_interruption_only_story(reverse):
    result = _recorded_failure(CAPTURE["windows"][0])
    mixed = deepcopy(result["details"]["transitions"][0])
    mixed["continuity_assessment"]["transport_failure_reasons"] = [
        "UDP continuity failed: recorded socket error"
    ]
    result["details"]["transitions"].append(mixed)
    if reverse:
        result["details"]["transitions"].reverse()
    assert explain_result(result)["kind"] == "check-failed"


@pytest.mark.parametrize("reverse", [False, True])
def test_mixed_assessments_preserve_migration_finding_and_failure_report(reverse):
    result = _recorded_failure(CAPTURE["windows"][0])
    mixed = deepcopy(result["details"]["transitions"][0])
    mixed["continuity_assessment"]["migration_outcomes"]["tcp_session"] = "FAIL"
    mixed["continuity_assessment"]["transport_failure_reasons"] = [
        "the established TCP session did not complete"
    ]
    result["details"]["transitions"].append(mixed)
    if reverse:
        result["details"]["transitions"].reverse()
    result["message"] = (
        "VM placement passed; the established TCP session did not complete; "
        "interruption exceeded limits"
    )
    payload = _payload()
    payload["results"] = [result]
    original = deepcopy(payload)
    model = build_dashboard_model(payload)
    assert model["findings"][0]["root_key"] == "migration"
    assert "TCP session did not complete" in model["findings"][0]["summary"]
    test = _embedded_payload(render_html(payload))["dashboard"]["results"][0]
    assert test["status"] == "FAIL"
    assert test["operator_explanation"]["kind"] == "check-failed"
    assert "TCP session did not complete" in test["message"]
    assert payload == original


def test_several_interruption_assessments_report_every_exceeded_limit():
    result = _recorded_failure(CAPTURE["windows"][0])
    other = _recorded_failure(CAPTURE["windows"][1])
    result["details"]["transitions"].extend(other["details"]["transitions"])
    original = deepcopy(result)
    story = explain_result(result)
    assert story["kind"] == "interruption-tolerance-exceeded"
    for transition in result["details"]["transitions"]:
        for reason in transition["continuity_assessment"]["tolerance_failure_reasons"]:
            clarified = reason.replace("ICMP loss", "ICMP failed observations").replace(
                "confirmed outage lower bound", "sampled failed-observation span"
            )
            assert clarified in story["what_happened"]
    payload = _payload()
    payload["results"] = [result]
    assert build_dashboard_model(payload)["findings"][0]["root_key"] == (
        "migration-interruption"
    )
    report = _embedded_payload(render_html(payload))
    test = report["dashboard"]["results"][0]
    assert test["status"] == "FAIL"
    message = test["message"]
    if isinstance(message, dict):
        message = report["evidence_pool"]["strings"][message["$neutron_flux_evidence"]]
    assert "2.000s exceeded 1.000s" in message
    assert "1.750s exceeded 1.000s" in message
    assert result == original


@pytest.mark.parametrize("result", CAPTURE["blocked"], ids=lambda row: row["test_id"])
def test_captured_blocked_traffic_is_explicitly_expected(result):
    original = deepcopy(result)
    story = explain_result(result)
    assert story["kind"] in {"expected-isolation", "expected-withdrawal"}
    assert "blocked as intended" in story["headline"]
    assert "intended block was observed" in story["why_this_status"]
    rendered = "\n".join(explanation_lines(result))
    assert "Purpose:" in rendered and "Path:" in rendered
    assert "Actual result:" in rendered and "deliberately unavailable" in rendered
    assert result == original


@pytest.mark.parametrize(
    "status", ["FAIL", "ERROR", "UNVERIFIED", "BLOCKED_BY_SETUP_ERROR"]
)
def test_failed_or_unverified_isolation_is_never_called_expected(status):
    result = deepcopy(CAPTURE["blocked"][0])
    result["status"] = status
    assert not explain_result(result)["kind"].startswith("expected-")


def test_unexpected_blocking_is_not_presented_as_expected():
    result = deepcopy(CAPTURE["blocked"][0])
    result["expected"] = "reachable"
    assert not explain_result(result)["kind"].startswith("expected-")


@pytest.mark.parametrize(
    "category,expected,contract_type",
    [
        ("security-group", "blocked", "security-group-isolation"),
        ("router-static-routing", "blocked", "static-routing"),
        ("router-static-routing", "withdrawn", "static-routing"),
        ("project-provider-connectivity", "blocked", "connectivity"),
        ("floating-ip-lifecycle", "withdrawn", "floating-ip-translation"),
        ("server-lifecycle", "withdrawn", "lifecycle-continuity"),
    ],
)
def test_blocked_observation_does_not_invent_security_group_attribution(
    category, expected, contract_type
):
    result = normalize_result_record(
        {
            "test_id": "STATIC-ROUTE-PHASE"
            if category == "router-static-routing"
            else "PHASE-CHECK",
            "category": category,
            "status": "PASS",
            "expected": expected,
            "observed": "blocked",
            "details": {},
        }
    )
    assert result["contract"]["type"] == contract_type
    if expected == "withdrawn":
        assert (
            "routing attachment" not in result["contract"]["expectation"]["description"]
        )


def test_captured_run_has_two_logical_failures_not_four():
    payload = deepcopy(CAPTURE["accounting"])
    assert Counter(row["status"] for row in payload["results"]) == {
        "PASS": 462,
        "FAIL": 4,
    }
    assert Counter(row["status"] for row in logical_results(payload)) == {
        "PASS": 350,
        "FAIL": 2,
    }


@pytest.mark.parametrize(
    "record", CAPTURE["legacy_results"], ids=lambda row: row["category"]
)
def test_historical_contracts_remain_readable_with_verdicts_and_inputs_intact(record):
    original = deepcopy(record)
    normalized = normalize_result_record(record)
    assert normalized["status"] == record["status"] == "PASS"
    assert normalized["contract"]["verdict"] == record["contract"]["verdict"]
    assert normalized["expected"] == record["expected"]
    assert normalized["observed"] == record["observed"]
    if record["category"] == "router-static-routing":
        assert record["contract"]["type"] == "security-group-isolation"
        assert normalized["contract"]["type"] == "static-routing"
        assert (
            normalized["path_signature"]["identity"]["contract_type"]
            == "static-routing"
        )
    assert normalize_result_record(normalized) == normalized
    assert record == original


@pytest.mark.parametrize(
    "field", ["description", "verdict", "path_signature_key", "endpoint", "signature"]
)
def test_legacy_classification_upgrade_does_not_accept_contradictory_contracts(field):
    record = deepcopy(
        next(
            row
            for row in CAPTURE["legacy_results"]
            if row["category"] == "router-static-routing"
        )
    )
    if field == "description":
        record["contract"]["description"] = "Unrecorded interpretation"
    elif field == "verdict":
        record["contract"]["verdict"]["state"] = "FAIL"
    elif field == "path_signature_key":
        record["contract"][field] = "sha256:" + "0" * 64
    elif field == "endpoint":
        record["contract"]["source"]["display"] = "Different endpoint"
    else:
        record["path_signature"]["key"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError):
        normalize_result_record(record)
