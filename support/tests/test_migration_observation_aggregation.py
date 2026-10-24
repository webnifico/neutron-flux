"""Preserve aggregate pass/fail semantics for measured migration downtime."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from copy import deepcopy
from pathlib import Path

import pytest

from neutron_flux.execution.placement_migration import PlacementMigrationMixin
from neutron_flux.junit_report import build_junit
from neutron_flux.logical_results import logical_results
from neutron_flux.models import Plan
from neutron_flux.models import TestSpec as FluxSpec
from neutron_flux.replay_plan import build_replay_plan
from neutron_flux.reporting import Reporter
from neutron_flux.reporting_components.dashboard_model import build_dashboard_model
from neutron_flux.result_contract import (
    normalize_result_record,
    typed_verdict,
    validate_result_contract,
)
from neutron_flux.results_io import load_results

CAPTURE = json.loads(
    (
        Path(__file__).with_name("fixtures")
        / "captured_translated_migration_interruptions.json"
    ).read_text()
)
PAIR_ID = "captured-migration-host-pair"


def _result(record, *, shape="transition", failed=False):
    continuity = deepcopy(record["continuity"])
    if failed:
        continuity["tcp"].update(survived=False, error="connection reset")
    status, observed, message, assessment = (
        PlacementMigrationMixin._live_continuity_verdict(continuity)
    )
    details = {
        "operation": "live-migration",
        "host_qualification_pair_id": PAIR_ID,
        "host_qualification_cycle": 1,
        "requested_source_host": "hyper003",
        "requested_destination_host": "hyper004",
        "source_compute_host": "hyper003",
        "destination_compute_host": "hyper003",
        "source_availability_zone": "az1",
        "destination_availability_zone": "az1",
    }
    if shape == "support":
        details.update(assessment)
    else:
        details["transitions"] = [{"continuity_assessment": assessment}]
    return {
        "test_id": record["check_id"],
        "category": "compute-placement",
        "status": status,
        "family": 4,
        "source": "az1/source (192.0.2.10)",
        "destination": "az1/target (192.0.2.20)",
        "message": message,
        "details": details,
        "expected": "placement-achieved",
        "observed": observed,
        "authoritative": True,
        "scenario": "Compute migration and placement lifecycle",
    }


def _assessment(result, shape):
    details = result["details"]
    if shape == "support":
        return details
    return details["transitions"][0]["continuity_assessment"]


def _payload(results):
    return {
        "schema_version": 1,
        "tool": "neutron-flux",
        "tool_version": "1.0.0 (prerelease)",
        "run": {
            "run_id": "migration-observation-aggregation",
            "action": "run",
            "final_status": "FAIL"
            if any(row["status"] == "FAIL" for row in results)
            else "PASS",
        },
        "configuration": {},
        "cleanup": {"attempted": True, "complete": True},
        "setup_failures": [],
        "results": results,
        "plan": {
            "host_qualification": {
                "enabled": True,
                "profile": "full",
                "pairs": [
                    {
                        "pair_id": PAIR_ID,
                        "source_host": "hyper003",
                        "destination_host": "hyper004",
                        "same_availability_zone": True,
                        "status": "PLANNED",
                    }
                ],
            }
        },
    }


@pytest.mark.parametrize("shape", ["support", "transition"])
@pytest.mark.parametrize("record", CAPTURE["windows"], ids=lambda row: row["check_id"])
def test_observed_interruption_keeps_completed_passing_typed_contract(record, shape):
    raw = _result(record, shape=shape)
    original = deepcopy(raw)
    result = normalize_result_record(raw)
    assessment = _assessment(result, shape)
    assert result["status"] == typed_verdict(result) == "PASS"
    assert result["contract"]["type"] == "migration-continuity"
    assert result["contract"]["verdict"]["outcome"] == "met"
    assert result["contract"]["execution"] == {
        "state": "completed",
        "complete": True,
    }
    assert assessment["migration_outcomes"]["interruption_tolerance"] == "OBSERVATION"
    assert len(assessment["interruption_observations"]) == 3
    assert assessment["continuity_failure_reasons"] == []
    validate_result_contract(
        result["contract"],
        status=result["status"],
        expected=result["expected"],
        observed=result["observed"],
        authoritative=result["authoritative"],
    )
    assert normalize_result_record(result) == result
    assert raw == original


@pytest.mark.parametrize("shape", ["support", "transition"])
def test_reporter_finalization_counts_observed_interruptions_as_passes(
    config_factory, shape
):
    reporter = Reporter(config_factory(action="run"), f"migration-observations-{shape}")
    reporter.plan = Plan([], [], {}, [], tests=[])
    reporter.cleanup_summary.update(attempted=True, complete=True)
    for record in CAPTURE["windows"]:
        reporter.result(**_result(record, shape=shape))
    assert reporter.finalize(0) == 0
    payload = json.loads(reporter.results_path.read_text())
    assert payload["run"]["final_status"] == "PASS WITH WARNINGS"
    assert (
        load_results(reporter.results_path)["run"]["final_status"]
        == "PASS WITH WARNINGS"
    )
    assert payload["summary"]["counts"] == {"PASS": 2}
    assert all(typed_verdict(row) == "PASS" for row in logical_results(payload))
    junit = ET.fromstring(reporter.junit_report_path.read_text())
    assert junit.attrib["tests"] == "2"
    assert junit.attrib["failures"] == junit.attrib["errors"] == "0"
    assert junit.attrib["skipped"] == "0"
    assert junit.findall("testcase/failure") == []
    assert json.loads(reporter.replay_plan_path.read_text())["cases"] == []


@pytest.mark.parametrize("shape", ["support", "transition"])
def test_supporting_observation_does_not_override_clean_terminal_check(
    config_factory, tmp_path, shape
):
    sample = _result(CAPTURE["windows"][0], shape=shape)
    sample["details"].update(planned_check_id="FINAL-CHECK", check_sample=True)
    terminal = {
        "test_id": "FINAL-PROBE",
        "category": "same-subnet",
        "status": "PASS",
        "message": "Current functional matrix passed",
        "expected": "reachable",
        "observed": "reachable",
        "details": {"planned_check_id": "FINAL-CHECK"},
    }
    specs = [
        FluxSpec(
            id=row["test_id"],
            category=row["category"],
            operation="probe",
            family=4,
            expectation="reachable",
            expectation_reason="Required current matrix",
            authoritative=True,
            dependencies=[],
            display_name=row["test_id"],
            metadata=row["details"],
        )
        for row in (sample, terminal)
    ]
    reporter = Reporter(
        config_factory(action="run", report_dir=tmp_path / "reports"),
        f"sample-observation-{shape}",
    )
    reporter.plan = Plan(
        [],
        [],
        {},
        [],
        tests=specs,
        checks=[
            {
                "id": "FINAL-CHECK",
                "title": "Current matrix",
                "kind": "network",
                "category": "same-subnet",
                "stage": "initial",
                "condition": "Current matrix passes",
                "prerequisites": [],
            }
        ],
    )
    reporter.cleanup_summary.update(attempted=True, complete=True)
    try:
        reporter.result(**sample)
        reporter.result(**terminal)
        assert reporter.finalize(0) == 0
        payload = json.loads(reporter.results_path.read_text())
        assert payload["run"]["final_status"] == "PASS"
        assert load_results(reporter.results_path)["run"]["final_status"] == "PASS"
        assert len(payload["results"]) == 2
        assert [row["test_id"] for row in logical_results(payload)] == ["FINAL-PROBE"]
        assert payload["planned_check_ledger"][0]["outcome"] == "PASSED"
        assert reporter._performance_warning_count() == 0
    finally:
        reporter.logger.close()


@pytest.mark.parametrize("shape", ["support", "transition"])
def test_host_pair_and_replay_counts_keep_only_real_failure(shape):
    passed = _result(CAPTURE["windows"][0], shape=shape)
    all_passes = _payload([passed, _result(CAPTURE["windows"][1], shape=shape)])
    pair = build_dashboard_model(all_passes)["host_qualification"]["pairs"][0]
    assert pair["status_counts"] == {"PASS": 2}
    assert pair["finding_count"] == 0
    assert build_replay_plan(all_passes)["cases"] == []

    failed = _result(CAPTURE["windows"][1], shape=shape, failed=True)
    assert failed["status"] == "FAIL"
    assert _assessment(failed, shape)["migration_outcomes"]["tcp_session"] == "FAIL"
    mixed = _payload([passed, failed])
    pair = build_dashboard_model(mixed)["host_qualification"]["pairs"][0]
    assert pair["status_counts"] == {"PASS": 1, "FAIL": 1}
    assert pair["finding_count"] == 1
    assert [row["target_result_id"] for row in build_replay_plan(mixed)["cases"]] == [
        failed["test_id"]
    ]
    junit = ET.fromstring(build_junit(mixed))
    assert junit.attrib["tests"] == "2"
    assert junit.attrib["failures"] == "1"
    assert junit.attrib["errors"] == junit.attrib["skipped"] == "0"
    assert [
        case.attrib["name"]
        for case in junit.findall("testcase")
        if case.find("failure") is not None
    ] == [failed["test_id"]]


@pytest.mark.parametrize("shape", ["support", "transition"])
def test_reporter_real_transport_failure_remains_fatal(config_factory, shape):
    reporter = Reporter(config_factory(action="run"), f"migration-failure-{shape}")
    reporter.plan = Plan([], [], {}, [], tests=[])
    reporter.cleanup_summary.update(attempted=True, complete=True)
    reporter.result(**_result(CAPTURE["windows"][0], shape=shape))
    failed = _result(CAPTURE["windows"][1], shape=shape, failed=True)
    reporter.result(**failed)
    assert reporter.finalize(0) == 1
    payload = json.loads(reporter.results_path.read_text())
    assert payload["run"]["final_status"] == "FAIL"
    assert payload["summary"]["counts"] == {"FAIL": 1, "PASS": 1}
    assert [
        row["target_result_id"]
        for row in json.loads(reporter.replay_plan_path.read_text())["cases"]
    ] == [failed["test_id"]]
