from __future__ import annotations

import copy
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter

import pytest

from neutron_flux.errors import SuiteError
from neutron_flux.junit_report import build_junit
from neutron_flux.logical_results import logical_results
from neutron_flux.offline_reports import regenerate
from neutron_flux.report_exports import render_incident_summary
from neutron_flux.reporting_components.dashboard_model import build_dashboard_model
from neutron_flux.reporting_components.report_payload import build_report_payload
from neutron_flux.results_io import load_results, render_results_text


def _check(identity, outcome, result_id=None, evidence_ids=()):
    return {
        "id": identity,
        "title": f"Validate path {identity}",
        "kind": "network",
        "category": "same-subnet",
        "stage": "group-local",
        "condition": "Required topology and prerequisites are available",
        "reason": "Recorded terminal assessment"
        if result_id
        else "Run cancelled before execution",
        "prerequisites": [],
        "outcome": outcome,
        "result_id": result_id,
        "evidence_ids": list(evidence_ids),
    }


def _row(identity, *, status="PASS", check="PATH-A", sample=False, tool_failure=False):
    return {
        "test_id": identity,
        "category": "same-subnet",
        "display_name": "Validate TCP delivery",
        "status": status,
        "expected": "reachable",
        "observed": "reachable" if status == "PASS" else "blocked",
        "message": "Fresh-flow terminal assessment"
        if not sample
        else "Earlier supporting observation",
        "authoritative": True,
        "details": {
            "planned_check_id": check,
            "check_sample": sample,
            "tool_failure": tool_failure,
        },
    }


def _payload(*, cancelled=0, sample_status="FAIL"):
    rows = [
        _row("PATH-A-FIRST", status=sample_status, sample=True),
        _row("PATH-A-FINAL"),
    ]
    checks = [
        _check("PATH-A", "PASSED", "PATH-A-FINAL", [row["test_id"] for row in rows])
    ]
    checks.extend(
        _check(f"PATH-CANCELLED-{index}", "CANCELLED") for index in range(cancelled)
    )
    return {
        "schema_version": 1,
        "run": {
            "run_id": "logical-checks",
            "action": "run",
            "final_status": "CANCELLED" if cancelled else "PASS",
        },
        "results": rows,
        "planned_check_ledger": checks,
        "plan": {
            "checks": [
                {
                    key: value
                    for key, value in check.items()
                    if key not in {"outcome", "result_id", "evidence_ids", "reason"}
                }
                for check in checks
            ],
            "tests": [],
        },
        "summary": {
            "counts": dict(Counter(row["status"] for row in rows)),
            "total_results": len(rows),
        },
        "cleanup": {"attempted": True, "complete": True},
    }


def _write(tmp_path, payload):
    path = tmp_path / "results.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _text_count(text, label):
    return int(re.search(rf"^{re.escape(label)}\s+(\d+)$", text, re.MULTILINE).group(1))


def test_confirmed_retry_pass_regenerates_without_discarding_failed_sample(tmp_path):
    payload = _payload()
    source = _write(tmp_path, payload)
    before = source.read_bytes()
    loaded = load_results(source)
    assert [row["status"] for row in loaded["results"]] == ["FAIL", "PASS"]
    written = regenerate(source, destination=tmp_path / "rendered", junit=True)
    assert source.read_bytes() == before
    assert written["html"].is_file()
    assert _text_count(render_results_text(loaded), "Total tests") == 1
    assert "Supporting sample [FAIL]" in render_results_text(loaded)
    suite = ET.fromstring(build_junit(loaded))
    assert suite.attrib["tests"] == "1"
    assert suite.attrib["failures"] == "0"
    assert suite.find("testcase").attrib["name"] == "PATH-A-FINAL"


@pytest.mark.parametrize("cancelled", [1, 8])
def test_fixed_inventory_remains_visible_when_cancelled_checks_have_no_probe_records(
    tmp_path, cancelled
):
    payload = _payload(cancelled=cancelled)
    original = copy.deepcopy(payload)
    loaded = load_results(_write(tmp_path, payload))
    text = render_results_text(loaded)
    loaded["dashboard"] = build_dashboard_model(loaded)
    report = build_report_payload(loaded)
    report_statuses = Counter(row["status"] for row in report["dashboard"]["results"])
    assert report_statuses == {"PASS": 1, "NOT_RUN_CANCELLED": cancelled}
    assert _text_count(text, "Total tests") == 1 + cancelled
    assert _text_count(text, "Did not run: cancelled") == cancelled
    assert "Supporting or retry records: 1" in text
    assert "Total saved result records: 2." in text
    assert "Supporting or retry records: -" not in text
    assert text.count("[NOT_RUN_CANCELLED]") == cancelled
    incident = render_incident_summary(loaded)
    assert (
        f"Planned checks: {1 + cancelled} total; CANCELLED={cancelled}, PASSED=1"
        in incident
    )
    assert "Evidence records: 2 total; FAIL=1, PASS=1" in incident
    suite = ET.fromstring(build_junit(loaded))
    assert int(suite.attrib["tests"]) == 2 + cancelled  # includes run cancellation
    assert int(suite.attrib["skipped"]) == 1 + cancelled
    assert payload == original


@pytest.mark.parametrize(
    "mutation",
    [
        "false_pass",
        "missing_evidence",
        "missing_check",
        "wrong_binding",
        "duplicate_check",
    ],
)
def test_saved_inventory_cannot_hide_terminal_failure_or_lose_evidence(
    tmp_path, mutation
):
    payload = _payload()
    check = payload["planned_check_ledger"][0]
    if mutation == "false_pass":
        payload["results"][1]["status"] = "FAIL"
        payload["summary"]["counts"] = {"FAIL": 2}
    elif mutation == "missing_evidence":
        check["evidence_ids"].remove("PATH-A-FIRST")
    elif mutation == "missing_check":
        payload["planned_check_ledger"][0]["id"] = "OTHER-CHECK"
    elif mutation == "wrong_binding":
        payload["results"][0]["details"]["planned_check_id"] = "OTHER-CHECK"
    else:
        payload["planned_check_ledger"].append(copy.deepcopy(check))
    with pytest.raises(SuiteError):
        load_results(_write(tmp_path, payload))


def test_supporting_tool_error_remains_fatal_even_if_parent_check_passed(tmp_path):
    payload = _payload(sample_status="ERROR")
    payload["results"][0]["details"]["tool_failure"] = True
    with pytest.raises(SuiteError, match="contradicts"):
        load_results(_write(tmp_path, payload))


def test_legacy_ledger_alias_does_not_duplicate_the_same_terminal_result():
    payload = _payload(sample_status="PASS")
    for row in payload["results"]:
        row["details"].pop("planned_check_id")
    assert [row["test_id"] for row in logical_results(payload)] == ["PATH-A-FINAL"]
    assert _text_count(render_results_text(payload), "Total tests") == 1


def test_read_only_normalization_shares_evidence_but_default_remains_isolated():
    from neutron_flux.result_contract import normalize_result_record

    row = _row("PATH-A-FINAL")
    row["details"]["samples"] = [{"sequence": 1, "received": True}]
    original = copy.deepcopy(row)
    shared = normalize_result_record(row, share_evidence=True)
    isolated = normalize_result_record(row)
    assert shared == isolated
    assert shared["details"] is row["details"]
    assert isolated["details"] is not row["details"]
    isolated["details"]["samples"][0]["received"] = False
    assert row == original
    assert shared["contract"] is not row.get("contract")


def test_read_only_legacy_translation_copies_only_affected_branches():
    from neutron_flux.result_contract import normalize_result_record

    row = _row("PATH-A-FINAL")
    row["details"]["raw_samples"] = [{"sequence": 1}]
    row["details"]["mutation_outcome"] = "completed"
    original = copy.deepcopy(row)
    shared = normalize_result_record(row, share_evidence=True)
    isolated = normalize_result_record(row)
    assert shared == isolated
    assert shared["details"] is not row["details"]
    assert shared["details"]["raw_samples"] is row["details"]["raw_samples"]
    assert "cloud_operation_outcome" in shared["details"]
    assert row == original


def test_captured_dashboard_and_junit_are_identical_with_borrowed_evidence(monkeypatch):
    from pathlib import Path

    from neutron_flux.reporting_components import dashboard_model
    from neutron_flux.result_contract import normalize_result_record

    capture = json.loads(
        Path(__file__)
        .with_name("fixtures")
        .joinpath("captured_pair_reporting_context.json")
        .read_text()
    )
    original = copy.deepcopy(capture)
    borrowed = json.dumps(build_dashboard_model(capture), sort_keys=True)
    borrowed_junit = build_junit(capture)
    monkeypatch.setattr(
        dashboard_model,
        "normalize_result_record",
        lambda row, **kwargs: normalize_result_record(row),
    )
    monkeypatch.setattr(
        "neutron_flux.junit_report.normalize_result_record",
        lambda row, **kwargs: normalize_result_record(row),
    )
    assert json.dumps(build_dashboard_model(capture), sort_keys=True) == borrowed
    assert build_junit(capture) == borrowed_junit
    assert capture == original


def test_runtime_summary_and_offline_outputs_keep_conditional_cancelled_inventory(
    config_factory, tmp_path
):
    from neutron_flux.check_ledger import resolve_checks
    from neutron_flux.models import Plan
    from neutron_flux.models import TestSpec as FluxSpec
    from neutron_flux.reporting import Reporter

    payload = _payload(cancelled=2)
    specs = [
        FluxSpec(
            id=row["test_id"],
            category=row["category"],
            operation="probe",
            family=4,
            expectation="reachable",
            expectation_reason="Recorded network contract",
            authoritative=True,
            dependencies=[],
            display_name=row["display_name"],
            metadata=row["details"],
        )
        for row in payload["results"]
    ]
    reporter = Reporter(
        config_factory(action="run", report_dir=tmp_path / "reports"),
        "conditional-cancellation",
    )
    reporter.plan = Plan([], [], {}, [], tests=specs, checks=payload["plan"]["checks"])
    try:
        for row in payload["results"]:
            reporter.result(
                row["test_id"],
                row["category"],
                row["status"],
                row["message"],
                expected=row["expected"],
                observed=row["observed"],
                details=row["details"],
            )
        resolve_checks(
            reporter,
            {
                f"PATH-CANCELLED-{index}": (
                    "CANCELLED",
                    "Run cancelled before execution",
                )
                for index in range(2)
            },
        )
        reporter.interrupted = True
        reporter.cancellation_reason = "operator cancellation"
        reporter.cleanup_summary.update({"attempted": True, "complete": True})
        assert reporter._category_summary()["same-subnet"] == {
            "PASS": 1,
            "NOT_RUN_CANCELLED": 2,
        }
        assert reporter.finalize(130) == 130
        loaded = load_results(reporter.results_path)
        assert len(loaded["planned_check_ledger"]) == 3
        assert len(loaded["results"]) == 2
        assert [row["status"] for row in loaded["results"]] == ["FAIL", "PASS"]
        text = reporter.report_path.read_text()
        assert "Checks planned (fixed):                3" in text
        assert "3 tests; 1 supporting record" in text
        assert _text_count(render_results_text(loaded), "Total tests") == 3
    finally:
        reporter.logger.close()


def test_unavailable_placement_is_blocked_without_rewriting_raw_unverified_contract(
    tmp_path,
):
    payload = _payload()
    payload["run"]["final_status"] = "INCOMPLETE"
    row = payload["results"][1]
    row.update(
        status="UNVERIFIED",
        observed="placement-unavailable",
        category="compute-placement",
    )
    payload["planned_check_ledger"][0]["outcome"] = "BLOCKED"
    payload["summary"]["counts"] = {"FAIL": 1, "UNVERIFIED": 1}
    loaded = load_results(_write(tmp_path, payload))
    before = copy.deepcopy(loaded)
    suite = ET.fromstring(build_junit(loaded))
    assert suite.attrib["tests"] == "2"  # logical check plus incomplete-run error
    assert suite.attrib["skipped"] == "1"
    assert suite.find("testcase/skipped") is not None
    text = render_results_text(loaded)
    assert _text_count(text, "Did not run: prerequisite") == 1
    assert _text_count(text, "Could not verify") == 0
    assert loaded["results"][1]["contract"]["verdict"]["state"] == "UNVERIFIED"
    assert loaded == before


@pytest.mark.parametrize(
    "field,value", [("outcome", []), ("result_id", []), ("evidence_ids", 0)]
)
def test_malformed_ledger_fields_raise_input_error_instead_of_indexing_exception(
    tmp_path, field, value
):
    payload = _payload()
    payload["planned_check_ledger"][0][field] = value
    with pytest.raises(SuiteError):
        load_results(_write(tmp_path, payload))


def test_recorded_host_discovery_resolution_is_pass_without_an_invented_probe(
    config_factory, tmp_path
):
    from neutron_flux.check_ledger import resolve_checks
    from neutron_flux.models import Plan
    from neutron_flux.reporting import Reporter

    check = _check("HOST-DISCOVERY", "PENDING")
    check.update(
        kind="migration",
        category="compute-placement",
        title="Discover endpoint compute hosts",
    )
    reporter = Reporter(
        config_factory(action="run", report_dir=tmp_path / "reports"),
        "recorded-prerequisite",
    )
    reporter.plan = Plan([], [], {}, [], tests=[], checks=[check])
    try:
        resolve_checks(
            reporter,
            {"HOST-DISCOVERY": ("PASSED", "Observed hosts: compute-a / compute-b")},
        )
        reporter.cleanup_summary.update({"attempted": True, "complete": True})
        assert reporter.finalize(0) == 0
        loaded = load_results(reporter.results_path)
        assert loaded["results"] == []
        assert loaded["planned_check_ledger"][0]["outcome"] == "PASSED"
        text = render_results_text(loaded)
        assert _text_count(text, "Passed") == 1
        assert "Actual result: Observed hosts: compute-a / compute-b" in text
        assert "No separate probe result was saved" in text
        report = build_report_payload(loaded)
        row = report["dashboard"]["results"][0]
        assert row["status"] == "PASS"
        assert row["observed"] == "Observed hosts: compute-a / compute-b"
        assert row["operator_explanation"]["kind"] == "prerequisite-assessment-passed"
        suite = ET.fromstring(build_junit(loaded))
        assert suite.attrib["tests"] == "1"
        assert suite.attrib["failures"] == "0"
    finally:
        reporter.logger.close()


def test_ordinary_live_row_uses_journal_index_without_scanning_prior_results(
    config_factory, tmp_path
):
    from neutron_flux.reporting import Reporter

    reporter = Reporter(
        config_factory(action="run", report_dir=tmp_path / "reports"), "indexed-console"
    )
    try:
        item = reporter.result(
            "ORDINARY-PATH",
            "same-subnet",
            "PASS",
            "TCP delivery succeeded",
            expected="reachable",
            observed="reachable",
        )

        class IndexedResults(list):
            def __iter__(self):
                raise AssertionError("ordinary live projection scanned prior results")

        reporter.results = IndexedResults(reporter.results)
        projected = reporter._presentation_result(item)
        assert projected["test_id"] == item.test_id
        assert projected["details"] is item.details
        assert projected["status"] == "PASS"
    finally:
        reporter.logger.close()


def test_incident_summary_grades_terminal_checks_and_retains_historical_sample_counts(
    tmp_path,
):
    loaded = load_results(_write(tmp_path, _payload()))
    before = copy.deepcopy(loaded)
    loaded["dashboard"] = build_dashboard_model(loaded)
    text = render_incident_summary(loaded)
    conditions = text.split("## Conditions requiring review", 1)[1]
    assert (
        "No executed network contract produced a failed, errored, or unverified verdict."
        in conditions
    )
    assert "**FAIL" not in conditions
    assert "Evidence records: 2 total; FAIL=1, PASS=1" in text
    assert loaded["results"] == before["results"]
    assert loaded["results"][0]["status"] == "FAIL"
