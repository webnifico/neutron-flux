from __future__ import annotations

import copy
import xml.etree.ElementTree as ET
from collections import Counter

from neutron_flux.junit_report import build_junit
from neutron_flux.reporting import Reporter
from neutron_flux.reporting_components.html import render_html
from neutron_flux.reporting_components.report_payload import enrich_findings
from neutron_flux.results_io import render_results_text
from support.tests.test_report_workflow import _embedded_payload, _payload


def _plan_test(test_id: str, *, category: str, operation: str) -> dict:
    return {
        "id": test_id,
        "category": category,
        "operation": operation,
        "scenario": "Planned functional validation",
        "metadata": {},
    }


def test_incomplete_and_pass_with_warnings_are_not_healthy() -> None:
    payload = _payload()
    payload["run"]["final_status"] = "INCOMPLETE"
    payload["results"][0]["status"] = "NOT_RUN_CANCELLED"
    payload["summary"]["counts"] = {"NOT_RUN_CANCELLED": 1}

    html = render_html(payload)
    report = _embedded_payload(html)
    text = render_results_text(payload)

    assert report["dashboard"]["summary"]["result_counts"] == {"NOT_RUN_CANCELLED": 1}
    assert (
        'finalIsCaution=value=>["PARTIAL","WARNING","PASS WITH WARNINGS","INCOMPLETE"]'
        in html
    )
    assert '["Cancelled",counts.NOT_RUN_CANCELLED||0' in html
    assert "+(counts.NOT_RUN_CANCELLED||0)" in html
    assert '<option value="blocked">Blocked</option>' not in html
    assert "Did not run: prerequisite           0" in text
    assert "Did not run: cancelled              1" in text
    assert "Total tests                         1" in text
    assert "Actual result: TCP reached and echoed application data." not in text


def test_incomplete_run_cannot_look_healthy_in_junit() -> None:
    payload = _payload()
    payload["run"]["final_status"] = "INCOMPLETE"
    payload["results"][0]["status"] = "BLOCKED_BY_PREREQUISITE"
    payload["summary"]["counts"] = {"BLOCKED_BY_PREREQUISITE": 1}

    suite = ET.fromstring(build_junit(payload, include_evidence=False))

    assert suite.get("tests") == "2"
    assert suite.get("errors") == "1"
    assert suite.get("skipped") == "1"
    lifecycle = suite.find("./testcase[@name='RUN-FINAL-STATUS']")
    assert lifecycle is not None
    error = lifecycle.find("error")
    assert error is not None
    assert error.get("type") == "run-lifecycle-error"
    assert "INCOMPLETE" in (error.get("message") or "")


def test_error_remediation_precedes_domain_diagnostics() -> None:
    payload = _payload()
    result = payload["results"][0]
    result.update(
        {
            "status": "ERROR",
            "category": "mtu",
            "message": "Probe command failed.",
        }
    )
    finding = {
        "finding_id": "F01",
        "finding_reference": "Finding 1",
        "root_key": "mtu",
        "title": "MTU validation",
        "summary": "MTU evidence was not recorded.",
        "result_ids": [result["test_id"]],
        "result_count": 1,
        "path_ids": ["project-route-v4"],
        "status_counts": {"ERROR": 1},
    }

    enriched = enrich_findings(payload, [finding], [result])[0]

    assert enriched["evidence_completeness"] == "Limited"
    assert "failing command" in enriched["next_check"]
    assert "standard error" in enriched["next_check"]
    assert "Compare advertised MTU" not in enriched["next_check"]


def test_mixed_fail_and_error_finding_preserves_confirmed_failure() -> None:
    payload = _payload()
    failed = payload["results"][0]
    failed.update(
        {
            "status": "FAIL",
            "message": "TCP connectivity contradicted the expected behaviour.",
            "observed": "TCP connection failed.",
        }
    )
    errored = copy.deepcopy(failed)
    errored.update(
        {
            "test_id": "PROJECT-ROUTE-TCP-REVERSE",
            "status": "ERROR",
            "message": "TCP connectivity probe command failed.",
            "observed": None,
        }
    )
    finding = {
        "finding_id": "F01",
        "finding_reference": "Finding 1",
        "root_key": "connectivity",
        "title": "Connectivity validation",
        "summary": "Connectivity results require review.",
        "severity": "error",
        "group": "errors",
        "result_ids": [failed["test_id"], errored["test_id"]],
        "result_count": 2,
        "path_ids": ["project-route-v4"],
        "status_counts": {"FAIL": 1, "ERROR": 1},
    }

    enriched = enrich_findings(payload, [finding], [failed, errored])[0]

    assert enriched["severity"] == "critical"
    assert enriched["group"] == "confirmed"
    assert enriched["evidence_completeness"] == "Conclusive with gaps"
    assert "1 completed validation contradicts expected behaviour" in enriched["impact"]
    assert "1 additional operation did not complete" in enriched["impact"]
    assert "confirmed contradiction" in enriched["next_check"]
    assert "failing command" in enriched["next_check"]
    assert "standard error" in enriched["next_check"]
    assert "1 completed result records FAIL" in enriched["evidence_summary"]
    assert "remain unvalidated" in enriched["evidence_summary"]


def test_cold_only_reporting_does_not_imply_live_transport(
    config_factory,
) -> None:
    payload = _payload()
    payload["configuration"]["migration"] = {
        "enabled": True,
        "mode": "cold-only",
        "storage": "host",
        "effective_storage": "host",
        "transport": "block live migration",
    }
    report = _embedded_payload(render_html(payload))

    assert report["configuration"]["migration"]["mode"] == "cold-only"
    assert report["configuration"]["migration"]["transport"] == "not used"
    assert report["configuration"]["migration"]["effective_storage"] == "not used"

    config = config_factory(action="run", migration_mode="cold-only")
    reporter = Reporter(config, "cold-only-report")
    summary = reporter._summary("PASS", reporter.started, Counter())

    assert "Migration:       cold-only" in summary
    assert "Live transport:  not used" in summary
    assert "block live migration" not in summary
    assert "shared/volume-backed live migration" not in summary
