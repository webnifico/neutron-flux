"""Keep port-state and execution abort evidence distinct."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from neutron_flux.operator_explanations import (
    explain_result,
    lifecycle_explanations,
    operator_overview,
)
from neutron_flux.reporting_components.dashboard_execution import (
    _command_centre,
    _coverage_model,
)
from neutron_flux.reporting_components.dashboard_model import _root_key
from neutron_flux.reporting_components.report_payload import _coverage_summary

CAPTURE = json.loads(
    (
        Path(__file__).with_name("fixtures")
        / "captured_execution_and_port_validation_failures.json"
    ).read_text()
)


def test_captured_icmp_failures_do_not_label_the_three_migration_port_failures():
    payload = {"results": copy.deepcopy(CAPTURE["results"])}
    original = copy.deepcopy(payload)
    groups = operator_overview(payload)["groups"]
    assert len(groups) == 2
    by_label = {group["label"]: group for group in groups}
    icmp = by_label["ICMP did not reach the destination as required"]
    ports = by_label["Migration port binding or state validation failed"]
    assert icmp["count"] == ports["count"] == 3
    assert all("EGRESS" in identity for identity in icmp["result_ids"])
    assert all("PLACEMENT" in identity for identity in ports["result_ids"])
    assert icmp["kind"] != ports["kind"]
    assert payload == original


def test_captured_port_failure_retains_good_continuity_and_failed_verdict():
    for result in CAPTURE["results"]:
        if result["category"] != "compute-placement":
            continue
        original = copy.deepcopy(result)
        story = explain_result(result)
        assert story["kind"] == "migration-port-validation-failed"
        assert "Nova migration completion was verified" in story["what_happened"]
        assert (
            "does not by itself establish a traffic interruption"
            in story["what_happened"]
        )
        assert _root_key(result) == (
            "migration-port-validation",
            "Migration port binding or state validation failed",
        )
        if result["expected"] == "traffic-continuity-measured":
            assert "0 of 1000 scheduled ping observations failed" in story["observed"]
            assert "TCP connection stayed established" in story["observed"]
        if result["expected"] == "bound-to-destination":
            assert any(
                "role=management; status=DOWN" in fact["value"]
                for fact in story["facts"]
            )
        assert result == original
        assert result["status"] == "FAIL"


def test_generic_failed_contracts_have_distinct_overview_labels():
    results = [
        {
            "test_id": protocol,
            "status": "FAIL",
            "expected": "reachable",
            "observed": "blocked",
            "details": {"protocol": protocol},
        }
        for protocol in ("icmp", "tcp")
    ]
    groups = operator_overview({"results": results})["groups"]
    assert len(groups) == 2
    assert {group["count"] for group in groups} == {1}
    assert len({group["kind"] for group in groups}) == 2


@pytest.mark.parametrize("failed_component", ["tcp_session", "traffic_recovery"])
def test_port_failure_does_not_hide_an_independent_transport_failure(failed_component):
    result = copy.deepcopy(
        next(
            row
            for row in CAPTURE["results"]
            if row["expected"] == "traffic-continuity-measured"
        )
    )
    result["details"]["migration_outcomes"][failed_component] = "FAIL"
    story = explain_result(result)
    assert story["kind"] == "check-failed"
    assert (
        "does not by itself establish a traffic interruption"
        not in story["what_happened"]
    )


def test_captured_execution_abort_is_not_controller_setup_failure():
    payload = {"setup_failures": CAPTURE["setup_failures"]}
    original = copy.deepcopy(payload)
    lifecycle = lifecycle_explanations(payload)
    assert lifecycle[0]["headline"] == "Test execution stopped"
    incident = _command_centre(payload, [], [])["top_incidents"][0]
    assert incident["title"] == "Neutron Flux test execution stopped in az-test1"
    assert incident["execution_failure"] is True
    assert incident["setup_failure"] is False
    assert "controller setup" not in json.dumps(lifecycle + [incident]).lower()
    assert (
        _root_key(
            {
                "status": "ERROR",
                "details": {
                    "tool_failure": True,
                    "root_lane_error": True,
                    "root_setup_error": False,
                    "failure_phase": "per-zone-execution",
                },
            }
        )[0]
        == "neutron-flux-execution"
    )
    assert payload == original


def test_setup_failure_keeps_bootstrap_classification():
    payload = {
        "setup_failures": [
            {
                "message": "controller access unavailable",
                "details": {
                    "availability_zone": "az-test1",
                    "root_setup_error": True,
                    "failure_phase": "controller-bootstrap",
                },
            }
        ]
    }
    assert lifecycle_explanations(payload)[0]["headline"] == "Setup did not complete"
    incident = _command_centre(payload, [], [])["top_incidents"][0]
    assert incident["setup_failure"] is True
    assert incident["execution_failure"] is False


@pytest.mark.parametrize("ledger_key", ["planned_check_ledger", "coverage_ledger"])
def test_blocked_planned_checks_are_not_complete_coverage(ledger_key):
    ledger = [
        {"id": f"{outcome}-{index}", "outcome": outcome}
        for outcome, count in CAPTURE["planned_outcomes"].items()
        for index in range(count)
    ]
    payload = {ledger_key: ledger}
    original = copy.deepcopy(payload)
    assert _coverage_model(payload)["complete"] is False
    assert _command_centre(payload, [], [])["coverage"] == {
        "total": 842,
        "never_ran": 467,
        "blocked": 467,
        "complete": False,
    }
    summary = _coverage_summary(payload, [], [])
    assert summary["never_ran_tests"] == 467
    assert summary["accounted_tests"] == summary["planned_tests"] == 842
    assert payload == original
