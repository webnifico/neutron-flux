from __future__ import annotations

import json
from copy import deepcopy
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.constants import MIGRATION_DOWNTIME_TOLERANCE_NOTE
from neutron_flux.models import Plan, RunCheckpoint
from neutron_flux.models import TestSpec as FluxTestSpec
from neutron_flux.multi_zone import MultiZoneOrchestrator, ZoneLane
from neutron_flux.reporting import Reporter, ScopedReporter
from neutron_flux.results_io import render_results_text
from neutron_flux.state import StateStore
from neutron_flux.suite import Suite
from neutron_flux.utils import iso_utc
from support.tests.test_translated_migration_reporting import _observation_pass


@pytest.mark.parametrize("supporting", [False, True])
def test_migration_tolerance_console_keeps_pass_and_emits_observation(
    supporting, config_factory, tmp_path, capsys
):
    result = _observation_pass()
    assessment = deepcopy(result["details"]["transitions"][0]["continuity_assessment"])
    details = {"continuity": assessment} if supporting else result["details"]
    if supporting:
        details["check_sample"] = True
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    reporter = Reporter(config, "sample-migration-observation-console")
    capsys.readouterr()
    try:
        item = reporter.result(
            result["test_id"],
            result["category"],
            result["status"],
            result["message"],
            expected=result["expected"],
            observed=result["observed"],
            authoritative=True,
            details=details,
            display_name="Migration placement and traffic continuity",
        )
        output = capsys.readouterr().out
        assert "[PASS] Migration placement" in output
        assert "[PASS WITH" not in output
        assert "[OBSERVATION] Above tolerance" in output
        assert MIGRATION_DOWNTIME_TOLERANCE_NOTE in output
        for reason in assessment["interruption_observations"]:
            assert reason in output
        assert item.status == "PASS"
        stored = json.loads(reporter.result_journal_path.read_text().splitlines()[-1])
        assert stored["status"] == "PASS"
        stored_assessment = (
            stored["details"]["continuity"]
            if supporting
            else stored["details"]["transitions"][0]["continuity_assessment"]
        )
        assert stored_assessment["migration_outcomes"]["interruption_tolerance"] == (
            "OBSERVATION"
        )
    finally:
        reporter.logger.close()


def _spec(test_id: str, *, controller: bool = False) -> FluxTestSpec:
    return FluxTestSpec(
        id=test_id,
        category="controller-bootstrap" if controller else "same-subnet",
        operation="controller-readiness" if controller else "probe",
        family=4,
        expectation="reachable",
        expectation_reason="planned validation",
        authoritative=True,
        dependencies=[],
        display_name=(
            "Reach the probe controller over SSH"
            if controller
            else f"Dataplane validation {test_id}"
        ),
        scenario="Controller readiness" if controller else "Same-network connectivity",
    )


def _checkpoint(tmp_path, plan: Plan) -> RunCheckpoint:
    now = iso_utc()
    return RunCheckpoint(
        run_id="lane-bc-van1",
        state="RUNNING",
        action="run",
        phase="controller-bootstrap",
        current_batch=None,
        started_at=now,
        updated_at=now,
        last_activity=now,
        completed_test_ids=[],
        failed_test_ids=[],
        pending_test_ids=[item.id for item in plan.tests],
        active_group_ids=[],
        manifest_path=str(tmp_path / "manifest.jsonl"),
        report_dir=str(tmp_path),
    )


@pytest.mark.parametrize(
    "status",
    [
        "BLOCKED_BY_SETUP_ERROR",
        "BLOCKED_BY_PREREQUISITE",
        "NOT_RUN_CANCELLED",
    ],
)
def test_synthetic_not_run_rows_are_durable_but_quiet_by_default(
    status, config_factory, tmp_path, capsys
):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    reporter = Reporter(config, f"sample-v2-quiet-{status.lower()}")

    capsys.readouterr()
    try:
        reporter.result(
            "PLANNED-NOT-RUN",
            "same-subnet",
            status,
            "synthetic ledger reason",
            expected="reachable",
            observed="not-run",
            display_name="Planned validation that did not run",
        )

        assert capsys.readouterr().out == ""
        assert reporter.results[0].status == status
        journal = reporter.result_journal_path.read_text(encoding="utf-8")
        assert '"test_id": "PLANNED-NOT-RUN"' in journal
        assert f'"status": "{status}"' in journal
    finally:
        reporter.logger.close()


def test_failed_lane_prints_one_grouped_summary_and_keeps_every_row(
    config_factory, tmp_path, capsys
):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    reporter = Reporter(config, "sample-v2-lane-console")
    scoped = ScopedReporter(reporter, "az-bc-van1", availability_zone="bc-van1")
    plan = Plan(
        [],
        [],
        {},
        [],
        tests=[
            _spec("CONTROL-SSH", controller=True),
            *[_spec(f"DATAPLANE-{index}") for index in range(30)],
        ],
    )
    scoped.plan = plan
    store = StateStore(tmp_path / "state")
    lane = ZoneLane(
        zone="bc-van1",
        scope="az-bc-van1",
        config=config,
        plan=plan,
        reporter=scoped,
        osc=mock.Mock(),
        tracker=mock.Mock(),
        cleanup_manager=mock.Mock(),
        state_store=store,
        checkpoint=_checkpoint(tmp_path, plan),
        builder=SimpleNamespace(controller_bootstrap_diagnostics=[]),
    )
    orchestrator = object.__new__(MultiZoneOrchestrator)
    orchestrator.zone_plan = SimpleNamespace(includes_per_zone=True)
    orchestrator.logger = reporter.logger

    capsys.readouterr()
    try:
        orchestrator._record_lane_failure(
            lane,
            RuntimeError("controller SSH access failed"),
            phase="controller-bootstrap",
        )
        terminal = capsys.readouterr().out

        assert (
            terminal.count(
                "Availability-zone lane bc-van1 failed during controller bootstrap"
            )
            == 1
        )
        assert "30 downstream validations were recorded as not run" in terminal
        assert "remaining lanes are evaluated independently" in terminal
        assert "Other healthy lanes" not in terminal
        assert "Dataplane validation DATAPLANE-0" not in terminal
        assert len(reporter.results) == 31
        assert (
            sum(item.status == "BLOCKED_BY_SETUP_ERROR" for item in reporter.results)
            == 30
        )
        journal = [
            json.loads(line)
            for line in reporter.result_journal_path.read_text(
                encoding="utf-8"
            ).splitlines()
            if line
        ]
        assert len(journal) == 31
    finally:
        reporter.logger.close()


def test_cancellation_prints_one_summary_and_compacts_final_text(
    config_factory, tmp_path, capsys
):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    reporter = Reporter(config, "sample-v2-cancel-console")
    plan = Plan(
        [],
        [],
        {},
        [],
        tests=[_spec(f"CANCELLED-{index}") for index in range(30)],
    )
    reporter.plan = plan
    suite = object.__new__(Suite)
    suite.plan = plan
    suite.reporter = reporter
    suite.checkpoint = SimpleNamespace(
        completed_test_ids=[],
        pending_test_ids=[],
        failed_test_ids=[],
        metadata={},
    )

    capsys.readouterr()
    assert suite.record_cancelled_results("received signal 2") == 30
    live_output = capsys.readouterr().out
    assert live_output.count("Cancellation summary:") == 1
    assert "30 planned validations did not start" in live_output
    assert "Dataplane validation CANCELLED-0" not in live_output
    assert len(reporter.results) == 30

    reporter.interrupted = True
    reporter.cancellation_reason = "received signal 2"
    reporter.cleanup_summary.update({"attempted": True, "complete": True})
    assert reporter.finalize(130) == 130
    final_output = capsys.readouterr().out
    assert "NOT RUN — CANCELLED | 30 validations" in final_output
    assert "Individual cancellation rows remain available" in final_output
    assert "CANCELLED-0" not in final_output
    assert "CANCELLED-29" not in final_output
    payload = json.loads(reporter.results_path.read_text(encoding="utf-8"))
    assert len(payload["results"]) == 30
    assert {item["status"] for item in payload["results"]} == {"NOT_RUN_CANCELLED"}


def _floating_ip_removal_result() -> dict:
    return {
        "test_id": "REMOVE-FLOATING-IP",
        "category": "floating-ip-lifecycle",
        "status": "PASS",
        "family": 4,
        "source": "Provider Public:A (198.51.100.208)",
        "destination": "Private VM:A (198.51.100.201)",
        "message": "The traffic was blocked.",
        "display_name": "Check TCP access after detaching a floating IP — cross — initial — IPv4",
        "expected": "withdrawn",
        "observed": "blocked",
        "authoritative": True,
        "details": {
            "operation": "fip-withdraw",
            "protocol": "TCP",
            "phase": "cross",
            "pair_placement": "initial",
            "pair_placement_policy": "initial-opposite-v1",
            "address_path": {
                "source": {
                    "fixed_ip": "198.51.100.208",
                    "probe_address": "198.51.100.208",
                },
                "destination": {
                    "fixed_ip": "10.128.0.134",
                    "floating_ip": "198.51.100.201",
                    "floating_ip_status": "detached",
                    "probe_address": "198.51.100.201",
                },
            },
            "path": {
                "source_compute_host": "hyper004",
                "destination_compute_host": "hyper003",
                "path_kind": "floating-ip",
            },
        },
    }


def test_completed_negative_check_explains_action_path_and_pass_in_console(
    config_factory, tmp_path, capsys
):
    result = _floating_ip_removal_result()
    reporter = Reporter(
        config_factory(action="run", report_dir=tmp_path / "reports"),
        "human-negative-check",
    )
    capsys.readouterr()
    try:
        item = reporter.result(
            result["test_id"],
            result["category"],
            result["status"],
            result["message"],
            **{
                key: result[key]
                for key in (
                    "family",
                    "source",
                    "destination",
                    "details",
                    "expected",
                    "observed",
                    "authoritative",
                    "display_name",
                )
            },
        )
        output = capsys.readouterr().out
        assert "[PASS]" in output
        assert "After removing the destination VM's floating IP" in output
        assert "198.51.100.208" in output
        assert "198.51.100.201" in output
        assert "10.128.0.134" in output
        assert "hyper004" in output and "hyper003" in output
        assert "different compute hosts" in output
        assert "Before migration" in output
        assert "Expected result:" in output
        assert "Actual result:" in output
        assert "Why this passed:" in output
        assert "— cross" not in output and "— initial" not in output
        assert "Baseline" not in output
        assert item.status == "PASS"
        stored = json.loads(reporter.result_journal_path.read_text().splitlines()[-1])
        assert "reporting_context" not in stored
        assert stored["details"]["phase"] == "cross"
    finally:
        reporter.logger.close()


def test_text_results_use_complete_context_for_pass_and_supporting_sample():
    result = _floating_ip_removal_result()
    sample = deepcopy(result)
    sample["test_id"] = "REMOVE-FLOATING-IP-SAMPLE"
    sample["details"]["check_sample"] = True
    payload = {"run": {"run_id": "human-text"}, "results": [result, sample]}
    before = deepcopy(payload)

    output = render_results_text(payload)

    assert output.count("Expected result:") == 2
    assert output.count("Actual result:") == 2
    assert output.count("Why this passed:") == 2
    assert output.count("10.128.0.134") == 2
    assert "Supporting sample [PASS]" in output
    assert "After removing the destination VM's floating IP" in output
    assert "Evidence summary: {" not in output
    assert "Full recorded evidence: results.json" in output
    assert "Total tests                         1" in output
    assert "Supporting or retry records: 1" in output
    assert "Total saved result records: 2." in output
    assert payload == before


def test_console_placement_is_actual_and_missing_timing_is_explicit(
    config_factory, tmp_path, capsys
):
    reporter = Reporter(
        config_factory(action="run", report_dir=tmp_path / "reports"),
        "human-actual-placement",
    )
    capsys.readouterr()
    try:
        reporter.result(
            "DIFFERENT-HOSTS",
            "same-subnet",
            "PASS",
            "The TCP connection succeeded.",
            family=4,
            source="Private VM:A (10.0.0.10)",
            destination="Private VM:B (10.0.0.11)",
            expected="reachable",
            observed="reachable",
            authoritative=True,
            display_name="Test TCP connectivity — intra — initial — IPv4",
            details={
                "phase": "intra",
                "pair_placement": "initial",
                "protocol": "TCP",
                "path": {
                    "source_compute_host": "hyper001",
                    "destination_compute_host": "hyper002",
                },
            },
        )
        output = capsys.readouterr().out
        assert "different compute hosts" in output
        assert "hyper001" in output and "hyper002" in output
        assert "Migration timing not recorded" in output
        assert "Before migration" not in output
        assert "same compute host" not in output
        assert "— intra" not in output
    finally:
        reporter.logger.close()


def test_final_text_starts_with_summary_and_preserves_runtime_history(
    config_factory, tmp_path, capsys
):
    reporter = Reporter(
        config_factory(action="run", report_dir=tmp_path / "reports"),
        "human-report-order",
    )
    reporter.cleanup_summary.update({"attempted": True, "complete": True})
    reporter.logger.log("An original chronological event")
    reporter.result(
        "HUMAN-SUMMARY-PASS",
        "same-subnet",
        "PASS",
        "TCP succeeded",
        expected="reachable",
        observed="reachable",
        authoritative=True,
        display_name="Test TCP connectivity",
    )
    capsys.readouterr()

    assert reporter.finalize(0) == 0

    text = reporter.report_path.read_text(encoding="utf-8")
    assert (
        text.index("NEUTRON FLUX FINAL SUMMARY")
        < text.index("RUNTIME HISTORY — TIMESTAMPED TECHNICAL LOG")
        < text.index("An original chronological event")
    )
    summary, history = text.split("RUNTIME HISTORY — TIMESTAMPED TECHNICAL LOG", 1)
    assert "Expected result:" in summary and "Actual result:" in summary
    assert "Why this passed:" in summary
    assert "An original chronological event" in history
    assert capsys.readouterr().out.count("NEUTRON FLUX FINAL SUMMARY") == 1


def test_text_attention_summary_includes_pass_measurement_and_advisory():
    result = {
        "test_id": "LATENCY-ADVISORY",
        "category": "network-performance",
        "status": "PASS",
        "family": 4,
        "display_name": "Latency under idle and loaded traffic",
        "expected": "latency-recorded",
        "observed": "latency-measured",
        "message": "The latency measurement completed.",
        "details": {
            "performance": True,
            "measurement": "latency",
            "health": "warning",
            "thresholds_enforced": False,
            "warning_reasons": [
                "The loaded round-trip delay was ten times the idle round-trip delay."
            ],
            "metrics": {
                "idle": {"forward": {"p95_ms": 1.0}},
                "loaded": {"forward": {"p95_ms": 10.0}},
                "loaded_p95_ratio": {"forward": 10.0},
            },
        },
    }
    payload = {"results": [result]}
    before = deepcopy(payload)

    text = render_results_text(payload)
    attention = text.split("\nNEEDS ATTENTION\n", 1)[1].split(
        "\nDETAILED RESULTS\n", 1
    )[0]

    assert "[PASS WITH WARNING]" in attention
    assert "Actual result:" in attention
    assert "1 ms" in attention and "10 ms" in attention
    assert "Review note:" in attention
    assert "ten times the idle round-trip delay" in attention
    assert "[FAIL]" not in attention
    assert payload == before


@pytest.mark.parametrize("health", ["good", "warning"])
def test_text_attention_summary_keeps_pass_and_shows_interruption_observation(health):
    result = _observation_pass()
    result["details"]["health"] = health
    payload = {"results": [result]}
    before = deepcopy(payload)

    text = render_results_text(payload)
    attention = text.split("\nNEEDS ATTENTION\n", 1)[1].split(
        "\nDETAILED RESULTS\n", 1
    )[0]

    assert "[PASS]" in attention
    assert "[PASS WITH WARNING]" not in attention
    assert "Actual result:" in attention and "Review note:" in attention
    assert "[OBSERVATION] Above tolerance:" in attention
    assert MIGRATION_DOWNTIME_TOLERANCE_NOTE in attention
    assert "[FAIL]" not in attention
    assert payload == before
