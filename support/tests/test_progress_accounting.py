"""A fixed initial-plan total must survive runtime expansion and recovery."""

from __future__ import annotations

import dataclasses
import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from neutron_flux.cli import _new_checkpoint, _reconcile_final_checkpoint
from neutron_flux.coverage_ledger import materialize_missing_results
from neutron_flux.models import Plan
from neutron_flux.models import TestSpec as FluxTestSpec
from neutron_flux.plan_contract import create_plan_contract, load_plan_contract
from neutron_flux.progress import progress_text, reporter_progress
from neutron_flux.progress import test_progress as calculate_progress
from neutron_flux.reporting import Reporter, ScopedReporter
from neutron_flux.reporting_components.html import build_run_payload
from neutron_flux.state import StateStore
from neutron_flux.utils import utc_now


def spec(test_id):
    return FluxTestSpec(
        test_id, "same-subnet", "probe", 4, "reachable", "fixture", True, []
    )


def plan(*ids):
    return Plan([], [], {}, [], tests=[spec(test_id) for test_id in ids])


@pytest.fixture
def reporter(config_factory):
    value = Reporter(config_factory(action="run"), "sample-progress")
    value.plan = plan("A", "B", "C")
    value.save_plan()
    try:
        yield value
    finally:
        value.logger.close()


def test_runtime_plan_and_unplanned_results_cannot_move_total(reporter, capsys):
    reporter.result("A", "same-subnet", "PASS", "reachable")
    for test_id in ("PERF", "MIGRATION", "RECHECK"):
        reporter.plan.tests.append(spec(test_id))
        reporter.save_plan()
        reporter.result(test_id, "same-subnet", "PASS", "reachable")
    reporter.result("DIAGNOSTIC", "same-subnet", "UNVERIFIED", "inconclusive")
    reporter.result("B", "same-subnet", "FAIL", "failed")
    progress = reporter_progress(reporter)
    assert progress["planned"] == progress["known"] == 3
    assert progress["planned_recorded"] == progress["planned_executed"] == 2
    assert progress["additional_recorded"] == 4
    assert progress["pending"] == 1
    assert progress["recorded"] == progress["executed"] == 6
    fractions = re.findall(r"Test progress: (\d+)/(\d+)", capsys.readouterr().out)
    assert fractions == [("1", "3")] * 5 + [("2", "3")]
    assert (
        len(reporter.plan.tests) == 6
    )  # Supplemental execution/coverage stays intact.


@pytest.mark.parametrize("status", ["PASS", "FAIL", "UNVERIFIED", "ERROR"])
def test_executed_results_are_not_pass_counts(reporter, status):
    reporter.result("A", "same-subnet", status, "result")
    progress = reporter_progress(reporter)
    assert progress["planned_executed"] == 1
    assert progress["planned_not_run"] == 0
    assert progress["planned_recorded"] == 1


@pytest.mark.parametrize(
    "status",
    [
        "NOT_RUN_CANCELLED",
        "BLOCKED_BY_SETUP_ERROR",
        "BLOCKED_BY_PREREQUISITE",
        "SKIP",
        "NOT_APPLICABLE",
    ],
)
def test_nonexecuted_results_remain_explicit(reporter, status):
    reporter.result("A", "same-subnet", status, "not run")
    progress = reporter_progress(reporter)
    assert progress["planned_recorded"] == 1
    assert progress["planned_executed"] == 0
    assert progress["planned_not_run"] == 1
    assert "(0 executed, 1 not run)" in progress_text(progress)


def test_pending_runtime_checks_remain_visible_after_initial_plan(reporter):
    for test_id in ("A", "B", "C"):
        reporter.result(test_id, "same-subnet", "PASS", "reachable")
    reporter.plan.tests.append(spec("MIGRATION"))
    reporter.save_plan()
    progress = reporter_progress(reporter)
    assert progress["planned_recorded"] == progress["planned"] == 3
    assert progress["additional_pending"] == 1
    assert "additional checks pending: 1" in progress_text(progress)
    assert "complete" not in progress_text(progress).lower()


def test_duplicate_results_do_not_advance_any_counter(reporter, capsys):
    reporter.result("A", "same-subnet", "PASS", "reachable")
    before = reporter_progress(reporter)
    capsys.readouterr()
    reporter.result("A", "same-subnet", "PASS", "reachable")
    assert reporter_progress(reporter) == before
    assert capsys.readouterr().out == ""


def test_preflight_does_not_freeze_an_unavailable_plan():
    value = SimpleNamespace(plan=None, results=[])
    assert reporter_progress(value)["plan_available"] is False
    value.plan = plan("A", "B")
    assert reporter_progress(value)["planned"] == 2
    value.plan.tests.append(spec("DYNAMIC"))
    assert reporter_progress(value)["planned"] == 2


@pytest.mark.parametrize("initial", [None, SimpleNamespace(tests=[object()])])
def test_missing_or_opaque_plan_has_no_fraction(initial):
    progress = calculate_progress(
        initial, [SimpleNamespace(test_id="A", status="PASS")]
    )
    assert progress["recorded"] == 1
    assert progress["plan_available"] is False
    assert "/" not in progress_text(progress)


def test_empty_plan_is_frozen_instead_of_adopting_runtime_tests():
    value = SimpleNamespace(plan=plan(), results=[])
    assert reporter_progress(value)["planned"] == 0
    value.plan.tests.append(spec("DYNAMIC"))
    value.results.append(SimpleNamespace(test_id="DYNAMIC", status="PASS"))
    progress = reporter_progress(value)
    assert progress["planned"] == progress["planned_recorded"] == 0
    assert progress["additional_recorded"] == 1


def test_resume_restores_original_total_from_approved_contract(
    config_factory, discovery_fixture
):
    config = config_factory(action="run")
    original = Reporter(config, "sample-resume")
    original.plan = plan("A", "B")
    original.plan_contract = create_plan_contract(
        config, discovery_fixture, original.plan
    )
    original.save_plan()
    original.plan.tests.append(spec("PERF"))
    original.save_plan()
    original.result("A", "same-subnet", "PASS", "reachable")
    original.result("PERF", "same-subnet", "PASS", "reachable")
    original.result(
        "B",
        "same-subnet",
        "NOT_RUN_CANCELLED",
        "cancelled",
        details={"coverage_outcome": "NEVER_RAN"},
    )
    original.logger.close()
    resumed = Reporter(config, "sample-resume", load_existing=True)
    try:
        resumed.plan_contract, resumed.plan = load_plan_contract(
            resumed.plan_path, prefer_runtime_plan=True
        )
        resumed.save_plan()
        progress = reporter_progress(resumed)
        assert len(resumed.plan.tests) == 3
        assert progress["planned"] == 2
        assert progress["planned_recorded"] == 1
        assert progress["additional_recorded"] == 1
        assert progress["pending"] == 1
        resumed.result("B", "same-subnet", "PASS", "reachable after resume")
        assert reporter_progress(resumed)["planned_recorded"] == 2
    finally:
        resumed.logger.close()


def test_concurrent_zones_keep_parent_plan_total(config_factory, capsys):
    parent = Reporter(config_factory(action="run"), "sample-zones")
    try:
        lanes = [
            ScopedReporter(parent, zone, availability_zone=zone)
            for zone in ("az1", "az2")
        ]
        parent.plan = plan(*(lane.scoped_test_id("A") for lane in lanes))
        parent.save_plan()
        for lane in lanes:
            lane.plan = plan("A", "DYNAMIC")
            lane.save_plan()

        def run_lane(lane):
            lane.result("A", "same-subnet", "PASS", "reachable")
            lane.result("DYNAMIC", "same-subnet", "PASS", "reachable")

        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(run_lane, lanes))
        progress = reporter_progress(parent)
        assert progress["planned"] == progress["planned_recorded"] == 2
        assert progress["additional_recorded"] == 2
        assert len(parent.plan.tests) == 4
        assert {
            total
            for _, total in re.findall(
                r"Test progress: (\d+)/(\d+)", capsys.readouterr().out
            )
        } == {"2"}
    finally:
        parent.logger.close()


def test_console_checkpoint_status_and_report_share_progress(reporter, capsys):
    checkpoint = _new_checkpoint(reporter.config, reporter.run_id, "run", reporter)
    reporter.plan.tests.append(spec("DYNAMIC"))
    reporter.save_plan()
    reporter.result("A", "same-subnet", "FAIL", "failed")
    reporter.result("DYNAMIC", "same-subnet", "PASS", "reachable")
    expected = reporter_progress(reporter)
    assert progress_text(expected) in capsys.readouterr().out
    _reconcile_final_checkpoint(checkpoint, reporter)
    assert checkpoint.metadata["test_progress"] == expected
    assert progress_text(expected) in StateStore(
        reporter.config.report_dir
    ).print_status(checkpoint)
    payload = build_run_payload(
        reporter,
        final_status="FAIL",
        finished=utc_now(),
        counts=Counter(item.status for item in reporter.results),
        include_dashboard=False,
    )
    assert payload["summary"]["test_progress"] == expected
    assert payload["results"] == [dataclasses.asdict(item) for item in reporter.results]


def test_cancellation_accounting_cannot_claim_every_check_executed(reporter):
    reporter.result("A", "same-subnet", "PASS", "reachable")
    reporter.interrupted = True
    reporter.cancellation_reason = "cancelled"
    assert materialize_missing_results(reporter, reporter.plan) == 2
    progress = reporter_progress(reporter)
    assert progress["planned_recorded"] == progress["planned"] == 3
    assert progress["planned_executed"] == 1
    assert progress["planned_not_run"] == 2
    assert "(1 executed, 2 not run)" in progress_text(progress)


@pytest.mark.parametrize(
    "metadata",
    [
        {},
        {
            "test_progress": {
                "recorded": 5,
                "known": 9,
                "plan_available": True,
                "total_can_grow": True,
            }
        },
    ],
)
def test_old_status_never_presents_a_growing_total(reporter, metadata):
    checkpoint = _new_checkpoint(reporter.config, reporter.run_id, "run", reporter)
    checkpoint.completed_test_ids = ["A", "B", "C", "D", "E"]
    checkpoint.pending_test_ids = ["F", "G", "H", "I"]
    checkpoint.metadata.update(metadata)
    status = StateStore(reporter.config.report_dir).print_status(checkpoint)
    assert "5 results recorded" in status
    assert "5/9" not in status
    assert "fixed planned total unavailable" in status
