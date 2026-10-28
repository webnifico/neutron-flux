from __future__ import annotations

from unittest import mock

import pytest

from neutron_flux.cli import _reconcile_final_checkpoint
from neutron_flux.errors import SuiteError
from neutron_flux.models import Plan, RunCheckpoint, ZoneExecutionPlan
from neutron_flux.models import TestSpec as FluxTestSpec
from neutron_flux.multi_zone import MultiZoneOrchestrator, aggregate_plan, zone_scope
from neutron_flux.reporting import Reporter
from neutron_flux.resources import SecurityGroupBundle
from neutron_flux.state import StateStore
from neutron_flux.suite import Suite
from neutron_flux.utils import iso_utc


def _runner(
    tmp_path,
    config_factory,
    discovery_fixture,
    monkeypatch,
    *,
    failed_zone=None,
    support_status=None,
    terminal_status="PASS",
    tool_failure=False,
):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    spec = FluxTestSpec(
        "CHECK", "same-subnet", "probe", 4, "reachable", "required", True, []
    )
    base = Plan([], [], {}, [], tests=[spec])
    if support_status is not None:
        spec.metadata = {"planned_check_id": "CHECK"}
        support = FluxTestSpec(
            "RETRY",
            "same-subnet",
            "probe",
            4,
            "reachable",
            "required",
            True,
            [],
            metadata={"planned_check_id": "CHECK", "check_sample": True},
        )
        base.tests.insert(0, support)
        base.checks = [
            {
                "id": "CHECK",
                "kind": "network",
                "category": "same-subnet",
                "stage": "intra",
                "condition": "Required final path",
            }
        ]
    zones = ZoneExecutionPlan(["zone-a", "zone-b"], "per-zone", {}, True, 2)
    reporter = Reporter(config, "zone-state-test")
    reporter.plan = aggregate_plan(base, zones, config)
    if support_status is not None:
        reporter.plan.checks = [
            {**base.checks[0], "id": f"{zone_scope(zone).upper()}-CHECK"}
            for zone in zones.zones
        ]
        for planned in reporter.plan.tests:
            planned.metadata["planned_check_id"] = (
                f"{zone_scope(planned.metadata['availability_zone']).upper()}-CHECK"
            )
    orchestrator = MultiZoneOrchestrator(
        config,
        discovery_fixture,
        base,
        zones,
        reporter,
        mock.Mock(),
        execution_plan=reporter.plan,
    )
    bundle = SecurityGroupBundle(
        "controller", "management", {"A": "a", "B": "b"}, "10.254.1.0/24", {}
    )
    monkeypatch.setattr(orchestrator, "_prepare_shared_security_groups", lambda: bundle)
    monkeypatch.setattr(
        orchestrator,
        "_prepare_lane",
        lambda lane: lane.state_store.save(lane.checkpoint),
    )

    class Executor:
        def __init__(self, *args):
            self.reporter = args[3]
            self.checkpoint = args[6]

        def run(self):
            if self.reporter.availability_zone == failed_zone:
                raise SuiteError("original lane failure")
            if support_status is not None:
                self.reporter.result(
                    "RETRY",
                    "same-subnet",
                    support_status,
                    "earlier supporting attempt",
                    details={"tool_failure": tool_failure},
                )
            self.reporter.result("CHECK", "same-subnet", terminal_status, "final probe")
            self.checkpoint.state = "RUNNING"
            self.checkpoint.phase = "group-local"

    monkeypatch.setattr("neutron_flux.multi_zone.AdaptiveExecutor", Executor)
    orchestrator.prepare()
    now = iso_utc()
    checkpoint = RunCheckpoint(
        "zone-state-test",
        "RUNNING",
        "run",
        "per-zone",
        None,
        now,
        now,
        now,
        [],
        [],
        [],
        [],
        str(reporter.manifest_path),
        str(reporter.run_dir),
    )
    suite = object.__new__(Suite)
    suite.config = config
    suite.reporter = reporter
    suite.logger = reporter.logger
    suite.checkpoint = checkpoint
    suite.state_store = StateStore(config.report_dir)
    suite.zone_orchestrator = orchestrator
    suite.builder = None
    suite.plan = reporter.plan
    suite.resources_started = True
    return suite, orchestrator


@pytest.mark.parametrize(
    "support,terminal,tool_failure,failed_ids",
    [
        ("FAIL", "PASS", False, []),
        ("ERROR", "PASS", False, []),
        ("UNVERIFIED", "PASS", False, []),
        ("NOT_RUN_CANCELLED", "PASS", False, []),
        ("PASS", "FAIL", False, ["CHECK"]),
        ("ERROR", "PASS", True, ["RETRY"]),
    ],
)
def test_bound_supporting_attempts_preserve_terminal_checkpoint_grades(
    tmp_path,
    config_factory,
    discovery_fixture,
    monkeypatch,
    support,
    terminal,
    tool_failure,
    failed_ids,
):
    suite, runner = _runner(
        tmp_path,
        config_factory,
        discovery_fixture,
        monkeypatch,
        support_status=support,
        terminal_status=terminal,
        tool_failure=tool_failure,
    )
    runner.run()
    suite.reporter.cleanup_summary.update(
        complete=True, errors=[], leftovers=[], unresolved_operations=[]
    )
    suite.checkpoint.cleanup_state = "COMPLETE"
    exit_code = suite.reporter.finalize(0)
    suite._save_checkpoint("COMPLETED", "finished", None)
    expected_root_failures = [
        lane.reporter.scoped_test_id(identity)
        for lane in runner.lanes.values()
        for identity in failed_ids
    ]
    assert sorted(suite.checkpoint.failed_test_ids) == sorted(expected_root_failures)
    _reconcile_final_checkpoint(suite.checkpoint, suite.reporter)
    assert sorted(suite.checkpoint.failed_test_ids) == sorted(expected_root_failures)
    assert exit_code == (2 if tool_failure else 1 if failed_ids else 0)
    for lane in runner.lanes.values():
        assert lane.checkpoint.state == ("FAILED" if failed_ids else "COMPLETED")
        assert lane.checkpoint.failed_test_ids == failed_ids
        assert lane.checkpoint.completed_test_ids == ["RETRY", "CHECK"]
        assert lane.checkpoint.pending_test_ids == []


def _clean(monkeypatch, runner, *, complete=True):
    for lane in runner.lanes.values():
        lane.cleanup_manager.cleanup = mock.Mock(return_value=True)
        lane.cleanup_manager._clear_recovery_artifacts = mock.Mock()

    class FinalCleanup:
        def __init__(self, *args, **kwargs):
            pass

        def cleanup(self, **kwargs):
            runner.reporter.cleanup_summary.update(
                complete=complete, errors=[], leftovers=[], unresolved_operations=[]
            )
            return complete

    monkeypatch.setattr("neutron_flux.multi_zone.CleanupManager", FinalCleanup)


def test_finished_lanes_are_saved_after_production_orchestration_and_cleanup(
    tmp_path, config_factory, discovery_fixture, monkeypatch
):
    suite, runner = _runner(tmp_path, config_factory, discovery_fixture, monkeypatch)
    try:
        runner.run()
        suite._save_checkpoint("TESTS_COMPLETE", "tests-complete", None)
        assert all(
            lane.state_store.load(lane.checkpoint.run_id).state == "TESTS_COMPLETE"
            for lane in runner.lanes.values()
        )
        _clean(monkeypatch, runner)
        assert suite.cleanup_if_required(True) is True
        for lane in runner.lanes.values():
            checkpoint = lane.state_store.load(lane.checkpoint.run_id)
            assert (checkpoint.state, checkpoint.cleanup_state) == (
                "COMPLETED",
                "COMPLETE",
            )
            assert checkpoint.completed_test_ids == ["CHECK"]
            assert checkpoint.pending_test_ids == checkpoint.active_group_ids == []
    finally:
        suite.reporter.logger.close()


def test_failed_lane_keeps_original_failure_while_other_lane_completes(
    tmp_path, config_factory, discovery_fixture, monkeypatch
):
    suite, runner = _runner(
        tmp_path, config_factory, discovery_fixture, monkeypatch, failed_zone="zone-b"
    )
    try:
        runner.run()
        _clean(monkeypatch, runner)
        assert suite.cleanup_if_required(False) is True
        suite.checkpoint.state = "FAILED"
        suite.sync_zone_checkpoints()
        first = runner.lanes["zone-a"].checkpoint
        failed = runner.lanes["zone-b"].checkpoint
        assert first.state == "COMPLETED"
        assert failed.state == "FAILED"
        assert failed.error == "SuiteError: original lane failure"
        assert failed.cleanup_state == first.cleanup_state == "COMPLETE"
    finally:
        suite.reporter.logger.close()


@pytest.mark.parametrize("cleanup", ["RETAINED", "INCOMPLETE"])
def test_retained_or_unverified_cleanup_is_not_reported_clean(
    tmp_path, config_factory, discovery_fixture, monkeypatch, cleanup
):
    suite, runner = _runner(tmp_path, config_factory, discovery_fixture, monkeypatch)
    try:
        runner.run()
        runner.reporter.cleanup_summary["complete"] = False
        suite.checkpoint.state = "COMPLETED"
        suite.checkpoint.cleanup_state = cleanup
        suite.sync_zone_checkpoints()
        for lane in runner.lanes.values():
            saved = lane.state_store.load(lane.checkpoint.run_id)
            assert saved.cleanup_state == cleanup
            assert saved.state == (
                "CLEANUP_INCOMPLETE" if cleanup == "INCOMPLETE" else "COMPLETED"
            )
        # A mistaken COMPLETE input cannot override absent cleanup proof.
        suite.checkpoint.cleanup_state = "COMPLETE"
        suite.sync_zone_checkpoints()
        assert all(
            lane.checkpoint.cleanup_state == "INCOMPLETE"
            for lane in runner.lanes.values()
        )
    finally:
        suite.reporter.logger.close()


def test_cancelled_root_rows_are_included_and_completed_lanes_stay_complete(
    tmp_path, config_factory, discovery_fixture, monkeypatch
):
    suite, runner = _runner(tmp_path, config_factory, discovery_fixture, monkeypatch)
    try:
        first = runner.lanes["zone-a"]
        first.reporter.result(
            "CHECK", "same-subnet", "PASS", "done before cancellation"
        )
        cancelled = runner.lanes["zone-b"]
        # CLI cancellation writes directly to the parent, outside ScopedReporter.
        suite.reporter.result(
            cancelled.reporter.scoped_test_id("CHECK"),
            "same-subnet",
            "NOT_RUN_CANCELLED",
            "operator cancelled",
        )
        suite.mark_terminal_state("CANCELLED", "received signal")
        _clean(monkeypatch, runner)
        assert suite.cleanup_if_required(False) is True
        suite.mark_terminal_state("CANCELLED", "received signal")
        assert first.checkpoint.state == "COMPLETED"
        assert cancelled.checkpoint.state == "CANCELLED"
        assert cancelled.checkpoint.error == "received signal"
        assert cancelled.checkpoint.completed_test_ids == ["CHECK"]
        assert cancelled.checkpoint.pending_test_ids == []
        assert cancelled.checkpoint.cleanup_state == "COMPLETE"
    finally:
        suite.reporter.logger.close()


def test_zone_persistence_failure_prevents_new_parent_complete_checkpoint(
    tmp_path, config_factory, discovery_fixture, monkeypatch
):
    suite, runner = _runner(tmp_path, config_factory, discovery_fixture, monkeypatch)
    try:
        runner.run()
        suite._save_checkpoint("TESTS_COMPLETE", "tests-complete", None)
        suite.reporter.cleanup_summary["complete"] = True
        suite.checkpoint.cleanup_state = "COMPLETE"
        failed = runner.lanes["zone-b"]
        monkeypatch.setattr(
            failed.state_store,
            "save",
            mock.Mock(side_effect=OSError("disk unavailable")),
        )
        with pytest.raises(OSError, match="disk unavailable"):
            suite._save_checkpoint("COMPLETED", "finished", None)
        assert suite.state_store.load(suite.checkpoint.run_id).state == "TESTS_COMPLETE"
    finally:
        suite.reporter.logger.close()


def test_cancelled_lane_keeps_signal_reason_when_cleanup_is_incomplete(
    tmp_path, config_factory, discovery_fixture, monkeypatch
):
    suite, runner = _runner(tmp_path, config_factory, discovery_fixture, monkeypatch)
    try:
        suite.record_cancelled_results("original operator signal")
        suite.mark_terminal_state("CANCELLED", "original operator signal")
        suite.checkpoint.state = "CLEANUP_INCOMPLETE"
        suite.checkpoint.cleanup_state = "INCOMPLETE"
        suite.sync_zone_checkpoints()
        for lane in runner.lanes.values():
            assert lane.checkpoint.state == "CLEANUP_INCOMPLETE"
            assert lane.checkpoint.metadata["execution_state"] == "CANCELLED"
            assert lane.checkpoint.error == "original operator signal"
    finally:
        suite.reporter.logger.close()
