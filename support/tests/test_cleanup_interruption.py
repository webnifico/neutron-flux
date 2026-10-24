from __future__ import annotations

import json
import signal
import threading
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.cancellation import (
    begin_cleanup_after_cancellation,
    cleanup_in_progress,
    hard_abort_requested,
    reset_cancellation,
)
from neutron_flux.cleanup import CleanupManager
from neutron_flux.cli import _execute_locked_action, _signal_handler
from neutron_flux.errors import RunCancelledError
from neutron_flux.reporting import Reporter, ResourceTracker, ScopedReporter
from neutron_flux.scheduling import READ_WORKERS
from neutron_flux.state import StateStore


def test_second_ctrl_c_during_cleanup_requests_durable_abort(capsys):
    reset_cancellation()
    try:
        with pytest.raises(KeyboardInterrupt):
            _signal_handler(signal.SIGINT, None)
        first_message = capsys.readouterr().err
        assert "clean up managed resources" in first_message
        assert "Press Ctrl-C again only to abort cleanup" in first_message

        begin_cleanup_after_cancellation()
        assert cleanup_in_progress() is True
        _signal_handler(signal.SIGINT, None)

        second_message = capsys.readouterr().err
        assert "Cleanup abort requested" in second_message
        assert "run cleanup again for this run" in second_message
        assert hard_abort_requested() is True
    finally:
        reset_cancellation()


def test_delete_cancellation_is_not_a_per_resource_failure(config_factory, tmp_path):
    config = config_factory(action="cleanup", report_dir=tmp_path / "reports")
    reporter = Reporter(config, "cancelled-delete")
    tracker = ResourceTracker(reporter)
    resource = tracker.add("network", "network-1", "managed-network")
    manager = CleanupManager(
        SimpleNamespace(exists=lambda *_args: True),
        reporter,
        tracker,
        config,
    )

    with pytest.raises(RunCancelledError, match="cleanup stopped"):
        manager._delete_record(
            resource,
            lambda _resource: (_ for _ in ()).throw(
                RunCancelledError("cleanup stopped")
            ),
        )

    assert resource.cleanup_state == "DELETE_REQUESTED"
    assert resource.delete_status not in {"delete-error", "leftover"}
    assert resource.cleanup_error is None
    assert reporter.cleanup_summary["errors"] == []
    reporter.logger.close()


def test_interrupted_cleanup_preserves_confirmed_deletions_without_false_leftovers(
    config_factory, tmp_path
):
    config = config_factory(action="cleanup", report_dir=tmp_path / "reports")
    reporter = Reporter(config, "interrupted-cleanup")
    tracker = ResourceTracker(reporter)
    deleted = tracker.add("floating_ip", "fip-deleted", "192.0.2.10")
    tracker.mark_deleted(deleted)
    pending = tracker.add("network", "network-pending", "managed-network")

    def cancelled_exists(_resource_type: str, _resource_id: str) -> bool:
        raise RunCancelledError("received signal 2")

    manager = CleanupManager(
        SimpleNamespace(exists=cancelled_exists),
        reporter,
        tracker,
        config,
    )

    assert manager.cleanup(adopt_discovered=False) is False
    assert deleted.delete_status == "deleted"
    assert deleted.cleanup_state == "DELETED"
    assert pending.delete_status not in {"delete-error", "leftover"}
    assert reporter.cleanup_summary["complete"] is None
    assert reporter.cleanup_summary["interrupted"] is True
    assert reporter.cleanup_summary["deleted"] == 1
    assert reporter.cleanup_summary["unverified_resource_count"] == 1
    assert reporter.cleanup_summary["leftovers"] == []
    assert reporter.cleanup_summary["errors"] == []
    assert "verification-error" not in reporter.report_path.read_text(encoding="utf-8")
    reporter.logger.close()


def test_hard_abort_before_cleanup_remains_recovery_eligible(
    config_factory, tmp_path, monkeypatch
):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    state_store = StateStore(config.report_dir)

    class FakeSuite:
        reporter: Reporter

        def __init__(self, config, reporter, state_store, checkpoint):
            self.reporter = reporter
            self.checkpoint = checkpoint
            FakeSuite.reporter = reporter
            ResourceTracker(reporter).add(
                "network", "network-unverified", "managed-network"
            )

        def execute(self):
            try:
                _signal_handler(signal.SIGINT, None)
            except KeyboardInterrupt:
                _signal_handler(signal.SIGINT, None)
                raise

        def record_cancelled_results(self, _reason):
            return 0

        def mark_terminal_state(self, state, message=None):
            self.checkpoint.state = state
            self.checkpoint.error = message

        def cleanup_if_required(self, _successful_execution):
            pytest.fail("hard abort before cleanup must not issue cleanup commands")

    monkeypatch.setattr("neutron_flux.cli.Suite", FakeSuite)
    code = _execute_locked_action(
        config,
        state_store,
        "hard-abort-before-cleanup",
        None,
        reopen_existing_run=False,
    )

    checkpoint = state_store.load("hard-abort-before-cleanup")
    recovered = state_store.latest(incomplete_only=True)
    payload = json.loads(FakeSuite.reporter.results_path.read_text(encoding="utf-8"))
    assert code == 130
    assert checkpoint.state == "CLEANUP_INCOMPLETE"
    assert checkpoint.cleanup_state == "INCOMPLETE"
    assert recovered.run_id == checkpoint.run_id
    assert payload["cleanup"]["complete"] is None
    assert payload["cleanup"]["unverified_resource_count"] == 1
    assert payload["cleanup"]["leftovers"] == []


def test_placement_verification_propagates_cleanup_cancellation(
    config_factory, tmp_path
):
    config = config_factory(action="cleanup", report_dir=tmp_path / "reports")
    reporter = Reporter(config, "interrupted-placement-verification")
    tracker = ResourceTracker(reporter)
    tracker.add("server", "server-1", "managed-server")

    def cancelled_exists(_resource_type: str, _resource_id: str) -> bool:
        raise RunCancelledError("received signal 2")

    manager = CleanupManager(
        SimpleNamespace(exists=cancelled_exists),
        reporter,
        tracker,
        config,
    )

    with pytest.raises(RunCancelledError, match="received signal 2"):
        manager._verify_placement_allocations()
    reporter.logger.close()


def test_exact_run_inventory_stops_on_cleanup_cancellation(config_factory, tmp_path):
    config = config_factory(action="cleanup", report_dir=tmp_path / "reports")
    reporter = Reporter(config, "interrupted-exact-run-inventory")
    tracker = ResourceTracker(reporter)
    osc = mock.Mock()
    barrier = threading.Barrier(READ_WORKERS, timeout=5)
    lock = threading.Lock()
    started = []
    drained = []
    active = 0
    peak = 0

    def cancel_initial_read(*args, **_kwargs):
        nonlocal active, peak
        with lock:
            started.append(args)
            active += 1
            peak = max(peak, active)
        try:
            # Admit the whole initial read batch before cancellation. No later
            # resource family or fallback query should then be submitted.
            barrier.wait()
            raise RunCancelledError("received signal 2")
        finally:
            with lock:
                active -= 1
                drained.append(args)

    osc.json.side_effect = cancel_initial_read
    tracker.add = mock.Mock(wraps=tracker.add)
    manager = CleanupManager(osc, reporter, tracker, config)
    try:
        with pytest.raises(RunCancelledError, match="received signal 2"):
            manager._adopt_orphans(reporter.run_tag, reporter.name_prefix)

        allowed = {
            ("floating", "ip", "list", "--tags", reporter.run_tag),
            ("server", "list"),
            ("router", "list", "--tags", reporter.run_tag),
            ("port", "list", "--tags", reporter.run_tag),
        }
        assert 0 < osc.json.call_count <= READ_WORKERS
        assert set(started) == allowed
        assert len(started) == len(set(started))
        assert peak <= READ_WORKERS
        assert active == 0
        assert set(drained) == set(started)
        assert len(drained) == len(started)
        osc.run.assert_not_called()
        tracker.add.assert_not_called()
        assert reporter.resources == []
        assert reporter.cleanup_summary["errors"] == []
        assert reporter.cleanup_summary["leftovers"] == []
    finally:
        reporter.logger.close()


def test_repeated_interrupt_during_run_cleanup_still_finalizes_durable_state(
    config_factory, tmp_path, monkeypatch
):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    state_store = StateStore(config.report_dir)

    class FakeSuite:
        reporter: Reporter

        def __init__(self, config, reporter, state_store, checkpoint):
            self.reporter = reporter
            self.checkpoint = checkpoint
            FakeSuite.reporter = reporter

        def execute(self):
            _signal_handler(signal.SIGINT, None)
            raise AssertionError("the first interrupt must unwind execution")

        def record_cancelled_results(self, _reason):
            return 0

        def mark_terminal_state(self, state, message=None):
            self.checkpoint.state = state
            self.checkpoint.error = message

        def cleanup_if_required(self, _successful_execution):
            assert cleanup_in_progress() is True
            _signal_handler(signal.SIGINT, None)
            self.reporter.cleanup_summary.update(
                {
                    "attempted": True,
                    "complete": None,
                    "interrupted": True,
                    "scope_verification": ("interrupted-before-final-verification"),
                    "unverified_resource_count": 2,
                }
            )
            self.checkpoint.cleanup_state = "INCOMPLETE"
            return False

    monkeypatch.setattr("neutron_flux.cli.Suite", FakeSuite)
    code = _execute_locked_action(
        config,
        state_store,
        "durable-cleanup-interrupt",
        None,
        reopen_existing_run=False,
    )

    checkpoint = state_store.load("durable-cleanup-interrupt")
    payload = json.loads(FakeSuite.reporter.results_path.read_text(encoding="utf-8"))
    assert code == 130
    assert checkpoint.state == "CLEANUP_INCOMPLETE"
    assert checkpoint.cleanup_state == "INCOMPLETE"
    assert checkpoint.metadata["cleanup_interrupted"] is True
    assert payload["cleanup"]["interrupted"] is True
    assert payload["cleanup"]["complete"] is None
    assert payload["cleanup"]["leftovers"] == []
    report_text = FakeSuite.reporter.report_path.read_text(encoding="utf-8")
    assert "Cleanup:         INTERRUPTED" in report_text
    assert "2 tracked resource(s) unverified" in report_text
    assert "rerun cleanup for this run" in report_text
    report_html = FakeSuite.reporter.html_report_path.read_text(encoding="utf-8")
    assert '"interrupted":true' in report_html
    assert '"unverified_resource_count":2' in report_html


def test_multi_zone_interruption_skips_parent_sweep_and_preserves_known_state(
    config_factory, tmp_path
):
    import neutron_flux.multi_zone as multi_zone

    config = config_factory(action="run", report_dir=tmp_path / "reports")
    reporter = Reporter(config, "multi-zone-cleanup-interrupt")
    scoped = ScopedReporter(reporter, "az-bc-van1", availability_zone="bc-van1")
    tracker = ResourceTracker(scoped)
    deleted = tracker.add("floating_ip", "fip-deleted", "192.0.2.20")
    tracker.mark_deleted(deleted)
    tracker.add("network", "network-unverified", "managed-network")

    class InterruptedCleanup:
        def cleanup(self, **_kwargs):
            scoped.cleanup_summary.update(
                {
                    "attempted": True,
                    "complete": None,
                    "interrupted": True,
                    "interruption_reason": "received signal 2",
                    "unverified_resource_count": 1,
                    "leftovers": [],
                    "errors": [],
                }
            )
            return False

    orchestrator = object.__new__(multi_zone.MultiZoneOrchestrator)
    orchestrator.config = config
    orchestrator.reporter = reporter
    orchestrator.logger = reporter.logger
    orchestrator.zone_plan = SimpleNamespace(parallel_workers=1)
    orchestrator.lanes = {
        "bc-van1": SimpleNamespace(
            cleanup_manager=InterruptedCleanup(),
            reporter=scoped,
        )
    }
    orchestrator.shared_security_cleanup = SimpleNamespace(
        cleanup=lambda **_kwargs: pytest.fail("shared cleanup must not start")
    )
    orchestrator.shared_security_reporter = None
    orchestrator.shared_security_builder = None
    orchestrator.cloud_operation_coordinator = SimpleNamespace(lock=None)
    orchestrator.lifecycle_lock = None

    assert orchestrator.cleanup_all() is False
    assert deleted.delete_status == "deleted"
    assert reporter.cleanup_summary["complete"] is None
    assert reporter.cleanup_summary["interrupted"] is True
    assert reporter.cleanup_summary["deleted"] == 1
    assert reporter.cleanup_summary["unverified_resource_count"] == 1
    assert reporter.cleanup_summary["leftovers"] == []
    assert "verification-error" not in reporter.report_path.read_text(encoding="utf-8")
    reporter.logger.close()
