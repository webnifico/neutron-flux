from __future__ import annotations

import json
import signal
import subprocess
import threading
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.cancellation import (
    cancellation_active,
    cancellation_reconciliation,
    force_cancellation_abort,
    hard_abort_requested,
    raise_if_cancelled,
    request_cancellation,
    reset_cancellation,
)
from neutron_flux.cleanup import CleanupManager
from neutron_flux.cli import _signal_handler
from neutron_flux.cloud_operation import CloudOperationCoordinator
from neutron_flux.errors import (
    CloudOperationBlockedError,
    CommandTimeoutError,
    ProbeServiceError,
    RunCancelledError,
)
from neutron_flux.execution.placement import PlacementValidationMixin
from neutron_flux.models import ComputeHostInfo, Endpoint
from neutron_flux.reporting import Reporter, ResourceTracker
from neutron_flux.resource_naming import ResourceNameRegistry
from neutron_flux.resources import ResourceBuilder


class _Logger:
    def __init__(self) -> None:
        self.lines: list[tuple[str, str]] = []

    def log(self, message: str, level: str = "INFO") -> None:
        self.lines.append((level, message))


class _Reporter:
    def __init__(self, run_dir, report_dir) -> None:
        self.logger = _Logger()
        self.events: list[dict[str, object]] = []
        self.run_dir = run_dir
        self.config = SimpleNamespace(report_dir=report_dir)

    def event(self, event_type: str, message: str, **details: object) -> None:
        self.events.append({"type": event_type, "message": message, "details": details})


def _coordinator(tmp_path) -> CloudOperationCoordinator:
    run_dir = tmp_path / "runs" / "current"
    run_dir.mkdir(parents=True)
    reporter = _Reporter(run_dir, tmp_path)
    coordinator = CloudOperationCoordinator(reporter)
    coordinator._sleep = lambda *_args, **_kwargs: None
    return coordinator


def _endpoint(side: str, host: str) -> Endpoint:
    return Endpoint(
        label=f"group:{side}",
        server_id=f"server-{side}",
        server_name=f"server-{side}",
        management_port_id=f"management-{side}",
        management_ip=f"10.0.0.{2 if side == 'A' else 3}",
        test_port_id=f"test-{side}",
        test_mac=f"fa:16:3e:00:00:0{1 if side == 'A' else 2}",
        fixed_ips={"subnet": f"192.0.2.{2 if side == 'A' else 3}"},
        host=host,
        availability_zone="az1",
        volume_id=None,
        side=side,
    )


def test_journal_is_written_before_callback(tmp_path):
    coordinator = _coordinator(tmp_path)
    journal = coordinator.journal.path
    assert journal is not None

    def callback():
        rows = [
            json.loads(line)
            for line in journal.read_text(encoding="utf-8").splitlines()
            if line
        ]
        assert [row["outcome"] for row in rows[-2:]] == [
            "PREPARED",
            "SUBMITTING",
        ]
        assert rows[-1]["submitted"] is True
        return subprocess.CompletedProcess(["openstack"], 0, "", "")

    coordinator.execute(
        "port-delete",
        ("port", "delete", "port-1"),
        callback,
    )
    assert (
        coordinator.cloud_operation_summary()["operations"][-1]["outcome"]
        == "SUCCEEDED"
    )


@pytest.mark.parametrize("resource", ["port", "server", "network", "volume"])
def test_fresh_name_cannot_bypass_ambiguous_create_in_transaction_or_resume(
    tmp_path, resource
):
    coordinator = _coordinator(tmp_path)
    path = tmp_path / "resource-identities.jsonl"
    registry = ResourceNameRegistry("nflux-ambiguous", journal_path=path)

    def allocate(owner):
        name = owner.allocate(
            identity="same-endpoint",
            descriptor="endpoint",
            role="a",
            resource_type=resource,
            limit=63,
        )
        owner.claim_for_create(name, resource_type=resource)
        return name

    first = allocate(registry)
    callback = mock.Mock(side_effect=OSError("lost API response"))
    blocked = mock.Mock()
    with pytest.raises(CloudOperationBlockedError, match="At-most-once"):
        with coordinator.transaction("server-create", "create endpoint"):
            with pytest.raises(OSError, match="lost API response"):
                coordinator.execute(
                    "server-create", (resource, "create", first), callback
                )
            replacement = allocate(registry)
            assert replacement != first
            coordinator.execute(
                "server-create", (resource, "create", replacement), blocked
            )

    restored = CloudOperationCoordinator(coordinator.reporter)
    restored_registry = ResourceNameRegistry("nflux-ambiguous", journal_path=path)
    third = allocate(restored_registry)
    assert third not in {first, replacement}
    with pytest.raises(CloudOperationBlockedError, match="remains AMBIGUOUS"):
        restored.execute("server-create", (resource, "create", third), blocked)
    callback.assert_called_once()
    blocked.assert_not_called()


def test_ambiguous_transaction_stays_quarantined(tmp_path):
    coordinator = _coordinator(tmp_path)
    with coordinator.transaction(
        "migration",
        "ambiguous migration",
        resource_ids=["server-1"],
        source_host="compute1",
        destination_host="compute2",
        max_attempts=2,
    ):
        with pytest.raises(CommandTimeoutError):
            coordinator.execute(
                "migration",
                ("server", "migrate", "--host", "compute2", "server-1"),
                lambda: (_ for _ in ()).throw(
                    CommandTimeoutError(["openstack", "server", "migrate"], 60)
                ),
            )
        coordinator.keep_current_ambiguity("acceptance window expired")

    summary = coordinator.cloud_operation_summary()
    assert summary["unresolved_count"] == 1
    assert summary["operations"][-1]["outcome"] == "AMBIGUOUS"
    assert summary["quarantined_resources"]["server-1"]
    assert summary["quarantined_hosts"] == ["compute1", "compute2"]
    assert coordinator.cleanup_blocker("server-1") is not None


def test_successful_transaction_resolves_in_progress(tmp_path):
    coordinator = _coordinator(tmp_path)
    with coordinator.transaction(
        "migration",
        "verified migration",
        resource_ids=["server-1"],
        source_host="compute1",
        destination_host="compute2",
        final_cooldown=5,
    ):
        coordinator.execute(
            "migration",
            ("server", "migrate", "--host", "compute2", "server-1"),
            lambda: subprocess.CompletedProcess(["openstack"], 0, "", ""),
        )
        assert coordinator.current_transaction_records()[-1]["outcome"] == "IN_PROGRESS"
    assert (
        coordinator.cloud_operation_summary()["operations"][-1]["outcome"]
        == "SUCCEEDED"
    )


def test_replayed_ambiguous_journal_blocks_cleanup(tmp_path):
    old = tmp_path / "runs" / "old"
    old.mkdir(parents=True)
    (old / "cloud-operations.jsonl").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "record_type": "operation",
                "operation_id": "old-migration",
                "transaction_id": "old-transaction",
                "kind": "migration",
                "resource_ids": ["server-old"],
                "source_host": "compute1",
                "destination_host": "compute2",
                "outcome": "AMBIGUOUS",
                "submitted": True,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    coordinator = _coordinator(tmp_path)
    assert coordinator.cleanup_blocker("server-old") is not None
    assert coordinator.cloud_operation_summary()["unresolved_count"] == 1


def test_only_b_is_selected_without_hidden_two_attempt_cap():
    source = _endpoint("A", "compute1")
    destination = _endpoint("B", "compute1")
    targets = [
        ComputeHostInfo(f"compute{index}", "az1", True, True) for index in (2, 3, 4)
    ]
    holder = type("PlacementHarness", (PlacementValidationMixin,), {})()
    holder.config = SimpleNamespace(migration_submission_budget=99)
    holder.builder = SimpleNamespace(
        select_compute_migration_targets=lambda *args, **kwargs: (
            targets,
            "eligible",
        )
    )
    attempts, reason = holder._compute_migration_attempts(
        source,
        destination,
        desired_relation="different",
    )
    assert reason == "eligible"
    assert len(attempts) == 3
    assert all(moving is destination for moving, _stationary, _target in attempts)
    assert all(stationary is source for _moving, stationary, _target in attempts)


def test_cancellation_reconciliation_is_thread_local():
    reset_cancellation()
    entered = threading.Event()
    release = threading.Event()
    worker_errors: list[BaseException] = []

    def worker() -> None:
        try:
            with cancellation_reconciliation():
                assert cancellation_active() is False
                raise_if_cancelled()
                entered.set()
                assert release.wait(timeout=5)
        except (AssertionError, RunCancelledError) as exc:
            worker_errors.append(exc)
            entered.set()

    try:
        assert request_cancellation("test") is True
        thread = threading.Thread(target=worker)
        thread.start()
        assert entered.wait(timeout=5)
        assert cancellation_active() is True
        with pytest.raises(RunCancelledError, match="test"):
            raise_if_cancelled()
        release.set()
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert worker_errors == []
        force_cancellation_abort("second signal")
        assert hard_abort_requested() is True
    finally:
        release.set()
        reset_cancellation()


def test_second_signal_is_hard_abort():
    reset_cancellation()
    try:
        with pytest.raises(KeyboardInterrupt):
            _signal_handler(signal.SIGINT, None)
        _signal_handler(signal.SIGINT, None)
        assert hard_abort_requested() is True
    finally:
        reset_cancellation()


def test_cleanup_skips_quarantined_resource(config_factory, tmp_path):
    config = config_factory(action="cleanup", report_dir=tmp_path / "reports")
    reporter = Reporter(config, "quarantined-cleanup")
    tracker = ResourceTracker(reporter)
    record = tracker.add("server", "server-1", "server")
    blocker = SimpleNamespace(
        lock=threading.RLock(),
        cleanup_blocker=lambda resource_id, **kwargs: (
            "ambiguous migration old-migration"
        ),
    )
    manager = CleanupManager(
        SimpleNamespace(exists=lambda *_args: True),
        reporter,
        tracker,
        config,
        cloud_operation_coordinator=blocker,
    )
    handler = mock.Mock()
    manager._delete_record(record, handler)
    handler.assert_not_called()
    assert record.cleanup_state == "QUARANTINED"
    assert record.delete_status == "leftover"


def test_probe_adoption_requires_stable_process_identity(config_factory, monkeypatch):
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.logger = mock.Mock()
    builder.security_control_ports = {4: 18082, 6: 18082}
    builder.probe_service = mock.Mock()
    builder.probe_service.is_running.return_value = False
    evidence = {
        "listeners": {"4": {"tcp": True, "udp": True}},
        "processes": [{"pid": 42, "start_ticks": "100"}],
        "inspection_complete": True,
    }
    builder._existing_probe_service_ready = mock.Mock(
        side_effect=[(True, evidence), (True, evidence)]
    )
    monkeypatch.setattr("neutron_flux.runtime.probes.time.sleep", lambda _s: None)
    endpoint = _endpoint("B", "compute2")
    builder._start_probe_server(endpoint, reuse_existing=True)
    builder.probe_service.start.assert_not_called()
    assert endpoint.metadata["probe_service"]["mode"] == "adopted-surviving-process"


def test_eaddrinuse_is_reconciled_without_second_start(config_factory):
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.logger = mock.Mock()
    builder.security_control_ports = {4: 18082, 6: 18082}
    builder.probe_service = mock.Mock()
    builder.probe_service.is_running.return_value = False
    builder.probe_service.start.side_effect = ProbeServiceError("EADDRINUSE")
    builder._stable_existing_probe_service = mock.Mock(
        return_value=(True, {"stable_identity": True})
    )
    endpoint = _endpoint("B", "compute2")
    builder._start_probe_server(endpoint, reuse_existing=False)
    builder.probe_service.start.assert_called_once()
    assert endpoint.metadata["probe_service"]["ready"] is True
