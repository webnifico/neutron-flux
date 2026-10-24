from __future__ import annotations

import json
import signal
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux import cancellation
from neutron_flux.cancellation import (
    begin_cleanup_after_cancellation,
    cancellation_active,
    cancellation_reconciliation,
    hard_abort_requested,
    raise_if_cancelled,
    reset_cancellation,
)
from neutron_flux.cli import _execute_locked_action, _signal_handler
from neutron_flux.errors import RunCancelledError
from neutron_flux.models import Endpoint, Plan
from neutron_flux.models import TestSpec as FluxTestSpec
from neutron_flux.reporting import Reporter
from neutron_flux.resources import ResourceBuilder
from neutron_flux.state import StateStore


@pytest.fixture
def cancellable_process(monkeypatch):
    reset_cancellation()
    process = mock.Mock(pid=61001, returncode=None)
    process.poll.side_effect = lambda: process.returncode
    events = []
    monkeypatch.setattr(
        cancellation.subprocess, "Popen", mock.Mock(return_value=process)
    )
    monkeypatch.setattr(
        cancellation.os,
        "killpg",
        lambda pid, signum: events.append(("signal", signum)),
    )
    unregister = cancellation.unregister_process

    def record_unregister(child):
        events.append(("unregister", child.returncode))
        unregister(child)

    monkeypatch.setattr(cancellation, "unregister_process", record_unregister)
    try:
        yield process, events
    finally:
        reset_cancellation()


@pytest.mark.parametrize("escalate", [False, True])
@pytest.mark.parametrize("failure", ["signal", "cancelled", "timeout"])
def test_cancellable_child_is_reaped_before_unregistering(
    cancellable_process, failure, escalate
):
    process, events = cancellable_process
    original = (
        subprocess.TimeoutExpired(["openstack"], 30)
        if failure == "timeout"
        else RunCancelledError("cancelled during command")
    )
    calls = 0

    def communicate(*, input=None, timeout=None):
        nonlocal calls, original
        calls += 1
        events.append(("communicate", timeout))
        if calls == 1:
            if failure == "signal":
                try:
                    _signal_handler(signal.SIGINT, None)
                except KeyboardInterrupt as exc:
                    original = exc
                    raise
            raise original
        if calls == 2 and escalate:
            raise subprocess.TimeoutExpired(["openstack"], timeout)
        process.returncode = -9 if escalate else -15
        return "", ""

    process.communicate.side_effect = communicate
    with pytest.raises(
        (KeyboardInterrupt, RunCancelledError, subprocess.TimeoutExpired)
    ) as caught:
        cancellation.run_cancellable(["openstack", "server", "list"], timeout=30)

    assert caught.value is original
    assert events[-1] == ("unregister", -9 if escalate else -15)
    assert ("communicate", 5) in events
    assert (("signal", signal.SIGKILL) in events) is escalate
    assert process.pid not in cancellation._STATE._processes


def test_cancellable_cleanup_pipe_failure_reaps_and_preserves_cancellation(
    cancellable_process,
):
    process, events = cancellable_process
    original = KeyboardInterrupt("original operator cancellation")
    process.communicate.side_effect = [
        original,
        OSError("cannot drain child pipes"),
        OSError("child pipes remain unavailable"),
    ]

    def wait():
        process.returncode = -9
        events.append(("wait", process.returncode))
        return process.returncode

    process.wait.side_effect = wait
    with pytest.raises(KeyboardInterrupt) as caught:
        cancellation.run_cancellable(["openstack", "server", "list"])

    assert caught.value is original
    assert events == [
        ("signal", signal.SIGTERM),
        ("signal", signal.SIGKILL),
        ("wait", -9),
        ("unregister", -9),
    ]
    assert process.pid not in cancellation._STATE._processes


def test_cancellable_reaps_before_propagating_fresh_cleanup_exit(cancellable_process):
    process, events = cancellable_process
    original = KeyboardInterrupt("operator cancellation")
    fresh_exit = SystemExit(8)
    calls = 0

    def communicate(*, input=None, timeout=None):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise original
        if calls == 2:
            raise fresh_exit
        process.returncode = -9
        return "", ""

    process.communicate.side_effect = communicate
    with pytest.raises(SystemExit) as caught:
        cancellation.run_cancellable(["openstack", "server", "list"])

    assert caught.value is fresh_exit
    assert events[-1] == ("unregister", -9)
    assert ("signal", signal.SIGKILL) in events
    process.wait.assert_called_once_with()


@pytest.mark.parametrize("registered", [False, True])
def test_cancellable_registration_interruption_reaps_child(
    cancellable_process, monkeypatch, registered
):
    process, events = cancellable_process
    original = KeyboardInterrupt("interrupted while registering child")
    register = cancellation.register_process

    def interrupted_register(child):
        if registered:
            register(child)
        raise original

    def reap(*, timeout=None):
        process.returncode = -15
        return "", ""

    monkeypatch.setattr(cancellation, "register_process", interrupted_register)
    process.communicate.side_effect = reap
    with pytest.raises(KeyboardInterrupt) as caught:
        cancellation.run_cancellable(["openstack", "server", "list"])

    assert caught.value is original
    assert events == [("signal", signal.SIGTERM), ("unregister", -15)]
    assert process.pid not in cancellation._STATE._processes


def test_reconciliation_allows_first_cancellation(cancellable_process):
    process, events = cancellable_process
    with pytest.raises(KeyboardInterrupt):
        _signal_handler(signal.SIGINT, None)
    with cancellation_reconciliation():
        assert cancellation_active() is False
        raise_if_cancelled()
        cancellation.register_process(process)
    assert events == []
    assert process.pid in cancellation._STATE._processes


@pytest.mark.parametrize("abort_inside", [False, True])
def test_emergency_abort_overrides_reconciliation(cancellable_process, abort_inside):
    process, events = cancellable_process
    with pytest.raises(KeyboardInterrupt):
        _signal_handler(signal.SIGINT, None)
    if not abort_inside:
        _signal_handler(signal.SIGINT, None)
    with cancellation_reconciliation(), cancellation_reconciliation():
        if abort_inside:
            _signal_handler(signal.SIGINT, None)
        begin_cleanup_after_cancellation()
        assert cancellation_active() is True
        with pytest.raises(RunCancelledError):
            raise_if_cancelled()
        cancellation.register_process(process)
        assert events == [("signal", signal.SIGKILL)]
        with pytest.raises(RunCancelledError):
            cancellation.run_cancellable(["openstack", "server", "list"])
        cancellation.subprocess.Popen.assert_not_called()


def _spec(test_id: str) -> FluxTestSpec:
    return FluxTestSpec(
        id=test_id,
        category="same-subnet",
        operation="connectivity",
        family=4,
        expectation="reachable",
        expectation_reason="planned coverage",
        authoritative=True,
        dependencies=["group"],
        source_group_id="group",
        destination_group_id="group",
        source_side="A",
        destination_side="B",
        source_subnet_id="subnet",
        destination_subnet_id="subnet",
        protocol="tcp",
        phase="intra",
        display_name=test_id,
        scenario="Same-network connectivity",
    )


def test_probe_reuse_verifies_wildcard_listener_through_guest_loopback(
    config_factory,
):
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory(tcp_port=18080, udp_port=18081)
    builder.security_control_ports = {4: 18082, 6: 18082}
    builder.probe_service = mock.Mock()
    builder.probe_service.is_running.return_value = False
    builder.logger = mock.Mock()
    endpoint = Endpoint(
        label="provider:B",
        server_id="server-b",
        server_name="server-b",
        management_port_id="mgmt",
        management_ip="10.254.0.40",
        test_port_id="test",
        test_mac="fa:16:3e:00:00:01",
        fixed_ips={"provider-subnet": "172.20.6.222"},
        host="compute3",
        availability_zone="bc-van1",
        volume_id=None,
        side="B",
    )
    commands: list[str] = []

    def ssh_endpoint(_endpoint, command, timeout=None):
        commands.append(command)
        return subprocess.CompletedProcess(
            ["ssh"],
            0,
            json.dumps(
                {
                    "listeners": {
                        "4": {
                            "tcp": True,
                            "udp": True,
                            "instance_id": "instance-42",
                            "errors": [],
                        }
                    },
                    "processes": [],
                    "service_identity": {
                        "probe_id": endpoint.server_id,
                        "instance_id": "instance-42",
                    },
                    "inspection_complete": True,
                }
            )
            + "\n",
            "",
        )

    builder.ssh_endpoint = ssh_endpoint
    ready, evidence = builder._existing_probe_service_ready(endpoint)

    assert ready is True
    assert evidence["listeners"]["4"]["tcp"] is True
    assert "127.0.0.1" in commands[0]
    assert "172.20.6.222" not in commands[0]

    builder._start_probe_server(endpoint, reuse_existing=True)
    builder.probe_service.start.assert_not_called()
    assert endpoint.metadata["probe_service"]["mode"] == "adopted-surviving-process"


def test_cancelled_plan_rows_are_not_execution_errors(config_factory, tmp_path):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    reporter = Reporter(config, "cancelled-accounting")
    specs = [_spec(f"check-{index}") for index in range(5)]
    reporter.plan = Plan([], [], {}, [], tests=specs)
    reporter.result(
        "check-0",
        "same-subnet",
        "PASS",
        "completed before cancellation",
        scenario="Same-network connectivity",
    )
    reporter.result(
        "check-1",
        "same-subnet",
        "BLOCKED_BY_SETUP_ERROR",
        "blocked by a prior readiness failure",
        scenario="Same-network connectivity",
    )
    reporter.cleanup_summary.update({"attempted": True, "complete": True})

    from neutron_flux.suite import Suite

    suite = object.__new__(Suite)
    suite.plan = reporter.plan
    suite.reporter = reporter
    suite.checkpoint = SimpleNamespace(
        completed_test_ids=[],
        pending_test_ids=[],
        failed_test_ids=[],
        metadata={},
    )
    assert suite.record_cancelled_results("received signal 2") == 3
    reporter.interrupted = True
    reporter.cancellation_reason = "received signal 2"

    assert reporter.finalize(130) == 130
    payload = json.loads(reporter.results_path.read_text(encoding="utf-8"))
    counts = payload["summary"]["counts"]
    assert counts["PASS"] == 1
    assert counts["BLOCKED_BY_SETUP_ERROR"] == 1
    assert counts["NOT_RUN_CANCELLED"] == 3
    assert counts.get("ERROR", 0) == 0
    assert payload["run"]["final_status"] == "CANCELLED"
    text = reporter.report_path.read_text(encoding="utf-8")
    assert "Execution errors:                   0" in text
    assert "Blocked by setup error:             1" in text
    assert "Cancelled before execution:         3" in text
    assert "NOT RUN — CANCELLED" in text
    assert "EXECUTION ERROR\n" not in text


def test_cleanup_waits_for_cancelled_worker_to_exit(
    config_factory, tmp_path, monkeypatch
):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    store = StateStore(config.report_dir)
    worker_started = threading.Event()
    worker_stopped = threading.Event()
    cleanup_called = threading.Event()

    class FakeSuite:
        def __init__(self, config, reporter, state_store, checkpoint):
            self.reporter = reporter
            self.checkpoint = checkpoint

        def execute(self):
            def worker():
                worker_started.set()
                while True:
                    try:
                        raise_if_cancelled()
                    except Exception:
                        worker_stopped.set()
                        raise
                    time.sleep(0.005)

            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(worker)
                assert worker_started.wait(2)
                _signal_handler(signal.SIGINT, None)
                future.result()
            return 0

        def mark_terminal_state(self, state, message=None):
            self.checkpoint.state = state
            self.checkpoint.error = message

        def record_cancelled_results(self, reason):
            return 0

        def cleanup_if_required(self, successful_execution):
            assert worker_stopped.is_set(), "cleanup raced a still-active AZ worker"
            cleanup_called.set()
            self.reporter.cleanup_summary.update(
                {"attempted": True, "complete": True, "deleted": 0}
            )
            self.checkpoint.cleanup_state = "COMPLETE"
            return True

    monkeypatch.setattr("neutron_flux.cli.Suite", FakeSuite)
    reset_cancellation()
    code = _execute_locked_action(
        config,
        store,
        "cancel-worker-order",
        None,
        reopen_existing_run=False,
    )

    assert code == 130
    assert worker_stopped.is_set()
    assert cleanup_called.is_set()
    assert cancellation_active() is False


def test_repeated_signal_does_not_interrupt_worker_drain():
    reset_cancellation()
    with pytest.raises(KeyboardInterrupt):
        _signal_handler(signal.SIGINT, None)
    assert cancellation_active() is True
    # A repeated signal is the explicit emergency hard-abort path.
    _signal_handler(signal.SIGINT, None)
    assert hard_abort_requested() is True
    reset_cancellation()


def test_early_cancellation_does_not_become_setup_failure(config_factory, tmp_path):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    reporter = Reporter(config, "early-cancel")
    specs = [_spec(f"check-{index}") for index in range(2)]
    reporter.plan = Plan([], [], {}, [], tests=specs)
    reporter.result(
        "check-0",
        "same-subnet",
        "NOT_RUN_CANCELLED",
        "Run cancelled by operator before this check executed: received signal 2",
        scenario="Same-network connectivity",
    )
    reporter.result(
        "check-1",
        "same-subnet",
        "NOT_RUN_CANCELLED",
        "Run cancelled by operator before this check executed: received signal 2",
        scenario="Same-network connectivity",
    )
    reporter.interrupted = True
    reporter.cancellation_reason = "received signal 2"
    reporter.cleanup_summary.update({"attempted": True, "complete": True})

    assert reporter.finalize(130) == 130
    payload = json.loads(reporter.results_path.read_text(encoding="utf-8"))
    assert payload["run"]["final_status"] == "CANCELLED"
    assert reporter.setup_failed is False
    assert reporter.setup_failures == []
