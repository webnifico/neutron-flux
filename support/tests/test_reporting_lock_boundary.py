from __future__ import annotations

import subprocess
import threading
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux import scheduling
from neutron_flux.cancellation import request_cancellation, reset_cancellation
from neutron_flux.errors import RunCancelledError
from neutron_flux.reporting import Reporter, ScopedReporter
from neutron_flux.suite import Suite


@pytest.mark.parametrize("scoped", [False, True])
def test_heartbeat_can_obtain_api_slot_while_completed_reads_publish_timings(
    config_factory, monkeypatch, scoped
):
    """Four readers need event storage while a result writer needs a read slot."""
    reset_cancellation()
    slots = threading.BoundedSemaphore(4)
    monkeypatch.setattr(scheduling, "_READ_SLOTS", slots)
    reporter = Reporter(config_factory(action="run"), "sample-heartbeat")
    scoped_reporter = (
        ScopedReporter(reporter, "az1", availability_zone="az1") if scoped else reporter
    )
    checkpoint = SimpleNamespace(metadata={}, last_activity="", updated_at="")
    suite = Suite(reporter.config, reporter, mock.Mock(), checkpoint)
    # The API wrapper uses this reporter when publishing admission/API timings.
    suite.osc.cloud_operation_coordinator.reporter = scoped_reporter
    readers_started = threading.Barrier(5)
    return_reads = threading.Event()
    heartbeat_waiting = threading.Event()
    published = threading.Event()
    failures = []
    heartbeat_calls = []

    def invoke(command, **kwargs):
        if command[1:3] == ["server", "show"]:
            readers_started.wait(timeout=3)
            assert return_reads.wait(3)
        else:
            assert command[1:3] == ["server", "set"]
            heartbeat_calls.append(command)
        return subprocess.CompletedProcess(command, 0, "{}", "")

    monkeypatch.setattr("neutron_flux.openstack.run_cancellable", invoke)

    def heartbeat(state):
        heartbeat_waiting.set()
        return_reads.set()
        suite.osc.run(
            "server", "set", "--property", f"state={state}", "controller", timeout=60
        )

    suite.builder = SimpleNamespace(update_cloud_heartbeat=heartbeat)

    def reader():
        try:
            suite.osc.run("server", "show", "endpoint", timeout=60)
        except (RunCancelledError, AssertionError, threading.BrokenBarrierError) as exc:
            failures.append(exc)

    def publish():
        try:
            scoped_reporter.result("TCP-A-B", "same-subnet", "PASS", "reachable")
            published.set()
        except (RunCancelledError, AssertionError) as exc:
            failures.append(exc)

    readers = [threading.Thread(target=reader, daemon=True) for _ in range(4)]
    writer = threading.Thread(target=publish, daemon=True)
    try:
        for thread in readers:
            thread.start()
        readers_started.wait(timeout=3)
        writer.start()
        assert heartbeat_waiting.wait(3)
        assert published.wait(3), "Result publication deadlocked with API-slot release"
        for thread in [*readers, writer]:
            thread.join(timeout=3)
            assert not thread.is_alive()
        assert not failures
        assert len(heartbeat_calls) == 1
        assert len(reporter.results) == 1 and reporter.results[0].status == "PASS"
        api_timings = [
            e
            for e in reporter.events
            if e["type"] == "runtime-timing" and e["details"]["category"] == "api-read"
        ]
        assert len(api_timings) == 4
        write_timings = [
            e
            for e in reporter.events
            if e["type"] == "runtime-timing" and e["details"]["category"] == "api-write"
        ]
        assert len(write_timings) == 1
        assert all(e["details"]["completed"] for e in api_timings)
        for _ in range(4):
            assert slots.acquire(blocking=False)
        assert not slots.acquire(blocking=False)
        for _ in range(4):
            slots.release()
    finally:
        # Older code fails above, then cancellation releases its cyclic wait.
        reporter.logger.heartbeat = None
        return_reads.set()
        request_cancellation("bounded deadlock regression teardown")
        for thread in [*readers, writer]:
            if thread.ident is not None:
                thread.join(timeout=3)
        reset_cancellation()
        reporter.logger.close()
    assert not any(isinstance(exc, RunCancelledError) for exc in failures)
