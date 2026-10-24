from __future__ import annotations

import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.cancellation import (
    begin_cleanup_after_cancellation,
    request_cancellation,
    reset_cancellation,
)
from neutron_flux.cloud_operation import CloudOperationCoordinator
from neutron_flux.errors import CloudOperationBlockedError, RunCancelledError
from neutron_flux.scheduling import (
    ActivityGate,
    admission,
    bounded_map,
    timed,
    timing_summary,
)


class Recorder:
    def __init__(self):
        self.logger = mock.Mock()
        self.events = []

    def event(self, event_type, message, **details):
        self.events.append({"type": event_type, "message": message, "details": details})


@pytest.mark.parametrize("prefix", [(), ("--os-compute-api-version", "2.95")])
@pytest.mark.parametrize("option", ["--help", "-h", "--version"])
def test_help_is_not_a_cloud_operation(prefix, option):
    assert (
        CloudOperationCoordinator.classify_openstack_command(
            (*prefix, "server", "create", option)
        )
        is None
    )


def test_help_like_resource_value_does_not_bypass_journaling():
    assert (
        CloudOperationCoordinator.classify_openstack_command(
            ("server", "delete", "--", "--help")
        )
        == "server-delete"
    )
    assert (
        CloudOperationCoordinator.classify_openstack_command(
            ("server", "create", "--property", "note=--help", "vm")
        )
        == "server-create"
    )


def test_nested_settlement_credits_elapsed_readiness(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr("neutron_flux.cloud_operation.time.monotonic", lambda: clock[0])
    recorder = Recorder()
    coordinator = CloudOperationCoordinator(recorder)
    waits = []

    def sleep(seconds, reason):
        waits.append(seconds)
        clock[0] += seconds

    coordinator._sleep = sleep
    coordinator.execute("port-create", ("port", "create", "new"), lambda: None)
    clock[0] += 1  # successful readback, already inside the five-second window
    coordinator.settle("server-create", "server wrapper")
    coordinator.settle("server-create", "endpoint wrapper")
    assert waits == [3.0, 1.0, 0.0]
    assert coordinator._last_completed_at == 100.0
    settlements = [
        item["details"]
        for item in recorder.events
        if item["type"] == "dataplane-settlement"
    ]
    assert settlements[-1]["credited_seconds"] == 5.0


def test_cleanup_scan_demands_fresh_visibility_window(monkeypatch):
    monkeypatch.setattr("neutron_flux.cloud_operation.time.monotonic", lambda: 200.0)
    coordinator = CloudOperationCoordinator(Recorder())
    coordinator._last_completed_at = 100.0
    coordinator._sleep = mock.Mock()
    coordinator.settle("network-topology", "second inventory", seconds=5, fresh=True)
    coordinator._sleep.assert_called_once_with(5.0, "second inventory")


@pytest.mark.parametrize(
    "message",
    [
        "Forbidden (HTTP 403)",
        "AvailabilityZone missing",
        "Invalid request",
        "Resource in use (HTTP 409)",
    ],
)
def test_deterministic_rejection_does_not_inflate_global_waits(message):
    coordinator = CloudOperationCoordinator(Recorder())
    coordinator._sleep = mock.Mock()
    response = subprocess.CompletedProcess([], 1, "", message)
    assert (
        coordinator.execute("port-create", ("port", "create", "bad"), lambda: response)
        is response
    )
    assert coordinator.adaptive_factor == 1.0


def test_slow_success_does_not_automatically_mean_congestion(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr("neutron_flux.cloud_operation.time.monotonic", lambda: clock[0])
    coordinator = CloudOperationCoordinator(Recorder())
    coordinator._sleep = mock.Mock()

    def submit():
        clock[0] += 35
        return subprocess.CompletedProcess([], 0, "ok", "")

    coordinator.execute("server-create", ("server", "create", "slow"), submit)
    assert coordinator.adaptive_factor == 1.0


def test_ambiguous_submission_still_blocks_unrelated_writes():
    coordinator = CloudOperationCoordinator(Recorder())
    coordinator._sleep = mock.Mock()
    response = subprocess.CompletedProcess([], 1, "", "HTTP 503 service unavailable")
    coordinator.execute("server-create", ("server", "create", "one"), lambda: response)
    with pytest.raises(CloudOperationBlockedError):
        coordinator.execute("server-create", ("server", "create", "two"), mock.Mock())
    assert coordinator.adaptive_factor > 1


def test_independent_creation_lifecycles_overlap():
    coordinator = CloudOperationCoordinator(Recorder())
    rendezvous = threading.Barrier(2)

    def lifecycle(index):
        with coordinator.freeze("server-create", f"server {index}"):
            rendezvous.wait(timeout=3)
        return index

    assert bounded_map(lifecycle, [1, 2], workers=2) == [1, 2]


def test_measurement_excludes_other_threads_and_is_reentrant():
    gate = ActivityGate()
    attempted = threading.Event()
    entered = threading.Event()

    def ordinary():
        attempted.set()
        with gate.scope():
            entered.set()

    with ThreadPoolExecutor(max_workers=1) as pool:
        with gate.scope(exclusive=True):
            with gate.scope(exclusive=True), gate.scope():
                future = pool.submit(ordinary)
                assert attempted.wait(2)
                assert not entered.wait(0.03)
        future.result(timeout=2)
    assert entered.is_set()


@pytest.mark.parametrize(
    "kind,slot_name",
    [
        ("api-read", "_READ_SLOTS"),
        ("probe", "_PROBE_SLOTS"),
        ("lifecycle", "_LIFECYCLE_SLOTS"),
    ],
)
@pytest.mark.parametrize("acquired", [False, True])
def test_admission_interrupt_releases_only_an_acquired_slot(
    monkeypatch, kind, slot_name, acquired
):
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(f"neutron_flux.scheduling.{slot_name}", slots)
    error = KeyboardInterrupt("interrupted admission timing")
    reporter = SimpleNamespace(event=mock.Mock(side_effect=error))
    if not acquired:
        assert slots.acquire(blocking=False)
        monkeypatch.setattr(
            "neutron_flux.scheduling.raise_if_cancelled", mock.Mock(side_effect=error)
        )
    with pytest.raises(KeyboardInterrupt) as caught, admission(kind, reporter):
        pytest.fail("interrupted admission must not enter the body")
    assert caught.value is error
    if not acquired:
        assert not slots.acquire(blocking=False)
        slots.release()
        monkeypatch.setattr("neutron_flux.scheduling.raise_if_cancelled", lambda: None)
    assert slots.acquire(blocking=False)
    slots.release()

    def next_worker():
        with admission(kind):
            return "admitted"

    with ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(next_worker).result(timeout=2) == "admitted"


@pytest.mark.parametrize(
    "exclusive,outer_exclusive",
    [(False, None), (True, None), (False, False), (True, True), (False, True)],
)
@pytest.mark.parametrize(
    "error", [KeyboardInterrupt("timing interrupted"), RunCancelledError("cancelled")]
)
def test_activity_timing_failure_preserves_only_the_outer_lease(
    exclusive, outer_exclusive, error
):
    gate = ActivityGate()
    reporter = SimpleNamespace(event=mock.Mock(side_effect=error))
    outer = (
        gate.scope(exclusive=outer_exclusive)
        if outer_exclusive is not None
        else nullcontext()
    )
    with outer:
        before = (dict(gate._readers), gate._writer, gate._write_depth)
        with (
            pytest.raises(type(error)) as caught,
            gate.scope(exclusive=exclusive, reporter=reporter),
        ):
            pytest.fail("interrupted activity must not enter the body")
        assert caught.value is error
        assert (gate._readers, gate._writer, gate._write_depth) == before
    assert (gate._readers, gate._writer, gate._write_depth) == ({}, None, 0)

    def next_worker():
        with gate.scope(exclusive=True):
            return "admitted"

    with ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(next_worker).result(timeout=2) == "admitted"


@pytest.mark.parametrize("exclusive", [False, True])
def test_activity_wait_cancellation_does_not_release_another_owners_lease(
    monkeypatch, exclusive
):
    gate = ActivityGate()
    error = RunCancelledError("cancelled while waiting")

    def wait_for_activity():
        with gate.scope(exclusive=exclusive):
            pytest.fail("cancelled activity must not enter the body")

    with gate.scope(exclusive=True):
        before = (dict(gate._readers), gate._writer, gate._write_depth)
        monkeypatch.setattr(
            "neutron_flux.scheduling.raise_if_cancelled", mock.Mock(side_effect=error)
        )
        with ThreadPoolExecutor(max_workers=1) as pool:
            with pytest.raises(RunCancelledError) as caught:
                pool.submit(wait_for_activity).result(timeout=2)
        assert caught.value is error
        assert (gate._readers, gate._writer, gate._write_depth) == before
    assert (gate._readers, gate._writer, gate._write_depth) == ({}, None, 0)


def test_measurement_waits_for_whole_admitted_child_batch():
    gate = ActivityGate()
    attempted = threading.Event()
    entered = threading.Event()

    def measure():
        attempted.set()
        with gate.scope(exclusive=True):
            entered.set()

    with ThreadPoolExecutor(max_workers=2) as pool:
        with gate.scope():
            writer = pool.submit(measure)
            assert attempted.wait(2)

            def child():
                with gate.scope():
                    assert not entered.is_set()
                    return "child complete"

            assert pool.submit(child).result(timeout=2) == "child complete"
        writer.result(timeout=2)
    assert entered.is_set()


def test_shared_to_exclusive_upgrade_is_rejected_without_leaking_lease():
    gate = ActivityGate()
    with (
        gate.scope(),
        pytest.raises(RuntimeError, match="upgrade"),
        gate.scope(exclusive=True),
    ):
        pass
    with gate.scope(exclusive=True):
        assert gate._readers == {}


@pytest.mark.parametrize("same_resource", [False, True])
def test_resource_conflicts_are_scoped(same_resource):
    gate = ActivityGate()
    attempted = threading.Event()
    entered = threading.Event()

    def other():
        attempted.set()
        with gate.resources(["one" if same_resource else "two"]):
            entered.set()

    with ThreadPoolExecutor(max_workers=1) as pool:
        with gate.resources(["one", "one"]):
            future = pool.submit(other)
            assert attempted.wait(2)
            if same_resource:
                assert not entered.wait(0.03)
            else:
                assert entered.wait(2)
        future.result(timeout=2)
    assert gate._resources == {}


def test_map_drains_running_workers_before_failure_and_does_not_start_queue():
    second_started = threading.Event()
    failed = threading.Event()
    release = threading.Event()
    calls = []

    def work(index):
        calls.append(index)
        if index == 0:
            assert second_started.wait(2)
            failed.set()
            raise ValueError("failed worker")
        second_started.set()
        assert release.wait(3)
        return index

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(bounded_map, work, range(10), workers=2)
        try:
            assert failed.wait(2)
            assert not future.done()
        finally:
            release.set()
        with pytest.raises(ValueError, match="failed worker"):
            future.result(timeout=3)
    assert set(calls) == {0, 1}


def test_cancellation_stops_new_map_work_and_can_be_cleaned_up():
    reset_cancellation()
    try:
        request_cancellation("test cancellation")
        with pytest.raises(RunCancelledError):
            bounded_map(lambda value: value, range(5), workers=2)
        begin_cleanup_after_cancellation()
        assert bounded_map(lambda value: value, [1, 2], workers=2) == [1, 2]
    finally:
        reset_cancellation()


def test_timing_distinguishes_nested_work_from_wall_time(monkeypatch):
    clock = [10.0]
    monkeypatch.setattr("neutron_flux.scheduling.time.monotonic", lambda: clock[0])
    recorder = Recorder()
    with timed(recorder, "endpoint-setup", "one"):
        clock[0] += 1
        with timed(recorder, "api-read", "Nova"):
            clock[0] += 2
        clock[0] += 3
    summary = timing_summary(recorder.events)
    assert summary["categories"]["endpoint-setup"] == {
        "count": 1,
        "elapsed_seconds": 6,
        "self_seconds": 4,
    }
    assert summary["categories"]["api-read"]["self_seconds"] == 2
    assert "overlap" in summary["interpretation"]


def test_cleanup_transactions_on_distinct_resources_overlap():
    coordinator = CloudOperationCoordinator(Recorder())
    coordinator._sleep = mock.Mock()
    rendezvous = threading.Barrier(2)

    def delete(index):
        with coordinator.transaction(
            "server-delete", f"delete {index}", resource_ids=[str(index)]
        ):
            coordinator.execute(
                "server-delete",
                ("server", "delete", str(index)),
                lambda: SimpleNamespace(returncode=0),
            )
            rendezvous.wait(timeout=3)
        return index

    assert bounded_map(delete, [1, 2], workers=2) == [1, 2]
    assert coordinator.unresolved_records() == []


def test_api_read_budget_is_shared_across_worker_batches(monkeypatch):
    from neutron_flux.openstack import OpenStack

    recorder = Recorder()
    osc = OpenStack(recorder.logger, CloudOperationCoordinator(recorder))
    state = {"active": 0, "peak": 0}
    lock = threading.Lock()
    admitted = threading.Event()
    release = threading.Event()

    def invoke(command, **_kwargs):
        with lock:
            state["active"] += 1
            state["peak"] = max(state["peak"], state["active"])
            if state["active"] == 4:
                admitted.set()
        try:
            assert release.wait(3)
            return subprocess.CompletedProcess(command, 0, "{}", "")
        finally:
            with lock:
                state["active"] -= 1

    monkeypatch.setattr("neutron_flux.openstack.run_cancellable", invoke)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            bounded_map,
            lambda index: osc.run("port", "show", str(index)),
            range(8),
            workers=8,
        )
        try:
            assert admitted.wait(2)
            assert state["peak"] == 4
        finally:
            release.set()
        assert len(future.result(timeout=3)) == 8
    assert state == {"active": 0, "peak": 4}


def test_performance_runner_reserves_measurement_window():
    from neutron_flux.performance import PerformanceRunner
    from neutron_flux.scheduling import ACTIVITY

    runner = PerformanceRunner.__new__(PerformanceRunner)
    runner.reporter = Recorder()
    measuring = threading.Event()
    attempting = threading.Event()
    ordinary_entered = threading.Event()
    release = threading.Event()

    def measure(_specs):
        measuring.set()
        assert release.wait(3)

    def ordinary():
        attempting.set()
        with ACTIVITY.scope():
            ordinary_entered.set()

    runner._run_specs_isolated = measure
    with ThreadPoolExecutor(max_workers=2) as pool:
        performance = pool.submit(runner.run_specs, [])
        try:
            assert measuring.wait(2)
            other = pool.submit(ordinary)
            assert attempting.wait(2)
            assert not ordinary_entered.wait(0.03)
        finally:
            release.set()
        performance.result(timeout=3)
        other.result(timeout=3)
    assert ordinary_entered.is_set()
