from __future__ import annotations

import dataclasses
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from neutron_flux.errors import RunCancelledError, SuiteError
from neutron_flux.pair_executor import PairScopeExecutor
from neutron_flux.pair_placement import PairPlacementMixin
from neutron_flux.scheduling import READ_WORKERS, admission, bounded_map

from .test_endpoint_parallel_setup import _endpoint, _group, _runtime


@pytest.fixture(params=[PairScopeExecutor, PairPlacementMixin])
def placement_subject(request):
    def make(verify):
        group = dataclasses.replace(
            _group("g"),
            metadata={
                "target_hosts": {"A": "compute-a", "B": "compute-b"},
                "target_availability_zones": {"A": "zone-a", "B": "zone-a"},
            },
        )
        runtime = _runtime(group)
        runtime.endpoints = [_endpoint("g", "A"), _endpoint("g", "B")]
        runtime.endpoints[1].host = "compute-b"
        executor = request.param.__new__(request.param)
        executor.groups = {"g": group}
        executor.scope = {
            "pair_placement": "initial",
            "requested_source_host": "compute-a",
            "requested_destination_host": "compute-b",
            "pair_selected_host_zones": {
                "compute-a": "zone-a",
                "compute-b": "zone-a",
            },
        }
        executor.builder = SimpleNamespace(verify_server_placement=verify)
        return executor, runtime

    return make


def test_actual_pair_verifiers_overlap_and_keep_the_complete_read_contract(
    placement_subject,
):
    rendezvous = threading.Barrier(2)
    second_finished = threading.Event()
    observed = []
    completed = []

    def verify(server_id, ports, **kwargs):
        observed.append((server_id, ports, kwargs))
        rendezvous.wait(timeout=3)
        if server_id.endswith("-A"):
            assert second_finished.wait(timeout=3)
        completed.append(server_id)
        if server_id.endswith("-B"):
            second_finished.set()

    executor, runtime = placement_subject(verify)
    executor._verify_runtime(runtime)
    assert completed == ["server-g-B", "server-g-A"]
    assert len(observed) == 2
    for identity, ports, contract in observed:
        side = identity[-1]
        assert ports == [f"management-g-{side}", f"data-g-{side}"]
        assert contract == {
            "expected_statuses": {"active"},
            "expected_host": "compute-a" if side == "A" else "compute-b",
            "expected_availability_zone": "zone-a",
            "display_name": f"server-g-{side}",
            "stable_observations": 2,
            "reuse_fresh": True,
        }


@pytest.mark.parametrize("fault", ["host", "zone", "role", "duplicate-role", "server"])
def test_every_endpoint_is_prevalidated_before_any_placement_read(
    placement_subject, fault
):
    verify = Mock()
    executor, runtime = placement_subject(verify)
    second = runtime.endpoints[1]
    if fault == "host":
        second.host = "outside-pair"
    elif fault == "zone":
        second.availability_zone = "outside-zone"
    elif fault == "role":
        second.side = "C"
    elif fault == "duplicate-role":
        second.side = "A"
    else:
        second.server_id = runtime.endpoints[0].server_id
    with pytest.raises(SuiteError):
        executor._verify_runtime(runtime)
    verify.assert_not_called()


@pytest.mark.parametrize(
    "failure",
    [
        SuiteError("placement read failed"),
        RunCancelledError("placement read cancelled"),
        ValueError("unexpected placement failure"),
    ],
)
def test_failed_pair_verification_drains_started_peer_before_propagating(
    placement_subject, failure
):
    rendezvous = threading.Barrier(2)
    failed = threading.Event()
    peer_waiting = threading.Event()
    release_peer = threading.Event()
    peer_finished = threading.Event()

    def verify(server_id, *_args, **_kwargs):
        rendezvous.wait(timeout=3)
        if server_id.endswith("-A"):
            failed.set()
            raise failure
        try:
            peer_waiting.set()
            assert release_peer.wait(timeout=3)
        finally:
            peer_finished.set()

    executor, runtime = placement_subject(verify)
    with ThreadPoolExecutor(max_workers=1) as caller:
        future = caller.submit(executor._verify_runtime, runtime)
        try:
            assert failed.wait(timeout=3)
            assert peer_waiting.wait(timeout=3)
            assert not future.done()
            release_peer.set()
            with pytest.raises(type(failure), match=str(failure)):
                future.result(timeout=3)
            assert peer_finished.is_set()
        finally:
            release_peer.set()


def test_nested_port_reads_can_use_the_full_budget_without_outer_read_leases(
    placement_subject,
):
    rendezvous = threading.Barrier(READ_WORKERS)
    lock = threading.Lock()
    active = peak = 0
    read_ids = []

    def read_port(identity):
        nonlocal active, peak
        with admission("api-read"):
            with lock:
                active += 1
                peak = max(peak, active)
            try:
                rendezvous.wait(timeout=3)
                read_ids.append(identity)
            finally:
                with lock:
                    active -= 1

    def verify(server_id, ports, **kwargs):
        bounded_map(read_port, ports, workers=READ_WORKERS)

    executor, runtime = placement_subject(verify)
    executor._verify_runtime(runtime)
    assert peak == READ_WORKERS
    assert active == 0
    assert sorted(read_ids) == [
        "data-g-A",
        "data-g-B",
        "management-g-A",
        "management-g-B",
    ]


def test_initial_verified_relation_is_accepted_without_normalizing_host_hints():
    group = dataclasses.replace(
        _group("g"), metadata={"target_hosts": {"A": "compute-a", "B": "compute-b"}}
    )
    runtime = _runtime(group)
    runtime.endpoints = [_endpoint("g", "A"), _endpoint("g", "B")]
    executor = PairPlacementMixin()
    executor.groups = {"g": group}
    executor.scope = {
        "pair_placement": "initial",
        "requested_source_host": "compute-a",
        "requested_destination_host": "compute-b",
        "pair_selected_host_zones": {"compute-a": "zone-a", "compute-b": "zone-a"},
    }
    verify = Mock()
    executor.builder = SimpleNamespace(verify_server_placement=verify)
    executor._verify_runtime(runtime)
    assert verify.call_count == 2
    assert all(
        call.kwargs["expected_host"] == "compute-a" for call in verify.call_args_list
    )
    executor.scope["pair_placement"] = "opposite"
    verify.reset_mock()
    with pytest.raises(SuiteError, match="Exact placement mismatch"):
        executor._verify_runtime(runtime)
    verify.assert_not_called()


def test_parallel_checks_preserve_real_cache_epoch_and_age_rules(placement_subject):
    from neutron_flux.runtime.control.servers import ServerRuntimeMixin

    builder = ServerRuntimeMixin()
    builder.cloud_operation_coordinator = SimpleNamespace(
        lock=threading.RLock(), _sequence=7, placement_evidence={}
    )
    builder.reporter = SimpleNamespace(event=Mock())
    rendezvous = threading.Barrier(2)
    settled = []

    def settle(server_id, ports, **kwargs):
        rendezvous.wait(timeout=3)
        settled.append(server_id)
        return {
            "id": server_id,
            "status": "ACTIVE",
            "host": kwargs["expected_host"],
            "availability_zone": "zone-a",
        }

    builder._wait_for_server_settlement = settle
    executor, runtime = placement_subject(builder.verify_server_placement)
    executor._verify_runtime(runtime)
    assert sorted(settled) == ["server-g-A", "server-g-B"]
    cache = builder.cloud_operation_coordinator.placement_evidence
    assert len(cache) == 2
    assert {key[0] for key in cache} == {"server-g-A", "server-g-B"}
    executor._verify_runtime(runtime)
    assert len(settled) == 2  # Both unchanged, recent observations are reusable.

    builder.cloud_operation_coordinator._sequence += 1
    executor._verify_runtime(runtime)
    assert len(settled) == 4  # A new operation epoch refreshes both endpoints.
    cache = builder.cloud_operation_coordinator.placement_evidence
    builder.cloud_operation_coordinator.placement_evidence = {
        key: (epoch, observed - 16, evidence)
        for key, (epoch, observed, evidence) in cache.items()
    }
    executor._verify_runtime(runtime)
    assert len(settled) == 6  # Old evidence is not reused within the same epoch.
    cache = builder.cloud_operation_coordinator.placement_evidence
    assert len(cache) == 2
    assert all(value[0] == 8 for value in cache.values())


@pytest.mark.parametrize(
    "preferred",
    [
        RunCancelledError("cancelled peer read"),
        pytest.param("controller", id="shared-controller-loss"),
        ValueError("unexpected peer read"),
        SystemExit(17),
    ],
)
@pytest.mark.parametrize("nested", [False, True], ids=["endpoint", "nested-port"])
def test_mixed_peer_failures_preserve_fatal_error_after_drain(
    placement_subject, preferred, nested
):
    from neutron_flux.errors import ControllerUnavailableError
    from neutron_flux.runtime.control.servers import ServerRuntimeMixin

    if preferred == "controller":
        preferred = ControllerUnavailableError("shared controller unavailable")
    rendezvous = threading.Barrier(2)
    ordinary_failed = threading.Event()
    peer_waiting = threading.Event()
    release_peer = threading.Event()
    peer_finished = threading.Event()

    def fail_pair(ordinary):
        rendezvous.wait(timeout=3)
        if ordinary:
            ordinary_failed.set()
            raise SuiteError("ordinary placement read failure")
        try:
            peer_waiting.set()
            assert release_peer.wait(timeout=3)
            raise preferred
        finally:
            peer_finished.set()

    def verify(server_id, *_args, **_kwargs):
        fail_pair(server_id.endswith("-A"))

    if nested:
        builder = ServerRuntimeMixin()
        builder.config = SimpleNamespace(
            resource_timeout=10, convergence_timeout=10, convergence_interval=0
        )
        builder.logger = Mock()
        builder.reporter = SimpleNamespace(event=Mock())
        builder.cloud_operation_coordinator = None

        def read(*args, **kwargs):
            identity = args[2]
            side = identity[-1]
            if args[:2] == ("server", "show"):
                return {
                    "id": identity,
                    "status": "ACTIVE",
                    "host": "compute-a" if side == "A" else "compute-b",
                    "availability_zone": "zone-a",
                    "task_state": None,
                }
            assert args[:2] == ("port", "show")
            if side == "A":
                fail_pair(identity.startswith("management"))
            return {
                "id": identity,
                "device_id": f"server-g-{side}",
                "binding:host_id": "compute-a" if side == "A" else "compute-b",
                "status": "ACTIVE",
            }

        builder.osc = SimpleNamespace(json=read)
        verify = builder.verify_server_placement

    executor, runtime = placement_subject(verify)
    with ThreadPoolExecutor(max_workers=1) as caller:
        future = caller.submit(executor._verify_runtime, runtime)
        try:
            assert ordinary_failed.wait(timeout=3)
            assert peer_waiting.wait(timeout=3)
            assert not future.done()
            release_peer.set()
            with pytest.raises(type(preferred)) as caught:
                future.result(timeout=3)
            assert caught.value is preferred
            assert peer_finished.is_set()
        finally:
            release_peer.set()


@pytest.mark.parametrize("error_kind", ["cancelled", "controller", "unexpected"])
def test_map_stops_admission_and_harvests_later_peer_failure(error_kind):
    from neutron_flux.errors import ControllerUnavailableError

    error = {
        "cancelled": RunCancelledError("cancelled peer"),
        "controller": ControllerUnavailableError("lost shared control"),
        "unexpected": ValueError("unexpected peer"),
    }[error_kind]
    rendezvous = threading.Barrier(2)
    ordinary_failed = threading.Event()
    release_peer = threading.Event()
    peer_finished = threading.Event()
    extra_started = threading.Event()
    started = []

    def work(index):
        started.append(index)
        if index > 1:
            extra_started.set()
            return index
        rendezvous.wait(timeout=3)
        if index == 0:
            ordinary_failed.set()
            raise SuiteError("ordinary operation failed first")
        try:
            assert release_peer.wait(timeout=3)
            raise error
        finally:
            peer_finished.set()

    with ThreadPoolExecutor(max_workers=1) as caller:
        future = caller.submit(bounded_map, work, range(8), workers=2)
        try:
            assert ordinary_failed.wait(timeout=3)
            assert not extra_started.wait(timeout=0.05)
            assert not future.done()
            release_peer.set()
            with pytest.raises(type(error)) as caught:
                future.result(timeout=3)
            assert caught.value is error
            assert peer_finished.is_set()
            assert sorted(started) == [0, 1]
        finally:
            release_peer.set()


@pytest.mark.parametrize("method", ["_build", "_ensure"])
@pytest.mark.parametrize("error_kind", ["cancelled", "controller"])
def test_pair_scope_wrappers_do_not_downgrade_fatal_placement_errors(
    monkeypatch, method, error_kind
):
    from neutron_flux.errors import ControllerUnavailableError
    from neutron_flux.executor import AdaptiveExecutor

    error = (
        RunCancelledError("cancelled verification")
        if error_kind == "cancelled"
        else ControllerUnavailableError("shared controller unavailable")
    )
    group = _group("g")
    runtime = _runtime(group)
    runtime.endpoints = [_endpoint("g", "A")]
    executor = PairScopeExecutor.__new__(PairScopeExecutor)
    executor.builder = SimpleNamespace(group_failures={}, stop_group_probes=Mock())
    executor._verify_runtime = Mock(side_effect=error)
    executor._cleanup_failed_build = Mock()
    executor._release = Mock()
    if method == "_build":
        monkeypatch.setattr(
            AdaptiveExecutor, "_build", lambda *_args, **_kwargs: runtime
        )
        arguments = ("g",)
        keywords = {"sides": ("A",)}
    else:
        monkeypatch.setattr(AdaptiveExecutor, "_ensure", lambda *_args, **_kwargs: None)
        executor.active = {"g": runtime}
        executor._hosts_for = Mock(return_value={"A": "compute-a"})
        executor._set_hosts = Mock()
        executor.failed_groups = set()
        arguments = (("g",),)
        keywords = {"required_sides": {"g": ("A",)}}
    with pytest.raises(type(error)) as caught:
        getattr(executor, method)(*arguments, **keywords)
    assert caught.value is error
    assert executor.builder.group_failures == {}
    executor.builder.stop_group_probes.assert_not_called()
    executor._cleanup_failed_build.assert_not_called()
    executor._release.assert_not_called()
