from __future__ import annotations

import threading
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.cancellation import (
    cancellation_active,
    request_cancellation,
    reset_cancellation,
)
from neutron_flux.errors import (
    ControllerUnavailableError,
    RunCancelledError,
    SuiteError,
)
from neutron_flux.executor import AdaptiveExecutor
from neutron_flux.models import Endpoint, PlannedGroup, RuntimeGroup
from neutron_flux.runtime.topology import TopologyRuntimeMixin


def _group(group_id: str) -> PlannedGroup:
    return PlannedGroup(
        id=group_id,
        kind="provider",
        label=group_id,
        network_id=f"network-{group_id}",
        network_name=f"network-{group_id}",
        subnet_ids=[f"subnet-{group_id}"],
        families=[4],
    )


def _endpoint(group_id: str, side: str = "A") -> Endpoint:
    return Endpoint(
        label=f"{group_id}:{side}",
        server_id=f"server-{group_id}-{side}",
        server_name=f"server-{group_id}-{side}",
        management_port_id=f"management-{group_id}-{side}",
        management_ip="192.0.2.10",
        test_port_id=f"data-{group_id}-{side}",
        test_mac="02:00:00:00:00:01",
        fixed_ips={f"subnet-{group_id}": "198.51.100.10"},
        host="compute-a",
        availability_zone="zone-a",
        volume_id=None,
        side=side,
    )


def _runtime(group: PlannedGroup) -> RuntimeGroup:
    return RuntimeGroup(
        plan=group,
        network_id=str(group.network_id),
        network_name=str(group.network_name),
        subnet_ids=group.subnet_ids,
        router_id=None,
        endpoints=[],
        source_nat_enabled=None,
        fips={},
    )


def _executor(populate):
    executor = AdaptiveExecutor.__new__(AdaptiveExecutor)
    executor.config = SimpleNamespace(max_active_endpoints=2)
    executor.groups = {name: _group(name) for name in ("first", "second", "third")}
    executor.active = {}
    executor.failed_groups = set()
    executor.group_loads = 0
    executor.checkpoint = SimpleNamespace(metadata={})
    events = []
    checkpoint_threads = []

    def build(group, *, sides, defer_endpoints=False):
        assert defer_endpoints is True
        assert sides == ("A",)
        assert threading.current_thread() is threading.main_thread()
        assert not any(event[0] == "populate" for event in events)
        events.append(("prepare", group.id))
        runtime = _runtime(group)
        executor.builder.runtime_groups.append(runtime)
        return runtime

    def complete(runtime, *, sides):
        assert set(executor.active) == {"first", "second"}
        assert {item.plan.id for item in executor.builder.runtime_groups} == {
            "first",
            "second",
        }
        events.append(("populate", runtime.plan.id))
        return populate(runtime, sides)

    executor.builder = SimpleNamespace(
        cloud_operation_coordinator=object(),
        runtime_groups=[],
        group_failures={},
        build_group=mock.Mock(side_effect=build),
        complete_group_endpoints=complete,
        finalize_group_endpoints=lambda runtime: events.append(
            ("finalize", runtime.plan.id)
        ),
        stop_group_probes=lambda group_id: events.append(("stop", group_id)),
    )
    executor.cleanup_manager = SimpleNamespace(
        cleanup_group=mock.Mock(return_value=True)
    )
    executor.reporter = SimpleNamespace(event=mock.Mock())
    executor._inject_failure = mock.Mock()

    def checkpoint():
        checkpoint_threads.append(threading.current_thread())
        events.append(("checkpoint", tuple(executor.active)))

    executor._refresh_checkpoint = checkpoint
    return executor, events, checkpoint_threads


def test_cross_endpoint_batch_prepares_serially_then_overlaps_and_harvests_in_order():
    rendezvous = threading.Barrier(2)
    second_finished = threading.Event()
    finished = []

    def populate(runtime, sides):
        rendezvous.wait(timeout=5)
        if runtime.plan.id == "first":
            assert second_finished.wait(timeout=5)
        runtime.endpoints = [_endpoint(runtime.plan.id, side) for side in sides]
        finished.append(runtime.plan.id)
        if runtime.plan.id == "second":
            second_finished.set()
        return runtime

    executor, events, checkpoint_threads = _executor(populate)
    executor._ensure(("first", "second"))

    assert [row for row in events if row[0] == "prepare"] == [
        ("prepare", "first"),
        ("prepare", "second"),
    ]
    assert finished == ["second", "first"]
    assert [row for row in events if row[0] == "finalize"] == [
        ("finalize", "first"),
        ("finalize", "second"),
    ]
    assert list(executor.active) == ["first", "second"]
    assert executor.builder.runtime_groups == list(executor.active.values())
    assert executor.group_loads == 2
    assert all(thread is threading.main_thread() for thread in checkpoint_threads)
    executor.cleanup_manager.cleanup_group.assert_not_called()


@pytest.mark.parametrize("failure", [None, SuiteError("endpoint setup failed")])
def test_endpoint_failure_joins_peer_before_serial_cleanup(failure):
    rendezvous = threading.Barrier(2)
    finished = set()

    def populate(runtime, sides):
        rendezvous.wait(timeout=5)
        try:
            if runtime.plan.id == "first":
                if failure is not None:
                    raise failure
                return None
            runtime.endpoints = [_endpoint(runtime.plan.id, side) for side in sides]
            return runtime
        finally:
            finished.add(runtime.plan.id)

    executor, events, _ = _executor(populate)

    def cleanup(group_id):
        assert threading.current_thread() is threading.main_thread()
        assert finished == {"first", "second"}
        events.append(("cleanup", group_id))
        return True

    executor.cleanup_manager.cleanup_group.side_effect = cleanup
    if failure is None:
        executor._ensure(("first", "second"))
    else:
        with pytest.raises(SuiteError, match="endpoint setup failed"):
            executor._ensure(("first", "second"))

    assert list(executor.active) == ["second"]
    assert executor.failed_groups == {"first"}
    executor.cleanup_manager.cleanup_group.assert_called_once_with("first")
    assert ("finalize", "second") in events
    assert executor.builder.runtime_groups == list(executor.active.values())


@pytest.mark.parametrize(
    "failure",
    [RunCancelledError("cancel endpoint setup"), ValueError("unexpected setup")],
)
def test_exception_joins_peer_and_preserves_partial_resource_ownership(failure):
    rendezvous = threading.Barrier(2)
    peer_finished = threading.Event()
    finished = set()

    def populate(runtime, sides):
        rendezvous.wait(timeout=5)
        try:
            if runtime.plan.id == "first":
                assert peer_finished.wait(timeout=5)
                raise failure
            runtime.endpoints = [_endpoint(runtime.plan.id, side) for side in sides]
            peer_finished.set()
            return runtime
        finally:
            finished.add(runtime.plan.id)

    executor, _, checkpoint_threads = _executor(populate)
    with pytest.raises(type(failure), match=str(failure)):
        executor._ensure(("first", "second"))

    assert finished == {"first", "second"}
    assert list(executor.active) == ["first", "second"]
    assert executor.active["second"].endpoints[0].server_id == "server-second-A"
    assert executor.builder.runtime_groups == list(executor.active.values())
    assert all(thread is threading.main_thread() for thread in checkpoint_threads)
    executor.cleanup_manager.cleanup_group.assert_not_called()


def test_endpoint_capacity_is_checked_before_releasing_or_creating_resources():
    executor, _, _ = _executor(mock.Mock())
    retained = _runtime(_group("retained"))
    retained.endpoints = [_endpoint("retained")]
    executor.active["retained"] = retained
    executor.builder.runtime_groups = [retained]
    executor._release = mock.Mock()

    with pytest.raises(SuiteError, match="3 > 2"):
        executor._ensure(("first", "second", "third"))

    executor._release.assert_not_called()
    executor.builder.build_group.assert_not_called()
    executor.cleanup_manager.cleanup_group.assert_not_called()
    assert executor.active == {"retained": retained}
    assert executor.builder.runtime_groups == [retained]


def test_process_cancellation_joins_started_workers_before_checkpointing_ownership():
    rendezvous = threading.Barrier(2)
    cancellation_sent = threading.Event()
    peer_finished = threading.Event()

    def populate(runtime, sides):
        rendezvous.wait(timeout=5)
        if runtime.plan.id == "first":
            request_cancellation("cancel parallel endpoint provisioning")
            cancellation_sent.set()
            raise RunCancelledError("cancel parallel endpoint provisioning")
        assert cancellation_sent.wait(timeout=5)
        runtime.endpoints = [_endpoint(runtime.plan.id, side) for side in sides]
        peer_finished.set()
        return runtime

    reset_cancellation()
    try:
        executor, _, _ = _executor(populate)
        with pytest.raises(RunCancelledError, match="cancel parallel endpoint"):
            executor._ensure(("first", "second"))
        assert peer_finished.is_set()
        assert list(executor.active) == ["first", "second"]
        assert executor.builder.runtime_groups == list(executor.active.values())
        assert executor.active["second"].endpoints[0].server_id == "server-second-A"
        executor.cleanup_manager.cleanup_group.assert_not_called()
    finally:
        reset_cancellation()


def test_group_build_propagates_child_cancellation_without_global_signal():
    reset_cancellation()
    builder = SimpleNamespace(
        runtime_groups=[],
        allocate_group_generation=mock.Mock(return_value=1),
        _build_provider_group=mock.Mock(
            side_effect=RunCancelledError("child exited 130")
        ),
        _refresh_neutron_placements=mock.Mock(),
        group_failures={},
        group_failure_types={},
        reporter=mock.Mock(),
        logger=mock.Mock(),
    )

    with pytest.raises(RunCancelledError, match="child exited 130"):
        TopologyRuntimeMixin.build_group(builder, _group("cancelled"), sides=("A",))

    assert not cancellation_active()
    assert not builder.group_failures
    assert not builder.group_failure_types
    assert not builder.runtime_groups
    builder.reporter.event.assert_not_called()
    builder._refresh_neutron_placements.assert_not_called()


@pytest.mark.parametrize("cancelled_group", ["first", "second"])
@pytest.mark.parametrize("peer_fails", [False, True])
def test_production_endpoint_handler_prioritizes_child_cancellation_after_join(
    cancelled_group, peer_fails
):
    reset_cancellation()
    rendezvous = threading.Barrier(2)
    finished = set()
    executor, events, checkpoint_threads = _executor(mock.Mock())
    builder = executor.builder
    builder.group_failure_types = {}
    builder.logger = mock.Mock()
    builder.reporter = mock.Mock()

    def create(group, _network, _subnets, *, sides, **_kwargs):
        rendezvous.wait(timeout=5)
        try:
            if group.id == cancelled_group:
                raise RunCancelledError("child exited 130")
            if peer_fails:
                raise SuiteError("peer boot failed")
            return [_endpoint(group.id, side) for side in sides]
        finally:
            finished.add(group.id)

    builder._create_endpoints = create
    builder.complete_group_endpoints = lambda runtime, *, sides: (
        TopologyRuntimeMixin.complete_group_endpoints(builder, runtime, sides=sides)
    )
    builder.finalize_group_endpoints = mock.Mock()

    with pytest.raises(RunCancelledError, match="child exited 130"):
        executor._ensure(("first", "second"))

    assert not cancellation_active()
    assert finished == {"first", "second"}
    assert list(executor.active) == ["first", "second"]
    assert builder.runtime_groups == list(executor.active.values())
    assert not executor.failed_groups
    assert cancelled_group not in builder.group_failures
    assert all(thread is threading.main_thread() for thread in checkpoint_threads)
    assert not any(event[0] == "stop" for event in events)
    builder.finalize_group_endpoints.assert_not_called()
    executor.cleanup_manager.cleanup_group.assert_not_called()


@pytest.mark.parametrize("cancelled_group", ["first", "second"])
def test_finalization_child_cancellation_preserves_owned_groups(cancelled_group):
    reset_cancellation()
    finished = set()

    def populate(runtime, sides):
        runtime.endpoints = [_endpoint(runtime.plan.id, side) for side in sides]
        finished.add(runtime.plan.id)
        return runtime

    executor, events, _ = _executor(populate)

    def refresh_placements(group_id):
        assert finished == {"first", "second"}
        if group_id == cancelled_group:
            raise RunCancelledError("child exited 130")

    builder = executor.builder
    builder._refresh_neutron_placements = refresh_placements
    builder.reporter = mock.Mock()
    builder.finalize_group_endpoints = lambda runtime: (
        TopologyRuntimeMixin.finalize_group_endpoints(builder, runtime)
    )

    with pytest.raises(RunCancelledError, match="child exited 130"):
        executor._ensure(("first", "second"))

    assert not cancellation_active()
    assert list(executor.active) == ["first", "second"]
    assert executor.builder.runtime_groups == list(executor.active.values())
    assert not executor.failed_groups
    assert not any(event[0] == "stop" for event in events)
    executor.cleanup_manager.cleanup_group.assert_not_called()


def test_production_endpoint_handler_prioritizes_shared_controller_failure():
    rendezvous = threading.Barrier(2)
    finished = set()
    executor, events, _ = _executor(mock.Mock())
    builder = executor.builder
    builder.group_failure_types = {}
    builder.logger = mock.Mock()
    builder.reporter = mock.Mock()

    def create(group, _network, _subnets, **_kwargs):
        rendezvous.wait(timeout=5)
        try:
            if group.id == "first":
                raise SuiteError("ordinary peer boot failure")
            raise ControllerUnavailableError("shared controller unavailable")
        finally:
            finished.add(group.id)

    builder._create_endpoints = create
    builder.complete_group_endpoints = lambda runtime, *, sides: (
        TopologyRuntimeMixin.complete_group_endpoints(builder, runtime, sides=sides)
    )
    builder.finalize_group_endpoints = mock.Mock()

    with pytest.raises(ControllerUnavailableError, match="shared controller"):
        executor._ensure(("first", "second"))

    assert finished == {"first", "second"}
    assert list(executor.active) == ["first", "second"]
    assert builder.runtime_groups == list(executor.active.values())
    assert not executor.failed_groups
    assert "ordinary peer boot failure" in builder.group_failures["first"]
    assert "second" not in builder.group_failures
    assert not any(event[0] == "stop" for event in events)
    builder.finalize_group_endpoints.assert_not_called()
    executor.cleanup_manager.cleanup_group.assert_not_called()


def test_missing_routed_side_binding_fails_before_creating_any_port():
    builder = SimpleNamespace(
        cloud_operation_coordinator=None,
        _create_port=mock.Mock(),
        _create_server=mock.Mock(),
    )
    with pytest.raises(SuiteError, match="Incomplete endpoint network bindings"):
        TopologyRuntimeMixin._create_endpoints(
            builder,
            _group("routed"),
            "network-a",
            ["subnet-a"],
            sides=("A", "B"),
            generation=1,
            side_networks={"A": ("network-a", ["subnet-a"])},
        )
    builder._create_port.assert_not_called()
    builder._create_server.assert_not_called()


def test_routed_pair_creates_one_endpoint_batch_with_distinct_side_bindings():
    group = _group("routed")
    builder = SimpleNamespace(
        config=SimpleNamespace(resource_timeout=60),
        _create_generated_tenant_network=mock.Mock(
            side_effect=[
                ("network-a", "name-a", "subnet-a", "192.0.2.0/24"),
                ("network-b", "name-b", "subnet-b", "198.51.100.0/24"),
            ]
        ),
        _create_scenario_router=mock.Mock(return_value=("router", "router-name")),
        osc=SimpleNamespace(run=mock.Mock(return_value=SimpleNamespace(returncode=0))),
        _optional_router_interface_ip=mock.Mock(return_value=None),
        _record_router_addresses=mock.Mock(),
        _create_endpoints=mock.Mock(
            return_value=[_endpoint("routed", "A"), _endpoint("routed", "B")]
        ),
    )

    runtime = TopologyRuntimeMixin._build_tenant_router_pair(
        builder, group, sides=("A", "B"), generation=7
    )

    builder._create_endpoints.assert_called_once_with(
        group,
        "network-a",
        ["subnet-a"],
        sides=("A", "B"),
        generation=7,
        side_networks={
            "A": ("network-a", ["subnet-a"]),
            "B": ("network-b", ["subnet-b"]),
        },
    )
    assert [endpoint.side for endpoint in runtime.endpoints] == ["A", "B"]
    assert runtime.metadata["network_ids"] == {"A": "network-a", "B": "network-b"}
