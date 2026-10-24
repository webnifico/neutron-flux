from __future__ import annotations

import dataclasses
import threading
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.cloud_operation import CloudOperationCoordinator
from neutron_flux.engine import TestEngine as Engine
from neutron_flux.errors import SuiteError
from neutron_flux.executor import AdaptiveExecutor
from neutron_flux.models import TestSpec as Spec
from neutron_flux.reporting import Reporter, ResourceTracker
from neutron_flux.resources import ResourceBuilder
from neutron_flux.scheduling import bounded_map
from support.tests.test_qualification_lifecycle import _Builder, _Cleanup, _plan


def spec(name, *, operation="probe", requires=(), requires_pass=()):
    return Spec(
        name,
        "same-subnet",
        operation,
        4,
        "reachable",
        "test",
        True,
        ["g"],
        protocol="icmp",
        requires=list(requires),
        requires_pass=list(requires_pass),
    )


class RecordingEngine(Engine):
    def _run_endpoint_probe(self, item):
        self.hook(item)
        self.reporter.result(
            item.id,
            item.category,
            "PASS",
            "observed",
            expected="reachable",
            observed="reachable",
            authoritative=True,
        )

    def _run_mtu_scenario(self, item):
        self._run_endpoint_probe(item)


def engine(config, reporter, hook):
    builder = SimpleNamespace(
        runtime_groups=[], ssh_endpoint=mock.Mock(), ssh_controller=mock.Mock()
    )
    result = RecordingEngine(config, SimpleNamespace(), builder, reporter)
    result.hook = hook
    return result


def test_three_shared_host_pairs_overlap_and_keep_their_results(config_factory):
    config = config_factory()
    reporter = Reporter(config, "sample-shared-host-probes")
    rendezvous = threading.Barrier(3)
    observed = []

    def probe(item):
        observed.append(item.id)
        rendezvous.wait(timeout=3)

    try:
        worker = engine(config, reporter, probe)
        worker.run_specs([spec("1-2"), spec("1-3"), spec("2-3")])
        assert set(observed) == {"1-2", "1-3", "2-3"}
        assert {row.test_id: row.status for row in reporter.results} == {
            name: "PASS" for name in observed
        }
    finally:
        reporter.logger.close()


@pytest.mark.parametrize("dependency_field", ["requires", "requires_pass"])
def test_probe_dependencies_wait_even_when_listed_after_dependents(
    config_factory, dependency_field
):
    config = config_factory()
    reporter = Reporter(config, f"sample-dependency-{dependency_field}")
    observed = []
    try:
        worker = engine(config, reporter, lambda item: observed.append(item.id))
        worker.run_specs(
            [spec("dependent", **{dependency_field: ["baseline"]}), spec("baseline")]
        )
        assert observed == ["baseline", "dependent"]
    finally:
        reporter.logger.close()


def test_failed_prerequisite_blocks_only_its_dependents(config_factory):
    config = config_factory()
    reporter = Reporter(config, "sample-failed-prerequisite")
    observed = []
    try:
        reporter.result("baseline", "same-subnet", "FAIL", "baseline failed")
        worker = engine(config, reporter, lambda item: observed.append(item.id))
        worker.run_specs(
            [spec("blocked", requires_pass=["baseline"]), spec("independent")]
        )
        assert observed == ["independent"]
        assert reporter.get_result("blocked").status == "BLOCKED_BY_PREREQUISITE"
    finally:
        reporter.logger.close()


@pytest.mark.parametrize("dependency_field", ["requires", "requires_pass"])
def test_dependency_cycles_never_execute(config_factory, dependency_field):
    config = config_factory()
    reporter = Reporter(config, f"sample-cycle-{dependency_field}")
    probe = mock.Mock()
    try:
        worker = engine(config, reporter, probe)
        worker.run_specs(
            [
                spec("one", **{dependency_field: ["two"]}),
                spec("two", **{dependency_field: ["one"]}),
            ]
        )
        probe.assert_not_called()
        assert all(row.status == "BLOCKED_BY_PREREQUISITE" for row in reporter.results)
    finally:
        reporter.logger.close()


def test_stateful_barrier_stays_between_probe_waves(config_factory):
    config = config_factory()
    reporter = Reporter(config, "sample-stateful-barrier")
    observed = []
    try:
        worker = engine(config, reporter, lambda item: observed.append(item.id))
        worker.run_specs(
            [spec("before"), spec("mtu", operation="mtu-scenario"), spec("after")]
        )
        assert observed == ["before", "mtu", "after"]
    finally:
        reporter.logger.close()


def test_engine_retains_its_endpoint_view_when_builder_moves_on(config_factory):
    config = config_factory()
    reporter = Reporter(config, "sample-immutable-view")
    try:
        worker = engine(config, reporter, mock.Mock())
        worker.builder.runtime_groups = [
            SimpleNamespace(plan=SimpleNamespace(id="another-pair"))
        ]
        assert worker.groups == {}
        later = RecordingEngine(config, SimpleNamespace(), worker.builder, reporter)
        assert set(later.groups) == {"another-pair"}
    finally:
        reporter.logger.close()


def test_fresh_placement_cache_invalidates_on_cloud_operation_age_and_failed_refresh(
    config_factory, monkeypatch
):
    clock = [100.0]
    monkeypatch.setattr(
        "neutron_flux.runtime.control.servers.time.monotonic", lambda: clock[0]
    )
    config = config_factory()
    reporter = Reporter(config, "sample-placement-cache")
    coordinator = CloudOperationCoordinator(reporter)
    coordinator._sleep = mock.Mock()
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config, builder.reporter = config, reporter
    builder.cloud_operation_coordinator = coordinator
    builder._wait_for_server_settlement = mock.Mock(
        return_value={
            "status": "ACTIVE",
            "OS-EXT-SRV-ATTR:host": "compute1",
            "OS-EXT-AZ:availability_zone": "az1",
        }
    )

    def verify(**kwargs):
        return builder.verify_server_placement(
            "vm",
            ["mgmt", "test"],
            expected_host="compute1",
            expected_availability_zone="az1",
            **kwargs,
        )

    try:
        original = verify()
        cached = verify(reuse_fresh=True)
        cached["server"]["status"] = "changed locally"
        assert original["server"]["status"] == "ACTIVE"
        assert builder._wait_for_server_settlement.call_count == 1
        coordinator.execute("port-create", ("port", "create", "other"), lambda: None)
        verify(reuse_fresh=True)
        assert builder._wait_for_server_settlement.call_count == 2
        clock[0] += 16
        verify(reuse_fresh=True)
        assert builder._wait_for_server_settlement.call_count == 3
        builder._wait_for_server_settlement.side_effect = SuiteError("binding changed")
        with pytest.raises(SuiteError, match="binding changed"):
            verify()
        with pytest.raises(SuiteError, match="binding changed"):
            verify(reuse_fresh=True)
        assert not coordinator.placement_evidence
    finally:
        reporter.logger.close()


def test_resource_journal_sequences_remain_unique_under_concurrent_creation(
    config_factory,
):
    reporter = Reporter(config_factory(), "sample-resource-journal")
    tracker = ResourceTracker(reporter)
    try:
        records = bounded_map(
            lambda index: tracker.add("port", f"port-{index}", f"name-{index}"),
            range(50),
            workers=8,
        )
        assert len({record.sequence for record in records}) == 50
        assert len(ResourceTracker.load_manifest(reporter.manifest_path)) == 50
    finally:
        reporter.logger.close()


def test_cross_batch_reuse_obeys_stateful_and_dependency_barriers():
    executor = AdaptiveExecutor.__new__(AdaptiveExecutor)
    executor.active = {"a": SimpleNamespace(endpoints=[SimpleNamespace(side="A")])}

    def key(*groups):
        return (groups, tuple((group, ("A",)) for group in groups))

    ab, cd, be, state, ef = (
        key("a", "b"),
        key("c", "d"),
        key("b", "e"),
        key("s"),
        key("e", "f"),
    )
    batches = {
        ab: [spec("ab")],
        cd: [spec("cd")],
        be: [spec("be")],
        state: [spec("state", operation="router-disable")],
        ef: [spec("ef")],
    }
    assert executor._reuse_ordered_cross_batches(batches) == [ab, be, cd, state, ef]
    batches[be] = [spec("be", requires_pass=["cd"])]
    assert executor._reuse_ordered_cross_batches(batches) == [ab, cd, be, state, ef]


def test_surplus_endpoint_release_retains_the_other_vm_and_topology(config_factory):
    plan = _plan(cycles=1)
    builder = _Builder(plan)
    group = dataclasses.replace(
        plan.groups[0],
        metadata={
            "target_hosts": {"A": "compute1", "B": "compute2"},
            "target_availability_zones": {"A": "az1", "B": "az1"},
        },
    )
    runtime = builder.build_group(group, sides=("A", "B"))
    original = runtime.endpoint("A")
    executor = AdaptiveExecutor.__new__(AdaptiveExecutor)
    executor.active = {group.id: runtime}
    executor.groups = {group.id: group}
    executor.builder = builder
    executor.failed_groups = set()
    executor.config = config_factory()
    executor.cleanup_manager = _Cleanup(builder)
    executor.reporter = mock.Mock()
    executor._refresh_checkpoint = mock.Mock()
    executor._ensure((group.id,), required_sides={group.id: ("A",)})
    assert runtime.endpoints == [original]
    assert len(builder.build_calls) == 1
    assert executor.cleanup_manager.side_calls == [(group.id, "B")]
    assert not executor.cleanup_manager.group_calls


@pytest.mark.parametrize("fail_side", [None, "A"])
def test_endpoint_creation_overlaps_and_joins_before_return_or_failure(
    config_factory, fail_side
):
    config = config_factory()
    reporter = Reporter(config, f"sample-boot-{fail_side or 'success'}")
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config, builder.reporter, builder.logger = config, reporter, reporter.logger
    builder.name_prefix = "sample-boot"
    builder.management_network_id, builder.management_subnet_id = "mgmt", "mgmt-subnet"
    builder.endpoint_management_sg_id = "mgmt-sg"
    builder.test_sg_id, builder.test_sg_ids = "test-sg", {}
    builder.cloud_operation_coordinator = CloudOperationCoordinator(reporter)
    builder.cloud_operation_coordinator._sleep = mock.Mock()
    rendezvous = threading.Barrier(2)
    finished = []

    def port(name, network, subnet_ids, *_args, **kwargs):
        side = kwargs["endpoint_side"]
        return {
            "id": f"{network}-{side}",
            "fixed_ips": [
                {
                    "subnet_id": subnet_ids[0],
                    "ip_address": f"10.0.0.{10 if side == 'A' else 11}",
                }
            ],
            "mac_address": "fa:16:3e:00:00:01",
        }

    def server(name, _ports, **kwargs):
        rendezvous.wait(timeout=3)
        if kwargs["endpoint_side"] == fail_side:
            raise SuiteError("simulated boot failure")
        return {
            "server_id": name,
            "server_name": name,
            "host": "compute",
            "availability_zone": "az1",
            "volume_id": None,
        }

    builder._create_port = port
    builder._create_server = server
    builder._wait_for_ssh = lambda *_args, **_kwargs: True
    builder._configure_endpoint = lambda endpoint, _table: finished.append(
        endpoint.side
    )
    group = _plan().groups[0]
    try:
        if fail_side:
            with pytest.raises(SuiteError, match="simulated boot failure"):
                builder._create_endpoints(
                    group, "network", ["subnet"], sides=("A", "B"), generation=1
                )
            assert finished == ["B"]
        else:
            endpoints = builder._create_endpoints(
                group, "network", ["subnet"], sides=("A", "B"), generation=1
            )
            assert [endpoint.side for endpoint in endpoints] == ["A", "B"]
            assert sorted(finished) == ["A", "B"]
    finally:
        reporter.logger.close()


def test_server_and_port_cleanup_remains_in_dependency_phases(config_factory):
    from neutron_flux.cleanup import CleanupManager

    config = config_factory()
    reporter = Reporter(config, "sample-cleanup-phases")
    tracker = ResourceTracker(reporter)
    for kind in ("server", "port", "volume"):
        for index in range(2):
            tracker.add(kind, f"{kind}-{index}", f"{kind}-{index}", group_id="group")
    manager = CleanupManager(mock.Mock(), reporter, tracker, config)
    done = []
    barriers = {kind: threading.Barrier(2) for kind in ("server", "port", "volume")}

    def remove(record, _handler):
        kind = record.resource_type
        if kind == "port":
            assert done.count("server") == 2
        if kind == "volume":
            assert done.count("port") == 2
        barriers[kind].wait(timeout=3)
        done.append(kind)
        tracker.mark_deleted(record)

    manager._delete_record = remove
    try:
        assert manager.cleanup_group("group") is True
        assert done == ["server", "server", "port", "port", "volume", "volume"]
    finally:
        reporter.logger.close()


def test_capped_performance_keeps_original_cross_path_selection_order(config_factory):
    executor = AdaptiveExecutor.__new__(AdaptiveExecutor)
    executor.config = config_factory(performance_enabled=True, performance_max_paths=6)
    executor.active = {"a": SimpleNamespace(endpoints=[SimpleNamespace(side="A")])}
    batches = {
        (("c", "d"), (("c", ("A",)), ("d", ("A",)))): [spec("cd")],
        (("a", "b"), (("a", ("A",)), ("b", ("A",)))): [spec("ab")],
    }
    assert executor._reuse_ordered_cross_batches(batches) == list(batches)
