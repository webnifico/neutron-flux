from __future__ import annotations

import dataclasses
import threading
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.errors import SuiteError
from neutron_flux.executor import AdaptiveExecutor
from neutron_flux.host_qualification import HostQualificationPlanner
from neutron_flux.performance import PerformanceRunner, PerformanceSession
from neutron_flux.probe_service import ProbeServiceManager
from neutron_flux.reporting import Reporter
from neutron_flux.resources import ResourceBuilder
from neutron_flux.runtime.context import serialized_lifecycle

from .test_host_qualification import _Inventory, _service
from .test_qualification_lifecycle import _Builder, _Cleanup, _plan

COMMAND = [
    "run",
    "--image",
    "debian-13",
    "--flavor",
    "s-g-1cpu-2gb",
    "--storage",
    "volume",
    "--volume-type",
    "premium",
    "--external-networks",
    "Public,Public2,Provider Two",
    "--target-host-pairs",
    "compute-a:compute-b,compute-c:compute-d",
    "--migration-mode",
    "live-preferred",
]


class ProbeBuilder(_Builder):
    """Use the real probe registry so reuse tests observe listener shutdown."""

    def __init__(self, plan):
        super().__init__(plan)
        self.probe_service = ProbeServiceManager(18080, 18081)
        self.probe_service._terminate = lambda process: setattr(
            process, "returncode", 0
        )
        self.logger = mock.Mock()

    def register(self, endpoint, group_id):
        endpoint.metadata["group_id"] = group_id
        endpoint.metadata["probe_service"] = {"ready": True}
        process = SimpleNamespace(returncode=None)
        process.poll = lambda: process.returncode
        self.probe_service._processes[endpoint.server_id] = SimpleNamespace(
            endpoint=endpoint,
            process=process,
        )

    def build_group(self, group, **kwargs):
        runtime = super().build_group(group, **kwargs)
        if runtime is not None:
            for endpoint in runtime.endpoints:
                self.register(endpoint, group.id)
        return runtime

    def build_group_side(self, runtime, group, side, **kwargs):
        super().build_group_side(runtime, group, side, **kwargs)
        self.register(runtime.endpoint(side), group.id)

    def stop_group_probes(self, group_id):
        self.probe_service.stop_group(group_id)

    def stop_endpoint_probe(self, endpoint):
        self.probe_service.stop(endpoint)


def test_cross_topology_reuse_preserves_retained_listener(config_factory):
    plan = _plan()
    builder = ProbeBuilder(plan)
    group = dataclasses.replace(
        plan.groups[0],
        metadata={
            "target_hosts": {"A": "compute1", "B": "compute2"},
            "target_availability_zones": {"A": "az1", "B": "az1"},
        },
    )
    runtime = builder.build_group(group, sides=("A", "B"))
    kept, removed = runtime.endpoint("A"), runtime.endpoint("B")
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
    assert builder.probe_service.is_running(kept)
    assert kept.metadata["probe_service"]["ready"]
    assert not builder.probe_service.is_running(removed)


@pytest.mark.parametrize("second_pair,second_cycle", [("p34", 1), ("p12", 2)])
@pytest.mark.parametrize("limit", [0, 1])
def test_qualification_performance_does_not_deduplicate_another_pair_or_cycle(
    config_factory,
    second_pair,
    second_cycle,
    limit,
):
    config = config_factory(action="run", performance_max_paths=limit)
    reporter = Reporter(config, "sample-performance-scope")
    session = PerformanceSession()
    base = _plan().tests[0]
    try:
        for index, (pair_id, cycle) in enumerate(
            (("p12", 1), (second_pair, second_cycle))
        ):
            specs = [
                dataclasses.replace(
                    base,
                    id=f"{pair_id}-C{cycle}-{source}-{destination}",
                    protocol="tcp",
                    source_side=source,
                    destination_side=destination,
                    source_subnet_id="subnet",
                    destination_subnet_id="subnet",
                    metadata={
                        "host_qualification_pair_id": pair_id,
                        "host_qualification_cycle": cycle,
                    },
                )
                for source, destination in (("A", "B"), ("B", "A"))
            ]
            for spec in specs:
                reporter.result(spec.id, spec.category, "PASS", "reachable")
            runner = PerformanceRunner(
                config, mock.Mock(), reporter, mock.Mock(), session=session
            )
            runner._resolve_endpoints = lambda path: (
                SimpleNamespace(server_id="source"),
                SimpleNamespace(server_id="destination"),
                "192.0.2.1",
                "192.0.2.2",
                None,
            )
            selected = runner.plan_specs(specs, stage="host-qualification")
            assert len(selected) == (0 if limit and index else len(runner.MEASUREMENTS))
            assert runner.plan_specs(specs, stage="host-qualification") == []
        assert session.selected_by_stage["host-qualification"] == (1 if limit else 2)
    finally:
        reporter.logger.close()


def test_fallback_lifecycle_lock_does_not_deadlock_endpoint_workers(config_factory):
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.logger = mock.Mock()
    builder.name_prefix = "sample-fallback"
    builder.management_network_id = "mgmt"
    builder.management_subnet_id = "mgmt-subnet"
    builder.endpoint_management_sg_id = "mgmt-sg"
    builder.test_sg_id, builder.test_sg_ids = "test-sg", {}
    builder.cloud_operation_coordinator = None

    class BoundedLock:
        def __init__(self):
            self.lock = threading.RLock()

        def __enter__(self):
            if not self.lock.acquire(timeout=0.2):
                raise SuiteError("nested lifecycle deadlock")

        def __exit__(self, *_args):
            self.lock.release()

    builder.lifecycle_lock = BoundedLock()

    @serialized_lifecycle
    def port(self, name, network, subnets, *_args, **kwargs):
        return {
            "id": name,
            "fixed_ips": [{"subnet_id": subnets[0], "ip_address": "10.0.0.10"}],
            "mac_address": "fa:16:3e:00:00:01",
        }

    builder._create_port = port.__get__(builder)
    builder._create_server = lambda name, *_args, **_kwargs: {
        "server_id": name,
        "server_name": name,
        "host": "compute1",
        "availability_zone": "az1",
        "volume_id": None,
    }
    builder._wait_for_ssh = lambda *_args, **_kwargs: True
    builder._configure_endpoint = lambda *_args: None
    result = builder._create_endpoints(
        _plan().groups[0],
        "test",
        ["test-subnet"],
        sides=("A", "B"),
        generation=1,
    )
    assert [endpoint.side for endpoint in result] == ["A", "B"]


@pytest.mark.parametrize("strategy,expected_boots", [("rolling", 12), ("stable", 24)])
def test_host_boot_estimates_cover_every_selected_provider_topology(
    config_factory,
    strategy,
    expected_boots,
):
    config = config_factory(
        target_host_pairs=[("compute1", "compute2"), ("compute3", "compute4")],
        qualification_strategy=strategy,
    )
    plan = _plan()
    base_group, base_spec = plan.groups[0], plan.tests[0]
    plan.provider_groups = [
        dataclasses.replace(base_group, id=f"provider-{index}") for index in range(3)
    ]
    plan.tests = [
        dataclasses.replace(
            base_spec,
            id=f"test-{index}",
            dependencies=[group.id],
            source_group_id=group.id,
            destination_group_id=group.id,
        )
        for index, group in enumerate(plan.groups)
    ]
    inventory = _Inventory(
        [_service(f"compute{index}", "zone-a") for index in range(1, 5)]
    )
    qualification = HostQualificationPlanner(
        config,
        SimpleNamespace(networks=[]),
        plan,
        inventory,
        mock.Mock(),
    ).build()
    assert qualification.estimates["endpoint_vm_boots"] == expected_boots
    assert qualification.estimates["peak_endpoint_instances"] == (
        2 if strategy == "rolling" else 8
    )
