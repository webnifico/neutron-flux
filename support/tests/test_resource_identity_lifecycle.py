from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.errors import SuiteError
from neutron_flux.executor import AdaptiveExecutor
from neutron_flux.models import PlannedGroup, RuntimeGroup
from neutron_flux.pair_workflow import CoordinatedPairExecutor
from neutron_flux.resource_naming import (
    ResourceNameCollisionError,
    ResourceNameRegistry,
    claim_runtime_resource_name,
    resource_name_registry,
)
from neutron_flux.resources import ResourceBuilder


def test_released_batch_then_new_executor_then_side_rotation(tmp_path):
    """Exercise rebuild/rotation collisions with real build and name ownership."""
    group = PlannedGroup(
        id="provider-public@workflow-observer",
        kind="provider",
        label="Provider observer",
        network_id="network-id",
        network_name="Public",
        subnet_ids=["subnet-id"],
        families=[4],
    )
    builder = object.__new__(ResourceBuilder)
    builder.name_prefix = "nflux-batch-rotation"
    builder.resource_name_registry = resource_name_registry(
        builder.name_prefix, run_dir=tmp_path
    )
    builder.runtime_groups = []
    builder.group_failures = {}
    builder.group_failure_types = {}
    builder.reporter = mock.Mock(resources=[])
    builder.logger = mock.Mock()
    builder.stop_endpoint_probe = mock.Mock()
    builder.run_tag = "neutron-flux-batch-rotation"
    builder.config = SimpleNamespace(max_active_endpoints=2)
    builder.management_network_id = "management"
    builder.management_subnet_id = "management-subnet"
    builder.endpoint_management_sg_id = "management-sg"
    builder.test_sg_id = "data-sg"
    builder.test_sg_ids = {}
    builder.tracker = mock.Mock()
    builder._network_port_security_enabled = lambda _: True
    builder._wait_for_ssh = lambda *args, **kwargs: True
    builder._configure_endpoint = mock.Mock()
    created = []
    port_names = []

    def cloud_port(*args):
        assert args[:2] == ("port", "create")
        name = args[-1]
        port_names.append(name)
        subnet = args[args.index("--fixed-ip") + 1].split("=", 1)[1]
        return {
            "id": name,
            "mac_address": "fa:16:3e:00:00:01",
            "fixed_ips": [{"subnet_id": subnet, "ip_address": "192.0.2.10"}],
        }

    builder.osc = SimpleNamespace(json=cloud_port)

    def cloud_server(name, port_ids, **kwargs):
        claim_runtime_resource_name(builder, name, resource_type="server")
        created.append(name)
        return dict(
            server_id=name,
            server_name=name,
            host="host-2",
            availability_zone="az",
            volume_id=None,
        )

    builder._create_server = cloud_server

    def build(planned, *, sides, generation):
        return RuntimeGroup(
            planned,
            "network-id",
            "Public",
            ["subnet-id"],
            None,
            builder._create_endpoints(
                planned, "network-id", ["subnet-id"], sides=sides, generation=generation
            ),
            None,
            {},
            generation=generation,
        )

    builder._build_provider_group = build
    first = builder.build_group(group, sides=("A",))
    assert first.generation == 1
    builder.runtime_groups.clear()  # Previous batch's verified cleanup.

    executor = object.__new__(CoordinatedPairExecutor)
    executor.builder = builder
    executor.groups = {group.id: group}
    executor.active = {}
    executor.group_loads = 0
    executor._inject_failure = mock.Mock()
    executor._refresh_checkpoint = mock.Mock()
    executor.cleanup_manager = mock.Mock()
    executor.cleanup_manager.cleanup_group_side.return_value = True
    second = AdaptiveExecutor._build(executor, group.id, sides=("A",))
    assert second.generation == 2
    executor.active[group.id] = second
    executor._rotate(group.id, second.endpoints[0])

    assert second.generation == 3
    assert len(set(created)) == 3
    assert len(set(port_names)) == 6
    assert len(set(created + port_names)) == 9
    recovered = ResourceNameRegistry(
        builder.name_prefix, journal_path=tmp_path / "resource-identities.jsonl"
    ).snapshot()
    assert set(recovered) == set(created + port_names)
    assert all(item["claimed_for_create"] for item in recovered.values())
    assert second.endpoints[0].label == first.endpoints[0].label
    assert second.endpoints[0].metadata["generation"] == 3
    executor.cleanup_manager.cleanup_group_side.assert_called_once_with(group.id, "A")


def test_durable_names_survive_concurrency_shortening_and_restart(tmp_path):
    prefix = "NFlux-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234"
    path = tmp_path / "resource-identities.jsonl"
    registry = ResourceNameRegistry(prefix, journal_path=path)

    def create(_):
        name = registry.allocate(
            identity="same-logical-endpoint",
            descriptor="long-descriptor" * 20,
            role="endpoint-a",
            resource_type="server",
            limit=50,
        )
        registry.claim_for_create(name, resource_type="server")
        generation = registry.allocate_group_generation("shared-group")
        return name, generation

    with ThreadPoolExecutor(max_workers=8) as pool:
        allocated = list(pool.map(create, range(64)))
    names = [name for name, _ in allocated]
    assert len(set(names)) == 64
    assert all(len(name) <= 50 and name.startswith(prefix + "-r") for name in names)
    assert sorted(g for _, g in allocated) == list(range(1, 65))
    restored = ResourceNameRegistry(prefix, journal_path=path)
    assert restored.snapshot() == registry.snapshot()
    with pytest.raises(ResourceNameCollisionError, match="already been claimed"):
        restored.claim_for_create(names[0], resource_type="server")
    assert restored.allocate_group_generation("shared-group") == 65
    replacement = restored.allocate(
        identity="same-logical-endpoint",
        descriptor="replacement",
        role="endpoint-a",
        resource_type="server",
        limit=50,
    )
    assert replacement not in names
    assert replacement.startswith(prefix + "-r41-")


def test_allocation_is_durable_before_create_and_unclaimed_ids_are_never_recycled(
    tmp_path,
):
    path = tmp_path / "resource-identities.jsonl"
    first = ResourceNameRegistry("nflux-restart", journal_path=path)
    name = first.allocate(
        identity="controller",
        descriptor="managed",
        role="controller",
        resource_type="server",
        limit=63,
    )
    # A crash before submission consumes the allocation; a restart gets a new ID.
    restarted = ResourceNameRegistry("nflux-restart", journal_path=path)
    assert name in restarted.snapshot()
    next_name = restarted.allocate(
        identity="controller",
        descriptor="managed",
        role="controller",
        resource_type="server",
        limit=63,
    )
    assert next_name != name
    restarted.claim_for_create(next_name, resource_type="server")
    assert ResourceNameRegistry("nflux-restart", journal_path=path).snapshot()[
        next_name
    ]["claimed_for_create"]


@pytest.mark.parametrize("corruption", ["{", "{}\n", '{"schema":1,"prefix":"other"}\n'])
def test_corrupt_identity_journal_stops_creation(tmp_path, corruption):
    path = tmp_path / "resource-identities.jsonl"
    path.write_text(corruption)
    with pytest.raises(SuiteError, match="Cannot replay"):
        ResourceNameRegistry("nflux-corrupt", journal_path=path)


def test_failed_journal_write_blocks_further_allocations(tmp_path, monkeypatch):
    import neutron_flux.resource_naming as naming

    registry = ResourceNameRegistry(
        "nflux-write-failure", journal_path=tmp_path / "ids.jsonl"
    )
    append = naming.append_text
    monkeypatch.setattr(
        naming, "append_text", mock.Mock(side_effect=SuiteError("disk full"))
    )
    with pytest.raises(SuiteError, match="disk full"):
        registry.allocate(
            identity="ep", descriptor="ep", role="a", resource_type="server", limit=63
        )
    monkeypatch.setattr(naming, "append_text", append)
    with pytest.raises(SuiteError, match="requires recovery"):
        registry.allocate(
            identity="ep", descriptor="ep", role="a", resource_type="server", limit=63
        )
    assert registry.snapshot() == {}
