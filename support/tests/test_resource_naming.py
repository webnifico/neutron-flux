from __future__ import annotations

import inspect
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.resource_naming import (
    ResourceNameCollisionError,
    ResourceNameRegistry,
    canonical_project_side,
    managed_resource_name,
    resource_name,
    resource_name_registry,
)
from neutron_flux.resources import ResourceBuilder
from neutron_flux.runtime.topology import TopologyRuntimeMixin


def _group(group_id: str) -> SimpleNamespace:
    return SimpleNamespace(
        id=group_id,
        kind="extra-route-pair",
        families=[4],
    )


def test_long_resource_names_preserve_prefix_roles_and_unique_identity():
    prefix = "NFlux-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234"
    groups = (
        _group("extra-route-pair-ipv4-db4ad1-" + ("a" * 80)),
        _group("extra-route-pair-ipv4-db4ad1-" + ("b" * 80)),
    )
    names = {
        resource_name(
            prefix,
            group,
            generation=generation,
            role=role,
            resource_type=resource_type,
            limit=63,
        )
        for group in groups
        for generation in (1, 2)
        for role in ("tenant-a", "tenant-b", "transit", "east-west")
        for resource_type in ("network", "subnet", "router")
    }

    assert len(names) == 48
    assert all(name.startswith(f"{prefix}-") for name in names)
    assert all(len(name) <= 63 for name in names)
    assert all(
        forbidden not in name.lower()
        for name in names
        for forbidden in ("tenant", "extra-route", "fabric-scale")
    )
    assert any(name.endswith("-project-a-net") for name in names)
    assert any(name.endswith("-project-b-net") for name in names)


def test_registry_rejects_different_identity_before_create_claim():
    registry = ResourceNameRegistry("nflux-sample-collision")
    name = "nflux-sample-collision-project-a-net"
    registry.reserve(name, identity="group-a", resource_type="network")

    with pytest.raises(ResourceNameCollisionError, match="collision"):
        registry.reserve(name, identity="group-b", resource_type="network")

    registry.claim_for_create(name, resource_type="network")
    with pytest.raises(ResourceNameCollisionError, match="already been claimed"):
        registry.claim_for_create(name, resource_type="network")


def test_registry_is_thread_safe_for_concurrent_resource_generation():
    prefix = "nflux-sample-threaded"
    registry = resource_name_registry(prefix)

    def allocate(index: int) -> str:
        return managed_resource_name(
            prefix,
            identity=f"concurrent-project-path:{index}",
            role="project-a",
            resource_type="port",
        )

    with ThreadPoolExecutor(max_workers=12) as executor:
        names = list(executor.map(allocate, range(128)))

    assert len(names) == len(set(names)) == 128
    assert all(name.startswith(f"{prefix}-") for name in names)
    assert all(len(name) <= 63 for name in names)
    assert len(registry.snapshot()) == 128


def test_security_group_duplicate_is_stopped_before_second_api_cloud_operation():
    builder = object.__new__(ResourceBuilder)
    builder.name_prefix = "nflux-sample-sg-guard"
    builder.resource_name_registry = resource_name_registry(builder.name_prefix)
    builder.run_tag = "neutron-flux-sample-sg-guard"
    builder.logger = mock.Mock()
    builder.tracker = mock.Mock()
    builder.osc = mock.Mock()
    builder.osc.json.return_value = {"id": "sg-id"}
    name = managed_resource_name(
        builder.name_prefix,
        identity="security-group:controller",
        role="controller",
        resource_type="security-group",
    )

    assert builder._create_security_group(name) == "sg-id"
    with pytest.raises(ResourceNameCollisionError, match="already been claimed"):
        builder._create_security_group(name)

    builder.osc.json.assert_called_once()


def test_recreated_topology_has_distinct_physical_names_even_with_same_logical_identity():
    builder = object.__new__(ResourceBuilder)
    builder.name_prefix = "nflux-sample-topology-guard"
    builder.resource_name_registry = resource_name_registry(builder.name_prefix)
    builder.run_tag = "neutron-flux-sample-topology-guard"
    builder.osc = mock.Mock()
    builder.osc.json.side_effect = [
        {"id": "network-id"},
        {
            "id": "subnet-id",
            "cidr": "192.0.2.0/24",
            "gateway_ip": "192.0.2.1",
        },
    ] * 2
    builder.tracker = mock.Mock()
    builder._availability_zone_hint_args = mock.Mock(return_value=[])
    builder._validate_created_resource_zone = mock.Mock()
    group = SimpleNamespace(
        id="two-router-static-routing-ipv4-topology-guard",
        kind="extra-route-pair",
        label="Two-router static-routing guard",
        families=[4],
        pool_id="pool-id",
        prefix_length=24,
        address_scope_id="scope-id",
    )

    builder._create_generated_tenant_network(
        group,
        generation=1,
        suffix="project-a",
    )
    builder._create_generated_tenant_network(group, generation=1, suffix="project-a")
    calls = builder.osc.json.call_args_list
    assert len(calls) == 4
    assert len({call.args[-1] for call in calls}) == 4


def test_recreated_router_has_distinct_physical_names_even_with_same_logical_identity():
    builder = object.__new__(ResourceBuilder)
    builder.name_prefix = "nflux-sample-router-guard"
    builder.resource_name_registry = resource_name_registry(builder.name_prefix)
    builder.run_tag = "neutron-flux-sample-router-guard"
    builder.osc = mock.Mock()
    builder.osc.json.return_value = {"id": "router-id"}
    builder.tracker = mock.Mock()
    builder._availability_zone_hint_args = mock.Mock(return_value=[])
    builder._validate_created_resource_zone = mock.Mock()
    group = SimpleNamespace(
        id="two-router-static-routing-ipv4-router-guard",
        kind="extra-route-pair",
        label="Two-router static-routing guard",
        families=[4],
    )

    builder._create_scenario_router(
        group,
        generation=1,
        suffix="project-router",
    )
    builder._create_scenario_router(group, generation=1, suffix="project-router")
    calls = builder.osc.json.call_args_list
    assert len(calls) == 2
    assert calls[0].args[-1] != calls[1].args[-1]


def test_legacy_side_names_read_as_project_identity():
    assert canonical_project_side("tenant-a") == "project-a"
    assert canonical_project_side("tenant-b") == "project-b"
    assert canonical_project_side("A") == "project-a"
    assert canonical_project_side("B") == "project-b"
    assert canonical_project_side("project-a") == "project-a"
    assert canonical_project_side("project-b") == "project-b"


def test_new_two_router_manifests_use_project_side_terms():
    source = inspect.getsource(TopologyRuntimeMixin._build_extra_route_pair)

    assert 'suffix="project-a"' in source
    assert 'suffix="project-b"' in source
    assert 'suffix="tenant-a"' not in source
    assert 'suffix="tenant-b"' not in source
