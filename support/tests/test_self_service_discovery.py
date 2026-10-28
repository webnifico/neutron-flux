from __future__ import annotations

import dataclasses
from types import SimpleNamespace

import pytest

from neutron_flux.check_plan import build_check_plan
from neutron_flux.discovery import Discoverer
from neutron_flux.log import Logger
from neutron_flux.network_contract import (
    NESTED_PUBLIC_PROJECT_NETWORK,
    PRIVATE_TRANSLATION_PROJECT_NETWORK,
    PROJECT_NETWORK,
)
from neutron_flux.policy import TopologyPolicy

from ._shared import build_plan


def _selected_networks(discovery, *network_ids: str):
    selected = set(network_ids)
    subnets = [item for item in discovery.subnets if item.network_id in selected]
    return dataclasses.replace(
        discovery,
        networks=[item for item in discovery.networks if item.id in selected],
        subnets=subnets,
        occupied_cidrs=[item.cidr for item in subnets],
    )


def _pool_groups(plan, pool_id: str):
    return [
        item
        for item in plan.tenant_groups
        if item.kind == PROJECT_NETWORK and item.pool_id == pool_id
    ]


def test_public1_and_public3_each_receive_one_level_ipv4_pool_coverage(
    config_factory, discovery_fixture, tmp_path
):
    discovery = _selected_networks(discovery_fixture, "n1", "n3")
    plan = build_plan(
        config_factory(external_networks=["Public1", "Public3"]),
        discovery,
        tmp_path,
    )
    groups = _pool_groups(plan, "tp4")

    assert {
        (item.external_network_name, item.external_subnet_id) for item in groups
    } == {("Public1", "s1v4"), ("Public3", "s3v4")}
    assert all(item.floating_subnet_id is None for item in groups)
    assert all(item.metadata["subnet_pool_fixed_ip_only"] is True for item in groups)
    assert all(item.metadata["source_nat_mode"] == "cloud-default" for item in groups)
    assert all(
        item.metadata["source_nat_controlled_by_flux"] is False for item in groups
    )
    assert not any(
        item.kind == NESTED_PUBLIC_PROJECT_NETWORK for item in plan.tenant_groups
    )

    by_external = {item.external_network_name: item for item in groups}
    assert by_external["Public1"].relationship == TopologyPolicy.DIRECT
    assert by_external["Public3"].relationship == TopologyPolicy.UNASSIGNED
    for group in groups:
        assert any(
            item.category == "project-provider-connectivity"
            and group.id in item.dependencies
            for item in plan.tests
        )


def test_public3_only_builds_only_public3_ipv4_paths(
    config_factory, discovery_fixture, tmp_path
):
    discovery = _selected_networks(discovery_fixture, "n3")
    plan = build_plan(
        config_factory(external_networks=["Public3"]), discovery, tmp_path
    )

    assert {
        (item.external_network_name, item.external_subnet_id)
        for item in _pool_groups(plan, "tp4")
    } == {("Public3", "s3v4")}
    assert not _pool_groups(plan, "tp6")
    internal_ids = {
        group.id
        for group in plan.groups
        if group.kind in {"one-router-project-networks", "two-router-static-routing"}
    }
    ipv6_specs = [spec for spec in plan.tests if spec.family == 6]
    assert ipv6_specs
    assert all(set(spec.dependencies) <= internal_ids for spec in ipv6_specs)
    assert all(6 not in group.families for group in plan.provider_groups)
    build_check_plan(plan, config_factory(migration_mode="live-preferred"))
    assert any("IPv6" in row["title"] for row in plan.checks)
    translations = [
        item
        for item in plan.tenant_groups
        if item.kind == PRIVATE_TRANSLATION_PROJECT_NETWORK
    ]
    assert {
        (item.external_network_name, item.external_subnet_id) for item in translations
    } == {("Public3", "s3v4")}


@pytest.mark.parametrize(
    "networks,ids", [(["Public1"], ["n1"]), (["Public2", "Public3"], ["n2", "n3"])]
)
def test_internal_router_families_follow_selected_dual_stack_paths(
    config_factory, discovery_fixture, tmp_path, networks, ids
):
    discovery = _selected_networks(discovery_fixture, *ids)
    plan = build_plan(
        config_factory(external_networks=networks),
        discovery,
        tmp_path,
    )
    internal = [
        group for group in plan.tenant_groups if group.relationship == "internal-router"
    ]
    assert {family for group in internal for family in group.families} == {4, 6}


def test_shared_default_pool_is_still_fixed_only_not_project_external(
    config_factory, discovery_fixture, tmp_path
):
    discovery_fixture.pools = [
        dataclasses.replace(item, raw={**item.raw, "is_default": True})
        for item in discovery_fixture.pools
        if not item.provider_pool
    ]
    discovery_fixture.subnets = [
        dataclasses.replace(item, subnetpool_id=None, address_scope_id=None)
        if item.id in {"s1v4", "s1v6", "s3v4"}
        else item
        for item in discovery_fixture.subnets
    ]
    discovery = _selected_networks(discovery_fixture, "n1", "n3")

    plan = build_plan(
        config_factory(external_networks=["Public1", "Public3"]),
        discovery,
        tmp_path,
    )
    ipv4 = _pool_groups(plan, "tp4")

    assert {(item.external_network_name, item.external_subnet_id) for item in ipv4} == {
        ("Public1", "s1v4"),
        ("Public3", "s3v4"),
    }
    assert all(item.floating_subnet_id is None for item in ipv4)
    assert all(item.metadata["floating_ip_target_allowed"] is False for item in ipv4)
    assert not any(item.id.startswith("NESTED-") for item in plan.tests)


def test_explicitly_different_scope_is_tested_as_expected_isolation(
    config_factory, discovery_fixture, tmp_path
):
    discovery_fixture.subnets = [
        dataclasses.replace(item, address_scope_id="other-scope")
        if item.id == "s3v4"
        else item
        for item in discovery_fixture.subnets
    ]
    discovery = _selected_networks(discovery_fixture, "n1", "n3")
    plan = build_plan(
        config_factory(external_networks=["Public1", "Public3"]),
        discovery,
        tmp_path,
    )

    public3 = next(
        item
        for item in _pool_groups(plan, "tp4")
        if item.external_network_name == "Public3"
    )
    tests = [
        item
        for item in plan.tests
        if public3.id in item.dependencies
        and item.category == "project-provider-connectivity"
    ]
    assert public3.relationship == TopologyPolicy.ISOLATED
    project_egress = [item for item in tests if item.source_group_id == public3.id]
    provider_ingress = [
        item for item in tests if item.destination_group_id == public3.id
    ]
    assert {item.expectation for item in project_egress} == {"reachable"}
    assert {item.expectation for item in provider_ingress} == {"blocked"}
    assert public3.metadata["source_nat_mode"] == "cloud-default"


def test_address_text_never_decides_pool_role(
    config_factory, discovery_fixture, tmp_path
):
    private_text_pool = dataclasses.replace(
        discovery_fixture.pool("tp4"),
        id="tp-text",
        name="NoPrefixInference",
        address_scope_id="scope4",
        prefixes=["10.77.0.0/16"],
    )
    discovery_fixture.pools.append(private_text_pool)
    discovery = _selected_networks(discovery_fixture, "n1")
    plan = build_plan(
        config_factory(external_networks=["Public1"]), discovery, tmp_path
    )

    group = next(item for item in _pool_groups(plan, "tp-text"))
    assert group.relationship == TopologyPolicy.DIRECT
    assert group.floating_subnet_id is None
    assert group.metadata["source_nat_mode"] == "cloud-default"


def test_different_ipv6_scopes_are_blocked_in_both_directions(
    config_factory, discovery_fixture, tmp_path
):
    discovery_fixture.subnets = [
        dataclasses.replace(item, address_scope_id="other-v6-scope")
        if item.id == "s1v6"
        else item
        for item in discovery_fixture.subnets
    ]
    discovery = _selected_networks(discovery_fixture, "n1")
    plan = build_plan(
        config_factory(external_networks=["Public1"]), discovery, tmp_path
    )

    group = next(item for item in _pool_groups(plan, "tp6"))
    tests = [
        item
        for item in plan.tests
        if group.id in item.dependencies
        and item.category == "project-provider-connectivity"
    ]
    assert group.relationship == TopologyPolicy.ISOLATED
    assert {item.expectation for item in tests} == {"blocked"}
    assert group.metadata["source_nat_mode"] == "not-applicable"


def test_ipv6_pool_is_fixed_routed_through_every_selected_ipv6_external(
    config_factory, discovery_fixture, tmp_path
):
    discovery = _selected_networks(discovery_fixture, "n1", "n2")
    plan = build_plan(
        config_factory(external_networks=["Public1", "Public2"]),
        discovery,
        tmp_path,
    )
    routed_ipv6 = _pool_groups(plan, "tp6")

    assert {
        (item.external_network_name, item.external_subnet_id) for item in routed_ipv6
    } == {("Public1", "s1v6"), ("Public2", "s2v6")}
    assert all(item.floating_subnet_id is None for item in routed_ipv6)
    assert all(
        item.metadata["source_nat_mode"] == "not-applicable" for item in routed_ipv6
    )
    assert all(
        item.metadata["source_nat_default_expected"] is False for item in routed_ipv6
    )
    assert not any(
        item.family == 6
        and item.operation
        in {
            "fip-baseline",
            "fip-withdraw",
            "fip-return",
            "snat-packet-size-profile",
        }
        for item in plan.tests
    )
    for group in routed_ipv6:
        paths = [
            item
            for item in plan.tests
            if item.category == "project-provider-connectivity"
            and group.id in item.dependencies
        ]
        if group.expected_routing == "observation":
            assert not paths
        else:
            assert paths and all(item.authoritative for item in paths)


def test_discovery_and_egress_wording_do_not_infer_roles_from_ip_text(
    config_factory, discovery_fixture, tmp_path
):
    logger = Logger(tmp_path / "discovery.log")
    discoverer = Discoverer(
        SimpleNamespace(backend_name="fixture"),
        logger,
        config_factory(),
    )
    discoverer._print_summary(discovery_fixture)
    logger.close()
    summary = (tmp_path / "discovery.log").read_text(encoding="utf-8")

    assert "class=" not in summary
    assert "subnet public3-ipv4: 172.20.4.0/22" in summary

    plan = build_plan(
        config_factory(
            ipv4_targets=["172.20.8.8"],
            ipv4_targets_configured=True,
        ),
        discovery_fixture,
        tmp_path,
    )
    ipv4_egress = [
        item for item in plan.tests if item.category == "egress" and item.family == 4
    ]
    assert ipv4_egress
    assert {item.expectation_reason for item in ipv4_egress} == {
        "operator-configured IPv4 targets are required reachability checks"
    }
