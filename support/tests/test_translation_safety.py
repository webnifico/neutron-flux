from __future__ import annotations

import dataclasses
from unittest import mock

import pytest

from neutron_flux.errors import SuiteError
from neutron_flux.models import Endpoint, PlannedGroup, RuntimeGroup
from neutron_flux.network_contract import (
    FLOATING_IP_TARGET_CONTRACT,
    PRIVATE_TRANSLATION_PROJECT_NETWORK,
    PROJECT_NETWORK,
)
from neutron_flux.plan_contract import plan_from_dict
from neutron_flux.resources import ResourceBuilder
from neutron_flux.test_selection import select_plan_tests

from ._shared import build_plan


def _public3_only(discovery):
    discovery.networks = [item for item in discovery.networks if item.id == "n3"]
    discovery.subnets = [item for item in discovery.subnets if item.network_id == "n3"]
    discovery.occupied_cidrs = [item.cidr for item in discovery.subnets]
    return discovery


def _endpoint(subnet_id: str = "fixed-subnet") -> Endpoint:
    return Endpoint(
        label="private:A",
        server_id="server-a",
        server_name="server-a",
        management_port_id="management-a",
        management_ip="10.254.0.10",
        test_port_id="test-a",
        test_mac="fa:16:3e:00:00:01",
        fixed_ips={subnet_id: "10.128.0.10"},
        host=None,
        availability_zone=None,
        volume_id=None,
        side="A",
    )


def test_pool_groups_are_fixed_only_and_translation_tests_use_private_groups(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    groups = {item.id: item for item in plan.groups}
    pool_groups = [
        item
        for item in plan.tenant_groups
        if item.kind == PROJECT_NETWORK and item.pool_id
    ]
    assert pool_groups
    assert all(item.floating_subnet_id is None for item in pool_groups)
    assert all(
        item.metadata["floating_ip_target_allowed"] is False
        and item.metadata["subnet_pool_fixed_ip_only"] is True
        for item in pool_groups
    )
    assert all(
        item.metadata["source_nat_mode"]
        == ("cloud-default" if item.families == [4] else "not-applicable")
        and item.metadata["source_nat_controlled_by_flux"] is False
        and item.metadata["source_nat_default_expected"] is (item.families == [4])
        for item in pool_groups
    )

    private_groups = [
        item
        for item in plan.tenant_groups
        if item.kind == PRIVATE_TRANSLATION_PROJECT_NETWORK
    ]
    assert {item.external_subnet_id for item in private_groups} == {"s1v4", "s3v4"}
    assert all(
        item.pool_id is None
        and item.synthetic_cidr
        and item.floating_subnet_id
        and item.metadata["fixed_address_role"] == "disposable-private"
        and item.metadata["floating_ip_target_contract"] == FLOATING_IP_TARGET_CONTRACT
        for item in private_groups
    )

    for spec in plan.tests:
        if spec.operation in {"fip-baseline", "fip-withdraw", "fip-return"}:
            target = groups[str(spec.destination_group_id)]
            assert target.kind == PRIVATE_TRANSLATION_PROJECT_NETWORK
            assert target.pool_id is None
            assert spec.destination_side == "A"
        if spec.operation in {
            "snat-packet-size-profile",
            "fip-egress-source-address",
            "fip-egress-mtu",
            "fip-egress-fragmentation",
        }:
            source = groups[str(spec.source_group_id)]
            assert source.kind == PRIVATE_TRANSLATION_PROJECT_NETWORK

    assert not any(item.operation == "source-nat-observe" for item in plan.tests)

    assert not any(
        item.id.startswith("FIP-EGRESS-PACKET-SIZE-project-network-")
        for item in plan.tests
    )


def test_public3_exact_fip_rerun_builds_only_safe_required_topology(
    config_factory, discovery_fixture, tmp_path
):
    discovery = _public3_only(discovery_fixture)
    plan = build_plan(
        config_factory(external_networks=["Public3"]),
        discovery,
        tmp_path,
    )
    target = next(
        item for item in plan.tests if item.id.startswith("FIP-EGRESS-SOURCE-ADDRESS-")
    )
    assert "private-translation" in target.id
    assert "project-network-tp4" not in target.id

    selected = select_plan_tests(plan, [target.id])
    assert {item.kind for item in selected.tenant_groups} == {
        PRIVATE_TRANSLATION_PROJECT_NETWORK
    }
    private = selected.tenant_groups[0]
    assert private.pool_id is None
    assert private.synthetic_cidr
    assert private.external_subnet_id == "s3v4"
    assert private.floating_subnet_id == "s3v4"
    assert {item.id for item in selected.provider_groups} == {"provider-n3"}
    assert {item.operation for item in selected.tests} == {
        "controller-observation",
        "controller-ssh",
        "fip-egress-source-address",
    }


def test_pool_groups_record_cloud_default_but_own_no_translation_tests(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(
        config_factory(
            compute_host_connectivity_enabled=False,
        ),
        discovery_fixture,
        tmp_path,
    )
    groups = {item.id: item for item in plan.groups}
    pool_groups = [
        item
        for item in plan.tenant_groups
        if item.kind == PROJECT_NETWORK and item.pool_id and item.families == [4]
    ]
    assert pool_groups
    assert all(
        item.metadata["source_nat_mode"] == "cloud-default"
        and item.floating_subnet_id is None
        for item in pool_groups
    )
    for spec in plan.tests:
        if spec.operation in {
            "fip-baseline",
            "fip-withdraw",
            "fip-return",
            "snat-packet-size-profile",
            "fip-egress-source-address",
            "fip-egress-mtu",
            "fip-egress-fragmentation",
        }:
            related = {
                groups[group_id].id
                for group_id in {
                    str(spec.source_group_id or ""),
                    str(spec.destination_group_id or ""),
                }
                if group_id in groups
                and groups[group_id].kind == PROJECT_NETWORK
                and groups[group_id].pool_id
            }
            assert not related


@pytest.mark.parametrize(
    ("kind", "pool_id", "synthetic_cidr"),
    [
        (PROJECT_NETWORK, "public-pool", None),
        ("routing-unassigned-project-network", None, "10.250.0.0/24"),
    ],
)
def test_stale_unsafe_group_is_rejected_before_topology_cloud_operation(
    kind, pool_id, synthetic_cidr
):
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.osc = mock.Mock()
    unsafe = PlannedGroup(
        id="stale-sample",
        kind=kind,
        label="Stale sample floating target",
        network_id=None,
        network_name=None,
        subnet_ids=[],
        families=[4],
        pool_id=pool_id,
        external_network_id="external-network",
        external_network_name="Public3",
        external_subnet_id="external-subnet",
        floating_subnet_id="external-subnet",
        prefix_length=24,
        synthetic_cidr=synthetic_cidr,
    )

    with pytest.raises(SuiteError, match="Unsafe translation topology"):
        builder._build_tenant_group(unsafe, sides=("A",), generation=1)
    builder.osc.json.assert_not_called()
    builder.osc.run.assert_not_called()


def test_stale_pool_fip_is_rejected_before_fip_api_call(config_factory):
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder.capture_router_state = mock.Mock()
    builder._create_group_fips = mock.Mock()
    endpoint = _endpoint()
    stale = PlannedGroup(
        id="stale-sample",
        kind=PROJECT_NETWORK,
        label="Pool fixed IP with upstream floating IP",
        network_id="fixed-network",
        network_name="fixed-network",
        subnet_ids=["fixed-subnet"],
        families=[4],
        pool_id="public-pool",
        external_network_id="external-network",
        external_subnet_id="external-subnet",
        floating_subnet_id="external-subnet",
        prefix_length=27,
    )
    runtime = RuntimeGroup(
        plan=stale,
        network_id="fixed-network",
        network_name="fixed-network",
        subnet_ids=["fixed-subnet"],
        router_id="router",
        endpoints=[endpoint],
        source_nat_enabled=True,
        fips={},
    )

    with pytest.raises(SuiteError, match="prohibited"):
        builder.ensure_group_fips(runtime)
    builder.capture_router_state.assert_not_called()
    builder._create_group_fips.assert_not_called()


def test_approved_plan_loader_rejects_signed_shape_with_pool_fip_target():
    unsafe = PlannedGroup(
        id="unsafe",
        kind=PROJECT_NETWORK,
        label="Unsafe",
        network_id=None,
        network_name=None,
        subnet_ids=[],
        families=[4],
        pool_id="pool",
        external_network_id="external",
        external_network_name="Public3",
        external_subnet_id="external-subnet",
        floating_subnet_id="external-subnet",
        prefix_length=27,
    )
    payload = {
        "provider_groups": [],
        "project_network_groups": [dataclasses.asdict(unsafe)],
        "estimated": {},
        "skipped": [],
        "tests": [],
        "warnings": [],
    }
    with pytest.raises(SuiteError, match="subnet-pool-derived fixed network"):
        plan_from_dict(payload)


def test_missing_floating_ip_service_role_omits_translation_suite(
    config_factory, discovery_fixture, tmp_path
):
    discovery = discovery_fixture
    discovery.subnet("s3v4").service_types = ["network:router_gateway"]
    plan = build_plan(
        config_factory(),
        discovery,
        tmp_path,
    )
    assert not any(
        item.kind == PRIVATE_TRANSLATION_PROJECT_NETWORK
        and item.external_subnet_id == "s3v4"
        for item in plan.tenant_groups
    )
    assert not any(
        item.operation in {"fip-baseline", "fip-withdraw", "fip-return"}
        and item.destination_group_id == "private-translation-ipv4-external-s3v4"
        for item in plan.tests
    )
    assert any("network:floatingip-eligible" in item["reason"] for item in plan.skipped)


def test_synthetic_translation_and_nested_cidrs_never_overlap_inventory(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    generated = [
        item.synthetic_cidr for item in plan.tenant_groups if item.synthetic_cidr
    ]
    assert len(generated) == len(set(generated))
    visible = set(discovery_fixture.occupied_cidrs)
    visible.update(
        prefix for pool in discovery_fixture.pools for prefix in pool.prefixes
    )
    import ipaddress

    assert all(
        not ipaddress.ip_network(candidate).overlaps(ipaddress.ip_network(existing))
        for candidate in generated
        for existing in visible
        if ipaddress.ip_network(candidate).version
        == ipaddress.ip_network(existing).version
    )


def test_valid_private_contract_still_allocates_lazily(config_factory):
    endpoint = _endpoint()
    group = PlannedGroup(
        id="private",
        kind=PRIVATE_TRANSLATION_PROJECT_NETWORK,
        label="Private translation",
        network_id="private-network",
        network_name="private-network",
        subnet_ids=["fixed-subnet"],
        families=[4],
        external_network_id="external-network",
        external_subnet_id="external-subnet",
        floating_subnet_id="floating-subnet",
        prefix_length=24,
        synthetic_cidr="10.32.0.0/24",
        metadata={
            "fixed_address_role": "disposable-private",
            "source_nat_mode": "cloud-default",
            "source_nat_controlled_by_flux": False,
            "source_nat_default_expected": True,
            "floating_ip_target_allowed": True,
            "floating_ip_target_contract": FLOATING_IP_TARGET_CONTRACT,
            "floating_ip_endpoint_side": "A",
        },
    )
    runtime = RuntimeGroup(
        plan=group,
        network_id="private-network",
        network_name="private-network",
        subnet_ids=["fixed-subnet"],
        router_id="router",
        endpoints=[endpoint],
        source_nat_enabled=True,
        fips={},
        metadata={"floating_ip_fixed_subnet_id": "fixed-subnet"},
    )
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder.logger = mock.Mock()
    builder.capture_router_state = mock.Mock(
        return_value={"external_gateway_info": {"enable_snat": True}}
    )

    def allocate(target):
        target.fips[endpoint.label] = {
            "id": "fip-id",
            "address": "192.0.2.20",
            "fixed_ip": "10.128.0.10",
        }

    builder._create_group_fips = mock.Mock(side_effect=allocate)
    builder.ensure_group_fips(runtime)
    builder._create_group_fips.assert_called_once_with(runtime)
