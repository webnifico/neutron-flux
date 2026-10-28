from __future__ import annotations

import dataclasses
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.engine import TestEngine as FluxTestEngine
from neutron_flux.errors import SuiteError
from neutron_flux.log import Logger
from neutron_flux.models import PlannedGroup, RuntimeGroup
from neutron_flux.models import TestSpec as FluxTestSpec
from neutron_flux.network_contract import NESTED_PUBLIC_PROJECT_NETWORK, PROJECT_NETWORK
from neutron_flux.planning import Planner
from neutron_flux.policy import TopologyPolicy
from neutron_flux.reporting import Reporter
from neutron_flux.reporting_components.html import render_html
from neutron_flux.resources import ResourceBuilder
from neutron_flux.test_selection import select_plan_tests
from neutron_flux.translation_safety import (
    validate_runtime_floating_ip_target,
    validate_tenant_group_before_build,
)

from ._shared import build_plan
from .test_report_workflow import _embedded_payload, _payload


def test_plans_member_realistic_pool_and_translation_suites(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)

    routed_ipv4 = next(
        item
        for item in plan.tenant_groups
        if item.pool_id == "tp4"
        and item.external_subnet_id == "s1v4"
        and item.relationship == TopologyPolicy.DIRECT
    )
    assert routed_ipv4.floating_subnet_id is None
    assert routed_ipv4.metadata["routed_fixed_ip_topology"] is True
    assert routed_ipv4.metadata["source_nat_mode"] == "cloud-default"
    assert routed_ipv4.metadata["source_nat_controlled_by_flux"] is False
    assert routed_ipv4.metadata["source_nat_default_expected"] is True
    assert not any(
        spec.destination_group_id == routed_ipv4.id
        and spec.operation in {"fip-baseline", "snat-packet-size-profile"}
        for spec in plan.tests
    )
    assert not any(
        item.kind == NESTED_PUBLIC_PROJECT_NETWORK for item in plan.tenant_groups
    )
    assert not any(item.id.startswith("NESTED-") for item in plan.tests)
    assert not any(item.operation == "source-nat-observe" for item in plan.tests)
    assert {
        item.external_network_name
        for item in plan.tenant_groups
        if item.kind == PROJECT_NETWORK and item.pool_id == "tp4"
    } == {"Public1", "Public3"}
    assert {
        item.external_network_name
        for item in plan.tenant_groups
        if item.kind == PROJECT_NETWORK and item.pool_id == "tp6"
    } == {"Public1", "Public2"}

    routed_ipv6 = [
        spec
        for spec in plan.tests
        if spec.family == 6
        and spec.category == "project-provider-connectivity"
        and "project-network-tp6" in " ".join(spec.dependencies)
    ]
    assert routed_ipv6
    assert not any(
        spec.family == 6 and spec.operation.startswith("fip") for spec in plan.tests
    )
    assert all(
        item.metadata["source_nat_mode"] == "not-applicable"
        and item.metadata["source_nat_controlled_by_flux"] is False
        for item in plan.tenant_groups
        if item.kind == PROJECT_NETWORK and item.pool_id == "tp6"
    )


def test_different_scope_pool_group_keeps_default_snat_and_fixed_routing(
    config_factory, discovery_fixture, tmp_path
):
    discovery_fixture.subnets = [
        dataclasses.replace(item, address_scope_id="other-scope")
        if item.id == "s3v4"
        else item
        for item in discovery_fixture.subnets
    ]
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    group = next(
        item
        for item in plan.tenant_groups
        if item.pool_id == "tp4"
        and item.external_subnet_id == "s3v4"
        and item.relationship == TopologyPolicy.ISOLATED
    )
    provider = next(item for item in plan.provider_groups if "s3v4" in item.subnet_ids)
    project_egress = [
        item
        for item in plan.tests
        if item.source_group_id == group.id
        and item.destination_group_id == provider.id
        and item.category == "project-provider-connectivity"
    ]
    provider_ingress = [
        item
        for item in plan.tests
        if item.source_group_id == provider.id
        and item.destination_group_id == group.id
        and item.category == "project-provider-connectivity"
    ]

    assert group.metadata["source_nat_mode"] == "cloud-default"
    assert group.metadata["source_nat_controlled_by_flux"] is False
    assert {item.protocol for item in project_egress} == {"icmp", "tcp", "udp"}
    assert {item.expectation for item in project_egress} == {"reachable"}
    assert {item.expectation for item in provider_ingress} == {"blocked"}
    assert all(
        item.metadata["routing_policy"]["basis"] == "router-default-snat"
        for item in project_egress
    )

    unassigned_ipv6 = next(
        item
        for item in plan.tenant_groups
        if item.pool_id == "tp6" and item.relationship == TopologyPolicy.UNASSIGNED
    )
    assert unassigned_ipv6.metadata["source_nat_mode"] == "not-applicable"


def test_pool_network_uses_the_pool_default_prefix_without_nested_reallocation(
    config_factory, discovery_fixture, tmp_path
):
    pool = discovery_fixture.pool("tp4")
    assert pool is not None
    replacement = dataclasses.replace(
        pool,
        default_prefix_length=30,
        min_prefix_length=24,
        max_prefix_length=30,
    )
    discovery_fixture.pools = [
        replacement if item.id == pool.id else item for item in discovery_fixture.pools
    ]

    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    groups = [item for item in plan.tenant_groups if item.pool_id == "tp4"]
    assert groups
    assert {item.prefix_length for item in groups} == {30}
    assert not any(item.kind == NESTED_PUBLIC_PROJECT_NETWORK for item in groups)


def test_exact_egress_selection_is_directional_and_prunes_resources(
    config_factory, discovery_fixture, tmp_path
):
    full_config = config_factory()
    full = build_plan(full_config, discovery_fixture, tmp_path)
    target = next(
        spec for spec in full.tests if spec.id.startswith("FIP-EGRESS-SOURCE-ADDRESS-")
    )
    assert target.requires == []
    assert target.requires_pass == []

    selected = select_plan_tests(full, [target.id])
    assert selected.selection_mode == "exact"
    assert selected.requested_test_ids == [target.id]
    assert {spec.id for spec in selected.tests} == {
        "CONTROL-OBSERVATION-PORTS",
        "CONTROL-SSH",
        target.id,
    }
    assert set(selected.automatically_included_test_ids) == {
        "CONTROL-OBSERVATION-PORTS",
        "CONTROL-SSH",
    }
    assert {item.id for item in selected.tenant_groups} == {target.source_group_id}
    assert len(selected.provider_groups) == 1
    selected_target = next(spec for spec in selected.tests if spec.id == target.id)
    assert "explicit_execution_authorized" not in selected_target.metadata
    assert "explicit_execution_authorization" not in selected_target.metadata

    selective_config = dataclasses.replace(full_config, test_ids=[target.id])
    Planner(
        selective_config, discovery_fixture, Logger(tmp_path / "select.log")
    ).recalculate(selected, quota_preflight=False)
    assert selected.estimated["test_results"] == 3
    assert selected.estimated["floating_ips_created"] >= 1
    assert selected.estimated["performance_path_candidates"] == 0
    assert selected.estimated["concurrent_load_pairs"] == 0


def test_exact_fip_withdraw_selection_also_keeps_restoration(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    withdraw = next(spec for spec in plan.tests if spec.id.startswith("FIP-WITHDRAW-"))
    selected = select_plan_tests(plan, [withdraw.id])
    ids = {spec.id for spec in selected.tests}

    assert withdraw.requires_pass[0] in ids
    assert any(item.startswith("FIP-RETURN-") for item in ids)


def test_unknown_saved_test_ids_have_suggestions(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    target = next(
        spec
        for spec in plan.tests
        if spec.category == "project-provider-connectivity" and spec.protocol == "tcp"
    )
    with pytest.raises(SuiteError, match="closest"):
        select_plan_tests(plan, [target.id[:-1] + "X"])


def test_report_prominently_identifies_exact_test_selection() -> None:
    payload = _payload()
    payload["configuration"]["test_selection"] = {
        "mode": "exact",
        "requested_test_ids": ["TEST-REQUESTED"],
        "automatically_included_test_ids": ["CONTROL-SSH", "BASELINE-TCP"],
    }

    html = render_html(payload)
    embedded = _embedded_payload(html)

    assert (
        embedded["configuration"]["test_selection"]
        == payload["configuration"]["test_selection"]
    )
    assert "Exact test selection" in html
    assert '["Test scope",testSelectionLabel]' in html


def test_failed_required_baseline_blocks_dependent_probe_without_cloud_operation(
    config_factory, tmp_path
):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    reporter = Reporter(config, "sample-prerequisite")
    reporter.result(
        "BASELINE",
        "floating-ip",
        "FAIL",
        "baseline failed",
        family=4,
        expected="reachable",
        observed="blocked",
        authoritative=True,
    )
    builder = SimpleNamespace(
        ssh_endpoint=lambda endpoint, command: None,
        ssh_controller=lambda command: None,
        runtime_groups=[],
        osc=mock.Mock(),
    )
    engine = FluxTestEngine(config, SimpleNamespace(), builder, reporter)
    operation = mock.Mock()
    engine.operations["probe"] = operation
    spec = FluxTestSpec(
        id="DEPENDENT",
        category="floating-ip-packet-size",
        operation="probe",
        family=4,
        expectation="reachable",
        expectation_reason="baseline must pass first",
        authoritative=True,
        dependencies=[],
        requires=["BASELINE"],
        requires_pass=["BASELINE"],
    )

    engine._run_spec(spec)

    operation.assert_not_called()
    result = reporter.get_result("DEPENDENT")
    assert result is not None
    assert result.status == "BLOCKED_BY_PREREQUISITE"
    assert result.details["cloud_operation_performed"] is False


def test_legacy_nested_topology_is_rejected_before_runtime_cloud_operation():
    group = PlannedGroup(
        id="nested",
        kind=NESTED_PUBLIC_PROJECT_NETWORK,
        label="Retired nested topology",
        network_id="project-net",
        network_name="project-net",
        subnet_ids=["project-subnet"],
        families=[4],
        metadata={},
    )

    with pytest.raises(SuiteError, match="legacy nested"):
        validate_tenant_group_before_build(group)


def test_fip_runtime_refuses_pool_and_legacy_nested_targets():
    builder = ResourceBuilder.__new__(ResourceBuilder)
    direct_plan = PlannedGroup(
        id="direct",
        kind="project-network",
        label="Routed fixed",
        network_id="fixed-net",
        network_name="fixed-net",
        subnet_ids=["fixed-subnet"],
        families=[4],
        floating_subnet_id="upstream-subnet",
        relationship=TopologyPolicy.DIRECT,
    )
    direct_runtime = RuntimeGroup(
        plan=direct_plan,
        network_id="fixed-net",
        network_name="fixed-net",
        subnet_ids=["fixed-subnet"],
        router_id="router",
        endpoints=[],
        source_nat_enabled=True,
        fips={},
    )
    with pytest.raises(SuiteError, match="prohibited"):
        builder.ensure_group_fips(direct_runtime)

    nested_plan = dataclasses.replace(
        direct_plan,
        id="nested",
        kind=NESTED_PUBLIC_PROJECT_NETWORK,
        label="Nested",
        metadata={},
    )
    nested_runtime = RuntimeGroup(
        plan=nested_plan,
        network_id="project-net",
        network_name="project-net",
        subnet_ids=["project-subnet"],
        router_id="router",
        endpoints=[],
        source_nat_enabled=True,
        fips={},
        metadata={},
    )
    with pytest.raises(SuiteError, match="prohibited"):
        validate_runtime_floating_ip_target(nested_runtime)
