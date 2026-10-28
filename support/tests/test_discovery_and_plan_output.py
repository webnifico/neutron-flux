from __future__ import annotations

import dataclasses
from types import SimpleNamespace

from neutron_flux.discovery import Discoverer
from neutron_flux.log import Logger
from neutron_flux.models import PoolInfo
from neutron_flux.network_contract import (
    ONE_ROUTER_PROJECT_NETWORKS,
    PROJECT_NETWORK,
    TWO_ROUTER_STATIC_ROUTING,
)
from neutron_flux.planning import Planner
from neutron_flux.reporting import Reporter


def _selected_networks(discovery, *network_ids: str):
    selected = set(network_ids)
    subnets = [item for item in discovery.subnets if item.network_id in selected]
    return dataclasses.replace(
        discovery,
        networks=[item for item in discovery.networks if item.id in selected],
        subnets=subnets,
        occupied_cidrs=[item.cidr for item in subnets],
    )


def _poisoned_public3_discovery(discovery):
    """Reproduce a self-service pool also seen on a visible external subnet."""

    discovery.pools = [
        dataclasses.replace(
            item,
            provider_pool=True,
            raw={**item.raw, "is_default": True},
        )
        if item.id == "tp4"
        else item
        for item in discovery.pools
    ]
    discovery.subnets = [
        dataclasses.replace(item, address_scope_id=None, subnetpool_id=None)
        if item.id == "s3v4"
        else item
        for item in discovery.subnets
    ]
    return _selected_networks(discovery, "n3")


def test_pool_default_flags_are_explicit_and_string_safe(discovery_fixture):
    pool = discovery_fixture.pool("tp4")

    assert dataclasses.replace(pool, raw={"is_default": True}).shared_default is True
    assert dataclasses.replace(pool, raw={"is_default": "yes"}).is_default is True
    assert dataclasses.replace(pool, raw={"default": "1"}).is_default is True
    assert dataclasses.replace(pool, raw={"is_default": False}).shared_default is False
    assert dataclasses.replace(pool, raw={"is_default": "false"}).is_default is False


def test_shared_default_pool_remains_project_usable_when_seen_external(
    config_factory, discovery_fixture, tmp_path
):
    discovery = _poisoned_public3_discovery(discovery_fixture)
    plan = Planner(
        config_factory(external_networks=["Public3"]),
        discovery,
        Logger(tmp_path / "poisoned-plan.log"),
    ).build()

    project_groups = [
        item
        for item in plan.tenant_groups
        if item.pool_id == "tp4" and item.kind == PROJECT_NETWORK
    ]
    router_groups = [
        item
        for item in plan.tenant_groups
        if item.pool_id == "tp4"
        and item.kind in {ONE_ROUTER_PROJECT_NETWORKS, TWO_ROUTER_STATIC_ROUTING}
    ]

    assert len(project_groups) == 1
    assert project_groups[0].external_network_name == "Public3"
    assert project_groups[0].floating_subnet_id is None
    assert project_groups[0].metadata["subnet_pool_fixed_ip_only"] is True
    assert project_groups[0].metadata["source_nat_mode"] == "cloud-default"
    assert project_groups[0].metadata["source_nat_controlled_by_flux"] is False
    assert {item.kind for item in router_groups} == {
        ONE_ROUTER_PROJECT_NETWORKS,
        TWO_ROUTER_STATIC_ROUTING,
    }
    assert not any(item.id.startswith("NESTED-") for item in plan.tests)
    assert not any(
        item.operation in {"fip-baseline", "fip-withdraw", "fip-return"}
        and project_groups[0].id in item.dependencies
        for item in plan.tests
    )

    # A provider pool remains provider-only. It cannot enter project allocation.
    assert not any(
        item.pool_id == "pp4" and item.kind != "provider" for item in plan.tenant_groups
    )


def test_discovery_prints_pool_facts_without_inferred_role(
    discovery_fixture, tmp_path, capsys
):
    discovery = _poisoned_public3_discovery(discovery_fixture)
    discoverer = object.__new__(Discoverer)
    discoverer.osc = SimpleNamespace(backend_name="fixture")
    discoverer.logger = Logger(tmp_path / "discovery-summary.log")

    discoverer._print_summary(discovery)
    discoverer.logger.close()

    output = capsys.readouterr().out
    pool_line = next(
        line for line in output.splitlines() if "Subnet pool SelfServeIPv4" in line
    )
    assert "observed facts:" in pool_line
    assert "backs_visible_external_subnet=True" in pool_line
    assert "shared=True" in pool_line
    assert "default=True" in pool_line
    assert "role=" not in pool_line
    assert "eligibility=" not in pool_line


def test_plan_summary_describes_planning_not_execution(
    config_factory, discovery_fixture, tmp_path, capsys
):
    config = config_factory(
        action="plan",
        report_dir=tmp_path / "reports",
        html_report_enabled=False,
        junit_report_enabled=False,
    )
    plan = Planner(
        config, discovery_fixture, Logger(tmp_path / "summary-plan.log")
    ).build()
    capsys.readouterr()
    reporter = Reporter(config, "sample-plan-summary")
    reporter.plan = plan
    reporter.cleanup_summary.update({"attempted": False, "complete": True})

    assert reporter.finalize(0) == 0

    terminal = capsys.readouterr().out
    report = reporter.report_path.read_text(encoding="utf-8")
    for text in (terminal, report):
        assert "NEUTRON FLUX PLAN SUMMARY" in text
        assert "Plan status:     COMPLETE" in text
        assert "PLAN RESULT" in text
        assert "Plan created successfully." in text
        assert "No cloud resources were created and no tests were executed." in text
        assert "planning created no cloud resources" in text
        assert "NEUTRON FLUX FINAL SUMMARY" not in text
        assert "Final status:    PASS" not in text
        assert "Results recorded:" not in text
        assert "No checks were recorded" not in text


def test_pool_info_property_does_not_require_shared_for_default_fact():
    pool = PoolInfo(
        "pool",
        "pool",
        4,
        "scope",
        ["192.0.2.0/24"],
        27,
        24,
        30,
        False,
        None,
        True,
        {"is_default": True},
    )

    assert pool.is_default is True
    assert pool.shared_default is False
