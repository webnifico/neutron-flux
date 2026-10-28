from __future__ import annotations

import copy
import dataclasses
from unittest import mock

import pytest

from neutron_flux.errors import SuiteError
from neutron_flux.models import ProbeResult
from neutron_flux.models import TestSpec as Spec
from neutron_flux.offline_reports import _apply_current_offline_interpretations
from neutron_flux.policy import PolicyEvaluator, TopologyPolicy
from neutron_flux.resources import ResourceBuilder

from ._shared import build_plan
from .test_engine_handlers import _engine, _spec


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("source_is_project", [False, True])
@pytest.mark.parametrize(
    "relationship",
    [
        TopologyPolicy.DIRECT,
        TopologyPolicy.ISOLATED,
        TopologyPolicy.UNASSIGNED,
    ],
)
def test_routing_truth_table(family, source_is_project, relationship):
    decision = TopologyPolicy.project_expectation(
        relationship,
        family,
        source_is_project=source_is_project,
    )
    if relationship == TopologyPolicy.DIRECT or (family == 4 and source_is_project):
        expected = "reachable"
    elif relationship == TopologyPolicy.ISOLATED:
        expected = "blocked"
    else:
        expected = "observation"
    assert decision.expectation == expected
    assert decision.authoritative is (expected != "observation")
    spec = Spec(
        "test",
        "routing",
        "probe",
        family,
        decision.expectation,
        decision.reason,
        decision.authoritative,
        [],
    )
    for outcome in ["reachable", "blocked"]:
        probe = ProbeResult(outcome, outcome == "reachable", 1, 1)
        result = PolicyEvaluator().evaluate(spec, probe)
        assert result.status == (
            "UNVERIFIED"
            if expected == "observation"
            else "PASS"
            if expected == outcome
            else "FAIL"
        )


def _staging_discovery(discovery):
    """SAMPLE run shape: dual-stack/IPv6/IPv4 providers, IPv4 pool, no scopes outside."""
    discovery.pools = [pool for pool in discovery.pools if pool.id == "tp4"]
    for subnet in discovery.subnets:
        subnet.address_scope_id = None
        subnet.subnetpool_id = None
    return discovery


@pytest.mark.parametrize("targets_configured", [False, True])
def test_run_regression_retains_internal_ipv6_and_ipv4_translation(
    config_factory,
    discovery_fixture,
    tmp_path,
    targets_configured,
):
    plan = build_plan(
        config_factory(
            performance_enabled=False,
            ipv6_targets=["2606:4700:4700::1111"],
            ipv6_targets_configured=targets_configured,
        ),
        _staging_discovery(discovery_fixture),
        tmp_path,
    )
    control = next(group for group in plan.tenant_groups if group.families == [6])
    assert control.synthetic_cidr.startswith("fd")
    assert not control.pool_id
    local = [spec for spec in plan.tests if spec.source_group_id == control.id]
    assert local and all(spec.destination_group_id == control.id for spec in local)
    assert all(spec.authoritative and spec.expectation == "reachable" for spec in local)
    assert {spec.protocol for spec in local} == {"icmp", "tcp", "udp"}
    assert any("generated private IPv6" in item["reason"] for item in plan.skipped)
    assert len([spec for spec in plan.tests if spec.operation == "fip-baseline"]) == 6
    assert (
        len(
            [
                spec
                for spec in plan.tests
                if spec.operation == "fip-egress-source-address"
            ]
        )
        == 2
    )
    assert plan.estimated["performance_result_rows"] == 0
    assert not any(
        spec.family == 6 and spec.category == "project-provider-connectivity"
        for spec in plan.tests
    )
    ipv6_egress = [
        spec for spec in plan.tests if spec.operation == "egress" and spec.family == 6
    ]
    ordinary = [s for s in ipv6_egress if not s.metadata.get("server_start_recovery")]
    recovery = [s for s in ipv6_egress if s.metadata.get("server_start_recovery")]
    assert len(ordinary) == len(recovery) == 1
    assert {s.source_group_id for s in ipv6_egress} <= {
        group.id for group in plan.provider_groups
    }
    assert all(s.authoritative and s.expectation == "reachable" for s in ipv6_egress)
    assert all(s.source_side == "B" for s in ipv6_egress)
    assert recovery[0].requires == [ordinary[0].id]
    assert recovery[0].requires_pass == [
        next(
            s.id
            for s in plan.tests
            if s.operation == "server-start"
            and s.family == 6
            and s.destination_group_id == ordinary[0].source_group_id
        )
    ]
    ipv4_sources = {
        spec.source_group_id
        for spec in plan.tests
        if spec.operation == "egress" and spec.family == 4
    }
    assert len(ipv4_sources) == 2
    assert any(
        group.id in ipv4_sources
        and group.metadata.get("source_nat_mode") == "cloud-default"
        for group in plan.tenant_groups
    )


@pytest.mark.parametrize("omission_recorded", [False, True])
def test_egress_selects_eligible_ipv6_group_after_internal_only_control(
    config_factory, discovery_fixture, tmp_path, omission_recorded
):
    from neutron_flux.log import Logger
    from neutron_flux.planning import Planner

    config = config_factory(ipv6_targets=["2606:4700:4700::1111"])
    plan = build_plan(config, discovery_fixture, tmp_path)
    eligible = next(
        group
        for group in plan.tenant_groups
        if group.families == [6] and group.relationship == TopologyPolicy.DIRECT
    )
    control = next(
        group
        for group in build_plan(
            config, _staging_discovery(copy.deepcopy(discovery_fixture)), tmp_path
        ).tenant_groups
        if group.families == [6]
    )
    if not omission_recorded:
        control.metadata.pop("external_checks_omitted_reason")
    planner = Planner(config, discovery_fixture, Logger(tmp_path / "egress.log"))
    tests = []
    planner._append_egress_tests(tests, plan.provider_groups, [control, eligible])
    ipv6_sources = {spec.source_group_id for spec in tests if spec.family == 6}
    assert eligible.id in ipv6_sources
    assert control.id not in ipv6_sources
    assert len(ipv6_sources) == 2


def _contract(source, destination, family=6, protocol="tcp", expectation="reachable"):
    return dict(
        source=source,
        destination=destination,
        family=family,
        protocol=protocol,
        expectation=expectation,
        authoritative=expectation != "observation",
        reason="operator-declared test path",
        provenance="test-config.yml",
    )


def test_explicit_private_ipv6_route_is_directional_and_protocol_specific(
    config_factory,
    discovery_fixture,
    tmp_path,
):
    discovery = _staging_discovery(discovery_fixture)
    plan = build_plan(config_factory(), discovery, tmp_path)
    control = next(group for group in plan.tenant_groups if group.families == [6])
    config = config_factory(
        routing_contracts=[_contract(control.id, "Public1", protocol="udp")]
    )
    plan = build_plan(config, discovery, tmp_path)
    external = [
        spec
        for spec in plan.tests
        if spec.family == 6 and spec.category == "project-provider-connectivity"
    ]
    assert len(external) == 1
    assert external[0].protocol == "udp"
    assert external[0].source_group_id == control.id
    assert external[0].authoritative
    assert (
        external[0].metadata["routing_policy"]["basis"] == "operator-routing-contract"
    )


def test_provider_contract_cannot_leak_to_project_groups(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(
        config_factory(routing_contracts=[_contract("Public1", "Public3", family=4)]),
        discovery_fixture,
        tmp_path,
    )
    contracted = [
        spec for spec in plan.tests if spec.metadata.get("routing_contract_configured")
    ]
    assert len(contracted) == 1
    assert contracted[0].category == "provider-network-connectivity"
    other = [
        spec
        for spec in plan.tests
        if spec.category == "provider-network-connectivity" and spec not in contracted
    ]
    assert all(spec.expectation == "reachable" and spec.authoritative for spec in other)


def test_alias_conflicts_rejected(config_factory, discovery_fixture, tmp_path):
    config = config_factory(
        routing_contracts=[
            _contract("Public1", "Public3", family=4),
            _contract("n1", "n3", family=4, expectation="blocked"),
        ]
    )
    with pytest.raises(SuiteError, match="Ambiguous routing contracts"):
        build_plan(config, discovery_fixture, tmp_path)


@pytest.mark.parametrize("snat", [False, None, True])
def test_unscoped_ipv4_runtime_snat_precondition(config_factory, snat):
    engine, _, _, groups, records = _engine(config_factory)
    groups["source"].source_nat_enabled = snat
    spec = _spec("probe", category="project-provider-connectivity", protocol="icmp")
    spec.metadata["routing_policy"] = TopologyPolicy.project_expectation(
        TopologyPolicy.UNASSIGNED,
        4,
        source_is_project=True,
    ).metadata()
    engine._run_endpoint_probe(spec)
    assert spec.authoritative is (snat is True)
    assert spec.expectation == ("reachable" if snat is True else "observation")
    assert records


@pytest.mark.parametrize("reachable", [False, True])
def test_controlled_fip_verdict_ignores_runner_reachability(config_factory, reachable):
    from ._evidence import configure_translation_target

    engine, _, target, groups, records = _engine(config_factory)
    groups["target"].fips[target.label] = {"id": "fip", "address": "192.0.2.99"}
    configure_translation_target(engine, groups["target"], target)
    engine.builder.inspect_endpoint_route = mock.Mock(
        return_value={"returncode": 0, "via_gateway": False}
    )
    engine.probes.runner_fip.run.return_value = (
        ProbeResult("blocked", False, 1, 1),
        True,
    )
    engine.probes.tcp.endpoint_peer_identity.return_value = ProbeResult(
        "reachable" if reachable else "blocked",
        reachable,
        1,
        1,
        diagnostics={
            "observer_probe_id": target.server_id,
            "observer_instance_id": "process",
            "observer_local_ip": "192.0.2.20",
            "observed_peer_ip": "192.0.2.10",
        },
    )
    spec = _spec("fip-baseline", category="floating-ip")
    spec.metadata.update(
        observer_path_contract="same-provider-subnet",
        floating_ip_subnet_id="subnet",
        target_external_cidr="192.0.2.0/24",
    )
    engine._run_fip_baseline(spec)
    probe = records[-1][1]
    assert PolicyEvaluator().evaluate(spec, probe).status == (
        "PASS" if reachable else "FAIL"
    )
    assert probe.diagnostics["external_ingress_observation"]["outcome"] == "blocked"
    assert probe.diagnostics["claim_boundary"] == "local floating-IP translation"
    assert engine.lifecycle["fip:target"]["runner"] is False


def test_ula_pool_can_supply_explicit_internal_routing(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    internal = [
        spec
        for spec in plan.tests
        if spec.family == 6 and spec.category == "project-network-routing"
    ]
    assert internal and all(spec.expectation == "reachable" for spec in internal)
    # Global/private address classification does not alter an explicit scope/router contract.
    direct = [
        spec
        for spec in plan.tests
        if spec.family == 6
        and spec.metadata.get("routing_relationship") == TopologyPolicy.DIRECT
    ]
    assert direct and all(spec.authoritative for spec in direct)


def test_unknown_paths_never_become_performance_candidates(
    config_factory, discovery_fixture, tmp_path
):
    from neutron_flux.planner_components.estimates import performance_estimate

    config = config_factory(performance_enabled=True)
    plan = build_plan(config, discovery_fixture, tmp_path)
    unknown = [spec for spec in plan.tests if spec.expectation == "observation"]
    assert not unknown
    assert any(
        "No declared routing expectation" in item["reason"] for item in plan.skipped
    )
    unknown = [
        dataclasses.replace(
            next(s for s in plan.tests if s.operation == "probe"),
            expectation="observation",
            authoritative=False,
        )
    ]
    assert performance_estimate(config, unknown)["performance_paths_selected"] == 0
    # Even fabricated successful observations cannot change the planned authority.
    for spec in unknown:
        result = PolicyEvaluator().evaluate(
            dataclasses.replace(spec), ProbeResult("reachable", True, 1, 1)
        )
        assert result.status == "UNVERIFIED"


def test_missing_snat_metadata_is_unknown():
    assert (
        ResourceBuilder._gateway_info({"network_id": "external"})["enable_snat"] is None
    )
    assert ResourceBuilder._gateway_info({"enable_snat": False})["enable_snat"] is False


def test_execution_error_is_not_hidden_by_missing_routing_authority():
    spec = Spec(
        "unknown",
        "routing",
        "probe",
        4,
        "observation",
        "unknown",
        False,
        [],
        metadata={"authority_required": True},
    )
    assert (
        PolicyEvaluator().evaluate(spec, ProbeResult("error", False, 1, 1)).status
        == "ERROR"
    )


def test_contract_to_unplanned_group_pair_is_rejected(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    groups = [
        group
        for group in plan.tenant_groups
        if group.kind == "project-network" and group.families == [4]
    ]
    config = config_factory(
        routing_contracts=[_contract(groups[0].id, groups[1].id, family=4)]
    )
    with pytest.raises(SuiteError, match="no applicable test"):
        build_plan(config, discovery_fixture, tmp_path)


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("expected", ["reachable", "blocked", "observation"])
def test_report_rebuild_preserves_current_routing_policy(family, expected):
    payload = {
        "results": [
            {
                "category": "project-provider-connectivity",
                "family": family,
                "status": "UNVERIFIED" if expected == "observation" else "FAIL",
                "expected": expected,
                "observed": "blocked",
                "details": {
                    "routing_relationship": TopologyPolicy.UNASSIGNED,
                    "routing_policy": {"basis": "operator-routing-contract"},
                },
            }
        ]
    }
    original = copy.deepcopy(payload)
    _apply_current_offline_interpretations(payload)
    assert payload == original


def test_report_rebuild_preserves_legacy_routing_requirement():
    payload = {
        "results": [
            {
                "test_id": "legacy",
                "category": "project-provider-connectivity",
                "family": 6,
                "status": "FAIL",
                "expected": "reachable",
                "observed": "blocked",
                "authoritative": True,
                "message": "historical declared requirement",
                "details": {"routing_relationship": TopologyPolicy.UNASSIGNED},
            }
        ]
    }
    _apply_current_offline_interpretations(payload)
    result = payload["results"][0]
    assert (result["status"], result["expected"], result["authoritative"]) == (
        "FAIL",
        "reachable",
        True,
    )
    assert (
        result["details"]["offline_interpretation"]["interpretation_status"]
        == "UNVERIFIED"
    )
