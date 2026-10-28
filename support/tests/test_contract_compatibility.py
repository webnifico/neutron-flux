from __future__ import annotations

import base64
import dataclasses
import json
import pathlib
import re
import shlex
import xml.etree.ElementTree as ET
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.contract_assessment import with_contract_assessment
from neutron_flux.errors import SuiteError
from neutron_flux.guest_network import GuestNetworkVerifier
from neutron_flux.junit_report import build_junit
from neutron_flux.models import Plan, PlannedGroup
from neutron_flux.models import TestResult as FluxTestResult
from neutron_flux.models import TestSpec as FluxTestSpec
from neutron_flux.plan_contract import (
    _sha256,
    load_plan_contract,
    plan_dict,
    verify_plan_contract,
)
from neutron_flux.reporting_components.summary import SummaryRendererMixin
from neutron_flux.runtime.probes import ProbeRuntimeMixin
from support.tests._shared import completed


def _static_route_plan(*, legacy: bool) -> Plan:
    group_id = (
        "extra-route-pair-ipv4-pool"
        if legacy
        else "two-router-static-routing-ipv4-pool"
    )
    group = PlannedGroup(
        id=group_id,
        kind="extra-route-pair" if legacy else "two-router-static-routing",
        label=(
            "legacy extra-route pair"
            if legacy
            else "IPv4 two-router static-routing topology"
        ),
        network_id=None,
        network_name=None,
        subnet_ids=[],
        families=[4],
        pool_id="pool",
        pool_name="project-pool",
        prefix_length=24,
        relationship="internal-router",
        metadata={
            "scenario": ("extra-route-pair" if legacy else "two-router-static-routing")
        },
    )
    spec = FluxTestSpec(
        id=(
            "EXTRA-ROUTE-ADD-4-extra-route-pair-ipv4-pool"
            if legacy
            else "STATIC-ROUTE-INSTALL-4-two-router-static-routing-ipv4-pool"
        ),
        category="router-extra-route" if legacy else "router-static-routing",
        operation="extra-route-add" if legacy else "static-route-install",
        family=4,
        expectation="reachable",
        expectation_reason=(
            "legacy extra route should work"
            if legacy
            else "router static routes should work"
        ),
        authoritative=True,
        dependencies=[group_id],
        source_group_id=group_id,
        destination_group_id=group_id,
        source_side="A",
        destination_side="B",
        source_subnet_id="side-A",
        destination_subnet_id="side-B",
        protocol="icmp",
        phase="intra",
        display_name=(
            "Legacy extra-route add" if legacy else "Install router static routes"
        ),
        scenario=(
            "Routing with extra routes"
            if legacy
            else "Routing with router static routes"
        ),
    )
    estimates = {
        "peak_instances": 2,
        ("fabric_scale_pairs" if legacy else "concurrent_load_pairs"): 2,
        (
            "fabric_scale_endpoint_boots"
            if legacy
            else "concurrent_load_endpoint_boots"
        ): 4,
    }
    return Plan([], [group], estimates, [], tests=[spec])


def _contract(plan: Plan, *, legacy: bool) -> dict:
    configuration = {
        "image": "image",
        "flavor": "flavor",
        ("fabric" if legacy else "concurrent_load"): {
            "enabled": True,
            "pairs": [1, 2],
            "runs": 2,
            "duration_seconds": 10,
        },
    }
    inventory = {
        "cloud": "cloud",
        "project_id": "project",
        "networks": [],
        "hosts": [],
    }
    payload = dataclasses.asdict(plan)
    signed = {
        "configuration": configuration,
        "inventory": inventory,
        "plan": payload,
    }
    return {
        "schema_version": 1,
        "kind": "neutron-flux-approved-plan",
        "fingerprint": _sha256(signed),
        **signed,
    }


def test_legacy_plan_fingerprint_is_validated_before_semantic_aliases(
    tmp_path,
):
    legacy = _contract(_static_route_plan(legacy=True), legacy=True)
    path = tmp_path / "mtu-plan.json"
    path.write_text(json.dumps(legacy), encoding="utf-8")

    loaded, runtime_plan = load_plan_contract(path)

    assert loaded["fingerprint"] == legacy["fingerprint"]
    assert runtime_plan.tenant_groups[0].id.startswith("extra-route-pair")
    assert runtime_plan.tests[0].operation == "extra-route-add"


def test_known_vocabulary_changes_do_not_create_false_plan_drift():
    legacy = _contract(_static_route_plan(legacy=True), legacy=True)
    canonical = _contract(_static_route_plan(legacy=False), legacy=False)

    assert verify_plan_contract(legacy, canonical) == []

    canonical["plan"]["tests"][0]["protocol"] = "udp"
    changes = verify_plan_contract(legacy, canonical)
    assert [item["path"] for item in changes] == ["plan.tests"]


def test_result_assessment_separates_contract_and_mechanism():
    details = with_contract_assessment(
        {
            "mechanism_assessment": {
                "name": "pmtud",
                "status": "worked",
            }
        },
        status="FAIL",
        expected="1500-byte boundary",
        observed="1424-byte boundary",
        authoritative=True,
    )

    assert details["assessment"]["contract"]["outcome"] == "violated"
    assert details["assessment"]["mechanism"]["status"] == "worked"
    assert details["assessment"]["authority"]["authoritative"] is True
    assert details["assessment"]["execution"]["status"] == "completed"
    assert details["assessment"]["path_health"]["status"] == "contract-violated"


def test_execution_error_does_not_become_a_contract_violation():
    details = with_contract_assessment(
        {},
        status="ERROR",
        expected="reachable",
        observed="probe could not execute",
        authoritative=True,
    )

    assessment = details["assessment"]
    assert assessment["contract"]["outcome"] == "not-evaluated"
    assert assessment["execution"]["status"] == "execution-error"
    assert assessment["path_health"]["status"] == "not-assessed-execution-error"


def test_contradictory_supplied_assessment_is_rejected():
    with pytest.raises(ValueError, match="contradicts"):
        with_contract_assessment(
            {
                "assessment": {
                    "contract": {
                        "expected": "reachable",
                        "observed": "blocked",
                        "outcome": "met",
                    }
                }
            },
            status="FAIL",
            expected="reachable",
            observed="blocked",
            authoritative=True,
        )


def test_release_has_no_retained_cloud_recording_subsystem():
    root = pathlib.Path(__file__).resolve().parents[2]
    assert not (root / "neutron_flux" / "inventory_recording.py").exists()
    assert not (root / "support" / "recordings").exists() or not any(
        (root / "support" / "recordings").iterdir()
    )


def test_serialized_plan_uses_project_network_vocabulary():
    plan = _static_route_plan(legacy=False)
    plan.estimated["tenant_topology_generations"] = 2

    payload = plan_dict(plan)

    assert "project_network_groups" in payload
    assert "tenant_groups" not in payload
    assert payload["estimated"]["project_network_topology_generations"] == 2
    assert "tenant_topology_generations" not in payload["estimated"]


def test_plan_rejects_mixed_canonical_and_legacy_aliases(tmp_path):
    contract = _contract(_static_route_plan(legacy=False), legacy=False)
    contract["plan"]["project_network_groups"] = list(contract["plan"]["tenant_groups"])
    signed = {
        "configuration": contract["configuration"],
        "inventory": contract["inventory"],
        "plan": contract["plan"],
    }
    contract["fingerprint"] = _sha256(signed)
    path = tmp_path / "ambiguous-plan.json"
    path.write_text(json.dumps(contract), encoding="utf-8")

    with pytest.raises(SuiteError, match="mixed aliases are ambiguous"):
        load_plan_contract(path)

    with pytest.raises(SuiteError, match="mixed aliases are ambiguous"):
        verify_plan_contract(contract, contract)

    canonical = _contract(_static_route_plan(legacy=False), legacy=False)
    canonical["plan"]["estimated"]["fabric_scale_pairs"] = 2
    signed["configuration"] = canonical["configuration"]
    signed["inventory"] = canonical["inventory"]
    signed["plan"] = canonical["plan"]
    canonical["fingerprint"] = _sha256(signed)
    path.write_text(json.dumps(canonical), encoding="utf-8")

    with pytest.raises(SuiteError, match="mixed aliases are ambiguous"):
        load_plan_contract(path)


def test_missing_neutron_mtu_is_not_enforced_as_1500():
    captured: list[str] = []
    verifier = GuestNetworkVerifier(
        lambda _subnet: {
            "cidr": "192.0.2.0/24",
            "gateway": "192.0.2.1",
            "mtu": None,
            "mtu_authoritative": False,
            "mtu_authority": "Neutron network.mtu unavailable",
            "mtu_source": "openstack network show",
            "mtu_resource_id": "network-id",
        }
    )
    verifier.verify(
        label="project-endpoint",
        mac_address="fa:16:3e:00:00:01",
        fixed_ips={"subnet-id": "192.0.2.10"},
        executor=lambda command: (
            captured.append(command)
            or completed(stdout='{"errors": [], "mtu_contracts": []}')
        ),
    )

    script = shlex.split(captured[0])[2]
    match = re.search(r"base64\.b64decode\('([^']+)'\)", script)
    assert match is not None
    entries = json.loads(base64.b64decode(match.group(1)))
    assert entries[0]["mtu"] is None
    assert entries[0]["mtu_authoritative"] is False
    assert "entry.get('mtu') or 1500" not in script
    assert re.search(
        r"mtu_authoritative\s+and expected_mtu is not None",
        script,
    )


def test_runtime_subnet_preserves_missing_mtu_provenance(
    discovery_fixture,
):
    missing_network = dataclasses.replace(
        discovery_fixture.networks[0],
        mtu=None,
    )
    discovery = dataclasses.replace(
        discovery_fixture,
        networks=[missing_network, *discovery_fixture.networks[1:]],
    )
    harness = SimpleNamespace(discovery=discovery, osc=mock.Mock())

    value = ProbeRuntimeMixin._runtime_subnet(harness, "s1v4")

    assert value["mtu"] is None
    assert value["mtu_authoritative"] is False
    assert value["mtu_authority"] == "Neutron network.mtu unavailable"
    assert value["mtu_source"] == "discovery inventory"
    assert value["mtu_resource_id"] == "n1"


def test_legacy_result_wording_is_normalized_in_text_and_junit():
    result = FluxTestResult(
        test_id="LEGACY-RESULT",
        category="router-extra-route",
        status="FAIL",
        family=4,
        source="tenant network A",
        destination="tenant network B",
        message="tenant traffic failed after the extra route was installed",
        started_at="2026-07-26T12:00:00Z",
        duration_ms=10,
        details={},
        expected="reachable",
        observed="blocked",
        authoritative=True,
        display_name="Two-router extra-route connectivity",
        scenario="Tenant-to-tenant routing through one Neutron router",
    )

    summary = "\n".join(SummaryRendererMixin._summary_result_lines(result)).lower()
    assert "tenant" not in summary
    assert "extra-route" not in summary
    assert "project" in summary
    assert "static-route" in summary

    payload = {
        "run": {"run_id": "legacy-import", "final_status": "FAIL"},
        "results": [dataclasses.asdict(result)],
        "cleanup": {"complete": True},
    }
    root = ET.fromstring(build_junit(payload, include_evidence=False))
    xml = ET.tostring(root, encoding="unicode").lower()
    assert "tenant" not in xml
    assert "extra-route" not in xml
    assert "router-static-routing" in xml
    assert "project" in xml
