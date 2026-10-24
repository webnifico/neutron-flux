from __future__ import annotations

import copy

import pytest

from neutron_flux.operator_explanations import explain_result, operator_overview
from neutron_flux.result_context import normalize_topology_label, result_context

from ._shared import build_plan


@pytest.mark.parametrize("network", ["Public", "Provider Two", "Tenant provider"])
def test_provider_aliases_keep_the_actual_network_name(network):
    result = {
        "category": "same-subnet",
        "status": "PASS",
        "family": 4,
        "source": f"Provider {network}:A (192.0.2.10)",
        "destination": f"Provider {network}:B (192.0.2.11)",
        "details": {"protocol": "tcp"},
    }
    original = copy.deepcopy(result)
    context = result_context(result)
    assert context["source"]["label"] == f"{network} VM A"
    assert context["destination"]["label"] == f"{network} VM B"
    assert context["source"]["network"] == network
    assert context["destination"]["network"] == network
    assert result == original


def test_pre_migration_baseline_does_not_claim_every_protocol_for_egress():
    result = {
        "category": "compute-placement",
        "status": "PASS",
        "expected": "fresh-functional-matrix",
        "observed": "fresh-functional-matrix",
        "display_name": "Verify fresh functional baseline before live migration",
        "details": {
            "protocols": ["icmp", "tcp", "udp"],
            "supporting_paths": [
                {"category": "same-subnet", "protocol": "tcp", "family": 4},
                {"category": "egress", "protocol": "icmp", "family": 4},
            ],
        },
    }
    original = copy.deepcopy(result)
    story = explain_result(result)
    assert (
        "VM-to-VM protocol checks and applicable external egress" in story["expected"]
    )
    assert "every selected path" not in story["observed"]
    assert "applicable external egress paths" in story["context"]["purpose"]
    assert result == original


def _migration_result(second_lost=0):
    assessment = {
        "migration_outcomes": {
            "vm_placement": "PASS",
            "migration_completion": "PASS",
            "tcp_session": "PASS",
            "traffic_recovery": "PASS",
            "interruption_tolerance": "PASS",
        },
        "icmp": {"lost": 0, "samples": 20},
        "udp": {"response": {"loss_pct": 0}},
    }
    other = copy.deepcopy(assessment)
    other["icmp"]["lost"] = second_lost
    return {
        "category": "compute-placement",
        "status": "PASS",
        "expected": "placement-achieved",
        "details": {
            "continuity": assessment,
            "transitions": [{"continuity_assessment": other}],
        },
    }


def test_identical_migration_descriptions_are_rendered_once_without_merging_evidence():
    result = _migration_result()
    original = copy.deepcopy(result)
    story = explain_result(result)
    assert story["observed"].lower().count("the vm reached the required host") == 1
    assert "Assessment 1:" not in story["observed"]
    assert result == original


def test_distinct_migration_descriptions_remain_visible():
    story = explain_result(_migration_result(second_lost=1))
    assert "Assessment 1:" in story["observed"]
    assert "Assessment 2:" in story["observed"]
    assert "0 of 20" in story["observed"]
    assert "1 of 20" in story["observed"]


def test_distinct_migration_endpoints_are_not_hidden_when_outcomes_agree():
    result = _migration_result()
    result["details"]["continuity"]["moving_server_id"] = "vm-a"
    result["details"]["transitions"][0]["continuity_assessment"]["moving_server_id"] = (
        "vm-b"
    )
    original = copy.deepcopy(result)
    story = explain_result(result)
    assert "Assessment 1:" in story["observed"]
    assert "Assessment 2:" in story["observed"]
    assert result == original


def test_historical_self_hairpin_expectation_describes_one_vm_and_mapping():
    result = {
        "category": "floating-ip-peer",
        "status": "PASS",
        "expected": "reachable",
        "observed": "reachable",
        "source": "Private IPv4 translation through Public:A (10.0.0.2)",
        "destination": "Private IPv4 translation through Public:A (192.0.2.2)",
        "details": {
            "protocol": "icmp",
            "nat_path": "self-hairpin",
            "expectation_reason": "Flux owns and verifies both private endpoints and floating-IP mappings on the same external subnet",
        },
    }
    original = copy.deepcopy(result)
    story = explain_result(result)
    assert "the VM and its own floating-IP mapping" in story["expected"]
    assert "both private endpoints" not in story["expected"]
    assert result == original


@pytest.mark.parametrize("side", [":A", ":B", " A", " B"])
@pytest.mark.parametrize("address", ["", " (fd7a:6e66:6c75::16d)"])
def test_historical_ipv6_label_keeps_endpoint_side_and_address(side, address):
    old = (
        "IPv6 project-network connectivity with routing metadata unassigned "
        f"through Provider Two{side}{address}"
    )
    assert normalize_topology_label(old) == (
        "Private IPv6 same-subnet connectivity; external routing not tested "
        "— selected external network Provider Two"
        f"{side}{address}"
    )


@pytest.mark.parametrize(
    "suffix",
    [
        " / HQ-COMPUTE-C-C1-INITIAL — IPv6",
        " — IPv6",
        ":B moved from host-a to host-b.",
        " B moved from host-a to host-b.",
        " was requested to move from host-a to host-b.",
    ],
)
def test_historical_ipv6_label_preserves_all_following_facts(suffix):
    old = (
        "IPv6 project-network connectivity with routing metadata unassigned "
        f"through Public{suffix}"
    )
    normalized = normalize_topology_label(old)
    assert "routing metadata unassigned" not in normalized
    assert normalized.endswith(f"selected external network Public{suffix}")


def test_historical_ipv6_label_explains_internal_scope_without_metadata_service_claim():
    old = "IPv6 project-network connectivity with routing metadata unassigned through Public:B"
    assert normalize_topology_label(old) == (
        "Private IPv6 same-subnet connectivity; external routing not tested "
        "— selected external network Public:B"
    )
    result = {
        "category": "compute-placement",
        "status": "PASS",
        "expected": "live-migration-complete",
        "source": old,
        "details": {
            "endpoint": old,
            "source_host": "host-a",
            "destination_host": "host-b",
            "confirmed": True,
        },
    }
    original = copy.deepcopy(result)
    story = explain_result(result)
    assert "external routing not tested" in story["observed"]
    assert "routing metadata unassigned" not in story["observed"]
    assert "routing metadata unassigned" not in story["location"][0]["value"]
    assert result == original


def test_new_plan_has_truthful_ipv6_control_and_single_vm_hairpin_wording(
    config_factory, discovery_fixture, tmp_path
):
    discovery_fixture.pools = []
    plan = build_plan(
        config_factory(performance_enabled=False), discovery_fixture, tmp_path
    )
    controls = [
        group
        for group in plan.groups
        if group.kind == "routing-unassigned-project-network" and group.families == [6]
    ]
    assert controls
    assert all("external routing not tested" in group.label for group in controls)
    hairpins = [
        spec for spec in plan.tests if spec.metadata.get("nat_path") == "self-hairpin"
    ]
    assert hairpins
    assert all(
        "the VM and its own floating-IP mapping" in spec.expectation_reason
        for spec in hairpins
    )


def _calibrated_udp():
    return {
        "test_id": "UDP-MIXED",
        "category": "network-performance",
        "status": "PASS",
        "details": {
            "measurement": "udp",
            "health": "warning",
            "warning_reasons": ["UDP packets arrived out of order above tolerance"],
            "metrics": {
                "forward": [
                    {
                        "packet_size": 128,
                        "configured_rate_mbps": 10,
                        "offered_mbps": 10,
                        "endpoint_limited": True,
                        "endpoint_limit_reason": "receiver-overload",
                    },
                    {
                        "packet_size": 128,
                        "configured_rate_mbps": 10,
                        "offered_mbps": 5,
                        "endpoint_limited": False,
                        "loss_pct": 0,
                    },
                ]
            },
        },
    }


def test_udp_calibration_and_ordering_advisory_share_the_same_logical_check():
    result = _calibrated_udp()
    original = copy.deepcopy(result)
    story = explain_result(result)
    assert story["kind"] == "advisory"
    assert story["udp_rate_calibrated"] is True
    overview = operator_overview({"results": [result]})
    groups = {group["kind"]: group for group in overview["groups"]}
    assert set(groups) == {"advisory", "measurement-rate-limited"}
    assert all(group["result_ids"] == ["UDP-MIXED"] for group in groups.values())
    assert all(group["count"] == 1 for group in groups.values())
    assert "overlap" in overview["note"]
    assert result == original


def test_endpoint_limited_udp_without_usable_lower_retry_is_not_a_calibration():
    result = _calibrated_udp()
    result["details"]["health"] = "good"
    result["details"]["warning_reasons"] = []
    result["details"]["metrics"]["forward"].pop()
    story = explain_result(result)
    assert story["kind"] == "measurement-rate-limited"
    assert story["udp_rate_calibrated"] is False
    overview = operator_overview({"results": [result]})
    assert [group["kind"] for group in overview["groups"]] == [
        "measurement-endpoint-limited"
    ]
