from __future__ import annotations

import copy

import pytest

from neutron_flux.reporting_components.operator_context import contextual_results
from neutron_flux.result_context import context_lines, result_context
from neutron_flux.test_names import execution_name
from neutron_flux.test_names import test_name as human_test_name


def _result(**details):
    return {
        "display_name": "Provider subnet connectivity — IPv4 A to B TCP",
        "category": "same-subnet",
        "status": "PASS",
        "family": 4,
        "source": "Provider Public:A (192.0.2.10)",
        "destination": "Provider Public:B (192.0.2.11)",
        "details": {
            "protocol": "tcp",
            "phase": "intra",
            "source_compute_host": "hyper001",
            "destination_compute_host": "hyper002",
            **details,
        },
    }


def test_grouping_phase_never_claims_timing_or_same_host():
    result = _result(path={"stage": "cross-topology"})
    before = copy.deepcopy(result)
    context = result_context(result)
    assert context["timing"] == "Migration timing not recorded"
    assert "different compute hosts" in context["placement"]
    assert "hyper001" in context["placement"] and "hyper002" in context["placement"]
    assert result == before
    assert "cross-topology" not in execution_name(result)
    assert "intra" not in execution_name(result)


@pytest.mark.parametrize(
    "placement,origin,timing",
    [
        ("initial", "initial-boot", "Before migration"),
        ("opposite", "after-transition", "After placement transition"),
        ("opposite", None, "Migration timing not recorded"),
    ],
)
def test_pair_timing_requires_explicit_policy_and_transition_origin(
    placement, origin, timing
):
    context = result_context(
        _result(
            pair_placement_policy="initial-opposite-v1",
            pair_placement=placement,
            placement_origin=origin,
        )
    )
    assert context["timing"] == timing


def test_move_and_safety_checks_override_inherited_placement_timing():
    result = _result(
        pair_placement_policy="initial-opposite-v1",
        pair_placement="initial",
        transitions=[
            {
                "source_host": "hyper002",
                "destination_host": "hyper001",
                "confirmed": True,
            }
        ],
    )
    result["category"] = "compute-placement"
    result["display_name"] = "Move one endpoint and verify intra-compute placement"
    assert result_context(result)["timing"] == "During migration"
    result["display_name"] = (
        "Verify fresh functional baseline before live migration submission 1"
    )
    result["details"]["pair_placement"] = "opposite"
    assert result_context(result)["timing"] == "Before migration"


def test_action_and_execution_time_are_independent():
    result = _result(
        operation="static-route-baseline",
        pair_placement="opposite",
        placement_origin="after-transition",
        pair_placement_policy="initial-opposite-v1",
    )
    result["category"] = "router-static-routing"
    result["expected"] = "blocked"
    context = result_context(result)
    assert context["timing"] == "After placement transition"
    assert context["action"] == "Before adding static routes"
    assert "ping receives no reply" in context["purpose"]


def test_blocked_check_only_describes_planned_action():
    result = _result(operation="fip-withdraw")
    result["status"] = "BLOCKED_BY_SETUP_ERROR"
    lines = context_lines(result)
    assert any("did not run" in line for line in lines)
    assert any(line.startswith("Planned condition:") for line in lines)
    assert not any(line.startswith("Condition:") for line in lines)
    assert "Did not run" in execution_name(result)


@pytest.mark.parametrize(
    "measurement,protocol",
    [
        ("tcp-throughput", "TCP"),
        ("udp", "UDP"),
        ("latency", "ICMP and TCP"),
        ("mtu-mss", "ICMP and TCP"),
        ("asymmetry", "ICMP, TCP and UDP"),
    ],
)
def test_measurement_codes_do_not_appear_as_protocols(measurement, protocol):
    result = _result(protocol="performance", measurement=measurement)
    result["category"] = "network-performance"
    context = result_context(result)
    assert context["protocol"] == protocol
    assert "PERFORMANCE" not in " ".join(context["lines"])


def test_floating_ip_mapping_keeps_fixed_and_test_address_distinct():
    result = _result(
        address_path={
            "source": {"fixed_ip": "192.0.2.10", "probe_address": "192.0.2.10"},
            "destination": {
                "fixed_ip": "10.0.0.2",
                "floating_ip": "192.0.2.20",
                "probe_address": "192.0.2.20",
                "floating_ip_status": "verified attached",
                "network_name": "Public",
            },
        }
    )
    result["category"] = "floating-ip"
    result["destination"] = "Private IPv4 translation through Public:A (192.0.2.20)"
    context = result_context(result)
    assert context["destination"]["fixed_ip"] == "10.0.0.2"
    assert context["destination"]["probe_address"] == "192.0.2.20"
    assert context["destination"]["network"] is None
    assert context["destination"]["external_network"] == "Public"
    assert "floating IP → private VM's fixed IP" in context["path"]


def test_self_hairpin_has_one_vm_and_retains_cycle_timing():
    result = _result(
        nat_path="self-hairpin",
        packet_path_placement="self",
        pair_placement="self",
        pair_placement_policy="initial-opposite-v1",
        topology_placement_context={
            "pair_placement": "initial",
            "compute_placement": "inter-compute",
        },
    )
    result["category"] = "floating-ip-peer"
    result["details"]["destination_compute_host"] = "hyper001"
    context = result_context(result)
    assert context["placement"] == "One VM on hyper001"
    assert context["timing"] == "Before migration"
    assert "the same VM" in context["path"]


def test_external_destination_is_an_external_address_without_flux_host():
    result = _result(operation="egress", target="1.1.1.1")
    result["category"] = "egress"
    result["destination"] = "1.1.1.1"
    result["details"].pop("destination_compute_host")
    context = result_context(result)
    assert context["destination"]["probe_address"] == "1.1.1.1"
    assert context["destination"]["fixed_ip"] is None
    assert "external destination" in context["placement"]


def test_service_port_is_part_of_human_traffic_context():
    lines = context_lines(_result(probe={"diagnostics": {"destination_port": 18080}}))
    assert "Traffic: TCP port 18080 over IPv4" in lines


def test_controller_setup_does_not_invent_packet_endpoints():
    result = {
        "category": "controller-bootstrap",
        "display_name": "Configure the OpenStack probe controller",
        "status": "PASS",
        "details": {
            "ports": [
                {"network_name": "Public", "fixed_ips": {"subnet-id": "192.0.2.10"}}
            ]
        },
    }
    lines = context_lines(result)
    assert not any(line.startswith(("Source:", "Destination:")) for line in lines)
    assert "Probe VM: fixed IP 192.0.2.10; provider network Public" in lines


def test_exact_planner_join_preserves_original_evidence_and_unknowns():
    result = _result()
    result["test_id"] = "PERFORMANCE-SAMPLE"
    result["details"]["path"] = {"source_spec_id": "EXACT-SPEC"}
    plan = {
        "tests": [
            {
                "id": "EXACT-SPEC",
                "operation": "security-restore",
                "metadata": {
                    "pair_placement_policy": "initial-opposite-v1",
                    "pair_placement": "opposite",
                    "placement_origin": "after-transition",
                },
            }
        ]
    }
    payload = {"results": [result], "plan": plan}
    original = copy.deepcopy(payload)
    contextual = contextual_results(payload)[0]
    context = result_context(contextual)
    assert context["timing"] == "After placement transition"
    assert context["action"] == "After removing the temporary TCP allow rule"
    assert payload == original
    assert contextual["details"] == result["details"]


def test_exact_transition_reference_identifies_the_moving_vm():
    transition = {
        "test_id": "MOVE",
        "category": "compute-placement",
        "display_name": "Move one endpoint",
        "status": "PASS",
        "details": {
            "transitions": [
                {
                    "server_id": "vm-b",
                    "source_host": "hyper002",
                    "destination_host": "hyper001",
                    "confirmed": True,
                }
            ]
        },
    }
    endpoint = _result(address_path={"source": {"server_id": "vm-b"}})
    aggregate = {
        "test_id": "SAMPLE",
        "category": "compute-placement",
        "status": "PASS",
        "display_name": "Migration placement",
        "details": {"transition_check_id": "MOVE"},
    }
    resource = {
        "id": "vm-b",
        "resource_type": "server",
        "name": "cloud-vm-b",
        "metadata": {"endpoint_side": "A"},
    }
    payload = {"results": [endpoint, transition, aggregate], "resources": [resource]}
    original = copy.deepcopy(payload)
    context = result_context(contextual_results(payload)[2])
    assert context["timing"] == "During migration"
    assert context["moves"][0]["label"] == "Public VM A"
    assert "hyper002 → hyper001" in " ".join(context["lines"])
    assert payload == original


def test_unlabelled_result_never_uses_machine_id_as_primary_title():
    assert (
        human_test_name({"test_id": "HQ-HYPER001-VERY-LONG-MACHINE-CODE"})
        == "Validation result"
    )


def test_route_action_matches_router_side_in_the_actual_probe_direction():
    result = _result(
        operation="static-route-withdraw",
        route_side="A",
        source_side="B",
        destination_side="A",
    )
    assert (
        result_context(result)["action"]
        == "After removing the static route on the destination network's router"
    )


def test_safety_aggregate_has_protocols_and_all_recorded_families():
    result = {
        "category": "compute-placement",
        "status": "PASS",
        "display_name": "Verify connectivity before migration",
        "details": {"protocols": ["icmp", "tcp", "udp"]},
        "reporting_context": {
            "supporting_paths": [_result(), {**_result(), "family": 6}]
        },
    }
    context = result_context(result)
    assert context["protocol"] == "ICMP, TCP and UDP"
    assert context["family"] == "IPv4 and IPv6"


def test_reverse_role_migration_keeps_path_mapping_and_both_host_snapshots():
    path = _result(
        nat_path="snat-to-floating-ip",
        address_path={
            "source": {
                "server_id": "moving",
                "fixed_ip": "10.0.0.2",
                "probe_address": "10.0.0.2",
            },
            "destination": {
                "server_id": "peer",
                "fixed_ip": "10.1.0.2",
                "floating_ip": "192.0.2.20",
                "probe_address": "192.0.2.20",
            },
        },
    )
    path["category"] = "floating-ip-peer"
    path["source"] = (
        "Private IPv4 translation through Public / source without floating IP:A (10.0.0.2)"
    )
    path["destination"] = (
        "Private IPv4 translation through Public / second router:A (192.0.2.20)"
    )
    transition = {
        "server_id": "moving",
        "source_host": "hyper001",
        "destination_host": "hyper002",
        "confirmed": True,
    }
    result = {
        "category": "compute-placement",
        "status": "PASS",
        "display_name": "Move one endpoint",
        "details": {"transitions": [transition]},
        "reporting_context": {"monitored_path": path},
    }
    context = result_context(result)
    text = " ".join(context["lines"])
    assert "router source NAT" in context["path"]
    assert all(value in text for value in ("10.0.0.2", "10.1.0.2", "192.0.2.20"))
    assert "Moving VM's role in this traffic test: traffic source" in text
    assert "VM placement before the move:" in text
    assert context["after_placement"] == "Both VMs on hyper002 (same compute host)"
    assert "Stationary peer's recorded compute host:" in text and "on hyper002" in text


def test_missing_moving_identity_does_not_choose_destination_or_derive_final_hosts():
    path = _result(
        address_path={
            "source": {"server_id": "source"},
            "destination": {"server_id": "destination"},
        }
    )
    result = {
        "category": "compute-placement",
        "status": "PASS",
        "display_name": "Move one endpoint",
        "details": {
            "transitions": [
                {
                    "source_host": "hyper001",
                    "destination_host": "hyper002",
                    "confirmed": True,
                }
            ]
        },
        "reporting_context": {"monitored_path": path},
    }
    context = result_context(result)
    assert "Moving VM's role in this traffic test: not recorded" in context["lines"]
    assert context["after_placement"] is None
    assert not any(line.startswith("Stationary peer") for line in context["lines"])


def test_execution_labels_distinguish_protocols_without_changing_identity():
    result = _result(nat_path="same-router")
    result["display_name"] = (
        "VM with floating IP to peer floating IP — same-router, A to B"
    )
    result["test_id"] = "EXACT-IDENTITY"
    other = copy.deepcopy(result)
    other["details"]["protocol"] = "udp"
    assert "TCP over IPv4" in execution_name(result)
    assert "UDP over IPv4" in execution_name(other)
    assert result["test_id"] == other["test_id"] == "EXACT-IDENTITY"
