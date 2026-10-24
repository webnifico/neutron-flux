from __future__ import annotations

import copy
import json
import xml.etree.ElementTree as ET
from typing import Any

import pytest

from neutron_flux.comparison import compare_payloads
from neutron_flux.junit_report import build_junit
from neutron_flux.offline_reports import regenerate
from neutron_flux.replay_plan import build_replay_plan
from neutron_flux.reporting import Reporter
from neutron_flux.reporting_components.dashboard_model import build_dashboard_model
from neutron_flux.result_contract import (
    build_path_signature,
    execution_state_for_status,
    normalize_result_record,
    packet_size_accounting,
    performance_expectation,
    performance_observation,
    semantic_result_key,
    typed_verdict_for_status,
    validate_result_contract,
)


def _result(
    test_id: str = "SAMPLE-CONNECTIVITY",
    *,
    status: str = "PASS",
    expected: str = "reachable",
    observed: str = "reachable",
    display_name: str = "Project path reachability",
    category: str = "network",
    measurement: str | None = None,
    authoritative: bool = True,
    source_host: str = "compute1",
    destination_host: str = "compute2",
    source_zone: str = "az1",
    destination_zone: str = "az1",
    placement: str = "different compute hosts",
    extra_details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    details: dict[str, Any] = {
        "source_compute_host": source_host,
        "destination_compute_host": destination_host,
        "source_availability_zone": source_zone,
        "destination_availability_zone": destination_zone,
        "compute_placement": placement,
        "availability_zone_placement": (
            "same-az" if source_zone == destination_zone else "cross-az"
        ),
        "execution_scope": source_zone,
        "operation": "probe",
        "protocol": "icmp",
        "path": {
            "source_label": "Project network A:A",
            "destination_label": "Project network A:B",
            "source_group_id": "project-network-a",
            "destination_group_id": "project-network-a",
            "source_compute_host": source_host,
            "destination_compute_host": destination_host,
            "source_availability_zone": source_zone,
            "destination_availability_zone": destination_zone,
            "placement": placement,
            "availability_scope": (
                "same-az" if source_zone == destination_zone else "cross-az"
            ),
            "execution_scope": source_zone,
            "operation": "probe",
            "protocol": "icmp",
        },
    }
    if measurement is not None:
        details.update(
            {
                "performance": True,
                "measurement": measurement,
                "health": "good",
                "thresholds_enforced": False,
            }
        )
    if extra_details:
        details.update(extra_details)
    return {
        "test_id": test_id,
        "display_name": display_name,
        "category": category,
        "scenario": "Project network connectivity",
        "status": status,
        "family": 4,
        "source": "az1/Project network A:A (192.0.2.10)",
        "destination": "az1/Project network A:B (192.0.2.11)",
        "message": "The selected project-network path produced terminal evidence.",
        "details": details,
        "expected": expected,
        "observed": observed,
        "authoritative": authoritative,
    }


def _payload(
    results: list[dict[str, Any]], run_id: str = "sample-run"
) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for item in results:
        status = str(item.get("status") or "UNKNOWN")
        counts[status] = counts.get(status, 0) + 1
    return {
        "schema_version": 1,
        "tool": "neutron-flux",
        "tool_version": "0.1.0 (prerelease)",
        "run": {
            "run_id": run_id,
            "action": "run",
            "started_at": "2026-07-27T00:00:00+00:00",
            "finished_at": "2026-07-27T00:01:00+00:00",
            "final_status": "FAIL"
            if any(item["status"] == "FAIL" for item in results)
            else "PASS",
        },
        "configuration": {
            "image": "debian-13",
            "flavor": "x1.nano",
            "storage": "host",
            "availability_zones": ["az1", "az2"],
            "zone_mode": "both",
            "external_networks": ["Public1", "Public3"],
        },
        "summary": {
            "counts": counts,
            "total_results": len(results),
            "performance": {},
            "categories": {},
        },
        "results": results,
        "cleanup": {"attempted": True, "complete": True},
        "events": [],
        "setup_failures": [],
        "error": None,
    }


@pytest.mark.parametrize(
    ("status", "verdict", "outcome", "execution"),
    [
        ("PASS", "PASS", "met", "completed"),
        ("FAIL", "FAIL", "violated", "completed"),
        (
            "UNVERIFIED",
            "UNVERIFIED",
            "unverified",
            "completed-with-insufficient-evidence",
        ),
        ("ERROR", "ERROR", "not-evaluated", "execution-error"),
        ("BLOCKED_BY_SETUP_ERROR", "BLOCKED", "blocked", "not-completed"),
        ("BLOCKED_BY_PREREQUISITE", "BLOCKED", "blocked", "not-completed"),
        ("SKIP", "INAPPLICABLE", "inapplicable", "not-applicable"),
        ("NOT_APPLICABLE", "INAPPLICABLE", "inapplicable", "not-applicable"),
        ("NOT_RUN_CANCELLED", "NOT_RUN", "not-run", "not-started"),
    ],
)
def test_status_maps_to_typed_verdict(
    status: str,
    verdict: str,
    outcome: str,
    execution: str,
):
    assert typed_verdict_for_status(status) == verdict
    normalized = normalize_result_record({"test_id": "SAMPLE", "status": status})
    assert normalized["contract"]["verdict"]["outcome"] == outcome
    assert execution_state_for_status(status) == execution


@pytest.mark.parametrize(
    ("details", "authoritative", "classification"),
    [
        ({"reason_authority": "live OpenStack network metadata"}, True, "openstack"),
        ({"performance": True, "measurement": "latency"}, True, "protocol"),
        ({"verdict_basis": "operator-threshold-policy"}, True, "operator"),
        ({}, False, "inferred"),
        ({"fallback_used": True}, False, "fallback"),
    ],
)
def test_authority_classification(
    details: dict[str, Any],
    authoritative: bool,
    classification: str,
):
    item = _result(authoritative=authoritative, extra_details=details)
    normalized = normalize_result_record(item)
    authority = normalized["contract"]["authority"]
    assert authority["classification"] == classification
    assert authority["authoritative"] is authoritative


@pytest.mark.parametrize(
    ("measurement", "expected", "observed"),
    [
        (
            "tcp-throughput",
            "tcp-throughput-profile-recorded",
            "tcp-throughput-profile-measured",
        ),
        (
            "latency",
            "idle-and-loaded-latency-profile-recorded",
            "idle-and-loaded-latency-measured",
        ),
        ("udp", "udp-quality-profile-recorded", "udp-quality-profile-measured"),
        ("mtu-mss", "packet-size-contract-assessed", "packet-size-contract-assessed"),
        ("asymmetry", "directional-balance-assessed", "directional-balance-measured"),
        (
            "concurrency",
            "concurrent-flow-scaling-assessed",
            "concurrent-flow-scaling-measured",
        ),
        (
            "repeatability",
            "throughput-repeatability-assessed",
            "throughput-repeatability-measured",
        ),
        (
            "fabric-scale",
            "concurrent-vm-pair-load-assessed",
            "concurrent-vm-pair-load-measured",
        ),
    ],
)
def test_performance_contract_codes_are_metric_specific(
    measurement: str,
    expected: str,
    observed: str,
):
    assert performance_expectation(measurement) == expected
    assert performance_observation(measurement, status="PASS") == observed
    assert expected != "measurement-complete"
    assert observed != "measured"


@pytest.mark.parametrize(
    ("case", "expected_change"),
    [
        ("contract", "contract changed"),
        ("observation", "observation changed"),
        ("verdict", "verdict regression"),
        ("coverage", "coverage loss"),
        ("mention", "mention drift"),
        ("not-comparable", "not comparable"),
        ("unchanged", "unchanged"),
    ],
)
def test_semantic_compare_classification(case: str, expected_change: str):
    baseline_result = _result()
    candidate_result = copy.deepcopy(baseline_result)
    if case == "contract":
        candidate_result["expected"] = "blocked"
    elif case == "observation":
        candidate_result["observed"] = "unreachable"
    elif case == "verdict":
        candidate_result["status"] = "FAIL"
        candidate_result["observed"] = "blocked"
    elif case == "coverage":
        candidate_result["status"] = "UNVERIFIED"
        candidate_result["observed"] = "dependency-unavailable"
    elif case == "mention":
        candidate_result["display_name"] = "Renamed project path reachability"
    elif case == "not-comparable":
        baseline = _payload([], "baseline")
        candidate = _payload([candidate_result], "candidate")
        assert (
            compare_payloads(baseline, candidate)["entries"][0]["change_type"]
            == expected_change
        )
        return
    comparison = compare_payloads(
        _payload([baseline_result], "baseline"),
        _payload([candidate_result], "candidate"),
    )
    assert len(comparison["entries"]) == 1
    assert comparison["entries"][0]["change_type"] == expected_change


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("scenario", "Renamed project-network connectivity"),
        ("message", "The path produced the same terminal evidence."),
    ],
)
def test_human_wording_changes_are_mention_drift(field: str, value: str):
    baseline = _result()
    candidate = copy.deepcopy(baseline)
    candidate[field] = value

    comparison = compare_payloads(
        _payload([baseline], "baseline"),
        _payload([candidate], "candidate"),
    )

    assert len(comparison["entries"]) == 1
    assert comparison["entries"][0]["change_type"] == "mention drift"


def test_unique_test_id_movement_matches_by_semantic_path():
    comparison = compare_payloads(
        _payload([_result("OLD-TEST-ID")], "baseline"),
        _payload([_result("NEW-TEST-ID")], "candidate"),
    )

    assert len(comparison["entries"]) == 1
    entry = comparison["entries"][0]
    assert entry["change_type"] == "mention drift"
    assert entry["baseline_test_id"] == "OLD-TEST-ID"
    assert entry["candidate_test_id"] == "NEW-TEST-ID"
    assert "test-ID change" in entry["comparison_reason"]


def test_test_id_movement_needs_more_than_category_and_family():
    baseline = _result("OLD-TEST-ID")
    candidate = _result("NEW-TEST-ID")
    for item in (baseline, candidate):
        item["source"] = None
        item["destination"] = None
        item["details"] = {}
        item["scenario"] = None

    comparison = compare_payloads(
        _payload([baseline], "baseline"),
        _payload([candidate], "candidate"),
    )

    assert len(comparison["entries"]) == 2
    assert {entry["change_type"] for entry in comparison["entries"]} == {
        "coverage loss",
        "not comparable",
    }


@pytest.mark.parametrize("case", ["ipv4-mtu", "ipv6-mtu", "udp", "direct"])
def test_packet_size_accounting_is_explicit(case: str):
    if case in {"ipv4-mtu", "ipv6-mtu"}:
        family = 4 if case == "ipv4-mtu" else 6
        mtu = 1450 if family == 4 else 1420
        accounting = packet_size_accounting(
            {
                "measurement": "mtu-mss",
                "metrics": {
                    "expected_mtu": mtu,
                    "forward": {
                        "discovered_mtu": mtu,
                        "fragmentation": {
                            "tested_packet_size": mtu + 100,
                            "capability": "observed",
                            "endpoint_observations": {
                                "destination_reassembly": {"directly_observed": True}
                            },
                        },
                        "expected_max_mss": mtu - (40 if family == 4 else 60),
                        "client_mss": mtu - (40 if family == 4 else 60),
                        "server_mss": mtu - (40 if family == 4 else 60),
                    },
                },
            },
            family=family,
        )
        forward = accounting["directions"]["forward"]
        assert forward["confirmed_no_fragment_ip_packet_bytes"] == mtu
        assert forward["fragmentation_test"]["reassembly_observed"] is True
        assert forward["tcp_mss"]["combined_tcp_ip_header_bytes"] == (
            40 if family == 4 else 60
        )
    elif case == "udp":
        accounting = packet_size_accounting(
            {
                "measurement": "udp",
                "metrics": {
                    "forward": [
                        {
                            "packet_size": 1200,
                            "offered_mbps": 100,
                            "achieved_mbps": 0,
                            "mbps": 98,
                        }
                    ]
                },
            },
            family=4,
        )
        row = accounting["directions"]["forward"][0]
        assert row["udp_application_datagram_bytes"] == 1200
        assert row["ip_packet_bytes"] == 1228
        assert row["achieved_mbps"] == 0
    else:
        accounting = packet_size_accounting(
            {"packet_size": 1500, "header_bytes": 28}, family=4
        )
        assert accounting["ip_packet_bytes"] == 1500
        assert accounting["payload_bytes"] == 1472


@pytest.mark.parametrize(
    ("case", "match"),
    [
        ("state", "contradicts typed contract verdict"),
        ("outcome", "outcome contradicts"),
        ("execution-state", "execution state contradicts"),
        ("execution-complete", "execution completion contradicts"),
        ("classification", "classification must be one of"),
        ("authority", "authoritative flag contradicts"),
        ("expectation-source", "expectation source contradicts"),
        ("expectation", "expected value contradicts"),
        ("family", "family must be IPv4"),
        ("path-signature-key", "path_signature_key must be"),
    ],
)
def test_contract_validation_rejects_contradictions(case: str, match: str):
    normalized = normalize_result_record(_result())
    contract = copy.deepcopy(normalized["contract"])
    if case == "state":
        contract["verdict"]["state"] = "FAIL"
    elif case == "outcome":
        contract["verdict"]["outcome"] = "violated"
    elif case == "execution-state":
        contract["execution"]["state"] = "not-started"
    elif case == "execution-complete":
        contract["execution"]["complete"] = False
    elif case == "classification":
        contract["authority"]["classification"] = "hidden-component"
    elif case == "authority":
        contract["authority"]["authoritative"] = False
    elif case == "expectation-source":
        contract["expectation"]["source"]["classification"] = "openstack"
    elif case == "expectation":
        contract["expectation"]["code"] = "blocked"
    elif case == "family":
        contract["family"] = 5
    elif case == "path-signature-key":
        contract["path_signature_key"] = "not-a-hash"
    with pytest.raises(ValueError, match=match):
        validate_result_contract(
            contract,
            status="PASS",
            expected=normalized["expected"],
            observed=normalized["observed"],
            authoritative=True,
        )


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("family",), 6),
        (("source", "semantic"), "different-endpoint"),
        (("expectation", "source", "classification"), "openstack"),
        (("verdict", "basis"), "different-basis"),
        (("authority", "classification"), "openstack"),
        (("execution", "state"), "not-started"),
        (("execution", "complete"), False),
    ],
)
def test_normalization_rejects_supplied_contract_overrides(
    path: tuple[str, ...], value: Any
):
    baseline = normalize_result_record(_result())
    contradictory = _result()
    contradictory["contract"] = copy.deepcopy(baseline["contract"])
    target = contradictory["contract"]
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value

    with pytest.raises(ValueError, match="contradicts the canonical value"):
        normalize_result_record(contradictory)


def test_normalization_rejects_supplied_path_context_override():
    baseline = normalize_result_record(_result())
    contradictory = _result()
    contradictory["path_signature"] = copy.deepcopy(baseline["path_signature"])
    contradictory["path_signature"]["context"]["placement"]["source_host"] = (
        "different-host"
    )

    with pytest.raises(ValueError, match="path_signature.*contradicts"):
        normalize_result_record(contradictory)


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("contract", "invalid", "contract must be an object"),
        ("path_signature", [], "path_signature must be an object"),
        ("authoritative", "false", "authoritative must be boolean"),
        ("family", True, "family must be IPv4"),
        ("family", 5, "family must be IPv4"),
    ],
)
def test_normalization_rejects_malformed_contract_inputs(
    field: str, value: Any, match: str
):
    item = _result()
    item[field] = value
    with pytest.raises(ValueError, match=match):
        normalize_result_record(item)


def test_normalization_is_idempotent_with_generated_contracts():
    normalized = normalize_result_record(_result())
    assert normalize_result_record(normalized) == normalized


@pytest.mark.parametrize("case", ["intra", "inter", "az", "contract"])
def test_path_signature_semantics(case: str):
    if case in {"intra", "inter"}:
        variants = (
            ("same compute host", "intra-compute")
            if case == "intra"
            else ("different compute hosts", "inter-compute")
        )
        signatures = [
            build_path_signature(
                test_id="PATH",
                category="network",
                family=4,
                source="Network A:A (192.0.2.10)",
                destination="Network A:B (192.0.2.11)",
                details={
                    "compute_placement": placement,
                    "source_availability_zone": "az1",
                    "destination_availability_zone": "az1",
                    "operation": "probe",
                    "protocol": "icmp",
                },
                scenario="Connectivity",
                contract_type="connectivity",
            )
            for placement in variants
        ]
        assert signatures[0]["key"] == signatures[1]["key"]
        assert signatures[0]["identity"]["placement"] == variants[1]
    elif case == "az":
        same = normalize_result_record(_result())
        cross = normalize_result_record(
            _result(destination_zone="az2", destination_host="compute9")
        )
        assert same["path_signature"]["key"] != cross["path_signature"]["key"]
    else:
        baseline = normalize_result_record(_result(expected="reachable"))
        candidate = normalize_result_record(_result(expected="blocked"))
        # A changed reachability expectation does not identify a different path
        # or establish that a security group enforces the blocked outcome.
        assert (
            baseline["contract"]["type"]
            == candidate["contract"]["type"]
            == "connectivity"
        )
        assert (
            baseline["contract"]["expectation"] != candidate["contract"]["expectation"]
        )
        assert baseline["path_signature"]["key"] == candidate["path_signature"]["key"]
        assert semantic_result_key(baseline) == semantic_result_key(candidate)

        contradictory = _result(expected="reachable")
        contradictory["contract"] = copy.deepcopy(baseline["contract"])
        contradictory["contract"]["path_signature_key"] = "sha256:" + ("0" * 64)
        with pytest.raises(ValueError, match="path signature key contradicts"):
            normalize_result_record(contradictory)


def test_scoped_test_ids_strip_only_the_exact_execution_scope():
    common = {
        "category": "network",
        "family": 4,
        "source": "bc-van1/Network A:A (192.0.2.10)",
        "destination": "bc-van1/Network A:B (192.0.2.11)",
        "details": {
            "execution_scope": "az-bc-van1",
            "availability_zone": "bc-van1",
            "operation": "probe",
            "protocol": "icmp",
        },
        "scenario": "Connectivity",
        "contract_type": "connectivity",
    }
    first = build_path_signature(
        test_id="AZ-BC-VAN1-MTU-LOCAL-LIMIT-4-PROVIDER-TEST",
        **common,
    )
    second = build_path_signature(
        test_id="AZ-BC-VAN1-SNAT-PROVIDER-TEST",
        **common,
    )

    assert first["identity"]["semantic_test"] == "mtu-local-limit-4-provider-test"
    assert second["identity"]["semantic_test"] == "snat-provider-test"
    assert first["key"] != second["key"]


def test_dashboard_projects_typed_contract_facts_without_replay_labels():
    result = _result(status="FAIL", observed="blocked")
    payload = _payload([result])
    payload["replay_plan"] = build_replay_plan(payload)

    model = build_dashboard_model(payload)

    row = model["results"][0]
    assert model["model_version"] == 15
    assert row["contract_type"] == "connectivity"
    assert row["contract_verdict"] == "FAIL"
    assert row["expected"]
    assert row["observed"]
    assert row["semantic_path_key"].startswith("sha256:")
    assert model["contracts"]["verdicts"]["FAIL"] == 1
    assert "replay_plan" not in model


def test_junit_contains_contract_and_path_properties():
    payload = _payload([_result(status="FAIL", observed="blocked")])
    root = ET.fromstring(build_junit(payload))
    case = root.find("testcase")
    assert case is not None
    properties = {
        item.attrib["name"]: item.attrib.get("value")
        for item in case.findall("./properties/property")
    }
    assert properties["contract_type"] == "connectivity"
    assert properties["contract_verdict"] == "FAIL"
    assert properties["expectation_source"] == "operator"
    assert properties["authority_classification"] == "operator"
    assert properties["semantic_path_key"].startswith("sha256:")
    assert case.find("failure").attrib["type"] == "contract-violation"


@pytest.mark.parametrize("case", ["control", "host", "az", "none"])
def test_replay_plan_selection(case: str):
    if case == "none":
        plan = build_replay_plan(_payload([_result("ONLY-PASS")]))
        assert plan["status"] == "no-replay-required"
        assert plan["cases"] == []
        return

    target = _result("TARGET", status="FAIL", observed="blocked")
    control = _result("ZZ-CONTROL")
    results = [target, control]
    if case == "host":
        results.append(
            _result(
                "AA-HOST-VARIATION",
                source_host="compute1",
                destination_host="compute8",
            )
        )
    elif case == "az":
        results.append(
            _result(
                "AA-AZ-VARIATION",
                source_host="compute8",
                destination_host="compute9",
                source_zone="az2",
                destination_zone="az2",
            )
        )

    plan = build_replay_plan(_payload(results))
    replay_case = plan["cases"][0]
    assert plan["immutable"] is True
    assert replay_case["target_result_id"] == "TARGET"
    assert replay_case["healthy_control_result_id"] == "ZZ-CONTROL"
    assert plan["execution_context"]["image"] == "debian-13"
    if case == "host":
        assert replay_case["variation_result_ids"] == ["AA-HOST-VARIATION"]
    elif case == "az":
        assert replay_case["variation_result_ids"] == ["AA-AZ-VARIATION"]
    else:
        assert replay_case["variation_result_ids"] == []


def test_replay_classifies_phase_only_controller_bootstrap_failure():
    target = _result(
        "BOOTSTRAP-FAILURE",
        status="ERROR",
        category="setup",
        extra_details={"failure_phase": "controller-bootstrap"},
    )

    plan = build_replay_plan(_payload([target]))

    assert len(plan["cases"]) == 1
    assert plan["cases"][0]["target_result_id"] == "BOOTSTRAP-FAILURE"
    assert plan["cases"][0]["contract_type"] == "controller-bootstrap"
    assert plan["cases"][0]["replay_kind"] == "controller-bootstrap"


def test_replay_controls_require_the_same_expectation_and_authority():
    target = _result(
        "TARGET",
        status="FAIL",
        expected="unreachable",
        observed="reachable",
    )
    opposite_expectation = _result(
        "OPPOSITE-EXPECTATION",
        expected="reachable",
        observed="reachable",
    )
    supporting_only = _result(
        "SUPPORTING-ONLY",
        expected="unreachable",
        observed="unreachable",
        authoritative=False,
    )
    different_authority_basis = _result(
        "DIFFERENT-AUTHORITY-BASIS",
        expected="unreachable",
        observed="unreachable",
        extra_details={"authority_classification": "openstack"},
    )

    plan = build_replay_plan(
        _payload(
            [
                target,
                opposite_expectation,
                supporting_only,
                different_authority_basis,
            ]
        )
    )

    assert plan["cases"][0]["healthy_control_result_id"] is None
    assert plan["cases"][0]["variation_result_ids"] == []


def test_replay_controls_require_the_same_stable_network_path():
    target = _result("TARGET", status="FAIL", observed="unreachable")
    different_path = _result(
        "DIFFERENT-PATH",
        extra_details={
            "path": {
                "source_label": "Project network B:A",
                "destination_label": "Project network B:B",
                "source_group_id": "project-network-b",
                "destination_group_id": "project-network-b",
                "source_compute_host": "compute1",
                "destination_compute_host": "compute2",
                "source_availability_zone": "az1",
                "destination_availability_zone": "az1",
                "placement": "different compute hosts",
                "availability_scope": "same-az",
                "execution_scope": "az1",
                "operation": "probe",
                "protocol": "icmp",
            }
        },
    )

    plan = build_replay_plan(_payload([target, different_path]))

    assert plan["cases"][0]["healthy_control_result_id"] is None
    assert plan["cases"][0]["variation_result_ids"] == []


def test_legacy_generic_performance_tokens_are_input_only():
    normalized = normalize_result_record(
        _result(
            "LEGACY-PERF",
            category="network-performance",
            measurement="tcp-throughput",
            expected="measurement-complete",
            observed="measured",
            extra_details={
                "metrics": {
                    "forward": {"streams": {"1": {"median_mbps": 100.0}}},
                    "reverse": {"streams": {"1": {"median_mbps": 95.0}}},
                }
            },
        )
    )
    assert normalized["expected"] == "tcp-throughput-profile-recorded"
    assert normalized["observed"] == "tcp-throughput-profile-measured"
    assert normalized["contract"]["expectation"]["code"] != "measurement-complete"
    assert normalized["contract"]["observation"]["code"] != "measured"
    encoded = json.dumps(normalized, sort_keys=True)
    assert '"measurement-complete"' not in encoded
    assert '"measured"' not in encoded


def test_missing_authority_never_claims_authoritative_verdict_evidence():
    item = _result()
    item.pop("authoritative")

    normalized = normalize_result_record(item)
    contract = normalized["contract"]

    assert contract["authority"]["authoritative"] is False
    assert contract["verdict"]["basis"] == "supporting-observation"
    assert "Supporting evidence" in contract["expectation"]["permitted_uncertainty"]


@pytest.mark.parametrize(
    ("measurement", "message", "metrics"),
    [
        (
            "tcp-throughput",
            "Forward 100.0 Mbps; reverse 95.0 Mbps; bidirectional 180.0 Mbps",
            {
                "forward": {"streams": {"1": {"median_mbps": 100.0}}},
                "reverse": {"streams": {"1": {"median_mbps": 95.0}}},
                "bidirectional": {"aggregate_mbps": 180.0},
            },
        ),
        (
            "latency",
            "Idle p95 2.0 ms; loaded p95 8.0 ms; loaded ratio 4.0",
            {
                "idle": {"forward": {"p95_ms": 2.0}},
                "loaded": {"forward": {"p95_ms": 8.0}},
                "loaded_p95_ratio": {"forward": 4.0},
            },
        ),
        (
            "udp",
            "Worst UDP loss 0.5%; jitter 0.8 ms; achieved 98.0 Mbps",
            {
                "forward": [
                    {
                        "packet_size": 1200,
                        "loss_pct": 0.5,
                        "jitter_ms": 0.8,
                        "achieved_mbps": 98.0,
                    }
                ]
            },
        ),
    ],
)
def test_reporter_emits_metric_specific_contract_language(
    measurement: str,
    message: str,
    metrics: dict[str, Any],
    config_factory,
):
    reporter = Reporter(config_factory(action="run"), f"sample-{measurement}")
    try:
        item = reporter.result(
            f"SAMPLE-{measurement}",
            "network-performance",
            "PASS",
            message,
            family=4,
            source="Project A (192.0.2.10)",
            destination="Project B (192.0.2.11)",
            details={
                "performance": True,
                "measurement": measurement,
                "health": "good",
                "thresholds_enforced": False,
                "metrics": metrics,
            },
            expected="measurement-complete",
            observed="measured",
            authoritative=True,
            display_name=f"{measurement} measurement",
            scenario="Project-network performance",
        )
        transcript = reporter.report_path.read_text(encoding="utf-8")
        assert item.expected == performance_expectation(measurement)
        assert item.observed == performance_observation(measurement, status="PASS")
        assert "Expected result:" in transcript
        assert "Actual result:" in transcript
        assert "Why this passed:" in transcript
        expected_measurements = {
            "tcp-throughput": ("100 Mbps", "95 Mbps", "180 Mbps", "single-connection"),
            "latency": ("2 ms", "8 ms", "95th-percentile round-trip time"),
            "udp": ("application loss 0.5 %", "0.8 ms", "achieved rate 98 Mbps"),
        }
        for observation in expected_measurements[measurement]:
            assert observation in transcript
        assert "192.0.2.10" in transcript and "192.0.2.11" in transcript
        stored = json.loads(reporter.result_journal_path.read_text().splitlines()[-1])
        assert stored["message"] == message
        assert stored["status"] == "PASS"
        assert "Expected behavior: Measurement complete" not in transcript
        assert "Actual behavior: Measured" not in transcript
    finally:
        reporter.logger.close()


def test_replay_plan_fingerprint_is_stable_and_content_addressed():
    payload = _payload(
        [
            _result("TARGET", status="FAIL", observed="blocked"),
            _result("CONTROL"),
        ]
    )
    first = build_replay_plan(payload)
    second = build_replay_plan(copy.deepcopy(payload))
    assert first == second
    assert first["fingerprint"].startswith("sha256:")
    without_fingerprint = dict(first)
    fingerprint = without_fingerprint.pop("fingerprint")
    import hashlib

    encoded = json.dumps(
        without_fingerprint,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    assert (
        fingerprint == "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    )


def test_offline_regeneration_injects_replay_and_rebuilds_dashboard(tmp_path):
    payload = _payload(
        [_result("OFFLINE-TARGET", status="FAIL", observed="blocked")],
        "offline-sample",
    )
    payload["dashboard"] = {"model_version": 4, "stale": True}
    payload["replay_plan"] = {
        "schema_version": 1,
        "status": "stale",
        "cases": [],
        "fingerprint": "sha256:" + ("0" * 64),
    }
    source = tmp_path / "results.json"
    source.write_text(json.dumps(payload), encoding="utf-8")
    output = tmp_path / "reports"

    regenerate(source, destination=output)

    incident = (output / "incident-summary.md").read_text(encoding="utf-8")
    assert "Replay plan: ready; 1 review case" in incident
    replay = json.loads((output / "replay-plan.json").read_text(encoding="utf-8"))
    assert replay["status"] == "ready"
    assert len(replay["cases"]) == 1
    html = (output / "report.html").read_text(encoding="utf-8")
    data = html.split('<script id="run-data" type="application/json">', 1)[1].split(
        "</script>", 1
    )[0]
    dashboard = json.loads(data)["dashboard"]
    assert dashboard["model_version"] == 15
    assert "replay_plan" not in dashboard
    assert "stale" not in dashboard
