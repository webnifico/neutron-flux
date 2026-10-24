from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from neutron_flux.operator_explanations import explain_result
from neutron_flux.packet_size_components import component_contracts
from neutron_flux.result_contract import normalize_result_record

CAPTURED = json.loads(
    (
        Path(__file__).parent / "fixtures/packet_size_component_observations.json"
    ).read_text()
)


def _result(case):
    return {
        "test_id": "CAPTURED-MTU",
        "category": "network-performance",
        "status": case["status"],
        "family": case["family"],
        "details": {
            "measurement": "mtu-mss",
            "metrics": copy.deepcopy(case["metrics"]),
        },
    }


@pytest.mark.parametrize("case", CAPTURED["packet_size"])
def test_captured_component_outcomes_do_not_inherit_advisory_pass(case):
    normalized = normalize_result_record(_result(case))
    components = {row["type"]: row for row in normalized["contract"]["components"]}
    assert normalized["status"] == "PASS"
    assert normalized["contract"]["verdict"]["state"] == "PASS"
    assert components["tcp-mss"]["verdict"] == "PASS"
    if case["case"] == "advertised-mismatch":
        assert components["mtu"]["verdict"] == "FAIL"
        assert components["pmtud"]["verdict"] == "PASS"
    elif case["case"] == "tested-fragment-not-delivered":
        assert components["mtu"]["verdict"] == "PASS"
        assert components["ipv4-fragmentation"]["verdict"] == "FAIL"
        assert (
            components["ipv4-fragmentation"]["scope"]
            == "Recorded packet sizes and probe window only"
        )
        assert components["ipv4-fragmentation"]["tested_packet_sizes"] == [1500]
    else:
        assert components["mtu"]["verdict"] == "PASS"
        assert components["pmtud"]["verdict"] == "INAPPLICABLE"


@pytest.mark.parametrize("case", CAPTURED["packet_size"])
def test_saved_advisory_component_annotations_are_refreshed(case):
    original = _result(case)
    expected = normalize_result_record(original)
    archived = copy.deepcopy(expected)
    archived["contract"]["components"] = copy.deepcopy(case["saved_components"])
    archived_before = copy.deepcopy(archived)
    assert normalize_result_record(archived) == expected
    assert archived == archived_before
    altered = copy.deepcopy(archived)
    altered["contract"]["components"][0]["observed"] = ["met", "met", "met"]
    with pytest.raises(ValueError, match="components.*contradicts"):
        normalize_result_record(altered)


@pytest.mark.parametrize(
    "values,verdict,observed",
    [
        ((1390, 1390, 1402), "PASS", "within-constraint"),
        ((1460, 1390, 1402), "FAIL", "above-constraint"),
        ((1390, 1460, 1402), "FAIL", "above-constraint"),
        ((0, 1390, 1402), "UNVERIFIED", "incomplete"),
        ((1390, None, 1402), "UNVERIFIED", "incomplete"),
        ((1390, 1390, None), "UNVERIFIED", "incomplete"),
        ((True, 1390, 1402), "UNVERIFIED", "incomplete"),
        ((1390, 1390, float("nan")), "UNVERIFIED", "incomplete"),
    ],
)
def test_mss_requires_valid_observations_and_a_matching_constraint(
    values, verdict, observed
):
    row = dict(
        zip(("client_mss", "server_mss", "expected_max_mss"), values, strict=True)
    )
    components = component_contracts(
        contract_type="packet-size-path",
        status="PASS",
        family=4,
        details={"metrics": {"forward": row}},
    )
    assert components[-1]["verdict"] == verdict
    assert components[-1]["observed"] == observed


def test_missing_requested_direction_cannot_pass_a_component():
    case = copy.deepcopy(CAPTURED["packet_size"][0])
    del case["metrics"]["reverse"]
    normalized = normalize_result_record(_result(case))
    components = normalized["contract"]["components"]
    assert all(row["verdict"] == "UNVERIFIED" for row in components)


def test_unknown_pmtud_and_unneeded_fragmentation_are_not_passes():
    components = component_contracts(
        contract_type="packet-size-path",
        status="PASS",
        family=6,
        details={
            "metrics": {
                "forward": {
                    "pmtud_status": "df-path-boundary-observed",
                    "fragmentation": {"capability": "not-required"},
                }
            }
        },
    )
    assert components[1]["verdict"] == "UNVERIFIED"
    assert components[2]["verdict"] == "INAPPLICABLE"


@pytest.mark.parametrize(
    "capability,packet_size,classification",
    [
        ("supported", None, "success"),
        ("supported", 1500, None),
        ("supported", 1500, "no-reply"),
        ("not-supported", None, "no-reply"),
        ("not-supported", 1500, "local-mtu-rejected"),
        ("not-supported", 1500, "mixed"),
    ],
)
def test_fragment_capability_without_matching_delivery_evidence_is_unverified(
    capability, packet_size, classification
):
    components = component_contracts(
        contract_type="packet-size-path",
        status="PASS",
        family=4,
        details={
            "metrics": {
                "forward": {
                    "fragmentation": {
                        "capability": capability,
                        "tested_packet_size": packet_size,
                        "fragmentation_permitted": {"classification": classification},
                    }
                }
            }
        },
    )
    assert components[2]["verdict"] == "UNVERIFIED"


@pytest.mark.parametrize("case", CAPTURED["partial_udp_comparisons"])
def test_captured_partial_udp_warning_does_not_claim_threshold_breach(case):
    original = copy.deepcopy(case)
    result = {
        **case,
        "details": {"measurement": "asymmetry", "metrics": case["metrics"]},
    }
    facts = {row["label"]: row["value"] for row in explain_result(result)["facts"]}
    value = facts["UDP directional comparison"]
    assert "equal measured loss" in value
    assert "coverage is partial" in value
    assert "Above" not in value
    assert case == original


@pytest.mark.parametrize("partial", [False, True])
def test_measured_udp_breach_remains_visible_with_partial_coverage(partial):
    result = {
        "status": "PASS",
        "details": {
            "measurement": "asymmetry",
            "metrics": {
                "udp_health": "warning",
                "udp_loss_difference_pct_points": 2,
                "udp_loss_advisory_threshold_pct_points": 1,
                "udp_unmatched_profiles": int(partial),
            },
        },
    }
    facts = {row["label"]: row["value"] for row in explain_result(result)["facts"]}
    assert (
        "Above the configured advisory threshold" in facts["UDP directional comparison"]
    )
    assert ("coverage is partial" in facts["UDP directional comparison"]) is partial
