from __future__ import annotations

import copy
import json
import re
import subprocess
from pathlib import Path

import pytest

from neutron_flux.reporting_components.dashboard_model import (
    build_dashboard_model,
    friendly_endpoint,
    friendly_host,
    friendly_title,
)
from neutron_flux.reporting_components.html import render_html
from support.tests.test_offline_reports_and_concurrent_load import _payload


def _script(html: str) -> str:
    return "\n".join(
        body
        for attrs, body in re.findall(
            r"<script([^>]*)>(.*?)</script>", html, re.S | re.I
        )
        if "application/json" not in attrs.lower() and body.strip()
    )


def _performance_result(
    base: dict,
    *,
    test_id: str,
    path_id: str,
    stage: str,
    measurement: str,
    metrics: dict,
    status: str = "PASS",
    health: str = "good",
) -> dict:
    result = copy.deepcopy(base)
    result.update(
        {
            "test_id": test_id,
            "status": status,
            "display_name": f"{measurement} — {path_id}",
            "source": "bc-van2/Provider Public3 [bc-van2]:A (172.20.4.10)",
            "destination": "bc-van2/Provider Public3 [bc-van2]:B (172.20.4.20)",
        }
    )
    result["details"] = {
        "performance": True,
        "measurement": measurement,
        "health": health,
        "path": {
            "path_id": path_id,
            "source_label": "Provider Public3 [bc-van2]:A",
            "destination_label": "Provider Public3 [bc-van2]:B",
            "source_ip": "172.20.4.10",
            "destination_ip": "172.20.4.20",
            "source_compute_host": "openstack-compute7-canada-west-cloud",
            "destination_compute_host": "openstack-compute8-canada-west-cloud",
            "source_availability_zone": "bc-van2",
            "destination_availability_zone": "bc-van2",
            "family": 4,
            "placement": "cross-compute",
            "stage": stage,
            "source_category": "same-subnet",
        },
        "metrics": metrics,
    }
    return result


def test_readable_names_keep_canonical_identity():
    result = {
        "test_id": "LONG-ID",
        "display_name": (
            "Representative provider MTU boundary — IPv4 — intra-compute "
            "[openstack-compute7-canada-west-cloud -> openstack-compute7-canada-west-cloud]"
        ),
        "details": {},
    }
    assert friendly_title(result) == "Test the provider-network MTU boundary"
    assert friendly_host("openstack-compute7-canada-west-cloud") == "compute7"
    endpoint = friendly_endpoint("bc-van2/Provider Public3 [bc-van2]:A (172.20.4.194)")
    assert endpoint["raw"] == "bc-van2/Provider Public3 [bc-van2]:A (172.20.4.194)"
    assert endpoint["label"] == "Public3 A"
    assert endpoint["ip"] == "172.20.4.194"
    assert endpoint["side"] == "A"
    assert endpoint["zone"] == "bc-van2"
    assert endpoint["network"] == "Public3"
    assert endpoint["description"] == "Provider network endpoint"


def test_network_inventory_recovers_only_exact_saved_network_identity():
    from neutron_flux.reporting_components.dashboard_environment import (
        build_network_inventory,
    )

    evidence = {
        "resource_id": "network-a",
        "resource_type": "network",
        "resource_name": "shared-name",
        "source": "openstack network show",
        "network_type": "geneve",
        "physical_network": None,
        "segmentation_id": 42,
        "reported_mtu": 1442,
    }
    resources = [
        {"resource_type": "network", "id": identity, "metadata": {}}
        for identity in ("network-a", "network-b")
    ]
    results = [{"details": {"path": {"source_mtu_evidence": evidence}}}]
    original = copy.deepcopy(resources)

    inventory, _ = build_network_inventory({}, resources, {}, results)

    by_id = {row["id"]: row for row in inventory}
    assert by_id["network-a"]["network_type"] == "geneve"
    assert by_id["network-a"]["mtu"] == 1442
    assert by_id["network-a"]["segmentation_id"] == 42
    assert by_id["network-a"]["physical_network"] is None
    assert by_id["network-b"]["network_type"] is None
    assert by_id["network-b"]["mtu"] is None
    assert resources == original


@pytest.mark.parametrize("captured_mtu", [1400, None])
def test_network_inventory_prefers_captured_metadata_over_older_mtu_evidence(
    captured_mtu,
):
    from neutron_flux.reporting_components.dashboard_environment import (
        build_network_inventory,
    )

    inventory, _ = build_network_inventory(
        {},
        [
            {
                "resource_type": "network",
                "id": "network-a",
                "metadata": {"mtu": captured_mtu},
            }
        ],
        {},
        [
            {
                "details": {
                    "path": {
                        "destination_mtu_evidence": {
                            "resource_id": "network-a",
                            "resource_type": "network",
                            "source": "openstack network show",
                            "reported_mtu": 1442,
                        }
                    }
                }
            }
        ],
    )
    assert inventory[0]["mtu"] == captured_mtu


def test_connectivity_uses_structured_udp_and_keeps_worst_sample():
    payload = _zone_payload()
    payload["results"] = [
        {
            **_zone_result(
                identity,
                source="zone-a/Provider Public3:A (192.0.2.10)",
                destination="zone-a/Provider Public3:B (192.0.2.20)",
                details={"protocol": protocol},
            ),
            "status": status,
            "observed": observed,
        }
        for identity, protocol, status, observed in (
            ("first", "udp", "FAIL", "UDP response missing"),
            ("second", "udp", "PASS", "UDP recovered"),
            ("third", "tcp", "PASS", "TCP reached destination"),
        )
    ]

    model = build_dashboard_model(payload)

    assert len(model["paths"]) == 1
    path = model["paths"][0]
    assert path["connectivity"]["tested"] == 3
    assert path["connectivity"]["status"] == "FAIL"
    assert path["connectivity"]["protocols"]["UDP"]["status"] == "FAIL"
    assert path["connectivity"]["protocols"]["UDP"]["result_id"] == "first"
    assert path["health"] == "critical"
    assert path["connectivity"]["protocols"]["TCP"]["status"] == "PASS"
    assert all(
        row["severity"] == "good" for row in model["results"] if row["status"] == "PASS"
    )


def test_external_target_does_not_inherit_peer_vm_compute_or_zone():
    result = _zone_result(
        "INTERNET-PROBE",
        source="zone-a/Provider Public3:A (192.0.2.10)",
        destination="1.1.1.1",
        details={
            "operation": "egress",
            "source_compute_host": "compute-source",
            "destination_compute_host": "stale-peer-compute",
            "source_availability_zone": "zone-a",
            "destination_availability_zone": "stale-peer-zone",
        },
    )
    result["category"] = "egress"
    payload = _zone_payload(result)
    original = copy.deepcopy(payload)

    model = build_dashboard_model(payload)

    path = model["paths"][0]
    assert path["source_host"] == "compute-source"
    assert path["destination"]["label"] == "External destination"
    assert path["destination_ip"] == "1.1.1.1"
    assert path["destination_host"] is None
    assert path["destination_host_alias"] is None
    assert path["destination_availability_zone"] is None
    assert model["results"][0]["destination_display"]["zone"] is None
    assert "stale-peer-zone" not in model["environment"]["zones"]
    assert "stale-peer-compute" not in {
        row["full_name"] for row in model["environment"]["hosts"]
    }
    assert payload == original


@pytest.mark.parametrize("network", ["Public", "Provider Two"])
@pytest.mark.parametrize("description", ["second router", "source without floating IP"])
@pytest.mark.parametrize("zone", [None, "zone-a", "North Zone_2.example"])
def test_descriptive_slashes_preserve_endpoint_identity(network, description, zone):
    label = f"Private IPv4 translation through {network} / {description}"
    raw = f"{label}:A (10.128.0.126)"
    if zone:
        raw = f"{zone}/{raw}"

    endpoint = friendly_endpoint(raw)

    assert endpoint["raw"] == raw
    assert endpoint["label"] == f"{label} A"
    assert endpoint["ip"] == "10.128.0.126"
    assert endpoint["side"] == "A"
    assert endpoint["zone"] == zone


def _zone_payload(*results):
    payload = _payload("zone-inventory")
    payload["results"] = list(results)
    payload["performance"] = []
    return payload


def _zone_result(test_id, *, source, destination, details):
    return {
        "test_id": test_id,
        "category": "same-subnet",
        "display_name": "Project-network same-subnet connectivity",
        "status": "PASS",
        "family": 4,
        "source": source,
        "destination": destination,
        "details": details,
    }


@pytest.mark.parametrize("host_inventory", [False, True])
def test_translation_descriptions_do_not_inflate_compute_zone_count(host_inventory):
    results = [
        _zone_result(
            f"TRANSLATION-{index}",
            source=f"Private IPv4 translation through {network} / source without floating IP:A (10.128.{index}.1)",
            destination=f"Private IPv4 translation through {network} / second router:B (10.128.{index}.2)",
            details={
                "source_availability_zone": "zone-a",
                "destination_availability_zone": "zone-a",
                "source_compute_host": "compute-c",
                "destination_compute_host": "compute-d",
            },
        )
        for index, network in enumerate(["Public", "Provider Two"])
    ]
    payload = _zone_payload(*results)
    if host_inventory:
        payload["plan"] = {
            "host_qualification": {
                "hosts": [
                    {"host": "compute-c", "availability_zone": "zone-a"},
                    {"host": "compute-d", "availability_zone": "zone-a"},
                ]
            }
        }
    original = copy.deepcopy(payload)

    model = build_dashboard_model(payload)

    assert model["environment"]["zones"] == ["zone-a"]
    assert len(model["environment"]["zones"]) == 1
    assert all(path["source"]["zone"] == "zone-a" for path in model["paths"])
    assert all(path["destination"]["zone"] == "zone-a" for path in model["paths"])
    assert payload == original


@pytest.mark.parametrize("location", ["details", "path"])
def test_structured_endpoint_zones_override_legacy_display_prefixes(location):
    zones = {
        "source_availability_zone": "zone-a",
        "destination_availability_zone": "zone-a",
    }
    details = zones if location == "details" else {"path": zones}
    result = _zone_result(
        "STRUCTURED-AZ",
        source="stale-source/Provider Public:A (10.0.0.1)",
        destination="stale-destination/Provider Public:B (10.0.0.2)",
        details=details,
    )
    payload = _zone_payload(result)
    original = copy.deepcopy(payload)

    model = build_dashboard_model(payload)

    assert model["environment"]["zones"] == ["zone-a"]
    assert model["paths"][0]["source"]["zone"] == "zone-a"
    assert model["paths"][0]["destination"]["zone"] == "zone-a"
    assert model["paths"][0]["source_availability_zone"] == "zone-a"
    assert model["paths"][0]["destination_availability_zone"] == "zone-a"
    assert payload == original


def test_structured_path_zones_preserve_actual_multi_zone_paths():
    result = _zone_result(
        "MULTI-AZ",
        source="stale-source/Private IPv4 translation through Public / second router:A (10.0.0.1)",
        destination="stale-destination/Private IPv4 translation through Public / second router:B (10.0.0.2)",
        details={
            "source_availability_zone": "stale-details-source",
            "destination_availability_zone": "stale-details-destination",
            "path": {
                "source_availability_zone": "zone-a",
                "destination_availability_zone": "zone-b",
            },
        },
    )
    payload = _zone_payload(result)

    model = build_dashboard_model(payload)

    assert model["environment"]["zones"] == ["zone-a", "zone-b"]
    assert model["paths"][0]["source"]["zone"] == "zone-a"
    assert model["paths"][0]["destination"]["zone"] == "zone-b"


def test_legacy_zone_labels_remain_available_without_structured_placement():
    payload = _zone_payload(
        _zone_result(
            "LEGACY-AZ",
            source="zone-a/Provider Public:A (10.0.0.1)",
            destination="zone-b/Provider Public:B (10.0.0.2)",
            details={},
        )
    )

    model = build_dashboard_model(payload)

    assert model["environment"]["zones"] == ["zone-a", "zone-b"]
    assert model["paths"][0]["source_availability_zone"] == "zone-a"
    assert model["paths"][0]["destination_availability_zone"] == "zone-b"


def test_cached_dashboard_13_rebuilds_false_zone_inventory(tmp_path: Path):
    payload = _zone_payload(
        _zone_result(
            "CACHED-TRANSLATION-AZ",
            source="Private IPv4 translation through Public / second router:A (10.0.0.1)",
            destination="Private IPv4 translation through Provider Two / second router:B (10.0.0.2)",
            details={
                "source_availability_zone": "zone-a",
                "destination_availability_zone": "zone-a",
            },
        )
    )
    payload["dashboard"] = build_dashboard_model(payload)
    payload["dashboard"]["model_version"] = 13
    payload["dashboard"]["environment"]["zones"] = [
        "Private IPv4 translation through Public",
        "Private IPv4 translation through Provider Two",
        "zone-a",
    ]
    source = tmp_path / "results.json"
    source.write_text(json.dumps(payload), encoding="utf-8")
    saved = json.loads(source.read_text(encoding="utf-8"))
    original = copy.deepcopy(saved)

    html = render_html(saved)

    embedded = html.split('<script id="run-data" type="application/json">', 1)[1].split(
        "</script>", 1
    )[0]
    rebuilt = json.loads(embedded)["dashboard"]
    assert rebuilt["model_version"] > 13
    assert rebuilt["environment"]["zones"] == ["zone-a"]
    assert saved == original


def test_groups_related_conditions_across_paths():
    payload = _payload("sample-findings")
    base = payload["results"][0]
    first = _performance_result(
        base,
        test_id="MTU-BASELINE",
        path_id="BASELINE",
        stage="group-local",
        measurement="mtu-mss",
        status="FAIL",
        health="critical",
        metrics={
            "expected_mtu": 1500,
            "forward": {"discovered_mtu": 1424},
            "reverse": {"discovered_mtu": 1424},
        },
    )
    second = _performance_result(
        base,
        test_id="MTU-POST",
        path_id="POST",
        stage="post-live-migration",
        measurement="mtu-mss",
        status="FAIL",
        health="critical",
        metrics={
            "expected_mtu": 1500,
            "forward": {"discovered_mtu": 1424},
            "reverse": {"discovered_mtu": 1424},
        },
    )
    payload["results"] = [first, second]
    payload["performance"] = [first, second]
    model = build_dashboard_model(payload)
    assert len(model["findings"]) == 1
    finding = model["findings"][0]
    assert finding["title"] == "Packet-size validation requires review"
    assert finding["result_count"] == 2
    assert len(finding["path_ids"]) == 2


def test_links_post_migration_path_to_baseline_measurements():
    payload = _payload("sample-comparison")
    base = payload["results"][0]
    baseline = _performance_result(
        base,
        test_id="TCP-BASELINE",
        path_id="BASELINE",
        stage="group-local",
        measurement="tcp-throughput",
        metrics={
            "forward": {"streams": {"1": {"median_mbps": 9000}}},
            "reverse": {"streams": {"1": {"median_mbps": 8800}}},
        },
    )
    post = _performance_result(
        base,
        test_id="TCP-POST",
        path_id="POST",
        stage="post-live-migration",
        measurement="tcp-throughput",
        metrics={
            "forward": {"streams": {"1": {"median_mbps": 8700}}},
            "reverse": {"streams": {"1": {"median_mbps": 8600}}},
        },
    )
    payload["results"] = [baseline, post]
    payload["performance"] = [baseline, post]
    model = build_dashboard_model(payload)
    post_path = next(
        path for path in model["paths"] if path["phase"] == "After migration"
    )
    baseline_path = next(
        path for path in model["paths"] if path["measurement_stage"] == "group-local"
    )
    assert post_path["comparison"]["baseline_path_id"] == baseline_path["path_id"]
    forward = next(
        row for row in post_path["comparison"]["rows"] if row["label"] == "TCP forward"
    )
    assert forward["before"] == 9000
    assert forward["after"] == 8700
    assert forward["delta"] == -300


def test_dashboard_has_progressive_disclosure_and_valid_javascript(tmp_path: Path):
    html = render_html(_payload("sample-dashboard"))
    markers = (
        "Run scope and limits",
        "Performance tests",
        "endpoint-pair",
        "Investigation",
        "What this test checks",
        "Expected behaviour",
        "Parsed evidence",
        "Evidence and technical identity",
        "function openFinding(",
        "function openTest(",
        "comparison",
        "P01",
    )
    for marker in markers:
        assert marker in html
    script = tmp_path / "sample-dashboard.js"
    script.write_text(_script(html), encoding="utf-8")
    subprocess.run(["node", "--check", str(script)], check=True, capture_output=True)
