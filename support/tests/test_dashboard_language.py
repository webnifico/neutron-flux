from __future__ import annotations

import copy
import re
import subprocess
from pathlib import Path

from neutron_flux.reporting_components.dashboard_model import (
    build_dashboard_model,
    friendly_endpoint,
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


def _static_route_result() -> dict:
    payload = _payload("sample-static-routing")
    result = copy.deepcopy(payload["results"][0])
    result.update(
        {
            "test_id": "STATIC-ROUTE-IPV4-CONNECTIVITY",
            "display_name": "Two-router extra-route connectivity — IPv4 — inter-compute",
            "source": "IPv4 two-router extra-route topology from SelfServeIPv4:A (10.0.3.107)",
            "destination": "IPv4 two-router extra-route topology from SelfServeIPv4:B (10.0.4.208)",
        }
    )
    result["details"] = {
        "path": {
            "path_id": "STATIC-ROUTE-PATH",
            "source_label": "IPv4 two-router extra-route topology from SelfServeIPv4:A",
            "destination_label": "IPv4 two-router extra-route topology from SelfServeIPv4:B",
            "source_ip": "10.0.3.107",
            "destination_ip": "10.0.4.208",
            "source_compute_host": "openstack-compute7-canada-west-cloud",
            "destination_compute_host": "openstack-compute8-canada-west-cloud",
            "source_availability_zone": "bc-van2",
            "destination_availability_zone": "bc-van2",
            "family": 4,
            "placement": "cross-compute",
            "source_category": "router-extra-route",
        }
    }
    return result


def test_static_route_endpoint_and_topology_are_plain_networking_language():
    endpoint = friendly_endpoint(
        "IPv4 two-router extra-route topology from SelfServeIPv4:A (10.0.3.107)"
    )
    assert endpoint["label"] == "Project subnet behind router A"
    assert endpoint["ip"] == "10.0.3.107"
    assert endpoint["network"] == "SelfServeIPv4"
    assert "static-routing topology" in endpoint["description"]

    payload = _payload("sample-static-routing")
    result = _static_route_result()
    payload["results"] = [result]
    model = build_dashboard_model(payload)
    path = model["paths"][0]
    assert path["path_reference"] == "Path 01"
    assert path["source_ip"] == "10.0.3.107"
    assert path["destination_ip"] == "10.0.4.208"
    assert path["endpoint_pair"] == "10.0.3.107 → 10.0.4.208"
    assert "topology_label" not in path
    assert "topology_description" not in path
    assert path["placement"] == (
        "Source VM on openstack-compute7-canada-west-cloud; "
        "destination VM on openstack-compute8-canada-west-cloud (different compute hosts)"
    )
    assert "placement_description" not in path


def test_glossary_defines_networking_abbreviations_and_percentiles():
    model = build_dashboard_model(_payload("sample-glossary"))
    glossary = {row["term"]: row["definition"] for row in model["glossary"]}
    for term in ("ICMP", "TCP", "UDP", "MTU", "PMTUD", "MSS", "p95", "RTT", "PPS"):
        assert term in glossary
        assert glossary[term]
    assert "95%" in glossary["p95"]
    assert "different OpenStack compute nodes" in glossary["Inter-compute"]


def test_findings_and_paths_have_readable_references():
    payload = _payload("sample-references")
    result = _static_route_result()
    result["status"] = "FAIL"
    result["actual"] = "blocked"
    payload["results"] = [result]
    model = build_dashboard_model(payload)
    assert model["model_version"] == 15
    assert model["paths"][0]["path_reference"] == "Path 01"
    assert model["paths"][0]["path_id"]
    assert model["findings"][0]["finding_reference"] == "Finding 1"
    assert model["findings"][0]["finding_id"]


def test_html_uses_readable_inventory_and_progressive_definitions(tmp_path: Path):
    payload = _payload("sample-dashboard")
    result = _static_route_result()
    payload["results"] = [result]
    html = render_html(payload)

    for marker in (
        "Technical path evidence",
        "Recorded endpoint pair",
        "Recorded route lookup",
        "What this test checks",
        "Pair 01",
        "Evidence and technical identity",
    ):
        assert marker in html

    from support.tests.test_report_workflow import _embedded_payload

    path = _embedded_payload(html)["dashboard"]["paths"][0]
    for side, suffix in (("source", " A"), ("destination", " B")):
        assert path[side]["label"] == "Project subnet behind router" + suffix

    assert "Extra-route IPv4" not in html
    assert ">P01<" not in html
    assert ">F01<" not in html
    assert "STATIC-ROUTE-IPV4-CONNECTIVITY" in html
    assert "direct L2" not in html
    assert "direct L3" not in html

    script = tmp_path / "sample-dashboard.js"
    script.write_text(_script(html), encoding="utf-8")
    subprocess.run(["node", "--check", str(script)], check=True, capture_output=True)
