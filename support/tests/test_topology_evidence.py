from __future__ import annotations

import re
import subprocess
from pathlib import Path

from neutron_flux.cli import parser
from neutron_flux.concurrent_load import ConcurrentLoadRunner
from neutron_flux.reporting_components.dashboard_model import build_dashboard_model
from neutron_flux.reporting_components.html import render_html
from support.tests.test_topology_and_jumbo_paths import _topology_payload


def _run_args(*extra: str):
    return parser().parse_args(
        [
            "run",
            "--image",
            "debian-13",
            "--flavor",
            "x1.nano",
            "--storage",
            "host",
            "--external-networks",
            "Public1",
            *extra,
        ]
    )


def test_fabric_comparison_modes_are_truthful():
    single = [{"pairs": 8, "median_pair_mbps": 600.0}]
    model = ConcurrentLoadRunner._attach_level_comparisons(single)
    assert model == {
        "mode": "fixed-concurrency",
        "baseline_pairs": None,
        "one_pair_baseline_present": False,
    }
    assert single[0]["per_pair_change_pct"] is None
    assert single[0]["per_pair_degradation_pct"] is None

    lowest = [
        {"pairs": 4, "median_pair_mbps": 1000.0},
        {"pairs": 8, "median_pair_mbps": 700.0},
    ]
    model = ConcurrentLoadRunner._attach_level_comparisons(lowest)
    assert model["mode"] == "lowest-requested-level"
    assert model["baseline_pairs"] == 4
    assert lowest[0]["per_pair_degradation_pct"] == 0.0
    assert lowest[1]["per_pair_change_pct"] == -30.0
    assert lowest[1]["per_pair_degradation_pct"] == 30.0
    assert lowest[1]["comparison_baseline_pairs"] == 4

    one_pair = [
        {"pairs": 1, "median_pair_mbps": 1000.0},
        {"pairs": 4, "median_pair_mbps": 250.0},
    ]
    model = ConcurrentLoadRunner._attach_level_comparisons(one_pair)
    assert model["mode"] == "one-pair-baseline"
    assert model["one_pair_baseline_present"] is True
    assert one_pair[1]["per_pair_degradation_pct"] == 75.0


def _diagram_payload() -> dict:
    payload = _topology_payload()
    payload["discovery"] = {
        "cloud": "test",
        "networks": [
            {
                "id": "external-net",
                "name": "Public1",
                "external": True,
                "network_type": "flat",
                "physical_network": "provider1",
                "mtu": 1500,
            }
        ],
        "subnets": [],
    }
    payload["resources"] = [
        *payload["resources"],
        {
            "resource_type": "network",
            "id": "network-v4",
            "name": "technical-project-network",
            "metadata": {
                "group_id": "project-v4",
                "role": "tenant-pool",
                "scenario_side": "a",
            },
        },
        {
            "resource_type": "router",
            "id": "router-v4",
            "name": "technical-router",
            "metadata": {
                "group_id": "project-v4",
                "role": "tenant-pool",
                "external_network_id": "external-net",
            },
        },
        {
            "resource_type": "port",
            "id": "port-a",
            "name": "technical-port-a",
            "parent_id": "network-v4",
            "metadata": {
                "group_id": "project-v4",
                "endpoint_side": "A",
                "role": "endpoint-test",
            },
        },
    ]
    result = payload["results"][0]
    result["details"]["path"] = {
        "path_id": "project-path",
        "source_group_id": "project-v4",
        "destination_group_id": "project-v4",
        "source_endpoint_side": "A",
        "destination_endpoint_side": "B",
        "source_label": "Project endpoint A",
        "destination_label": "Flux runner",
        "source_ip": "10.0.3.107",
        "destination_ip": "192.0.2.10",
        "family": 4,
        "source_category": "source-nat-egress",
    }
    return payload


def test_dashboard_omits_reconstructed_network_relationships():
    model = build_dashboard_model(_diagram_payload())
    assert "topology" not in model
    path = model["paths"][0]
    assert path["source_ip"] == "10.0.3.107"
    assert path["destination_ip"] == "192.0.2.10"
    assert "route_hops" not in path


def test_dashboard_renders_fact_only_endpoint_workflow(tmp_path: Path):
    html = render_html(_diagram_payload())
    for marker in (
        "Technical path evidence",
        "Recorded endpoint pair",
        "No route lookup was recorded for this endpoint pair.",
        "Copy endpoint facts",
        "Open affected tests",
    ):
        assert marker in html
    assert "Interactive Neutron Flux network topology diagram" not in html
    assert "Relationship reconstructed" not in html

    scripts = [
        body
        for attrs, body in re.findall(
            r"<script([^>]*)>(.*?)</script>", html, re.S | re.I
        )
        if "application/json" not in attrs.lower() and body.strip()
    ]
    script = tmp_path / "sample-dashboard.js"
    script.write_text("\n".join(scripts), encoding="utf-8")
    subprocess.run(["node", "--check", str(script)], check=True, capture_output=True)
