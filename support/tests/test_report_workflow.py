from __future__ import annotations

import copy
import json
import re
import subprocess
from pathlib import Path

from neutron_flux.reporting_components.dashboard_model import build_dashboard_model
from neutron_flux.reporting_components.html import render_html


def _payload() -> dict:
    result = {
        "test_id": "PROJECT-ROUTE-TCP",
        "category": "project-network-routing",
        "status": "PASS",
        "family": 4,
        "source": "zone-a/Project network A:A (10.0.3.107)",
        "destination": "zone-a/Project network B:B (10.0.4.107)",
        "message": "TCP reached the destination and echoed application data.",
        "expected": "TCP reaches the named destination.",
        "observed": "TCP reached and echoed application data.",
        "display_name": "Project-network TCP connectivity",
        "scenario": "Project networks on one Neutron router",
        "details": {
            "path": {
                "path_id": "project-route-v4",
                "source_category": "project-network-routing",
                "source_group_id": "project-a",
                "destination_group_id": "project-b",
                "source_endpoint_side": "A",
                "destination_endpoint_side": "B",
                "source_ip": "10.0.3.107",
                "destination_ip": "10.0.4.107",
                "source_compute_host": "compute1",
                "destination_compute_host": "compute2",
                "source_availability_zone": "zone-a",
                "destination_availability_zone": "zone-a",
                "family": 4,
            },
            "probe": {
                "diagnostics": {
                    "runner_route": (
                        "10.0.4.107 via 10.0.3.97 dev ens3 src 10.0.3.107"
                    ),
                    "runner_route_returncode": 0,
                }
            },
        },
    }
    return {
        "schema_version": 1,
        "tool": "neutron-flux",
        "tool_version": "0.1.0",
        "run": {
            "run_id": "sample-test",
            "started_at": "2026-08-01T00:00:00Z",
            "finished_at": "2026-08-01T00:01:00Z",
            "final_status": "PASS",
        },
        "configuration": {
            "availability_zones": ["zone-a"],
            "performance_enabled": False,
            "evidence_enabled": True,
        },
        "summary": {
            "counts": {"PASS": 1},
            "total_results": 1,
            "cleanup_complete": True,
        },
        "plan": {
            "tenant_groups": [
                {"id": "project-a", "kind": "one-router-project-networks"},
                {"id": "project-b", "kind": "one-router-project-networks"},
            ]
        },
        "discovery": {
            "cloud": "test-cloud",
            "project_name": "test-project",
            "networks": [
                {
                    "id": "network-a",
                    "name": "Project network A",
                    "network_type": "geneve",
                    "mtu": 1442,
                },
                {
                    "id": "network-b",
                    "name": "Project network B",
                    "network_type": "geneve",
                    "mtu": 1442,
                },
            ],
            "subnets": [
                {
                    "id": "subnet-a",
                    "name": "project-subnet-a",
                    "network_id": "network-a",
                    "cidr": "10.0.3.96/27",
                    "gateway_ip": "10.0.3.97",
                },
                {
                    "id": "subnet-b",
                    "name": "project-subnet-b",
                    "network_id": "network-b",
                    "cidr": "10.0.4.96/27",
                    "gateway_ip": "10.0.4.97",
                },
            ],
        },
        "resources": [
            {
                "resource_type": "network",
                "id": "network-a",
                "name": "generated-network-a",
                "metadata": {
                    "role": "one-router-project-networks",
                    "group_id": "project-a",
                    "scenario_side": "a",
                },
            },
            {
                "resource_type": "network",
                "id": "network-b",
                "name": "generated-network-b",
                "metadata": {
                    "role": "one-router-project-networks",
                    "group_id": "project-b",
                    "scenario_side": "b",
                },
            },
            {
                "resource_type": "subnet",
                "id": "subnet-a",
                "name": "generated-subnet-a",
                "parent_id": "network-a",
                "metadata": {
                    "role": "one-router-project-networks",
                    "group_id": "project-a",
                    "cidr": "10.0.3.96/27",
                    "gateway_ip": "10.0.3.97",
                },
            },
            {
                "resource_type": "subnet",
                "id": "subnet-b",
                "name": "generated-subnet-b",
                "parent_id": "network-b",
                "metadata": {
                    "role": "one-router-project-networks",
                    "group_id": "project-b",
                    "cidr": "10.0.4.96/27",
                    "gateway_ip": "10.0.4.97",
                },
            },
        ],
        "results": [result],
        "performance": [],
        "events": [],
        "cleanup": {"attempted": True, "complete": True},
    }


def _embedded_payload(html: str) -> dict:
    match = re.search(
        r'<script id="run-data" type="application/json">(.*?)</script>',
        html,
        re.S,
    )
    assert match
    return json.loads(match.group(1))


def test_blocked_report_links_shared_cause_and_preserves_recorded_results():
    payload = _payload()
    template = payload["results"][0]
    payload["results"] = [
        {
            **template,
            "test_id": "MTU",
            "status": "FAIL",
            "category": "mtu",
            "display_name": "Provider MTU boundary",
            "observed": "path-mtu-below-advertised",
            "message": "1500-byte packet rejected with MTU 1442",
        },
        {
            **template,
            "test_id": "MIGRATION",
            "status": "UNVERIFIED",
            "category": "compute-placement",
            "observed": "fresh-functional-baseline-unavailable",
            "message": "Migration was not submitted",
        },
    ]
    payload["planned_check_ledger"] = [
        {
            "id": identity,
            "title": title,
            "kind": "migration",
            "stage": "migration",
            "condition": "Prerequisites pass",
            "outcome": outcome,
            "reason": reason,
            "prerequisites": prerequisites,
            "result_id": result_id,
            "evidence_ids": [result_id] if result_id else [],
        }
        for identity, title, outcome, reason, prerequisites, result_id in [
            (
                "MTU",
                "Provider MTU boundary",
                "FAILED",
                "1500-byte packet rejected with MTU 1442",
                [],
                "MTU",
            ),
            (
                "MOVE",
                "Migrate endpoint",
                "BLOCKED",
                "Migration was not submitted",
                ["MTU"],
                "MIGRATION",
            ),
            (
                "AFTER",
                "Connectivity after migration",
                "BLOCKED",
                "Migration did not run",
                ["MOVE"],
                None,
            ),
            (
                "PERFORMANCE",
                "Performance after migration",
                "BLOCKED",
                "Connectivity after migration did not run",
                ["AFTER"],
                None,
            ),
        ]
    ]
    original = copy.deepcopy(payload)
    report = _embedded_payload(render_html(payload))
    rows = report["dashboard"]["results"]
    blocked = [r for r in rows if r["status"] == "BLOCKED_BY_PREREQUISITE"]
    assert len(blocked) == 3
    assert (
        next(r for r in blocked if r["result_id"] == "MIGRATION")["recorded_status"]
        == "UNVERIFIED"
    )
    for row in blocked:
        assert len(row["blocking_checks"]) == 1
        root = row["blocking_checks"][0]
        assert root["result_id"] == "MTU"
        assert "1442" in root["reason"]
        assert row["blocked_reason"]
    assert payload["results"] == original["results"]
    assert payload["planned_check_ledger"] == original["planned_check_ledger"]


def test_blocking_causes_keep_distinct_failures_and_handle_cycles():
    from neutron_flux.reporting_components.report_payload import _blocking_check_ids

    checks = {
        "child": {
            "outcome": "BLOCKED",
            "prerequisites": ["cycle", "failed-a", "failed-b", "missing"],
        },
        "cycle": {"outcome": "BLOCKED", "prerequisites": ["child", "failed-a"]},
        "failed-a": {"outcome": "FAILED", "prerequisites": []},
        "failed-b": {"outcome": "ERROR", "prerequisites": []},
    }
    assert _blocking_check_ids("child", checks) == ["failed-a", "failed-b"]


def test_report_is_compact_and_uses_recorded_route_output(tmp_path: Path):
    payload = _payload()
    payload["results"][0]["details"]["probe"].update(
        {
            "command": ["probe", "--path", "project-a"],
            "stdout": "evidence-line\n" * 5_000,
            "stderr": "",
        }
    )

    html = render_html(payload)
    report = _embedded_payload(html)
    dashboard = report["dashboard"]
    views = re.findall(
        r'<section class="view(?: active)?" data-view="([^"]+)"',
        html,
    )

    assert report["report_model_version"] == 13
    assert dashboard["model_version"] == 15
    assert dashboard["report_shape_version"] == 13
    assert views == ["overview", "findings", "paths", "tests", "performance", "run"]
    assert "Review queue" in html
    assert 'id="contextBar"' in html
    assert len(dashboard["results"]) == 1
    assert dashboard["results"][0]["reference"] == "Test 0001"
    assert len(dashboard["results"][0]["evidence"]["stdout"]) <= 1_201
    assert "evidence-line\n" * 2_000 not in html

    path = dashboard["paths"][0]
    assert path["endpoint_pair"] == "10.0.3.107 → 10.0.4.107"
    assert path["source_host"] == "compute1"
    assert path["destination_host"] == "compute2"
    assert path["source_availability_zone"] == "zone-a"
    assert path["destination_availability_zone"] == "zone-a"
    assert path["route_observations"] == [
        {
            "observer": "Flux runner",
            "output": "10.0.4.107 via 10.0.3.97 dev ens3 src 10.0.3.107",
        }
    ]
    for key in (
        "topology",
        "topology_label",
        "topology_description",
        "placement",
        "route_hops",
        "route_text",
        "address_route",
    ):
        assert key not in path
    assert dashboard["coverage"]["paths_with_endpoint_ips"] == 1
    assert dashboard["coverage"]["paths_with_route_observations"] == 1

    scripts = [
        body
        for attrs, body in re.findall(r"<script([^>]*)>(.*?)</script>", html, re.S)
        if "application/json" not in attrs.lower() and body.strip()
    ]
    script = tmp_path / "sample-report.js"
    script.write_text("\n".join(scripts), encoding="utf-8")
    subprocess.run(["node", "--check", str(script)], check=True, capture_output=True)


def test_never_classifies_the_172_20_4_0_22_endpoint_pair():
    payload = _payload()
    result = payload["results"][0]
    result.update(
        {
            "test_id": "SAME-SUBNET-TCP",
            "category": "same-subnet",
            "source": "zone-a/Endpoint A:A (172.20.4.20)",
            "destination": "zone-a/Endpoint B:B (172.20.4.30)",
            "scenario": "same-subnet",
        }
    )
    result["details"]["path"].update(
        {
            "source_category": "same-subnet",
            "source_ip": "172.20.4.20",
            "destination_ip": "172.20.4.30",
        }
    )
    result["details"]["probe"]["diagnostics"] = {}
    for subnet in payload["discovery"]["subnets"]:
        subnet["cidr"] = "172.20.4.0/22"
        subnet.pop("gateway_ip", None)
    for resource in payload["resources"]:
        if resource["resource_type"] == "subnet":
            resource["metadata"]["cidr"] = "172.20.4.0/22"
            resource["metadata"].pop("gateway_ip", None)

    model = build_dashboard_model(payload)
    assert "topology" not in model
    for path in model["paths"]:
        assert "topology" not in path
        assert "topology_label" not in path
        assert "topology_description" not in path
        assert "route_hops" not in path
        assert "route_text" not in path

    html = render_html(payload)
    report = _embedded_payload(html)
    path = report["dashboard"]["paths"][0]
    assert path["endpoint_pair"] == "172.20.4.20 → 172.20.4.30"
    assert not path["route_observations"]
    assert path["source_addressing"]["gateway_ip"] is None
    assert path["destination_addressing"]["gateway_ip"] is None
    assert "No route lookup was recorded for this endpoint pair." in html
    lowered = html.lower()
    assert "direct l2" not in lowered
    assert "direct l3" not in lowered
    assert "172.20.4.1" not in html


def test_canonical_aggregate_keeps_supporting_routes_and_endpoint_names():
    payload = _payload()
    supporting = payload["results"][0]
    aggregate = copy.deepcopy(supporting)
    aggregate.update(
        test_id="MIGRATION-BASELINE",
        display_name="Verify functional baseline before migration",
        category="compute-placement",
    )
    aggregate["details"]["probe"] = {}
    payload["results"].append(aggregate)
    payload["planned_check_ledger"] = [
        {
            "id": "BASELINE",
            "title": "Verify baseline",
            "kind": "migration",
            "stage": "migration",
            "condition": "Endpoints are ready",
            "outcome": "PASSED",
            "reason": "All protocol samples passed",
            "prerequisites": [],
            "result_id": aggregate["test_id"],
            "evidence_ids": [aggregate["test_id"], supporting["test_id"]],
        }
    ]

    report = _embedded_payload(render_html(payload))["dashboard"]

    assert len(report["results"]) == 1
    assert report["results"][0]["result_id"] == "MIGRATION-BASELINE"
    path = report["paths"][0]
    assert path["source"]["label"] == "Project network A A"
    assert path["destination"]["label"] == "Project network B B"
    assert path["route_observations"] == [
        {
            "observer": "Flux runner",
            "output": "10.0.4.107 via 10.0.3.97 dev ens3 src 10.0.3.107",
        }
    ]
    assert report["coverage"]["paths_with_route_observations"] == 1


def test_saved_structured_route_stdout_counts_as_observation():
    payload = _payload()
    payload["results"][0]["details"]["probe"] = {}
    payload["results"][0]["details"]["metrics"] = {
        "reverse": {
            "route": {
                "command": "ip -4 route get 10.0.3.107",
                "stdout": "10.0.3.107 via 10.0.4.97 dev ens4",
                "returncode": 0,
            }
        }
    }
    path = _embedded_payload(render_html(payload))["dashboard"]["paths"][0]
    assert path["route_observations"] == [
        {
            "observer": "Destination endpoint",
            "output": "ip -4 route get 10.0.3.107\n10.0.3.107 via 10.0.4.97 dev ens4",
        }
    ]


def test_resolution_only_checks_retain_exact_planner_execution_stage():
    payload = _payload()
    payload["results"] = []
    payload["plan"]["tests"] = [
        {
            "id": "FUNCTIONAL-SPEC",
            "metadata": {
                "check_bindings": {
                    "placement": {
                        "HOST-DISCOVERY": "PLACEMENT-CHECK",
                        "MIGRATION-BASELINE": "BASELINE-CHECK",
                    }
                }
            },
        }
    ]
    payload["planned_check_ledger"] = [
        {
            "id": identity,
            "title": identity,
            "kind": "migration",
            "stage": "migration",
            "condition": "The saved placement assertion is satisfied",
            "outcome": "PASSED",
            "reason": "Resolved from its recorded prerequisites",
            "prerequisites": [],
            "result_id": None,
            "evidence_ids": [],
        }
        for identity in ("PLACEMENT-CHECK", "BASELINE-CHECK")
    ]
    original = copy.deepcopy(payload)

    rows = _embedded_payload(render_html(payload))["dashboard"]["results"]

    assert [row["timing"] for row in rows] == [
        "Initial placement discovery",
        "Before migration",
    ]
    assert all(row["status"] == "PASS" for row in rows)
    assert payload == original


def test_removes_interpretive_evidence_labels():
    payload = _payload()
    result = payload["results"][0]
    result["details"]["metrics"] = {
        "actual_counter_delta": 3,
        "component_inference": {"label": "Direct L2 path"},
        "likely_failure": "gateway issue",
        "fragmentation_location_label": "suspected router",
    }
    report = _embedded_payload(render_html(payload))
    parsed = report["dashboard"]["results"][0]["evidence"]["parsed"]

    assert "actual_counter_delta" in parsed
    assert "component_inference" not in parsed
    assert "likely_failure" not in parsed
    assert "fragmentation_location_label" not in parsed
    assert "Direct L2" not in parsed


def test_neutralizes_interpretive_presentation_text_but_keeps_raw_output():
    payload = _payload()
    result = payload["results"][0]
    result.update(
        {
            "display_name": "Likely direct L2 path",
            "scenario": "Inferred topology",
            "message": "This appears to be a routed IP path.",
            "expected": "Presumably direct L3 forwarding.",
            "observed": "A reconstructed path was suggested.",
        }
    )
    result["details"]["probe"]["stdout"] = (
        "raw probe output containing the words direct L2"
    )

    report = _embedded_payload(render_html(payload))
    row = report["dashboard"]["results"][0]

    assert row["title"] == "Validation test 0001"
    assert row["scenario"] == "Routed project networks"
    assert row["message"] == ""
    assert row["expected"] == ""
    assert row["observed"] == ""
    assert row["evidence"]["stdout"] == (
        "raw probe output containing the words direct L2"
    )


def test_udp_finding_is_short_and_actionable():
    payload = _payload()
    prototype = copy.deepcopy(payload["results"][0])
    results = []
    for index in range(25):
        result = copy.deepcopy(prototype)
        result.update(
            {
                "test_id": f"UDP-QUALITY-{index:02d}",
                "category": "network-performance",
                "status": "UNVERIFIED",
                "display_name": "UDP application-delivery loss and jitter",
                "message": (
                    "application loss requires review; sender achievement was below "
                    "the attribution threshold; this deliberately repeated diagnostic "
                    "must not become a wall of finding text"
                ),
            }
        )
        result["details"].update(
            {
                "measurement": "udp",
                "metrics": {
                    "forward": [{"loss_pct": 42.1}],
                    "reverse": [{"loss_pct": 4.2}],
                },
            }
        )
        results.append(result)
    payload["results"] = results
    payload["performance"] = results

    report = _embedded_payload(render_html(payload))
    finding = next(
        row for row in report["dashboard"]["findings"] if row["root_key"] == "udp"
    )

    assert finding["result_count"] == 25
    assert len(finding["summary"]) < 360
    assert finding["summary"].count(";") <= 1
    assert "42.100%" in finding["summary"]
    assert finding["impact"]
    assert finding["evidence_completeness"] == "Partial"
    assert finding["evidence_summary"]
    assert finding["next_check"]
    assert len(finding["impact"]) < 260
    assert len(finding["next_check"]) < 300
