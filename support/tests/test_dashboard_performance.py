from __future__ import annotations

import copy
import re
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from neutron_flux.comparison import _apply_statistical_confidence
from neutron_flux.models import Endpoint
from neutron_flux.performance import (
    PerformancePath,
    PerformanceRunner,
    ResolvedPerformancePath,
)
from neutron_flux.performance_metrics import (
    _confidence_interval_95,
    _parse_ping,
    _tukey_outliers,
)
from neutron_flux.reporting_components.dashboard_model import build_dashboard_model
from neutron_flux.reporting_components.html import render_html
from support.tests.test_offline_reports_and_concurrent_load import _payload


def _endpoint(label: str, side: str, host: str, address: str) -> Endpoint:
    return Endpoint(
        label=label,
        server_id=f"server-{label}",
        server_name=f"server-{label}",
        management_port_id=f"management-{label}",
        management_ip="10.254.0.10" if side == "A" else "10.254.0.11",
        test_port_id=f"test-{label}",
        test_mac="fa:16:3e:00:00:01",
        fixed_ips={"subnet": address},
        host=host,
        availability_zone="az1" if host == "compute1" else "az2",
        volume_id=None,
        side=side,
    )


def _resolved_path() -> ResolvedPerformancePath:
    plan = PerformancePath(
        path_id="SAMPLE-PERFORMANCE-PATH",
        source_spec_id="PROVIDER-PERFORMANCE",
        category="provider-network-connectivity",
        family=4,
        source_group_id="provider-public1",
        destination_group_id="provider-public1",
        source_side="A",
        destination_side="B",
        source_subnet_id="subnet-public1",
        destination_subnet_id="subnet-public1",
        stage="host-qualification",
    )
    return ResolvedPerformancePath(
        plan,
        _endpoint("source", "A", "compute1", "192.0.2.10"),
        _endpoint("destination", "B", "compute2", "192.0.2.11"),
        "192.0.2.10",
        "192.0.2.11",
        1500,
        1500,
        "cross-compute",
        "cross-az",
    )


def _dashboard_payload() -> dict:
    payload = _payload("execution-dashboard", status="FAIL")
    failures = []
    for index in (1, 2):
        result = copy.deepcopy(payload["results"][0])
        result.update(
            {
                "test_id": f"HOST-QUALIFICATION-FAILURE-{index}",
                "display_name": f"Host qualification failure {index}",
                "status": "FAIL",
                "message": "Provider path did not meet the expected contract",
                "expected": "reachable with expected performance",
                "observed": "packet loss and reduced throughput",
                "authoritative": True,
            }
        )
        result["details"] = {
            **result["details"],
            "host_qualification_pair_id": "HQ-PAIR-COMPUTE1-COMPUTE2",
            "host_qualification_cycle": index,
            "network_id": "network-public1",
            "network_name": "Public1",
            "direction": "compute1-to-compute2",
            "measurement": "tcp-throughput",
            "authority": "guest dataplane measurement",
            "command": "sanitized-probe-command",
            "path": {
                **result["details"]["path"],
                "source_compute_host": "compute1",
                "destination_compute_host": "compute2",
                "source_availability_zone": "az1",
                "destination_availability_zone": "az2",
                "source_network": "Public1",
                "destination_network": "Public1",
                "source_subnet_id": "subnet-public1",
                "destination_subnet_id": "subnet-public1",
                "source_category": "provider-network-connectivity",
                "direction": "forward",
            },
        }
        failures.append(result)
    payload["results"] = failures
    payload["performance"] = failures
    payload["summary"]["counts"] = {"FAIL": 2}
    payload["summary"]["categories"] = {"network-performance": {"FAIL": 2}}
    payload["plan_approval"] = {
        "fingerprint": "a" * 64,
        "verified": True,
        "source": "approved-plan.json",
    }
    payload["capabilities"] = {"blockers": []}
    payload["discovery"] = {
        "cloud": "recorded-openstack",
        "project_id": "project-sample",
        "project_name": "SAMPLE qualification",
    }
    payload["plan"] = {
        "host_qualification": {
            "enabled": True,
            "strategy": "rolling",
            "inventory_fingerprint": "b" * 64,
            "hosts": [
                {
                    "host": "compute1",
                    "availability_zone": "az1",
                    "aggregate_names": ["aggregate-west"],
                },
                {
                    "host": "compute2",
                    "availability_zone": "az2",
                    "aggregate_names": ["aggregate-east"],
                },
            ],
            "pairs": [
                {
                    "pair_id": "HQ-PAIR-COMPUTE1-COMPUTE2",
                    "source_host": "compute1",
                    "destination_host": "compute2",
                    "source_availability_zone": "az1",
                    "destination_availability_zone": "az2",
                    "same_host": False,
                    "same_availability_zone": False,
                }
            ],
        }
    }
    payload["coverage_ledger"] = [
        {
            "test_id": "HOST-QUALIFICATION-FAILURE-1",
            "title": "Cycle 1",
            "category": "network-performance",
            "phase": "host-qualification",
            "outcome": "FAILED",
            "reason": "measurement failed",
            "host_pair_id": "HQ-PAIR-COMPUTE1-COMPUTE2",
            "cycle": 1,
        },
        {
            "test_id": "HOST-QUALIFICATION-FAILURE-2",
            "title": "Cycle 2",
            "category": "network-performance",
            "phase": "host-qualification",
            "outcome": "BLOCKED",
            "reason": "performance prerequisite blocked",
            "host_pair_id": "HQ-PAIR-COMPUTE1-COMPUTE2",
            "cycle": 2,
        },
        {
            "test_id": "IPV6-PROVIDER-PATH",
            "title": "IPv6 provider path",
            "category": "provider-connectivity",
            "phase": "host-qualification",
            "outcome": "NEVER_RAN",
            "reason": "run cancelled after failure",
        },
    ]
    payload["events"] = [
        {
            "timestamp": "2026-07-22T00:00:05+00:00",
            "type": "server-ready",
            "message": "Endpoint became ready",
            "details": {"server_id": "server-source"},
        },
        {
            "timestamp": "2026-07-22T00:00:20+00:00",
            "type": "dataplane-settlement",
            "message": "Port binding converged",
            "details": {"port_id": "test-source"},
        },
    ]
    payload["resources"] = [
        {
            "sequence": 1,
            "resource_type": "server",
            "name": "execution-endpoint-a",
            "created_at": "2026-07-22T00:00:02+00:00",
            "deleted_at": "2026-07-22T00:00:50+00:00",
            "cleanup_state": "DELETED",
            "metadata": {
                "role": "endpoint",
                "endpoint_side": "A",
                "availability_zone": "az1",
                "requested_host": "compute1",
            },
        }
    ]
    return payload


def _script(html: str) -> str:
    return "\n".join(
        body
        for attributes, body in re.findall(
            r"<script([^>]*)>(.*?)</script>",
            html,
            re.S | re.I,
        )
        if "application/json" not in attributes.lower() and body.strip()
    )


def _tcp_run(mbps: float) -> dict:
    return {
        "streams": 1,
        "mbps": mbps,
        "retransmissions": 0,
        "intervals_mbps": [mbps - 1, mbps + 1],
        "client_mss": 1460,
        "server_mss": 1460,
    }


def test_dashboard_model_exposes_command_coverage_and_fault_domains():
    model = build_dashboard_model(_dashboard_payload())

    assert model["command_centre"]["plan_fingerprint"] == "a" * 64
    assert model["command_centre"]["plan_verified"] is True
    assert model["command_centre"]["coverage"]["never_ran"] == 2
    assert model["command_centre"]["coverage"]["blocked"] == 1
    assert model["coverage_matrix"]["outcomes"] == {
        "FAILED": 1,
        "BLOCKED": 1,
        "NEVER_RAN": 1,
    }
    assert model["coverage_matrix"]["complete"] is False
    assert model["correlated_fault_domains"]
    dimensions = {
        (row["dimension"], row["value"]) for row in model["correlated_fault_domains"]
    }
    assert ("host", "compute1") in dimensions
    assert ("network", "Public1") in dimensions
    assert model["baseline_comparison"]["runs_entirely_in_browser"] is True
    assert model["virtualization"] == {
        "result_window": 200,
        "matrix_window": 250,
    }


def test_dashboard_avoids_duplicating_raw_evidence_and_keeps_pair_dimensions():
    model = build_dashboard_model(_dashboard_payload())

    assert "evidence" not in model["results"][0]
    assert "details" not in model["results"][0]
    pair = model["host_qualification"]["pairs"][0]
    assert pair["networks"] == ["Public1", "network-public1"]
    assert pair["test_types"] == ["tcp-throughput"]
    assert pair["topologies"] == ["provider-network-connectivity"]
    assert pair["completed_cycles"] == [1, 2]


def test_dashboard_omits_topology_workspace_and_keeps_lifecycle_timeline():
    model = build_dashboard_model(_dashboard_payload())
    assert "topology_workspace" not in model
    kinds = {row["kind"] for row in model["lifecycle_timeline"]}
    assert {
        "server-ready",
        "dataplane-settlement",
        "server-created",
        "server-deleted",
        "test-result",
    }.issubset(kinds)


def test_setup_failure_capabilities_do_not_collide_with_zone_inventory():
    payload = _dashboard_payload()
    payload["results"] = []
    payload["performance"] = []
    payload["events"] = [
        {
            "timestamp": "2026-07-22T00:00:00+00:00",
            "type": "availability-zone-scope-validated",
            "message": "zone inventory",
            "details": {
                "capabilities": {
                    "az1": {
                        "enabled_hosts": ["compute1"],
                        "migration_cohort_size": 1,
                    }
                }
            },
        },
        {
            "timestamp": "2026-07-22T00:00:01+00:00",
            "type": "setup-failed",
            "message": "capability preflight blocked resource creation",
            "details": {
                "capabilities": {
                    "generated_at": "2026-07-22T00:00:01Z",
                    "checks": [],
                    "counts": {"PASS": 4, "FAIL": 1},
                    "blockers": ["neutron-port-binding-visibility"],
                    "complete": False,
                }
            },
        },
    ]

    model = build_dashboard_model(payload)

    assert model["environment"]["zones"] == ["az1", "az2"]
    assert {row["full_name"] for row in model["environment"]["hosts"]} == {
        "compute1",
        "compute2",
    }
    assert "generated_at" not in model["environment"]["zones"]
    assert "counts" not in model["environment"]["zones"]
    assert "<!doctype html>" in render_html(payload).lower()


def test_self_contained_html_has_interactive_workspaces(tmp_path: Path):
    html = render_html(_dashboard_payload())

    for marker in (
        "Run overview",
        "Run scope and limits",
        "Coverage by test suite",
        "Technical path evidence",
        "Tests and coverage",
        "Evidence and technical identity",
        "Performance summary",
        "Full technical evidence",
    ):
        assert marker in html
    script = tmp_path / "execution-dashboard.js"
    script.write_text(_script(html), encoding="utf-8")
    subprocess.run(["node", "--check", str(script)], check=True, capture_output=True)


def test_tcp_warmup_is_excluded_from_all_configured_samples(monkeypatch):
    runner = object.__new__(PerformanceRunner)
    runner.config = SimpleNamespace(
        performance_repeats=4,
        performance_tcp_streams=[1, 4],
    )
    samples = iter(
        [
            _tcp_run(5),
            _tcp_run(20),
            _tcp_run(30),
            _tcp_run(40),
            _tcp_run(50),
            _tcp_run(100),
        ]
    )
    monkeypatch.setattr(runner, "_tcp_upload", lambda *args, **kwargs: next(samples))

    result = runner._tcp_direction(
        _endpoint("source", "A", "compute1", "192.0.2.10"),
        "192.0.2.10",
        "192.0.2.11",
        4,
    )

    single = result["streams"]["1"]
    assert result["warmup"]["mbps"] == 5
    assert [row["mbps"] for row in result["repeats"]] == [20, 30, 40, 50]
    assert single["median_mbps"] == 35
    assert single["confidence_95_mbps"]["sample_count"] == 4
    assert single["warmup_samples"] == 1
    assert result["streams"]["4"]["median_mbps"] == 100


def test_udp_reports_offered_and_achieved_rates(monkeypatch):
    runner = object.__new__(PerformanceRunner)
    runner.config = SimpleNamespace(
        performance_udp_packet_sizes=[64],
        performance_udp_rates_mbps=[100],
    )
    monkeypatch.setattr(
        runner,
        "_udp_measurement",
        lambda *args, **kwargs: {"mbps": 80.0, "loss_pct": 1.0},
    )

    result = runner._udp_matrix(_resolved_path())

    samples = result["forward"] + result["reverse"]
    assert len(samples) == 4
    assert {sample["packet_size"] for sample in samples} == {64, 1472}
    assert all(sample["offered_mbps"] == 100 for sample in samples)
    assert all(sample["achieved_mbps"] == 80 for sample in samples)
    assert all(sample["offered_achievement_pct"] == 80 for sample in samples)


def test_small_sample_confidence_and_outliers_are_explicit():
    interval = _confidence_interval_95([10, 12, 14, 16])
    outliers = _tukey_outliers([10, 10, 11, 11, 12, 100])
    ping = _parse_ping(
        0,
        (
            "4 packets transmitted, 4 received, 0% packet loss\n"
            "64 bytes: time=1.0 ms\n64 bytes: time=1.2 ms\n"
            "64 bytes: time=1.4 ms\n64 bytes: time=1.6 ms"
        ),
        "",
    )

    assert interval["sample_count"] == 4
    assert interval["lower"] < interval["mean"] < interval["upper"]
    assert outliers["values"] == [100.0]
    assert ping["confidence_95_ms"]["sample_count"] == 4
    assert ping["outliers_ms"]["method"] == "tukey-1.5-iqr"


@pytest.mark.parametrize(
    ("candidate", "expected_assessment", "expected_statistical"),
    [
        (
            {"lower": 85, "upper": 105},
            "unchanged",
            "inconclusive-overlap",
        ),
        (
            {"lower": 60, "upper": 80},
            "regressed",
            "significant-regression",
        ),
    ],
)
def test_baseline_comparison_uses_confidence_intervals(
    candidate,
    expected_assessment,
    expected_statistical,
):
    change = _apply_statistical_confidence(
        {"assessment": "regressed"},
        {"lower": 90, "upper": 110},
        candidate,
        "higher",
    )

    assert change["assessment"] == expected_assessment
    assert change["statistical_assessment"] == expected_statistical
