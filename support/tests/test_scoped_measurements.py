from __future__ import annotations

import xml.etree.ElementTree as ET
from types import SimpleNamespace

from neutron_flux.comparison import _index, compare_payloads
from neutron_flux.concurrent_load import ConcurrentLoadRunner
from neutron_flux.junit_report import build_junit
from neutron_flux.models import Plan, PlannedGroup, RuntimeGroup
from neutron_flux.resources import ResourceBuilder

from ._shared import endpoint


def _placement_result(scope: str, status: str) -> dict:
    return {
        "test_id": f"{scope.upper()}-PLACEMENT-MIGRATION-DIFFERENT",
        "category": "placement",
        "family": 4,
        "scenario": "Compute migration and placement lifecycle",
        "display_name": "Create different-host placement",
        "expected": "placement-achieved",
        "status": status,
        "details": {"execution_scope": scope, "availability_zone": scope},
    }


def test_comparison_keeps_placement_results_from_separate_az_scopes():
    indexed = _index(
        {
            "results": [
                _placement_result("az1", "PASS"),
                _placement_result("az2", "FAIL"),
            ]
        }
    )
    assert len(indexed) == 2
    assert {item["test_id"] for item in indexed.values()} == {
        "AZ1-PLACEMENT-MIGRATION-DIFFERENT",
        "AZ2-PLACEMENT-MIGRATION-DIFFERENT",
    }


def test_comparison_does_not_call_lost_execution_an_improvement():
    baseline = {
        "run": {"run_id": "before"},
        "results": [{"test_id": "T1", "status": "FAIL", "details": {}}],
        "summary": {},
        "cleanup": {},
    }
    candidate = {
        "run": {"run_id": "after"},
        "results": [{"test_id": "T1", "status": "SKIP", "details": {}}],
        "summary": {},
        "cleanup": {},
    }
    comparison = compare_payloads(baseline, candidate)
    assert comparison["entries"][0]["assessment"] == "regressed"

    candidate["results"][0]["status"] = "PASS"
    comparison = compare_payloads(baseline, candidate)
    assert comparison["entries"][0]["assessment"] == "improved"


def test_junit_uses_scoped_test_ids_as_unique_case_names():
    payload = {
        "run": {"run_id": "run", "started_at": "2026-01-01T00:00:00Z"},
        "results": [
            {
                **_placement_result("az1", "PASS"),
                "display_name": "Same friendly name",
                "duration_ms": 1,
            },
            {
                **_placement_result("az2", "PASS"),
                "display_name": "Same friendly name",
                "duration_ms": 1,
            },
        ],
        "cleanup": {"complete": True},
    }
    root = ET.fromstring(build_junit(payload))
    cases = root.findall("testcase")
    assert [item.attrib["name"] for item in cases] == [
        "AZ1-PLACEMENT-MIGRATION-DIFFERENT",
        "AZ2-PLACEMENT-MIGRATION-DIFFERENT",
    ]
    assert [item.attrib["classname"] for item in cases] == [
        "placement.az1",
        "placement.az2",
    ]


def test_fabric_summary_exposes_whether_pairs_reach_the_fabric():
    runs = [
        {
            "aggregate_mbps": 100.0,
            "median_pair_mbps": 100.0,
            "slowest_pair_mbps": 100.0,
            "fairness": 1.0,
            "idle_latency": {"p95_ms": 1.0, "loss_pct": 0.0},
            "loaded_latency": {"p95_ms": 2.0, "loss_pct": 0.0},
            "loaded_latency_ratio": 2.0,
            "loaded_udp": {"loss_pct": 0.0, "jitter_ms": 0.1},
            "retransmissions": 0,
        }
    ]
    pairs = [
        {
            "placement": "same-compute",
            "source_host": "compute1",
            "destination_host": "compute1",
            "availability_zone": "az1",
        },
        {
            "placement": "cross-compute",
            "source_host": "compute1",
            "destination_host": "compute2",
            "availability_zone": "az1",
        },
    ]
    level = ConcurrentLoadRunner._summarize_level(2, pairs, runs)
    assert level["cross_compute_pairs"] == 1
    assert level["same_compute_pairs"] == 1
    assert level["unknown_placement_pairs"] == 0
    assert level["unique_compute_hosts"] == ["compute1", "compute2"]


def test_fabric_pair_creation_updates_peak_endpoint_count(config_factory):
    base = PlannedGroup(
        id="provider-group",
        kind="provider",
        label="Provider",
        network_id="network",
        network_name="Provider",
        subnet_ids=["subnet"],
        families=[4],
    )

    def build_group(group, **kwargs):
        index = len(executor.builder.runtime_groups) + 1
        a = endpoint(f"a-{index}", "A")
        b = endpoint(f"b-{index}", "B")
        a.fixed_ips = {"subnet": f"192.0.2.{index * 2}"}
        b.fixed_ips = {"subnet": f"192.0.2.{index * 2 + 1}"}
        return RuntimeGroup(
            plan=group,
            network_id="network",
            network_name="Provider",
            subnet_ids=["subnet"],
            router_id=None,
            endpoints=[a, b],
            source_nat_enabled=None,
            fips={},
        )

    executor = SimpleNamespace(
        config=config_factory(fabric_scale_enabled=True, fabric_scale_pairs=[1, 2]),
        plan=Plan([base], [], {}, [], tests=[]),
        builder=SimpleNamespace(
            build_group=build_group,
            runtime_groups=[],
            stop_group_probes=lambda group_id: None,
        ),
        reporter=SimpleNamespace(),
        cleanup_manager=SimpleNamespace(cleanup_group=lambda group_id: True),
        logger=SimpleNamespace(section=lambda *args: None),
        peak_endpoints=0,
    )
    runner = ConcurrentLoadRunner(executor)
    runner._create_pairs(2)
    assert executor.peak_endpoints == 4


def test_live_continuity_tcp_is_paced_instead_of_saturating(config_factory):
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    code = builder._live_continuity_code(
        source_ip="192.0.2.10",
        destination_ip="192.0.2.11",
        family=4,
        stop_path="/tmp/stop",
        result_path="/tmp/result",
        maximum_seconds=60,
    )
    assert "interval=0.1" in code
    assert "tcp['target_mbps']" in code
    assert "next_send=time.monotonic()+interval" in code


def test_comparison_counts_executed_result_becoming_skipped_as_lost_coverage():
    from neutron_flux.comparison import compare_payloads

    baseline = {
        "run": {"run_id": "before"},
        "results": [
            {
                "test_id": "AZ1-TCP-1",
                "display_name": "TCP",
                "category": "connectivity",
                "status": "FAIL",
                "details": {"execution_scope": "az1"},
            }
        ],
    }
    candidate = {
        "run": {"run_id": "after"},
        "results": [
            {
                "test_id": "AZ1-TCP-1",
                "display_name": "TCP",
                "category": "connectivity",
                "status": "SKIP",
                "details": {"execution_scope": "az1"},
            }
        ],
    }

    comparison = compare_payloads(baseline, candidate)
    assert comparison["summary"]["lost_coverage"] == 1
    assert comparison["entries"][0]["assessment"] == "regressed"
