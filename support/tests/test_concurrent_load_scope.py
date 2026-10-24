from __future__ import annotations

from types import SimpleNamespace

from neutron_flux.cli import parser
from neutron_flux.concurrent_load import ConcurrentLoadRunner
from neutron_flux.models import Plan
from neutron_flux.mtu_contract import classify_fragmentation_location
from neutron_flux.performance import PerformanceRunner
from neutron_flux.reporting_components.dashboard_model import (
    _safe_fragmentation_view,
)


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


def _counters(*, fragments: int = 0, reassemblies: int = 0) -> dict:
    return {
        "family": 4,
        "available": True,
        "source": "/proc/net/snmp",
        "counters": {
            "FragCreates": fragments,
            "ReasmOKs": reassemblies,
        },
        "error": None,
    }


def test_performance_priority_treats_canonical_and_legacy_categories_equally():
    assert (
        PerformanceRunner.CATEGORY_PRIORITY["project-network-routing"]
        == PerformanceRunner.CATEGORY_PRIORITY["tenant-router"]
    )
    assert (
        PerformanceRunner.CATEGORY_PRIORITY["project-provider-connectivity"]
        == PerformanceRunner.CATEGORY_PRIORITY["tenant-provider-connectivity"]
    )


def test_concurrent_load_records_only_observed_cross_az_scope():
    run = {
        "aggregate_mbps": 200.0,
        "median_pair_mbps": 100.0,
        "slowest_pair_mbps": 100.0,
        "fairness": 1.0,
        "idle_latency": {"p95_ms": 1.0, "loss_pct": 0.0},
        "loaded_latency": {"p95_ms": 2.0, "loss_pct": 0.0},
        "loaded_latency_ratio": 2.0,
        "loaded_udp": {"loss_pct": 0.0, "jitter_ms": 0.1},
    }
    pairs = [
        {
            "pair_index": 1,
            "compute_placement": "cross-compute",
            "source_host": "compute-a",
            "destination_host": "compute-b",
            "source_availability_zone": "az-a",
            "destination_availability_zone": "az-b",
        }
    ]
    level = ConcurrentLoadRunner._summarize_level(1, pairs, [run])
    placement = level["placements"][0]
    assert placement["source_availability_zone"] == "az-a"
    assert placement["destination_availability_zone"] == "az-b"
    assert placement["availability_zone_placement"] == "cross-availability-zone"
    assert level["cross_availability_zone_pairs"] == 1
    assessment = ConcurrentLoadRunner._placement_assessment(level)
    assert assessment["scope"] == "cross-availability-zone-only"
    assert assessment["availability_zone_scope"] == "cross-availability-zone-only"
    assert assessment["authoritative"] is True

    same_az = {
        **level,
        "cross_availability_zone_pairs": 0,
        "same_availability_zone_pairs": 1,
    }
    assessment = ConcurrentLoadRunner._placement_assessment(same_az)
    assert assessment["scope"] == "inter-compute-only"
    assert assessment["cross_availability_zone_pairs"] == 0

    mixed = {
        **level,
        "same_availability_zone_pairs": 1,
    }
    assert ConcurrentLoadRunner._placement_assessment(mixed)["scope"] == "mixed"


def test_concurrent_load_error_is_non_authoritative(config_factory, monkeypatch):
    recorded = []
    plan = Plan([], [], {}, [], tests=[])
    executor = SimpleNamespace(
        config=config_factory(
            action="run",
            fabric_scale_enabled=True,
            fabric_scale_pairs=[1],
        ),
        plan=plan,
        builder=SimpleNamespace(
            discovery=SimpleNamespace(),
            runtime_groups=[],
            stop_group_probes=lambda group_id: None,
        ),
        reporter=SimpleNamespace(
            scope="az1",
            result=lambda test_id, category, status, message, **kwargs: recorded.append(
                SimpleNamespace(status=status, message=message, **kwargs)
            ),
        ),
        cleanup_manager=SimpleNamespace(cleanup_group=lambda group_id: True),
        logger=SimpleNamespace(section=lambda message: None),
        active={},
        _append_runtime_specs=lambda specs: plan.tests.extend(specs),
        _refresh_checkpoint=lambda: None,
    )
    runner = ConcurrentLoadRunner(executor)
    monkeypatch.setattr(
        runner,
        "_create_pairs",
        lambda count: (_ for _ in ()).throw(RuntimeError("injected error")),
    )
    runner.run()
    result = recorded[-1]
    assert result.status == "ERROR"
    assert result.authoritative is False
    assert result.details["execution_status"] == "error"
    assert result.details["contract_verdict"] == "not-evaluated"
    assert result.details["path_health"]["status"] == "not-assessed"


def test_endpoint_counters_do_not_become_direct_ovn_component_evidence():
    profile = {
        "family": 4,
        "capability": "supported",
        "fragmentation_permitted": {"counts": {"success": 3}},
        "source_fragment_counters": {
            "before": _counters(),
            "after_permitted": _counters(),
        },
    }
    result = classify_fragmentation_location(
        profile,
        destination_before=_counters(reassemblies=10),
        destination_after=_counters(reassemblies=13),
        router_ids=["router-one"],
        router_backend_evidence={"backend": "ovn", "confirmed": True},
    )
    assert result["fragmentation_location"] == "in-path"
    assert result["in_path_fragmentation_observed"] is False
    assert result["in_path_fragmentation_inferred"] is True
    assert "inferred" in result["fragmentation_location_label"].lower()
    assert result["component_attribution_directly_observed"] is False
    assert result["ovn_router_fragmentation_observed"] is None
    assert result["component_inference"]["component"] == (
        "ovn-backed-neutron-router-path"
    )
    assert result["component_inference"]["directly_observed"] is False


def test_dashboard_rejects_unsubstantiated_direct_component_attribution():
    sanitized = _safe_fragmentation_view(
        {
            "fragmentation_location": "in-path",
            "component_attribution_directly_observed": True,
            "router_fragmentation_observed": True,
            "ovn_router_fragmentation_observed": True,
            "component_inference": {
                "component": "ovn-logical-router",
                "directly_observed": True,
            },
        }
    )

    assert sanitized["component_attribution_directly_observed"] is False
    assert "component_inference" not in sanitized
    assert sanitized["router_fragmentation_observed"] is None
    assert sanitized["ovn_router_fragmentation_observed"] is None
