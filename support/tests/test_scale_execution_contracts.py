from __future__ import annotations

import itertools
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from neutron_flux.concurrent_load import ConcurrentLoadRunner
from neutron_flux.errors import RunCancelledError
from neutron_flux.host_qualification import HostQualificationPlanner
from neutron_flux.models import Plan, PlannedGroup
from neutron_flux.models import TestSpec as Spec
from neutron_flux.pair_suite import estimate_pair_suite, expand_pair_suite
from neutron_flux.pair_workflow import workflow_plans
from neutron_flux.planning import Planner
from neutron_flux.scheduling import bounded_map
from neutron_flux.translation_safety import floating_ip_target_sides
from support.tests.test_host_qualification import _Inventory, _service


@pytest.mark.parametrize("order", list(itertools.permutations((1, 2, 4))))
def test_scaling_reference_is_lowest_requested_level_regardless_of_order(order):
    levels = [
        {"pairs": count, "median_pair_mbps": {1: 100, 2: 90, 4: 75}[count]}
        for count in order
    ]
    comparison = ConcurrentLoadRunner._attach_level_comparisons(levels)
    assert comparison == {
        "mode": "one-pair-baseline",
        "baseline_pairs": 1,
        "one_pair_baseline_present": True,
    }
    by_count = {level["pairs"]: level for level in levels}
    assert by_count[1]["comparison_baseline_pairs"] is None
    assert by_count[2]["comparison_baseline_pairs"] == 1
    assert by_count[4]["comparison_baseline_pairs"] == 1
    assert by_count[2]["per_pair_degradation_pct"] == 10
    assert by_count[4]["per_pair_degradation_pct"] == 25


def test_scaling_without_one_pair_uses_actual_lowest_requested_level():
    levels = [
        {"pairs": 8, "median_pair_mbps": 60},
        {"pairs": 2, "median_pair_mbps": 100},
        {"pairs": 4, "median_pair_mbps": 80},
    ]
    comparison = ConcurrentLoadRunner._attach_level_comparisons(levels)
    assert comparison["mode"] == "lowest-requested-level"
    assert comparison["baseline_pairs"] == 2
    assert comparison["one_pair_baseline_present"] is False
    assert levels[0]["per_pair_degradation_pct"] == 40
    assert levels[1]["comparison_baseline_pairs"] is None
    assert levels[2]["per_pair_degradation_pct"] == 20


def test_workflow_partition_does_not_rescan_dependencies_for_unrelated_groups():
    scans = []

    class Dependencies(list):
        def __iter__(self):
            scans.append(len(self))
            return super().__iter__()

    providers = [SimpleNamespace(id=f"provider-{index}") for index in range(128)]
    tenants = [SimpleNamespace(id=f"tenant-{index}") for index in range(128)]
    specs = [
        Spec(
            f"probe-{index}",
            "same-subnet",
            "probe",
            4,
            "reachable",
            "declared",
            True,
            Dependencies(["tenant-12", "provider-24", "provider-3"]),
            metadata={"workflow_batch": f"batch-{index}"},
        )
        for index in range(16)
    ]
    lanes = workflow_plans(Plan(providers, tenants, {}, [], tests=specs))
    assert len(lanes) == len(specs)
    assert len(scans) <= len(specs) * 2
    for index, lane in enumerate(lanes):
        assert lane.provider_groups == [providers[3], providers[24]]
        assert lane.tenant_groups == [tenants[12]]
        assert lane.provider_groups[0] is providers[3]
        assert lane.tests == [specs[index]]


def test_floating_owner_estimate_preserves_both_sides_without_repeated_scans(
    config_factory, monkeypatch
):
    groups = [
        PlannedGroup(f"group-{index}", "tenant", f"Group {index}", None, None, [], [4])
        for index in range(16)
    ]
    tests = [
        Spec(
            f"fip-{index}",
            "floating-ip",
            "fip-peer",
            4,
            "reachable",
            "owned floating mapping",
            True,
            [groups[index % 16].id],
            source_group_id=groups[index % 16].id,
            destination_group_id=groups[index % 16].id,
            source_side="A" if index < 32 else "B",
            destination_side="A" if index < 32 else "B",
            phase="intra",
        )
        for index in range(64)
    ]
    scans = []

    def counted(spec):
        scans.append(spec.id)
        return floating_ip_target_sides(spec)

    monkeypatch.setattr(
        "neutron_flux.planner_components.estimates.floating_ip_target_sides", counted
    )
    estimate = Planner(config_factory(), SimpleNamespace(), Mock())._execution_estimate(
        tests, groups
    )
    assert estimate["fip_group_generations"] == 32
    assert estimate["group_loads"] == 16
    assert estimate["endpoint_vm_boots"] == 32
    assert len(scans) <= len(tests) * 2


def test_explicit_hosts_and_aggregate_resolve_union_once(
    config_factory, discovery_fixture
):
    config = config_factory(
        target_hosts=["compute-a", "compute-b"],
        target_aggregates=["selected"],
        qualification_strategy="rolling",
    )
    plan = Planner(config, discovery_fixture, Mock()).build()
    inventory = _Inventory(
        [_service(host, "az1") for host in ("compute-a", "compute-b", "compute-c")],
        aggregates=[
            {"id": "agg", "name": "selected", "hosts": ["compute-b", "compute-c"]}
        ],
    )
    scope = HostQualificationPlanner(
        config, discovery_fixture, plan, inventory, Mock()
    ).build()
    assert scope is not None
    assert {host.host for host in scope.hosts} == {
        "compute-a",
        "compute-b",
        "compute-c",
    }
    assert {
        frozenset((pair.source_host, pair.destination_host)) for pair in scope.pairs
    } == {
        frozenset(pair)
        for pair in itertools.combinations(("compute-a", "compute-b", "compute-c"), 2)
    }


@pytest.mark.parametrize("scope", ["same-host", "same-az", "cross-az"])
def test_exact_pair_scope_has_only_permitted_transition(
    config_factory, discovery_fixture, scope
):
    second = "compute-a" if scope == "same-host" else "compute-b"
    config = config_factory(
        target_host_pairs=[("compute-a", second)],
        qualification_strategy="rolling",
    )
    planner = Planner(config, discovery_fixture, Mock())
    base = planner.build()
    services = [_service("compute-a", "az1")]
    if second != "compute-a":
        services.append(_service(second, "az2" if scope == "cross-az" else "az1"))
    base.host_qualification = HostQualificationPlanner(
        config, discovery_fixture, base, _Inventory(services), Mock()
    ).build()
    plan = expand_pair_suite(base)
    estimate_pair_suite(planner, plan)
    lanes = workflow_plans(plan)
    assert lanes
    for lane in lanes:
        slots = {test.metadata["pair_placement"] for test in lane.tests}
        assert slots == (
            {"initial"} if scope == "same-host" else {"initial", "opposite"}
        )
        assert sum(test.operation == "pair-transition" for test in lane.tests) == (
            0 if scope == "same-host" else 1
        )
    assert plan.estimated["peak_endpoint_instances"] == 2
    if scope != "same-az":
        assert plan.estimated["targeted_migrations_maximum"] == 0


@pytest.mark.parametrize("stage", ["build", "measurement"])
def test_concurrent_load_cancellation_propagates_and_releases_pairs(
    config_factory, monkeypatch, stage
):
    recorded = []
    plan = Plan([], [], {}, [])
    config = config_factory(fabric_scale_enabled=True, fabric_scale_pairs=[1])
    runner = ConcurrentLoadRunner(
        SimpleNamespace(
            config=config,
            plan=plan,
            builder=SimpleNamespace(discovery=SimpleNamespace()),
            reporter=SimpleNamespace(
                result=lambda *args, **kwargs: recorded.append((args, kwargs))
            ),
            cleanup_manager=SimpleNamespace(),
            logger=SimpleNamespace(section=lambda message: None),
            _append_runtime_specs=lambda specs: plan.tests.extend(specs),
        )
    )
    cleanup = Mock()
    monkeypatch.setattr(runner, "_cleanup_runtimes", cleanup)
    monkeypatch.setattr(
        "neutron_flux.concurrent_load.TestEngine", lambda *args: object()
    )
    monkeypatch.setattr(
        "neutron_flux.concurrent_load.PerformanceRunner", lambda *args: object()
    )

    def cancel(*args):
        raise RunCancelledError("requested interruption")

    monkeypatch.setattr(
        runner, "_create_pairs", cancel if stage == "build" else lambda count: [{}]
    )
    monkeypatch.setattr(runner, "_traffic_run", cancel)
    with pytest.raises(RunCancelledError, match="requested interruption"):
        runner.run()
    assert recorded == []
    cleanup.assert_called_once()


@pytest.mark.parametrize("count", [1, 2, 8, 32])
def test_all_requested_pair_clients_overlap_during_loaded_quality(
    config_factory, count
):
    config = config_factory(
        fabric_scale_enabled=True,
        fabric_scale_pairs=[count],
        fabric_scale_duration_seconds=3,
        performance_udp_rates_mbps=[10],
        performance_udp_packet_sizes=[128],
    )
    runner = ConcurrentLoadRunner(
        SimpleNamespace(
            config=config,
            plan=Plan([], [], {}, []),
            builder=SimpleNamespace(),
            reporter=SimpleNamespace(),
            cleanup_manager=SimpleNamespace(),
            logger=SimpleNamespace(),
        )
    )
    lock = threading.Lock()
    clean_wave = threading.Barrier(count)
    load_ready = threading.Event()
    load_release = threading.Event()
    state = {"tcp_calls": 0, "ping_calls": 0, "tcp": 0, "udp": 0, "ping": 0}
    observations = []

    class Performance:
        def _tcp_upload(self, *args, **kwargs):
            with lock:
                state["tcp_calls"] += 1
                loaded = state["tcp_calls"] > count * 2
                if loaded:
                    state["tcp"] += 1
                    if state["tcp"] == state["udp"] == count:
                        load_ready.set()
            if loaded:
                assert load_release.wait(5)
            else:
                clean_wave.wait(5)
            return {"mbps": 100.0, "bytes": 1_000_000, "elapsed_s": 1.0}

        def _udp_measurement(self, *args, **kwargs):
            with lock:
                state["udp"] += 1
                if state["tcp"] == state["udp"] == count:
                    load_ready.set()
            assert load_release.wait(5)
            return {
                "mbps": 10.0,
                "sender_mbps": 10.0,
                "loss_pct": 0.0,
                "jitter_ms": 0.1,
            }

        def _ping(self, *args):
            with lock:
                state["ping_calls"] += 1
                loaded = state["ping_calls"] > count
            if loaded:
                assert load_ready.wait(5)
                with lock:
                    observations.append((state["tcp"], state["udp"]))
                    state["ping"] += 1
                    if state["ping"] == count:
                        load_release.set()
            return {"p95_ms": 2.0 if loaded else 1.0, "loss_pct": 0.0}

    pairs = [
        {
            "pair_index": index + 1,
            "source": object(),
            "destination": object(),
            "source_ip": f"192.0.2.{index * 2 + 1}",
            "destination_ip": f"192.0.2.{index * 2 + 2}",
            "family": 4,
        }
        for index in range(count)
    ]
    measurement = runner._traffic_run(Performance(), pairs)
    assert observations == [(count, count)] * count
    assert len(measurement["loaded_latency_by_pair"]) == count
    assert len(measurement["loaded_udp_by_pair"]) == count
    assert measurement["loaded_tcp_aggregate_mbps"] == 100 * count
    assert measurement["aggregate_mbps"] == 100 * count


@pytest.mark.parametrize("count", [1, 8, 32, 256])
def test_bounded_execution_keeps_admission_limit_and_exact_result_order(count):
    lock = threading.Lock()
    state = {"active": 0, "peak": 0}
    seen = []

    def operation(value):
        with lock:
            state["active"] += 1
            state["peak"] = max(state["peak"], state["active"])
            seen.append(value)
        try:
            return value * 2
        finally:
            with lock:
                state["active"] -= 1

    assert bounded_map(operation, range(count), workers=8) == [
        value * 2 for value in range(count)
    ]
    assert sorted(seen) == list(range(count))
    assert 1 <= state["peak"] <= min(count, 8)
    assert state["active"] == 0
