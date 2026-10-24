from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from neutron_flux.comparison import _index
from neutron_flux.concurrent_load import ConcurrentLoadRunner
from neutron_flux.models import ComputeHostInfo, MigrationResult, Plan
from neutron_flux.resources import ResourceBuilder
from neutron_flux.trends import trend_payload

from ._evidence import data_route
from ._shared import _placement_executor, endpoint


def _performance_result(
    scope: str, *, health: str = "good", mbps: float = 100.0
) -> dict:
    return {
        "test_id": f"{scope.upper()}-PERF-TCP",
        "category": "network-performance",
        "status": "PASS",
        "family": 4,
        "source": f"{scope}/vm-a",
        "destination": f"{scope}/vm-b",
        "details": {
            "performance": True,
            "measurement": "tcp-throughput",
            "health": health,
            "execution_scope": scope,
            "availability_zone": scope,
            "path": {
                "execution_scope": scope,
                "source_category": "tenant-routing",
                "placement": "cross-compute",
                "availability_scope": "same-az",
                "stage": "group-local",
                "source_group_id": "tenant-a",
                "destination_group_id": "tenant-a",
                "source_availability_zone": scope,
                "destination_availability_zone": scope,
                "source_label": "vm-a",
                "destination_label": "vm-b",
            },
            "metrics": {
                "forward": {"streams": {"1": {"median_mbps": mbps}}},
                "reverse": {"streams": {"1": {"median_mbps": mbps}}},
            },
        },
    }


def test_comparison_keeps_performance_results_from_separate_az_scopes():
    payload = {
        "results": [
            _performance_result("az1", mbps=100.0),
            _performance_result("az2", mbps=200.0),
        ]
    }
    indexed = _index(payload)
    assert len(indexed) == 2
    assert {item["test_id"] for item in indexed.values()} == {
        "AZ1-PERF-TCP",
        "AZ2-PERF-TCP",
    }


def test_comparison_duplicate_selection_keeps_warning_evidence():
    good = _performance_result("az1", health="good")
    warning = _performance_result("az1", health="warning")
    warning["test_id"] = good["test_id"]
    indexed = _index({"results": [good, warning]})
    assert len(indexed) == 1
    assert next(iter(indexed.values()))["details"]["health"] == "warning"


def test_trend_sorting_respects_timezone_offsets(tmp_path: Path):
    earlier = {
        "schema_version": 1,
        "run": {
            "run_id": "earlier",
            "started_at": "2026-01-01T01:00:00+01:00",
            "final_status": "PASS",
        },
        "summary": {"counts": {}},
        "results": [],
        "cleanup": {"complete": True},
    }
    later = {
        "schema_version": 1,
        "run": {
            "run_id": "later",
            "started_at": "2026-01-01T00:30:00+00:00",
            "final_status": "PASS",
        },
        "summary": {"counts": {}},
        "results": [],
        "cleanup": {"complete": True},
    }
    paths = []
    for name, payload in (("later", later), ("earlier", earlier)):
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        paths.append(path)
    trend = trend_payload(paths)
    assert [item["run_id"] for item in trend["runs"]] == ["earlier", "later"]


def test_fabric_unexpected_error_preserves_completed_levels(
    config_factory, monkeypatch
):
    config = config_factory(
        action="run",
        fabric_scale_enabled=True,
        fabric_scale_pairs=[1, 2],
        fabric_scale_runs=1,
    )
    recorded = []
    plan = Plan([], [], {}, [], tests=[])
    builder = SimpleNamespace(
        discovery=SimpleNamespace(),
        runtime_groups=[],
        stop_group_probes=lambda group_id: None,
    )
    reporter = SimpleNamespace(
        scope="az1",
        result=lambda test_id, category, status, message, **kwargs: recorded.append(
            SimpleNamespace(
                test_id=test_id,
                category=category,
                status=status,
                message=message,
                **kwargs,
            )
        ),
    )
    executor = SimpleNamespace(
        config=config,
        plan=plan,
        builder=builder,
        reporter=reporter,
        cleanup_manager=SimpleNamespace(cleanup_group=lambda group_id: None),
        logger=SimpleNamespace(section=lambda message: None),
        active={},
        _append_runtime_specs=lambda specs: plan.tests.extend(specs),
        _refresh_checkpoint=lambda: None,
    )
    runner = ConcurrentLoadRunner(executor)
    pairs = [
        {
            "placement": "cross-compute",
            "source_host": "compute1",
            "destination_host": "compute2",
            "availability_zone": "az1",
        },
        {
            "placement": "cross-compute",
            "source_host": "compute3",
            "destination_host": "compute4",
            "availability_zone": "az1",
        },
    ]
    monkeypatch.setattr(runner, "_create_pairs", lambda count: pairs[:count])
    calls = 0

    def traffic(*args):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("unexpected parser failure")
        return {
            "aggregate_mbps": 500.0,
            "median_pair_mbps": 500.0,
            "slowest_pair_mbps": 500.0,
            "fairness": 1.0,
            "idle_latency": {"p95_ms": 1.0, "loss_pct": 0.0},
            "loaded_latency": {"p95_ms": 2.0, "loss_pct": 0.0},
            "loaded_latency_ratio": 2.0,
            "loaded_udp": {"loss_pct": 0.0, "jitter_ms": 0.1},
            "retransmissions": 0,
        }

    monkeypatch.setattr(runner, "_traffic_run", traffic)
    monkeypatch.setattr(
        "neutron_flux.concurrent_load.TestEngine", lambda *args: object()
    )
    monkeypatch.setattr(
        "neutron_flux.concurrent_load.PerformanceRunner", lambda *args: object()
    )
    runner.run()
    assert recorded[-1].status == "ERROR"
    assert "unexpected parser failure" in recorded[-1].message
    levels = recorded[-1].details["metrics"]["levels"]
    assert [item["pairs"] for item in levels] == [1]


def test_live_migration_reconciles_transient_nonzero_client_result(config_factory):
    moving = endpoint("moving-transient", "A")
    moving.host = "compute1"
    moving.availability_zone = "az1"
    target = ComputeHostInfo("compute2", "az1", True, True, {"agg"}, {"agg"})
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory(
        action="run",
        storage="host",
        migration_storage="host",
        live_migration_continuity=False,
    )
    builder.osc = SimpleNamespace(
        run=lambda *args, **kwargs: subprocess.CompletedProcess(
            list(args), 1, "", "HTTP 503 Service Unavailable"
        )
    )
    builder.logger = SimpleNamespace(log=lambda *args, **kwargs: None)
    builder.reporter = SimpleNamespace(event=lambda *args, **kwargs: None)
    builder._capture_endpoint_migration_state = lambda item: {
        "migration_ids": set(),
        "migration_inventory_error": None,
        "volume_ids": set(),
        "guest_marker": None,
    }
    builder._wait_for_migration_acceptance = lambda *args, **kwargs: {
        "accepted": True,
        "evidence": "test harness",
    }
    builder._wait_for_live_destination = lambda item, host: {
        "status": "ACTIVE",
        "host": host,
        "availability_zone": "az1",
        "task_state": None,
    }
    builder._verify_nova_migration_record = lambda *args, **kwargs: (True, None, {})
    builder._verify_migrated_ports = lambda *args, **kwargs: (True, {})
    builder._wait_for_ssh = lambda *args, **kwargs: True
    builder.reconfigure_endpoint = lambda item: None

    result = builder._live_migrate_endpoint_once(moving, target)
    assert result.destination_host == "compute2"
    assert "503" in result.details["request_error"]


def test_live_migration_runs_post_migration_performance_when_tcp_path_exists(
    config_factory,
):
    source = endpoint("source-perf", "A")
    destination = endpoint("destination-perf", "B")
    source.host = destination.host = "compute1"
    target = ComputeHostInfo("compute2", "az1", True, True, {"agg"}, {"agg"})

    def live(moving, selected, stationary):
        old_host = moving.host
        moving.host = selected.host
        return MigrationResult(
            server_id=moving.server_id,
            source_host=old_host,
            destination_host=selected.host,
            source_availability_zone="az1",
            destination_availability_zone="az1",
            confirmed=True,
            automatically_confirmed=False,
            port_binding_verified=True,
            migration_record_verified=True,
            task_state_cleared=True,
            guest_marker_verified=True,
            endpoint_ready=True,
            details={
                "migration_mode": "live",
                "continuity": {
                    "available": True,
                    "health": "good",
                    "icmp": {"loss_pct": 0.0, "longest_outage_s": 0.0},
                    "tcp": {"survived": True},
                    "udp": {"response": {"loss_pct": 0.0}},
                },
            },
        )

    builder = SimpleNamespace(
        select_compute_migration_targets=lambda *args, **kwargs: ([target], "eligible"),
        live_migrate_endpoint=live,
    )
    config = config_factory(action="run", migration_mode="live-only")
    executor, spec, _recorded = _placement_executor(
        config, source, destination, builder
    )
    spec.protocol = "tcp"
    spec.source_group_id = "placement-group"
    spec.destination_group_id = "placement-group"
    stages = []
    executor._run_performance = lambda specs, engine, *, stage: stages.append(stage)
    engine = SimpleNamespace(run_specs=lambda specs: None)

    executor._run_compute_placement_validation(
        [spec], engine, dependencies=("placement-group",)
    )
    assert stages == ["post-live-migration"]


def test_fabric_loaded_latency_keeps_load_active_for_full_ping_window(config_factory):
    config = config_factory(
        fabric_scale_duration_seconds=3,
        performance_ping_count=50,
        performance_udp_rates_mbps=[10],
        performance_udp_packet_sizes=[128],
    )
    durations = []

    class FakeRunner:
        def _ping(self, *args):
            return {"p95_ms": 1.0, "loss_pct": 0.0}

        def _tcp_upload(self, *args, streams, duration_seconds):
            durations.append(("tcp", duration_seconds))
            return {"mbps": 100.0, "retransmissions": 0, "streams": streams}

        def _udp_measurement(self, *args, duration_seconds):
            durations.append(("udp", duration_seconds))
            return {"loss_pct": 0.0, "jitter_ms": 0.1}

    executor = SimpleNamespace(
        config=config,
        plan=Plan([], [], {}, [], tests=[]),
        builder=SimpleNamespace(),
        reporter=SimpleNamespace(),
        cleanup_manager=SimpleNamespace(),
        logger=SimpleNamespace(),
    )
    runner = ConcurrentLoadRunner(executor)
    ep_a = endpoint("fabric-a", "A")
    ep_b = endpoint("fabric-b", "B")
    pair = {
        "source": ep_a,
        "destination": ep_b,
        "source_ip": "192.0.2.10",
        "destination_ip": "192.0.2.11",
        "family": 4,
    }
    result = runner._traffic_run(FakeRunner(), [pair])
    expected = 13  # ceil((50 measured + 5 warm-up) * 0.2) + 2
    assert ("udp", expected) in durations
    assert durations.count(("tcp", expected)) == 3
    assert ("tcp", 3) not in durations
    assert result["clean_throughput_sample_duration_seconds"] == expected
    assert result["loaded_sample_duration_seconds"] == expected


def test_comparison_treats_a_new_warning_as_a_regression():
    from neutron_flux.comparison import compare_payloads

    baseline = {
        "run": {"run_id": "before"},
        "results": [],
        "summary": {},
        "cleanup": {},
    }
    candidate = {
        "run": {"run_id": "after"},
        "results": [_performance_result("az1", health="warning")],
        "summary": {},
        "cleanup": {},
    }
    comparison = compare_payloads(baseline, candidate)
    assert comparison["entries"][0]["assessment"] == "regressed"


def test_fabric_clone_ids_remain_unique_when_base_group_id_is_long(
    config_factory, monkeypatch
):
    from neutron_flux.models import PlannedGroup, RuntimeGroup

    base = PlannedGroup(
        id=(
            "tenant-pool-12345678-1234-1234-1234-123456789abc-"
            "ext-abcdef12-1234-1234-1234-abcdef123456"
        ),
        kind="tenant-pool",
        label="Long tenant pool",
        network_id=None,
        network_name=None,
        subnet_ids=[],
        families=[4],
        pool_id="pool-id",
        external_network_id="external-id",
        external_network_name="Public1",
        external_subnet_id="external-subnet",
        prefix_length=24,
    )
    created_ids = []

    def build_group(group, **kwargs):
        created_ids.append(group.id)
        a = endpoint(f"a-{len(created_ids)}", "A")
        b = endpoint(f"b-{len(created_ids)}", "B")
        a.fixed_ips = {"subnet": f"192.0.2.{len(created_ids) * 2}"}
        b.fixed_ips = {"subnet": f"192.0.2.{len(created_ids) * 2 + 1}"}
        return RuntimeGroup(
            plan=group,
            network_id="network",
            network_name="network",
            subnet_ids=["subnet"],
            router_id=None,
            endpoints=[a, b],
            source_nat_enabled=None,
            fips={},
        )

    executor = SimpleNamespace(
        config=config_factory(fabric_scale_enabled=True, fabric_scale_pairs=[1, 2, 4]),
        plan=Plan([base], [], {}, [], tests=[]),
        builder=SimpleNamespace(
            build_group=build_group,
            runtime_groups=[],
            stop_group_probes=lambda group_id: None,
        ),
        reporter=SimpleNamespace(),
        cleanup_manager=SimpleNamespace(cleanup_group=lambda group_id: None),
        logger=SimpleNamespace(section=lambda message: None),
    )
    pairs = ConcurrentLoadRunner(executor)._create_pairs(4)
    assert len(pairs) == 4
    assert len(created_ids) == len(set(created_ids)) == 4
    assert all(len(item) <= 72 for item in created_ids)


def test_fabric_quota_estimate_includes_tenant_router_ports(
    config_factory, discovery_fixture, tmp_path
):
    from neutron_flux.log import Logger
    from neutron_flux.planning import Planner

    config = config_factory(
        fabric_scale_enabled=True,
        fabric_scale_pairs=[1, 2, 4],
    )
    plan = Planner(
        config, discovery_fixture, Logger(tmp_path / "fabric-plan.log")
    ).build()
    assert plan.estimated["peak_ports"] >= 4 + 4 * 6
    assert plan.estimated["networks_created"] >= 1 + 4
    assert plan.estimated["subnets_created"] >= 1 + 4
    assert plan.estimated["routers_created"] >= 4


def test_live_continuity_window_covers_request_and_reconciliation_time(config_factory):
    moving = endpoint("moving-window", "B")
    stationary = endpoint("stationary-window", "A")
    moving.fixed_ips = {"subnet": "192.0.2.20"}
    stationary.fixed_ips = {"subnet": "192.0.2.10"}
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory(resource_timeout=600)
    captured = {}

    def code(**kwargs):
        captured.update(kwargs)
        return "print('ok')"

    builder._live_continuity_code = code
    builder.ssh_endpoint = lambda *args, **kwargs: subprocess.CompletedProcess(
        ["ssh"], 0, "1234\t/tmp/neutron-flux-live.ABC123\n", ""
    )
    builder.inspect_endpoint_route = data_route
    state = builder._start_live_continuity(stationary, moving)
    assert state["available"] is True
    assert (
        captured["maximum_seconds"]
        == 4 * 600 + 2 * builder.config.convergence_timeout + 120
    )


def test_live_continuity_warns_when_monitor_did_not_cover_full_window(config_factory):
    stationary = endpoint("stationary-short", "A")
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory()
    payload = {
        "duration_s": 5.0,
        "icmp": [{"t": 0.0, "ok": True}, {"t": 4.5, "ok": True}],
        "tcp": {"survived": True},
        "udp": {"response": {"loss_pct": 0.0}},
    }
    commands = []

    def ssh(_endpoint, command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(["ssh"], 0, json.dumps(payload), "")

    builder.ssh_endpoint = ssh
    state = {
        "available": True,
        "started_at": __import__("time").monotonic() - 20.0,
        "stop_path": "/tmp/live.stop",
        "result_path": "/tmp/live.json",
        "error_path": "/tmp/live.err",
        "pid": "1234",
    }
    result = builder._stop_live_continuity(stationary, state)
    assert result["full_migration_window"] is False
    assert result["health"] == "warning"
    assert any("ended before" in item for item in result["warnings"])
    assert "rm -f" in commands[0]


def test_placement_validation_uses_the_shared_network_load_lock():
    events = []

    class TrackingLock:
        def __enter__(self):
            events.append("lock-enter")

        def __exit__(self, exc_type, exc, tb):
            events.append("lock-exit")

    from neutron_flux.executor import AdaptiveExecutor

    executor = object.__new__(AdaptiveExecutor)
    executor.performance_lock = TrackingLock()
    executor._run_compute_placement_validation = lambda specs, engine, *, dependencies: (
        events.append(("placement", tuple(dependencies)))
    )
    executor._run_placement_validation_serialized(
        [], object(), dependencies=("group-a",)
    )
    assert events == [
        "lock-enter",
        ("placement", ("group-a",)),
        "lock-exit",
    ]


def test_exact_host_pairs_suppress_scheduler_selected_migrations():
    from neutron_flux.executor import AdaptiveExecutor

    executor = object.__new__(AdaptiveExecutor)
    executor.config = SimpleNamespace(
        selective_run=False,
        target_host_pairs=[("compute1", "compute2")],
    )
    executor.logger = SimpleNamespace(log=mock.Mock())
    executor._run_compute_placement_validation = mock.Mock()

    executor._run_placement_validation_serialized(
        [], object(), dependencies=("scheduler-selected-group",)
    )

    executor._run_compute_placement_validation.assert_not_called()
    executor.logger.log.assert_called_once()
    assert "exact --target-host-pairs" in executor.logger.log.call_args.args[0]


def test_live_continuity_prefers_addresses_on_a_shared_subnet():
    stationary = endpoint("stationary-multi", "A")
    moving = endpoint("moving-multi", "B")
    stationary.fixed_ips = {
        "source-only": "192.0.2.10",
        "shared": "198.51.100.10",
    }
    moving.fixed_ips = {
        "destination-only": "203.0.113.20",
        "shared": "198.51.100.20",
    }
    selected = ResourceBuilder._shared_endpoint_family(stationary, moving)
    assert selected == (4, "198.51.100.10", "198.51.100.20")


def test_trend_html_escapes_run_metadata_before_inner_html():
    from neutron_flux.trends import _trend_html

    payload = {
        "runs": [
            {
                "run_id": "</script><img src=x onerror=alert(1)>",
                "started_at": "<b>bad</b>",
                "final_status": "<svg/onload=alert(1)>",
            }
        ],
        "summary": {
            "run_count": 1,
            "failed_runs": 0,
            "cleanup_failures": 0,
            "latest_run": "</script><img src=x onerror=alert(1)>",
        },
    }
    rendered = _trend_html(payload)
    assert "esc(r.run_id)" in rendered
    assert "esc(r.started_at" in rendered
    assert "esc(r.final_status" in rendered
    assert "esc(x[1])" in rendered
    assert "</script><img" not in rendered
