from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

from neutron_flux.concurrent_load import ConcurrentLoadRunner
from neutron_flux.errors import PortValidationError
from neutron_flux.models import ComputeHostInfo, Plan, PlannedGroup, RuntimeGroup
from neutron_flux.resources import ResourceBuilder

from ._evidence import data_route
from ._shared import endpoint


def _run_args(*extra: str):
    from neutron_flux.cli import parser

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


def test_continuity_window_covers_two_resource_timeouts(config_factory):
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory(action="run", resource_timeout=2400)
    captured = {}
    builder._live_continuity_code = lambda **kwargs: captured.update(kwargs) or "pass"
    builder.ssh_endpoint = lambda *args, **kwargs: subprocess.CompletedProcess(
        ["ssh"], 0, "123\t/tmp/neutron-flux-live.ABC123\n", ""
    )
    stationary = endpoint("stationary", "A")
    moving = endpoint("moving", "B")
    builder.inspect_endpoint_route = data_route
    state = builder._start_live_continuity(stationary, moving)
    assert state["available"] is True
    assert (
        captured["maximum_seconds"]
        == 4 * 2400 + 2 * builder.config.convergence_timeout + 120
    )


def _live_builder_without_reported_az(config_factory):
    moving = endpoint("moving-hidden-az", "A")
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
        run=lambda *args, **kwargs: subprocess.CompletedProcess(list(args), 0, "", "")
    )
    builder.logger = SimpleNamespace(log=lambda *args, **kwargs: None)
    builder.reporter = SimpleNamespace(event=lambda *args, **kwargs: None)
    builder._capture_endpoint_migration_state = lambda item: {
        "migration_ids": set(),
        "migration_inventory_error": None,
        "volume_ids": set(),
        "guest_marker": {
            "path": "/tmp/migration-marker",
            "sha256": "a" * 64,
            "token": "marker",
        },
    }
    builder._wait_for_live_destination = lambda item, host: {
        "status": "ACTIVE",
        "host": host,
        "task_state": None,
    }
    builder._verify_nova_migration_record = lambda *args, **kwargs: (True, None, {})
    builder._verify_migrated_ports = lambda *args, **kwargs: (True, {})
    builder._verify_guest_migration_marker = lambda *_args: (True, None)
    builder._wait_for_ssh = lambda *args, **kwargs: True
    builder.reconfigure_endpoint = lambda item: None
    return builder, moving, target


@pytest.mark.parametrize("migration_kind", ["live", "cold"])
def test_completed_migration_keeps_failed_port_snapshots(
    config_factory, migration_kind
):
    builder, moving, target = _live_builder_without_reported_az(config_factory)
    ports = {
        "management": {"status": "DOWN", "binding_host_id": target.host},
        "test": {"status": "ACTIVE", "binding_host_id": target.host},
    }

    def fail_ports(*_args, **_kwargs):
        raise PortValidationError("management port remained DOWN", ports=ports)

    builder._verify_migrated_ports = fail_ports
    if migration_kind == "cold":
        builder.probe_service = SimpleNamespace(stop=lambda _: None)
        builder._wait_for_migration_handoff = lambda *_args: ({}, True)
        builder._wait_for_status = lambda *_args, **_kwargs: None
        builder._wait_for_active_on_target = builder._wait_for_live_destination
    result = getattr(builder, f"_{migration_kind}_migrate_endpoint_once")(
        moving, target
    )
    assert result.port_binding_verified is False
    assert result.details["ports"] == ports
    assert result.destination_host == target.host
    assert result.endpoint_ready is True


def test_live_migration_uses_target_inventory_when_server_az_is_hidden(config_factory):
    builder, moving, target = _live_builder_without_reported_az(config_factory)
    result = builder._live_migrate_endpoint_once(moving, target)
    assert result.destination_availability_zone == "az1"
    assert (
        result.details["destination_availability_zone_source"]
        == "target-host-inventory"
    )


def test_cold_migration_uses_target_inventory_when_server_az_is_hidden(config_factory):
    moving = endpoint("cold-hidden-az", "A")
    moving.host = "compute1"
    moving.availability_zone = "az1"
    target = ComputeHostInfo("compute2", "az1", True, True, {"agg"}, {"agg"})
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory(action="run", storage="host")
    builder.osc = SimpleNamespace(
        run=lambda *args, **kwargs: subprocess.CompletedProcess(list(args), 0, "", "")
    )
    builder.logger = SimpleNamespace(log=lambda *args, **kwargs: None)
    builder.reporter = SimpleNamespace(event=lambda *args, **kwargs: None)
    builder.probe_service = SimpleNamespace(stop=lambda item: None)
    builder._capture_endpoint_migration_state = lambda item: {
        "migration_ids": set(),
        "migration_inventory_error": None,
        "volume_ids": set(),
        "guest_marker": None,
    }
    builder._wait_for_migration_handoff = lambda item, host: ({}, True)
    builder._wait_for_status = lambda *args, **kwargs: None
    builder._wait_for_active_on_target = lambda item, host: {
        "status": "ACTIVE",
        "host": host,
        "task_state": None,
    }
    builder._verify_nova_migration_record = lambda *args, **kwargs: (True, None, {})
    builder._verify_migrated_ports = lambda *args, **kwargs: (True, {})
    builder._wait_for_ssh = lambda *args, **kwargs: True
    builder.reconfigure_endpoint = lambda item: None
    result = builder._cold_migrate_endpoint_once(moving, target)
    assert result.destination_availability_zone == "az1"
    assert (
        result.details["destination_availability_zone_source"]
        == "target-host-inventory"
    )


def test_fabric_pair_order_prefers_cross_compute_baseline(config_factory):
    base = PlannedGroup(
        id="provider",
        kind="provider",
        label="Provider",
        network_id="network",
        network_name="Provider",
        subnet_ids=["subnet"],
        families=[4],
    )
    calls = 0

    def build_group(group, **kwargs):
        nonlocal calls
        calls += 1
        a = endpoint(f"a-{calls}", "A")
        b = endpoint(f"b-{calls}", "B")
        a.fixed_ips = {"subnet": f"192.0.2.{calls * 2}"}
        b.fixed_ips = {"subnet": f"192.0.2.{calls * 2 + 1}"}
        if calls == 2:
            b.host = "compute2"
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
        cleanup_manager=SimpleNamespace(cleanup_group=lambda group_id: None),
        logger=SimpleNamespace(section=lambda message: None),
        peak_endpoints=0,
    )
    pairs = ConcurrentLoadRunner(executor)._create_pairs(2)
    assert [item["placement"] for item in pairs] == ["cross-compute", "same-compute"]
    assert pairs[0]["pair_index"] == 2
    level = ConcurrentLoadRunner._summarize_level(
        2,
        pairs,
        [
            {
                "aggregate_mbps": 100.0,
                "median_pair_mbps": 50.0,
                "slowest_pair_mbps": 40.0,
                "fairness": 1.0,
                "idle_latency": {"p95_ms": 1.0, "loss_pct": 0.0},
                "loaded_latency": {"p95_ms": 2.0, "loss_pct": 0.0},
                "loaded_latency_ratio": 2.0,
                "loaded_tcp_aggregate_mbps": 90.0,
                "loaded_udp": {"loss_pct": 0.0, "jitter_ms": 0.1},
                "retransmissions": 0,
                "loaded_retransmissions": 0,
            }
        ],
    )
    assert [item["pair"] for item in level["placements"]] == [2, 1]


def test_concurrent_load_same_compute_pair_is_valid(config_factory, monkeypatch):
    config = config_factory(
        action="run",
        fabric_scale_enabled=True,
        fabric_scale_pairs=[1],
        fabric_scale_runs=1,
        performance_enforce_thresholds=True,
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
            SimpleNamespace(status=status, message=message, **kwargs)
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
    pair = {
        "pair_index": 1,
        "placement": "same-compute",
        "source_host": "compute1",
        "destination_host": "compute1",
        "availability_zone": "az1",
    }
    monkeypatch.setattr(runner, "_create_pairs", lambda count: [pair])
    monkeypatch.setattr(
        runner,
        "_traffic_run",
        lambda *args: {
            "aggregate_mbps": 100.0,
            "median_pair_mbps": 100.0,
            "slowest_pair_mbps": 100.0,
            "fairness": 1.0,
            "idle_latency": {"p95_ms": 1.0, "loss_pct": 0.0},
            "loaded_latency": {"p95_ms": 2.0, "loss_pct": 0.0},
            "loaded_latency_ratio": 2.0,
            "loaded_udp": {"loss_pct": 0.0, "jitter_ms": 0.1},
            "retransmissions": 0,
        },
    )
    monkeypatch.setattr(
        "neutron_flux.concurrent_load.TestEngine", lambda *args: object()
    )
    monkeypatch.setattr(
        "neutron_flux.concurrent_load.PerformanceRunner", lambda *args: object()
    )
    runner.run()
    assert recorded[-1].status == "PASS"
    assert recorded[-1].observed == "concurrent-vm-pair-load-measured"
    assert recorded[-1].authoritative is True
    assert (
        recorded[-1].details["attribution"]["placement"]["scope"]
        == "intra-compute-only"
    )


def test_comparison_tracks_loaded_fabric_throughput_and_retransmissions():
    from neutron_flux.comparison import _performance_metrics

    result = {
        "details": {
            "measurement": "fabric-scale",
            "metrics": {
                "levels": [
                    {
                        "pairs": 4,
                        "median_loaded_tcp_aggregate_mbps": 2800.0,
                        "total_loaded_retransmissions": 7,
                    }
                ]
            },
        }
    }
    metrics = _performance_metrics(result)
    assert metrics["pairs_4_loaded_tcp_aggregate_mbps"] == (2800.0, "higher")
    assert metrics["pairs_4_loaded_retransmissions"] == (7.0, "lower")
