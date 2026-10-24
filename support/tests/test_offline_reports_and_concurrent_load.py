from __future__ import annotations

import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace

import pytest

from neutron_flux.cli import main, parser
from neutron_flux.comparison import compare_files, compare_payloads
from neutron_flux.concurrent_load import ConcurrentLoadRunner
from neutron_flux.config import Config
from neutron_flux.errors import (
    CommandTimeoutError,
    RetryableMigrationError,
    SuiteError,
)
from neutron_flux.junit_report import build_junit
from neutron_flux.models import ComputeHostInfo, MigrationResult, Plan, PlannedGroup
from neutron_flux.offline_reports import regenerate
from neutron_flux.reporting_components.html import _performance_summary
from neutron_flux.resources import ResourceBuilder
from neutron_flux.trends import trend_files, trend_payload

from ._shared import _placement_executor, endpoint


def _payload(
    run_id: str,
    *,
    status: str = "PASS",
    tcp_mbps: float = 1000.0,
    latency_ms: float = 1.0,
) -> dict:
    result = {
        "test_id": "PERF-PATH-TCP-THROUGHPUT",
        "category": "network-performance",
        "status": status,
        "family": 4,
        "source": "vm-a",
        "destination": "vm-b",
        "message": "measurement complete",
        "started_at": "2026-07-22T00:00:00+00:00",
        "duration_ms": 1000,
        "expected": "measurement-complete",
        "observed": "measured",
        "authoritative": True,
        "display_name": "TCP throughput — path",
        "scenario": "Tenant-visible network performance",
        "details": {
            "performance": True,
            "measurement": "tcp-throughput",
            "health": "good",
            "path": {
                "path_id": "PATH",
                "source_category": "tenant-routing",
                "placement": "cross-compute",
                "availability_scope": "same-az",
                "stage": "cross-topology",
                "source_label": "vm-a",
                "destination_label": "vm-b",
                "family": 4,
            },
            "metrics": {
                "forward": {
                    "streams": {
                        "1": {
                            "median_mbps": tcp_mbps,
                            "total_retransmissions": 0,
                        }
                    }
                },
                "reverse": {
                    "streams": {
                        "1": {
                            "median_mbps": tcp_mbps * 0.9,
                            "total_retransmissions": 1,
                        }
                    }
                },
                "bidirectional": {"aggregate_mbps": tcp_mbps * 1.6},
            },
        },
    }
    latency = {
        **result,
        "test_id": "PERF-PATH-LATENCY",
        "display_name": "Latency — path",
        "details": {
            **result["details"],
            "measurement": "latency",
            "metrics": {
                "idle": {
                    "forward": {"p95_ms": latency_ms},
                    "reverse": {"p95_ms": latency_ms * 1.1},
                },
                "loaded": {
                    "forward": {"p95_ms": latency_ms * 2},
                    "reverse": {"p95_ms": latency_ms * 2.2},
                },
                "loaded_p95_ratio": {"forward": 2.0, "reverse": 2.0},
            },
        },
    }
    return {
        "schema_version": 1,
        "tool": "neutron-flux",
        "tool_version": "0.1.0",
        "run": {
            "run_id": run_id,
            "action": "run",
            "started_at": "2026-07-22T00:00:00+00:00",
            "finished_at": "2026-07-22T00:01:00+00:00",
            "final_status": status,
            "run_tag": run_id,
            "name_prefix": "nflux",
        },
        "configuration": {
            "performance_enabled": True,
            "performance_thresholds": {},
            "evidence_enabled": True,
        },
        "summary": {
            "counts": {status: 2},
            "total_results": 2,
            "performance_results": 2,
            "performance": {
                "paths": 1,
                "lowest_single_stream_mbps": tcp_mbps * 0.9,
                "highest_idle_p95_ms": latency_ms * 1.1,
            },
            "categories": {"network-performance": {status: 2}},
            "cleanup_complete": True,
        },
        "results": [result, latency],
        "performance": [result, latency],
        "resources": [],
        "cleanup": {"attempted": True, "complete": True, "deleted": 4},
        "events": [],
        "setup_failures": [],
        "error": None,
        "traceback": None,
    }


def _write_payload(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _check_embedded_javascript(path: Path, tmp_path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    scripts = []
    marker = "<script>"
    cursor = 0
    while True:
        start = text.find(marker, cursor)
        if start < 0:
            break
        end = text.find("</script>", start)
        assert end > start
        scripts.append(text[start + len(marker) : end])
        cursor = end + 9
    assert scripts
    script = tmp_path / f"{path.stem}.js"
    script.write_text("\n".join(scripts), encoding="utf-8")
    subprocess.run(["node", "--check", str(script)], check=True, capture_output=True)


def test_cli_defaults_use_live_migration_and_disable_concurrent_load(tmp_path):
    args = parser().parse_args(
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
        ]
    )
    config = Config.from_args(args)
    assert config.migration_mode == "live-preferred"
    assert config.migration_storage == "auto"
    assert config.effective_migration_storage == "host"
    assert config.live_migration_attempts == 5
    assert config.live_migration_continuity is True
    assert config.cold_migration_fallback is True
    assert config.fabric_scale_enabled is False
    assert config.fabric_scale_pairs == [1, 2, 4]
    assert config.fabric_scale_runs == 2


def test_report_regeneration_and_junit_are_valid(tmp_path):
    source = _write_payload(tmp_path / "results.json", _payload("run-a"))
    written = regenerate(source, destination=tmp_path / "rendered")
    assert set(written) == {
        "text",
        "html",
        "junit",
        "host_qualification_csv",
        "incident_summary",
        "replay_plan_json",
        "replay_plan_text",
    }
    assert "run-a" in written["html"].read_text(encoding="utf-8")
    assert "PERFORMANCE SUMMARY" in written["text"].read_text(encoding="utf-8")
    root = ET.fromstring(written["junit"].read_text(encoding="utf-8"))
    assert root.tag == "testsuite"
    assert root.attrib["tests"] == "2"
    _check_embedded_javascript(written["html"], tmp_path)


def test_offline_cli_report_returns_success_after_writing_outputs(tmp_path):
    source = _write_payload(tmp_path / "results.json", _payload("offline-cli"))
    output = tmp_path / "rendered-cli"
    assert main(["report", str(source), "--output-dir", str(output)]) == 0
    assert (output / "report.html").is_file()
    assert (output / "report.txt").is_file()
    assert (output / "report.junit.xml").is_file()


def test_offline_cli_compare_and_trend_return_success(tmp_path):
    first = _write_payload(tmp_path / "first-cli.json", _payload("first-cli"))
    second_payload = _payload("second-cli", tcp_mbps=900.0)
    second_payload["run"]["started_at"] = "2026-07-23T00:00:00+00:00"
    second = _write_payload(tmp_path / "second-cli.json", second_payload)
    comparison = tmp_path / "comparison-cli"
    trend = tmp_path / "trend-cli"
    assert (
        main(["compare", str(first), str(second), "--output-dir", str(comparison)]) == 0
    )
    assert (comparison / "comparison.html").is_file()
    assert main(["trend", str(first), str(second), "--output-dir", str(trend)]) == 0
    assert (trend / "trend.html").is_file()


def test_junit_maps_failures_errors_and_unverified():
    payload = _payload("junit")
    payload["results"] = [
        {**payload["results"][0], "status": "FAIL", "test_id": "fail"},
        {**payload["results"][0], "status": "ERROR", "test_id": "error"},
        {**payload["results"][0], "status": "UNVERIFIED", "test_id": "skip"},
    ]
    root = ET.fromstring(build_junit(payload))
    assert root.attrib["failures"] == "1"
    assert root.attrib["errors"] == "1"
    assert root.attrib["skipped"] == "1"


def test_comparison_detects_performance_regression_and_writes_valid_html(tmp_path):
    baseline = _payload("baseline", tcp_mbps=1000.0, latency_ms=1.0)
    candidate = _payload("candidate", tcp_mbps=700.0, latency_ms=2.0)
    comparison = compare_payloads(baseline, candidate)
    assert comparison["summary"]["regressed"] >= 1
    before = _write_payload(tmp_path / "before.json", baseline)
    after = _write_payload(tmp_path / "after.json", candidate)
    written = compare_files(before, after, destination=tmp_path / "comparison")
    assert "regressed" in written["text"].read_text(encoding="utf-8").lower()
    assert "</script>;" not in written["html"].read_text(encoding="utf-8")
    _check_embedded_javascript(written["html"], tmp_path)


def test_comparison_treats_new_performance_warning_as_regression():
    baseline = _payload("baseline-health")
    candidate = _payload("candidate-health")
    candidate["results"][0]["details"]["health"] = "warning"
    candidate["performance"][0]["details"]["health"] = "warning"
    comparison = compare_payloads(baseline, candidate)
    throughput = next(
        item
        for item in comparison["entries"]
        if item["candidate_test_id"] == "PERF-PATH-TCP-THROUGHPUT"
    )
    assert throughput["assessment"] == "regressed"
    assert throughput["baseline_health"] == "good"
    assert throughput["candidate_health"] == "warning"


def test_comparison_reports_cleanup_and_coverage_regressions():
    baseline = _payload("baseline-run")
    candidate = _payload("candidate-run")
    candidate["cleanup"]["complete"] = False
    candidate["results"] = candidate["results"][:1]
    candidate["performance"] = candidate["performance"][:1]
    candidate["summary"]["counts"] = {"PASS": 1}
    candidate["summary"]["performance"]["paths"] = 0
    comparison = compare_payloads(baseline, candidate)
    assert comparison["run_changes"]["cleanup"]["assessment"] == "regressed"
    assert (
        comparison["run_changes"]["metrics"]["total_results"]["assessment"]
        == "regressed"
    )
    assert (
        comparison["run_changes"]["metrics"]["performance_paths"]["assessment"]
        == "regressed"
    )
    assert comparison["summary"]["lost_coverage"] >= 1
    assert comparison["summary"]["run_regressions"] >= 3


def test_trend_aggregates_runs_and_writes_valid_html(tmp_path):
    first = _write_payload(tmp_path / "first.json", _payload("first", tcp_mbps=500))
    second_payload = _payload("second", tcp_mbps=800)
    second_payload["run"]["started_at"] = "2026-07-23T00:00:00+00:00"
    second = _write_payload(tmp_path / "second.json", second_payload)
    payload = trend_payload([first, second])
    assert [item["run_id"] for item in payload["runs"]] == ["first", "second"]
    assert payload["runs"][0]["lowest_tcp_mbps"] == 450.0
    assert payload["runs"][1]["lowest_tcp_mbps"] == 720.0
    written = trend_files([first, second], destination=tmp_path / "trend")
    assert "second" in written["html"].read_text(encoding="utf-8")
    _check_embedded_javascript(written["html"], tmp_path)


def test_migration_storage_mode_selects_explicit_nova_flag(config_factory):
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory(migration_storage="host")
    assert builder._live_migration_storage_args() == ["--block-migration"]
    builder.config = config_factory(migration_storage="shared")
    assert builder._live_migration_storage_args() == ["--shared-migration"]
    builder.config = config_factory(storage="host", migration_storage="auto")
    assert builder._live_migration_storage_args() == ["--block-migration"]
    builder.config = config_factory(storage="volume", migration_storage="auto")
    assert builder._live_migration_storage_args() == ["--shared-migration"]


def test_live_preferred_uses_cold_fallback_without_hiding_live_failure(config_factory):
    source = endpoint("source", "A")
    destination = endpoint("destination", "B")
    source.host = destination.host = "compute1"
    target = ComputeHostInfo("compute2", "az1", True, True, {"agg"}, {"agg"})
    live_calls = []
    cold_calls = []

    def live(moving, selected, stationary):
        live_calls.append(selected.host)
        raise RetryableMigrationError("live migration unavailable", unavailable=True)

    def cold(moving, selected):
        cold_calls.append(selected.host)
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
            details={"migration_mode": "cold"},
        )

    builder = SimpleNamespace(
        select_compute_migration_targets=lambda *args, **kwargs: ([target], "eligible"),
        live_migrate_endpoint=live,
        cold_migrate_endpoint=cold,
    )
    config = config_factory(
        action="run",
        migration_mode="live-preferred",
        live_migration_attempts=2,
        cold_migration_fallback=True,
    )
    executor, spec, recorded = _placement_executor(config, source, destination, builder)
    engine = SimpleNamespace(run_specs=lambda specs: None)
    executor._run_compute_placement_validation(
        [spec], engine, dependencies=("placement-group",)
    )
    assert live_calls == ["compute2", "compute2"]
    assert cold_calls == ["compute2"]
    live_result = next(
        item for item in recorded if item.scenario == "Live migration capability"
    )
    lifecycle = next(
        item
        for item in recorded
        if item.scenario == "Compute migration and placement lifecycle"
    )
    assert live_result.status == "UNVERIFIED"
    assert live_result.details["health"] == "warning"
    assert lifecycle.status == "PASS"
    assert lifecycle.details["details"]["cold_fallback_used"] is True


def test_live_preferred_marks_real_live_failure_even_when_cold_fallback_passes(
    config_factory,
):
    source = endpoint("source", "A")
    destination = endpoint("destination", "B")
    source.host = destination.host = "compute1"
    target = ComputeHostInfo("compute2", "az1", True, True, {"agg"}, {"agg"})

    def live(moving, selected, stationary):
        raise RetryableMigrationError("live migration failed", unavailable=False)

    def cold(moving, selected):
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
            details={"migration_mode": "cold"},
        )

    builder = SimpleNamespace(
        select_compute_migration_targets=lambda *args, **kwargs: ([target], "eligible"),
        live_migrate_endpoint=live,
        cold_migrate_endpoint=cold,
    )
    config = config_factory(
        action="run",
        migration_mode="live-preferred",
        live_migration_attempts=2,
        cold_migration_fallback=True,
    )
    executor, spec, recorded = _placement_executor(config, source, destination, builder)
    executor._run_compute_placement_validation(
        [spec],
        SimpleNamespace(run_specs=lambda specs: None),
        dependencies=("placement-group",),
    )
    live_result = next(
        item for item in recorded if item.scenario == "Live migration capability"
    )
    lifecycle = next(
        item
        for item in recorded
        if item.scenario == "Compute migration and placement lifecycle"
    )
    assert live_result.status == "FAIL"
    assert live_result.details["health"] == "critical"
    assert lifecycle.status == "PASS"
    assert lifecycle.details["details"]["cold_fallback_used"] is True


def test_live_success_records_network_continuity(config_factory):
    from ._evidence import complete_continuity

    source = endpoint("source", "A")
    destination = endpoint("destination", "B")
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
            details={
                "migration_mode": "live",
                "continuity": complete_continuity(),
            },
        )

    builder = SimpleNamespace(
        select_compute_migration_targets=lambda *args, **kwargs: ([target], "eligible"),
        live_migrate_endpoint=live,
    )
    config = config_factory(action="run", migration_mode="live-only")
    executor, spec, recorded = _placement_executor(config, source, destination, builder)
    engine = SimpleNamespace(run_specs=lambda specs: None)
    executor._run_compute_placement_validation(
        [spec], engine, dependencies=("placement-group",)
    )
    statuses = {item.scenario: item.status for item in recorded}
    assert statuses["Live migration capability"] == "PASS"
    assert statuses["Live migration network continuity"] == "PASS"
    assert statuses["Compute migration and placement lifecycle"] == "PASS"


@pytest.mark.parametrize("requested", [[1, 2, 4], [4, 2, 1], [2, 4], [32, 1, 8]])
def test_fabric_scale_reports_each_requested_pair_level(
    config_factory, monkeypatch, requested
):
    config = config_factory(
        action="run",
        fabric_scale_enabled=True,
        fabric_scale_pairs=requested,
        fabric_scale_runs=2,
    )
    recorded = []
    plan = Plan([], [], {}, [], tests=[])
    builder = SimpleNamespace(discovery=SimpleNamespace(), runtime_groups=[])
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
    fake_pairs = [
        {
            "placement": "cross-compute",
            "source_host": f"compute-{index}",
            "destination_host": f"compute-{index + 1}",
            "availability_zone": "az1",
        }
        for index in range(max(requested))
    ]
    monkeypatch.setattr(runner, "_create_pairs", lambda count: fake_pairs[:count])
    monkeypatch.setattr(
        runner,
        "_traffic_run",
        lambda perf, pairs: {
            "aggregate_mbps": len(pairs) * 500.0,
            "forward_aggregate_mbps": len(pairs) * 500.0,
            "reverse_aggregate_mbps": len(pairs) * 500.0,
            "lowest_directional_aggregate_mbps": len(pairs) * 500.0,
            "forward_pair_mbps": [500.0] * len(pairs),
            "reverse_pair_mbps": [500.0] * len(pairs),
            "pair_median_mbps": [500.0] * len(pairs),
            "median_pair_mbps": 500.0,
            "slowest_pair_mbps": 500.0,
            "fairness": 1.0,
            "retransmissions": 0,
            "idle_latency": {"p95_ms": 0.5, "loss_pct": 0.0},
            "loaded_latency": {"p95_ms": 1.0, "loss_pct": 0.0},
            "loaded_latency_ratio": 2.0,
            "loaded_udp": {"loss_pct": 0.0, "jitter_ms": 0.1},
        },
    )
    monkeypatch.setattr(
        "neutron_flux.concurrent_load.TestEngine", lambda *args: object()
    )
    monkeypatch.setattr(
        "neutron_flux.concurrent_load.PerformanceRunner", lambda *args: object()
    )
    runner.run()
    assert recorded[0].status == "PASS"
    levels = recorded[0].details["metrics"]["levels"]
    assert [item["pairs"] for item in levels] == requested
    assert [item["median_aggregate_mbps"] for item in levels] == [
        500 * count for count in requested
    ]
    assert [item["median_pair_mbps"] for item in levels] == [500] * len(requested)
    assert [item["per_pair_degradation_pct"] for item in levels] == [0.0] * len(
        requested
    )
    assert f"{max(requested)} simultaneous VM pairs" in recorded[0].message
    assert recorded[0].details["configuration"]["comparison_baseline_pairs"] == min(
        requested
    )
    assert recorded[0].details["configuration"]["one_pair_baseline_present"] == (
        1 in requested
    )


def test_new_fault_injection_points_are_recognized(config_factory):
    from neutron_flux.failure_injection import inject_failure

    for point in (
        "before-live-migration",
        "after-live-request",
        "after-live-handoff",
        "before-cold-fallback",
        "before-fabric-build",
        "after-fabric-build",
        "before-fabric-level:4",
        "after-fabric-level:4",
    ):
        config = config_factory(failure_injection=point)
        with pytest.raises(SuiteError, match=point):
            inject_failure(config, point)


@pytest.mark.parametrize(
    ("boot_storage", "storage_mode", "expected_flag"),
    [
        ("host", "host", "--block-migration"),
        ("volume", "shared", "--shared-migration"),
        ("host", "auto", "--block-migration"),
    ],
)
def test_live_migration_builds_expected_nova_command_and_records_history(
    config_factory, boot_storage, storage_mode, expected_flag
):
    moving = endpoint("moving", "A")
    moving.host = "compute1"
    moving.availability_zone = "az1"
    target = ComputeHostInfo("compute2", "az1", True, True, {"agg"}, {"agg"})
    commands = []
    events = []

    def run(*args, **kwargs):
        commands.append((args, kwargs))
        return subprocess.CompletedProcess(list(args), 0, "", "")

    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory(
        action="run",
        storage=boot_storage,
        migration_storage=storage_mode,
        live_migration_continuity=False,
    )
    builder.osc = SimpleNamespace(run=run)
    builder.logger = SimpleNamespace(log=lambda *args, **kwargs: None)
    builder.reporter = SimpleNamespace(
        event=lambda name, message, **kwargs: events.append((name, message, kwargs))
    )
    moving.volume_id = "original-root-volume" if boot_storage == "volume" else None
    original_volumes = {moving.volume_id} if moving.volume_id else set()
    builder._capture_endpoint_migration_state = lambda item: {
        "migration_ids": set(),
        "migration_inventory_error": None,
        "volume_ids": original_volumes,
        "guest_marker": {"path": "/tmp/marker", "sha256": "a" * 64, "token": "marker"},
    }
    builder._wait_for_migration_acceptance = lambda *args, **kwargs: {
        "accepted": True,
        "evidence": "test harness",
    }
    builder._wait_for_live_destination = lambda item, host: {
        "status": "ACTIVE",
        "OS-EXT-SRV-ATTR:host": host,
        "OS-EXT-AZ:availability_zone": "az1",
        "OS-EXT-STS:task_state": None,
    }
    builder._verify_nova_migration_record = lambda *args, **kwargs: (
        True,
        None,
        {"id": "migration-1", "migration_type": "live-migration"},
    )
    builder._verify_migrated_ports = lambda *args, **kwargs: (
        True,
        {"test-port": {"binding_host_id": "compute2"}},
    )
    builder._verify_guest_migration_marker = lambda *_args: (True, None)
    builder._wait_for_ssh = lambda *args, **kwargs: True
    builder.reconfigure_endpoint = lambda item: None
    builder._server_volume_ids = lambda server_id: original_volumes
    builder._verify_expected_volume_attachment = lambda volume_id, server_id: (
        volume_id == moving.volume_id and server_id == moving.server_id,
        None,
        {"attachments": [{"server_id": moving.server_id}]},
    )

    result = builder._live_migrate_endpoint_once(moving, target)

    assert result.destination_host == "compute2"
    assert moving.host == "compute2"
    args, kwargs = commands[0]
    assert args[:6] == (
        "--os-compute-api-version",
        "2.56",
        "server",
        "migrate",
        "--live-migration",
        "--host",
    )
    assert "compute2" in args
    assert "--wait" in args
    assert kwargs["check"] is False
    if expected_flag:
        assert expected_flag in args
    else:
        assert "--block-migration" not in args
        assert "--shared-migration" not in args
    effective = builder.config.effective_migration_storage
    history = moving.metadata["migration_history"][-1]
    assert history["migration_storage"] == effective
    assert history["configured_migration_storage"] == storage_mode
    assert events[-1][0] == "live-migration-complete"


def test_live_migration_reconciles_a_timed_out_client_request(config_factory):
    moving = endpoint("moving-timeout", "A")
    target = ComputeHostInfo("compute2", "az1", True, True, {"agg"}, {"agg"})
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory(
        action="run",
        storage="host",
        migration_storage="host",
        live_migration_continuity=False,
    )
    builder.osc = SimpleNamespace(
        run=lambda *args, **kwargs: (_ for _ in ()).throw(
            CommandTimeoutError(args, kwargs.get("timeout"))
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
    assert result.details["request_error"].startswith("Command timed out")


def test_live_migration_wrapper_cleans_continuity_before_retry(config_factory):
    moving = endpoint("moving-cleanup", "A")
    stationary = endpoint("stationary-cleanup", "B")
    target = ComputeHostInfo("compute2", "az1", True, True, {"agg"}, {"agg"})
    cleaned = []
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder.logger = SimpleNamespace(log=lambda *args, **kwargs: None)

    def fail(item, selected, peer):
        item.metadata["_live_continuity_state"] = {
            "available": True,
            "stop_path": "/tmp/stop",
        }
        raise SuiteError("request failed")

    builder._live_migrate_endpoint_once = fail
    builder._recover_endpoint_after_failed_migration = lambda *args: (
        True,
        "endpoint restored to source host",
    )
    builder._stop_live_continuity = lambda peer, state: (
        cleaned.append((peer, state)) or state
    )

    with pytest.raises(RetryableMigrationError, match="endpoint restored"):
        builder.live_migrate_endpoint(moving, target, stationary)
    assert cleaned == [(stationary, {"available": True, "stop_path": "/tmp/stop"})]
    assert "_live_continuity_state" not in moving.metadata


def test_live_continuity_result_reports_outage_and_cleans_guest_files(config_factory):
    stationary = endpoint("continuity", "A")
    payload = {
        "duration_s": 1.0,
        "icmp": [
            {"t": 0.0, "ok": True},
            {"t": 0.25, "ok": False},
            {"t": 0.5, "ok": False},
            {"t": 0.75, "ok": True},
        ],
        "tcp": {"connected": True, "survived": True, "bytes_sent": 1024},
        "udp": {"sent": 10, "response": {"loss_pct": 0.0}},
    }
    commands = []
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder.ssh_endpoint = lambda item, command: (
        commands.append(command)
        or subprocess.CompletedProcess(["ssh"], 0, json.dumps(payload), "")
    )
    state = {
        "available": True,
        "stop_path": "/tmp/live.stop",
        "result_path": "/tmp/live.json",
        "error_path": "/tmp/live.err",
        "pid": "123",
    }

    result = builder._stop_live_continuity(stationary, state)
    assert result["health"] == "warning"
    assert result["icmp"]["loss_pct"] == 50.0
    assert result["icmp"]["longest_outage_s"] == pytest.approx(0.25)
    assert result["icmp"]["outage"]["failed_observations"] == 2
    assert result["icmp"]["outage"]["outage_lower_bound_s"] == pytest.approx(0.25)
    assert result["icmp"]["outage"]["outage_upper_bound_s"] == pytest.approx(0.75)
    assert result["tcp"]["survived"] is True
    assert "rm -f" in commands[0]


def test_fabric_partial_pair_build_is_cleaned_immediately(config_factory, monkeypatch):
    group = PlannedGroup(
        id="provider-a",
        kind="provider",
        label="Provider A",
        network_id="network-a",
        network_name="Provider A",
        subnet_ids=["subnet-a"],
        families=[4],
    )
    stopped = []
    cleaned = []
    builder = SimpleNamespace(
        build_group=lambda *args, **kwargs: None,
        group_failure_reason=lambda group_id: "injected partial build failure",
        stop_group_probes=lambda group_id: stopped.append(group_id),
        runtime_groups=[],
    )
    executor = SimpleNamespace(
        config=config_factory(action="run", fabric_scale_enabled=True),
        plan=Plan([group], [], {}, [], tests=[]),
        builder=builder,
        reporter=SimpleNamespace(scope="az1"),
        cleanup_manager=SimpleNamespace(
            cleanup_group=lambda group_id: cleaned.append(group_id)
        ),
        logger=SimpleNamespace(section=lambda message: None),
    )
    runner = ConcurrentLoadRunner(executor)
    monkeypatch.setattr(runner, "_base_group", lambda: group)

    with pytest.raises(SuiteError, match="partial build failure"):
        runner._create_pairs(1)
    assert stopped == ["concurrent-load-provider-a-1"]
    assert cleaned == ["concurrent-load-provider-a-1"]


def test_fabric_traffic_run_measures_both_directions_and_loaded_quality(config_factory):
    config = config_factory(
        action="run",
        fabric_scale_duration_seconds=1,
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
    ping_calls = []

    class Performance:
        def _ping(self, *args):
            ping_calls.append(args)
            return {"p95_ms": 1.0 if len(ping_calls) == 1 else 3.0, "loss_pct": 0.0}

        def _tcp_upload(self, source, source_ip, destination_ip, family, **kwargs):
            return {
                "mbps": 500.0 if source_ip.endswith("1") else 400.0,
                "retransmissions": 1,
            }

        def _udp_measurement(self, *args, **kwargs):
            return {"loss_pct": 0.25, "jitter_ms": 0.4, "mbps": 9.8, "pps": 9000}

    pairs = [
        {
            "source": object(),
            "destination": object(),
            "source_ip": "192.0.2.1",
            "destination_ip": "192.0.2.2",
            "family": 4,
        },
        {
            "source": object(),
            "destination": object(),
            "source_ip": "192.0.2.3",
            "destination_ip": "192.0.2.4",
            "family": 4,
        },
    ]
    result = runner._traffic_run(Performance(), pairs)
    assert result["forward_aggregate_mbps"] == 900.0
    assert result["reverse_aggregate_mbps"] == 800.0
    assert result["aggregate_mbps"] == 850.0
    assert result["loaded_latency_ratio"] == 3.0
    assert result["loaded_udp"]["loss_pct"] == 0.25
    assert result["retransmissions"] == 4
    assert result["loaded_retransmissions"] == 2
    assert result["loaded_tcp_aggregate_mbps"] == 900.0
    windows = result["tcp_windows"]
    assert len(windows) == 6
    assert [row["direction"] for row in windows] == [
        "forward",
        "forward",
        "reverse",
        "reverse",
        "forward",
        "forward",
    ]
    assert windows[0]["source_label"] == "192.0.2.1"
    assert windows[2]["source_label"] == "192.0.2.2"
    assert windows[2]["destination_label"] == "192.0.2.1"
    assert all(row["retransmissions"] == 1 for row in windows)
    assert "elapsed_s" not in windows[0]
    # Aggregate totals remain available, but are not confused with a window.
    summary = _performance_summary(
        [
            {
                "details": {
                    "measurement": "concurrent-path-load",
                    "metrics": {"levels": [{"pairs_used": 2, "runs": [result]}]},
                },
            }
        ]
    )
    assert summary["worst_tcp_retransmissions"] == 1
    assert summary["worst_tcp_retransmission_window"]["elapsed_s"] is None


def test_fabric_summary_exposes_operator_quality_metrics():
    summary = _performance_summary(
        [
            {
                "status": "PASS",
                "details": {
                    "performance": True,
                    "measurement": "concurrent-path-load",
                    "health": "good",
                    "metrics": {
                        "levels": [
                            {
                                "pairs": 4,
                                "median_aggregate_mbps": 3200.0,
                                "median_pair_mbps": 760.0,
                                "minimum_fairness": 0.91,
                                "maximum_loaded_loss_pct": 0.4,
                                "per_pair_degradation_pct": 24.0,
                                "median_loaded_latency_ratio": 3.5,
                                "maximum_loaded_udp_jitter_ms": 0.8,
                                "median_loaded_tcp_aggregate_mbps": 2800.0,
                                "total_retransmissions": 3,
                                "total_loaded_retransmissions": 7,
                            }
                        ]
                    },
                },
            }
        ]
    )
    assert summary["concurrent_load_max_pairs"] == 4
    assert summary["concurrent_load_lowest_pair_mbps"] == 760.0
    assert summary["concurrent_load_worst_degradation_pct"] == 24.0
    assert summary["concurrent_load_worst_loaded_latency_ratio"] == 3.5
    assert (
        summary["concurrent_load_highest_observed_loaded_tcp_aggregate_mbps"] == 2800.0
    )
    assert summary["concurrent_load_worst_clean_retransmissions"] == 3.0
    assert summary["concurrent_load_worst_loaded_retransmissions"] == 7.0
