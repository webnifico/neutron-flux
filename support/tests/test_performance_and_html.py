from __future__ import annotations

import dataclasses
import json
import re
import socket
import struct
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from neutron_flux.models import (
    Endpoint,
    Plan,
    PlannedGroup,
    RuntimeGroup,
)
from neutron_flux.models import (
    TestSpec as FluxTestSpec,
)
from neutron_flux.performance import PerformanceRunner, _parse_ping
from neutron_flux.probe_service import ProbeServiceManager
from neutron_flux.reporting import Reporter, ScopedReporter


def _free_port(socket_type: int, *, offset: int = 0) -> int:
    while True:
        sock = socket.socket(socket.AF_INET, socket_type)
        sock.bind(("127.0.0.1", 0))
        port = int(sock.getsockname()[1]) - offset
        sock.close()
        if port <= 1024 or port + offset > 65535:
            continue
        checks = []
        try:
            for candidate in sorted({port, port + offset}):
                check = socket.socket(socket.AF_INET, socket_type)
                checks.append(check)
                check.bind(("127.0.0.1", candidate))
        except OSError:
            continue
        finally:
            for check in checks:
                check.close()
        return port


def _close_probe_process(
    server: subprocess.Popen[str], sock: socket.socket | None = None
) -> None:
    if sock is not None:
        sock.close()
    server.terminate()
    try:
        server.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=5)
    for pipe in (server.stdout, server.stderr):
        if pipe is not None:
            pipe.close()


def _endpoint(label: str, side: str, address: str, host: str) -> Endpoint:
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
        availability_zone="az1",
        volume_id=None,
        side=side,
    )


def _reverse_tcp_spec(spec: FluxTestSpec, test_id: str | None = None) -> FluxTestSpec:
    return dataclasses.replace(
        spec,
        id=test_id or f"{spec.id}-REVERSE",
        source_group_id=spec.destination_group_id,
        destination_group_id=spec.source_group_id,
        source_side=spec.destination_side,
        destination_side=spec.source_side,
        source_subnet_id=spec.destination_subnet_id,
        destination_subnet_id=spec.source_subnet_id,
    )


def test_parse_ping_calculates_percentiles_and_loss():
    output = """PING 192.0.2.11 (192.0.2.11) 56(84) bytes of data.
64 bytes from 192.0.2.11: icmp_seq=1 ttl=64 time=0.4 ms
64 bytes from 192.0.2.11: icmp_seq=2 ttl=64 time=0.8 ms
64 bytes from 192.0.2.11: icmp_seq=3 ttl=64 time=1.2 ms

--- 192.0.2.11 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 201ms
rtt min/avg/max/mdev = 0.400/0.800/1.200/0.100 ms
"""
    result = _parse_ping(0, output, "")
    assert result["loss_pct"] == 0.0
    assert result["p50_ms"] == 0.8
    assert result["p95_ms"] > 1.1
    assert result["received"] == 3


def test_builtin_probe_service_runs_tcp_and_udp_performance_protocols():
    tcp_port = _free_port(socket.SOCK_STREAM, offset=2)
    udp_port = _free_port(socket.SOCK_DGRAM)
    endpoint = _endpoint("local", "A", "127.0.0.1", "local")
    manager = ProbeServiceManager(tcp_port, udp_port)
    server = subprocess.Popen(
        [sys.executable, "-u", "-c", manager._server_code(endpoint)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    sock: socket.socket | None = None
    try:
        assert server.stdout is not None
        ready = server.stdout.readline().strip()
        assert "NEUTRON_FLUX_READY" in ready
        assert "performance=builtin" in ready

        tcp_code = PerformanceRunner._tcp_client_code(
            "127.0.0.1", "127.0.0.1", 4, tcp_port, 1, 2
        )
        tcp = subprocess.run(
            [sys.executable, "-c", tcp_code],
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert tcp.returncode == 0, tcp.stderr
        tcp_result = json.loads(tcp.stdout)
        assert tcp_result["streams"] == 2
        assert tcp_result["mbps"] > 0
        assert tcp_result["client_mss"] > 0
        assert "retransmissions" in tcp_result

        udp_code = PerformanceRunner._udp_client_code(
            "127.0.0.1", "127.0.0.1", 4, udp_port, 1, 1, 128
        )
        udp = subprocess.run(
            [sys.executable, "-c", udp_code],
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert udp.returncode == 0, udp.stderr
        udp_result = json.loads(udp.stdout)
        assert udp_result["sent"] > 0
        assert udp_result["received"] > 0
        assert udp_result["wire_received"] >= udp_result["received"]
        assert udp_result["duplicates"] == 0
        assert udp_result["jitter_ms"] >= 0
        server_code = manager._server_code(endpoint)
        assert "seen_chunks" in server_code
        assert "seen_sequences" not in server_code
        assert "120_000_000_000" in server_code
    finally:
        _close_probe_process(server, sock)


def test_reporter_writes_self_contained_visual_and_json_reports(
    config_factory, tmp_path
):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    reporter = Reporter(config, "visual-report")
    reporter.plan = Plan([], [], {}, [], tests=[])
    reporter.cleanup_summary.update({"attempted": True, "complete": True})
    reporter.result(
        "FUNCTIONAL-PASS",
        "same-subnet",
        "PASS",
        "VM path was reachable",
        family=4,
        source="vm-a (192.0.2.10)",
        destination="vm-b (192.0.2.11)",
        expected="reachable",
        observed="reachable",
        authoritative=True,
        display_name="TCP reachability",
        scenario="Same-network connectivity",
    )
    reporter.result(
        "PERF-PATH-TCP",
        "network-performance",
        "PASS",
        "Completed TCP throughput",
        family=4,
        source="vm-a (192.0.2.10)",
        destination="vm-b (192.0.2.11)",
        expected="measurement-complete",
        observed="measured",
        authoritative=True,
        display_name="TCP throughput",
        scenario="Tenant-visible network performance",
        details={
            "performance": True,
            "measurement": "tcp-throughput",
            "health": "good",
            "path": {
                "path_id": "PATH-1",
                "source_label": "vm-a",
                "destination_label": "vm-b",
                "family": 4,
                "source_category": "same-subnet",
                "placement": "cross-compute",
                "availability_scope": "same-az",
                "stage": "group-local",
            },
            "metrics": {
                "forward": {"streams": {"1": {"median_mbps": 9000}}},
                "reverse": {"streams": {"1": {"median_mbps": 8700}}},
                "bidirectional": {"aggregate_mbps": 15000},
            },
        },
    )
    assert reporter.finalize(0) == 0
    payload = json.loads(reporter.results_path.read_text())
    html = reporter.html_report_path.read_text()
    assert payload["run"]["final_status"] == "PASS"
    assert len(payload["results"]) == 2
    assert payload["performance"]["storage"] == "canonical-results"
    assert payload["performance"]["result_count"] == 1
    assert payload["performance"]["result_ids"] == ["PERF-PATH-TCP"]
    assert payload["summary"]["performance"]["paths"] == 1
    assert payload["summary"]["performance"]["lowest_single_stream_mbps"] == 8700
    assert "TCP throughput" in html
    assert 'id="performanceSummary"' in html
    assert 'id="performancePaths"' in html
    thresholds = payload["configuration"]["performance_thresholds"]
    assert thresholds["udp_loss_pct"] == config.performance_udp_loss_threshold_pct
    assert (
        thresholds["udp_reordering_pct"]
        == config.performance_udp_reordering_threshold_pct
    )
    assert (
        thresholds["udp_sender_achievement_pct"]
        == config.performance_udp_sender_achievement_threshold_pct
    )
    assert len(thresholds) == 6
    assert 'data-view="findings"' in html
    assert "Review queue" in html
    assert 'id="findingList"' in html
    assert "Performance tests" in html
    assert "What this test checks" in html
    assert "font:15px/1.55" in html
    assert 'id="coverageLimits"' in html
    # URL parsing validates typed IPv6 addresses without fetching anything.
    # Offline reports must not load remote scripts, styles, images or frames.
    assert not re.search(
        r'<(?:script|link|img|iframe)\b[^>]*(?:src|href)=["\']https?://', html, re.I
    )
    assert "fetch(" not in html


def test_udp_performance_counts_unique_packets_duplicates_and_loss():
    tcp_port = _free_port(socket.SOCK_STREAM, offset=2)
    udp_port = _free_port(socket.SOCK_DGRAM)
    endpoint = _endpoint("local-duplicates", "A", "127.0.0.1", "local")
    manager = ProbeServiceManager(tcp_port, udp_port)
    server = subprocess.Popen(
        [sys.executable, "-u", "-c", manager._server_code(endpoint)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    sock: socket.socket | None = None
    try:
        assert server.stdout is not None
        assert "NEUTRON_FLUX_READY" in server.stdout.readline()
        data_header = struct.Struct("!4sQIQ")
        end_header = struct.Struct("!4sQIQ")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        session = 101
        now = time.monotonic_ns()
        for sequence in (0, 0, 2):
            sock.sendto(
                data_header.pack(
                    b"NFP1", session, sequence, now + sequence * 1_000_000
                ),
                ("127.0.0.1", udp_port),
            )
        sock.sendto(
            end_header.pack(b"NFE1", session, 3, 1_000_000_000), ("127.0.0.1", udp_port)
        )
        response, _ = sock.recvfrom(65535)
        metrics = json.loads(response[4:])
        assert metrics["wire_received"] == 3
        assert metrics["received"] == 2
        assert metrics["duplicates"] == 1
        assert metrics["lost"] == 1
        assert metrics["loss_pct"] == 100.0 / 3.0
    finally:
        _close_probe_process(server, sock)


def test_performance_planner_ignores_paths_that_did_not_pass(config_factory, tmp_path):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    reporter = Reporter(config, "performance-skip")
    reporter.result(
        "BASE-FAILED",
        "same-subnet",
        "FAIL",
        "not reachable",
        family=4,
        expected="reachable",
        observed="blocked",
        authoritative=True,
    )
    source = FluxTestSpec(
        id="BASE-FAILED",
        category="same-subnet",
        operation="probe",
        family=4,
        expectation="reachable",
        expectation_reason="functional path",
        authoritative=True,
        dependencies=["group"],
        source_group_id="group",
        destination_group_id="group",
        source_side="A",
        destination_side="B",
        source_subnet_id="subnet",
        destination_subnet_id="subnet",
        protocol="tcp",
        phase="intra",
    )
    runner = PerformanceRunner(config, SimpleNamespace(), reporter, SimpleNamespace())
    assert runner.plan_specs([source], stage="group-local") == []


def test_loaded_latency_keeps_tcp_load_active_for_full_ping_sample(
    config_factory, tmp_path, monkeypatch
):
    config = config_factory(
        action="run",
        report_dir=tmp_path / "reports",
        performance_duration_seconds=1,
        performance_ping_count=50,
        performance_tcp_streams=[1, 4],
    )
    reporter = Reporter(config, "loaded-latency")
    runner = PerformanceRunner(config, SimpleNamespace(), reporter, SimpleNamespace())
    captured = {}

    def fake_upload(*args, **kwargs):
        captured["duration"] = kwargs["duration_seconds"]
        return {"mbps": 100.0, "streams": kwargs["streams"]}

    monkeypatch.setattr(runner, "_tcp_upload", fake_upload)
    monkeypatch.setattr(
        runner,
        "_ping",
        lambda *args, **kwargs: {"p95_ms": 1.0, "loss_pct": 0.0},
    )
    result = runner._loaded_latency(
        _endpoint("a", "A", "192.0.2.10", "compute1"),
        "192.0.2.10",
        "192.0.2.11",
        4,
    )
    assert captured["duration"] >= 12
    assert result["load_mbps"] == 100.0


def test_reporter_can_disable_html_but_keeps_structured_json(config_factory, tmp_path):
    config = config_factory(
        action="run", report_dir=tmp_path / "reports", html_report_enabled=False
    )
    reporter = Reporter(config, "json-only")
    active = json.loads(reporter.active_path.read_text())
    assert active["html_report"] is None
    reporter.plan = Plan([], [], {}, [], tests=[])
    reporter.cleanup_summary.update({"attempted": True, "complete": True})
    assert reporter.finalize(0) == 0
    assert reporter.results_path.is_file()
    assert not reporter.html_report_path.exists()
    assert "Visual report:   disabled" in reporter.report_path.read_text()


def _resolved_path():
    from neutron_flux.performance import PerformancePath, ResolvedPerformancePath

    plan = PerformancePath(
        path_id="PATH-UNIT",
        source_spec_id="BASE",
        category="tenant-router",
        family=4,
        source_group_id="ga",
        destination_group_id="gb",
        source_side="A",
        destination_side="B",
        source_subnet_id="sa",
        destination_subnet_id="sb",
        stage="group-local",
        execution_scope=None,
    )
    return ResolvedPerformancePath(
        plan=plan,
        source=_endpoint("source", "A", "192.0.2.10", "compute1"),
        destination=_endpoint("destination", "B", "198.51.100.10", "compute2"),
        source_ip="192.0.2.10",
        destination_ip="198.51.100.10",
        source_mtu=1500,
        destination_mtu=1450,
        placement="cross-compute",
        availability_scope="same-az",
    )


def _tcp_summary(mbps=1000.0, variation=2.0, streams=1):
    run = {
        "streams": streams,
        "mbps": mbps,
        "client_mss": 1410,
        "server_mss": 1410,
        "stream_mbps": [mbps / streams] * streams,
    }
    return {
        "repeats": [run],
        "streams": {
            str(streams): {
                "runs": [run],
                "median_mbps": mbps,
                "minimum_mbps": mbps,
                "maximum_mbps": mbps,
                "mean_mbps": mbps,
                "stdev_mbps": 0.0,
                "variation_pct": variation,
                "client_mss": 1410,
                "server_mss": 1410,
            },
            "1": {
                "runs": [{**run, "streams": 1, "stream_mbps": [mbps]}],
                "median_mbps": mbps,
                "minimum_mbps": mbps,
                "maximum_mbps": mbps,
                "mean_mbps": mbps,
                "stdev_mbps": 0.0,
                "variation_pct": variation,
                "client_mss": 1410,
                "server_mss": 1410,
            },
        },
    }


def test_measure_orchestrates_all_seven_payloads(config_factory, tmp_path, monkeypatch):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    reporter = Reporter(config, "measure-all")
    runner = PerformanceRunner(config, SimpleNamespace(), reporter, SimpleNamespace())
    tcp = _tcp_summary()
    ping = {"loss_pct": 0.0, "p95_ms": 1.0}
    loaded = {"loss_pct": 0.0, "p95_ms": 2.0, "load_mbps": 900.0, "load_streams": 8}
    udp = {
        "forward": [{"loss_pct": 0.0, "jitter_ms": 0.2}],
        "reverse": [{"loss_pct": 0.0, "jitter_ms": 0.3}],
    }
    mtu_item = {"discovered_mtu": 1450, "probe_mode": "df-pmtud"}
    monkeypatch.setattr(runner, "_tcp_direction", lambda *args, **kwargs: tcp)
    monkeypatch.setattr(
        runner,
        "_bidirectional_tcp",
        lambda path: {"forward_mbps": 900, "reverse_mbps": 850, "aggregate_mbps": 1750},
    )
    monkeypatch.setattr(runner, "_ping", lambda *args, **kwargs: dict(ping))
    monkeypatch.setattr(runner, "_loaded_latency", lambda *args, **kwargs: dict(loaded))
    monkeypatch.setattr(runner, "_udp_matrix", lambda path: udp)
    monkeypatch.setattr(runner, "_mtu_probe", lambda *args, **kwargs: dict(mtu_item))
    monkeypatch.setattr(
        runner,
        "_fragmentation_probe",
        lambda *args, **kwargs: {
            "capability": "not-required",
            "fragmentation_model": "ipv4-fragmentation-permitted",
            "tested_packet_size": 1450,
        },
    )
    payloads, errors = runner._measure(_resolved_path())
    assert errors == {}
    assert set(payloads) == {name for name, _ in runner.MEASUREMENTS}
    assert all(item["health"] == "good" for item in payloads.values())
    assert payloads["mtu-mss"]["metrics"]["expected_mtu"] == 1450


def test_tcp_direction_summarizes_repeats_and_stream_counts(
    config_factory, tmp_path, monkeypatch
):
    config = config_factory(
        action="run",
        report_dir=tmp_path / "reports",
        performance_repeats=3,
        performance_tcp_streams=[1, 4],
    )
    reporter = Reporter(config, "tcp-summary")
    runner = PerformanceRunner(config, SimpleNamespace(), reporter, SimpleNamespace())
    calls = []

    def upload(*args, streams, **kwargs):
        calls.append(streams)
        return {
            "streams": streams,
            "mbps": 100.0 * streams,
            "client_mss": 1400,
            "server_mss": 1400,
            "stream_mbps": [100.0] * streams,
        }

    monkeypatch.setattr(runner, "_tcp_upload", upload)
    result = runner._tcp_direction(
        _endpoint("a", "A", "192.0.2.10", "compute1"),
        "192.0.2.10",
        "192.0.2.11",
        4,
    )
    assert calls == [1, 1, 1, 1, 4]
    assert len(result["repeats"]) == 3
    assert result["streams"]["1"]["warmup_samples"] == 1
    assert result["streams"]["1"]["median_mbps"] == 100.0
    assert result["streams"]["4"]["median_mbps"] == 400.0


def test_udp_matrix_adds_near_mtu_and_both_directions(
    config_factory, tmp_path, monkeypatch
):
    config = config_factory(
        action="run",
        report_dir=tmp_path / "reports",
        performance_udp_rates_mbps=[10],
        performance_udp_packet_sizes=[128],
    )
    reporter = Reporter(config, "udp-matrix")
    runner = PerformanceRunner(config, SimpleNamespace(), reporter, SimpleNamespace())
    calls = []

    def measure(endpoint, source_ip, destination_ip, family, rate, size):
        calls.append((source_ip, destination_ip, rate, size))
        return {"loss_pct": 0.0, "jitter_ms": 0.1}

    monkeypatch.setattr(runner, "_udp_measurement", measure)
    result = runner._udp_matrix(_resolved_path())
    assert len(result["forward"]) == 2
    assert len(result["reverse"]) == 2
    assert {item[3] for item in calls} == {128, 1422}


def test_performance_health_assessments_cover_warning_and_critical(
    config_factory, tmp_path
):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    runner = PerformanceRunner(
        config, SimpleNamespace(), Reporter(config, "health"), SimpleNamespace()
    )
    assert (
        runner._tcp_health({"forward": _tcp_summary(), "reverse": _tcp_summary(0.0)})
        == "critical"
    )
    assert (
        runner._latency_health(
            {
                "idle": {"forward": {"loss_pct": 0}, "reverse": {"loss_pct": 0}},
                "loaded": {"forward": {"loss_pct": 0}, "reverse": {"loss_pct": 0}},
                "loaded_p95_ratio": {"forward": 20.0, "reverse": 1.0},
            }
        )
        == "warning"
    )
    assert (
        runner._udp_health(
            {"forward": [{"loss_pct": 2.0}], "reverse": [{"loss_pct": 0.0}]}
        )
        == "warning"
    )
    assert (
        runner._udp_health({"forward": [{"loss_pct": 100.0}], "reverse": []})
        == "critical"
    )
    assert (
        runner._udp_health(
            {
                "forward": [{"loss_pct": 0.0, "duplicates": 1}],
                "reverse": [{"loss_pct": 0.0}],
            }
        )
        == "warning"
    )
    assert (
        runner._latency_health(
            {
                "idle": {"forward": {"loss_pct": 0}, "reverse": {"loss_pct": 0}},
                "loaded": {
                    "forward": {"loss_pct": 100},
                    "reverse": {"loss_pct": 0},
                },
                "loaded_p95_ratio": {"forward": None, "reverse": 1.0},
            }
        )
        == "critical"
    )
    asymmetry = runner._asymmetry(
        {"streams": {"1": {"median_mbps": 1000.0}}},
        {"streams": {"1": {"median_mbps": 1000.0}}},
        {"forward": {"p95_ms": 1.0}, "reverse": {"p95_ms": 1.0}},
        {"forward": [{"loss_pct": 0.0}], "reverse": [{"loss_pct": 5.0}]},
    )
    assert asymmetry["udp_loss_difference_pct_points"] == 5.0
    assert asymmetry["health"] == "warning"

    assert (
        runner._mtu_health(
            {
                "forward": {
                    "discovered_mtu": 1500,
                    "expected_max_mss": 1460,
                    "client_mss": 1460,
                    "server_mss": 1460,
                    "probe_mode": "fragmentation-permitted-fallback",
                },
                "reverse": {
                    "discovered_mtu": 1500,
                    "expected_max_mss": 1460,
                    "client_mss": 1460,
                    "server_mss": 1460,
                    "probe_mode": "df-pmtud",
                },
            },
            1500,
        )
        == "warning"
    )
    assert (
        runner._mtu_health(
            {
                "forward": {
                    "discovered_mtu": 1499,
                    "expected_max_mss": 1459,
                    "client_mss": 1459,
                },
                "reverse": {
                    "discovered_mtu": 1500,
                    "expected_max_mss": 1460,
                    "client_mss": 1460,
                },
            },
            1500,
        )
        == "warning"
    )
    assert (
        runner._mtu_health(
            {
                "forward": {
                    "discovered_mtu": 1500,
                    "expected_max_mss": 1460,
                    "client_mss": 1460,
                    "server_mss": 1460,
                    "above_expected_reachable": True,
                    "probe_mode": "df-pmtud",
                },
                "reverse": {
                    "discovered_mtu": 1500,
                    "expected_max_mss": 1460,
                    "client_mss": 1460,
                    "server_mss": 1460,
                    "above_expected_reachable": False,
                    "probe_mode": "df-pmtud",
                },
            },
            1500,
        )
        == "warning"
    )
    assert (
        runner._mtu_health(
            {
                "forward": {
                    "discovered_mtu": 1500,
                    "expected_max_mss": 1460,
                    "client_mss": 1460,
                    "server_mss": 1461,
                },
                "reverse": {
                    "discovered_mtu": 1500,
                    "expected_max_mss": 1460,
                    "client_mss": 1460,
                    "server_mss": 1460,
                },
            },
            1500,
        )
        == "critical"
    )


def test_run_specs_records_success_and_isolates_measurement_errors(
    config_factory, tmp_path, monkeypatch
):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    reporter = Reporter(config, "run-specs")
    runner = PerformanceRunner(config, SimpleNamespace(), reporter, SimpleNamespace())
    path = _resolved_path().plan
    specs = []
    for measurement, label in runner.MEASUREMENTS:
        spec = FluxTestSpec(
            id=f"PERF-{measurement}",
            category="network-performance",
            operation=f"performance-{measurement}",
            family=4,
            expectation="measurement-complete",
            expectation_reason="eligible",
            authoritative=True,
            dependencies=["ga", "gb"],
            metadata={
                "performance_path_id": path.path_id,
                "performance_measurement": measurement,
            },
            display_name=label,
            scenario="Tenant-visible network performance",
        )
        runner._planned[spec.id] = path
        specs.append(spec)
    monkeypatch.setattr(runner, "_resolve", lambda value: _resolved_path())
    monkeypatch.setattr(
        runner,
        "_measure",
        lambda value: (
            {
                measurement: {"label": label, "health": "good", "metrics": {"ok": True}}
                for measurement, label in runner.MEASUREMENTS
            },
            {},
        ),
    )
    runner.run_specs(specs)
    assert all(reporter.get_result(spec.id).status == "PASS" for spec in specs)

    reporter_partial = Reporter(config, "run-specs-partial")
    runner_partial = PerformanceRunner(
        config, SimpleNamespace(), reporter_partial, SimpleNamespace()
    )
    for spec in specs:
        runner_partial._planned[spec.id] = path
    monkeypatch.setattr(runner_partial, "_resolve", lambda value: _resolved_path())
    monkeypatch.setattr(
        runner_partial,
        "_measure",
        lambda value: (
            {
                measurement: {"label": label, "health": "good", "metrics": {"ok": True}}
                for measurement, label in runner.MEASUREMENTS
                if measurement != "udp"
            },
            {"udp": RuntimeError("UDP statistics unavailable")},
        ),
    )
    runner_partial.run_specs(specs)
    assert reporter_partial.get_result("PERF-udp").status == "ERROR"
    assert all(
        reporter_partial.get_result(spec.id).status == "PASS"
        for spec in specs
        if spec.id != "PERF-udp"
    )

    reporter2 = Reporter(config, "run-specs-error")
    runner2 = PerformanceRunner(config, SimpleNamespace(), reporter2, SimpleNamespace())
    for spec in specs:
        runner2._planned[spec.id] = path
    monkeypatch.setattr(
        runner2, "_resolve", lambda value: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    runner2.run_specs(specs)
    statuses = [reporter2.get_result(spec.id).status for spec in specs]
    assert statuses.count("ERROR") == 1
    assert statuses.count("UNVERIFIED") == len(specs) - 1


def test_run_json_classifies_remote_output(config_factory, tmp_path):
    from neutron_flux.errors import SuiteError

    config = config_factory(action="run", report_dir=tmp_path / "reports")
    endpoint = _endpoint("a", "A", "192.0.2.10", "compute1")

    class Builder:
        result = SimpleNamespace(returncode=0, stdout='noise\n{"ok":true}\n', stderr="")

        def ssh_endpoint(self, *args, **kwargs):
            return self.result

    builder = Builder()
    runner = PerformanceRunner(
        config, builder, Reporter(config, "run-json"), SimpleNamespace()
    )
    value = runner._run_json(endpoint, "print('{}')", timeout=5)
    assert value["ok"] is True
    assert value["execution_evidence"]["command"].startswith("python3 -c ")
    assert value["execution_evidence"]["server_id"] == endpoint.server_id
    assert value["execution_evidence"]["location"] == "guest"
    assert value["execution_evidence"]["returncode"] == 0
    builder.result = SimpleNamespace(returncode=1, stdout="", stderr="failed")
    with pytest.raises(SuiteError, match="remote performance command failed"):
        runner._run_json(endpoint, "bad", timeout=5)
    builder.result = SimpleNamespace(returncode=0, stdout="", stderr="")
    with pytest.raises(SuiteError, match="returned no JSON"):
        runner._run_json(endpoint, "empty", timeout=5)
    builder.result = SimpleNamespace(returncode=0, stdout="not-json", stderr="")
    with pytest.raises(SuiteError, match="invalid JSON"):
        runner._run_json(endpoint, "invalid", timeout=5)


def test_multi_az_performance_path_ids_include_execution_scope(
    config_factory, tmp_path
):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    parent = Reporter(config, "scoped-performance")
    group = PlannedGroup(
        "group", "provider", "Provider", "network", "network", ["subnet"], [4]
    )
    runtime = RuntimeGroup(
        plan=group,
        network_id="network",
        network_name="network",
        subnet_ids=["subnet"],
        router_id=None,
        endpoints=[
            _endpoint("a", "A", "192.0.2.10", "compute1"),
            _endpoint("b", "B", "192.0.2.11", "compute2"),
        ],
        source_nat_enabled=None,
        fips={},
    )
    engine = SimpleNamespace(
        _endpoint_address=lambda group_id, side, subnet_id: (
            runtime.endpoint(side),
            runtime.endpoint(side).fixed_ips["subnet"],
        ),
        _network_mtu=lambda group_id: 1500,
    )
    source = FluxTestSpec(
        id="BASE",
        category="same-subnet",
        operation="probe",
        family=4,
        expectation="reachable",
        expectation_reason="passed",
        authoritative=True,
        dependencies=["group"],
        source_group_id="group",
        destination_group_id="group",
        source_side="A",
        destination_side="B",
        source_subnet_id="subnet",
        destination_subnet_id="subnet",
        protocol="tcp",
        phase="intra",
    )
    path_ids = []
    for scope in ("az-one", "az-two"):
        scoped = ScopedReporter(parent, scope, availability_zone=scope)
        scoped.result(
            "BASE",
            "same-subnet",
            "PASS",
            "reachable",
            family=4,
            expected="reachable",
            observed="reachable",
            authoritative=True,
            details={"execution_stage": "post-live-migration"},
        )
        scoped.result(
            "BASE-REVERSE",
            "same-subnet",
            "PASS",
            "reachable",
            family=4,
            expected="reachable",
            observed="reachable",
            authoritative=True,
        )
        planned = PerformanceRunner(
            config, SimpleNamespace(), scoped, engine
        ).plan_specs(
            [source, _reverse_tcp_spec(source, "BASE-REVERSE")],
            stage="group-local",
        )
        path_ids.append(planned[0].metadata["performance_path_id"])
        assert planned[0].metadata["execution_stage"] == "post-live-migration"
    assert path_ids[0] != path_ids[1]
    assert path_ids[0].startswith("AZ-ONE")
    assert path_ids[1].startswith("AZ-TWO")


def test_udp_client_reports_sender_elapsed_and_server_finalizes_after_grace():
    code = PerformanceRunner._udp_client_code(
        "192.0.2.10", "192.0.2.20", 4, 18081, 1, 10, 128
    )
    assert "send_finished_ns = time.monotonic_ns()" in code
    assert "END = struct.Struct('!4sQIQ')" in code
    assert "sender_elapsed_ns" in code
    assert "send_finished_ns - started_ns" in code
    assert "time.sleep(0.25)" not in code


def test_mtu_client_recognizes_common_ping_option_errors():
    code = PerformanceRunner._mtu_client_code("192.0.2.10", "192.0.2.20", 4, 1500)
    for marker in (
        "invalid option",
        "illegal option",
        "unknown option",
        "unrecognized option",
        "invalid argument",
    ):
        assert marker in code
    assert "unsupported_ping_option" in code
    assert "classification == 'unsupported'" in code
    assert "'-c', '1'" in code
    assert "TRIALS = 3" in code
    assert "'-W', '1'" in code


def test_performance_path_limit_counts_selected_paths_even_before_completion(
    config_factory, tmp_path
):
    config = config_factory(
        action="run",
        report_dir=tmp_path / "reports",
        performance_max_paths=1,
    )
    reporter = Reporter(config, "performance-selection-limit")
    for test_id in ("BASE-ONE", "BASE-ONE-REVERSE", "BASE-TWO", "BASE-TWO-REVERSE"):
        reporter.result(
            test_id,
            "same-subnet",
            "PASS",
            "reachable",
            family=4,
            expected="reachable",
            observed="reachable",
            authoritative=True,
        )
    endpoints = {
        "A": _endpoint("limit-a", "A", "192.0.2.10", "compute1"),
        "B": _endpoint("limit-b", "B", "192.0.2.11", "compute2"),
    }
    engine = SimpleNamespace(
        _endpoint_address=lambda group_id, side, subnet_id: (
            endpoints[side],
            endpoints[side].fixed_ips["subnet"],
        ),
        _network_mtu=lambda group_id: 1500,
    )

    def source_pair(test_id, group_id):
        forward = FluxTestSpec(
            id=test_id,
            category="same-subnet",
            operation="probe",
            family=4,
            expectation="reachable",
            expectation_reason="passed",
            authoritative=True,
            dependencies=[group_id],
            source_group_id=group_id,
            destination_group_id=group_id,
            source_side="A",
            destination_side="B",
            source_subnet_id="subnet",
            destination_subnet_id="subnet",
            protocol="tcp",
            phase="intra",
        )
        return [forward, _reverse_tcp_spec(forward, f"{test_id}-REVERSE")]

    runner = PerformanceRunner(config, SimpleNamespace(), reporter, engine)
    assert (
        len(runner.plan_specs(source_pair("BASE-ONE", "g1"), stage="group-local")) == 7
    )
    # The first path has been selected but not completed. It must still consume
    # the stage budget so repeated batch planning remains bounded after errors.
    assert runner.plan_specs(source_pair("BASE-TWO", "g2"), stage="group-local") == []
    assert runner.session.selected_by_stage["group-local"] == 1


def test_advisory_performance_health_sets_pass_with_warnings(config_factory, tmp_path):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    reporter = Reporter(config, "performance-warning-status")
    reporter.plan = Plan([], [], {}, [], tests=[])
    reporter.cleanup_summary.update({"attempted": True, "complete": True})
    reporter.result(
        "PERF-WARNING",
        "network-performance",
        "PASS",
        "Completed UDP performance; assessment=warning",
        family=4,
        expected="measurement-complete",
        observed="measured",
        authoritative=True,
        display_name="UDP performance warning",
        scenario="Tenant-visible network performance",
        details={
            "performance": True,
            "measurement": "udp",
            "health": "warning",
            "metrics": {
                "forward": [{"loss_pct": 2.0}],
                "reverse": [{"loss_pct": 0.0}],
            },
            "path": {"path_id": "PATH-WARNING", "family": 4},
        },
    )

    assert reporter.finalize(0) == 0
    payload = json.loads(reporter.results_path.read_text())
    text = reporter.report_path.read_text()
    assert payload["run"]["final_status"] == "PASS WITH WARNINGS"
    assert payload["summary"]["performance"]["warning_results"] == 1
    assert "Network path performance" in text
    assert "PASS WITH WARNINGS" in text
    assert "1 performance measurement warning" in text
    assert "[PASS WITH WARNING]" in text
    assert "Actual result:" in text
    assert "Observation:" in text
    assert "Why this passed:" in text
    assert payload["results"][0]["status"] == "PASS"
