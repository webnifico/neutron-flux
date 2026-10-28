from __future__ import annotations

import json
import socket
import struct
import subprocess
import sys
import time
from types import SimpleNamespace

from neutron_flux.models import Endpoint
from neutron_flux.performance import (
    PerformancePath,
    PerformanceRunner,
    ResolvedPerformancePath,
)
from neutron_flux.probe_service import ProbeServiceManager
from neutron_flux.reporting import Reporter


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


def _resolved_path() -> ResolvedPerformancePath:
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


def _tcp_summary(mbps: float = 1000.0) -> dict:
    run = {
        "streams": 1,
        "mbps": mbps,
        "client_mss": 1410,
        "server_mss": 1410,
        "stream_mbps": [mbps],
    }
    summary = {
        "runs": [run],
        "median_mbps": mbps,
        "minimum_mbps": mbps,
        "maximum_mbps": mbps,
        "mean_mbps": mbps,
        "stdev_mbps": 0.0,
        "variation_pct": 2.0,
        "client_mss": 1410,
        "server_mss": 1410,
    }
    return {"repeats": [run], "streams": {"1": summary}}


def test_udp_receiver_waits_for_reordered_tail_and_uses_sender_duration():
    tcp_port = _free_port(socket.SOCK_STREAM, offset=2)
    udp_port = _free_port(socket.SOCK_DGRAM)
    endpoint = _endpoint("local-tail", "A", "127.0.0.1", "local")
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
        session = 202
        started = time.monotonic_ns()
        sock.sendto(
            data_header.pack(b"NFP1", session, 0, started),
            ("127.0.0.1", udp_port),
        )
        sock.sendto(
            end_header.pack(b"NFE1", session, 2, 1_000_000_000),
            ("127.0.0.1", udp_port),
        )
        time.sleep(0.02)
        for _ in range(2):
            sock.sendto(
                data_header.pack(b"NFP1", session, 1, started + 500_000_000),
                ("127.0.0.1", udp_port),
            )
        response, _ = sock.recvfrom(65535)
        metrics = json.loads(response[4:])
        assert metrics["received"] == 2
        assert metrics["lost"] == 0
        assert metrics["loss_pct"] == 0.0
        assert metrics["duplicates"] == 1
        assert metrics["wire_received"] == 3
        assert metrics["elapsed_s"] == 1.0
        assert metrics["pps"] == 2.0
        assert metrics["mbps"] < 1.0
        assert metrics["finalization_grace_s"] == 0.5
    finally:
        if sock is not None:
            sock.close()
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
        if server.stdout is not None:
            server.stdout.close()
        if server.stderr is not None:
            server.stderr.close()


def test_bidirectional_tcp_failure_does_not_erase_concurrency_or_repeatability(
    config_factory, tmp_path, monkeypatch
):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    reporter = Reporter(config, "partial-tcp")
    runner = PerformanceRunner(config, SimpleNamespace(), reporter, SimpleNamespace())
    tcp = _tcp_summary()
    monkeypatch.setattr(runner, "_tcp_direction", lambda *args, **kwargs: tcp)
    monkeypatch.setattr(
        runner,
        "_bidirectional_tcp",
        lambda path: (_ for _ in ()).throw(RuntimeError("bidirectional unavailable")),
    )
    metrics, payloads, error = runner._measure_tcp_family(_resolved_path())
    assert set(metrics) == {"forward", "reverse"}
    assert set(payloads) == {"concurrency", "repeatability"}
    assert isinstance(error, RuntimeError)

    measurements, errors = runner._measure(_resolved_path())
    assert errors["tcp-throughput"].args == ("bidirectional unavailable",)
    assert "concurrency" in measurements
    assert "repeatability" in measurements


def test_udp_receiver_handles_maximum_sequence_without_proportional_allocation():
    tcp_port = _free_port(socket.SOCK_STREAM, offset=2)
    udp_port = _free_port(socket.SOCK_DGRAM)
    endpoint = _endpoint("local-sparse", "A", "127.0.0.1", "local")
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
        session = 303
        now = time.monotonic_ns()
        # A uint32 sequence at the protocol maximum previously implied a
        # roughly 512 MiB contiguous bitset. Sparse chunks keep this bounded.
        sock.sendto(
            data_header.pack(b"NFP1", session, 0xFFFFFFFF, now),
            ("127.0.0.1", udp_port),
        )
        sock.sendto(
            end_header.pack(b"NFE1", session, 1, 1_000_000_000),
            ("127.0.0.1", udp_port),
        )
        response, _ = sock.recvfrom(65535)
        metrics = json.loads(response[4:])
        assert metrics["received"] == 1
        assert metrics["lost"] == 0
        assert server.poll() is None
        server_code = manager._server_code(endpoint)
        assert "seen_chunks" in server_code
        assert "UDP_SEQUENCE_CHUNK_BYTES" in server_code
        assert "seen_bits.extend" not in server_code
    finally:
        if sock is not None:
            sock.close()
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
        if server.stdout is not None:
            server.stdout.close()
        if server.stderr is not None:
            server.stderr.close()
