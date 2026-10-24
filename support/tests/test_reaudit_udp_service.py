"""Run the complete generated service on primary/alternate local UDP addresses.

IPv4 uses distinct real local addresses. IPv6 uses real ::1 sockets here;
separate ancillary-boundary tests cover multiple IPv6 addresses and scopes.
"""

from __future__ import annotations

import ast
import contextlib
import errno
import json
import selectors
import shlex
import socket
import struct
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from neutron_flux.probe_service import ProbeServiceManager
from neutron_flux.probes import ProbeContext, TCPProbe, UDPProbe

from ._shared import endpoint


@contextlib.contextmanager
def reserved_service_ports(family):
    # Match the service's wildcard bindings and hold all selections together so
    # its TCP and control listeners cannot receive the same ephemeral port.
    with contextlib.ExitStack() as stack:
        sockets = []
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM, socket.SOCK_STREAM):
            sock = stack.enter_context(socket.socket(family, kind))
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", 0))
            sockets.append(sock)
        yield [sock.getsockname()[1] for sock in sockets]


@pytest.fixture(params=[4, 6])
def live_service(request):
    version = request.param
    family = socket.AF_INET6 if version == 6 else socket.AF_INET
    source_ip, target_ip = (
        ("::1", "::1") if version == 6 else ("127.0.0.2", "127.0.0.3")
    )
    target = endpoint()
    target.management_ip = target_ip
    target.fixed_ips = {"data": target_ip}
    for attempt in range(3):
        with reserved_service_ports(family) as (tcp_port, udp_port, control):
            manager = ProbeServiceManager(tcp_port, udp_port)
            manager.set_control_ports({version: control})
            code = manager._server_code(target)
        # Ports must be released before the child can bind them. Another local
        # socket can win this narrow race; retry only its explicit startup error.
        process = subprocess.Popen(
            [sys.executable, "-u", "-c", code],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            with selectors.DefaultSelector() as poller:
                poller.register(process.stdout, selectors.EVENT_READ)
                assert poller.select(timeout=10), (
                    "Probe service did not produce startup evidence"
                )
                ready = process.stdout.readline().strip()
            if attempt < 2 and ready.startswith(
                f"NEUTRON_FLUX_ERROR OSError: [Errno {errno.EADDRINUSE}] "
            ):
                continue
            assert ready.startswith("NEUTRON_FLUX_READY "), ready
            yield SimpleNamespace(
                manager=manager,
                target=target,
                source_ip=source_ip,
                target_ip=target_ip,
                family=family,
                version=version,
            )
            return
        finally:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)


def test_local_service_fixture_retries_a_real_port_collision_and_reaps_children(
    monkeypatch,
):
    processes = []
    original_popen = subprocess.Popen
    original_code = ProbeServiceManager._server_code

    def start(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        processes.append(process)
        return process

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied:
        occupied.bind(("127.0.0.4", 0))
        occupied.listen(1)

        def code(manager, target):
            if not processes:
                manager.tcp_port = occupied.getsockname()[1]
            return original_code(manager, target)

        monkeypatch.setattr(subprocess, "Popen", start)
        monkeypatch.setattr(ProbeServiceManager, "_server_code", code)
        service = live_service.__wrapped__(SimpleNamespace(param=4))
        try:
            next(service)
            assert len(processes) == 2
            assert processes[0].poll() is not None
        finally:
            service.close()
    assert all(process.poll() is not None for process in processes)


@pytest.mark.parametrize(
    "message,attempts",
    [
        (
            f"NEUTRON_FLUX_ERROR OSError: [Errno {errno.EADDRINUSE}] Address already in use",
            3,
        ),
        ("NEUTRON_FLUX_ERROR ValueError: invalid service configuration", 1),
    ],
)
def test_local_service_fixture_retries_are_bounded_and_specific(
    monkeypatch, message, attempts
):
    processes = []
    original_popen = subprocess.Popen

    def start(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(subprocess, "Popen", start)
    monkeypatch.setattr(
        ProbeServiceManager,
        "_server_code",
        lambda *_args: f"print({message!r}, flush=True)",
    )
    service = live_service.__wrapped__(SimpleNamespace(param=4))
    try:
        with pytest.raises(AssertionError, match="NEUTRON_FLUX_ERROR"):
            next(service)
    finally:
        service.close()
    assert len(processes) == attempts
    assert all(process.poll() is not None for process in processes)


@contextlib.contextmanager
def udp_client(service):
    with socket.socket(service.family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.bind((service.source_ip, 0))
        sock.connect((service.target_ip, service.manager.udp_port))
        yield sock


@pytest.mark.parametrize("message", ["echo", "health", "identity"])
def test_every_immediate_reply_uses_requested_local_address(live_service, message):
    service = live_service
    payload = {
        "echo": b"distinct-udp-payload",
        "health": ("NF-HEALTH " + service.target.server_id).encode(),
        "identity": b"NF-PEER unique-identity-token",
    }[message]
    with udp_client(service) as sock:
        sock.send(payload)
        response, peer = sock.recvfrom(65535)
    assert peer[0] == service.target_ip
    if message == "echo":
        assert response == payload
    elif message == "health":
        assert (
            json.loads(response[len(b"NF-HEALTH-OK ") :])["probe_id"]
            == service.target.server_id
        )
    else:
        identity = json.loads(response[len(b"NF-PEER-OK ") :])
        assert identity["token"] == "unique-identity-token"
        assert identity["local_ip"] == service.target_ip
        assert identity["peer_ip"] == service.source_ip


@pytest.mark.parametrize("data_count", [0, 3])
def test_deferred_and_cached_statistics_keep_the_source_address(
    live_service, data_count
):
    service = live_service
    header = struct.Struct("!4sQIQ")
    with udp_client(service) as sock:
        for sequence in range(data_count):
            sock.send(header.pack(b"NFP1", 88, sequence, time.monotonic_ns()) + b"data")
        finish = header.pack(b"NFE1", 88, data_count + 1, 1_000_000_000)
        sock.send(finish)
        first, peer = sock.recvfrom(65535)
        assert peer[0] == service.target_ip
        result = json.loads(first[4:])
        assert result["received"] == data_count
        assert result["local_ip"] == service.target_ip
        assert result["session_id"] == 88
        assert result["lost"] == 1
        sock.send(finish)
        cached, peer = sock.recvfrom(65535)
        assert peer[0] == service.target_ip and cached == first


def test_actual_connected_udp_and_tcp_clients_both_succeed(live_service):
    service = live_service
    source = endpoint()
    source.management_ip = service.source_ip
    source.fixed_ips = {"data": service.source_ip}
    ctx = ProbeContext(
        lambda _ep, command: subprocess.run(
            shlex.split(command), capture_output=True, text=True, timeout=15
        ),
        lambda _command: None,
        service.manager.tcp_port,
        service.manager.udp_port,
    )
    udp = UDPProbe(ctx).endpoint(
        source, service.source_ip, service.target_ip, service.version
    )
    tcp = TCPProbe(ctx).endpoint_peer_identity(
        source, service.source_ip, service.target_ip, service.version
    )
    assert udp.outcome == tcp.outcome == "reachable"
    assert udp.diagnostics["observer_local_ip"] == service.target_ip


@pytest.mark.parametrize("live_service", [4], indirect=True)
def test_same_sender_and_session_are_isolated_by_local_destination(live_service):
    service = live_service
    header = struct.Struct("!4sQIQ")
    expected = {"127.0.0.3": 2, "127.0.0.4": 3}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((service.source_ip, 0))
        sock.settimeout(3)
        for destination, count in expected.items():
            for sequence in range(count):
                sock.sendto(
                    header.pack(b"NFP1", 99, sequence, time.monotonic_ns()),
                    (destination, service.manager.udp_port),
                )
            sock.sendto(
                header.pack(b"NFE1", 99, count, 1_000_000_000),
                (destination, service.manager.udp_port),
            )
        actual = {}
        for _ in expected:
            payload, peer = sock.recvfrom(65535)
            result = json.loads(payload[4:])
            assert result["local_ip"] == peer[0]
            actual[peer[0]] = result["received"]
        assert actual == expected


def generated_functions():
    tree = ast.parse(ProbeServiceManager(18080, 18081)._server_code(endpoint()))
    tree.body = [node for node in tree.body if not isinstance(node, ast.Try)]
    namespace = {}
    exec(compile(tree, "<production-probe-functions>", "exec"), namespace)
    return namespace


@pytest.mark.parametrize(
    "ip,index,expected_scope",
    [
        ("2001:db8::10", 4, 0),
        ("2001:db8::20", 8, 0),
        ("fe80::10", 4, 4),
        ("fe80::10", 8, 8),
    ],
)
def test_ipv6_reply_ancillary_selects_exact_address_and_required_scope(
    ip, index, expected_scope
):
    namespace = generated_functions()
    sent = []
    sock = SimpleNamespace(
        family=socket.AF_INET6,
        sendmsg=lambda *args: sent.append(args) or len(args[0][0]),
    )
    assert namespace["udp_reply"](
        sock, b"reply", ("2001:db8::99", 1234, 0, 0), ip, index
    )
    buffers, ancillary, flags, peer = sent[0]
    assert buffers == [b"reply"] and flags == 0
    assert peer == ("2001:db8::99", 1234, 0, 0)
    assert len(ancillary) == 1
    level, kind, value = ancillary[0]
    assert (level, kind) == (socket.IPPROTO_IPV6, socket.IPV6_PKTINFO)
    addr, scope = struct.unpack("=16sI", value)
    assert socket.inet_ntop(socket.AF_INET6, addr) == ip and scope == expected_scope


def test_reply_failure_does_not_fall_back_to_wildcard_or_kill_receiver(capsys):
    namespace = generated_functions()
    calls = []

    def broken(*args):
        calls.append(args)
        raise OSError("source address is no longer available")

    sock = SimpleNamespace(family=socket.AF_INET, sendmsg=broken)
    assert (
        namespace["udp_reply"](sock, b"reply", ("127.0.0.2", 1234), "127.0.0.3", 1)
        is False
    )
    assert len(calls) == 1
    assert "UDP reply" in capsys.readouterr().out


def test_real_monitor_through_runtime_collection_completion_and_verdict(
    live_service, tmp_path, config_factory
):
    """Real TCP/UDP -> production collector -> migration producer -> validator.

    ICMP is a local success stub; Nova, SSH transport and guest interface
    inventory are controlled boundaries. This is not a live cloud migration.
    """
    import os

    from neutron_flux.execution.placement_migration import PlacementMigrationMixin
    from neutron_flux.path_evidence import data_route_evidence
    from neutron_flux.runtime.live_migration import LiveMigrationRuntimeMixin

    from ._evidence import data_route
    from .test_migration_and_load_evidence import _live_builder_without_reported_az

    service = live_service
    observer = endpoint("observer", "A")
    observer.fixed_ips = {"data": service.source_ip}
    moving = service.target
    moving.host, moving.availability_zone = "compute1", "az1"
    builder, _unused, target_host = _live_builder_without_reported_az(config_factory)
    builder.config.live_migration_continuity = True
    builder.config.tcp_port = service.manager.tcp_port
    builder.config.udp_port = service.manager.udp_port
    builder.inspect_endpoint_route = data_route
    ping = tmp_path / "ping"
    ping.write_text("#!/bin/sh\nexit 0\n")
    ping.chmod(0o755)
    state = {
        "available": True,
        "observer_server_id": observer.server_id,
        "target_server_id": moving.server_id,
        "target_fixed_ip": service.target_ip,
        "source_ip": service.source_ip,
        "destination_ip": service.target_ip,
        "family": service.version,
        "stop_path": str(tmp_path / "stop"),
        "result_path": str(tmp_path / "result.json"),
        "ready_path": str(tmp_path / "ready.json"),
        "error_path": str(tmp_path / "errors"),
        "started_at": time.monotonic(),
        "data_path_before": data_route_evidence(
            observer,
            service.source_ip,
            service.target_ip,
            data_route(observer, service.source_ip, service.target_ip, service.version),
        ),
    }
    code = LiveMigrationRuntimeMixin._live_continuity_code(
        builder,
        source_ip=service.source_ip,
        destination_ip=service.target_ip,
        family=service.version,
        stop_path=state["stop_path"],
        result_path=state["result_path"],
        ready_path=state["ready_path"],
        maximum_seconds=2,
        expected_probe_id=moving.server_id,
        expected_fixed_ip=service.target_ip,
        expected_source_ips=(service.source_ip,),
    )
    completed = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"]},
        timeout=25,
    )
    assert completed.returncode == 0, completed.stderr
    raw = (tmp_path / "result.json").read_text()
    # Return exactly the real monitor payload across the SSH boundary. Neither
    # migration_succeeded nor a verdict is fabricated in the guest evidence.
    assert "migration_succeeded" not in json.loads(raw)
    builder._start_live_continuity = lambda *_args: state
    builder.ssh_endpoint = lambda *_args, **_kwargs: subprocess.CompletedProcess(
        ["ssh"], 0, raw, ""
    )
    result = builder._live_migrate_endpoint_once(
        moving, target_host, stationary_peer=observer
    )
    evidence = result.details["continuity"]
    assert evidence["migration_succeeded"] is True
    assert evidence["target_server_id"] == moving.server_id
    assert (
        evidence["tcp"]["server_result"]["bytes"] == evidence["tcp"]["bytes_sent"] > 0
    )
    assert evidence["udp"]["response"]["received"] == evidence["udp"]["sent"] > 0
    status, _, message, details = PlacementMigrationMixin._live_continuity_verdict(
        evidence
    )
    assert status == "PASS", message
    assert details["evidence_complete"] is True
