"""Adversarial socket integrations; no OpenStack credentials or cloud access.

TCP/UDP use actual loopback sockets. ICMP tests exercise the generated parser and
observer transport at the AF_PACKET boundary: CI need not have CAP_NET_RAW.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shlex
import socket
import struct
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.icmp_attestation import (
    attested_icmp,
    observer_code,
    parse_icmp_request,
)
from neutron_flux.models import ProbeResult
from neutron_flux.probes import TCPProbe
from neutron_flux.runtime.live_migration import LiveMigrationRuntimeMixin

from ._shared import endpoint


def _frame(sock):
    value = b""
    while not value.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            raise EOFError(value)
        value += chunk
    return value


def test_generic_tcp_accepts_a_fragmented_complete_echo():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(5)
        errors = []

        def serve():
            try:
                connection, _ = listener.accept()
                with connection:
                    message = _frame(connection)
                    connection.sendall(message[:3])
                    time.sleep(0.15)
                    connection.sendall(message[3:])
            except (OSError, EOFError, ValueError, KeyError, AssertionError) as exc:
                errors.append(exc)

        thread = threading.Thread(target=serve)
        thread.start()
        code = TCPProbe._attempt_code(
            "127.0.0.2",
            "127.0.0.1",
            4,
            listener.getsockname()[1],
            "unique-complete-frame",
        )
        result = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, timeout=8
        )
        thread.join(5)
        assert not errors and not thread.is_alive()
        assert result.returncode == 0, result.stdout + result.stderr
        assert TCPProbe._attempt_diagnostics(result.stdout)["echo_validated"] is True


@pytest.mark.parametrize(
    "fault,delay,expected",
    [
        (None, 13, True),
        ("late-ack", 16, False),
        ("short-delivery", 0, False),
        ("missing-ack", 0, False),
        ("wrong-destination", 0, False),
        ("wrong-session", 0, False),
    ],
)
def test_complete_monitor_waits_for_receiver_and_never_reconnects(
    tmp_path, fault, delay, expected
):
    """Execute the entire generated monitor, not an extracted TCP worker.

    The 13-second ACK uses the *unmodified* 15-second worker and 20-second outer
    finalization deadlines. Ping is a local stub to isolate this socket test.
    """
    ping = tmp_path / "ping"
    ping.write_text("#!/bin/sh\nexit 0\n")
    ping.chmod(0o755)
    tcp = socket.socket()
    tcp.bind(("127.0.0.1", 0))
    tcp.listen()
    tcp.settimeout(6)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(0.2)
    finished = threading.Event()
    evidence = {"connections": 0}
    errors = []

    def receive_tcp():
        try:
            connection, peer = tcp.accept()
            evidence["connections"] += 1
            with connection:
                connection.settimeout(6)
                request = _frame(connection)
                assert request.startswith(b"NF-PERF ")
                payload = json.loads(request[len(b"NF-PERF ") :])
                identity = {
                    "probe_id": "wrong-vm"
                    if fault == "wrong-destination"
                    else "expected-vm",
                    "instance_id": "receiver-process",
                    "local_ip": "127.0.0.1",
                    "peer_ip": peer[0],
                    "token": payload["token"],
                }
                connection.sendall(b"READY " + json.dumps(identity).encode() + b"\n")
                count = 0
                while True:
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    count += len(chunk)
                evidence["bytes"] = count
                time.sleep(delay)
                if fault != "missing-ack":
                    response = {
                        **identity,
                        "bytes": count - 1 if fault == "short-delivery" else count,
                    }
                    if fault == "wrong-session":
                        response["token"] = "0" * 32
                    try:
                        connection.sendall(
                            b"RESULT " + json.dumps(response).encode() + b"\n"
                        )
                    except (BrokenPipeError, ConnectionResetError):
                        if expected:
                            raise
            # A second connection would be a silent-reconnect defect.
            tcp.settimeout(0.1)
            try:
                extra, _ = tcp.accept()
                evidence["connections"] += 1
                extra.close()
            except TimeoutError:
                pass
        except (OSError, EOFError, ValueError, KeyError, AssertionError) as exc:
            # Early identity rejection deliberately closes the original stream.
            if not (
                fault == "wrong-destination" and isinstance(exc, ConnectionResetError)
            ):
                errors.append(exc)
        finally:
            tcp.close()

    def receive_udp():
        sequences = set()
        header = struct.Struct("!4sQIQ")
        try:
            while not finished.is_set():
                try:
                    data, peer = udp.recvfrom(65535)
                except TimeoutError:
                    continue
                tag, session, sequence, _ = header.unpack(data[: header.size])
                if tag == b"NFP1":
                    sequences.add(sequence)
                elif tag in (b"NFE1", b"NFC2"):
                    response = {
                        "session_id": session,
                        "sent": sequence,
                        "received": len(sequences),
                        "max_sequence": max(sequences, default=-1),
                        "loss_pct": 100
                        * (sequence - len(sequences))
                        / max(sequence, 1),
                        "probe_id": "expected-vm",
                        "instance_id": "receiver-process",
                        "local_ip": "127.0.0.1",
                        "peer_ip": peer[0],
                    }
                    udp.sendto(b"NFR1" + json.dumps(response).encode(), peer)
        except (OSError, EOFError, ValueError, KeyError, AssertionError) as exc:
            errors.append(exc)
        finally:
            udp.close()

    context = SimpleNamespace(
        config=SimpleNamespace(
            tcp_port=tcp.getsockname()[1], udp_port=udp.getsockname()[1]
        )
    )
    code = LiveMigrationRuntimeMixin._live_continuity_code(
        context,
        source_ip="127.0.0.2",
        destination_ip="127.0.0.1",
        family=4,
        stop_path=str(tmp_path / "stop"),
        result_path=str(tmp_path / "result.json"),
        ready_path=str(tmp_path / "ready.json"),
        maximum_seconds=2,
        expected_probe_id="expected-vm",
        expected_fixed_ip="127.0.0.1",
        expected_source_ips=("127.0.0.2",),
    )
    threads = [
        threading.Thread(target=receive_tcp),
        threading.Thread(target=receive_udp),
    ]
    for thread in threads:
        thread.start()
    try:
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            env={**os.environ, "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"]},
            timeout=27,
        )
        assert result.returncode == 0, result.stderr
        payload = json.loads((tmp_path / "result.json").read_text())
    finally:
        finished.set()
        for thread in threads:
            thread.join(20)
    assert all(not thread.is_alive() for thread in threads)
    assert not errors, errors
    assert evidence["connections"] == 1
    assert payload["workers_complete"] is True
    assert payload["tcp"]["terminal"] is True
    assert payload["tcp"]["survived"] is expected, payload
    if expected:
        assert (
            payload["tcp"]["bytes_sent"]
            == payload["tcp"]["server_result"]["bytes"]
            == evidence["bytes"]
            > 0
        )
        assert payload["tcp"]["identity_verified"] is True
        assert payload["udp"]["identity_verified"] is True
        assert payload["tcp"]["error"] is None
    else:
        assert payload["tcp"]["error"]
        if fault == "late-ack":
            assert payload["tcp"]["failure_kind"] == "acknowledgement-timeout"
        if fault in {"short-delivery", "wrong-session"}:
            assert payload["tcp"]["failure_phase"] == "receiver-delivery"
        if fault == "missing-ack":
            assert payload["tcp"]["failure_kind"] == "missing-acknowledgement"


def _icmp_packet(token, destination="10.42.0.2", source="192.0.2.9", sequence=1):
    body = (
        struct.pack("!BBHHH", 8, 0, 0, 412, sequence)
        + b"timestamp"
        + bytes.fromhex(token)
    )
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(body),
        0,
        0,
        64,
        1,
        0,
        socket.inet_aton(source),
        socket.inet_aton(destination),
    )
    return header + body


@pytest.mark.parametrize(
    "fault", [None, "wrong-token", "wrong-address", "fragment", "short", "reply"]
)
def test_icmp_capture_parser_rejects_unrelated_or_malformed_packets(fault):
    token = "ab" * 16
    packet = _icmp_packet(token)
    if fault == "wrong-token":
        packet = _icmp_packet("cd" * 16)
    if fault == "wrong-address":
        packet = _icmp_packet(token, destination="10.42.0.3")
    if fault == "fragment":
        packet = packet[:6] + b"\x20\x00" + packet[8:]
    if fault == "short":
        packet = packet[:10]
    if fault == "reply":
        packet = packet[:20] + b"\x00" + packet[21:]
    observed = parse_icmp_request(packet, bytes.fromhex(token), "10.42.0.2")
    assert bool(observed) is (fault is None)
    if observed:
        assert observed == {
            "peer_ip": "192.0.2.9",
            "local_ip": "10.42.0.2",
            "identifier": 412,
            "sequence": 1,
        }


def test_generated_icmp_observer_binds_data_mac_and_collects_three_unique_requests(
    monkeypatch,
):
    target = endpoint("capture-target", "A")
    token = "ab" * 16
    packets = [
        (_icmp_packet(token, sequence=n), ("ens4", 0x800, 0, 1, b""))
        for n in (1, 1, 2, 3)
    ]
    raw = mock.MagicMock()
    raw.__enter__.return_value = raw
    raw.recvfrom.side_effect = packets
    interface = SimpleNamespace(
        parent=SimpleNamespace(name="ens4"), read_text=lambda: target.test_mac
    )
    captured = io.StringIO()
    with (
        mock.patch("pathlib.Path.glob", return_value=[interface]),
        mock.patch("socket.socket", return_value=raw),
        contextlib.redirect_stdout(captured),
    ):
        exec(observer_code(target, "10.42.0.2", token), {})
    raw.bind.assert_called_once_with(("ens4", 0x800))
    rows = captured.getvalue().splitlines()
    assert rows[0].startswith("NF_ICMP_READY ")
    result = json.loads(rows[1].split(" ", 1)[1])
    assert result["probe_id"] == target.server_id
    assert [row["sequence"] for row in result["requests"]] == [1, 2, 3]


@pytest.mark.parametrize("fault", [None, "no-request", "wrong-token", "permission"])
def test_icmp_observer_transport_cannot_accept_unattested_ping(monkeypatch, fault):
    target = endpoint("capture-target", "A")
    token = "ab" * 16
    monkeypatch.setattr(
        "neutron_flux.icmp_attestation.secrets.token_hex", lambda _: token
    )
    probe = mock.Mock(
        return_value=ProbeResult("reachable", True, 1, 1, protocol="icmp")
    )

    def launch(_endpoint, _command):
        if fault == "permission":
            program = "import sys;sys.stderr.write('PermissionError: CAP_NET_RAW unavailable');sys.exit(1)"
        else:
            ready = {"device": "ens4", "probe_id": target.server_id, "token": token}
            observed = {
                **ready,
                "complete": True,
                "requests": []
                if fault == "no-request"
                else [
                    {
                        "peer_ip": "192.0.2.9",
                        "local_ip": "10.42.0.2",
                        "identifier": 7,
                        "sequence": 1,
                    }
                ],
            }
            if fault == "wrong-token":
                observed["token"] = "cd" * 16
            program = (
                "print("
                + repr("NF_ICMP_READY " + json.dumps(ready))
                + ",flush=True);print("
                + repr("NF_ICMP_RESULT " + json.dumps(observed))
                + ",flush=True)"
            )
        return subprocess.Popen(
            [sys.executable, "-c", program],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    if fault == "permission":
        from neutron_flux.errors import SuiteError

        with pytest.raises(SuiteError, match="PermissionError|unavailable"):
            attested_icmp(launch, target, "10.42.0.2", probe)
        probe.assert_not_called()
    else:
        result = attested_icmp(launch, target, "10.42.0.2", probe)
        assert result.success is (fault is None)
        if fault is None:
            assert result.diagnostics["observed_peer_ip"] == "192.0.2.9"
        else:
            assert result.outcome in {"wrong-destination", "inconclusive"}


def test_real_service_and_full_monitor_agree_on_vm_session_and_delivery(tmp_path):
    """Both ends are unmodified generated production programs on loopback."""
    from neutron_flux.probe_service import ProbeServiceManager
    from neutron_flux.probes import ProbeContext, UDPProbe

    from .test_performance_and_html import _close_probe_process, _endpoint, _free_port

    tcp_port = _free_port(socket.SOCK_STREAM, offset=2)
    udp_port = _free_port(socket.SOCK_DGRAM)
    target = _endpoint("real-receiver", "A", "127.0.0.1", "local")
    manager = ProbeServiceManager(tcp_port, udp_port)
    server = subprocess.Popen(
        [sys.executable, "-u", "-c", manager._server_code(target)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert "NEUTRON_FLUX_READY" in server.stdout.readline()
        ctx = ProbeContext(
            lambda ep, cmd: subprocess.run(
                shlex.split(cmd), capture_output=True, text=True, timeout=8
            ),
            lambda _: None,
            tcp_port,
            udp_port,
        )
        actual = UDPProbe(ctx).endpoint_peer_identity(
            target, "127.0.0.2", "127.0.0.1", 4
        )
        assert actual.success, actual
        assert actual.diagnostics["observer_probe_id"] == target.server_id
        assert actual.diagnostics["observer_local_ip"] == "127.0.0.1"
        assert actual.diagnostics["observed_peer_ip"] == "127.0.0.2"
        ping = tmp_path / "ping"
        ping.write_text("#!/bin/sh\nexit 0\n")
        ping.chmod(0o755)
        context = SimpleNamespace(
            config=SimpleNamespace(tcp_port=tcp_port, udp_port=udp_port)
        )
        code = LiveMigrationRuntimeMixin._live_continuity_code(
            context,
            source_ip="127.0.0.2",
            destination_ip="127.0.0.1",
            family=4,
            stop_path=str(tmp_path / "stop"),
            result_path=str(tmp_path / "result.json"),
            ready_path=str(tmp_path / "ready.json"),
            maximum_seconds=2,
            expected_probe_id=target.server_id,
            expected_fixed_ip="127.0.0.1",
            expected_source_ips=("127.0.0.2",),
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=25,
            env={**os.environ, "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"]},
        )
        assert result.returncode == 0, result.stderr
        evidence = json.loads((tmp_path / "result.json").read_text())
        assert evidence["tcp"]["survived"], evidence
        assert (
            evidence["tcp"]["server_result"]["bytes"]
            == evidence["tcp"]["bytes_sent"]
            > 0
        )
        assert evidence["tcp"]["server_result"]["probe_id"] == target.server_id
        assert evidence["udp"]["identity_verified"] is True, evidence
        assert evidence["udp"]["response"]["received"] == evidence["udp"]["sent"] > 0
        assert (
            evidence["udp"]["response"]["instance_id"]
            == actual.diagnostics["observer_instance_id"]
        )
    finally:
        _close_probe_process(server)


@pytest.mark.parametrize("wrong_vm", [False, True])
def test_actual_udp_ingress_rejects_wrong_vm_despite_matching_api_association(
    config_factory, wrong_vm
):
    """API-shaped mapping + real UDP endpoint; deliberately no simulated NAT claim."""
    from neutron_flux.policy import PolicyEvaluator
    from neutron_flux.probes import ProbeContext, UDPProbe

    from ._evidence import configure_translation_target, data_route
    from .test_engine_handlers import _engine, _spec

    engine, source, target, groups, records = _engine(config_factory)
    target.fixed_ips = {"subnet": "192.0.2.20"}
    source.fixed_ips = {"subnet": "127.0.0.2"}
    groups["target"].fips[target.label] = {"id": "fip1", "address": "127.0.0.3"}
    configure_translation_target(engine, groups["target"], target)
    engine.builder.inspect_endpoint_route = data_route
    engine._endpoint_address = lambda group, side, subnet: (
        (source, "127.0.0.2") if group == "source" else (target, "192.0.2.20")
    )
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.3", 0))
    listener.settimeout(6)
    port = listener.getsockname()[1]
    errors = []

    def serve():
        try:
            data, peer = listener.recvfrom(4096)
            response = {
                "token": data[len(b"NF-PEER ") :].decode().strip(),
                "probe_id": "WRONG-VM" if wrong_vm else target.server_id,
                "instance_id": "process",
                "local_ip": "192.0.2.20",
                "peer_ip": peer[0],
            }
            listener.sendto(
                b"NF-PEER-OK " + json.dumps(response).encode() + b"\n", peer
            )
        except (OSError, EOFError, ValueError, KeyError, AssertionError) as exc:
            errors.append(exc)
        finally:
            listener.close()

    thread = threading.Thread(target=serve)
    thread.start()
    engine.probes.udp = UDPProbe(
        ProbeContext(
            lambda ep, cmd: subprocess.run(
                shlex.split(cmd), capture_output=True, text=True, timeout=8
            ),
            lambda _: None,
            18080,
            port,
        )
    )
    spec = _spec("fip-baseline", category="floating-ip", protocol="udp")
    spec.metadata.update(
        observer_path_contract="same-provider-subnet",
        floating_ip_subnet_id="subnet",
        target_external_cidr="127.0.0.0/8",
    )
    try:
        engine._run_fip_baseline(spec)
    finally:
        thread.join(8)
    assert not thread.is_alive() and not errors
    probe = records[-1][1]
    assert PolicyEvaluator().evaluate(spec, probe).status == (
        "FAIL" if wrong_vm else "PASS"
    )
    assert probe.diagnostics["observer_probe_id"] == (
        "WRONG-VM" if wrong_vm else target.server_id
    )
