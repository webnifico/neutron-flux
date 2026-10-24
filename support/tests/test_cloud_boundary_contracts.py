"""External CLI shapes and receiver responses, independent of cloud mocks."""

from __future__ import annotations

import json
import socket
import struct
import subprocess
import sys
import threading
from unittest import mock

import pytest

from neutron_flux.capability_preflight import CapabilityPreflight
from neutron_flux.discovery import Discoverer
from neutron_flux.errors import CommandError, CommandTimeoutError, SuiteError
from neutron_flux.log import Logger
from neutron_flux.models import QuotaInfo
from neutron_flux.openstack import OpenStack
from neutron_flux.performance import PerformanceRunner
from neutron_flux.probes import MTUProbe, ProbeContext
from neutron_flux.resources import ResourceBuilder
from neutron_flux.utils import nova_task_state_cleared

from ._shared import endpoint
from .test_reaudit_udp_service import live_service as live_service


@pytest.mark.parametrize(
    "payload",
    [
        {"instances": {"limit": 20, "in_use": 16, "reserved": 3}},
        [{"Resource": "instances", "Limit": 20, "In Use": 16, "Reserved": 3}],
        {"instances": 20, "usage": {"instances": 16}, "reservation": {"instances": 3}},
    ],
)
def test_real_quota_shapes_include_pending_reservations(payload):
    quota = Discoverer._quota_info(payload)["instances"]
    assert (quota.limit, quota.used, quota.reserved, quota.available) == (20, 16, 3, 1)


def test_quota_zero_usage_and_unlimited_limit_remain_distinct():
    quotas = Discoverer._quota_info(
        [
            {"Resource": "floating-ips", "Limit": 0, "In Use": 0, "Reserved": 0},
            {"Resource": "instances", "Limit": -1, "In Use": 30, "Reserved": 1},
        ]
    )
    assert quotas["floating_ips"].available == 0
    assert quotas["instances"].limit == -1
    assert quotas["instances"].available is None


@pytest.mark.parametrize(
    "used,reserved", [("unknown", 0), (1, "unknown"), (1, -1), (-1, 0)]
)
def test_invalid_usage_cannot_invent_quota_headroom(used, reserved):
    quotas = Discoverer._quota_info(
        {"instances": {"limit": 20, "in_use": used, "reserved": reserved}}
    )
    assert quotas["instances"].available is None


def test_missing_quota_usage_is_deferred_not_claimed_sufficient(
    config_factory, discovery_fixture
):
    discovery_fixture.quota_info = {"instances": QuotaInfo("instances", 20, None)}
    preflight = CapabilityPreflight(
        config_factory(),
        discovery_fixture,
        mock.Mock(estimated={"peak_instances": 4}),
        mock.Mock(),
        mock.Mock(),
    )
    preflight._quota_headroom()
    check = preflight.checks[-1]
    assert check["status"] == "DEFERRED"
    assert check["evidence"]["instances"]["available"] is None


def test_unlimited_quota_does_not_need_usage_to_prove_headroom(
    config_factory, discovery_fixture
):
    discovery_fixture.quota_info = {"instances": QuotaInfo("instances", -1, None)}
    preflight = CapabilityPreflight(
        config_factory(),
        discovery_fixture,
        mock.Mock(estimated={"peak_instances": 4}),
        mock.Mock(),
        mock.Mock(),
    )
    preflight._quota_headroom()
    assert preflight.checks[-1]["status"] == "PASS"


@pytest.mark.parametrize(
    "resource,message",
    [
        ("server", "No Volume found for volume-1"),
        ("port", "Network network-1 could not be found"),
        ("server", "No Server Group with a name or ID of group-1 exists"),
        ("network", "Network Segment segment-1 not found"),
        ("volume", "No VolumeType found for premium"),
    ],
)
def test_unrelated_missing_object_does_not_prove_target_absence(resource, message):
    result = subprocess.CompletedProcess(["openstack"], 1, "", message)
    assert OpenStack.is_not_found_result(result, expected_resource=resource) is False


def test_server_presence_stays_unknown_after_a_missing_dependency(tmp_path):
    logger = Logger(tmp_path / "boundary.log")
    osc = OpenStack(logger)
    osc.run = mock.Mock(
        return_value=subprocess.CompletedProcess(
            ["openstack"], 1, "", "No ServerGroup found for group-1"
        )
    )
    try:
        assert osc.presence("server", "server-1").unknown
        with pytest.raises(CommandError):
            osc.json("server", "show", "server-1", check=False)
    finally:
        logger.close()


@pytest.mark.parametrize("explicit", [None, 900])
def test_cli_deadlines_bound_inventory_and_preserve_long_resource_operations(
    tmp_path, monkeypatch, explicit
):
    logger = Logger(tmp_path / "deadline.log")
    osc = OpenStack(logger)
    selected = []

    def stalled(command, **kwargs):
        selected.append(kwargs["timeout"])
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr("neutron_flux.openstack.run_cancellable", stalled)
    try:
        with pytest.raises(CommandTimeoutError):
            osc.run("server", "list", timeout=explicit)
        assert selected == [120 if explicit is None else explicit]
    finally:
        logger.close()


def _tcp_frame(sock):
    data = bytearray()
    while not data.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            raise EOFError("Incomplete frame")
        data.extend(chunk)
    return bytes(data)


@pytest.mark.parametrize(
    "fault", ["wrong-token", "short-delivery", "zero-duration", "valid"]
)
def test_tcp_benchmark_requires_correlated_complete_delivery(fault):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(5)
        errors = []

        def serve():
            try:
                connection, peer = listener.accept()
                with connection:
                    connection.settimeout(5)
                    request = json.loads(_tcp_frame(connection)[len(b"NF-PERF ") :])
                    connection.sendall(b"READY\n")
                    received = 0
                    while chunk := connection.recv(262144):
                        received += len(chunk)
                    response = {
                        "token": "different"
                        if fault == "wrong-token"
                        else request.get("token"),
                        "bytes": received - 1
                        if fault == "short-delivery"
                        else received,
                        "elapsed_s": 0.0 if fault == "zero-duration" else 0.1,
                        "mbps": received * 8.0 / 0.1 / 1_000_000.0,
                        "mss": 1460,
                        "peer_ip": peer[0],
                    }
                    connection.sendall(
                        b"RESULT " + json.dumps(response).encode() + b"\n"
                    )
            except (OSError, ValueError, EOFError) as exc:
                errors.append(exc)

        thread = threading.Thread(target=serve)
        thread.start()
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                PerformanceRunner._tcp_client_code(
                    "127.0.0.2", "127.0.0.1", 4, listener.getsockname()[1], 0.05, 1
                ),
            ],
            capture_output=True,
            text=True,
            timeout=8,
        )
        thread.join(5)
        assert not thread.is_alive() and not errors
        assert (result.returncode == 0) == (fault == "valid"), (
            result.stdout + result.stderr
        )


@pytest.mark.parametrize("fault", ["wrong-session", "wrong-sent-count", "valid"])
def test_udp_benchmark_rejects_statistics_from_another_session(fault):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.settimeout(5)
        errors = []

        def serve():
            try:
                while True:
                    data, peer = listener.recvfrom(65535)
                    if data[:4] != b"NFE1":
                        continue
                    _, session, sent, elapsed_ns = struct.unpack("!4sQIQ", data)
                    elapsed = max(elapsed_ns / 1_000_000_000.0, 1e-9)
                    response = {
                        "session_id": session + 1
                        if fault == "wrong-session"
                        else session,
                        "sent": sent + 1 if fault == "wrong-sent-count" else sent,
                        "received": sent,
                        "loss_pct": 0.0,
                        "mbps": sent * 128 * 8 / elapsed / 1_000_000.0,
                        "pps": sent / elapsed,
                        "jitter_ms": 0.0,
                        "duplicates": 0,
                        "out_of_order": 0,
                    }
                    listener.sendto(b"NFR1" + json.dumps(response).encode(), peer)
                    return
            except (OSError, ValueError) as exc:
                errors.append(exc)

        thread = threading.Thread(target=serve)
        thread.start()
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                PerformanceRunner._udp_client_code(
                    "127.0.0.2", "127.0.0.1", 4, listener.getsockname()[1], 0.05, 1, 128
                ),
            ],
            capture_output=True,
            text=True,
            timeout=8,
        )
        thread.join(5)
        assert not thread.is_alive() and not errors
        assert (result.returncode == 0) == (fault == "valid"), (
            result.stdout + result.stderr
        )


def test_full_benchmark_service_runs_on_ipv4_and_ipv6_with_bound_sources(live_service):
    service = live_service
    for code in (
        PerformanceRunner._tcp_client_code(
            service.source_ip,
            service.target_ip,
            service.version,
            service.manager.tcp_port,
            0.05,
            2,
        ),
        PerformanceRunner._udp_client_code(
            service.source_ip,
            service.target_ip,
            service.version,
            service.manager.udp_port,
            0.05,
            1,
            128,
        ),
    ):
        result = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, timeout=8
        )
        assert result.returncode == 0, result.stdout + result.stderr
        measured = json.loads(result.stdout)
        assert measured["peer_ip"] == service.source_ip
        assert measured["mbps"] > 0


@pytest.mark.parametrize(
    "fault",
    [
        "listener-list",
        "malformed-item",
        "non-boolean",
        "foreign-server",
        "foreign-instance",
        "valid",
    ],
)
def test_surviving_probe_health_requires_complete_matching_identity(
    config_factory, fault
):
    target = endpoint()
    target.fixed_ips = {"data": "192.0.2.10"}
    target.management_ip = "10.254.0.10"
    item = {"tcp": True, "udp": True, "instance_id": "same-instance"}
    listeners = {"4": item}
    identity = {"probe_id": target.server_id, "instance_id": "same-instance"}
    if fault == "listener-list":
        listeners = [item]
    elif fault == "malformed-item":
        listeners = {"4": None}
    elif fault == "non-boolean":
        item.update(tcp="ready", udp="ready")
    elif fault == "foreign-server":
        identity["probe_id"] = "another-server"
    elif fault == "foreign-instance":
        item["instance_id"] = "another-process"
    runtime = object.__new__(ResourceBuilder)
    runtime.config = config_factory()
    runtime.ssh_endpoint = mock.Mock(
        return_value=subprocess.CompletedProcess(
            ["ssh"],
            0,
            json.dumps(
                {
                    "listeners": listeners,
                    "service_identity": identity,
                    "inspection_complete": True,
                }
            ),
            "",
        )
    )
    ready, _ = runtime._existing_probe_service_ready(target)
    assert ready is (fault == "valid")


@pytest.mark.parametrize(
    "stdout",
    ["", "NEUTRON_FLUX_MTU_RESULT={broken", "NEUTRON_FLUX_MTU_RESULT=null"],
)
def test_mtu_command_exit_zero_requires_structured_packet_evidence(stdout):
    context = ProbeContext(
        lambda _endpoint, _command: subprocess.CompletedProcess(["ssh"], 0, stdout, ""),
        lambda _command: None,
        18080,
        18081,
    )
    measured = MTUProbe(context).endpoint(
        endpoint(), "192.0.2.10", "192.0.2.11", 4, 1500
    )
    assert measured.outcome == "error"
    assert measured.success is False


@pytest.mark.parametrize(
    "field", ["OS-EXT-STS:task_state", "os_ext_sts_task_state", "task_state"]
)
@pytest.mark.parametrize(
    "value,expected",
    [
        (None, True),
        ("", True),
        (" None ", True),
        ("null", True),
        ("<none>", True),
        (" resize_migrating ", False),
        ("0", False),
        ("false", False),
        ("[]", False),
        ("{}", False),
        (False, None),
        (0, None),
        ([], None),
        ({}, None),
    ],
)
def test_task_state_evidence_preserves_native_schema(field, value, expected):
    assert nova_task_state_cleared({field: value}) is expected


def test_missing_task_state_is_unverified():
    assert nova_task_state_cleared({"status": "ACTIVE"}) is None


@pytest.mark.parametrize(
    "fault",
    [
        "task-hidden",
        "task-false",
        "task-zero",
        "task-list",
        "task-dict",
        "task-busy",
        "owner-hidden",
        "binding-hidden",
        "binding-empty",
        "server-mismatch",
        "port-mismatch",
        "valid-active",
        "valid-stopped",
        "valid-task-string",
    ],
)
def test_settlement_requires_explicit_task_and_port_ownership(
    config_factory, monkeypatch, fault
):
    server = {
        "id": "server",
        "status": "ACTIVE",
        "OS-EXT-STS:task_state": None,
        "OS-EXT-SRV-ATTR:host": "compute",
    }
    port = {
        "id": "port",
        "device_id": "server",
        "binding:host_id": "compute",
        "status": "ACTIVE",
    }
    if fault == "task-hidden":
        del server["OS-EXT-STS:task_state"]
    elif fault in {"task-false", "task-zero", "task-list", "task-dict", "task-busy"}:
        server["OS-EXT-STS:task_state"] = {
            "task-false": False,
            "task-zero": 0,
            "task-list": [],
            "task-dict": {},
            "task-busy": "migrating",
        }[fault]
    elif fault == "owner-hidden":
        del port["device_id"]
    elif fault == "binding-hidden":
        del port["binding:host_id"]
    elif fault == "binding-empty":
        port["binding:host_id"] = ""
    elif fault == "server-mismatch":
        server["id"] = "other-server"
    elif fault == "port-mismatch":
        port["id"] = "other-port"
    elif fault == "valid-stopped":
        server["status"] = "SHUTOFF"
        port["status"] = "DOWN"
    elif fault == "valid-task-string":
        server["OS-EXT-STS:task_state"] = " None "
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(convergence_interval=0)
    builder.logger = mock.Mock()
    builder.osc = mock.Mock()
    builder.osc.json.side_effect = lambda kind, *_args, **_kwargs: (
        server if kind == "server" else port
    )
    clock = iter(range(12))
    monkeypatch.setattr(
        "neutron_flux.runtime.control.servers.time.monotonic", lambda: next(clock)
    )
    monkeypatch.setattr(
        "neutron_flux.runtime.control.servers.time.sleep", lambda *_args: None
    )

    def call():
        return builder._wait_for_server_settlement(
            "server", ["port"], expected_statuses={server["status"].lower()}, timeout=3
        )

    if fault.startswith("valid-"):
        assert call() == server
    else:
        with pytest.raises(SuiteError, match="Timed out.*settlement"):
            call()
