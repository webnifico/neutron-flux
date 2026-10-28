"""Full generated service + monitor + phase markers + collector + completion.

TCP/UDP are real local sockets. ICMP responses and Nova/guest inventory are
explicit synthetic boundaries; this is not an OpenStack live migration.
"""

from __future__ import annotations

import json
import os
import struct
import subprocess
import time
import zlib
from types import SimpleNamespace

import pytest

from neutron_flux.execution.placement_migration import PlacementMigrationMixin
from neutron_flux.runtime.migration_validation import MigrationValidationMixin

from ._evidence import data_route
from ._shared import endpoint
from .test_migration_and_load_evidence import _live_builder_without_reported_az
from .test_reaudit_udp_service import live_service as live_service
from .test_reaudit_udp_service import udp_client


@pytest.mark.parametrize(
    "startup_loss,disruption", [(False, False), (True, False), (True, True)]
)
def test_actual_runtime_phase_partition_and_unchanged_thresholds(
    live_service,
    config_factory,
    tmp_path,
    startup_loss,
    disruption,
):
    service = live_service
    builder, _, target_host = _live_builder_without_reported_az(config_factory)
    moving = service.target
    moving.host, moving.availability_zone = "compute1", "az1"
    observer = endpoint("observer", "B")
    observer.fixed_ips = {"data": service.source_ip}
    observer.management_ip = service.source_ip
    builder.config.resource_timeout = 5
    builder.config.live_migration_continuity = True
    builder.config.tcp_port, builder.config.udp_port = (
        service.manager.tcp_port,
        service.manager.udp_port,
    )
    builder.inspect_endpoint_route = data_route
    count = tmp_path / "count"
    drop = tmp_path / "drop"
    ping = tmp_path / "ping"
    ping.write_text(
        f"#!/bin/sh\nn=0; test ! -f '{count}' || n=$(cat '{count}'); n=$((n+1)); "
        f"echo $n > '{count}'; test $n -gt {3 if startup_loss else 0} && test ! -f '{drop}'\n"
    )
    ping.chmod(0o755)
    env = {
        **os.environ,
        "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
        "TMPDIR": str(tmp_path),
    }
    observed_raw = []

    def local_transport(_endpoint, command):
        result = subprocess.run(
            ["sh", "-c", command], text=True, capture_output=True, env=env, timeout=40
        )
        if command.startswith("touch ") and result.returncode == 0:
            observed_raw.append(json.loads(result.stdout))
        return result

    builder.ssh_endpoint = local_transport
    submitted = []

    def submit(*args, **kwargs):
        submitted.append(args)
        if disruption:
            drop.touch()
        time.sleep(0.8 if disruption else 0.3)
        drop.unlink(missing_ok=True)
        return subprocess.CompletedProcess(args, 0, "", "")

    builder.osc = SimpleNamespace(run=submit)

    def placed(_ep, host):
        time.sleep(0.4)
        return {"status": "ACTIVE", "host": host, "task_state": None}

    builder._wait_for_live_destination = placed
    reads = []

    def rows(_server):
        reads.append(1)
        return [
            {
                "id": "new",
                "type": "live-migration",
                "source_compute": "compute1",
                "dest_compute": "compute2",
                "status": "running" if len(reads) == 1 else "completed",
            }
        ], None

    builder._migration_rows = rows
    builder._verify_nova_migration_record = (
        MigrationValidationMixin._verify_nova_migration_record.__get__(builder)
    )
    result = builder._live_migrate_endpoint_once(moving, target_host, observer)
    evidence = result.details["continuity"]
    status, _, message, details = PlacementMigrationMixin._live_continuity_verdict(
        evidence
    )
    assert len(submitted) == 1 and len(reads) == 2
    assert result.migration_record_verified is True
    assert evidence["phase_evidence"]["verified"] is True, message
    phases = evidence["phase_evidence"]["phases"]
    assert phases["startup"]["icmp"]["lost"] == (3 if startup_loss else 0)
    assert (
        phases["protected"]["icmp"]["lost"] > 0
        if disruption
        else phases["protected"]["icmp"]["lost"] == 0
    )
    assert len(evidence["phase_evidence"]["raw_icmp_observations"]) == len(
        observed_raw[0]["icmp"]
    )
    assert evidence["tcp"]["survived"] is True
    assert (
        evidence["tcp"]["bytes_sent"] == evidence["tcp"]["server_result"]["bytes"] > 0
    )
    assert evidence["udp"]["response"]["received"] == evidence["udp"]["sent"]
    assert evidence["udp"]["protected_measurement"]["sent"] < evidence["udp"]["sent"]
    assert details["evaluated_thresholds"] == {
        "icmp_loss_pct": 1.0,
        "udp_loss_pct": 1.0,
        "outage_lower_bound_s": 1.0,
    }
    assert status == "PASS", message
    assert details["migration_outcomes"]["migration_completion"] == "PASS"
    assert details["migration_outcomes"]["tcp_session"] == "PASS"
    assert details["migration_outcomes"]["traffic_recovery"] == "PASS"
    assert details["migration_outcomes"]["interruption_tolerance"] == (
        "OBSERVATION" if disruption else "PASS"
    )
    assert bool(details["interruption_observations"]) is disruption


@pytest.mark.parametrize("sent,received", [(0, []), (6, [0, 2, 5]), (9, [0, 7, 8])])
def test_receiver_bitmap_attests_each_delivered_sequence(live_service, sent, received):
    service = live_service
    header = struct.Struct("!4sQIQ")
    with udp_client(service) as sock:
        for sequence in received:
            sock.send(header.pack(b"NFP1", 345, sequence, time.monotonic_ns()))
        request = header.pack(b"NFC2", 345, sent, 1_000_000_000)
        sock.send(request)
        raw, peer = sock.recvfrom(65535)
        assert raw.startswith(b"NFR2") and len(raw) <= 1200
        data = json.loads(zlib.decompress(raw[4:]))
        assert peer[0] == service.target_ip
        assert data["sequence_bitmap_complete"] is True
        bitmap = bytes.fromhex(data["received_bitmap_hex"])
        assert [i for i in range(sent) if bitmap[i >> 3] & (1 << (i & 7))] == received
        assert data["received"] == len(received)
        sock.send(request)
        assert sock.recv(65535) == raw


@pytest.mark.parametrize("sent", [6000, 65536])
def test_long_monitor_stats_do_not_introduce_oversized_udp_replies(live_service, sent):
    service = live_service
    header = struct.Struct("!4sQIQ")
    with udp_client(service) as sock:
        # Sparse real deliveries in a long declared send window. No invented
        # successful delivery count; all absent sequence numbers remain lost.
        for sequence in (0, sent // 2, sent - 1):
            sock.send(header.pack(b"NFP1", 678, sequence, time.monotonic_ns()))
        sock.send(header.pack(b"NFC2", 678, sent, 1_000_000_000))
        raw, peer = sock.recvfrom(65535)
        assert raw.startswith(b"NFR2") and len(raw) <= 1200
        assert peer[0] == service.target_ip
        value = json.loads(zlib.decompress(raw[4:]))
        assert value["sequence_bitmap_complete"] is True
        assert value["sent"] == sent and value["received"] == 3
        bits = bytes.fromhex(value["received_bitmap_hex"])
        assert sum(byte.bit_count() for byte in bits) == 3
        assert value["lost"] == sent - 3


def test_incompressible_bitmap_stays_bounded_and_cannot_claim_complete_evidence():
    import random
    import socket

    from .test_reaudit_udp_service import generated_functions

    namespace = generated_functions()
    replies = []
    namespace["udp_reply"] = lambda _sock, value, *_args: replies.append(value)
    namespace["udp_kernel_counters"] = lambda _family: {}
    bits = bytearray(random.Random(123).randbytes(8192))
    delivered = sum(byte.bit_count() for byte in bits)
    state = {
        "received": delivered,
        "bytes": delivered * 128,
        "first_ns": 0,
        "last_ns": 1_000_000_000,
        "jitter_ms": 0.0,
        "out_of_order": 0,
        "local_ip": "127.0.0.3",
        "max_sequence": 65535,
        "seen_chunks": {0: bits},
    }
    namespace["finalize_udp"](
        SimpleNamespace(family=socket.AF_INET),
        (("127.0.0.2", 1234), 987),
        state,
        {
            "sent_count": 65536,
            "sender_elapsed_ns": 1_000_000_000,
            "local_ip": "127.0.0.3",
            "interface_index": 1,
            "include_sequence_bitmap": True,
        },
        {},
        1_000_000_001,
    )
    assert len(replies) == 1 and len(replies[0]) <= 1200
    value = json.loads(zlib.decompress(replies[0][4:]))
    assert value["sequence_bitmap_complete"] is False
    assert value["received_bitmap_hex"] is None
    assert value["received"] == delivered and value["lost"] == 65536 - delivered
    assert value["phase_evidence_error"]


@pytest.mark.parametrize(
    "encoded",
    [
        b"invalid",
        zlib.compress(b"x" * 70000),
        zlib.compress(b"{}") + b"extra",
        zlib.compress(b"{}")[:-1],
    ],
    ids=["invalid", "oversized", "trailing", "truncated"],
)
def test_compressed_receiver_envelope_has_a_strict_decoding_bound(
    config_factory, encoded
):
    import ast
    import socket

    from neutron_flux.runtime.live_migration import LiveMigrationRuntimeMixin

    builder = LiveMigrationRuntimeMixin()
    builder.config = config_factory()
    code = builder._live_continuity_code(
        source_ip="127.0.0.2",
        destination_ip="127.0.0.3",
        family=4,
        stop_path="stop",
        result_path="result",
        maximum_seconds=3,
    )
    tree = ast.parse(code)
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "udp_worker"
    )
    channel = SimpleNamespace(
        settimeout=lambda *_: None,
        bind=lambda *_: None,
        connect=lambda *_: None,
        close=lambda: None,
        send=lambda value: len(value),
        recv=lambda *_: b"NFR2" + encoded,
    )
    value = {"sent": 0, "response": None, "error": None, "send_times_s": []}
    namespace = {
        "struct": struct,
        "time": time,
        "zlib": zlib,
        "json": json,
        "socket": SimpleNamespace(
            socket=lambda *_: channel,
            SOCK_DGRAM=socket.SOCK_DGRAM,
            timeout=socket.timeout,
        ),
        "FAMILY": socket.AF_INET,
        "SOURCE": "127.0.0.2",
        "DESTINATION": "127.0.0.3",
        "UDP_PORT": 18081,
        "udp": value,
        "should_stop": lambda: True,
        "started": time.monotonic(),
        "EXPECTED_PROBE_ID": None,
        "EXPECTED_SOURCE_IPS": None,
    }
    exec(
        compile(
            ast.Module(body=[function], type_ignores=[]),
            "<production-udp-worker>",
            "exec",
        ),
        namespace,
    )
    namespace["udp_worker"]()
    assert value["terminal"] is True
    assert value["response"] is None and value["error"]
