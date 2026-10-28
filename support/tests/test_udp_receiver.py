from __future__ import annotations

import ast
import io
import json
import socket
import struct
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.performance import PerformanceRunner
from neutron_flux.probe_service import ProbeServiceManager

from ._shared import endpoint
from .test_performance_and_html import _resolved_path


@pytest.mark.parametrize("family", [socket.AF_INET, socket.AF_INET6])
@pytest.mark.parametrize("sessions", [1, 2])
def test_udp_kernel_files_are_read_at_session_boundaries_not_per_packet(
    family, sessions
):
    tree = ast.parse(ProbeServiceManager(18080, 18081)._server_code(endpoint()))
    # Execute the actual generated functions without starting listener threads.
    tree.body = [node for node in tree.body if not isinstance(node, ast.Try)]
    namespace = {}
    exec(compile(tree, "<generated-probe>", "exec"), namespace)
    header = namespace["UDP_DATA"]
    peer = (
        ("192.0.2.10", 12345)
        if family == socket.AF_INET
        else ("2001:db8::10", 12345, 0, 0)
    )
    destination = "192.0.2.20" if family == socket.AF_INET else "2001:db8::20"
    packet_info = (
        (
            socket.IPPROTO_IP,
            getattr(socket, "IP_PKTINFO", 8),
            struct.pack(
                "=I4s4s",
                4,
                socket.inet_pton(family, destination),
                socket.inet_pton(family, destination),
            ),
        )
        if family == socket.AF_INET
        else (
            socket.IPPROTO_IPV6,
            socket.IPV6_PKTINFO,
            struct.pack("=16sI", socket.inet_pton(family, destination), 4),
        )
    )
    sequence = [0, 2, 1, 1, *range(3, 500)]
    packets = []
    for number in sequence:
        for session in range(sessions):
            payload = header.pack(b"NFP1", session, number, number * 1000) + b"x" * 104
            packets.append((payload, [packet_info], 0, peer))
    for session in range(sessions):
        marker = namespace["UDP_END"].pack(b"NFE1", session, 507, 1_000_000_000)
        overflow = [(socket.SOL_SOCKET, namespace["SO_RXQ_OVFL"], struct.pack("I", 7))]
        packets.append((marker, [packet_info, *overflow], 0, peer))
    stream = iter(packets)
    clock = SimpleNamespace(now=20_000_000_000, finalizing=False)
    sent = []

    def receive(*_args):
        clock.now += 1000
        try:
            return next(stream)
        except StopIteration:
            if not clock.finalizing:
                clock.finalizing = True
                clock.now += 600_000_000
                raise TimeoutError from None
            raise

    def read_counters(path, *_args, **_kwargs):
        value = 7 if clock.finalizing else 0
        expected = "/proc/net/snmp6" if family == socket.AF_INET6 else "/proc/net/snmp"
        assert path == expected
        if family == socket.AF_INET6:
            return io.StringIO(f"Udp6InErrors {value}\nUdp6RcvbufErrors {value}\n")
        return io.StringIO(f"Udp: InErrors RcvbufErrors\nUdp: {value} {value}\n")

    reads = mock.Mock(side_effect=read_counters)
    namespace["open"] = reads
    namespace["time"] = SimpleNamespace(monotonic_ns=lambda: clock.now)
    sock = SimpleNamespace(
        family=family,
        recvmsg=receive,
        settimeout=lambda _: None,
        sendmsg=lambda buffers, _ancillary, _flags, _peer: (
            sent.append(buffers[0]) or len(buffers[0])
        ),
    )
    with pytest.raises(StopIteration):
        namespace["udp_loop"](sock)

    assert len(sent) == sessions
    assert reads.call_count == sessions * 2
    for payload in sent:
        result = json.loads(payload[4:])
        assert result["received"] == 500
        assert result["socket_dequeued"] == 501
        assert result["duplicates"] == 1
        assert result["out_of_order"] == 1
        assert result["lost"] == 7
        assert result["receiver_kernel_udp_deltas"] == {
            "InErrors": 7,
            "RcvbufErrors": 7,
        }
        assert result["receiver_socket_rxq_overflow"] == 7
        assert result["receiver_drop_attribution"] == "receiver-drop-counters-increased"


def _runner(config_factory, **overrides):
    runner = object.__new__(PerformanceRunner)
    runner.config = config_factory(
        performance_udp_rates_mbps=[10, 50],
        performance_udp_packet_sizes=[128],
        performance_udp_calibration_max_attempts=4,
        performance_udp_calibration_min_rate_mbps=1,
        **overrides,
    )
    return runner


def _measurement(rate, *, limited=False, loss=0.0):
    return {
        "sender_mbps": rate,
        "mbps": rate,
        "loss_pct": loss,
        "receiver_socket_rxq_overflow": 7 if limited else 0,
        "receiver_drop_attribution": "receiver-drop-counters-increased"
        if limited
        else "not-observed",
    }


def test_matrix_retests_known_sustainable_rate_within_original_attempt_budget(
    config_factory,
):
    runner = _runner(config_factory)
    calls = []

    def measure(_endpoint, source, _destination, _family, rate, size, **_kwargs):
        calls.append((source, rate, size))
        return _measurement(rate, limited=size == 128 and rate > 2)

    runner._udp_measurement = measure
    result = runner._udp_matrix(_resolved_path())
    for direction in ("forward", "reverse"):
        small = [s for s in result[direction] if s["packet_size"] == 128]
        assert [s["requested_mbps"] for s in small] == [10, 5, 2, 50, 25, 12, 2]
        assert small[-1]["configured_rate_mbps"] == 50
        assert small[-1]["calibration_selected_rate_mbps"] == 2
        assert small[-1]["calibration_attempts"] == 4
        assert small[-1]["calibration_selected"] is True
    assert runner._udp_health(result) == "good"
    assert len(calls) == 18


def test_sustainable_hints_do_not_cross_direction_packet_size_or_matrix(config_factory):
    runner = _runner(config_factory)
    recorded = []

    def samples(
        _endpoint,
        source,
        _destination,
        _family,
        configured,
        size,
        *,
        sustainable_rate_hint=None,
        **_kwargs,
    ):
        recorded.append((source, configured, size, sustainable_rate_hint))
        return [
            {
                "requested_mbps": 2,
                "loss_pct": 0.0,
                "calibration_selected": True,
                "load_valid": True,
                "endpoint_limited": False,
                "sender_telemetry_available": True,
            }
        ]

    runner._adaptive_udp_samples = samples
    for _ in range(2):
        result = runner._udp_matrix(_resolved_path())
        assert set(result) == {"forward", "reverse", "comparison"}
        assert result["comparison"]["incomplete_profiles"] == 0
    assert len(recorded) == 16
    assert all(
        hint is None if rate == 10 else hint == 2
        for _source, rate, _size, hint in recorded
    )


@pytest.mark.parametrize("hint", [None, 0, 100])
def test_missing_or_out_of_range_hint_preserves_bounded_backoff(config_factory, hint):
    runner = _runner(config_factory)
    runner._udp_measurement = lambda _e, _s, _d, _f, rate, _z: _measurement(
        rate, limited=True
    )
    result = runner._adaptive_udp_samples(
        endpoint(), "a", "b", 4, 50, 128, sustainable_rate_hint=hint
    )
    assert [s["requested_mbps"] for s in result] == [50, 25, 12, 6]
    assert runner._udp_health({"forward": result}) == "unverified"


def test_failed_hint_recheck_stays_unverified(config_factory):
    runner = _runner(config_factory)
    runner._udp_measurement = lambda _e, _s, _d, _f, rate, _z: _measurement(
        rate, limited=True
    )
    result = runner._adaptive_udp_samples(
        endpoint(), "a", "b", 4, 50, 128, sustainable_rate_hint=2
    )
    assert [s["requested_mbps"] for s in result] == [50, 25, 12, 2]
    assert result[-1]["calibration_status"] == "endpoint-limited"
    assert runner._udp_health({"forward": result}) == "unverified"


@pytest.mark.parametrize("budget", [1, 2, 4])
def test_hint_never_adds_attempts_or_skips_requested_load(config_factory, budget):
    runner = _runner(config_factory)
    runner.config.performance_udp_calibration_max_attempts = budget
    runner._udp_measurement = lambda _e, _s, _d, _f, rate, _z: _measurement(
        rate, limited=rate > 2
    )
    result = runner._adaptive_udp_samples(
        endpoint(), "a", "b", 4, 50, 128, sustainable_rate_hint=2
    )
    assert len(result) == budget
    assert result[0]["requested_mbps"] == 50
    assert result[-1]["requested_mbps"] == (50 if budget == 1 else 2)


def test_hint_below_operator_minimum_is_not_used(config_factory):
    runner = _runner(config_factory)
    runner.config.performance_udp_calibration_min_rate_mbps = 5
    runner._udp_measurement = lambda _e, _s, _d, _f, rate, _z: _measurement(
        rate, limited=True
    )
    result = runner._adaptive_udp_samples(
        endpoint(), "a", "b", 4, 50, 128, sustainable_rate_hint=2
    )
    assert [s["requested_mbps"] for s in result] == [50, 25, 12, 6]


@pytest.mark.parametrize("adaptive", [False, True])
def test_network_loss_does_not_trigger_calibration_to_hide_it(config_factory, adaptive):
    runner = _runner(config_factory, performance_udp_adaptive_calibration=adaptive)
    runner._udp_measurement = mock.Mock(return_value=_measurement(50, loss=100.0))
    result = runner._adaptive_udp_samples(
        endpoint(), "a", "b", 4, 50, 128, sustainable_rate_hint=2
    )
    runner._udp_measurement.assert_called_once()
    assert runner._udp_health({"forward": result}) == "critical"
