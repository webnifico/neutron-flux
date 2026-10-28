from __future__ import annotations

import contextlib
import dataclasses
import errno
import io
import json
import socket
import struct
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.errors import MeasurementExecutionError
from neutron_flux.measurement_programs import udp_client_code
from neutron_flux.performance_metrics import udp_sample_assessable
from neutron_flux.performance_results import _performance_result_summary

from .test_performance_and_html import _resolved_path
from .test_udp_receiver import _measurement, _runner


class _PMTUSocket:
    """Exercise the generated production client against deterministic PMTU feedback."""

    def __init__(
        self,
        *,
        mtu=1436,
        family=4,
        reject_after=0,
        size_limit=None,
        send_errno=errno.EMSGSIZE,
        pmtu_available=True,
        control_error=False,
        wrong_session=False,
    ):
        self.mtu = mtu
        self.family = family
        self.reject_after = reject_after
        self.size_limit = size_limit
        self.send_errno = send_errno
        self.pmtu_available = pmtu_available
        self.control_error = control_error
        self.wrong_session = wrong_session
        self.sent = []
        self.end = None
        self.closed = False

    def settimeout(self, _value):
        pass

    def bind(self, address):
        self.source = address[0]

    def connect(self, _address):
        pass

    def getsockopt(self, level, option):
        assert (level, option) == (
            (socket.IPPROTO_IPV6, getattr(socket, "IPV6_MTU", 24))
            if self.family == 6
            else (socket.IPPROTO_IP, getattr(socket, "IP_MTU", 14))
        )
        if not self.pmtu_available:
            raise OSError(errno.ENOPROTOOPT, "not available")
        return self.mtu

    def send(self, data):
        if data.startswith(b"NFP1"):
            if self.size_limit is None or len(data) > self.size_limit:
                if len(self.sent) >= self.reject_after:
                    raise OSError(self.send_errno, "Message too long")
            self.sent.append(data)
        else:
            assert data.startswith(b"NFE1")
            if self.control_error:
                raise OSError(errno.ENETUNREACH, "No return route")
            self.end = data
        return len(data)

    def recv(self, _size):
        assert self.end is not None
        _, session, count, elapsed_ns = struct.unpack("!4sQIQ", self.end)
        assert count == len(self.sent)
        return (
            b"NFR1"
            + json.dumps(
                {
                    "session_id": session + int(self.wrong_session),
                    "sent": count,
                    "received": count,
                    "peer_ip": self.source,
                    "mbps": sum(len(item) for item in self.sent)
                    * 8.0
                    / max(elapsed_ns / 1e9, 1e-9)
                    / 1e6,
                    "loss_pct": 0.0,
                    "pps": count / max(elapsed_ns / 1e9, 1e-9),
                    "jitter_ms": 0.0,
                    "duplicates": 0,
                    "out_of_order": 0,
                }
            ).encode()
        )

    def close(self):
        self.closed = True


def _execute_client(code, sock):
    clock = SimpleNamespace(now=0)

    def tick():
        clock.now += 10_000
        return clock.now

    output = io.StringIO()
    with (
        mock.patch("socket.socket", return_value=sock),
        mock.patch("time.monotonic_ns", side_effect=tick),
        mock.patch("time.sleep"),
        contextlib.redirect_stdout(output),
    ):
        exec(compile(code, "<production-udp-client>", "exec"), {})
    return json.loads(output.getvalue())


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("completed", [0, 3])
def test_generated_client_preserves_prior_packets_and_reports_only_size_rejection(
    family, completed
):
    sock = _PMTUSocket(family=family, reject_after=completed)
    result = _execute_client(
        udp_client_code("192.0.2.1", "192.0.2.2", family, 18081, 1, 10, 1472), sock
    )
    assert result["packet_size_supported"] is False
    assert result["packet_size_status"] == "local-pmtu-rejection"
    assert result["packet_size_error"]["errno"] == errno.EMSGSIZE
    assert result["kernel_path_mtu"] == 1436
    assert result["packet_size_rejected"] == 1472
    assert result["sent"] == result["received"] == completed
    assert result["control_statistics_available"] is True
    assert sock.closed


def test_generated_client_does_not_invent_pmtu_when_kernel_cannot_report_it():
    result = _execute_client(
        udp_client_code("192.0.2.1", "192.0.2.2", 4, 18081, 1, 10, 1472),
        _PMTUSocket(pmtu_available=False),
    )
    assert result["kernel_path_mtu"] is None
    assert result["packet_size_supported"] is False


def test_generated_client_preserves_size_evidence_if_statistics_unavailable():
    result = _execute_client(
        udp_client_code("192.0.2.1", "192.0.2.2", 4, 18081, 1, 10, 1472),
        _PMTUSocket(control_error=True),
    )
    assert result["packet_size_supported"] is False
    assert result["control_statistics_available"] is False
    assert result["control_statistics_error"]
    assert "mbps" not in result and "loss_pct" not in result


@pytest.mark.parametrize("failure", ["route", "session"])
def test_unrelated_socket_errors_and_invalid_responder_still_fail(failure):
    with pytest.raises((OSError, ValueError)):
        _execute_client(
            udp_client_code("192.0.2.1", "192.0.2.2", 4, 18081, 1, 10, 1472),
            _PMTUSocket(
                send_errno=errno.ENETUNREACH,
                wrong_session=failure == "session",
                **({"reject_after": 0} if failure == "route" else {}),
            )
            if failure == "route"
            else _PMTUSocket(wrong_session=True),
        )


@pytest.mark.parametrize("family,mtu", [(4, 1436), (6, 1380)])
@pytest.mark.parametrize("reject_both", [False, True])
def test_matrix_keeps_requested_profiles_and_verifies_dynamic_payload_both_ways(
    config_factory, family, mtu, reject_both
):
    runner = _runner(config_factory)
    runner.config.performance_duration_seconds = 0.01
    path = _resolved_path()
    path = dataclasses.replace(
        path, plan=dataclasses.replace(path.plan, family=family), destination_mtu=1500
    )
    payload = mtu - (48 if family == 6 else 28)
    attempted = []

    def execute(source, code, **_kwargs):
        constrained = reject_both or source is path.destination
        sock = _PMTUSocket(
            family=family, mtu=mtu, size_limit=payload if constrained else 65535
        )
        result = _execute_client(code, sock)
        attempted.append((source, len(sock.sent[0]) if sock.sent else None, result))
        return result

    runner._run_json_with_transient_retry = execute
    metrics = runner._udp_matrix(path)
    near_mtu = 1500 - (48 if family == 6 else 28)
    for direction in ("forward", "reverse"):
        rows = metrics[direction]
        assert any(
            row["packet_size"] == 128 and udp_sample_assessable(row) for row in rows
        )
        supplements = [
            row for row in rows if row["packet_size_origin"] == "kernel-pmtu-supplement"
        ]
        assert {row["packet_size"] for row in supplements} == {payload}
        assert all(
            row["sent"] > 0 and row["received"] == row["sent"] for row in supplements
        )
        assert all(row["supplements_packet_sizes"] == [near_mtu] for row in supplements)
        assert all(udp_sample_assessable(row) for row in supplements)
    rejects = [
        row for row in metrics["reverse"] if row.get("packet_size_supported") is False
    ]
    assert len(rejects) == 2
    assert rejects[0]["packet_size_status"] == "local-pmtu-rejection"
    assert rejects[1]["measurement_attempted"] is False
    assert all(not udp_sample_assessable(row) for row in rejects)
    assert len(
        [
            row
            for _source, _size, row in attempted
            if row["packet_size_supported"] is False
        ]
    ) == (2 if reject_both else 1)
    assert metrics["comparison"]["incomplete_profiles"] == 2
    assert metrics["comparison"]["packet_size_rejected_profiles"] == 2
    assert metrics["comparison"]["original_requested_profiles"] == 4
    assert metrics["comparison"]["supplemental_profiles"] == 2
    assert runner._udp_health(metrics) == "warning"
    assert any(
        "this requested size was not validated" in reason
        for reason in runner._warning_reasons("udp", metrics, "warning")
    )
    assert "endpoint-limited" not in _performance_result_summary("udp", metrics)
    tcp = {"streams": {"1": {"median_mbps": 100}}}
    asymmetry = runner._asymmetry(
        tcp, tcp, {"forward": {"p95_ms": 1}, "reverse": {"p95_ms": 1}}, metrics
    )
    assert asymmetry["health"] == asymmetry["udp_health"] == "warning"
    assert (
        asymmetry["udp_unmatched_profiles"]
        == asymmetry["udp_packet_size_rejected_profiles"]
        == 2
    )
    assert asymmetry["udp_compared_profiles"] == 4


def test_missing_kernel_pmtu_preserves_small_profiles_without_inventing_fallback(
    config_factory,
):
    runner = _runner(config_factory)
    runner.config.performance_udp_rates_mbps = [10]

    def measure(_endpoint, _source, _destination, _family, rate, size, **_kwargs):
        return (
            {
                "packet_size_supported": False,
                "packet_size_status": "local-pmtu-rejection",
                "kernel_path_mtu": None,
            }
            if size > 128
            else _measurement(rate)
        )

    runner._udp_measurement = measure
    metrics = runner._udp_matrix(_resolved_path())
    assert {row["packet_size"] for row in metrics["forward"]} == {128, 1422}
    assert runner._udp_health(metrics) == "warning"
    assert metrics["comparison"]["incomplete_profiles"] == 1


def test_no_supported_udp_profiles_is_unverified_not_zero_loss_pass(config_factory):
    runner = _runner(config_factory)
    runner._udp_measurement = lambda *_args, **_kwargs: {
        "packet_size_supported": False,
        "packet_size_status": "local-pmtu-rejection",
        "kernel_path_mtu": None,
    }
    metrics = runner._udp_matrix(_resolved_path())
    assert runner._udp_health(metrics) == "unverified"
    assert not runner._udp_assessable_rows(metrics)
    assert metrics["comparison"]["incomplete_profiles"] == 4


def test_one_supported_direction_does_not_validate_missing_reverse_throughput(
    config_factory,
):
    runner = _runner(config_factory)
    runner.config.performance_udp_packet_sizes = [1420]
    path = _resolved_path()

    def measure(endpoint, _source, _destination, _family, rate, _size, **_kwargs):
        return (
            {"packet_size_supported": False, "kernel_path_mtu": None}
            if endpoint is path.destination
            else _measurement(rate)
        )

    runner._udp_measurement = measure
    metrics = runner._udp_matrix(path)
    assert runner._udp_assessable_rows({"forward": metrics["forward"]})
    assert not runner._udp_assessable_rows({"reverse": metrics["reverse"]})
    assert runner._udp_health(metrics) == "unverified"
    for sample in metrics["forward"]:
        sample["loss_pct"] = 100.0
    assert runner._udp_health(metrics) == "critical"


def test_comparison_pmtu_feedback_is_visible_and_drives_one_supplement(config_factory):
    runner = _runner(config_factory)
    runner.config.performance_udp_rates_mbps = [10]
    path = _resolved_path()
    calls = []

    def measure(endpoint, _source, _destination, _family, rate, size, **_kwargs):
        calls.append((endpoint, rate, size))
        if endpoint is path.source and size == 1422 and rate == 5:
            return {
                "packet_size_supported": False,
                "packet_size_status": "local-pmtu-rejection",
                "kernel_path_mtu": 1400,
            }
        return _measurement(
            rate, limited=endpoint is path.destination and size == 1422 and rate == 10
        )

    runner._udp_measurement = measure
    metrics = runner._udp_matrix(path)
    assert runner._udp_health(metrics) == "warning"
    assert metrics["comparison"]["packet_size_rejected_profiles"] == 1
    assert metrics["comparison"]["incomplete_profiles"] == 1
    assert metrics["comparison"]["supplemental_profiles"] == 1
    assert metrics["packet_size_constraints"][0]["direction"] == "forward"
    for direction in ("forward", "reverse"):
        assert any(
            row["packet_size"] == 1372
            and row["packet_size_origin"] == "kernel-pmtu-supplement"
            for row in metrics[direction]
        )
    assert calls.count((path.source, 5, 1422)) == 1
    assert any(
        "Message too long" in reason
        for reason in runner._warning_reasons("udp", metrics, "warning")
    )
    assert "local packet-size constraint" in _performance_result_summary("udp", metrics)


def test_new_path_clears_old_udp_profile_even_when_udp_cannot_start(config_factory):
    runner = _runner(config_factory)
    runner.reporter = SimpleNamespace(
        logger=SimpleNamespace(section=lambda *_: None, log=lambda *_: None)
    )
    runner._udp_active_profile = {
        "endpoint": "previous-path",
        "completed_attempts": [{"old": True}],
    }
    runner._partial_udp_samples = {"forward": [{"old": True}]}
    runner._capture_measurement = lambda *_args: None
    runner._measure(_resolved_path())
    assert runner._udp_active_profile == {}
    assert runner._partial_udp_samples == {}


def test_unrelated_later_profile_error_preserves_completed_samples(config_factory):
    runner = _runner(config_factory)

    def measure(_endpoint, _source, _destination, _family, rate, size, **_kwargs):
        if size != 128:
            raise MeasurementExecutionError("Responder command failed")
        return _measurement(rate)

    runner._udp_measurement = measure
    with pytest.raises(MeasurementExecutionError, match="Responder command failed"):
        runner._udp_matrix(_resolved_path())
    rows = runner._partial_udp_samples["forward"]
    assert len(rows) == 1 and rows[0]["packet_size"] == 128
    assert udp_sample_assessable(rows[0])


def test_comparison_error_keeps_completed_comparison_direction(config_factory):
    runner = _runner(config_factory)
    runner.config.performance_udp_rates_mbps = [10]
    runner._partial_udp_samples = {}
    path = _resolved_path()

    def measure(endpoint, _source, _destination, _family, rate, _size, **_kwargs):
        if endpoint is path.destination:
            raise MeasurementExecutionError("Reverse responder command failed")
        return _measurement(rate)

    runner._udp_measurement = measure
    with pytest.raises(
        MeasurementExecutionError, match="Reverse responder command failed"
    ):
        runner._matched_udp_comparison(
            path,
            [
                (
                    "forward",
                    path.source,
                    path.forward_source_ip,
                    path.forward_destination_ip,
                    None,
                ),
                (
                    "reverse",
                    path.destination,
                    path.reverse_source_ip,
                    path.reverse_destination_ip,
                    None,
                ),
            ],
            [128],
            {},
        )
    comparison = runner._partial_udp_samples["comparison"]
    assert len(comparison["forward"]) == 1 and not comparison["reverse"]
    assert comparison["forward"][0]["comparison_selected"] is False
