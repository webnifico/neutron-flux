from __future__ import annotations

import contextlib
import json
import selectors
import socket
import subprocess
import sys

import pytest

from neutron_flux.reporting_components.manual_programs import manual_helper_source


@pytest.fixture(scope="module")
def manual_helper(tmp_path_factory):
    path = tmp_path_factory.mktemp("portable-manual") / "neutron-flux-manual.py"
    path.write_text(manual_helper_source())
    return path


def _port(address, kind):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with socket.socket(family, kind) as sock:
        sock.bind((address, 0))
        return int(sock.getsockname()[1])


def _run(helper, *args, timeout=15):
    return subprocess.run(
        [sys.executable, str(helper), *map(str, args)],
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


@contextlib.contextmanager
def _server(helper, address):
    tcp = _port(address, socket.SOCK_STREAM)
    control = _port(address, socket.SOCK_STREAM)
    while control == tcp:
        control = _port(address, socket.SOCK_STREAM)
    udp = _port(address, socket.SOCK_DGRAM)
    process = subprocess.Popen(
        [
            sys.executable,
            str(helper),
            "probe-server",
            "--bind",
            address,
            "--probe-id",
            "manual-destination",
            "--tcp-port",
            str(tcp),
            "--udp-port",
            str(udp),
            "--control-port",
            str(control),
            "--lifetime",
            "30",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert process.stdout is not None
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdout, selectors.EVENT_READ)
            assert ready.select(timeout=10), (
                "portable responder did not announce readiness"
            )
            message = process.stdout.readline()
        assert message.startswith("NEUTRON_FLUX_READY "), message
        yield tcp, udp
    finally:
        # SIGINT exercises the helper's finally block and reaps its responder.
        import signal

        process.send_signal(signal.SIGINT)
        try:
            process.communicate(timeout=6)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)


@pytest.mark.parametrize("address", ["127.0.0.1", "::1"])
def test_portable_helper_matches_functional_and_performance_protocols(
    manual_helper, address
):
    with _server(manual_helper, address) as (tcp, udp):
        for protocol, port in (("tcp", tcp), ("udp", udp)):
            probe = _run(
                manual_helper,
                "probe-client",
                "--source",
                address,
                "--destination",
                address,
                "--protocol",
                protocol,
                "--port",
                port,
                "--token",
                "fresh-correlation-token",
                "--expected-probe-id",
                "manual-destination",
                "--expected-peer-ip",
                address,
            )
            assert probe.returncode == 0, probe.stderr
            assert '"response_validated":true' in probe.stdout
            measure = _run(
                manual_helper,
                "perf-client",
                "--source",
                address,
                "--destination",
                address,
                "--protocol",
                protocol,
                "--port",
                port,
                "--duration",
                "0.25",
                "--streams",
                "2",
                "--repeats",
                "2",
                "--rate-mbps",
                "1",
                "--packet-size",
                "256",
                "--expected-probe-id",
                "manual-destination",
                "--expected-peer-ip",
                address,
            )
            assert measure.returncode == 0, measure.stderr
            line = next(
                row
                for row in measure.stdout.splitlines()
                if row.startswith("NEUTRON_FLUX_MANUAL_RESULT ")
            )
            result = json.loads(line.split(" ", 1)[1])
            assert result["repeats"] == 2
            assert all(
                row["bytes"] > 0 if protocol == "tcp" else row["received"] > 0
                for row in result["samples"]
            )
        # The ordinary TCP probe also uses newline framing rather than nc defaults.
        echo = _run(
            manual_helper,
            "probe-client",
            "--source",
            address,
            "--destination",
            address,
            "--protocol",
            "tcp",
            "--port",
            tcp,
            "--token",
            "manual newline echo",
        )
        assert echo.returncode == 0, echo.stderr
        assert '"echo_validated":true' in echo.stdout


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
def test_portable_helper_rejects_wrong_observer_or_nat_source(manual_helper, protocol):
    with _server(manual_helper, "127.0.0.1") as (tcp, udp):
        arguments = (
            "probe-client",
            "--source",
            "127.0.0.1",
            "--destination",
            "127.0.0.1",
            "--protocol",
            protocol,
            "--port",
            tcp if protocol == "tcp" else udp,
            "--token",
            "manual-check",
        )
        wrong_id = _run(
            manual_helper, *arguments, "--expected-probe-id", "wrong-responder"
        )
        assert wrong_id.returncode != 0
        assert "identity mismatch" in wrong_id.stderr
        wrong_nat = _run(manual_helper, *arguments, "--expected-peer-ip", "192.0.2.44")
        assert wrong_nat.returncode != 0
        assert "source/NAT address mismatch" in wrong_nat.stderr


def test_portable_helper_requires_receiver_and_valid_family(manual_helper):
    unused = _port("127.0.0.1", socket.SOCK_STREAM)
    missing = _run(
        manual_helper,
        "perf-client",
        "--source",
        "127.0.0.1",
        "--destination",
        "127.0.0.1",
        "--protocol",
        "tcp",
        "--port",
        unused,
        "--duration",
        "0.25",
    )
    assert missing.returncode != 0
    assert "NEUTRON_FLUX_MANUAL_ERROR" in missing.stderr
    family = _run(
        manual_helper,
        "probe-client",
        "--source",
        "127.0.0.1",
        "--destination",
        "::1",
        "--protocol",
        "tcp",
        "--port",
        unused,
    )
    assert family.returncode != 0
    assert "address families differ" in family.stderr


def test_portable_helper_icmp_observer_uses_current_mac_ip_and_token(manual_helper):
    namespace = {"__name__": "portable_test"}
    exec(manual_helper.read_text(), namespace)
    from argparse import Namespace

    code = namespace["program"](
        "icmp",
        Namespace(
            local_ip="192.0.2.55",
            data_mac="FA:16:3E:12:34:56",
            probe_id="current-destination",
            token="a" * 32,
            timeout=17,
        ),
    )
    assert "MAC='fa:16:3e:12:34:56'" in code
    assert "FIXED='192.0.2.55'" in code
    assert "TOKEN='" + "a" * 32 + "'" in code
    assert "PROBE_ID='current-destination'" in code
    assert "time.monotonic()+17" in code
    assert "__NF_" not in code


@pytest.mark.parametrize("received", [0, 20])
def test_portable_helper_does_not_pass_a_rejected_udp_profile(
    manual_helper, monkeypatch, capsys, received
):
    namespace = {"__name__": "manual_test"}
    exec(manual_helper.read_text(), namespace)
    sample = {
        "packet_size_supported": False,
        "received": received,
        "reported_path_mtu": 1400,
    }
    monkeypatch.setitem(namespace, "peer", lambda _args: None)
    monkeypatch.setitem(namespace, "run_code", lambda *_args: json.dumps(sample))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(manual_helper),
            "perf-client",
            "--protocol",
            "udp",
            "--source",
            "127.0.0.1",
            "--destination",
            "127.0.0.1",
            "--port",
            "18081",
            "--packet-size",
            "1472",
        ],
    )
    with pytest.raises(SystemExit) as error:
        namespace["main"]()
    assert error.value.code == 2
    output = capsys.readouterr().out
    result = json.loads(output.split("NEUTRON_FLUX_MANUAL_RESULT ", 1)[1])
    assert result["outcome"] == "UNVERIFIED"
    assert result["samples"] == [sample]
    assert "did not complete" in result["reason"]


def test_portable_helper_substitutes_literals_once_without_corrupting_values(
    manual_helper,
):
    from argparse import Namespace

    namespace = {"__name__": "portable_test"}
    exec(manual_helper.read_text(), namespace)
    args = Namespace(
        bind="127.0.0.1",
        probe_id="probe-61503-8675309",
        tcp_port=61502,
        udp_port=55000,
        control_port=55001,
        source="127.0.0.1",
        destination="127.0.0.1",
        token="manual-8675309-61503-__NF_TOKEN__",
        port=61502,
    )
    server = namespace["program"]("server", args)
    assert "TCP_PORT = 61502" in server
    assert "UDP_PORT = 55000" in server
    assert "PROBE_ID = 'probe-61503-8675309'" in server
    client = namespace["program"]("peer-tcp", args)
    assert repr(args.token) in client
    assert "('127.0.0.1',61502)" in client


@pytest.mark.parametrize(
    ("reachable", "confirmed", "measured", "outcome"),
    [
        (True, True, 1500, "PASS"),
        (True, True, 1442, "PASS_WITH_OBSERVATION"),
        (True, False, 1442, "UNVERIFIED"),
        (False, False, None, "UNVERIFIED"),
    ],
)
def test_portable_mtu_assessment_requires_confirmed_evidence(
    manual_helper, reachable, confirmed, measured, outcome
):
    namespace = {"__name__": "portable_test"}
    exec(manual_helper.read_text(), namespace)
    result = namespace["assess_mtu"](
        {
            "reachable": reachable,
            "boundary_confirmed": confirmed,
            "discovered_mtu": measured,
            "expected_mtu": 1500,
        }
    )
    assert result["outcome"] == outcome
    assert result["confirmed_mtu"] == (measured if confirmed else None)
