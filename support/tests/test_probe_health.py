from __future__ import annotations

import shlex
import socket
import subprocess
from unittest import mock

from neutron_flux.models import Endpoint
from neutron_flux.probe_service import ProbeServiceManager
from neutron_flux.resources import ResourceBuilder


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _endpoint(address: str = "127.0.0.1") -> Endpoint:
    return Endpoint(
        label="provider:B",
        server_id="server-b",
        server_name="server-b",
        management_port_id="mgmt",
        management_ip=address,
        test_port_id="test",
        test_mac="fa:16:3e:00:00:01",
        fixed_ips={},
        host="compute3",
        availability_zone="bc-van1",
        volume_id=None,
        side="B",
    )


def _local_ssh(_endpoint, command: str, timeout=None):
    return subprocess.run(
        shlex.split(command),
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def test_generated_probe_health_script_executes_and_does_not_match_itself(
    config_factory,
):
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory(tcp_port=_free_port(), udp_port=_free_port())
    builder.logger = mock.Mock()
    builder.ssh_endpoint = _local_ssh

    ready, evidence = builder._existing_probe_service_ready(_endpoint(""))

    assert ready is False
    assert evidence["inspection_complete"] is True
    assert evidence["listeners"] == {}
    assert evidence["processes"] == []


def test_generated_probe_health_script_verifies_real_tcp_udp_process(
    config_factory,
):
    tcp_port = _free_port()
    udp_port = _free_port()
    control_port = _free_port()
    endpoint = _endpoint()
    manager = ProbeServiceManager(tcp_port, udp_port)
    manager.set_control_ports({4: control_port})
    process = subprocess.Popen(
        shlex.split(manager.command(endpoint))[1:],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None
        assert process.stdout.readline().startswith("NEUTRON_FLUX_READY ")

        builder = ResourceBuilder.__new__(ResourceBuilder)
        builder.config = config_factory(tcp_port=tcp_port, udp_port=udp_port)
        builder.logger = mock.Mock()
        builder.ssh_endpoint = _local_ssh

        ready, evidence = builder._existing_probe_service_ready(endpoint)

        assert ready is True
        assert evidence["listeners"]["4"]["tcp"] is True
        assert evidence["listeners"]["4"]["udp"] is True
        assert evidence["service_identity"]["probe_id"] == endpoint.server_id
        assert len(evidence["service_identity"]["instance_id"]) == 32
    finally:
        process.terminate()
        process.wait(timeout=10)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
