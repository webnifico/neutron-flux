from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.errors import SuiteError
from neutron_flux.runtime.control.controller import ControllerRuntimeMixin
from neutron_flux.runtime.control.ssh import SSHRuntimeMixin


class SSHControllerRuntime(ControllerRuntimeMixin, SSHRuntimeMixin):
    pass


def test_exact_public1_refused_then_banner_timeout_is_tcp_reachable(
    monkeypatch,
):
    import neutron_flux.runtime.control.ssh as ssh_module

    clock = {"value": 0.0}
    errors = [
        "ssh: connect to host 172.20.1.194 port 22: Connection refused",
        "Connection timed out during banner exchange",
    ]
    calls = {"count": 0}

    def monotonic():
        return clock["value"]

    def run_failed_ssh(_command, **_kwargs):
        index = min(calls["count"], len(errors) - 1)
        calls["count"] += 1
        clock["value"] += 15.0
        return subprocess.CompletedProcess(
            args=["ssh"],
            returncode=255,
            stdout="",
            stderr=errors[index],
        )

    def sleep(seconds):
        clock["value"] += float(seconds)

    monkeypatch.setattr(ssh_module.time, "monotonic", monotonic)
    monkeypatch.setattr(ssh_module.time, "sleep", sleep)
    monkeypatch.setattr(ssh_module, "run_cancellable", run_failed_ssh)

    runtime = object.__new__(SSHControllerRuntime)
    runtime.config = SimpleNamespace(
        ssh_timeout=15,
        resource_timeout=180,
        progress_interval=15,
    )
    runtime.key_path = Path("/tmp/nonexistent-key")
    runtime.ssh_user = "debian"
    runtime.logger = mock.Mock()
    runtime.reporter = mock.Mock()
    runtime.reporter.event = mock.Mock()

    assert runtime._wait_for_ssh("172.20.1.194", proxy=False, timeout=180) is False

    evidence = runtime._ssh_readiness_evidence("172.20.1.194", proxy=False)
    assert evidence["tcp_reachability_observed"] is True
    assert evidence["path_classification"] == "tcp-reachable-ssh-not-ready"
    assert errors[0] in evidence["attempt_errors"]
    assert errors[1] in evidence["attempt_errors"]
    final_log = str(runtime.logger.log.call_args_list[-1].args[0])
    assert "TCP reached 172.20.1.194" in final_log
    assert "No TCP path" not in final_log

    runtime.reporter.reset_mock()
    with pytest.raises(SuiteError, match="was TCP-reachable"):
        runtime._require_network_path_failure_before_bastion(
            "172.20.1.194",
            network_name="Public1",
            diagnostics={
                "transport": {
                    "classification": "tcp-connected-no-ssh-banner",
                    "tcp_connected": True,
                    "ssh_banner_observed": False,
                    "error": "TCP port 22 connected but no SSH banner arrived",
                }
            },
        )
    event = runtime.reporter.event.call_args
    assert event.args[0] == "controller-direct-ssh-service-not-ready"
    assert event.kwargs["assessment"]["fallback_allowed"] is False


def test_public1_tcp_evidence_prohibits_bastion_fallback():
    runtime = object.__new__(SSHControllerRuntime)
    runtime.reporter = mock.Mock()
    runtime.reporter.event = mock.Mock()
    runtime._last_ssh_readiness = {
        "False:172.20.1.194": {
            "ready": False,
            "last_error": "Connection timed out during banner exchange",
            "tcp_reachability_observed": True,
            "network_path_failure_observed": False,
        }
    }
    diagnostics = {
        "transport": {
            "classification": "tcp-connected-no-ssh-banner",
            "tcp_connected": True,
            "ssh_banner_observed": False,
            "error": "TCP port 22 connected but no SSH banner arrived",
        }
    }

    with pytest.raises(SuiteError, match="was TCP-reachable") as exc_info:
        runtime._require_network_path_failure_before_bastion(
            "172.20.1.194",
            network_name="Public1",
            diagnostics=diagnostics,
        )

    assert "no management bastion was created" in str(exc_info.value)
    event = runtime.reporter.event.call_args
    assert event.args[0] == "controller-direct-ssh-service-not-ready"
    assert event.kwargs["network"] == "Public1"
    assessment = event.kwargs["assessment"]
    assert assessment["tcp_reachability_observed"] is True
    assert assessment["fallback_allowed"] is False


def test_connection_refused_probe_proves_path_reachability(monkeypatch):
    import neutron_flux.runtime.control.ssh as ssh_module

    def refused(*_args, **_kwargs):
        raise ConnectionRefusedError(111, "Connection refused")

    monkeypatch.setattr(ssh_module.socket, "create_connection", refused)
    runtime = object.__new__(SSHControllerRuntime)

    evidence = runtime._probe_direct_ssh_transport(
        "172.20.1.194",
        timeout=2.0,
    )

    assert evidence["tcp_connected"] is False
    assert evidence["connection_refused"] is True
    assert evidence["classification"] == "tcp-reachable-connection-refused"


def test_clear_network_path_failure_still_permits_bastion():
    runtime = object.__new__(SSHControllerRuntime)
    runtime.reporter = mock.Mock()
    runtime.reporter.event = mock.Mock()
    runtime._last_ssh_readiness = {
        "False:172.20.1.194": {
            "ready": False,
            "last_error": (
                "ssh: connect to host 172.20.1.194 port 22: No route to host"
            ),
            "tcp_reachability_observed": False,
            "network_path_failure_observed": True,
        }
    }

    assessment = runtime._require_network_path_failure_before_bastion(
        "172.20.1.194",
        network_name="Public1",
        diagnostics={
            "transport": {
                "classification": "tcp-connect-failed",
                "error": "OSError: [Errno 113] No route to host",
            }
        },
    )

    assert assessment["classification"] == "network-path-unavailable"
    assert assessment["fallback_allowed"] is True
    event = runtime.reporter.event.call_args
    assert event.args[0] == "controller-direct-network-path-unavailable"
