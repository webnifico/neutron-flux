"""A failed SSH jump host is an execution prerequisite, not the measured network."""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.diagnostics import DiagnosticCollector
from neutron_flux.errors import ControllerUnavailableError, SuiteError
from neutron_flux.runtime.control_plane import ControlPlaneRuntimeMixin
from neutron_flux.runtime.topology import TopologyRuntimeMixin


def runtime(monkeypatch, *, recover=False, endpoint_only=False):
    import neutron_flux.runtime.control.ssh as module

    clock = {"now": 0.0}
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        clock["now"] += 3
        if recover and len(commands) > 1:
            return subprocess.CompletedProcess(command, 0, "", "")
        error = (
            "channel 0: open failed: connect failed: No route to host\nstdio forwarding failed"
            if endpoint_only
            else "ssh: connect to host 192.0.2.10 port 22: No route to host"
        )
        return subprocess.CompletedProcess(command, 255, "", error)

    monkeypatch.setattr(module.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(
        module.time, "sleep", lambda delay: clock.update(now=clock["now"] + delay)
    )
    monkeypatch.setattr(module, "run_cancellable", run)
    value = ControlPlaneRuntimeMixin()
    value.config = SimpleNamespace(
        ssh_timeout=15, resource_timeout=600, progress_interval=15
    )
    value.control_address = "192.0.2.10"
    value.key_path = Path("/tmp/unused-key")
    value.ssh_user = "debian"
    value.reporter = mock.Mock()
    value.logger = mock.Mock()
    value._collect_ssh_failure_diagnostics = mock.Mock(
        return_value={
            "address": value.control_address,
            "openstack_readback": {"server_id": "controller"},
        }
    )
    return value, clock, commands


def test_unreachable_controller_stops_endpoint_wait_with_controller_evidence(
    monkeypatch,
):
    value, clock, commands = runtime(monkeypatch)
    with pytest.raises(SuiteError, match="Controller SSH.*unavailable"):
        value._wait_for_ssh("10.254.0.11", proxy=True, timeout=600)
    assert clock["now"] <= 35
    assert len(commands) < 10
    value._collect_ssh_failure_diagnostics.assert_called_with("192.0.2.10", proxy=False)
    assert any(
        call.args[0] == "controller-access-lost"
        for call in value.reporter.event.call_args_list
    )


def test_transient_controller_failure_is_rechecked_before_endpoint_retry(monkeypatch):
    value, _clock, commands = runtime(monkeypatch, recover=True)
    assert value._wait_for_ssh("10.254.0.11", proxy=True, timeout=600) is True
    assert any(command[-2] == "debian@192.0.2.10" for command in commands)
    assert commands[-1][-2] == "debian@10.254.0.11"
    assert not any(
        call.args[0] == "controller-access-lost"
        for call in value.reporter.event.call_args_list
    )


def test_endpoint_forwarding_failure_does_not_assert_controller_loss(monkeypatch):
    value, _clock, commands = runtime(monkeypatch, endpoint_only=True)
    assert value._wait_for_ssh("10.254.0.11", proxy=True, timeout=12) is False
    assert all(command[-2] == "debian@10.254.0.11" for command in commands)
    value._collect_ssh_failure_diagnostics.assert_not_called()


def test_ssh_jump_failure_is_not_classified_as_measured_path_routing():
    probe = SimpleNamespace(
        outcome="error",
        stdout="",
        stderr="ssh: connect to host 192.0.2.10 port 22: No route to host",
        source_ip="10.0.0.2",
    )
    assert DiagnosticCollector._classify(probe) == "CONTROL_SSH"


def test_known_control_failure_is_checked_before_another_group_is_provisioned():
    value = TopologyRuntimeMixin()
    value.runtime_groups = []
    value.allocate_group_generation = mock.Mock(return_value=1)
    value._controller_recheck_required = True
    value._require_controller_ssh = mock.Mock(
        side_effect=ControllerUnavailableError("controller lost")
    )
    value._build_provider_group = mock.Mock()
    with pytest.raises(ControllerUnavailableError, match="controller lost"):
        value.build_group(
            SimpleNamespace(
                id="next-group", label="next group", kind="provider-network"
            )
        )
    value._build_provider_group.assert_not_called()


def test_controller_evidence_is_shared_across_failed_guest_probes(monkeypatch):
    value, _clock, _commands = runtime(monkeypatch)
    error = "ssh: connect to host 192.0.2.10 port 22: No route to host"
    first = value.record_controller_ssh_failure(error)
    second = value.record_controller_ssh_failure(error)
    assert first == second
    assert first["openstack_readback"]["server_id"] == "controller"
    assert first["observed_error"] == error
    value._collect_ssh_failure_diagnostics.assert_called_once()
    assert value._controller_recheck_required is True
