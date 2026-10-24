"""Reject missing cloud evidence and preserve operator cancellation."""

from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.cleanup import CleanupManager
from neutron_flux.errors import CommandError, RunCancelledError, SuiteError
from neutron_flux.executor import AdaptiveExecutor
from neutron_flux.openstack import OpenStack
from neutron_flux.pair_suite import PairScopeExecutor
from neutron_flux.resources import ResourceBuilder

from ._shared import completed


def settlement_builder(config_factory, monkeypatch, ports):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(convergence_interval=0)
    builder.logger = mock.Mock()
    ready = {
        "status": "ACTIVE",
        "OS-EXT-SRV-ATTR:host": "expected",
        "OS-EXT-STS:task_state": None,
    }
    port_rows = iter(ports)

    def observe(kind, *_args, **_kwargs):
        value = ready if kind == "server" else next(port_rows)
        if isinstance(value, BaseException):
            raise value
        return value

    builder.osc = SimpleNamespace(json=mock.Mock(side_effect=observe))
    clock = iter(range(20))
    monkeypatch.setattr(
        "neutron_flux.runtime.control.servers.time.monotonic", lambda: next(clock)
    )
    monkeypatch.setattr(
        "neutron_flux.runtime.control.servers.time.sleep", lambda *_args: None
    )
    return builder, ready


@pytest.mark.parametrize("port", [None, {}, [], False])
def test_missing_port_cannot_establish_server_settlement(
    config_factory, monkeypatch, port
):
    builder, _ = settlement_builder(config_factory, monkeypatch, [port] * 4)
    with pytest.raises(SuiteError, match="Timed out.*settlement"):
        builder._wait_for_server_settlement(
            "vm", ["port"], expected_statuses={"active"}, timeout=3
        )


def test_missing_port_resets_consecutive_observations(config_factory, monkeypatch):
    valid = {"device_id": "vm", "binding:host_id": "expected", "status": "ACTIVE"}
    builder, ready = settlement_builder(
        config_factory, monkeypatch, [valid, None, valid, valid]
    )
    result = builder._wait_for_server_settlement(
        "vm",
        ["port"],
        expected_statuses={"active"},
        expected_host="expected",
        timeout=8,
        initial_server=ready,
    )
    assert result == ready
    calls = [call.args[0] for call in builder.osc.json.call_args_list]
    assert calls.count("port") == 4
    assert calls.count("server") == 3


def test_hidden_port_binding_cannot_establish_admin_settlement(
    config_factory, monkeypatch
):
    valid = {"id": "port", "device_id": "vm", "status": "ACTIVE"}
    builder, ready = settlement_builder(config_factory, monkeypatch, [valid, valid])
    with pytest.raises(SuiteError, match="Timed out.*settlement"):
        builder._wait_for_server_settlement(
            "vm", ["port"], expected_statuses={"active"}, timeout=3
        )


@pytest.mark.parametrize(
    "error",
    [
        RunCancelledError("cancelled"),
        CommandError(["openstack", "port", "show"], 1, "", "403 Forbidden"),
    ],
)
def test_port_read_error_is_not_settlement_evidence(config_factory, monkeypatch, error):
    builder, _ = settlement_builder(config_factory, monkeypatch, [error])
    with pytest.raises(type(error)):
        builder._wait_for_server_settlement(
            "vm", ["port"], expected_statuses={"active"}, timeout=3
        )


def allocation_manager(config_factory, output):
    manager = object.__new__(CleanupManager)
    manager.config = config_factory()
    manager.reporter = SimpleNamespace(
        resources=[SimpleNamespace(resource_type="server", id="vm", name="vm")]
    )
    manager.osc = OpenStack(mock.Mock())
    manager.osc.exists = mock.Mock(return_value=False)
    manager.osc.run = mock.Mock(return_value=completed(stdout=output))
    return manager


@pytest.mark.parametrize(
    "output",
    [
        "",
        " ",
        '{"allocations":null}',
        '{"allocations":false}',
        '{"allocations":0}',
        '{"allocations":""}',
        '{"allocations":[]}',
    ],
)
def test_allocation_verification_rejects_missing_or_invalid_evidence(
    config_factory, output
):
    manager = allocation_manager(config_factory, output)
    issues = manager._verify_placement_allocations()
    assert len(issues) == 1
    assert "verification-error" in issues[0]


@pytest.mark.parametrize("output", ['{"allocations":{}}', "{}", "[]"])
def test_explicit_empty_allocation_formats_remain_supported(config_factory, output):
    assert (
        allocation_manager(config_factory, output)._verify_placement_allocations() == []
    )


def test_invalid_allocation_does_not_skip_other_servers(config_factory):
    manager = allocation_manager(config_factory, "")
    manager.reporter.resources.append(
        SimpleNamespace(resource_type="server", id="other", name="other")
    )
    manager.osc.run.side_effect = [
        completed(stdout=""),
        completed(stdout='{"allocations":{"provider":{"resources":{"VCPU":1}}}}'),
    ]
    issues = manager._verify_placement_allocations()
    assert len(issues) == 2
    assert issues[0].startswith("placement-allocation:vm:verification-error")
    assert issues[1] == "placement_allocation:other:other"
    assert manager.osc.run.call_count == 2


@pytest.mark.parametrize("retained", [False, True])
def test_pair_placement_cancellation_is_not_a_setup_failure(retained):
    executor = object.__new__(PairScopeExecutor)
    runtime = SimpleNamespace(endpoints=[SimpleNamespace(side="A", host="expected")])
    executor.active = {"group": runtime}
    executor.failed_groups = set()
    executor.builder = SimpleNamespace(
        group_failures={}, stop_group_probes=mock.Mock(), runtime_groups=[]
    )
    executor._verify_runtime = mock.Mock(side_effect=RunCancelledError("cancelled"))
    executor._cleanup_failed_build = mock.Mock()
    executor._release = mock.Mock()
    executor._hosts_for = mock.Mock(return_value={"A": "expected"})
    executor._set_hosts = mock.Mock()
    with (
        mock.patch.object(AdaptiveExecutor, "_build", return_value=runtime),
        mock.patch.object(AdaptiveExecutor, "_ensure"),
    ):
        with pytest.raises(RunCancelledError):
            if retained:
                executor._ensure(("group",), required_sides={"group": ("A",)})
            else:
                executor._build("group", sides=("A",))
    assert executor.builder.group_failures == {}
    assert executor.failed_groups == set()
    executor._cleanup_failed_build.assert_not_called()
    executor._release.assert_not_called()


def test_cancellation_during_group_release_stops_further_rotation():
    executor = object.__new__(AdaptiveExecutor)
    executor.active = {"first": object(), "second": object()}
    executor._release = mock.Mock(side_effect=RunCancelledError("cancelled"))
    executor._refresh_checkpoint = mock.Mock()
    with pytest.raises(RunCancelledError):
        executor._release_all()
    executor._release.assert_called_once_with("first")
    assert set(executor.active) == {"first", "second"}
