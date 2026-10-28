from __future__ import annotations

import shlex
from collections import Counter
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.cleanup import CleanupManager
from neutron_flux.cli import parser
from neutron_flux.cloud_operation import CloudOperationCoordinator, CloudOperationIntent
from neutron_flux.config import Config
from neutron_flux.configuration.snapshots import (
    execution_settings,
    restore_execution_settings,
)
from neutron_flux.errors import SuiteError
from neutron_flux.plan_contract import configuration_snapshot
from neutron_flux.replay_plan import _replay_command
from neutron_flux.reporting import Reporter
from neutron_flux.reporting_components.html import build_run_payload

from .test_cloud_operation_coordinator import _Reporter

LAUNCH = [
    "--image",
    "debian-13",
    "--flavor",
    "s-g-1cpu-2gb",
    "--storage",
    "volume",
    "--external-networks",
    "Public",
]


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NEUTRON_FLUX_CONFIG", raising=False)


def _coordinator(monkeypatch, quiet=1, gap=1):
    reporter = _Reporter()
    reporter.config = SimpleNamespace(quiet_period_scale=quiet, operation_gap_scale=gap)
    coordinator = CloudOperationCoordinator(reporter)
    clock = SimpleNamespace(now=100.0)
    monkeypatch.setattr(
        "neutron_flux.cloud_operation.time.monotonic", lambda: clock.now
    )
    coordinator._sleep = mock.Mock()
    return coordinator, clock, reporter


@pytest.mark.parametrize("quiet,gap", [(1, 1), (0.5, 0.25), (0, 0), (2, 3)])
def test_execute_scales_quiet_and_spacing_independently(monkeypatch, quiet, gap):
    coordinator, _clock, reporter = _coordinator(monkeypatch, quiet, gap)
    coordinator.execute("port-create", ("port", "create", "a"), lambda: "a")
    coordinator.execute("port-create", ("port", "create", "b"), lambda: "b")
    finishes = [
        e["details"] for e in reporter.events if e["type"] == "cloud-operation-finish"
    ]
    assert [e["quiet_period_seconds"] for e in finishes] == [3 * quiet, 3 * quiet]
    gaps = [
        call.args[0]
        for call in coordinator._sleep.call_args_list
        if "spacing before" in call.args[1]
    ]
    assert gaps == ([3 * gap] if gap else [])


def test_explicit_settlement_scales_before_crediting_elapsed_time(monkeypatch):
    coordinator, clock, reporter = _coordinator(monkeypatch, quiet=0.5)
    coordinator._last_completed_at = clock.now - 3
    coordinator.settle("network-topology", "topology ready", seconds=15)
    coordinator._sleep.assert_called_once_with(4.5, "topology ready")
    event = reporter.events[-1]["details"]
    assert event["requested_seconds"] == 7.5
    assert event["credited_seconds"] == 3


def test_host_gap_is_scaled_and_quarantine_still_blocks(monkeypatch):
    coordinator, clock, _reporter = _coordinator(monkeypatch, quiet=0, gap=0.5)
    coordinator._host_last_activity_at["compute1"] = clock.now
    intent = CloudOperationIntent("test", None, "migration", source_host="compute1")
    coordinator._assert_submission_allowed(intent, "fingerprint")
    assert coordinator._sleep.call_args.args[0] == 2.5
    coordinator._quarantined_resources["server1"] = "unresolved"
    assert "quarantined" in coordinator.cleanup_blocker("server1")


@pytest.mark.parametrize("scale", [0, 0.5, 2])
def test_error_backoff_and_fresh_inventory_windows_cannot_be_shortened(
    monkeypatch, scale
):
    coordinator, _clock, reporter = _coordinator(monkeypatch, quiet=scale, gap=scale)
    coordinator.settle("network-topology", "inventory", seconds=5, fresh=True)
    assert reporter.events[-1]["details"]["requested_seconds"] == 5 * max(1, scale)
    coordinator._adaptive_level = 1
    coordinator.settle("network-topology", "error recovery", seconds=5)
    assert reporter.events[-1]["details"]["requested_seconds"] == 7.5 * max(1, scale)
    coordinator._host_last_activity_at["compute1"] = 100
    coordinator._assert_submission_allowed(
        CloudOperationIntent("test", None, "migration", source_host="compute1"),
        "fingerprint",
    )
    assert coordinator._sleep.call_args.args[0] == 7.5 * max(1, scale)


@pytest.mark.parametrize("value", [-1, 11, float("nan"), float("inf"), True])
def test_coordinator_rejects_invalid_restored_pacing(monkeypatch, value):
    with pytest.raises(SuiteError, match="quiet_period_scale"):
        _coordinator(monkeypatch, quiet=value)


@pytest.mark.parametrize("scale", [0, 0.5, 2])
def test_cleanup_records_protected_scaled_inventory_wait(monkeypatch, scale):
    coordinator, _clock, reporter = _coordinator(monkeypatch, quiet=scale)
    manager = CleanupManager(
        mock.Mock(),
        reporter,
        mock.Mock(),
        SimpleNamespace(convergence_interval=5),
        cloud_operation_coordinator=coordinator,
    )
    seconds = manager._wait_for_exact_run_inventory_settlement(2)
    assert seconds == 5 * max(1, scale)
    assert coordinator._sleep.call_args.args[0] == seconds


def test_plan_snapshot_report_and_replay_preserve_nondefault_pacing(config_factory):
    config = config_factory(
        action="run",
        external_networks=["Public"],
        quiet_period_scale=0.5,
        operation_gap_scale=0,
    )
    snapshot = configuration_snapshot(config)
    restored = config_factory(action="run")
    restore_execution_settings(restored, snapshot["execution_settings"])
    assert restored.quiet_period_scale == 0.5
    assert restored.operation_gap_scale == 0
    reporter = Reporter(config, "pacing-replay")
    try:
        payload = build_run_payload(
            reporter,
            final_status="PASS",
            finished=datetime.now(timezone.utc),
            counts=Counter(),
            include_dashboard=False,
        )
        assert payload["configuration"]["quiet_period_scale"] == 0.5
        assert payload["configuration"]["operation_gap_scale"] == 0
        command = _replay_command(payload)
        args = parser().parse_args(shlex.split(command)[2:])
        replayed = Config.from_args(args)
        assert replayed.quiet_period_scale == 0.3
        assert replayed.operation_gap_scale == 0.3
        assert execution_settings(restored)["quiet_period_scale"] == 0.5
    finally:
        reporter.logger.close()
