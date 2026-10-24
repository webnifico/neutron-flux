"""Empty inventory is insufficient when visibility or command acceptance is unsettled."""

from __future__ import annotations

import subprocess
from unittest import mock

import pytest

from neutron_flux.cleanup import CleanupManager
from neutron_flux.cloud_operation import CloudOperationCoordinator
from neutron_flux.openstack import OpenStack
from neutron_flux.reporting import Reporter, ResourceTracker


def _manager(config_factory, tmp_path):
    config = config_factory(
        action="cleanup",
        report_dir=tmp_path,
        cleanup_orphans=True,
        cleanup_assume_yes=True,
    )
    reporter = Reporter(config, "orphan-cleanup-20260930010101-a1b2c3")
    osc = OpenStack(reporter.logger)
    osc.json = mock.Mock(
        side_effect=lambda *args, **kwargs: (
            {"project_id": "project-a"} if args[:2] == ("token", "issue") else []
        )
    )
    coordinator = CloudOperationCoordinator(reporter)
    coordinator._sleep = lambda *_args, **_kwargs: None
    manager = CleanupManager(
        osc,
        reporter,
        ResourceTracker(reporter),
        config,
        cloud_operation_coordinator=coordinator,
    )
    return manager, coordinator


def test_project_cleanup_waits_for_late_visibility_after_empty_inventory(
    config_factory, tmp_path
):
    manager, _ = _manager(config_factory, tmp_path)
    cloud = {"present": True, "visible": False}
    candidate = {
        "resource_type": "network",
        "id": "late-network",
        "name": "late-network",
        "run_id": "old-run",
        "evidence": {"name": "exact-run-prefix"},
    }

    def inventory():
        return {
            "candidates": [candidate] if cloud["visible"] and cloud["present"] else [],
            "protected": [],
            "unknown": [],
            "runs": {},
        }

    def settle(*_args):
        cloud["visible"] = True
        return 5.0

    def delete(**_kwargs):
        cloud["present"] = False
        for item in manager.reporter.resources:
            manager.tracker.mark_deleted(item, "deleted")
        return True

    manager._discover_project_orphans = mock.Mock(side_effect=inventory)
    manager._wait_for_exact_run_inventory_settlement = mock.Mock(side_effect=settle)
    manager.cleanup = mock.Mock(side_effect=delete)
    assert manager.cleanup_orphans() is True
    assert cloud["present"] is False
    manager.cleanup.assert_called_once()
    assert manager._wait_for_exact_run_inventory_settlement.call_count >= 2
    manager.reporter.logger.close()


@pytest.mark.parametrize("scope", ["project", "run"])
def test_unresolved_create_prevents_clean_verdict_with_empty_inventory(
    config_factory, tmp_path, scope
):
    manager, coordinator = _manager(config_factory, tmp_path)
    coordinator._latest["lost-create"] = {
        "operation_id": "lost-create",
        "kind": "network-topology",
        "command": ["network", "create", "nflux-pending-network"],
        "outcome": "AMBIGUOUS",
        "submitted": True,
    }
    manager.osc.run = mock.Mock(
        return_value=subprocess.CompletedProcess(
            [], 1, "", "No Network found for nflux-pending-network"
        )
    )
    action = manager.cleanup_orphans if scope == "project" else manager.cleanup
    assert action() is False
    assert manager.reporter.cleanup_summary["complete"] is False
    assert "lost-create" in manager.reporter.cleanup_summary["unresolved_operations"]
    assert coordinator.unresolved_records()
    assert all("delete" not in call.args for call in manager.osc.run.call_args_list)
    manager.reporter.logger.close()


def test_empty_dry_run_remains_a_preview_and_does_not_reconcile(
    config_factory, tmp_path
):
    manager, coordinator = _manager(config_factory, tmp_path)
    manager.config.cleanup_dry_run = True
    coordinator._latest["pending-create"] = {
        "operation_id": "pending-create",
        "outcome": "AMBIGUOUS",
        "command": ["network", "create", "nflux-pending-network"],
        "submitted": True,
    }
    manager.osc.run = mock.Mock()
    coordinator.resolve = mock.Mock()
    manager._wait_for_exact_run_inventory_settlement = mock.Mock()
    assert manager.cleanup_orphans() is True
    summary = manager.reporter.cleanup_summary
    assert summary["dry_run"] is True
    assert summary["complete"] is None
    assert summary["attempted"] is False
    assert summary["unresolved_operations"] == ["pending-create"]
    manager.osc.run.assert_not_called()
    coordinator.resolve.assert_not_called()
    manager._wait_for_exact_run_inventory_settlement.assert_not_called()
    manager.reporter.logger.close()


def test_unresolved_cleanup_writes_recovery_without_unsafe_deletes(
    config_factory, tmp_path
):
    manager, _ = _manager(config_factory, tmp_path)
    manager.reporter.cleanup_summary["unresolved_operations"] = ["lost-create"]
    manager._write_recovery_artifacts()
    guide = (manager.reporter.run_dir / "recovery.md").read_text()
    script = (manager.reporter.run_dir / "recovery.sh").read_text()
    assert "lost-create" in guide
    assert "unknown" in guide
    assert "openstack" not in script
    manager.reporter.logger.close()


def test_exact_run_cleanup_does_not_claim_to_reconcile_other_runs(
    config_factory, tmp_path
):
    manager, coordinator = _manager(config_factory, tmp_path)
    coordinator._external_unresolved = [
        {"operation_id": "other-run-create", "outcome": "AMBIGUOUS"}
    ]
    assert manager.cleanup() is True
    assert manager.reporter.cleanup_summary["unresolved_operations"] == []
    assert coordinator.unresolved_records()[0]["operation_id"] == "other-run-create"
    manager.reporter.logger.close()
