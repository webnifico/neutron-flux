"""Recovered cleanup keeps current resource evidence across repeated passes."""

from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.cleanup import CleanupManager
from neutron_flux.cloud_operation import (
    CloudOperationCoordinator,
    CloudOperationOutcome,
)
from neutron_flux.errors import CommandTimeoutError
from neutron_flux.reporting import Reporter, ResourceTracker


def _manager(config_factory, tmp_path, *, project=False):
    config = config_factory(
        action="cleanup",
        report_dir=tmp_path / "reports",
        cleanup_orphans=project,
        cleanup_assume_yes=True,
    )
    reporter = Reporter(config, "nflux-20261009010101-a1b2c3")
    tracker = ResourceTracker(reporter)
    cloud = set()
    osc = SimpleNamespace(
        exists=lambda _kind, identity: identity in cloud,
        json=lambda *args, **_kwargs: (
            {"project_id": "project-id"} if args[:2] == ("token", "issue") else []
        ),
    )
    manager = CleanupManager(osc, reporter, tracker, config)
    manager._wait_absent = lambda _kind, identity, *_args: identity not in cloud
    manager._remove_local_keys = mock.Mock()
    manager._verify_placement_allocations = mock.Mock(return_value=[])
    manager._wait_for_exact_run_inventory_settlement = mock.Mock(return_value=0)
    return manager, reporter, tracker, cloud


def test_resolved_quarantine_is_retired_after_verified_deletion(
    config_factory, tmp_path
):
    manager, reporter, tracker, cloud = _manager(config_factory, tmp_path)
    record = tracker.add("network", "network-id", "network-name", group_id="pair-1")
    cloud.add(record.id)
    coordinator = CloudOperationCoordinator(reporter)
    coordinator._sleep = mock.Mock()
    manager.cloud_operation_coordinator = coordinator

    def lost_response():
        raise CommandTimeoutError(["network", "set", "network-id"], 60)

    try:
        with pytest.raises(CommandTimeoutError):
            coordinator.execute(
                "network-topology", ("network", "set", "network-id"), lost_response
            )
        operation = coordinator.unresolved_records()[0]
        manager._delete_network = lambda item: cloud.remove(item.id)
        manager._delete_record(record, manager._delete_network)
        assert record.cleanup_state == "QUARANTINED"
        assert reporter.cleanup_summary["leftovers"]
        coordinator.resolve(
            operation["operation_id"],
            CloudOperationOutcome.FAILED_FINAL,
            evidence={"terminal_state_verified": True},
            message="The prior operation reached a verified terminal failure",
        )

        assert manager.cleanup(adopt_discovered=False) is True
        assert cloud == set()
        assert record.delete_status == "deleted"
        assert reporter.cleanup_summary["leftovers"] == []
        assert reporter.cleanup_summary["unresolved_operations"] == []
        assert ResourceTracker.load_manifest(reporter.manifest_path)[
            0
        ].delete_status == ("deleted")
    finally:
        reporter.logger.close()


def _inventory(cloud):
    return {
        "candidates": [
            {
                "resource_type": "network",
                "id": identity,
                "name": identity,
                "run_id": "old-run",
                "evidence": {"name": "exact-run-prefix"},
            }
            for identity in sorted(cloud)
        ],
        "protected": [],
        "unknown": [],
        "runs": {},
    }


@pytest.mark.parametrize("status", ["deleted", "already-absent"])
@pytest.mark.parametrize("count", [1, 8])
def test_project_inventory_reopens_terminal_records_without_new_identity(
    config_factory, tmp_path, status, count
):
    manager, reporter, tracker, cloud = _manager(config_factory, tmp_path, project=True)
    records = [
        tracker.add("network", f"network-{index}", f"network-{index}")
        for index in range(count)
    ]
    for record in records:
        tracker.mark_deleted(record, status)
        cloud.add(record.id)
    manager._discover_project_orphans = lambda: _inventory(cloud)
    deleted = []

    def delete(record):
        deleted.append(record.id)
        cloud.remove(record.id)

    manager._delete_network = delete
    try:
        assert manager.cleanup_orphans() is True
        assert cloud == set()
        assert sorted(deleted) == sorted(record.id for record in records)
        loaded = ResourceTracker.load_manifest(reporter.manifest_path)
        assert len(loaded) == count
        assert {(item.sequence, item.id) for item in loaded} == {
            (item.sequence, item.id) for item in records
        }
        assert all(item.delete_status == "deleted" for item in loaded)
        assert all(
            item.metadata["cleanup_rediscovery_reason"] == "rediscovered-during-cleanup"
            for item in loaded
        )
    finally:
        reporter.logger.close()


def test_project_inventory_reopens_uuid_which_returns_between_passes(
    config_factory, tmp_path
):
    manager, reporter, _tracker, cloud = _manager(
        config_factory, tmp_path, project=True
    )
    cloud.add("returned-network")
    deleted = []
    reappeared = False

    def inventory():
        nonlocal reappeared
        if len(deleted) == 1 and not reappeared:
            cloud.add("returned-network")
            reappeared = True
        return _inventory(cloud)

    def delete(record):
        deleted.append(record.id)
        cloud.remove(record.id)

    manager._discover_project_orphans = inventory
    manager._delete_network = delete
    try:
        assert manager.cleanup_orphans() is True
        assert deleted == ["returned-network", "returned-network"]
        assert cloud == set()
        loaded = ResourceTracker.load_manifest(reporter.manifest_path)
        assert len(loaded) == 1
        assert loaded[0].delete_status == "deleted"
        assert loaded[0].metadata["cleanup_rediscovery_reason"] == (
            "rediscovered-during-cleanup"
        )
        assert reporter.cleanup_summary["leftovers"] == []
    finally:
        reporter.logger.close()
