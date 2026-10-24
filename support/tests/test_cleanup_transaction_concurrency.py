"""Independent AZ cleanup must wait for live topology work without abandoning a lane."""

from __future__ import annotations

import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.cleanup import CleanupManager
from neutron_flux.cloud_operation import CloudOperationCoordinator
from neutron_flux.reporting import Reporter, ResourceTracker


@pytest.mark.parametrize(
    "resource_type,kind,command",
    [
        (
            "router",
            "router-gateway",
            ("router", "unset", "--external-gateway", "first"),
        ),
        ("subnet", "network-topology", ("subnet", "delete", "first")),
        ("network", "network-topology", ("network", "delete", "first")),
    ],
)
@pytest.mark.parametrize("verified", [True, False])
def test_live_topology_cleanup_does_not_abort_another_zone(
    config_factory, resource_type, kind, command, verified
):
    reporter = Reporter(config_factory(action="cleanup"), "concurrent-zone-cleanup")
    tracker = ResourceTracker(reporter)
    first = tracker.add(resource_type, "first", "first", group_id="zone-a")
    peer = tracker.add("subnet", "peer", "peer", group_id="zone-b")
    coordinator = CloudOperationCoordinator(reporter)
    coordinator._sleep = mock.Mock()
    exists = {"first", "peer"}
    manager = CleanupManager(
        SimpleNamespace(exists=lambda _type, identity: identity in exists),
        reporter,
        tracker,
        reporter.config,
        cloud_operation_coordinator=coordinator,
    )
    manager._wait_absent = lambda _type, identity, *_args: identity not in exists
    accepted, release, peer_checked = (threading.Event() for _ in range(3))
    original_blocker = coordinator.cleanup_blocker

    def blocker(identity, **kwargs):
        if identity == "peer":
            peer_checked.set()
        return original_blocker(identity, **kwargs)

    coordinator.cleanup_blocker = blocker

    def delete(resource):
        coordinator.execute(
            kind if resource is first else "network-topology",
            command if resource is first else ("subnet", "delete", "peer"),
            lambda: subprocess.CompletedProcess([], 0, "", ""),
        )
        if resource is first:
            accepted.set()
            assert release.wait(5)
        if resource is not first or verified:
            exists.remove(resource.id)

    manager._delete_subnet = delete
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            first_task = pool.submit(manager._delete_record, first, delete)
            try:
                assert accepted.wait(5)
                peer_task = pool.submit(manager.cleanup_group, "zone-b")
                assert peer_checked.wait(5)
                with pytest.raises(TimeoutError):
                    peer_task.result(timeout=0.05)
            finally:
                release.set()
            first_task.result(timeout=5)
            assert peer_task.result(timeout=5) is verified
        if verified:
            assert first.delete_status == peer.delete_status == "deleted"
            assert reporter.cleanup_summary["leftovers"] == []
            assert coordinator.unresolved_records() == []
        else:
            assert first.delete_status == peer.delete_status == "leftover"
            assert coordinator.unresolved_records()[0]["outcome"] == "AMBIGUOUS"
            assert "peer" in exists
            assert peer.cleanup_state == "QUARANTINED"
    finally:
        reporter.logger.close()
