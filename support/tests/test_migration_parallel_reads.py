"""Parallel port observations preserve migration safety and fresh evidence."""

from __future__ import annotations

import threading
from collections import Counter

import pytest

from neutron_flux.errors import (
    RunCancelledError,
    SuiteError,
    UnverifiableMigrationError,
)

from . import test_migration_safety_barriers as migration_boundary

safety_cloud = migration_boundary.safety_cloud


def test_safety_rounds_join_both_port_reads_before_advancing(safety_cloud):
    cloud = safety_cloud
    original = cloud.builder._json_with_transient_retry
    rendezvous = threading.Barrier(2)
    lock = threading.Lock()
    active = 0
    peak = 0
    observed_rounds = []

    def read(*args, **kwargs):
        nonlocal active, peak
        if args[:2] != ("port", "show"):
            with lock:
                assert active == 0
            return original(*args, **kwargs)
        with lock:
            active += 1
            peak = max(peak, active)
            observed_rounds.append((cloud.server_reads, args[2]))
        try:
            rendezvous.wait(timeout=2)
            return original(*args, **kwargs)
        finally:
            with lock:
                active -= 1

    cloud.builder._json_with_transient_retry = read
    with cloud.coordinator.transaction("migration", "barrier"):
        evidence = cloud.builder._pre_migration_control_plane_barrier(
            cloud.moving, "compute1"
        )
    assert peak == 2
    assert active == 0
    assert Counter(number for number, _ in observed_rounds) == {1: 2, 2: 2, 3: 2}
    assert all(
        {port for observed, port in observed_rounds if observed == number}
        == {cloud.moving.management_port_id, cloud.moving.test_port_id}
        for number in range(1, 4)
    )
    assert evidence["observation_count"] == 3
    assert (
        evidence["stable_observations"].count(evidence["stable_observations"][0]) == 3
    )
    assert cloud.clock.now == 4
    assert cloud.builder._wait_for_ssh.call_count == 3
    assert cloud.builder._existing_probe_service_ready.call_count == 3
    assert not cloud.submissions


@pytest.mark.parametrize(
    "fault", ["hidden-field", "changed-state", "read-error", "cancelled"]
)
def test_parallel_port_faults_prevent_barrier_completion(safety_cloud, fault):
    cloud = safety_cloud
    original = cloud.builder._json_with_transient_retry
    rendezvous = threading.Barrier(2)
    completed = []
    lock = threading.Lock()

    def read(*args, **kwargs):
        if args[:2] != ("port", "show"):
            return original(*args, **kwargs)
        try:
            rendezvous.wait(timeout=2)
            if args[2] == cloud.moving.test_port_id:
                if fault == "read-error":
                    raise SuiteError("Neutron inventory unavailable")
                if fault == "cancelled":
                    raise RunCancelledError("operator cancellation")
            detail = original(*args, **kwargs)
            if args[2] == cloud.moving.test_port_id:
                if fault == "hidden-field":
                    detail.pop("fixed_ips")
                if fault == "changed-state" and cloud.server_reads > 1:
                    detail["mac_address"] = "fa:16:3e:00:00:99"
            return detail
        finally:
            with lock:
                completed.append((cloud.server_reads, args[2]))

    cloud.builder._json_with_transient_retry = read
    error = RunCancelledError if fault == "cancelled" else SuiteError
    with cloud.coordinator.transaction("migration", "unsafe observation"):
        with pytest.raises(error):
            cloud.builder._pre_migration_control_plane_barrier(cloud.moving, "compute1")
    rounds = 2 if fault == "changed-state" else 1
    assert Counter(number for number, _ in completed) == {
        number: 2 for number in range(1, rounds + 1)
    }
    assert cloud.server_reads == rounds
    assert not cloud.submissions
    cloud.builder._create_guest_migration_marker.assert_not_called()
    assert not cloud.coordinator.cloud_operation_summary()["operations"]


def test_fresh_snapshot_parallel_reads_do_not_reuse_barrier_ports(safety_cloud):
    cloud = safety_cloud
    cloud.config.storage = "host"
    with cloud.coordinator.transaction("migration", "fresh snapshot"):
        cloud.builder._pre_migration_control_plane_barrier(cloud.moving, "compute1")
        cloud.ports[cloud.moving.test_port_id]["binding:host_id"] = "another-compute"
        with pytest.raises(
            UnverifiableMigrationError, match="changed after the safety barrier"
        ):
            cloud.builder._capture_endpoint_migration_state(cloud.moving)
    cloud.builder._create_guest_migration_marker.assert_not_called()
    assert not cloud.submissions


def test_fresh_snapshot_reads_both_ports_concurrently(safety_cloud):
    cloud = safety_cloud
    cloud.config.storage = "host"
    original = cloud.builder._json_with_transient_retry
    rendezvous = threading.Barrier(2)
    seen = []

    def read(*args, **kwargs):
        if args[:2] == ("port", "show"):
            seen.append(args[2])
            rendezvous.wait(timeout=2)
        return original(*args, **kwargs)

    cloud.builder._json_with_transient_retry = read
    with cloud.coordinator.transaction("migration", "capture"):
        evidence = cloud.builder._capture_endpoint_migration_state(cloud.moving)
    assert set(seen) == {cloud.moving.management_port_id, cloud.moving.test_port_id}
    assert set(evidence["ports"]) == set(seen)
    assert evidence["guest_marker"]["token"] == "original"
    assert not cloud.submissions
