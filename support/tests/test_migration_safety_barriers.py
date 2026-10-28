"""Real migration barriers and acceptance waiters under API/time faults.

Nova, Neutron, Cinder and guest I/O are controlled external boundaries. The
production barrier, snapshot, acceptance waiter, record validator, submission
loop and durable operation journal execute without replacement verdicts.
"""

from __future__ import annotations

import copy
import subprocess
import time
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.errors import (
    AmbiguousCloudOperationError,
    CommandTimeoutError,
)
from neutron_flux.migration_completion import migration_completion
from neutron_flux.models import ComputeHostInfo
from neutron_flux.resources import ResourceBuilder

from ._shared import _placement_executor, endpoint
from .test_migration_settlement import _coordinator


@pytest.fixture
def safety_cloud(config_factory, tmp_path, monkeypatch):
    clock = SimpleNamespace(now=0.0)
    monkeypatch.setattr(time, "monotonic", lambda: clock.now)
    monkeypatch.setattr(
        time, "sleep", lambda seconds: setattr(clock, "now", clock.now + seconds)
    )
    moving, stationary = endpoint("moving", "B"), endpoint("stationary", "A")
    moving.volume_id = "root-volume"
    stationary.host = "compute2"
    target = ComputeHostInfo(
        "compute2", "az1", True, True, {"aggregate"}, {"aggregate"}
    )
    config = config_factory(
        action="run",
        storage="volume",
        migration_mode="live-preferred",
        live_migration_attempts=5,
        live_migration_continuity=False,
        resource_timeout=30,
        convergence_timeout=10,
    )
    server = {
        "status": "ACTIVE",
        "OS-EXT-STS:task_state": None,
        "OS-EXT-STS:power_state": 1,
        "OS-EXT-SRV-ATTR:host": "compute1",
        "OS-EXT-AZ:availability_zone": "az1",
    }
    ports = {
        port_id: {
            "device_id": moving.server_id,
            "status": "ACTIVE",
            "binding:host_id": "compute1",
            "mac_address": moving.test_mac,
            "fixed_ips": [
                {"subnet_id": subnet, "ip_address": address}
                for subnet, address in moving.fixed_ips.items()
            ],
            "security_group_ids": ["security-group"],
        }
        for port_id in (moving.management_port_id, moving.test_port_id)
    }
    cloud = SimpleNamespace(
        clock=clock,
        moving=moving,
        stationary=stationary,
        target=target,
        server=server,
        ports=ports,
        config=config,
        submitted=False,
        scenario="accepted",
        visible_at=0.0,
        submissions=[],
        server_reads=0,
        mutate_server=lambda detail, number: None,
        mutate_port=lambda detail, port_id, number: None,
        volume_rows=[{"ID": moving.volume_id}],
    )
    coordinator = _coordinator(tmp_path)
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config
    builder.reporter = coordinator.reporter
    builder.logger = coordinator.reporter.logger
    builder.cloud_operation_coordinator = coordinator
    builder.lifecycle_settlement_enabled = False
    builder._migration_command_args = lambda _server, *args: args
    builder._create_guest_migration_marker = mock.Mock(
        return_value={
            "path": "/tmp/original-marker",
            "token": "original",
            "sha256": "a" * 64,
        }
    )
    builder._verify_guest_migration_marker = mock.Mock(return_value=(True, None))
    builder._existing_probe_service_ready = mock.Mock(
        return_value=(True, {"identity": moving.server_id})
    )
    builder._wait_for_ssh = mock.Mock(return_value=True)
    builder.reconfigure_endpoint = mock.Mock()
    builder._live_action_ids = lambda *_args: set()
    builder._recover_endpoint_after_failed_migration = lambda *_args: (
        True,
        "source independently healthy",
    )
    builder.probe_service = SimpleNamespace(stop=mock.Mock())
    builder._wait_for_status = lambda *_args, **_kwargs: None
    builder.select_compute_migration_targets = lambda *_args, **_kwargs: (
        [target],
        "eligible",
    )

    def visible():
        return (
            cloud.submitted
            and cloud.scenario != "never"
            and clock.now >= cloud.visible_at
        )

    def read(*args, **kwargs):
        if args[:2] == ("server", "show"):
            cloud.server_reads += 1
            detail = copy.deepcopy(server)
            if visible():
                detail["OS-EXT-SRV-ATTR:host"] = target.host
            cloud.mutate_server(detail, cloud.server_reads)
            return detail
        if args[:2] == ("port", "show"):
            detail = copy.deepcopy(ports[args[2]])
            if visible():
                detail["binding:host_id"] = target.host
            cloud.mutate_port(detail, args[2], cloud.server_reads)
            return detail
        if args[:3] == ("server", "volume", "list"):
            return copy.deepcopy(cloud.volume_rows)
        if args[:2] == ("volume", "show"):
            return {"attachments": [{"server_id": moving.server_id}]}
        raise AssertionError(args)

    def rows(_server):
        if cloud.submitted and cloud.scenario == "lookup-error":
            return None, "Nova inventory unavailable"
        if not visible():
            return [], None
        return [
            {
                "ID": "new-migration",
                "Source Compute": "compute1",
                "Dest Compute": "wrong-host"
                if cloud.scenario == "wrong-record"
                else target.host,
                "Migration Type": "live-migration"
                if config.migration_mode != "cold-only"
                else "migration",
                "Status": "completed"
                if config.migration_mode != "cold-only"
                else "confirmed",
            }
        ], None

    def submit(*args, **kwargs):
        cloud.submissions.append(args)
        cloud.submitted = True
        cloud.visible_at = clock.now + (8 if cloud.scenario == "late" else 0)

        def remote():
            if cloud.scenario == "accepted":
                return subprocess.CompletedProcess(args, 0, "", "")
            raise CommandTimeoutError(list(args), 30)

        return coordinator.execute("migration", args, remote)

    builder._json_with_transient_retry = read
    builder._migration_rows = rows
    builder.osc = SimpleNamespace(run=submit, json=read)
    cloud.builder, cloud.coordinator = builder, coordinator
    return cloud


def test_real_barrier_records_three_stable_observations(safety_cloud):
    cloud = safety_cloud
    with cloud.coordinator.transaction(
        "migration", "barrier", resource_ids=[cloud.moving.server_id]
    ):
        evidence = cloud.builder._pre_migration_control_plane_barrier(
            cloud.moving, "compute1"
        )
    assert evidence["observation_count"] == 3
    assert all(
        item == evidence["stable_observations"][0]
        for item in evidence["stable_observations"]
    )
    assert cloud.clock.now == 4
    assert not cloud.submissions
    assert (
        len(
            [
                event
                for event in cloud.coordinator.reporter.events
                if event["type"] == "migration-safety-observation"
            ]
        )
        == 3
    )


@pytest.mark.parametrize("kind", ["live", "cold"])
def test_completed_move_with_down_management_port_settles_without_retry(
    safety_cloud, kind
):
    cloud = safety_cloud
    if kind == "cold":
        cloud.config.migration_mode = "cold-only"
    cloud.builder.osc.json = cloud.builder._json_with_transient_retry

    def port_health(detail, port_id, _number):
        if cloud.submitted and port_id == cloud.moving.management_port_id:
            detail["status"] = "DOWN"

    cloud.mutate_port = port_health
    with cloud.coordinator.transaction(
        "migration", "completed but unhealthy management port"
    ):
        result = getattr(cloud.builder, f"{kind}_migrate_endpoint")(
            cloud.moving, cloud.target
        )

    assert len(cloud.submissions) == 1
    assert result.migration_record_verified is True
    assert result.task_state_cleared is True
    assert result.port_binding_verified is False
    assert result.endpoint_ready is True
    assert result.volume_attachment_verified is True
    assert result.guest_marker_verified is True
    assert result.details["completion_assessment"]["status"] == "FAIL"
    assert result.details["ports"][cloud.moving.management_port_id]["status"] == "DOWN"
    settlement = result.details["operation_settlement_assessment"]
    assert settlement["verified"] is True
    assert settlement["validation_status"] == "FAIL"
    assert settlement["resubmission_permitted"] is False
    assert cloud.server_reads >= 7  # Three fresh observations after health failed.
    operation = cloud.coordinator.cloud_operation_summary()["operations"][-1]
    assert operation["outcome"] == "SUCCEEDED"
    assert operation["evidence"]["completion_assessment"]["status"] == "FAIL"
    assert operation["evidence"]["operation_settlement_assessment"] == settlement
    assert not cloud.coordinator.cleanup_blocker(cloud.moving.server_id)
    assert not cloud.coordinator.cleanup_blocker("unrelated-server")


@pytest.mark.parametrize(
    "fault",
    ["task-active", "wrong-owner", "wrong-host", "running-record", "foreign-record"],
)
def test_unsettled_move_with_down_management_port_still_blocks_cleanup(
    safety_cloud, fault
):
    cloud = safety_cloud
    cloud.builder.osc.json = cloud.builder._json_with_transient_retry
    fresh_observation = False

    def port_health(detail, port_id, _number):
        if cloud.submitted and port_id == cloud.moving.management_port_id:
            detail["status"] = "DOWN"
            if fault == "wrong-owner":
                detail["device_id"] = "different-server"
            if fault == "wrong-host":
                detail["binding:host_id"] = "compute1"

    def current_server(detail, number):
        nonlocal fresh_observation
        if cloud.submitted and number >= 5:
            fresh_observation = True
            if fault == "task-active":
                detail["OS-EXT-STS:task_state"] = "migrating"

    original_rows = cloud.builder._migration_rows

    def current_rows(server_id):
        rows, error = original_rows(server_id)
        if fresh_observation and fault == "running-record":
            rows[0]["Status"] = "running"
        if fresh_observation and fault == "foreign-record":
            rows[0]["Server UUID"] = "different-server"
        return rows, error

    cloud.mutate_port = port_health
    cloud.mutate_server = current_server
    cloud.builder._migration_rows = current_rows
    with cloud.coordinator.transaction("migration", "unsettled move"):
        result = cloud.builder.live_migrate_endpoint(cloud.moving, cloud.target)

    assert len(cloud.submissions) == 1
    assert result.port_binding_verified is False
    assert result.details["completion_assessment"]["status"] == "FAIL"
    assert result.details["operation_settlement_assessment"]["verified"] is not True
    operation = cloud.coordinator.cloud_operation_summary()["operations"][-1]
    assert operation["outcome"] == "AMBIGUOUS"
    assert cloud.coordinator.cleanup_blocker(cloud.moving.server_id)


@pytest.mark.parametrize("kind", ["live", "cold"])
def test_settled_validation_failure_stops_actual_attempt_loop_without_fallback(
    safety_cloud, kind
):
    cloud = safety_cloud
    if kind == "cold":
        cloud.config.migration_mode = "cold-only"

    def down_after_move(detail, port_id, _number):
        if cloud.submitted and port_id == cloud.moving.management_port_id:
            detail["status"] = "DOWN"

    cloud.mutate_port = down_after_move
    executor, spec, rows = _placement_executor(
        cloud.config, cloud.stationary, cloud.moving, cloud.builder
    )
    with cloud.coordinator.transaction("migration", "configured validation failure"):
        outcome = executor._attempt_configured_migration(
            dependencies=tuple(spec.dependencies),
            source=cloud.stationary,
            destination=cloud.moving,
            current_relation="inter-compute",
            desired_relation="same",
            desired_label="intra-compute",
        )

    result, attempts = outcome[1], outcome[3]
    assert result.port_binding_verified is False
    assert len(cloud.submissions) == 1
    assert len(attempts) == 1
    assert attempts[0]["status"] == "validation-failed"
    assert attempts[0]["cloud_operation_outcome"] == "SUCCEEDED"
    assert attempts[0]["retry_permitted"] is False
    assert outcome[5] is False  # No live-to-cold fallback after a completed move.
    assert outcome[7] is None  # No submission/recovery exception was invented.
    assert not cloud.coordinator.cleanup_blocker(cloud.moving.server_id)
    if kind == "live":
        capability = next(
            row for row in rows if row.scenario == "Live migration capability"
        )
        assert capability.status == "FAIL"
        assert capability.observed == "migration-validation-failed"


@pytest.mark.parametrize("kind", ["live", "cold"])
@pytest.mark.parametrize(
    "fault",
    [
        "missing-status",
        "missing-task",
        "missing-power",
        "missing-host",
        "busy",
        "wrong-host",
        "wrong-power",
        "port-down",
        "port-hidden",
        "port-host",
        "changing-address",
        "changing-mac",
        "changing-groups",
        "ssh",
        "probe",
        "active-migration",
        "missing-inventory",
    ],
)
def test_real_barrier_prevents_submission_and_fallback_on_uncertainty(
    safety_cloud, kind, fault
):
    cloud = safety_cloud
    missing = {
        "missing-status": "status",
        "missing-task": "OS-EXT-STS:task_state",
        "missing-power": "OS-EXT-STS:power_state",
        "missing-host": "OS-EXT-SRV-ATTR:host",
    }
    if fault in missing:
        cloud.server.pop(missing[fault])
    elif fault == "busy":
        cloud.server["OS-EXT-STS:task_state"] = "migrating"
    elif fault == "wrong-host":
        cloud.server["OS-EXT-SRV-ATTR:host"] = "outside-scope"
    elif fault == "wrong-power":
        cloud.server["OS-EXT-STS:power_state"] = 0
    elif fault.startswith("port-"):
        port = cloud.ports[cloud.moving.test_port_id]
        if fault == "port-down":
            port["status"] = "DOWN"
        elif fault == "port-hidden":
            port.pop("fixed_ips")
        else:
            port["binding:host_id"] = "outside-scope"
    elif fault.startswith("changing-"):
        field = {
            "changing-address": "fixed_ips",
            "changing-mac": "mac_address",
            "changing-groups": "security_group_ids",
        }[fault]
        value = {
            "changing-address": [{"subnet_id": "s4", "ip_address": "192.0.2.99"}],
            "changing-mac": "fa:16:3e:00:00:99",
            "changing-groups": ["other-group"],
        }[fault]
        cloud.mutate_port = lambda detail, port, number: (
            detail.update({field: value})
            if number > 1 and port == cloud.moving.test_port_id
            else None
        )
    elif fault == "ssh":
        cloud.builder._wait_for_ssh.return_value = False
    elif fault == "probe":
        cloud.builder._existing_probe_service_ready.return_value = (
            False,
            {"reason": "unhealthy"},
        )
    elif fault == "active-migration":
        cloud.builder._migration_rows = lambda *_args: (
            [{"ID": "existing", "Status": "running"}],
            None,
        )
    else:
        cloud.builder._migration_rows = lambda *_args: (None, "unavailable")
    if kind == "cold":
        cloud.config.migration_mode = "cold-only"
    executor, spec, _ = _placement_executor(
        cloud.config, cloud.stationary, cloud.moving, cloud.builder
    )
    with cloud.coordinator.transaction(
        "migration", "unsafe barrier", resource_ids=[cloud.moving.server_id]
    ):
        result = executor._attempt_configured_migration(
            dependencies=tuple(spec.dependencies),
            source=cloud.stationary,
            destination=cloud.moving,
            current_relation="inter-compute",
            desired_relation="same",
            desired_label="intra-compute",
        )
    assert result[1] is None
    assert len(result[3]) == 1
    assert result[3][0]["cloud_operation_outcome"] == "NOT_SUBMITTED"
    assert not result[3][0]["retry_permitted"]
    assert not cloud.submissions
    cloud.builder._create_guest_migration_marker.assert_not_called()
    assert not cloud.coordinator.cloud_operation_summary()["operations"]


@pytest.mark.parametrize("kind", ["live", "cold"])
@pytest.mark.parametrize(
    "scenario", ["accepted", "late", "never", "wrong-record", "lookup-error"]
)
def test_real_acceptance_waiter_through_submission_loop_and_journal(
    safety_cloud, kind, scenario
):
    cloud = safety_cloud
    cloud.scenario = scenario
    if kind == "cold":
        cloud.config.migration_mode = "cold-only"
    executor, spec, _ = _placement_executor(
        cloud.config, cloud.stationary, cloud.moving, cloud.builder
    )
    with cloud.coordinator.transaction(
        "migration", "acceptance", resource_ids=[cloud.moving.server_id]
    ):
        result = executor._attempt_configured_migration(
            dependencies=tuple(spec.dependencies),
            source=cloud.stationary,
            destination=cloud.moving,
            current_relation="inter-compute",
            desired_relation="same",
            desired_label="intra-compute",
        )
    assert len(cloud.submissions) == 1
    assert len(result[3]) == 1
    assert not result[3][0]["retry_permitted"]
    operations = cloud.coordinator.cloud_operation_summary()["operations"]
    events = [item["type"] for item in cloud.coordinator.reporter.events]
    if scenario in {"accepted", "late"}:
        assert result[1] is not None
        import dataclasses

        assert migration_completion(dataclasses.asdict(result[1]))["verified"] is True
        assert operations[-1]["outcome"] == "SUCCEEDED"
        assert not cloud.coordinator.cleanup_blocker(cloud.moving.server_id)
        if scenario == "late":
            assert "migration-acceptance-detected" in events
    else:
        assert operations[-1]["outcome"] == "AMBIGUOUS"
        assert cloud.coordinator.cleanup_blocker(cloud.moving.server_id)
        if result[1] is not None:
            import dataclasses

            assert (
                migration_completion(dataclasses.asdict(result[1]))["verified"]
                is not True
            )
        assert "live-migration-complete" not in events
        assert "cold-migration-complete" not in events


@pytest.mark.parametrize("signal", ["task", "host", "binding", "record"])
def test_acceptance_signals_are_evidence_of_submission_only(safety_cloud, signal):
    cloud = safety_cloud
    if signal == "task":
        cloud.server["OS-EXT-STS:task_state"] = "resize_migrating"
    elif signal == "host":
        cloud.server["OS-EXT-SRV-ATTR:host"] = "unexpected-host"
    elif signal == "binding":
        cloud.ports[cloud.moving.test_port_id]["binding:host_id"] = "unexpected-host"
    else:
        cloud.builder._migration_rows = lambda *_args: (
            [{"ID": "new", "Status": "failed", "Dest Compute": "unexpected-host"}],
            None,
        )
    evidence = cloud.builder._wait_for_migration_acceptance(
        cloud.moving,
        cloud.target.host,
        {"source_host": "compute1", "migration_ids": set()},
    )
    assert evidence["elapsed_seconds"] == 0
    assert not cloud.submissions
    assert "migration_succeeded" not in evidence


def test_no_observable_acceptance_exhausts_deadline_without_submission(safety_cloud):
    cloud = safety_cloud
    cloud.server.clear()
    cloud.builder._migration_rows = lambda *_args: (None, "lookup failed")
    cloud.ports.clear()
    cloud.builder._json_with_transient_retry = lambda *_args, **_kwargs: None
    with pytest.raises(AmbiguousCloudOperationError, match="no retry"):
        cloud.builder._wait_for_migration_acceptance(
            cloud.moving,
            cloud.target.host,
            {"source_host": "compute1", "migration_ids": set()},
        )
    assert cloud.clock.now == 30
    assert not cloud.submissions


@pytest.mark.parametrize("kind", ["live", "cold"])
@pytest.mark.parametrize("volume_rows", [None, {"error": "unavailable"}, [None]])
def test_unknown_volume_inventory_prevents_submission_without_tool_crash(
    safety_cloud, kind, volume_rows
):
    cloud = safety_cloud
    cloud.volume_rows = volume_rows
    if kind == "cold":
        cloud.config.migration_mode = "cold-only"
    executor, spec, _ = _placement_executor(
        cloud.config, cloud.stationary, cloud.moving, cloud.builder
    )
    with cloud.coordinator.transaction(
        "migration", "unknown volumes", resource_ids=[cloud.moving.server_id]
    ):
        result = executor._attempt_configured_migration(
            dependencies=tuple(spec.dependencies),
            source=cloud.stationary,
            destination=cloud.moving,
            current_relation="inter-compute",
            desired_relation="same",
            desired_label="intra-compute",
        )
    assert result[1] is None
    assert result[3][0]["cloud_operation_outcome"] == "NOT_SUBMITTED"
    assert not cloud.submissions
    cloud.builder._create_guest_migration_marker.assert_not_called()
