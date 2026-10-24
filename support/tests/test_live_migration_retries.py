"""Live retry settlement with real runtime, submission loop and durable journal."""

from __future__ import annotations

import copy
import subprocess
import time
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.errors import RunCancelledError, SuiteError
from neutron_flux.execution.placement_migration import PlacementMigrationMixin
from neutron_flux.models import ComputeHostInfo
from neutron_flux.resources import ResourceBuilder

from ._shared import _placement_executor, endpoint
from .test_migration_settlement import _coordinator


@pytest.fixture
def live_cloud(tmp_path, config_factory, monkeypatch):
    clock = SimpleNamespace(now=1000.0)
    monkeypatch.setattr(time, "monotonic", lambda: clock.now)
    monkeypatch.setattr(
        time, "sleep", lambda seconds: setattr(clock, "now", clock.now + seconds)
    )
    config = config_factory(
        migration_mode="live-preferred",
        live_migration_attempts=5,
        live_migration_continuity=False,
        storage="volume",
        resource_timeout=30,
        convergence_timeout=10,
    )
    moving, peer = endpoint("moving"), endpoint("peer")
    moving.volume_id = "volume-1"
    peer.host = "compute2"
    target = ComputeHostInfo("compute2", "az1", True, True, {"agg"}, {"agg"})
    server = {
        "status": "ACTIVE",
        "OS-EXT-STS:task_state": None,
        "OS-EXT-STS:power_state": 1,
        "OS-EXT-SRV-ATTR:host": "compute1",
    }
    ports = {
        port_id: {
            "device_id": moving.server_id,
            "binding:host_id": "compute1",
            "binding:vif_type": "ovs",
            "status": "ACTIVE",
            "mac_address": moving.test_mac,
            "security_group_ids": ["sg-1"],
            "fixed_ips": [{"subnet_id": "s4", "ip_address": "192.0.2.10"}],
        }
        for port_id in (moving.management_port_id, moving.test_port_id)
    }
    volume = {"attachments": [{"server_id": moving.server_id, "host_name": "compute1"}]}
    cloud = SimpleNamespace(
        clock=clock,
        config=config,
        moving=moving,
        peer=peer,
        target=target,
        server=server,
        ports=ports,
        volume=volume,
        rows=[],
        actions=[],
        action_details={},
        submissions=[],
        succeed_at=2,
        after_submit=lambda: None,
    )
    coordinator = _coordinator(tmp_path)
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config
    builder.logger = mock.Mock()
    builder.reporter = coordinator.reporter
    builder.cloud_operation_coordinator = coordinator
    builder._record_migration_destination = mock.Mock()
    builder._pre_migration_control_plane_barrier = mock.Mock()
    builder._migration_rows = lambda *_: (copy.deepcopy(cloud.rows), None)
    builder._server_volume_ids = lambda *_: {moving.volume_id}
    builder._verify_expected_volume_attachment = lambda *_: (
        True,
        None,
        copy.deepcopy(volume),
    )
    marker = {
        "path": "/tmp/flux-original-marker",
        "token": "original-token",
        "sha256": "original-hash",
    }
    builder._create_guest_migration_marker = mock.Mock(return_value=marker)
    builder._verify_guest_migration_marker = mock.Mock(return_value=(True, None))
    builder._wait_for_ssh = mock.Mock(return_value=True)
    builder.reconfigure_endpoint = mock.Mock()
    builder._migration_command_args = lambda _server, *args: args
    builder.select_compute_migration_targets = lambda *args, **kwargs: (
        [target],
        "eligible",
    )
    builder.cold_migrate_endpoint = mock.Mock(
        side_effect=AssertionError("Must remain live")
    )

    def read(*args, **kwargs):
        if args[:2] == ("server", "show"):
            return copy.deepcopy(server)
        if args[:2] == ("port", "show"):
            return copy.deepcopy(ports[args[2]])
        if args[:3] == ("server", "event", "list"):
            return copy.deepcopy(cloud.actions)
        if args[:3] == ("server", "event", "show"):
            return copy.deepcopy(cloud.action_details[args[4]])
        raise AssertionError(args)

    builder._json_with_transient_retry = read

    def submit(args):
        cloud.submissions.append(args)
        number = len(cloud.submissions)
        succeeded = number == cloud.succeed_at
        cloud.rows.append(
            {
                "ID": str(number),
                "Status": "completed" if succeeded else "failed",
                "Type": "live-migration",
                "Source Compute": "compute1",
                "Dest Compute": "compute2",
            }
        )
        request_id = f"req-{number}"
        cloud.actions.append({"Action": "live-migration", "Request ID": request_id})
        cloud.action_details[request_id] = {
            "request_id": request_id,
            "events": [
                {
                    "event": "compute_rollback_live_migration_at_destination",
                    "result": "Success",
                    "finish_time": "2026-10-06T08:09:42",
                }
            ],
        }
        host = "compute2" if succeeded else "compute1"
        server["OS-EXT-SRV-ATTR:host"] = host
        volume["attachments"][0]["host_name"] = host
        for port in ports.values():
            port.update(
                {"binding:host_id": host, "status": "ACTIVE" if succeeded else "DOWN"}
            )
        cloud.after_submit()
        return subprocess.CompletedProcess(args, 0, "", "")

    builder.osc = SimpleNamespace(
        json=read,
        run=lambda *args, **kwargs: coordinator.execute(
            "migration", args, lambda: submit(args)
        ),
    )
    executor, _, results = _placement_executor(config, peer, moving, builder)
    backoffs = []

    def backoff(seconds):
        backoffs.append(seconds)
        PlacementMigrationMixin._live_retry_backoff(seconds)

    executor._live_retry_backoff = backoff
    cloud.builder, cloud.coordinator, cloud.executor = builder, coordinator, executor
    cloud.results, cloud.backoffs, cloud.marker = results, backoffs, marker
    return cloud


def run_attempts(cloud):
    barrier = mock.Mock(return_value=True)
    with cloud.coordinator.transaction("migration", "live retry sequence"):
        result = cloud.executor._execute_migration_attempts(
            [(cloud.moving, cloud.peer, cloud.target)],
            migration_kind="live",
            submission_budget=5,
            pre_submission_barrier=barrier,
        )
    return result, barrier


@pytest.mark.parametrize("succeed_at", [2, 5, None])
def test_live_retries_down_ports_until_success_or_budget(live_cloud, succeed_at):
    cloud = live_cloud
    cloud.succeed_at = succeed_at
    outcome, barrier = run_attempts(cloud)
    count = succeed_at or 5
    assert len(cloud.submissions) == count
    assert all("--live-migration" in command for command in cloud.submissions)
    assert cloud.backoffs == [10 * i for i in range(1, count)]
    barrier.assert_called_once()
    cloud.builder._pre_migration_control_plane_barrier.assert_called_once()
    cloud.builder._create_guest_migration_marker.assert_called_once()
    cloud.builder.cold_migrate_endpoint.assert_not_called()
    records = list(cloud.coordinator._latest.values())
    assert [record["outcome"] for record in records] == [
        *(["FAILED_RETRYABLE"] * (count - 1)),
        "SUCCEEDED" if succeed_at else "FAILED_FINAL",
    ]
    for index, record in enumerate(records):
        assert record["pre_state"]["migration_ids"] == [
            str(i) for i in range(1, index + 1)
        ]
    assert cloud.coordinator.unresolved_records() == []
    assert cloud.coordinator.cleanup_blocker(cloud.moving.server_id) is None
    assert "_live_migration_retry" not in cloud.moving.metadata
    if succeed_at:
        result = outcome[0]
        assert result.destination_host == "compute2"
        assert result.port_binding_verified is True
        assert result.guest_marker_verified is True
        assert result.migration_record_verified is True
        assert result.endpoint_ready is True
        cloud.builder._verify_guest_migration_marker.assert_called_once_with(
            cloud.moving, cloud.marker
        )
    else:
        assert outcome[0] is None
        assert outcome[2][-1]["cloud_operation_outcome"] == "FAILED_FINAL"
        cloud.builder._verify_guest_migration_marker.assert_not_called()
    # Terminal Nova failures are detected without spending the destination timeout.
    assert cloud.clock.now - 1000 < 200


@pytest.mark.parametrize(
    "hazard",
    [
        "running",
        "unknown",
        "wrong-target",
        "wrong-source",
        "wrong-type",
        "old-record",
        "busy",
        "moved",
        "powered-off",
        "hidden-task",
        "port-owner",
        "port-host",
        "port-mac",
        "port-ip",
        "port-sg",
        "unbound",
        "hidden-port",
        "volume-host",
        "volume-duplicate",
        "rollback-pending",
        "rollback-failed",
        "rollback-missing",
    ],
)
def test_live_retry_refuses_uncertain_ownership(live_cloud, hazard):
    cloud = live_cloud
    baseline = cloud.builder._capture_endpoint_migration_state(cloud.moving)
    baseline["live_action_ids"] = set()
    # Create the same failed move without running its reconciliation loop.
    with cloud.coordinator.transaction("migration", "test failure"):
        cloud.builder.osc.run(
            "server", "migrate", "--live-migration", cloud.moving.server_id
        )
        row = cloud.rows[0]
        port = cloud.ports[cloud.moving.management_port_id]
        rollback = cloud.action_details["req-1"]["events"][0]
        if hazard in {"running", "unknown"}:
            cloud.rows.append({"ID": "other", "Status": hazard})
        elif hazard == "wrong-target":
            row["Dest Compute"] = "compute3"
        elif hazard == "wrong-source":
            row["Source Compute"] = "compute3"
        elif hazard == "wrong-type":
            row["Type"] = "resize"
        elif hazard == "old-record":
            baseline["migration_ids"] = {"1"}
        elif hazard == "busy":
            cloud.server["OS-EXT-STS:task_state"] = "migrating"
        elif hazard == "moved":
            cloud.server["OS-EXT-SRV-ATTR:host"] = "compute2"
        elif hazard == "powered-off":
            cloud.server["OS-EXT-STS:power_state"] = 4
        elif hazard == "hidden-task":
            del cloud.server["OS-EXT-STS:task_state"]
        elif hazard == "port-owner":
            port["device_id"] = "other-server"
        elif hazard == "port-host":
            port["binding:host_id"] = "compute2"
        elif hazard == "port-mac":
            port["mac_address"] = "fa:16:3e:00:00:ff"
        elif hazard == "port-ip":
            port["fixed_ips"][0]["ip_address"] = "192.0.2.99"
        elif hazard == "port-sg":
            port["security_group_ids"] = ["other-sg"]
        elif hazard == "unbound":
            port["binding:vif_type"] = "unbound"
        elif hazard == "hidden-port":
            del port["binding:host_id"]
        elif hazard == "volume-host":
            cloud.volume["attachments"][0]["host_name"] = "compute2"
        elif hazard == "volume-duplicate":
            cloud.volume["attachments"] *= 2
        elif hazard == "rollback-pending":
            rollback["finish_time"] = None
        elif hazard == "rollback-failed":
            rollback["result"] = "Error"
        elif hazard == "rollback-missing":
            cloud.action_details["req-1"]["events"] = []
        with pytest.raises(SuiteError):
            cloud.builder._live_retry_observation(cloud.moving, "compute2", baseline)
    assert len(cloud.submissions) == 1


def test_live_retry_rechecks_after_backoff(live_cloud):
    cloud = live_cloud
    cloud.executor._live_retry_backoff = lambda _: cloud.rows.append(
        {"ID": "other", "Status": "running"}
    )
    outcome, _ = run_attempts(cloud)
    assert outcome[0] is None
    assert len(cloud.submissions) == 1
    assert outcome[2][-1]["cloud_operation_outcome"] == "NOT_SUBMITTED"


def test_live_retry_keeps_incomplete_rollback_ambiguous(live_cloud):
    cloud = live_cloud
    cloud.after_submit = lambda: cloud.action_details["req-1"]["events"][0].update(
        finish_time=None
    )
    outcome, _ = run_attempts(cloud)
    assert outcome[0] is None
    assert len(cloud.submissions) == 1
    assert outcome[2][-1]["cloud_operation_outcome"] == "AMBIGUOUS"
    assert cloud.coordinator.cleanup_blocker(cloud.moving.server_id) is not None


def test_live_retry_cancelled_during_backoff_submits_no_more(live_cloud):
    cloud = live_cloud
    cloud.executor._live_retry_backoff = mock.Mock(
        side_effect=RunCancelledError("cancelled")
    )
    with pytest.raises(RunCancelledError):
        run_attempts(cloud)
    assert len(cloud.submissions) == 1
    assert cloud.coordinator.unresolved_records() == []


def run_configured(cloud):
    with cloud.coordinator.transaction("migration", "configured live sequence"):
        return cloud.executor._attempt_configured_migration(
            dependencies=("placement-group",),
            source=cloud.peer,
            destination=cloud.moving,
            current_relation="different",
            desired_relation="same",
            desired_label="same-host",
            pre_submission_barrier=mock.Mock(return_value=True),
        )


@pytest.mark.parametrize("ready", [True, False])
def test_recovery_capability_requires_final_guest_validation(live_cloud, ready):
    cloud = live_cloud
    cloud.builder._wait_for_ssh.return_value = ready
    outcome = run_configured(cloud)
    assert outcome is not None
    capability = next(
        row for row in cloud.results if row.scenario == "Live migration capability"
    )
    assert capability.status == ("PASS" if ready else "FAIL")
    assert len(capability.details["attempts"]) == 2
    cloud.builder.cold_migrate_endpoint.assert_not_called()


def test_budget_exhaustion_does_not_cold_migrate_unrecovered_guest(live_cloud):
    cloud = live_cloud
    cloud.succeed_at = None
    run_configured(cloud)
    assert len(cloud.submissions) == 5
    cloud.builder.cold_migrate_endpoint.assert_not_called()


def test_healthy_failed_move_retains_existing_full_recovery_path(live_cloud):
    cloud = live_cloud

    def healthy_failure():
        for port in cloud.ports.values():
            port["status"] = "ACTIVE"
        cloud.action_details["req-1"]["events"] = []

    cloud.after_submit = healthy_failure
    cloud.builder._recover_endpoint_after_failed_migration = mock.Mock(
        return_value=(True, "healthy source")
    )
    outcome, barrier = run_attempts(cloud)
    assert outcome[0] is not None
    assert len(cloud.submissions) == 2
    assert barrier.call_count == 2
    cloud.builder._recover_endpoint_after_failed_migration.assert_called_once()
