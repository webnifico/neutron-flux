"""Offline API faults through production migration guards and packet scheduling."""

from __future__ import annotations

import dataclasses
from unittest import mock

import pytest

from neutron_flux.engine import TestEngine as FluxEngine
from neutron_flux.errors import (
    AmbiguousCloudOperationError,
    PortValidationError,
    RunCancelledError,
    SuiteError,
)
from neutron_flux.migration_completion import migration_completion
from neutron_flux.models import ComputeHostInfo, MigrationResult
from neutron_flux.pair_workflow import CoordinatedPairExecutor
from neutron_flux.runtime.migration_execution import MigrationExecutionMixin

from . import test_external_recovery_coverage as egress_boundary
from . import test_live_migration_retries as retry_boundary
from . import test_migration_safety_barriers as migration_boundary
from ._shared import _placement_executor

external_cloud = egress_boundary.external_cloud
safety_cloud = migration_boundary.safety_cloud
live_cloud = retry_boundary.live_cloud

MALFORMED_TASK_STATES = [
    pytest.param(False, id="boolean-false"),
    pytest.param(0, id="integer-zero"),
    pytest.param([], id="empty-list"),
    pytest.param({}, id="empty-object"),
]


@pytest.mark.parametrize("kind", ["live", "cold"])
@pytest.mark.parametrize("task_state", MALFORMED_TASK_STATES)
def test_malformed_nova_task_state_prevents_real_submission(
    safety_cloud, kind, task_state
):
    cloud = safety_cloud
    cloud.server["OS-EXT-STS:task_state"] = task_state
    if kind == "cold":
        cloud.config.migration_mode = "cold-only"
    executor, spec, _ = _placement_executor(
        cloud.config, cloud.stationary, cloud.moving, cloud.builder
    )
    with cloud.coordinator.transaction(
        "migration", "malformed task state", resource_ids=[cloud.moving.server_id]
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
    assert not result[3][0]["retry_permitted"]
    assert not cloud.submissions
    assert not cloud.coordinator.cloud_operation_summary()["operations"]
    cloud.builder._create_guest_migration_marker.assert_not_called()


@pytest.mark.parametrize("kind", ["live", "cold"])
@pytest.mark.parametrize("task_state", [None, "", "None", "null", "<none>"])
def test_visible_null_task_markers_allow_real_complete_migration(
    safety_cloud, kind, task_state
):
    cloud = safety_cloud
    cloud.server["OS-EXT-STS:task_state"] = task_state
    with cloud.coordinator.transaction(
        "migration", "visible clear task", resource_ids=[cloud.moving.server_id]
    ):
        if kind == "cold":
            cloud.config.migration_mode = "cold-only"
            result = cloud.builder._cold_migrate_endpoint_once(
                cloud.moving, cloud.target
            )
        else:
            result = cloud.builder._live_migrate_endpoint_once(
                cloud.moving, cloud.target, cloud.stationary
            )
    assert len(cloud.submissions) == 1
    assert result.task_state_cleared is True
    assert migration_completion(dataclasses.asdict(result))["status"] == "PASS"


@pytest.mark.parametrize("task_state", MALFORMED_TASK_STATES)
def test_malformed_final_nova_task_state_is_unverified_in_real_cold_result(
    safety_cloud, task_state
):
    cloud = safety_cloud
    cloud.config.migration_mode = "cold-only"
    cloud.mutate_server = lambda detail, _: (
        detail.update({"OS-EXT-STS:task_state": task_state})
        if cloud.submitted
        else None
    )
    with cloud.coordinator.transaction(
        "migration", "malformed final task", resource_ids=[cloud.moving.server_id]
    ):
        result = cloud.builder._cold_migrate_endpoint_once(cloud.moving, cloud.target)
    assert len(cloud.submissions) == 1
    assert result.task_state_cleared is None
    assert migration_completion(dataclasses.asdict(result))["status"] == "UNVERIFIED"
    assert (
        cloud.coordinator.cloud_operation_summary()["operations"][-1]["outcome"]
        == "AMBIGUOUS"
    )


@pytest.mark.parametrize("task_state", MALFORMED_TASK_STATES)
def test_malformed_nova_task_state_cannot_certify_live_destination(
    safety_cloud, task_state
):
    cloud = safety_cloud
    cloud.mutate_server = lambda detail, _: (
        detail.update({"OS-EXT-STS:task_state": task_state})
        if cloud.submitted
        else None
    )
    with pytest.raises(SuiteError, match="Timed out waiting for live migration"):
        with cloud.coordinator.transaction(
            "migration", "malformed live task", resource_ids=[cloud.moving.server_id]
        ):
            cloud.builder._live_migrate_endpoint_once(
                cloud.moving, cloud.target, cloud.stationary
            )
    assert len(cloud.submissions) == 1
    cloud.builder.reconfigure_endpoint.assert_not_called()
    assert (
        cloud.coordinator.cloud_operation_summary()["operations"][-1]["outcome"]
        == "AMBIGUOUS"
    )


@pytest.mark.parametrize("task_state", MALFORMED_TASK_STATES)
@pytest.mark.parametrize("with_baseline", [True, False])
def test_malformed_nova_task_state_prevents_cold_failed_move_recovery(
    safety_cloud, task_state, with_baseline
):
    cloud = safety_cloud
    before = (
        cloud.builder._capture_endpoint_migration_state(cloud.moving)
        if with_baseline
        else None
    )
    cloud.server["OS-EXT-STS:task_state"] = task_state
    recovered, reason = (
        MigrationExecutionMixin._recover_endpoint_after_failed_migration(
            cloud.builder, cloud.moving, "compute1", "az1", before
        )
    )
    assert recovered is False
    assert "not verified clear" in reason
    cloud.builder.reconfigure_endpoint.assert_not_called()
    assert not cloud.submissions


@pytest.mark.parametrize("task_state", MALFORMED_TASK_STATES)
def test_malformed_nova_task_state_stops_actual_live_retry_loop(live_cloud, task_state):
    cloud = live_cloud
    cloud.after_submit = lambda: cloud.server.update(
        {"OS-EXT-STS:task_state": task_state}
    )
    outcome, _ = retry_boundary.run_attempts(cloud)
    assert outcome[0] is None
    assert len(cloud.submissions) == 1
    assert not cloud.backoffs
    cloud.builder.cold_migrate_endpoint.assert_not_called()
    assert outcome[2][-1]["cloud_operation_outcome"] == "AMBIGUOUS"
    assert not outcome[2][-1]["retry_permitted"]
    assert cloud.coordinator.cleanup_blocker(cloud.moving.server_id) is not None


@pytest.mark.parametrize("task_state", [["migrating"], {"task": "resize_migrating"}])
def test_malformed_native_task_container_is_not_acceptance_evidence(
    safety_cloud, task_state
):
    cloud = safety_cloud
    cloud.server["OS-EXT-STS:task_state"] = task_state
    with pytest.raises(AmbiguousCloudOperationError, match="no retry"):
        cloud.builder._wait_for_migration_acceptance(
            cloud.moving,
            cloud.target.host,
            {"source_host": "compute1", "migration_ids": set()},
        )
    assert not cloud.submissions
    events = cloud.coordinator.reporter.events
    assert not any(event["type"] == "migration-acceptance-detected" for event in events)
    assert events[-1]["details"]["task_state_cleared"] is None


@pytest.mark.parametrize("kind", ["live", "cold"])
@pytest.mark.parametrize(
    "fault",
    [
        "capture-unavailable",
        "unknown-status",
        "missing-id",
        "duplicate-id",
        "wrong-port-owner",
        "hidden-port-owner",
    ],
)
def test_no_submission_without_fresh_correlatable_inventory_and_port_owner(
    safety_cloud, kind, fault
):
    cloud = safety_cloud
    original = cloud.builder._migration_rows
    reads = 0

    def rows(server):
        nonlocal reads
        reads += 1
        if fault == "capture-unavailable":
            return (
                (None, "inventory failed after stable barrier")
                if reads == 4
                else original(server)
            )
        if fault == "unknown-status":
            return [{"ID": "old", "Status": "unrecognized"}], None
        if fault == "missing-id":
            return [{"Status": "completed"}], None
        if fault == "duplicate-id":
            return [{"ID": "old", "Status": "completed"}] * 2, None
        return original(server)

    cloud.builder._migration_rows = rows
    if fault == "wrong-port-owner":
        cloud.ports[cloud.moving.test_port_id]["device_id"] = "other-server"
    elif fault == "hidden-port-owner":
        cloud.ports[cloud.moving.test_port_id].pop("device_id")
    if kind == "cold":
        cloud.config.migration_mode = "cold-only"
    executor, spec, _ = _placement_executor(
        cloud.config, cloud.stationary, cloud.moving, cloud.builder
    )
    with cloud.coordinator.transaction(
        "migration", fault, resource_ids=[cloud.moving.server_id]
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
    assert not cloud.coordinator.cloud_operation_summary()["operations"]
    cloud.builder._create_guest_migration_marker.assert_not_called()


def test_terminal_historical_record_cannot_certify_missing_baseline(safety_cloud):
    cloud = safety_cloud
    cloud.builder._migration_rows = lambda _: (
        [
            {
                "ID": "historical",
                "Source Compute": "compute1",
                "Dest Compute": "compute2",
                "Migration Type": "migration",
                "Status": "confirmed",
            }
        ],
        None,
    )
    verified, error, record = cloud.builder._verify_nova_migration_record(
        cloud.moving,
        "compute1",
        "compute2",
        None,
    )
    assert verified is None
    assert "proven new" in error
    assert not record


def test_multiple_new_records_cannot_be_selected_by_newest_id(safety_cloud):
    cloud = safety_cloud
    cloud.builder._migration_rows = lambda _: (
        [
            {
                "ID": str(index),
                "Source Compute": "compute1",
                "Dest Compute": "compute2",
                "Migration Type": "migration",
                "Status": "confirmed",
            }
            for index in (10, 11)
        ],
        None,
    )
    verified, error, _ = cloud.builder._verify_nova_migration_record(
        cloud.moving, "compute1", "compute2", set()
    )
    assert verified is None
    assert "Multiple new" in error


@pytest.mark.parametrize(
    "field,value",
    [
        ("Source Compute", "other-source"),
        ("Dest Compute", "other-target"),
        ("Migration Type", "live-migration"),
    ],
)
def test_cold_failed_record_must_match_the_submitted_move(safety_cloud, field, value):
    cloud = safety_cloud
    before = cloud.builder._capture_endpoint_migration_state(cloud.moving)
    before.update(migration_type="cold", target_host="compute2")
    row = {
        "ID": "new",
        "Source Compute": "compute1",
        "Dest Compute": "compute2",
        "Migration Type": "migration",
        "Status": "error",
        field: value,
    }
    cloud.builder._migration_rows = lambda _: ([row], None)
    proven, evidence = cloud.builder._authoritative_migration_failure(
        cloud.moving, before
    )
    assert proven is False
    assert "does not match" in evidence["reason"]


@pytest.mark.parametrize("kind", ["live", "cold"])
@pytest.mark.parametrize(
    "fault", ["wrong-owner", "multiple-owners", "hidden-owner", "malformed-owner"]
)
def test_nova_volume_ids_do_not_replace_cinder_completion_ownership(
    safety_cloud, kind, fault
):
    cloud = safety_cloud
    if kind == "cold":
        cloud.config.migration_mode = "cold-only"
    original = cloud.builder._json_with_transient_retry
    attachments = {
        "wrong-owner": [{"server_id": "replacement"}],
        "multiple-owners": [
            {"server_id": cloud.moving.server_id},
            {"server_id": "replacement"},
        ],
        "hidden-owner": [{}],
        "malformed-owner": [{"server_id": cloud.moving.server_id}, "malformed"],
    }[fault]

    def read(*args, **kwargs):
        if args[:2] == ("volume", "show") and cloud.submitted:
            return {"attachments": attachments}
        return original(*args, **kwargs)

    cloud.builder._json_with_transient_retry = read
    executor, spec, _ = _placement_executor(
        cloud.config, cloud.stationary, cloud.moving, cloud.builder
    )
    with cloud.coordinator.transaction(
        "migration", fault, resource_ids=[cloud.moving.server_id]
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
    assert result[1].volume_attachment_verified is not True
    assert migration_completion(dataclasses.asdict(result[1]))["status"] != "PASS"
    assert not result[3][0]["retry_permitted"]
    assert (
        cloud.coordinator.cloud_operation_summary()["operations"][-1]["outcome"]
        == "AMBIGUOUS"
    )


@pytest.mark.parametrize("owner", ["other-server", None])
def test_destination_binding_does_not_replace_port_ownership(safety_cloud, owner):
    cloud = safety_cloud
    before = cloud.builder._capture_endpoint_migration_state(cloud.moving)
    cloud.submitted = True
    if owner is None:
        cloud.ports[cloud.moving.test_port_id].pop("device_id")
        verified, _ = cloud.builder._verify_migrated_ports(
            cloud.moving, "compute2", before
        )
        assert verified is None
    else:
        cloud.ports[cloud.moving.test_port_id]["device_id"] = owner
        with pytest.raises(PortValidationError, match="owned by"):
            cloud.builder._verify_migrated_ports(cloud.moving, "compute2", before)


@pytest.mark.parametrize(
    "fault",
    [
        "guest-changed",
        "guest-hidden",
        "volume-changed",
        "volume-hidden",
        "volume-owner",
        "az-changed",
    ],
)
def test_cold_retry_requires_original_guest_volume_and_zone(safety_cloud, fault):
    cloud = safety_cloud
    cloud.builder._recover_endpoint_after_failed_migration = (
        MigrationExecutionMixin._recover_endpoint_after_failed_migration.__get__(
            cloud.builder
        )
    )
    before = cloud.builder._capture_endpoint_migration_state(cloud.moving)
    if fault.startswith("guest"):
        cloud.builder._verify_guest_migration_marker.return_value = (
            False if fault == "guest-changed" else None,
            "original marker unavailable",
        )
    elif fault == "volume-changed":
        cloud.volume_rows = [{"ID": "replacement-volume"}]
    elif fault == "volume-hidden":
        cloud.volume_rows = None
    elif fault == "volume-owner":
        cloud.builder._verify_expected_volume_attachment = lambda *_: (
            False,
            "wrong owner",
            {},
        )
    else:
        cloud.server["OS-EXT-AZ:availability_zone"] = "other-zone"
    recovered, reason = cloud.builder._recover_endpoint_after_failed_migration(
        cloud.moving, "compute1", "az1", before
    )
    assert recovered is False, reason
    cloud.builder.reconfigure_endpoint.assert_not_called()
    assert not cloud.submissions


@pytest.mark.parametrize(
    "field",
    [
        "migration_record_verified",
        "task_state_cleared",
        "volume_attachment_verified",
        "guest_marker_verified",
        "confirmed",
    ],
)
def test_generic_nova_lifecycle_cannot_pass_missing_required_evidence(
    external_cloud, field
):
    cloud = external_cloud
    cloud.config.migration_mode = "cold-only"
    target = ComputeHostInfo("compute1", "az1", True, True)

    def migrate(moving, selected):
        prior = moving.host
        moving.host = selected.host
        result = MigrationResult(
            moving.server_id, prior, selected.host, "az1", "az1", True, False, True
        )
        setattr(result, field, None)
        return result

    cloud.executor.builder.select_compute_migration_targets = lambda *_a, **_k: (
        [target],
        "eligible",
    )
    cloud.executor.builder.cold_migrate_endpoint = migrate
    selected = [s for s in cloud.specs if s.operation == "probe"]
    cloud.engine.run_specs(selected)
    cloud.executor._run_compute_placement_validation(
        selected, cloud.engine, dependencies=(cloud.group.id,)
    )
    lifecycle = next(
        r for r in cloud.reporter.results if r.scenario == "Cold migration lifecycle"
    )
    assert lifecycle.status == "UNVERIFIED"
    assert (
        lifecycle.details["details"]["nova_lifecycle_assessment"]["status"]
        == "UNVERIFIED"
    )
    assert (
        lifecycle.details["details"]["completion_assessment"]["status"] == "UNVERIFIED"
    )
    assert any(
        r.scenario == "Intra-compute connectivity" for r in cloud.reporter.results
    )


def test_post_migration_readback_uses_its_own_measurement_dependencies(external_cloud):
    cloud = external_cloud
    baseline = next(s for s in cloud.specs if s.operation == "probe")
    source = dataclasses.replace(
        baseline,
        id="source-address",
        operation="fip-egress-source-address",
        metadata={"require_floating_ip": True},
    )
    mtu = dataclasses.replace(
        source,
        id="mtu",
        operation="fip-egress-mtu",
        requires_pass=[source.id],
        metadata={"require_floating_ip": True, "source_address_test_id": source.id},
    )
    fragment = dataclasses.replace(
        source,
        id="fragment",
        operation="fip-egress-fragmentation",
        requires=[mtu.id],
        requires_pass=[mtu.id],
        metadata={"require_floating_ip": True, "mtu_test_id": mtu.id},
    )
    readbacks = cloud.executor._placement_probe_specs(
        [source, mtu, fragment],
        relation="intra-compute",
        source=cloud.endpoints["A"],
        destination=cloud.endpoints["B"],
    )
    observed_source, observed_mtu, observed_fragment = readbacks
    assert observed_mtu.requires_pass == [observed_source.id]
    assert observed_mtu.metadata["source_address_test_id"] == observed_source.id
    assert (
        observed_fragment.requires
        == observed_fragment.requires_pass
        == [observed_mtu.id]
    )
    assert observed_fragment.metadata["mtu_test_id"] == observed_mtu.id
    assert {s.id for s in readbacks}.isdisjoint({source.id, mtu.id, fragment.id})


def test_coordinated_readback_attempts_packets_after_readiness_failure_without_lifecycle_writes(
    external_cloud, monkeypatch
):
    cloud = external_cloud
    executor = CoordinatedPairExecutor.__new__(CoordinatedPairExecutor)
    executor.config, executor.builder, executor.reporter = (
        cloud.config,
        cloud.executor.builder,
        cloud.reporter,
    )
    executor.logger, executor.active = cloud.executor.logger, cloud.executor.active
    executor.scope = {
        "pair_scope_id": "readback",
        "requested_source_host": "compute1",
        "requested_destination_host": "compute2",
        "pair_placement": "opposite",
        "host_qualification_cycle": 1,
    }
    executor._mark_specs_unavailable = cloud.executor._mark_specs_unavailable
    executor._run_performance = mock.Mock(
        side_effect=AssertionError("load work during failed recovery")
    )

    class BoundaryEngine(FluxEngine):
        def __init__(self, *args):
            super().__init__(*args)
            self.probes, self.diagnostics = (
                cloud.engine.probes,
                cloud.engine.diagnostics,
            )

    monkeypatch.setattr("neutron_flux.pair_workflow.TestEngine", BoundaryEngine)
    cloud.builder = executor.builder
    cloud.builder.discovery = cloud.engine.discovery
    cloud.state.active = False  # The actual packet boundary reports unreachable.
    executor._run_pair_stage(cloud.specs, "intra", read_only=True)
    assert cloud.state.calls
    assert not cloud.state.operations
    assert all(
        cloud.reporter.get_result(s.id).status == "FAIL"
        for s in cloud.specs
        if s.operation == "probe"
    )
    assert all(
        cloud.reporter.get_result(s.id).status == "BLOCKED_BY_PREREQUISITE"
        for s in cloud.specs
        if s.operation in {"server-stop", "server-start"}
    )
    executor._run_performance.assert_not_called()


@pytest.mark.parametrize("operation", ["inventory", "cinder-owner", "recovery"])
def test_migration_evidence_read_cancellation_is_not_an_unverified_result(
    safety_cloud, operation
):
    cloud = safety_cloud
    cloud.builder._json_with_transient_retry = mock.Mock(
        side_effect=RunCancelledError("operator cancelled")
    )
    with pytest.raises(RunCancelledError, match="operator cancelled"):
        if operation == "inventory":
            cloud.builder._server_volume_ids(cloud.moving.server_id)
        elif operation == "cinder-owner":
            cloud.builder._verify_expected_volume_attachment(
                cloud.moving.volume_id, cloud.moving.server_id
            )
        else:
            MigrationExecutionMixin._recover_endpoint_after_failed_migration(
                cloud.builder, cloud.moving, "compute1", "az1"
            )
    assert not cloud.submissions


@pytest.mark.parametrize("kind", ["live", "cold"])
def test_cancelled_guest_reconfiguration_stops_the_migration_execution(
    safety_cloud, kind
):
    cloud = safety_cloud
    cloud.builder.reconfigure_endpoint.side_effect = RunCancelledError(
        "operator cancelled during recovery"
    )
    with pytest.raises(RunCancelledError, match="operator cancelled"):
        with cloud.coordinator.transaction(
            "migration", "cancel recovery", resource_ids=[cloud.moving.server_id]
        ):
            if kind == "cold":
                cloud.config.migration_mode = "cold-only"
                cloud.builder._cold_migrate_endpoint_once(cloud.moving, cloud.target)
            else:
                cloud.builder._live_migrate_endpoint_once(
                    cloud.moving, cloud.target, cloud.stationary
                )
    assert len(cloud.submissions) == 1
    assert (
        cloud.coordinator.cloud_operation_summary()["operations"][-1]["outcome"]
        == "AMBIGUOUS"
    )


def test_live_destination_with_hidden_task_state_cannot_certify_completion(
    safety_cloud,
):
    cloud = safety_cloud
    cloud.mutate_server = lambda detail, _: (
        detail.pop("OS-EXT-STS:task_state", None) if cloud.submitted else None
    )
    with pytest.raises(SuiteError, match="Timed out waiting for live migration"):
        with cloud.coordinator.transaction(
            "migration", "hidden final task", resource_ids=[cloud.moving.server_id]
        ):
            cloud.builder._live_migrate_endpoint_once(
                cloud.moving, cloud.target, cloud.stationary
            )
    assert len(cloud.submissions) == 1
    cloud.builder.reconfigure_endpoint.assert_not_called()
    assert (
        cloud.coordinator.cloud_operation_summary()["operations"][-1]["outcome"]
        == "AMBIGUOUS"
    )


def test_unreadable_guest_marker_is_unknown_rather_than_a_changed_disk(safety_cloud):
    cloud = safety_cloud
    cloud.builder._wait_for_ssh.side_effect = lambda *_a, **_k: not cloud.submitted
    with cloud.coordinator.transaction(
        "migration", "SSH recovery failed", resource_ids=[cloud.moving.server_id]
    ):
        result = cloud.builder._live_migrate_endpoint_once(
            cloud.moving, cloud.target, cloud.stationary
        )
    assert result.endpoint_ready is False
    assert result.guest_marker_verified is None
    cloud.builder._verify_guest_migration_marker.assert_not_called()
    assert migration_completion(dataclasses.asdict(result))["status"] == "FAIL"
