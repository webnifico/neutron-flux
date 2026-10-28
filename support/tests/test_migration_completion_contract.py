"""Asynchronous Nova records through production waiter, producer and journal."""

from __future__ import annotations

import dataclasses
import subprocess
from copy import deepcopy
from types import SimpleNamespace

import pytest

from neutron_flux.cloud_operation import CloudOperationCoordinator
from neutron_flux.execution.placement_migration import PlacementMigrationMixin
from neutron_flux.migration_completion import (
    migration_completion,
    migration_operation_settlement,
)
from neutron_flux.runtime.migration_validation import MigrationValidationMixin

from ._evidence import completed_migration_evidence
from ._shared import endpoint
from .test_migration_and_load_evidence import _live_builder_without_reported_az
from .test_reaudit_continuity import attested_continuity


class Clock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, duration):
        assert 0 <= duration <= 2
        self.now += duration


def record(clock, terminal_at, terminal="completed", **overrides):
    return {
        "id": "new-record",
        "source_compute": "compute1",
        "dest_compute": "compute2",
        "type": "live-migration",
        "status": terminal if clock.now >= terminal_at else "running",
        **overrides,
    }


@pytest.mark.parametrize(
    "terminal_at,expected",
    [(0, True), (2, True), (122, True), (598, True), (600, True), (602, None)],
)
def test_real_record_observer_honors_configured_budget(
    monkeypatch, terminal_at, expected
):
    clock = Clock()
    monkeypatch.setattr("neutron_flux.runtime.migration_validation.time", clock)
    runtime = MigrationValidationMixin()
    runtime.config = SimpleNamespace(resource_timeout=600)
    runtime._migration_rows = lambda _server: ([record(clock, terminal_at)], None)
    result, error, evidence = runtime._verify_nova_migration_record(
        endpoint(),
        "compute1",
        "compute2",
        {"old-record"},
        expected_types={"live-migration"},
    )
    assert result is expected
    assert clock.now == min(terminal_at, 600)
    assert evidence["validation_observations"][-1]["elapsed_s"] == clock.now
    if expected is None:
        assert "600s" in error and evidence["status"] == "running"


@pytest.mark.parametrize("terminal", ["error", "failed", "cancelled"])
def test_delayed_failure_is_not_success(monkeypatch, terminal):
    clock = Clock()
    monkeypatch.setattr("neutron_flux.runtime.migration_validation.time", clock)
    runtime = MigrationValidationMixin()
    runtime.config = SimpleNamespace(resource_timeout=600)
    runtime._migration_rows = lambda _server: ([record(clock, 122, terminal)], None)
    assert (
        runtime._verify_nova_migration_record(
            endpoint(), "compute1", "compute2", set(), expected_types={"live-migration"}
        )[0]
        is False
    )
    assert clock.now == 122


@pytest.mark.parametrize(
    "field", ["server_uuid", "Server UUID", "instance_uuid", "server_id"]
)
@pytest.mark.parametrize(
    "identity,expected",
    [("foreign-server", False), (None, None), ("server-source", True)],
)
def test_explicit_nova_record_server_identity_must_match(field, identity, expected):
    clock = Clock()
    runtime = MigrationValidationMixin()
    runtime._migration_rows = lambda _server: (
        [record(clock, 0, **{field: identity})],
        None,
    )
    verified, error, _ = runtime._observe_nova_migration_record(
        endpoint(), "compute1", "compute2", set(), expected_types={"live-migration"}
    )
    assert verified is expected
    if expected is not True:
        assert "server" in error


def test_foreign_terminal_failure_cannot_authorize_migration_retry():
    runtime = MigrationValidationMixin()
    runtime._migration_rows = lambda _server: (
        [{"id": "new", "status": "failed", "server_uuid": "different-server"}],
        None,
    )
    verified, evidence = runtime._authoritative_migration_failure(
        endpoint(), {"migration_ids": set()}
    )
    assert verified is False
    assert "not submitted server" in evidence["reason"]


@pytest.mark.parametrize(
    "field",
    [
        "migration_record_verified",
        "task_state_cleared",
        "port_binding_verified",
        "volume_attachment_verified",
        "guest_marker_verified",
        "endpoint_ready",
    ],
)
@pytest.mark.parametrize(
    "value,expected",
    [(None, "UNVERIFIED"), (False, "FAIL"), ("true", "UNVERIFIED"), (True, "PASS")],
)
def test_completion_requires_positive_typed_evidence(field, value, expected):
    evidence = completed_migration_evidence()
    evidence[field] = value
    assert migration_completion(evidence)["status"] == expected


@pytest.mark.parametrize(
    "field",
    [
        "server_id",
        "source_host",
        "destination_host",
        "source_availability_zone",
        "destination_availability_zone",
    ],
)
def test_missing_placement_identity_is_not_completion(field):
    evidence = completed_migration_evidence()
    evidence.pop(field)
    assert migration_completion(evidence)["verified"] is None


def test_cross_az_evidence_never_qualifies_completion():
    evidence = completed_migration_evidence()
    evidence["destination_availability_zone"] = "other-zone"
    assert migration_completion(evidence)["verified"] is False


@pytest.mark.parametrize(
    "terminal_at,terminal,expected",
    [(122, "completed", True), (602, "completed", None), (122, "error", False)],
)
def test_delayed_record_through_runtime_producer_journal_and_verdict(
    config_factory,
    tmp_path,
    monkeypatch,
    terminal_at,
    terminal,
    expected,
):
    clock = Clock()
    monkeypatch.setattr("neutron_flux.runtime.migration_validation.time", clock)
    builder, moving, target = _live_builder_without_reported_az(config_factory)
    builder.config.resource_timeout = 600
    builder.config.live_migration_continuity = True
    events = []
    builder.reporter = SimpleNamespace(
        run_dir=tmp_path,
        config=SimpleNamespace(report_dir=None),
        logger=builder.logger,
        event=lambda event_type, message, **kw: events.append(
            (event_type, message, kw)
        ),
    )
    coordinator = CloudOperationCoordinator(builder.reporter)
    coordinator._sleep = lambda *_args, **_kwargs: None
    builder.cloud_operation_coordinator = coordinator
    builder._pre_migration_control_plane_barrier = lambda *_args: None
    builder._live_action_ids = lambda *_args: set()
    builder._migration_rows = lambda _server: (
        [record(clock, terminal_at, terminal)],
        None,
    )
    # Bind the real waiter; its real observer inspects the API-shaped records.
    builder._verify_nova_migration_record = (
        MigrationValidationMixin._verify_nova_migration_record.__get__(builder)
    )
    submissions = []

    def submit(*args, **kwargs):
        submissions.append(args)
        return coordinator.execute(
            "migration", args, lambda: subprocess.CompletedProcess(args, 0, "", "")
        )

    builder.osc = SimpleNamespace(run=submit)
    builder._start_live_continuity = lambda *_args: {"available": True}
    builder._stop_live_continuity = lambda *_args: deepcopy(attested_continuity())
    with coordinator.transaction(
        "migration",
        "delayed record",
        resource_ids=[moving.server_id],
        source_host=moving.host,
        destination_host=target.host,
    ):
        result = builder._live_migrate_endpoint_once(
            moving, target, endpoint("observer", "B")
        )
    assert len(submissions) == 1  # Pending finalization never means submit again.
    assert moving.host == target.host
    assert result.migration_record_verified is expected
    assert result.details["continuity"]["migration_succeeded"] is expected
    assert migration_completion(dataclasses.asdict(result))["verified"] is expected
    status = PlacementMigrationMixin._live_continuity_verdict(
        result.details["continuity"]
    )[0]
    assert status == (
        "PASS" if expected is True else "FAIL" if expected is False else "UNVERIFIED"
    )
    operations = coordinator.cloud_operation_summary()["operations"]
    assert operations[-1]["outcome"] == (
        "SUCCEEDED" if expected is True else "AMBIGUOUS"
    )
    assert bool(coordinator.cleanup_blocker(moving.server_id)) is (expected is not True)
    assert any(kind == "live-migration-complete" for kind, _, _ in events) is (
        expected is True
    )
    assert clock.now == min(terminal_at, 600)


def test_sparse_success_publication_cannot_override_missing_completion(tmp_path):
    reporter = SimpleNamespace(
        run_dir=tmp_path,
        config=SimpleNamespace(report_dir=None),
        logger=SimpleNamespace(log=lambda *_args: None),
        event=lambda *_args, **_kw: None,
    )
    coordinator = CloudOperationCoordinator(reporter)
    coordinator._sleep = lambda *_args, **_kw: None
    runtime = MigrationValidationMixin()
    runtime.cloud_operation_coordinator = coordinator
    with coordinator.transaction("migration", "sparse", resource_ids=["server-b"]):
        coordinator.execute(
            "migration",
            ("server", "migrate", "server-b"),
            lambda: subprocess.CompletedProcess([], 0, "", ""),
        )
        runtime._mark_current_migration_succeeded(
            {"server_id": "server-b", "server_status": "ACTIVE"}
        )
    assert (
        coordinator.cloud_operation_summary()["operations"][-1]["outcome"]
        == "AMBIGUOUS"
    )
    assert coordinator.cleanup_blocker("server-b")


def settled_unhealthy_port_evidence():
    return {
        **completed_migration_evidence(),
        "port_binding_verified": False,
        "server_status": "ACTIVE",
        "port_ownership_verified": True,
        "operation_inventory_verified": True,
    }


def test_settled_move_does_not_turn_failed_port_validation_into_a_pass():
    evidence = settled_unhealthy_port_evidence()
    validation = migration_completion(evidence)
    settlement = migration_operation_settlement(evidence)
    assert validation["status"] == "FAIL"
    assert validation["failed_checks"] == ["port_binding_verified"]
    assert settlement["status"] == "SETTLED"
    assert settlement["verified"] is True
    assert settlement["validation_status"] == "FAIL"
    assert settlement["resubmission_permitted"] is False


@pytest.mark.parametrize(
    "key",
    [
        "migration_record_verified",
        "task_state_cleared",
        "volume_attachment_verified",
        "port_ownership_verified",
        "operation_inventory_verified",
    ],
)
@pytest.mark.parametrize("value", [None, False, "true"])
def test_failed_validation_requires_explicit_typed_settlement(key, value):
    evidence = settled_unhealthy_port_evidence()
    evidence[key] = value
    assert migration_operation_settlement(evidence)["verified"] is not True


@pytest.mark.parametrize(
    "changes",
    [
        {"server_status": "VERIFY_RESIZE"},
        {"server_status": None},
        {"source_host": "compute2"},
        {"destination_host": None},
        {"destination_availability_zone": "other-az"},
        {"confirmed": False},
    ],
)
def test_destination_and_confirmation_evidence_cannot_be_bypassed(changes):
    evidence = {**settled_unhealthy_port_evidence(), **changes}
    assert migration_operation_settlement(evidence)["verified"] is not True


@pytest.mark.parametrize(
    "key", ["server_status", "port_ownership_verified", "operation_inventory_verified"]
)
@pytest.mark.parametrize("value", [None, "true", False])
def test_explicit_unknown_or_false_settlement_cannot_use_legacy_success(key, value):
    evidence = {**completed_migration_evidence(), key: value}
    assert migration_completion(evidence)["verified"] is True
    assert migration_operation_settlement(evidence)["verified"] is not True
