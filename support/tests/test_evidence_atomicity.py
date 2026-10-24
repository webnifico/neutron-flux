from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.cli import _reconcile_final_checkpoint
from neutron_flux.cloud_operation import (
    CloudOperationCoordinator,
    CloudOperationOutcome,
)
from neutron_flux.errors import PortValidationError, SuiteError
from neutron_flux.models import Endpoint, Plan, RunCheckpoint
from neutron_flux.models import TestSpec as FluxTestSpec
from neutron_flux.reporting import Reporter
from neutron_flux.resources import ResourceBuilder
from neutron_flux.runtime.migration_validation import MigrationValidationMixin
from neutron_flux.state import StateStore
from neutron_flux.utils import iso_utc


def _endpoint() -> Endpoint:
    return Endpoint(
        label="moving",
        server_id="server-b",
        server_name="server-b",
        management_port_id="port-b",
        management_ip="192.0.2.10",
        test_port_id=None,
        test_mac=None,
        fixed_ips={},
        host="compute1",
        availability_zone="az1",
        volume_id=None,
    )


def _spec(test_id: str) -> FluxTestSpec:
    return FluxTestSpec(
        test_id,
        "migration",
        "probe",
        4,
        "reachable",
        "regression fixture",
        True,
        [],
    )


def _checkpoint(store: StateStore, run_id: str) -> RunCheckpoint:
    now = iso_utc()
    run_dir = store.run_dir(run_id)
    return RunCheckpoint(
        run_id=run_id,
        state="FAILED",
        action="run",
        phase="finished",
        current_batch=None,
        started_at=now,
        updated_at=now,
        last_activity=now,
        completed_test_ids=[],
        failed_test_ids=[],
        pending_test_ids=[],
        active_group_ids=[],
        manifest_path=str(run_dir / "manifest.jsonl"),
        report_dir=str(run_dir),
        cleanup_state="INCOMPLETE",
    )


def test_migrated_port_evidence_is_json_serializable(
    config_factory,
):
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory(
        action="run",
        convergence_timeout=1,
        convergence_interval=0,
        resource_timeout=1,
    )
    builder._json_with_transient_retry = mock.Mock(
        return_value={
            "device_id": "server-b",
            "mac_address": "fa:16:3e:00:00:01",
            "fixed_ips": [{"subnet_id": "subnet-1", "ip_address": "192.0.2.10"}],
            "security_group_ids": ["sg-2", "sg-1"],
            "binding_host_id": "compute2",
            "status": "ACTIVE",
        }
    )
    before = {
        "ports": {
            "port-b": {
                "mac_address": "fa:16:3e:00:00:01",
                "fixed_ips": {"subnet-1": "192.0.2.10"},
                # Accept a historical in-memory baseline set while ensuring
                # the returned durable evidence is a deterministic JSON list.
                "security_groups": {"sg-1", "sg-2"},
            }
        }
    }

    verified, observed = builder._verify_migrated_ports(_endpoint(), "compute2", before)

    assert verified is True
    assert observed["port-b"]["security_groups"] == ["sg-1", "sg-2"]
    assert json.loads(json.dumps(observed, allow_nan=False)) == observed


def test_migration_port_timeout_preserves_last_management_and_test_states(
    config_factory, monkeypatch
):
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory(
        action="run", convergence_timeout=5, convergence_interval=0
    )
    clock = iter([0, 0, 0, 4, 6])
    monkeypatch.setattr(
        "neutron_flux.runtime.migration_execution.time.monotonic", lambda: next(clock)
    )
    monkeypatch.setattr(
        "neutron_flux.runtime.migration_execution.time.sleep", lambda _: None
    )
    moving = _endpoint()
    moving.test_port_id = "port-test"
    before = {
        "ports": {
            port: {"mac_address": "mac", "fixed_ips": {}, "security_groups": []}
            for port in ("port-b", "port-test")
        }
    }
    builder._json_with_transient_retry = lambda *args, **kwargs: {
        "device_id": moving.server_id,
        "mac_address": "mac",
        "fixed_ips": [],
        "security_group_ids": [],
        "binding_host_id": "compute2",
        "status": "DOWN" if args[2] == "port-b" else "ACTIVE",
    }
    with pytest.raises(PortValidationError) as raised:
        builder._verify_migrated_ports(moving, "compute2", before)
    ports = raised.value.ports
    assert ports["port-b"]["role"] == "management"
    assert ports["port-b"]["status"] == "DOWN"
    assert ports["port-test"]["status"] == "ACTIVE"
    assert {port["binding_host_id"] for port in ports.values()} == {"compute2"}
    assert json.loads(json.dumps(ports)) == ports


def test_result_rejection_is_atomic(config_factory):
    reporter = Reporter(config_factory(action="run"), "atomic-result")
    try:
        with pytest.raises(SuiteError, match="non-JSON evidence"):
            reporter.result(
                "MIGRATION",
                "migration",
                "PASS",
                "invalid evidence fixture",
                details={"security_groups": {"sg-1"}},
            )

        assert reporter.results == []
        assert reporter.has_result("MIGRATION") is False
        assert reporter.result_journal_path.read_text(encoding="utf-8") == ""

        reporter.result(
            "MIGRATION",
            "migration",
            "PASS",
            "valid retry",
            details={"security_groups": ["sg-1"]},
        )
        assert reporter.has_result("MIGRATION") is True
        journal = reporter.result_journal_path.read_text(encoding="utf-8")
        assert json.loads(journal)["test_id"] == "MIGRATION"
    finally:
        reporter.logger.close()


def test_event_rejects_non_json_details_before_buffering(
    config_factory,
):
    reporter = Reporter(config_factory(action="run"), "atomic-event")
    try:
        with pytest.raises(SuiteError, match="non-JSON details"):
            reporter.event("bad-event", "invalid", values={"one"})
        assert reporter.events == []
    finally:
        reporter.logger.close()


def test_failed_checkpoint_repartitions_materialized_results(
    tmp_path,
):
    store = StateStore(tmp_path / "reports")
    checkpoint = _checkpoint(store, "failed-materialized")
    checkpoint.pending_test_ids = ["MIGRATION", "POST-CHECK"]
    reporter = SimpleNamespace(
        results=[
            SimpleNamespace(test_id="MIGRATION", status="PASS"),
            SimpleNamespace(
                test_id="POST-CHECK",
                status="BLOCKED_BY_SETUP_ERROR",
            ),
        ],
        plan=Plan([], [], {}, [], tests=[_spec("MIGRATION"), _spec("POST-CHECK")]),
    )

    _reconcile_final_checkpoint(checkpoint, reporter)

    assert checkpoint.completed_test_ids == ["MIGRATION", "POST-CHECK"]
    assert checkpoint.pending_test_ids == []
    store.save(checkpoint)


def test_failed_checkpoint_retains_only_genuinely_pending_ids(
    tmp_path,
):
    store = StateStore(tmp_path / "reports")
    checkpoint = _checkpoint(store, "failed-partial")
    checkpoint.pending_test_ids = ["MIGRATION", "POST-CHECK"]
    reporter = SimpleNamespace(
        results=[SimpleNamespace(test_id="MIGRATION", status="ERROR")],
        plan=Plan([], [], {}, [], tests=[_spec("MIGRATION"), _spec("POST-CHECK")]),
    )

    _reconcile_final_checkpoint(checkpoint, reporter)

    assert checkpoint.completed_test_ids == ["MIGRATION"]
    assert checkpoint.failed_test_ids == ["MIGRATION"]
    assert checkpoint.pending_test_ids == ["POST-CHECK"]
    store.save(checkpoint)


def test_proven_migration_stays_resolved_after_reporting_error(
    tmp_path,
):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    reporter = SimpleNamespace(
        run_dir=run_dir,
        config=SimpleNamespace(report_dir=None),
        logger=mock.Mock(),
        event=mock.Mock(),
    )
    coordinator = CloudOperationCoordinator(reporter)
    harness = MigrationValidationMixin()
    harness.cloud_operation_coordinator = coordinator

    with pytest.raises(SuiteError, match="simulated reporting failure"):
        with coordinator.transaction(
            "migration",
            "live migration regression",
            resource_ids=["server-b", "port-b"],
            source_host="compute1",
            destination_host="compute2",
        ):
            coordinator.execute(
                "migration",
                (
                    "server",
                    "migrate",
                    "--live-migration",
                    "--host",
                    "compute2",
                    "server-b",
                ),
                lambda: subprocess.CompletedProcess([], 0, "", ""),
            )
            from ._evidence import completed_migration_evidence

            harness._mark_current_migration_succeeded(
                {
                    **completed_migration_evidence(),
                    "server_id": "server-b",
                    "source_host": "compute1",
                    "destination_host": "compute2",
                    "server_status": "ACTIVE",
                }
            )
            raise SuiteError("simulated reporting failure")

    records = coordinator.cloud_operation_summary()["operations"]
    assert records[-1]["outcome"] == CloudOperationOutcome.SUCCEEDED.value
    assert coordinator.cleanup_blocker("server-b") is None
