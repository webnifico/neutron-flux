from __future__ import annotations

import subprocess
from types import SimpleNamespace
from unittest import mock

import pytest

import neutron_flux.engine_handlers.packet_size as packet_size_module
from neutron_flux.cleanup import CleanupManager
from neutron_flux.cloud_operation import CloudOperationOutcome
from neutron_flux.errors import SuiteError
from neutron_flux.models import ProbeResult
from neutron_flux.reporting import ResourceTracker
from neutron_flux.runtime.migration_validation import MigrationValidationMixin
from neutron_flux.suite import Suite

from ._shared import endpoint, make_reporter
from .test_directional_floating_ip_egress import _fragmentation_spec, _mtu_spec
from .test_engine_handlers import _engine
from .test_measurement_integrity import _packet_size_spec


def _completed(returncode: int = 0, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess(["probe"], returncode, stdout, stderr)


def _recording_reporter(*, get_result=None):
    recorded: list[tuple[tuple, dict]] = []
    reporter = SimpleNamespace(
        result=lambda *args, **kwargs: recorded.append((args, kwargs)),
    )
    if get_result is not None:
        reporter.get_result = get_result
    return reporter, recorded


def _ready_fip_engine(config_factory):
    engine, provider, project, groups, _records = _engine(config_factory)
    groups["target"].fips[project.label] = {
        "id": "fip-id",
        "address": "203.0.113.10",
        "port_id": project.test_port_id,
        "fixed_ip": "192.0.2.20",
    }
    provider.metadata["probe_service"] = {"ready": True, "tcp_port": 18080}
    engine.builder.capture_router_state = mock.Mock(
        return_value={
            "external_gateway_info": {
                "enable_snat": True,
                "external_fixed_ips": [{"ip_address": "203.0.113.1"}],
            }
        }
    )
    engine.builder.ensure_group_fips = mock.Mock()
    engine._network_mtu = lambda group_id: 9000 if group_id == "target" else 1500
    return engine, provider, project, groups


@pytest.mark.parametrize(
    ("result", "message"),
    [
        (_completed(1, stderr="ssh failed"), "remote packet-size profile failed"),
        (_completed(0, stdout="\n"), "returned no JSON"),
        (_completed(0, stdout="not-json\n"), "returned invalid JSON"),
        (_completed(0, stdout="[]\n"), "JSON must be an object"),
    ],
)
def test_packet_profile_rejects_unusable_remote_evidence(
    config_factory, result, message
):
    engine, _provider, _project, _groups, _records = _engine(config_factory)
    engine.builder.ssh_endpoint = mock.Mock(return_value=result)

    with pytest.raises(SuiteError, match=message):
        engine._endpoint_json(endpoint(), "print('{}')")


@pytest.mark.parametrize(
    ("condition", "observed"),
    [
        ("setup-error", "floating-ip-association-setup-failed"),
        ("missing-fip", "floating-ip-association-unavailable"),
        ("observer-down", "provider-observer-service-unavailable"),
    ],
)
def test_fip_source_prerequisites_fail_closed_without_sending_probe(
    config_factory, condition, observed
):
    engine, provider, project, groups, _records = _engine(config_factory)
    engine.builder.capture_router_state = mock.Mock(
        return_value={"external_gateway_info": {"enable_snat": True}}
    )
    provider.metadata["probe_service"] = {
        "ready": condition != "observer-down",
        "tcp_port": 18080,
    }
    if condition == "setup-error":
        engine.builder.ensure_group_fips = mock.Mock(
            side_effect=SuiteError("floating IP create failed")
        )
    else:
        engine.builder.ensure_group_fips = mock.Mock()
    if condition == "observer-down":
        groups["target"].fips[project.label] = {
            "id": "fip-id",
            "address": "203.0.113.10",
            "port_id": project.test_port_id,
            "fixed_ip": "192.0.2.20",
        }
    engine.reporter, recorded = _recording_reporter()

    engine._run_fip_egress_source_address(_packet_size_spec())

    args, kwargs = recorded[-1]
    assert args[2] == "ERROR"
    assert kwargs["observed"] == observed
    assert kwargs["authoritative"] is False
    engine.probes.tcp.endpoint_peer_identity.assert_not_called()


@pytest.mark.parametrize(
    ("probe", "status", "observed"),
    [
        (
            ProbeResult("error", False, 4, 1, stderr="command failed"),
            "ERROR",
            "floating-ip-outbound-tcp-connection-failed",
        ),
        (
            ProbeResult("inconclusive", False, 4, 1),
            "UNVERIFIED",
            "floating-ip-outbound-tcp-connection-failed",
        ),
        (
            ProbeResult("blocked", False, 4, 1),
            "FAIL",
            "floating-ip-outbound-tcp-connection-failed",
        ),
        (
            ProbeResult("reachable", True, 4, 1, diagnostics={}),
            "UNVERIFIED",
            "translated-source-address-unavailable",
        ),
        (
            ProbeResult(
                "reachable",
                True,
                4,
                1,
                diagnostics={"observed_peer_ip": "203.0.113.99"},
            ),
            "FAIL",
            "unexpected-translated-source-address",
        ),
    ],
)
def test_fip_source_probe_outcomes_do_not_overstate_authority(
    config_factory, probe, status, observed
):
    engine, _provider, _project, _groups = _ready_fip_engine(config_factory)
    engine.probes.tcp.endpoint_peer_identity.return_value = probe
    engine.reporter, recorded = _recording_reporter()

    engine._run_fip_egress_source_address(_packet_size_spec())

    args, kwargs = recorded[-1]
    assert args[2] == status
    assert kwargs["observed"] == observed
    assert kwargs["authoritative"] is (status == "FAIL")


def test_fip_mtu_command_error_is_a_non_authoritative_error(config_factory):
    engine, _provider, _project, _groups = _ready_fip_engine(config_factory)
    engine._endpoint_json = mock.Mock(side_effect=SuiteError("remote command failed"))
    engine.reporter, recorded = _recording_reporter()

    engine._run_fip_egress_mtu(_mtu_spec())

    args, kwargs = recorded[-1]
    assert args[2] == "ERROR"
    assert kwargs["observed"] == "floating-ip-outbound-mtu-check-error"
    assert kwargs["authoritative"] is False
    assert kwargs["details"]["profile_error"] == "remote command failed"


def test_fip_fragmentation_refuses_to_run_without_passed_mtu_evidence(
    config_factory,
):
    engine, _provider, _project, _groups = _ready_fip_engine(config_factory)
    engine.reporter, _recorded = _recording_reporter(get_result=lambda _test_id: None)
    engine._endpoint_json = mock.Mock()

    with pytest.raises(SuiteError, match="requires the recorded outbound MTU result"):
        engine._run_fip_egress_fragmentation(_fragmentation_spec())

    engine._endpoint_json.assert_not_called()


@pytest.mark.parametrize(
    ("profile", "status", "observed"),
    [
        (
            {"applicable": False, "capability": "not-required"},
            "NOT_APPLICABLE",
            "fragmentation-not-required",
        ),
        (
            {"applicable": True, "capability": "not-supported"},
            "FAIL",
            "fragmented-delivery-not-observed",
        ),
        (
            {"applicable": True, "capability": "unverified"},
            "UNVERIFIED",
            "fragmentation-behaviour-unverified",
        ),
    ],
)
def test_fip_fragmentation_classification_is_preserved(
    config_factory, monkeypatch, profile, status, observed
):
    engine, _provider, _project, _groups = _ready_fip_engine(config_factory)
    mtu_result = SimpleNamespace(
        details={
            "mtu_profile": {
                "discovery_confidence": "expected-confirmed",
                "discovered_mtu": 1500,
                "path_boundary_confirmed": True,
            }
        }
    )
    engine.reporter, recorded = _recording_reporter(
        get_result=lambda _test_id: mtu_result
    )
    engine._endpoint_json = mock.Mock(side_effect=[{}, profile, {}])
    engine._network_router_backend_evidence = mock.Mock(return_value={})
    monkeypatch.setattr(
        packet_size_module,
        "classify_fragmentation_location",
        lambda raw, **_kwargs: raw,
    )

    engine._run_fip_egress_fragmentation(_fragmentation_spec())

    args, kwargs = recorded[-1]
    assert args[2] == status
    assert kwargs["observed"] == observed
    assert kwargs["authoritative"] is (status == "FAIL")


def test_fip_fragmentation_probe_error_is_not_reported_as_path_failure(
    config_factory,
):
    engine, _provider, _project, _groups = _ready_fip_engine(config_factory)
    mtu_result = SimpleNamespace(
        details={
            "mtu_profile": {
                "discovery_confidence": "expected-confirmed",
                "discovered_mtu": 1500,
                "path_boundary_confirmed": True,
            }
        }
    )
    engine.reporter, recorded = _recording_reporter(
        get_result=lambda _test_id: mtu_result
    )
    engine._endpoint_json = mock.Mock(side_effect=OSError("guest command unavailable"))

    engine._run_fip_egress_fragmentation(_fragmentation_spec())

    args, kwargs = recorded[-1]
    assert args[2] == "ERROR"
    assert kwargs["observed"] == "floating-ip-outbound-fragmentation-check-error"
    assert kwargs["authoritative"] is False
    assert kwargs["details"]["profile_error"] == "guest command unavailable"


def _cleanup_manager(config_factory, tmp_path, *, resource_type="port"):
    reporter = make_reporter(config_factory(report_dir=tmp_path / "reports"))
    tracker = ResourceTracker(reporter)
    record = tracker.add(resource_type, "resource-id", "resource-name")
    osc = mock.Mock()
    manager = CleanupManager(osc, reporter, tracker, reporter.config)
    return manager, reporter, tracker, record


def test_cleanup_unknown_presence_never_becomes_confirmed_absence(
    config_factory, tmp_path
):
    manager, reporter, _tracker, record = _cleanup_manager(config_factory, tmp_path)
    manager.osc.presence.return_value = SimpleNamespace(
        state="unknown", detail="identity endpoint unavailable"
    )
    handler = mock.Mock()

    manager._delete_record(record, handler)

    assert record.cleanup_state == "FAILED"
    assert record.delete_status == "delete-error"
    assert "identity endpoint unavailable" in str(record.cleanup_error)
    assert reporter.cleanup_summary["errors"]
    handler.assert_not_called()


def test_cleanup_quarantines_resource_blocked_by_ambiguous_cloud_operation(
    config_factory, tmp_path
):
    manager, reporter, _tracker, record = _cleanup_manager(config_factory, tmp_path)
    manager.osc.presence.return_value = SimpleNamespace(state="present", detail="")
    manager._cleanup_progress_details = mock.Mock(return_value={})
    manager.cloud_operation_coordinator = SimpleNamespace(
        cleanup_blocker=lambda _resource_id, **kwargs: (
            "migration acceptance is ambiguous"
        )
    )
    handler = mock.Mock()

    manager._delete_record(record, handler)

    assert record.cleanup_state == "QUARANTINED"
    assert record.delete_status == "leftover"
    assert reporter.cleanup_summary["leftovers"] == [
        "port:resource-id:QUARANTINED:migration acceptance is ambiguous"
    ]
    handler.assert_not_called()


def test_server_cleanup_uses_fallback_only_after_normal_delete_timeout(
    config_factory, tmp_path
):
    manager, reporter, _tracker, record = _cleanup_manager(
        config_factory, tmp_path, resource_type="server"
    )
    manager.osc.presence.return_value = SimpleNamespace(state="present", detail="")
    manager._cleanup_progress_details = mock.Mock(return_value={})
    manager._wait_absent = mock.Mock(return_value=False)
    manager._server_delete_fallback = mock.Mock(return_value=True)
    handler = mock.Mock()

    manager._delete_record(record, handler)

    handler.assert_called_once_with(record)
    manager._server_delete_fallback.assert_called_once_with(record)
    assert record.cleanup_state == "DELETED"
    assert record.delete_status == "deleted"
    assert reporter.cleanup_summary["deleted"] == 1


def test_exact_run_fixed_point_requires_two_clean_authoritative_scans(
    config_factory, tmp_path
):
    manager, _reporter, _tracker, _record = _cleanup_manager(config_factory, tmp_path)
    inventories = [
        {"visible_resources": [{"resource_type": "port", "id": "late-port"}]},
        {"visible_resources": []},
        {"visible_resources": []},
    ]

    def adopt(_run_tag, _name_prefix, *, discovery_errors, inventory_state):
        inventory_state.update(inventories.pop(0))
        return 1 if inventory_state["visible_resources"] else 0

    manager._adopt_orphans = mock.Mock(side_effect=adopt)
    manager._delete_all_types = mock.Mock()
    manager._wait_for_exact_run_inventory_settlement = mock.Mock(return_value=0.25)

    adopted, fixed_point, passes, errors = manager._final_exact_run_sweep(
        run_tag="run-tag", name_prefix="run-prefix"
    )

    assert adopted == 1
    assert fixed_point is True
    assert errors == []
    assert [item["consecutive_clean_scans"] for item in passes] == [0, 1, 2]
    assert manager._delete_all_types.call_count == 1
    assert manager._wait_for_exact_run_inventory_settlement.call_count == 2


def test_cleanup_is_incomplete_when_exact_run_inventory_never_converges(
    config_factory, tmp_path
):
    manager, reporter, _tracker, record = _cleanup_manager(config_factory, tmp_path)
    manager._adopt_orphans = mock.Mock(return_value=0)
    manager._delete_all_types = mock.Mock()
    manager._remove_local_keys = mock.Mock()
    manager._final_exact_run_sweep = mock.Mock(
        return_value=(
            0,
            False,
            [{"pass": 5, "visible_count": 0, "discovery_errors": ["API timeout"]}],
            ["API timeout"],
        )
    )
    manager._verify_placement_allocations = mock.Mock(return_value=[])
    manager._write_recovery_artifacts = mock.Mock()
    manager.osc.exists.return_value = False

    assert manager.cleanup() is False

    verification = reporter.cleanup_summary["exact_run_verification"]
    assert verification["fixed_point"] is False
    assert (
        "exact-run-inventory:verification-error:API timeout"
        in reporter.cleanup_summary["leftovers"]
    )
    assert reporter.cleanup_summary["complete"] is False
    manager._write_recovery_artifacts.assert_called_once()
    assert record.delete_status == "already-absent"


@pytest.mark.parametrize(
    ("placement_output", "expected_marker"),
    [
        ("not-json", "verification-error:invalid JSON"),
        (
            '{"allocations": {"provider-id": {"resources": {"VCPU": 1}}}}',
            "placement_allocation:resource-id:resource-name",
        ),
    ],
)
def test_placement_verification_cannot_silently_accept_bad_or_leftover_data(
    config_factory, tmp_path, placement_output, expected_marker
):
    manager, _reporter, _tracker, _record = _cleanup_manager(
        config_factory, tmp_path, resource_type="server"
    )
    manager.osc.exists.return_value = False
    manager.osc.run.return_value = _completed(0, stdout=placement_output)

    leftovers = manager._verify_placement_allocations()

    assert len(leftovers) == 1
    assert expected_marker in leftovers[0]


def _terminal_suite(*, state_save_error=None, cloud_error=None):
    suite = object.__new__(Suite)
    suite.reporter = SimpleNamespace(logger=SimpleNamespace(heartbeat=object()))
    suite.logger = mock.Mock()
    suite.checkpoint = SimpleNamespace(
        state="RUNNING",
        phase="testing",
        error=None,
        updated_at=None,
        last_activity=None,
        cleanup_state=None,
    )
    suite.state_store = mock.Mock()
    if state_save_error is not None:
        suite.state_store.save.side_effect = state_save_error
    suite.builder = mock.Mock()
    if cloud_error is not None:
        suite.builder.update_cloud_heartbeat.side_effect = cloud_error
    suite.zone_orchestrator = None
    return suite


def test_terminal_state_is_persisted_and_published_to_cloud():
    suite = _terminal_suite()

    suite.mark_terminal_state(" cleanup_incomplete ", "port remained")

    assert suite.reporter.logger.heartbeat is None
    assert suite.checkpoint.state == "CLEANUP_INCOMPLETE"
    assert suite.checkpoint.phase == "cleanup-incomplete"
    assert suite.checkpoint.error == "port remained"
    assert suite.checkpoint.last_activity == suite.checkpoint.updated_at
    suite.state_store.save.assert_called_once_with(suite.checkpoint)
    suite.builder.update_cloud_heartbeat.assert_called_once_with("cleanup_incomplete")


def test_terminal_state_survives_local_and_cloud_publication_errors():
    suite = _terminal_suite(
        state_save_error=OSError("disk full"),
        cloud_error=SuiteError("metadata update failed"),
    )

    suite.mark_terminal_state("cancelled", "operator interrupt")

    assert suite.checkpoint.state == "CANCELLED"
    assert suite.checkpoint.error == "operator interrupt"
    suite.logger.log.assert_called_once()
    assert suite.logger.log.call_args.args[1] == "WARNING"


def test_interrupted_run_stops_probes_and_records_cleanup_incomplete():
    suite = _terminal_suite()
    suite.config = SimpleNamespace(
        keep_resources=False,
        auto_cleanup_on_failure=True,
    )
    suite.resources_started = True
    suite.cleanup_manager = SimpleNamespace(cleanup=mock.Mock(return_value=False))
    suite._save_checkpoint = mock.Mock()

    assert suite.cleanup_if_required(successful_execution=False) is False

    suite.builder.stop_all_probes.assert_called_once()
    suite.cleanup_manager.cleanup.assert_called_once()
    assert suite.checkpoint.cleanup_state == "INCOMPLETE"
    assert suite._save_checkpoint.call_args_list == [
        mock.call("CLEANING", "cleanup", None),
        mock.call("CLEANUP_INCOMPLETE", "cleanup-incomplete", None),
    ]


class _MigrationHarness(MigrationValidationMixin):
    pass


def _migration_harness(config_factory):
    harness = _MigrationHarness()
    harness.config = config_factory(action="run", progress_interval=1)
    harness.logger = mock.Mock()
    harness.reporter = mock.Mock()
    return harness


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("HTTP 503 Service Unavailable", True),
        ("connection reset by peer", True),
        ("No valid host was found", False),
        ("Policy does not allow server:migrate", False),
    ],
)
def test_migration_request_retry_classification_is_narrow(message, expected):
    assert (
        MigrationValidationMixin._migration_request_error_is_transient(message)
        is expected
    )


@pytest.mark.parametrize(
    ("rows", "before", "expected", "reason"),
    [
        (None, {"migration_ids": set()}, False, "inventory unavailable"),
        (
            [{"id": "old", "status": "failed"}],
            {"migration_ids": {"old"}},
            False,
            "no provably new",
        ),
        (
            [{"id": "new", "status": "migrating"}],
            {"migration_ids": set()},
            False,
            "running or has an unknown",
        ),
        (
            [{"id": "new", "status": "completed"}],
            {"migration_ids": set()},
            False,
            "not terminal-failed",
        ),
        ([{"id": "new", "status": "failed"}], {"migration_ids": set()}, True, None),
    ],
)
def test_only_new_terminal_failed_migrations_authorize_retry(
    config_factory, rows, before, expected, reason
):
    harness = _migration_harness(config_factory)
    harness._migration_rows = mock.Mock(
        return_value=(rows, "inventory unavailable" if rows is None else None)
    )

    failed, evidence = harness._authoritative_migration_failure(endpoint(), before)

    assert failed is expected
    if reason is None:
        assert evidence == {
            "new_migration_ids": ["new"],
            "statuses": ["failed"],
            "migration_records": [{"id": "new", "status": "failed"}],
        }
    else:
        assert reason in evidence["reason"]


@pytest.mark.parametrize(
    ("method_name", "expected_outcome"),
    [
        (
            "_mark_current_migration_failed_retryable",
            CloudOperationOutcome.FAILED_RETRYABLE,
        ),
        ("_mark_current_migration_succeeded", CloudOperationOutcome.SUCCEEDED),
        ("_mark_current_migration_failed_final", CloudOperationOutcome.FAILED_FINAL),
    ],
)
def test_migration_terminal_decisions_resolve_ambiguous_journal_entry(
    config_factory, method_name, expected_outcome
):
    harness = _migration_harness(config_factory)
    coordinator = mock.Mock()
    coordinator.current_transaction_records.return_value = [
        {"operation_id": "operation-1", "outcome": "AMBIGUOUS"}
    ]
    harness.cloud_operation_coordinator = coordinator
    from ._evidence import completed_migration_evidence

    evidence = {"migration_id": "42"}
    if method_name == "_mark_current_migration_succeeded":
        evidence.update(completed_migration_evidence())

    getattr(harness, method_name)(evidence)

    call = coordinator.resolve.call_args
    assert call.args[:2] == ("operation-1", expected_outcome)
    assert {key: call.kwargs["evidence"][key] for key in evidence} == evidence
    if method_name == "_mark_current_migration_succeeded":
        assert call.kwargs["evidence"]["completion_assessment"]["verified"] is True


@pytest.mark.parametrize(
    ("detail", "auto_confirmed"),
    [
        ({"status": "VERIFY_RESIZE", "host": "compute2"}, False),
        ({"status": "ACTIVE", "host": "compute2"}, True),
    ],
)
def test_cold_migration_handoff_accepts_only_explicit_terminal_states(
    config_factory, detail, auto_confirmed
):
    harness = _migration_harness(config_factory)
    harness._json_with_transient_retry = mock.Mock(return_value=detail)

    observed, actual_auto_confirmed = harness._wait_for_migration_handoff(
        endpoint(), "compute2"
    )

    assert observed == detail
    assert actual_auto_confirmed is auto_confirmed


def test_cold_migration_error_state_is_terminal(config_factory):
    harness = _migration_harness(config_factory)
    harness._json_with_transient_retry = mock.Mock(
        return_value={
            "status": "ERROR",
            "host": "compute1",
            "fault": {"message": "migration failed"},
        }
    )

    with pytest.raises(SuiteError, match="placed .* into ERROR"):
        harness._wait_for_migration_handoff(endpoint(), "compute2")


def test_active_on_target_rejects_nova_error_instead_of_timing_out(
    config_factory,
):
    harness = _migration_harness(config_factory)
    harness._json_with_transient_retry = mock.Mock(
        return_value={
            "status": "ERROR",
            "host": "compute1",
            "fault": {"message": "migration failed"},
        }
    )

    with pytest.raises(SuiteError, match="placed .* into ERROR"):
        harness._wait_for_active_on_target(endpoint(), "compute2")
