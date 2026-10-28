from __future__ import annotations

import dataclasses
import json
import shutil
import subprocess
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from neutron_flux.coverage_ledger import materialize_missing_results
from neutron_flux.models import (
    Endpoint,
    Plan,
    ZoneCapability,
    ZoneExecutionPlan,
)
from neutron_flux.models import (
    TestSpec as FluxTestSpec,
)
from neutron_flux.replay_plan import build_replay_plan, render_replay_plan_text
from neutron_flux.report_exports import render_incident_summary
from neutron_flux.reporting import Reporter, ScopedReporter
from neutron_flux.reporting_components.dashboard_model import build_dashboard_model
from neutron_flux.resources import ResourceBuilder
from neutron_flux.results_io import render_results_text
from neutron_flux.runtime.control.ssh import SSHRuntimeMixin

from ._shared import *  # noqa: F403, F405


def _bootstrap_spec(test_id: str, display_name: str) -> FluxTestSpec:
    return FluxTestSpec(
        id=test_id,
        category="controller-bootstrap",
        operation="controller-readiness",
        family=4,
        expectation="reachable",
        expectation_reason="controller preparation is required",
        authoritative=True,
        dependencies=[],
        display_name=display_name,
        scenario="Controller readiness",
    )


def _lane_validation_spec() -> FluxTestSpec:
    return FluxTestSpec(
        id="LANE-DATAPLANE-CHECK",
        category="same-subnet",
        operation="probe",
        family=4,
        expectation="reachable",
        expectation_reason="lane dataplane validation",
        authoritative=True,
        dependencies=[],
        display_name="Validate the prepared availability-zone lane",
        scenario="Same-network connectivity",
        protocol="icmp",
    )


def _minimal_zone_plan(
    zones: list[str], *, mode: str = "per-zone"
) -> ZoneExecutionPlan:
    return ZoneExecutionPlan(
        zones=zones,
        mode=mode,
        capabilities={
            zone: ZoneCapability(
                zone, [f"{zone}-compute1", f"{zone}-compute2"], 2, None, {}
            )
            for zone in zones
        },
        explicit_selection=True,
        parallel_workers=len(zones),
    )


def _shared_bundle():
    from neutron_flux.resources import SecurityGroupBundle

    return SecurityGroupBundle(
        controller_security_group_id="controller-sg",
        endpoint_management_security_group_id="management-sg",
        data_security_group_ids={"A": "data-a", "B": "data-b"},
        management_cidr="10.254.10.0/24",
        security_group_rules={},
    )


def test_failed_controller_lanes_do_not_abort_healthy_zone(
    tmp_path, config_factory, discovery_fixture, monkeypatch
):
    from neutron_flux.multi_zone import MultiZoneOrchestrator

    zones = ["bc-van1", "bc-van2", "bc-van3"]
    config = config_factory(
        action="run",
        report_dir=tmp_path / "reports",
        availability_zones=zones,
        zone_mode="per-zone",
    )
    base_plan = Plan(
        [],
        [],
        {},
        [],
        tests=[
            _bootstrap_spec(
                "CONTROL-OBSERVATION-PORTS",
                "Configure the OpenStack probe controller",
            ),
            _bootstrap_spec("CONTROL-SSH", "Reach the probe controller over SSH"),
            _lane_validation_spec(),
        ],
    )
    reporter = Reporter(config, "sample-fixed-lane-isolation")
    orchestrator = MultiZoneOrchestrator(
        config,
        discovery_fixture,
        base_plan,
        _minimal_zone_plan(zones),
        reporter,
        _zone_launch_selection(),  # noqa: F405
    )
    monkeypatch.setattr(
        orchestrator,
        "_prepare_shared_security_groups",
        lambda: _shared_bundle(),
    )

    def prepare_lane(_self, lane):
        if lane.zone != "bc-van3":
            raise SuiteError(f"synthetic controller harness failure in {lane.zone}")
        lane.reporter.result(
            "CONTROL-OBSERVATION-PORTS",
            "controller-bootstrap",
            "PASS",
            "controller ports ready",
            expected="reachable",
            observed="reachable",
            authoritative=True,
            display_name="Configure the OpenStack probe controller",
            scenario="Controller readiness",
        )
        lane.reporter.result(
            "CONTROL-SSH",
            "controller-bootstrap",
            "PASS",
            "controller SSH ready",
            expected="reachable",
            observed="reachable",
            authoritative=True,
            display_name="Reach the probe controller over SSH",
            scenario="Controller readiness",
        )

    monkeypatch.setattr(MultiZoneOrchestrator, "_prepare_lane", prepare_lane)
    executed: list[str] = []

    def run_lane(_self, lane):
        executed.append(lane.zone)
        lane.reporter.result(
            "LANE-DATAPLANE-CHECK",
            "same-subnet",
            "PASS",
            "healthy lane executed",
            expected="reachable",
            observed="reachable",
            authoritative=True,
            display_name="Validate the prepared availability-zone lane",
            scenario="Same-network connectivity",
        )

    monkeypatch.setattr(MultiZoneOrchestrator, "_run_lane", run_lane)

    try:
        orchestrator.prepare()
        assert set(orchestrator.active_lanes) == {"bc-van3"}
        orchestrator.run()
        assert executed == ["bc-van3"]

        by_id = {item.test_id: item for item in reporter.results}
        for zone in ("bc-van1", "bc-van2"):
            prefix = f"AZ-{zone.upper()}"
            root = by_id[f"{prefix}-CONTROL-SSH"]
            assert root.status == "ERROR"
            assert root.authoritative is False
            assert root.details["tool_failure"] is True
            assert root.details["root_setup_error"] is True
            assert root.contract["type"] == "tool-execution"
            assert root.expected == "controller-bootstrap-complete"
            assert root.observed == "controller-bootstrap-error"
            assert root.display_name == "Prepare the availability-zone probe controller"
            assert by_id[f"{prefix}-LANE-DATAPLANE-CHECK"].status == (
                "BLOCKED_BY_SETUP_ERROR"
            )

        assert by_id["AZ-BC-VAN3-LANE-DATAPLANE-CHECK"].status == "PASS"
        assert all(
            not (
                item.test_id.startswith("AZ-BC-VAN3-")
                and item.status == "BLOCKED_BY_SETUP_ERROR"
            )
            for item in reporter.results
        )
        counts = Counter(item.status for item in reporter.results)
        summary = reporter._summary("SETUP FAILED", reporter.started, counts)
        assert "bc-van1" in summary
        assert "bc-van2" in summary
        assert "bc-van3" in summary
        assert "TOOL OR LANE EXECUTION ERRORS" in summary
        assert "FAILED OR ERRORED VALIDATIONS" not in summary
        assert "no cloud networking verdict was produced" in summary
    finally:
        for lane in orchestrator.lanes.values():
            shutil.rmtree(lane.builder.work_dir, ignore_errors=True)
        reporter.logger.close()


def test_execution_exception_gets_dedicated_tool_error(tmp_path, config_factory):
    from neutron_flux.models import RunCheckpoint
    from neutron_flux.multi_zone import MultiZoneOrchestrator, ZoneLane
    from neutron_flux.state import StateStore
    from neutron_flux.utils import iso_utc

    config = config_factory(action="run", report_dir=tmp_path / "reports")
    reporter = Reporter(config, "sample-fixed-execution-root")
    scoped = ScopedReporter(reporter, "az-bc-van1", availability_zone="bc-van1")
    completed_spec = dataclasses.replace(
        _lane_validation_spec(), id="NETWORK-CONTRACT-FAIL"
    )
    blocked_spec = dataclasses.replace(
        _lane_validation_spec(), id="NETWORK-CONTRACT-NOT-RUN"
    )
    plan = Plan([], [], {}, [], tests=[completed_spec, blocked_spec])
    scoped.plan = plan
    state_store = StateStore(tmp_path / "state")
    now = iso_utc()
    checkpoint = RunCheckpoint(
        run_id="lane-bc-van1",
        state="RUNNING",
        action="run",
        phase="per-zone-execution",
        current_batch=None,
        started_at=now,
        updated_at=now,
        last_activity=now,
        completed_test_ids=[],
        failed_test_ids=[],
        pending_test_ids=[item.id for item in plan.tests],
        active_group_ids=[],
        manifest_path=str(scoped.manifest_path),
        report_dir=str(scoped.run_dir),
        cleanup_state="NOT_STARTED",
        metadata={"availability_zone": "bc-van1"},
    )
    lane = ZoneLane(
        zone="bc-van1",
        scope="az-bc-van1",
        config=config,
        plan=plan,
        reporter=scoped,
        osc=mock.Mock(),
        tracker=mock.Mock(),
        cleanup_manager=mock.Mock(),
        state_store=state_store,
        checkpoint=checkpoint,
        builder=SimpleNamespace(controller_bootstrap_diagnostics=[]),
        prepared=True,
    )
    scoped.result(
        completed_spec.id,
        completed_spec.category,
        "FAIL",
        "a real contract failure was already recorded",
        expected="reachable",
        observed="unreachable",
        authoritative=True,
        display_name=completed_spec.display_name,
        scenario=completed_spec.scenario,
    )
    orchestrator = object.__new__(MultiZoneOrchestrator)
    orchestrator.zone_plan = SimpleNamespace(includes_per_zone=True)
    orchestrator.logger = reporter.logger

    try:
        orchestrator._record_lane_failure(
            lane, RuntimeError("executor crashed"), phase="per-zone-execution"
        )
        by_id = {item.test_id: item for item in reporter.results}
        assert by_id["AZ-BC-VAN1-NETWORK-CONTRACT-FAIL"].status == "FAIL"
        tool_error = by_id["AZ-BC-VAN1-LANE-EXECUTION-ERROR"]
        assert tool_error.status == "ERROR"
        assert tool_error.category == "execution-control"
        assert tool_error.details["root_lane_error"] is True
        assert by_id["AZ-BC-VAN1-NETWORK-CONTRACT-NOT-RUN"].status == (
            "BLOCKED_BY_SETUP_ERROR"
        )
    finally:
        reporter.logger.close()


def test_cleanup_adopts_orphans_once_at_parent_scope(
    tmp_path, config_factory, monkeypatch
):
    import neutron_flux.multi_zone as multi_zone

    config = config_factory(action="run", report_dir=tmp_path / "reports")
    reporter = Reporter(config, "sample-fixed-cleanup-ownership")
    lane_cleanup_calls: dict[str, mock.Mock] = {}
    lanes = {}
    for zone in ("bc-van1", "bc-van2", "bc-van3"):
        scoped = ScopedReporter(reporter, f"az-{zone}", availability_zone=zone)
        cleanup = mock.Mock()
        cleanup.cleanup.return_value = True
        lane_cleanup_calls[zone] = cleanup.cleanup
        work_dir = tmp_path / f"work-{zone}"
        work_dir.mkdir()
        lanes[zone] = SimpleNamespace(
            cleanup_manager=cleanup,
            reporter=scoped,
            builder=SimpleNamespace(work_dir=work_dir),
        )

    shared_reporter = ScopedReporter(
        reporter, "shared-security", availability_zone=None
    )
    shared_cleanup = mock.Mock()
    shared_cleanup.cleanup.return_value = True
    shared_work_dir = tmp_path / "work-shared"
    shared_work_dir.mkdir()
    final_calls: list[dict] = []

    class FinalCleanup:
        def __init__(self, _osc, parent, _tracker, _config, **_kwargs):
            self.parent = parent

        def cleanup(self, **kwargs):
            final_calls.append(dict(kwargs))
            self.parent.cleanup_summary.update(
                {
                    "attempted": True,
                    "complete": True,
                    "deleted": 0,
                    "adopted_orphans": 0,
                    "errors": [],
                    "leftovers": [],
                }
            )
            return True

    monkeypatch.setattr(multi_zone, "CleanupManager", FinalCleanup)
    orchestrator = object.__new__(multi_zone.MultiZoneOrchestrator)
    orchestrator.config = config
    orchestrator.reporter = reporter
    orchestrator.logger = reporter.logger
    orchestrator.zone_plan = SimpleNamespace(parallel_workers=3)
    orchestrator.lanes = lanes
    orchestrator.shared_security_cleanup = shared_cleanup
    orchestrator.shared_security_reporter = shared_reporter
    orchestrator.shared_security_builder = SimpleNamespace(work_dir=shared_work_dir)
    orchestrator.cloud_operation_coordinator = mock.Mock(lock=mock.Mock())
    orchestrator.lifecycle_lock = mock.Mock()

    try:
        assert orchestrator.cleanup_all() is True
        for call in lane_cleanup_calls.values():
            call.assert_called_once_with(
                adopt_discovered=False,
                clear_recovery_artifacts=False,
                completion_message=None,
            )
        shared_cleanup.cleanup.assert_called_once_with(
            adopt_discovered=False,
            clear_recovery_artifacts=False,
            completion_message=None,
        )
        assert len(final_calls) == 1
        assert final_calls[0]["adopt_discovered"] is True
        assert "run_tag" in final_calls[0]
        assert reporter.cleanup_summary["ownership_model"] == (
            "tracked lane cleanup followed by one parent exact-run adoption sweep"
        )
        assert reporter.cleanup_summary["zones"]["bc-van1"]["adopted_orphans"] == 0
    finally:
        reporter.logger.close()


def _legacy_setup_result(
    test_id: str,
    status: str,
    *,
    zone: str,
    category: str = "controller-bootstrap",
    display_name: str = "Reach the probe controller over SSH",
    scenario: str = "Controller readiness",
) -> dict:
    return {
        "test_id": test_id,
        "display_name": display_name,
        "category": category,
        "scenario": scenario,
        "status": status,
        "family": 4,
        "source": None,
        "destination": f"{zone}/controller",
        "message": (
            "controller ready"
            if status == "PASS"
            else "Not run because controller preparation failed"
        ),
        "details": {
            "availability_zone": zone,
            "execution_scope": f"az-{zone}",
            "blocked_by_setup_error": status == "BLOCKED_BY_SETUP_ERROR",
            "tool_failure": status == "BLOCKED_BY_SETUP_ERROR",
            "failure_phase": "controller-bootstrap",
            "operation": "controller-readiness",
        },
        "expected": "reachable",
        "observed": "reachable" if status == "PASS" else "not-run",
        "authoritative": status == "PASS",
    }


def _legacy_setup_abort_payload() -> dict:
    results = [
        _legacy_setup_result(
            "AZ-BC-VAN3-CONTROL-OBSERVATION-PORTS",
            "PASS",
            zone="bc-van3",
            display_name="Configure the OpenStack probe controller",
        ),
        _legacy_setup_result("AZ-BC-VAN3-CONTROL-SSH", "PASS", zone="bc-van3"),
    ]
    for zone in ("bc-van1", "bc-van2"):
        results.extend(
            [
                _legacy_setup_result(
                    f"AZ-{zone.upper()}-CONTROL-OBSERVATION-PORTS",
                    "BLOCKED_BY_SETUP_ERROR",
                    zone=zone,
                    display_name="Configure the OpenStack probe controller",
                ),
                _legacy_setup_result(
                    f"AZ-{zone.upper()}-CONTROL-SSH",
                    "BLOCKED_BY_SETUP_ERROR",
                    zone=zone,
                ),
            ]
        )
    for zone in ("bc-van1", "bc-van2", "bc-van3"):
        for suffix, category, title in (
            ("MTU-CHECK", "mtu", "Effective MTU validation"),
            (
                "ROUTER-LIFECYCLE",
                "router-interface-lifecycle",
                "Router interface lifecycle",
            ),
            ("CONNECTIVITY", "same-subnet", "Same-network connectivity"),
        ):
            results.append(
                _legacy_setup_result(
                    f"AZ-{zone.upper()}-{suffix}",
                    "BLOCKED_BY_SETUP_ERROR",
                    zone=zone,
                    category=category,
                    display_name=title,
                    scenario=title,
                )
            )
    return {
        "schema_version": 1,
        "tool": "neutron-flux",
        "tool_version": "0.1.0 (prerelease)",
        "run": {
            "run_id": "legacy-sample-setup-abort",
            "action": "run",
            "started_at": "2026-07-28T00:00:00+00:00",
            "finished_at": "2026-07-28T00:05:00+00:00",
            "final_status": "ERROR",
        },
        "configuration": {
            "image": "debian-13",
            "flavor": "x1.nano",
            "storage": "host",
            "availability_zones": ["bc-van1", "bc-van2", "bc-van3"],
            "zone_mode": "per-zone",
            "external_networks": ["Public3"],
        },
        "summary": {"counts": {}, "total_results": len(results)},
        "results": results,
        "cleanup": {"attempted": True, "complete": True},
        "events": [],
        "setup_failures": [
            {"message": "bc-van1 controller setup failed"},
            {"message": "bc-van2 controller setup failed"},
        ],
        "error": "controller setup failed",
    }


def test_legacy_setup_abort_has_no_fake_network_findings_and_two_replays():
    payload = _legacy_setup_abort_payload()
    replay = build_replay_plan(payload)
    assert [case["target_result_id"] for case in replay["cases"]] == [
        "AZ-BC-VAN1-CONTROL-SSH",
        "AZ-BC-VAN2-CONTROL-SSH",
    ]
    assert {case["healthy_control_result_id"] for case in replay["cases"]} == {
        "AZ-BC-VAN3-CONTROL-SSH"
    }
    assert {case["replay_kind"] for case in replay["cases"]} == {"controller-bootstrap"}
    assert {case["contract_type"] for case in replay["cases"]} == {
        "controller-bootstrap"
    }
    assert "controller-bootstrap blockers" in replay["selection_policy"]["scope"]
    replay_text = render_replay_plan_text(replay)
    assert "Setup target: controller bootstrap / IPv4" in replay_text
    assert "Contract: connectivity" not in replay_text

    payload["replay_plan"] = replay
    dashboard = build_dashboard_model(payload)
    finding_text = json.dumps(dashboard.get("findings") or [], sort_keys=True).lower()
    assert "mtu" not in finding_text
    assert "router" not in finding_text
    assert "connectivity" not in finding_text
    assert dashboard["correlated_fault_domains"] == []
    command = dashboard["command_centre"]
    assert command["evidence"]["complete"] == 2
    assert command["evidence"]["required"] == len(payload["results"])
    assert command["evidence"]["percentage"] == (200.0 / len(payload["results"]))
    assert len(command["top_incidents"]) == 2
    assert all(item.get("setup_failure") for item in command["top_incidents"])
    assert "authority" not in dashboard["contracts"]

    incident = render_incident_summary(payload)
    text_report = render_results_text(payload)
    assert "PERFORMANCE SUMMARY" not in text_report
    assert "Neutron Flux setup/tool failures blocked coverage" in text_report
    assert "No failures, errors, unverified results" not in text_report
    assert "Effective MTU differs" not in incident
    assert "Router-interface lifecycle did not complete" not in incident
    assert "Connectivity did not match" not in incident
    assert (
        "No executed network contract produced a failed, errored, or unverified verdict"
        in incident
    )
    assert "bc-van1" in incident and "bc-van2" in incident and "bc-van3" in incident


def test_ssh_attempt_is_capped_by_remaining_deadline(monkeypatch):
    import neutron_flux.runtime.control.ssh as ssh_module

    clock = {"value": 0.0}
    attempt_timeouts: list[float] = []

    def monotonic():
        return clock["value"]

    def run_timeout(_command, **kwargs):
        timeout = float(kwargs["timeout"])
        attempt_timeouts.append(timeout)
        clock["value"] += timeout
        raise subprocess.TimeoutExpired("ssh", timeout)

    def sleep(seconds):
        clock["value"] += float(seconds)

    monkeypatch.setattr(ssh_module.time, "monotonic", monotonic)
    monkeypatch.setattr(ssh_module.time, "sleep", sleep)
    monkeypatch.setattr(ssh_module, "run_cancellable", run_timeout)

    builder = object.__new__(ResourceBuilder)
    builder.config = SimpleNamespace(
        ssh_timeout=30,
        resource_timeout=180,
        progress_interval=5,
    )
    builder.key_path = Path("/tmp/nonexistent-key")
    builder.ssh_user = "debian"
    builder.logger = mock.Mock()
    builder.reporter = mock.Mock()
    builder.reporter.event = mock.Mock()

    assert builder._wait_for_ssh("192.0.2.10", proxy=False, timeout=3) is False
    assert attempt_timeouts == [3.0]
    assert max(attempt_timeouts) <= 3.0
    messages = [str(call.args[0]) for call in builder.logger.log.call_args_list]
    assert not any("4s/3s" in message or "5s/3s" in message for message in messages)
    timeout_event = builder.reporter.event.call_args_list[-1]
    assert timeout_event.args[0] == "ssh-readiness-timeout"
    assert timeout_event.kwargs["readiness_elapsed_seconds"] == 3.0


def test_direct_transport_distinguishes_tcp_without_ssh_banner(monkeypatch):
    import neutron_flux.runtime.control.ssh as ssh_module

    class ConnectedSocket:
        def __enter__(self):
            return self

        def __exit__(self, _type, _value, _traceback):
            return False

        def settimeout(self, _timeout):
            return None

        def recv(self, _size):
            raise TimeoutError("banner timeout")

    monkeypatch.setattr(
        ssh_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: ConnectedSocket(),
    )
    runtime = object.__new__(SSHRuntimeMixin)
    evidence = runtime._probe_direct_ssh_transport("192.0.2.20", timeout=2.0)

    assert evidence["tcp_connected"] is True
    assert evidence["ssh_banner_observed"] is False
    assert evidence["classification"] == "tcp-connected-no-ssh-banner"
    assert "no SSH banner" in evidence["error"]


def test_bastion_uses_explicit_selected_external_network(
    config_factory, discovery_fixture
):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(external_networks=["Public3"])
    builder.discovery = discovery_fixture
    builder.controller_probe_ports = []

    network, subnet = builder._selected_bastion_external_subnet()

    assert network.name == "Public3"
    assert subnet.name == "public3-ipv4"
    assert subnet.network_id == network.id


def test_bastion_selects_different_eligible_host_when_available():
    builder = object.__new__(ResourceBuilder)
    builder.controller = Endpoint(
        label="controller",
        server_id="controller-id",
        server_name="controller",
        management_port_id="management-port",
        management_ip="10.254.0.10",
        test_port_id=None,
        test_mac=None,
        fixed_ips={},
        host="compute1",
        availability_zone="bc-van1",
        volume_id=None,
    )
    builder.reporter = mock.Mock()
    builder.compute_host_inventory = mock.Mock(
        return_value={
            "compute1": SimpleNamespace(
                host="compute1", eligible=True, availability_zone="bc-van1"
            ),
            "compute2": SimpleNamespace(
                host="compute2", eligible=True, availability_zone="bc-van1"
            ),
            "compute3": SimpleNamespace(
                host="compute3", eligible=True, availability_zone="bc-van2"
            ),
        }
    )

    host, zone = builder._select_bastion_target_host()

    assert (host, zone) == ("compute2", "bc-van1")
    event = builder.reporter.event.call_args
    assert event.args[0] == "management-bastion-target-host-selected"
    assert event.kwargs["controller_host"] == "compute1"
    assert event.kwargs["bastion_target_host"] == "compute2"


def test_controller_composites_do_not_hold_global_cloud_operation_lock():
    assert not hasattr(ResourceBuilder._create_controller, "__wrapped__")
    assert not hasattr(ResourceBuilder._create_management_bastion, "__wrapped__")
    assert hasattr(ResourceBuilder._create_management_network, "__wrapped__")
    assert hasattr(ResourceBuilder._create_bastion_access_topology, "__wrapped__")
    assert hasattr(ResourceBuilder._create_bastion_floating_ip, "__wrapped__")
    assert hasattr(ResourceBuilder._create_port, "__wrapped__")
    assert hasattr(ResourceBuilder._create_server, "__wrapped__")


def test_never_marks_nonexecuted_contracts_authoritative(tmp_path, config_factory):
    spec = _lane_validation_spec()
    plan = Plan([], [], {}, [], tests=[spec])
    fake = SimpleNamespace(
        action="run",
        interrupted=False,
        cancellation_reason=None,
        setup_failed=True,
        error="synthetic setup failure",
        recorded=[],
        has_result=lambda _test_id: False,
    )
    fake.result = lambda *args, **kwargs: fake.recorded.append((args, kwargs))

    assert materialize_missing_results(fake, plan) == 1
    assert fake.recorded[0][1]["authoritative"] is False

    config = config_factory(action="run", report_dir=tmp_path / "reports")
    reporter = Reporter(config, "sample-fixed-authority-guard")
    try:
        result = reporter.result(
            "BLOCKED",
            "same-subnet",
            "BLOCKED_BY_SETUP_ERROR",
            "setup did not complete",
            expected="reachable",
            observed="not-run",
            authoritative=True,
        )
        assert result.authoritative is False
        assert result.contract["authority"]["authoritative"] is False
        assert result.contract["verdict"]["state"] == "BLOCKED"
    finally:
        reporter.logger.close()


def test_reports_scoped_cleanup_adoption_accounting_as_tool_anomaly():
    payload = _legacy_setup_abort_payload()
    payload["cleanup"] = {
        "attempted": True,
        "complete": True,
        "deleted": 36,
        "adopted_orphans": 0,
        "errors": [],
        "leftovers": [],
        "zones": {
            "bc-van1": {"adopted_orphans": 7},
            "bc-van2": {"adopted_orphans": 7},
            "bc-van3": {"adopted_orphans": 8},
            "shared-security": {"adopted_orphans": 0},
        },
    }

    incident = render_incident_summary(payload)
    text_report = render_results_text(payload)

    assert "22 adopted orphan records" in incident
    assert "historical tool cleanup evidence" in incident
    assert "22 adopted orphan records" in text_report
    assert "tool cleanup ownership/accounting anomaly" in text_report


def test_tool_lane_error_is_not_reported_as_cloud_network_finding():
    tool_error = {
        "test_id": "AZ-BC-VAN1-LANE-EXECUTION-ERROR",
        "display_name": "Complete the availability-zone execution lane",
        "category": "execution-control",
        "scenario": "Availability-zone execution",
        "status": "ERROR",
        "family": None,
        "source": None,
        "destination": None,
        "message": "Neutron Flux stopped the bc-van1 execution lane",
        "details": {
            "availability_zone": "bc-van1",
            "execution_scope": "az-bc-van1",
            "tool_failure": True,
            "root_lane_error": True,
            "failure_phase": "per-zone-execution",
        },
        "expected": "execution-complete",
        "observed": "execution-error",
        "authoritative": False,
    }
    blocked = _legacy_setup_result(
        "AZ-BC-VAN1-MTU-CHECK",
        "BLOCKED_BY_SETUP_ERROR",
        zone="bc-van1",
        category="mtu",
        display_name="Effective MTU validation",
        scenario="Effective MTU validation",
    )
    payload = _legacy_setup_abort_payload()
    payload["results"] = [tool_error, blocked]
    payload["summary"] = {
        "counts": {"ERROR": 1, "BLOCKED_BY_SETUP_ERROR": 1},
        "total_results": 2,
    }
    payload["setup_failures"] = [
        {"message": "Execution failed in availability zone bc-van1"}
    ]

    incident = render_incident_summary(payload)
    text_report = render_results_text(payload)
    dashboard = build_dashboard_model(payload)

    assert "No executed network contract produced a failed" in incident
    conditions = incident.split("## Conditions requiring review", 1)[1].split(
        "## Coverage blocked", 1
    )[0]
    assert "Complete the availability-zone execution lane" not in conditions
    needs_attention = text_report.split("NEEDS ATTENTION", 1)[1].split(
        "BLOCKED COVERAGE", 1
    )[0]
    assert "Complete the availability-zone execution lane" not in needs_attention
    assert len(dashboard["findings"]) == 1
    tool_finding = dashboard["findings"][0]
    assert tool_finding["root_key"] == "neutron-flux-execution"
    assert tool_finding["path_ids"] == []
    assert "Neutron Flux" in tool_finding["title"]
    assert any(
        "Tool/setup failures did not create additional cloud-network findings" in line
        for line in dashboard["summary"]["narrative"]
    )


def test_ssh_failure_snapshot_includes_console_and_security_group_rules():
    runtime = object.__new__(SSHRuntimeMixin)
    runtime.config = SimpleNamespace(resource_timeout=30)
    runtime.controller = Endpoint(
        label="controller",
        server_id="server-id",
        server_name="controller",
        management_port_id="management-port-id",
        management_ip="10.254.0.10",
        test_port_id="provider-port-id",
        test_mac="fa:16:3e:00:00:01",
        fixed_ips={4: "172.20.5.10"},
        host="compute1",
        availability_zone="bc-van1",
        volume_id=None,
    )
    runtime.bastion = None
    runtime.controller_probe_ports = []

    class FakeOpenStack:
        def json(self, *args, **_kwargs):
            if args[:2] == ("server", "show"):
                return {
                    "status": "ACTIVE",
                    "OS-EXT-SRV-ATTR:host": "compute1",
                    "OS-EXT-AZ:availability_zone": "bc-van1",
                    "addresses": {"Public3": ["172.20.5.10"]},
                }
            if args[:2] == ("port", "show"):
                return {
                    "status": "ACTIVE",
                    "device_id": "server-id",
                    "device_owner": "compute:nova",
                    "binding:host_id": "compute1",
                    "binding:vif_type": "ovs",
                    "fixed_ips": [{"ip_address": "172.20.5.10"}],
                    "security_group_ids": ["controller-sg"],
                }
            if args[:3] == ("security", "group", "show"):
                return {
                    "name": "controller-sg",
                    "security_group_rules": [
                        {
                            "protocol": "tcp",
                            "port_range_min": 22,
                            "port_range_max": 22,
                            "remote_ip_prefix": "0.0.0.0/0",
                        }
                    ],
                }
            raise AssertionError(args)

        def run(self, *args, **_kwargs):
            assert args[:3] == ("console", "log", "show")
            return subprocess.CompletedProcess(
                ["openstack", *args],
                0,
                stdout="cloud-init finished\nsshd started\n",
                stderr="",
            )

    runtime.osc = FakeOpenStack()

    snapshot = runtime._ssh_resource_snapshot("172.20.5.10", proxy=False)

    assert snapshot["server"]["status"] == "ACTIVE"
    assert snapshot["console_log"]["available"] is True
    assert "sshd started" in snapshot["console_log"]["tail"]
    assert snapshot["ports"][0]["binding_host"] == "compute1"
    assert snapshot["security_groups"][0]["name"] == "controller-sg"
    assert snapshot["security_groups"][0]["rules"][0]["port_range_min"] == 22
