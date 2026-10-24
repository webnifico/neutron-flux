from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.cleanup import CleanupManager
from neutron_flux.errors import SuiteError
from neutron_flux.junit_report import build_junit
from neutron_flux.models import RunCheckpoint
from neutron_flux.openstack import OpenStack
from neutron_flux.reporting import Reporter, ResourceTracker
from neutron_flux.results_io import load_results
from neutron_flux.state import StateStore
from neutron_flux.utils import iso_utc

from ._shared import completed


def _checkpoint(run_id: str, report_dir: Path, *, complete: bool) -> RunCheckpoint:
    return RunCheckpoint(
        run_id=run_id,
        state="COMPLETED" if complete else "RUNNING",
        action="run",
        phase="finished" if complete else "tests",
        current_batch=None,
        started_at=iso_utc(),
        updated_at=iso_utc(),
        last_activity=iso_utc(),
        completed_test_ids=[],
        failed_test_ids=[],
        pending_test_ids=[] if complete else ["T1"],
        active_group_ids=[],
        manifest_path=str(report_dir / "manifest.jsonl"),
        report_dir=str(report_dir),
        cleanup_state="COMPLETE" if complete else "INCOMPLETE",
    )


def _offline_payload(*, status: str = "PASS") -> dict:
    return {
        "schema_version": 1,
        "run": {
            "run_id": "offline-run",
            "started_at": "2026-07-22T00:00:00Z",
            "final_status": status,
        },
        "summary": {"counts": {status: 1}, "total_results": 1},
        "results": [
            {
                "test_id": "T1",
                "category": "connectivity",
                "status": status,
                "duration_ms": 1,
                "details": {},
            }
        ],
        "cleanup": {
            "attempted": True,
            "complete": True,
            "deleted": 0,
            "leftovers": [],
            "errors": [],
        },
    }


def test_state_store_rejects_symlinked_checkpoint_and_lock(tmp_path):
    store = StateStore(tmp_path / "reports")
    run_dir = store.run_dir("run")
    outside = tmp_path / "outside"
    outside.write_text("outside", encoding="utf-8")
    (run_dir / "state.json").symlink_to(outside)
    with pytest.raises(SuiteError, match="Run checkpoint must not be a symbolic link"):
        store.load("run")

    (run_dir / "state.json").unlink()
    (run_dir / "run.lock").symlink_to(outside)
    with pytest.raises(SuiteError, match="Run lock must not be a symbolic link"):
        with store.lock("run"):
            pass


def test_reporter_rejects_symlinked_managed_artifact(config_factory, tmp_path):
    reports = tmp_path / "reports"
    run_dir = reports / "runs" / "run"
    run_dir.mkdir(parents=True)
    outside = tmp_path / "outside-report"
    outside.write_text("safe", encoding="utf-8")
    (run_dir / "report.txt").symlink_to(outside)
    with pytest.raises(SuiteError, match="Managed run artifact"):
        Reporter(config_factory(report_dir=reports), "run")
    assert outside.read_text(encoding="utf-8") == "safe"


def test_offline_loader_normalizes_statuses_before_junit(tmp_path):
    source = tmp_path / "results.json"
    source.write_text(json.dumps(_offline_payload(status="pass")), encoding="utf-8")
    payload = load_results(source)
    assert payload["run"]["final_status"] == "PASS"
    assert payload["results"][0]["status"] == "PASS"
    assert payload["summary"]["counts"] == {"PASS": 1}
    xml = build_junit(payload)
    assert 'failures="0"' in xml
    assert 'errors="0"' in xml


def test_offline_loader_rejects_nonfinite_json_and_bad_summary(tmp_path):
    nonfinite = tmp_path / "nonfinite.json"
    nonfinite.write_text(
        json.dumps(_offline_payload()).replace(
            '"duration_ms": 1', '"duration_ms": NaN'
        ),
        encoding="utf-8",
    )
    with pytest.raises(SuiteError, match="non-standard JSON numeric constant"):
        load_results(nonfinite)

    mismatched = tmp_path / "mismatched.json"
    payload = _offline_payload()
    payload["summary"]["counts"] = {"FAIL": 1}
    mismatched.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SuiteError, match="does not match the result rows"):
        load_results(mismatched)


def test_offline_loader_rejects_missing_identity_bad_duration_and_cleanup(tmp_path):
    source = tmp_path / "results.json"
    payload = _offline_payload()
    payload["results"][0]["test_id"] = ""
    source.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SuiteError, match="has no test_id"):
        load_results(source)

    payload = _offline_payload()
    payload["results"][0]["duration_ms"] = -1
    source.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SuiteError, match="finite non-negative number"):
        load_results(source)

    payload = _offline_payload()
    payload["cleanup"]["leftovers"] = "server-one"
    source.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SuiteError, match="cleanup.leftovers must be an array"):
        load_results(source)


def test_absent_placement_allocation_is_not_a_cleanup_leftover(
    config_factory, tmp_path
):
    config = config_factory(report_dir=tmp_path / "reports", action="run")
    reporter = Reporter(config, "placement-absent")
    tracker = ResourceTracker(reporter)
    tracker.add("server", "server-1", "server-one")
    osc = OpenStack(reporter.logger)
    osc.exists = mock.Mock(return_value=False)
    osc.run = mock.Mock(
        return_value=completed(
            1,
            stderr="No Resource Provider Allocation found for server-1",
        )
    )
    manager = CleanupManager(osc, reporter, tracker, config)
    assert manager._verify_placement_allocations() == []
    reporter.logger.close()


def test_live_continuity_malformed_numeric_evidence_is_unverified_not_exception(
    config_factory,
):
    from neutron_flux.resources import ResourceBuilder

    from ._shared import endpoint

    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder.ssh_endpoint = mock.Mock(
        return_value=completed(
            stdout=json.dumps(
                {
                    "duration_s": "not-a-number",
                    "icmp": [
                        {"t": "bad", "ok": "false"},
                        "not-an-object",
                    ],
                    "tcp": [],
                    "udp": {"response": "bad"},
                }
            )
        )
    )
    state = {
        "available": True,
        "stop_path": "/tmp/stop",
        "result_path": "/tmp/result",
        "error_path": "/tmp/error",
        "pid": "123",
        "started_at": "bad",
    }
    result = builder._stop_live_continuity(endpoint(), state)
    assert result["available"] is True
    assert result["health"] == "warning"
    assert result["full_migration_window"] is False
    assert result["icmp"]["samples"] == 1
    assert any("invalid" in item or "malformed" in item for item in result["warnings"])


def test_recovery_artifacts_reject_symlink_redirect(config_factory, tmp_path):
    config = config_factory(report_dir=tmp_path / "reports", action="run")
    reporter = Reporter(config, "recovery-symlink")
    tracker = ResourceTracker(reporter)
    tracker.add("server", "server-1", "server-one")
    outside = tmp_path / "outside-recovery"
    outside.write_text("safe", encoding="utf-8")
    (reporter.run_dir / "recovery.md").symlink_to(outside)
    manager = CleanupManager(mock.Mock(), reporter, tracker, config)
    with pytest.raises(
        SuiteError, match="recovery artifact must not be a symbolic link"
    ):
        manager._write_recovery_artifacts()
    assert outside.read_text(encoding="utf-8") == "safe"
    reporter.logger.close()


def test_manifest_cannot_delete_arbitrary_local_file(config_factory, tmp_path):
    config = config_factory(report_dir=tmp_path / "reports", action="run")
    reporter = Reporter(config, "local-key-guard")
    tracker = ResourceTracker(reporter)
    victim = tmp_path / "important.txt"
    victim.write_text("keep", encoding="utf-8")
    tracker.add(
        "keypair",
        "key-one",
        "key-one",
        private_key_path=str(victim),
    )
    manager = CleanupManager(mock.Mock(), reporter, tracker, config)
    with pytest.raises(SuiteError, match="outside the Flux run directory"):
        manager._remove_local_keys()
    assert victim.read_text(encoding="utf-8") == "keep"
    reporter.logger.close()


def test_offline_report_refuses_symlinked_output_artifact(tmp_path):
    from neutron_flux.offline_reports import regenerate

    source_dir = tmp_path / "source"
    source_dir.mkdir()
    source = source_dir / "results.json"
    source.write_text(json.dumps(_offline_payload()), encoding="utf-8")
    output = tmp_path / "output"
    output.mkdir()
    victim = tmp_path / "victim"
    victim.write_text("safe", encoding="utf-8")
    (output / "report.txt").symlink_to(victim)
    with pytest.raises(SuiteError, match="Output artifact must not be a symbolic link"):
        regenerate(source, destination=output)
    assert victim.read_text(encoding="utf-8") == "safe"


def _runtime_group(group_id: str, zone: str = "az1"):
    from neutron_flux.models import PlannedGroup, RuntimeGroup

    plan = PlannedGroup(
        id=group_id,
        kind="provider",
        label=group_id,
        network_id="network",
        network_name="Provider",
        subnet_ids=["subnet"],
        families=[4],
        metadata={"availability_zone": zone},
    )
    return RuntimeGroup(
        plan=plan,
        network_id="network",
        network_name="Provider",
        subnet_ids=["subnet"],
        router_id=None,
        endpoints=[],
        source_nat_enabled=None,
        fips={},
    )


def test_adaptive_release_keeps_incomplete_group_checkpointed():
    from neutron_flux.executor import AdaptiveExecutor

    runtime = _runtime_group("group-one")
    refreshes: list[list[str]] = []
    executor = object.__new__(AdaptiveExecutor)
    executor.active = {"group-one": runtime}
    executor.builder = SimpleNamespace(
        runtime_groups=[runtime],
        stop_group_probes=mock.Mock(),
    )
    executor.cleanup_manager = SimpleNamespace(cleanup_group=lambda _group_id: False)
    executor.logger = mock.Mock()
    executor.checkpoint = SimpleNamespace(metadata={})
    executor._refresh_checkpoint = lambda: refreshes.append(list(executor.active))

    with pytest.raises(SuiteError, match="later endpoint batches were not started"):
        executor._release("group-one")

    assert executor.active == {"group-one": runtime}
    assert executor.builder.runtime_groups == [runtime]
    assert executor.checkpoint.metadata["unresolved_group_ids"] == ["group-one"]
    assert refreshes == [["group-one"]]


def test_adaptive_release_all_attempts_every_group_before_raising():
    from neutron_flux.executor import AdaptiveExecutor

    first = _runtime_group("group-one")
    second = _runtime_group("group-two")
    attempts: list[str] = []
    executor = object.__new__(AdaptiveExecutor)
    executor.active = {"group-one": first, "group-two": second}
    executor.builder = SimpleNamespace(
        runtime_groups=[first, second],
        stop_group_probes=lambda _group_id: None,
    )

    def cleanup_group(group_id: str) -> bool:
        attempts.append(group_id)
        return group_id == "group-two"

    executor.cleanup_manager = SimpleNamespace(cleanup_group=cleanup_group)
    executor.logger = mock.Mock()
    executor.checkpoint = SimpleNamespace(metadata={})
    executor._refresh_checkpoint = lambda: None

    with pytest.raises(SuiteError, match="One or more endpoint groups"):
        executor._release_all()

    assert attempts == ["group-one", "group-two"]
    assert list(executor.active) == ["group-one"]
    assert executor.builder.runtime_groups == [first]


def test_partial_failed_build_cleanup_stops_later_batches():
    from neutron_flux.executor import AdaptiveExecutor

    executor = object.__new__(AdaptiveExecutor)
    executor.active = {}
    executor.builder = SimpleNamespace(runtime_groups=[])
    executor.cleanup_manager = SimpleNamespace(cleanup_group=lambda _group_id: False)
    executor.checkpoint = SimpleNamespace(metadata={})
    executor._refresh_checkpoint = lambda: None

    with pytest.raises(SuiteError, match="Partial endpoint group"):
        executor._cleanup_failed_build("partial-group")

    assert executor.checkpoint.metadata["unresolved_group_ids"] == ["partial-group"]


def test_cross_zone_cleanup_attempts_all_and_preserves_unresolved_lane_state():
    from neutron_flux.models import RunCheckpoint
    from neutron_flux.multi_zone import CrossZoneExecutor, zone_group_id

    zone = "az1"
    first_id = zone_group_id("group-one", zone)
    second_id = zone_group_id("group-two", zone)
    first = _runtime_group(first_id, zone)
    second = _runtime_group(second_id, zone)
    foreign = _runtime_group(zone_group_id("group-one", "az2"), "az2")
    attempts: list[str] = []
    saved: list[list[str]] = []

    def cleanup_group(group_id: str) -> bool:
        attempts.append(group_id)
        return group_id == second_id

    now = iso_utc()
    checkpoint = RunCheckpoint(
        run_id="run-az1",
        state="RUNNING",
        action="run",
        phase="cross-zone",
        current_batch=None,
        started_at=now,
        updated_at=now,
        last_activity=now,
        completed_test_ids=[],
        failed_test_ids=[],
        pending_test_ids=[],
        active_group_ids=[],
        manifest_path="manifest.jsonl",
        report_dir="reports",
        cleanup_state="NOT_STARTED",
    )
    lane = SimpleNamespace(
        zone=zone,
        plan=SimpleNamespace(tests=[]),
        reporter=SimpleNamespace(has_result=lambda _test_id: False, results=[]),
        builder=SimpleNamespace(
            runtime_groups=[first, second, foreign],
            stop_group_probes=lambda _group_id: None,
        ),
        cleanup_manager=SimpleNamespace(cleanup_group=cleanup_group),
        checkpoint=checkpoint,
        state_store=SimpleNamespace(
            save=lambda item: saved.append(list(item.active_group_ids))
        ),
    )
    executor = object.__new__(CrossZoneExecutor)
    executor.lanes = {zone: lane}
    executor.workers = 1
    executor.logger = mock.Mock()

    failures = executor._cleanup_batch(("group-one", "group-two"))

    assert attempts == [first_id, second_id]
    assert failures == [f"{zone}:{first_id} (cleanup incomplete)"]
    assert lane.builder.runtime_groups == [first]
    assert checkpoint.active_group_ids == [first_id]
    assert saved[-1] == [first_id]


def test_successful_adaptive_release_refreshes_checkpoint():
    from neutron_flux.executor import AdaptiveExecutor

    runtime = _runtime_group("group-one")
    refreshes: list[list[str]] = []
    executor = object.__new__(AdaptiveExecutor)
    executor.active = {"group-one": runtime}
    executor.builder = SimpleNamespace(
        runtime_groups=[runtime],
        stop_group_probes=lambda _group_id: None,
    )
    executor.cleanup_manager = SimpleNamespace(cleanup_group=lambda _group_id: True)
    executor._refresh_checkpoint = lambda: refreshes.append(list(executor.active))

    executor._release("group-one")

    assert refreshes == [[]]
    assert executor.active == {}


def test_release_all_final_checkpoint_excludes_groups_cleaned_after_failure():
    from neutron_flux.executor import AdaptiveExecutor

    first = _runtime_group("group-one")
    second = _runtime_group("group-two")
    refreshes: list[list[str]] = []
    executor = object.__new__(AdaptiveExecutor)
    executor.active = {"group-one": first, "group-two": second}
    executor.builder = SimpleNamespace(
        runtime_groups=[first, second],
        stop_group_probes=lambda _group_id: None,
    )
    executor.cleanup_manager = SimpleNamespace(
        cleanup_group=lambda group_id: group_id == "group-two"
    )
    executor.logger = mock.Mock()
    executor.checkpoint = SimpleNamespace(metadata={})
    executor._refresh_checkpoint = lambda: refreshes.append(list(executor.active))

    with pytest.raises(SuiteError):
        executor._release_all()

    assert refreshes[-1] == ["group-one"]


def test_manifest_append_refuses_symlink_replacement(config_factory, tmp_path):
    config = config_factory(report_dir=tmp_path / "reports", action="run")
    reporter = Reporter(config, "manifest-swap")
    victim = tmp_path / "victim-manifest"
    victim.write_text("safe\n", encoding="utf-8")
    reporter.manifest_path.unlink()
    reporter.manifest_path.symlink_to(victim)
    tracker = ResourceTracker(reporter)

    with pytest.raises(SuiteError, match="Output journal must not be a symbolic link"):
        tracker.add("server", "server-one", "server-one")

    assert victim.read_text(encoding="utf-8") == "safe\n"
    assert reporter.resources == []
    reporter.logger.close()


def test_scoped_plan_refuses_symlink_replacement(config_factory, tmp_path):
    from neutron_flux.models import Plan
    from neutron_flux.reporting import ScopedReporter

    config = config_factory(report_dir=tmp_path / "reports", action="run")
    parent = Reporter(config, "scoped-plan-swap")
    scoped = ScopedReporter(parent, "az-one", availability_zone="az1")
    scoped.plan = Plan([], [], {}, [], tests=[])
    victim = tmp_path / "victim-plan"
    victim.write_text("safe\n", encoding="utf-8")
    scoped.plan_path.symlink_to(victim)

    with pytest.raises(SuiteError, match="Output artifact must not be a symbolic link"):
        scoped.save_plan()

    assert victim.read_text(encoding="utf-8") == "safe\n"
    parent.logger.close()


def test_state_store_concurrent_saves_use_unique_atomic_temporary_files(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    report_dir = tmp_path / "state"
    stores = [StateStore(report_dir), StateStore(report_dir)]
    checkpoints = [
        _checkpoint(
            "concurrent-run", report_dir / "runs" / "concurrent-run", complete=False
        )
        for _ in range(20)
    ]

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [
            pool.submit(stores[index % 2].save, checkpoint)
            for index, checkpoint in enumerate(checkpoints)
        ]
        for future in futures:
            future.result()

    loaded = StateStore(report_dir).load("concurrent-run")
    assert loaded.run_id == "concurrent-run"
    assert not list((report_dir / "runs" / "concurrent-run").glob("*.tmp"))
    assert not list(report_dir.glob(".latest-run.*.tmp"))


def test_diagnostic_directories_remain_unique_after_name_bounding(
    config_factory, tmp_path
):
    from neutron_flux.diagnostics import DiagnosticCollector
    from neutron_flux.models import ProbeResult, TestSpec

    config = config_factory(report_dir=tmp_path / "reports", action="run")
    reporter = Reporter(config, "diagnostic-collision")
    collector = DiagnosticCollector(SimpleNamespace(), reporter)
    common = "TEST-" + ("A" * 180)
    specs = [
        TestSpec(
            id=common + suffix,
            category="connectivity",
            operation="probe",
            family=4,
            expectation="reachable",
            expectation_reason="test",
            authoritative=True,
            dependencies=[],
        )
        for suffix in ("-ONE", "-TWO")
    ]
    probe = ProbeResult("timeout", False, 1, 1, stderr="timed out")

    directories = [
        collector.collect(spec, probe, None, None)[1]["diagnostic_directory"]
        for spec in specs
    ]

    assert len(set(directories)) == 2
    assert all((Path(item) / "diagnostics.json").is_file() for item in directories)
    reporter.logger.close()


def test_cold_migration_transient_client_error_reconciles_nova_state(config_factory):
    import subprocess

    from neutron_flux.models import ComputeHostInfo
    from neutron_flux.resources import ResourceBuilder

    from ._shared import endpoint

    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run", storage="host")
    builder.logger = mock.Mock()
    builder.reporter = mock.Mock()
    builder.probe_service = SimpleNamespace(stop=lambda _endpoint: None)
    builder.osc = mock.Mock()
    builder.osc.run.return_value = subprocess.CompletedProcess(
        ["openstack", "server", "migrate"],
        1,
        "",
        "HTTP 503 Service Unavailable",
    )
    builder._capture_endpoint_migration_state = lambda _endpoint: {
        "migration_ids": set(),
        "migration_inventory_error": None,
        "volume_ids": set(),
        "guest_marker": None,
    }
    builder._wait_for_migration_acceptance = lambda *args, **kwargs: {
        "accepted": True,
        "evidence": "test harness",
    }
    handoff_calls: list[str] = []
    builder._wait_for_migration_handoff = lambda _endpoint, target: (
        handoff_calls.append(target) or {"status": "VERIFY_RESIZE"},
        False,
    )
    builder._confirm_cold_migration = lambda _endpoint, _target: False
    builder._wait_for_status = lambda *args, **kwargs: None
    builder._wait_for_active_on_target = lambda _endpoint, target: {
        "status": "ACTIVE",
        "host": target,
        "availability_zone": "az1",
        "task_state": None,
    }
    builder._verify_nova_migration_record = lambda *args, **kwargs: (True, None, {})
    builder._verify_migrated_ports = lambda *args, **kwargs: (True, {})
    builder._wait_for_ssh = lambda *args, **kwargs: True
    builder.reconfigure_endpoint = lambda _endpoint: None

    moving = endpoint("cold-transient", "A")
    moving.host = "compute1"
    moving.availability_zone = "az1"
    target = ComputeHostInfo("compute2", "az1", True, True, {"agg"}, {"agg"})

    result = builder._cold_migrate_endpoint_once(moving, target)

    assert result.destination_host == "compute2"
    assert result.details["request_error"] == "HTTP 503 Service Unavailable"
    assert handoff_calls == ["compute2"]


def test_logger_refuses_symlinked_transcript(tmp_path):
    from neutron_flux.log import Logger

    victim = tmp_path / "victim-log"
    victim.write_text("safe\n", encoding="utf-8")
    link = tmp_path / "report.txt"
    link.symlink_to(victim)

    with pytest.raises(OSError):
        Logger(link)

    assert victim.read_text(encoding="utf-8") == "safe\n"


def test_blocked_setup_result_cannot_produce_green_run(config_factory, tmp_path):
    import json

    config = config_factory(report_dir=tmp_path / "reports", action="run")
    reporter = Reporter(config, "blocked-verdict")
    reporter.result("PASSING", "connectivity", "PASS", "ok")
    reporter.result(
        "BLOCKED",
        "cross-zone-connectivity",
        "BLOCKED_BY_SETUP_ERROR",
        "endpoint setup failed",
    )
    reporter.cleanup_summary.update({"attempted": True, "complete": True})

    exit_code = reporter.finalize(0)
    payload = json.loads(reporter.results_path.read_text(encoding="utf-8"))

    assert exit_code != 0
    assert payload["run"]["final_status"] == "INCOMPLETE"


def test_finalize_recovers_from_atomic_writer_suite_error(config_factory, tmp_path):
    import json

    config = config_factory(report_dir=tmp_path / "reports", action="run")
    reporter = Reporter(config, "finalize-suite-error")
    reporter.result("PASSING", "connectivity", "PASS", "ok")
    reporter.cleanup_summary.update({"attempted": True, "complete": True})
    victim = tmp_path / "victim-html"
    victim.write_text("safe\n", encoding="utf-8")
    reporter.html_report_path.symlink_to(victim)

    exit_code = reporter.finalize(0)
    payload = json.loads(reporter.results_path.read_text(encoding="utf-8"))

    assert exit_code != 0
    assert payload["run"]["final_status"] == "ERROR"
    assert victim.read_text(encoding="utf-8") == "safe\n"


def test_multi_zone_provider_only_plan_does_not_require_router_quota(
    config_factory, discovery_fixture
):
    from neutron_flux.models import QuotaInfo
    from neutron_flux.zones import ZonePreflight

    from ._shared import _zone_launch_selection

    config = config_factory(storage="host", zone_mode="both")
    plan = SimpleNamespace(
        estimated={
            "peak_instances": 3,
            "peak_ports": 7,
            "peak_created_networks": 1,
            "peak_created_subnets": 1,
            "peak_created_routers": 0,
            "peak_floating_ips": 1,
            "security_groups_created": 4,
            "security_group_rules_peak": 24,
        }
    )
    discovery_fixture.quota_info = {
        name: QuotaInfo(name, 10000, 0)
        for name in (
            "instances",
            "cores",
            "ram",
            "ports",
            "networks",
            "subnets",
            "floating_ips",
            "security_groups",
            "security_group_rules",
            "key_pairs",
        )
    }
    discovery_fixture.quota_info["routers"] = QuotaInfo("routers", 0, 0)
    preflight = object.__new__(ZonePreflight)
    preflight.config = config
    preflight.discovery = discovery_fixture
    preflight.plan = plan
    preflight.launch_selection = _zone_launch_selection()

    preflight._validate_parallel_quota(3)


def test_reporter_closes_logger_when_safe_journal_initialization_fails(
    config_factory, monkeypatch, tmp_path
):
    import neutron_flux.reporting as reporting

    created = []

    class FakeLogger:
        def __init__(self, path):
            self.path = path
            self.closed = False
            created.append(self)

        def close(self):
            self.closed = True

    monkeypatch.setattr(reporting, "Logger", FakeLogger)
    monkeypatch.setattr(
        reporting,
        "append_text",
        lambda *args, **kwargs: (_ for _ in ()).throw(SuiteError("unsafe journal")),
    )

    with pytest.raises(SuiteError, match="Could not initialize run journal"):
        reporting.Reporter(
            config_factory(report_dir=tmp_path / "reports", action="run"),
            "journal-init-failure",
        )

    assert len(created) == 1
    assert created[0].closed is True


def test_heartbeat_ignores_safe_state_writer_failure():
    import time

    from neutron_flux.suite import Suite

    suite = object.__new__(Suite)
    suite._last_heartbeat = 0.0
    suite._last_cloud_heartbeat = time.monotonic()
    suite.checkpoint = SimpleNamespace(last_activity=None, updated_at=None, metadata={})
    suite.reporter = SimpleNamespace(plan=None, results=[])
    suite.state_store = SimpleNamespace(
        save=lambda checkpoint: (_ for _ in ()).throw(SuiteError("state unavailable"))
    )
    suite.zone_orchestrator = None
    suite.builder = None

    suite._heartbeat()

    assert suite.checkpoint.last_activity
    assert suite.checkpoint.updated_at == suite.checkpoint.last_activity


def test_setup_blocked_result_uses_failure_cleanup_policy():
    from neutron_flux.cli import _successful_for_cleanup

    reporter = SimpleNamespace(
        results=[SimpleNamespace(status="BLOCKED_BY_SETUP_ERROR")],
        setup_failed=False,
        error=None,
    )
    assert _successful_for_cleanup(0, reporter) is False


def test_checkpoint_failed_ids_include_setup_blocked_result(tmp_path):
    from neutron_flux.suite import Suite

    saved = []
    suite = object.__new__(Suite)
    suite.checkpoint = SimpleNamespace(
        metadata={},
        state=None,
        phase=None,
        current_batch=None,
        completed_test_ids=[],
        failed_test_ids=[],
        pending_test_ids=[],
        manifest_path=None,
        report_dir=None,
        updated_at=None,
        last_activity=None,
    )
    suite.reporter = SimpleNamespace(
        plan=None,
        results=[SimpleNamespace(test_id="blocked", status="BLOCKED_BY_SETUP_ERROR")],
        manifest_path=tmp_path / "manifest.jsonl",
        run_dir=tmp_path,
    )
    suite.plan = None
    suite.state_store = SimpleNamespace(
        save=lambda checkpoint: saved.append(checkpoint)
    )
    suite.builder = None
    suite.zone_orchestrator = None

    suite._save_checkpoint("RUNNING", "tests", None)

    assert suite.checkpoint.failed_test_ids == []
    assert saved == [suite.checkpoint]


def test_manifest_update_cannot_change_resource_identity(tmp_path):
    import dataclasses

    from neutron_flux.models import ResourceRecord
    from neutron_flux.reporting import ResourceTracker

    path = tmp_path / "manifest.jsonl"
    original = ResourceRecord(1, "port", "port-one", "port-one", None, {}, iso_utc())
    tampered = ResourceRecord(
        1, "server", "server-victim", "server-victim", None, {}, iso_utc()
    )
    path.write_text(
        json.dumps(dataclasses.asdict(original))
        + "\n"
        + json.dumps(dataclasses.asdict(tampered))
        + "\n",
        encoding="utf-8",
    )
    errors = []

    loaded = ResourceTracker.load_manifest(path, errors=errors)

    assert [(item.resource_type, item.id) for item in loaded] == [("port", "port-one")]
    assert len(errors) == 1
    assert "resource identity changed" in errors[0]


def test_manifest_rejects_invalid_sequence_metadata_and_duplicate_identity(tmp_path):
    import dataclasses

    from neutron_flux.models import ResourceRecord
    from neutron_flux.reporting import ResourceTracker

    valid = ResourceRecord(1, "port", "port-one", "port-one", None, {}, iso_utc())
    duplicate = ResourceRecord(2, "port", "port-one", "port-copy", None, {}, iso_utc())
    invalid_sequence = dataclasses.asdict(valid) | {"sequence": 0, "id": "port-zero"}
    invalid_metadata = dataclasses.asdict(valid) | {
        "sequence": 3,
        "id": "port-three",
        "metadata": [],
    }
    path = tmp_path / "manifest.jsonl"
    path.write_text(
        "\n".join(
            json.dumps(item)
            for item in (
                dataclasses.asdict(valid),
                dataclasses.asdict(duplicate),
                invalid_sequence,
                invalid_metadata,
            )
        )
        + "\n",
        encoding="utf-8",
    )
    errors = []

    loaded = ResourceTracker.load_manifest(path, errors=errors)

    assert [item.id for item in loaded] == ["port-one"]
    assert len(errors) == 3
    assert any("duplicated across sequences" in item for item in errors)
    assert any("positive integer" in item for item in errors)
    assert any("metadata must be an object" in item for item in errors)


def test_new_run_resource_prefix_preserves_full_identity_with_digest(
    config_factory, tmp_path
):
    first_id = "abcdefghijklmnop-20260723010101-abcd00"
    second_id = "abcdefghijklmnop-20260723010101-abcd11"
    first = Reporter(
        config_factory(report_dir=tmp_path / "reports", action="run"), first_id
    )
    second = Reporter(
        config_factory(report_dir=tmp_path / "reports", action="run"), second_id
    )
    try:
        assert first.name_prefix != second.name_prefix
        assert len(first.name_prefix) <= 36
        assert len(second.name_prefix) <= 36
    finally:
        first.logger.close()
        second.logger.close()


def test_recovery_preserves_stored_legacy_resource_prefix(config_factory, tmp_path):
    report_dir = tmp_path / "reports"
    config = config_factory(report_dir=report_dir, action="run")
    original = Reporter(config, "legacy-20260723010101-abcdef")
    original.logger.close()
    payload = json.loads(original.active_path.read_text(encoding="utf-8"))
    payload["name_prefix"] = "legacy-truncated-prefix"
    original.active_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")

    reopened = Reporter(
        config_factory(report_dir=report_dir, action="cleanup"),
        original.run_id,
        load_existing=True,
    )
    try:
        assert reopened.name_prefix == "legacy-truncated-prefix"
        assert reopened.run_tag == payload["run_tag"]
    finally:
        reopened.logger.close()
