from __future__ import annotations

import dataclasses
import datetime as dt
import json
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.errors import (
    MeasurementExecutionError,
    SSHExecutionError,
)
from neutron_flux.execution_diagnostics import capture_execution_diagnostics
from neutron_flux.models import ComputeHostInfo
from neutron_flux.performance import PerformanceRunner
from neutron_flux.reporting import Reporter

from .test_compute_placement import _placement_builder
from .test_diagnostics_and_measurement_classification import _resolved_path, _spec


@pytest.mark.parametrize(
    "message",
    [
        "Connection timed out during banner exchange",
        "ssh: connect to host 10.254.0.137 port 22: No route to host",
        "channel 0: open failed: connect failed: Connection refused; stdio forwarding failed",
    ],
)
def test_management_failures_never_become_udp_verdicts(config_factory, message):
    runner = PerformanceRunner(
        config_factory(),
        SimpleNamespace(
            ssh_endpoint=lambda *a, **k: subprocess.CompletedProcess(
                [], 255, "", message
            )
        ),
        mock.Mock(),
        SimpleNamespace(lifecycle={}),
    )
    with pytest.raises(SSHExecutionError) as caught:
        runner._run_json(_resolved_path().source, "print('{}')", timeout=10)
    assert runner._classify_measurement_exception(caught.value) is caught.value
    assert caught.value.evidence["returncode"] == 255
    assert caught.value.evidence["stderr"] == message


def test_failed_remote_program_is_execution_error_without_probe_verdict(config_factory):
    runner = PerformanceRunner(
        config_factory(),
        SimpleNamespace(
            ssh_endpoint=lambda *a, **k: subprocess.CompletedProcess(
                [], 1, "", "No route to host"
            )
        ),
        mock.Mock(),
        SimpleNamespace(lifecycle={}),
    )
    with pytest.raises(MeasurementExecutionError):
        runner._run_json(_resolved_path().source, "print('{}')", timeout=10)


@pytest.mark.parametrize(
    "returncode,output,expected_error",
    [
        (255, "Connection timed out during banner exchange", SSHExecutionError),
        (127, "ping: command not found", MeasurementExecutionError),
    ],
)
def test_latency_requires_actual_packet_statistics(
    config_factory, returncode, output, expected_error
):
    runner = PerformanceRunner(
        config_factory(),
        SimpleNamespace(
            ssh_endpoint=lambda *a, **k: subprocess.CompletedProcess(
                [], returncode, "", output
            )
        ),
        mock.Mock(),
        SimpleNamespace(lifecycle={}),
    )
    with pytest.raises(expected_error):
        runner._ping(_resolved_path().source, "10.0.0.1", "10.0.0.2", 4)


def test_actual_ping_packet_loss_remains_a_measurement(config_factory):
    runner = PerformanceRunner(
        config_factory(),
        SimpleNamespace(
            ssh_endpoint=lambda *a, **k: subprocess.CompletedProcess(
                [], 1, "10 packets transmitted, 0 received, 100% packet loss", ""
            )
        ),
        mock.Mock(),
        SimpleNamespace(lifecycle={}),
    )
    metrics = runner._ping(_resolved_path().source, "10.0.0.1", "10.0.0.2", 4)
    assert metrics["transmitted"] == 10 and metrics["loss_pct"] == 100.0


def test_retry_retains_transport_type_and_both_attempts(config_factory, monkeypatch):
    monkeypatch.setattr("neutron_flux.performance_results.time.sleep", lambda _: None)
    runner = PerformanceRunner(
        config_factory(), SimpleNamespace(), mock.Mock(), SimpleNamespace(lifecycle={})
    )
    runner._run_json = mock.Mock(
        side_effect=[
            SSHExecutionError(
                "SSH command timed out after 38s", evidence={"timeout_seconds": 38}
            ),
            SSHExecutionError(
                "Connection timed out during banner exchange",
                evidence={"returncode": 255},
            ),
        ]
    )
    with pytest.raises(SSHExecutionError) as caught:
        runner._run_json_with_transient_retry(
            _resolved_path().source, "probe", timeout=38
        )
    assert len(caught.value.evidence["attempts"]) == 2
    assert (
        caught.value.evidence["attempt_history"][0]["evidence"]["timeout_seconds"] == 38
    )


def test_udp_transport_loss_preserves_prior_measurements_and_stops_dependents(
    config_factory,
):
    runner = PerformanceRunner(
        config_factory(), SimpleNamespace(), mock.Mock(), SimpleNamespace(lifecycle={})
    )
    runner._measure_tcp_family = lambda _: (
        {},
        {"tcp-throughput": {"metrics": {}, "health": "healthy"}},
        None,
    )
    runner._measure_latency_family = lambda _: (
        {},
        {"metrics": {}, "health": "healthy"},
    )
    runner._measure_udp_family = mock.Mock(
        side_effect=SSHExecutionError("Connection timed out during banner exchange")
    )
    runner._measure_mtu_family = mock.Mock()
    measurements, errors = runner._measure(_resolved_path())
    assert set(measurements) == {"tcp-throughput", "latency"}
    assert isinstance(errors["udp"], SSHExecutionError)
    assert "management transport" in str(errors["mtu-mss"])
    assert "path was unreachable" not in str(errors["mtu-mss"])
    runner._measure_mtu_family.assert_not_called()


def test_root_transport_error_is_error_and_not_authoritative_network_fail(
    config_factory,
):
    reporter = Reporter(config_factory(action="run"), "transport-error")
    try:
        runner = PerformanceRunner(
            reporter.config, SimpleNamespace(), reporter, SimpleNamespace(lifecycle={})
        )
        spec = _spec("UDP", measurement="udp")
        runner._record_measurement_error(
            spec,
            _resolved_path(),
            SSHExecutionError("banner exchange timed out"),
            started=time.monotonic(),
        )
        result = reporter.get_result("UDP")
        assert result.status == "ERROR"
        assert result.authoritative is False
        assert result.details["root_path_failure"] is False
        assert Path(result.details["execution_diagnostics_file"]).is_file()
    finally:
        reporter.logger.close()


def test_diagnostics_capture_compute_health_and_host_evidence(config_factory, tmp_path):
    calls = []

    def read(*args, **kwargs):
        calls.append(args)
        assert 0 < kwargs["timeout"] <= 5
        if args[0] == "compute":
            return [{"Host": "compute1", "State": "down", "Status": "enabled"}]
        return {
            "status": "ACTIVE",
            "OS-EXT-SRV-ATTR:host": "secret-compute",
            "binding:host_id": "secret-compute",
        }

    builder = SimpleNamespace(
        osc=SimpleNamespace(
            json=read,
            run=lambda *a, **k: subprocess.CompletedProcess([], 0, "console", ""),
        ),
        ssh_endpoint=lambda *a, **k: subprocess.CompletedProcess(
            [], 255, "", "Connection timed out during banner exchange"
        ),
        ssh_controller=lambda *a, **k: subprocess.CompletedProcess([], 0, "", ""),
    )
    reporter = SimpleNamespace(config=config_factory(), run_dir=tmp_path)
    result = capture_execution_diagnostics(
        builder,
        reporter,
        "mode",
        (_resolved_path().source,),
        SSHExecutionError("timeout"),
    )
    payload = result["execution_diagnostics"]
    assert any(args[0] == "compute" for args in calls)
    assert payload["compute_service_health"]["data"][0]["State"] == "down"
    assert "secret-compute" in json.dumps(payload)
    assert "secret-compute" in Path(result["execution_diagnostics_file"]).read_text()


def test_denied_optional_admin_read_is_not_retried_or_host_down(
    config_factory, tmp_path
):
    compute_calls = []

    def read(*args, **kwargs):
        if args[0] == "compute":
            compute_calls.append(args)
            raise RuntimeError("403 Forbidden")
        return {"status": "ACTIVE"}

    builder = SimpleNamespace(osc=SimpleNamespace(json=read))
    reporter = SimpleNamespace(config=config_factory(), run_dir=tmp_path)
    for test_id in ("first", "second"):
        payload = capture_execution_diagnostics(
            builder,
            reporter,
            test_id,
            (_resolved_path().source,),
            SSHExecutionError("timeout"),
        )["execution_diagnostics"]
        assert payload["compute_service_health"]["status"] == "permission-denied"
    assert len(compute_calls) == 1


def test_selector_explains_down_same_zone_host_and_never_returns_other_zone(
    config_factory,
):
    source = dataclasses.replace(
        _resolved_path().source, host="compute6", availability_zone="az2"
    )
    peer = dataclasses.replace(source, server_id="peer")
    inventory = {
        "compute1": ComputeHostInfo("compute1", "az1", True, True, {"agg"}),
        "compute5": ComputeHostInfo("compute5", "az2", True, False, {"agg"}),
        "compute6": ComputeHostInfo("compute6", "az2", True, True, {"agg"}),
    }
    builder = _placement_builder(config_factory(), inventory)
    builder.reporter = mock.Mock()
    targets, reason = builder.select_compute_migration_targets(
        source, peer, desired_relation="different"
    )
    assert targets == []
    assert "compute5" in reason and "not enabled and up" in reason
    assert "compute1" not in reason and "No migration was submitted" in reason
    event = builder.reporter.event.call_args.kwargs
    assert event["candidates"] == [
        {
            "host": "compute5",
            "eligible": False,
            "reason": "target host compute5 is not enabled and up",
        }
    ]
    assert event["excluded_other_zones"] == 1
    inventory["compute5"].up = True
    targets, _ = builder.select_compute_migration_targets(
        source, peer, desired_relation="different"
    )
    assert [target.host for target in targets] == ["compute5"]


def test_result_start_time_is_not_publication_time(config_factory):
    reporter = Reporter(config_factory(), "clock")
    try:
        before = dt.datetime.now(dt.timezone.utc)
        result = reporter.result(
            "timed", "control", "PASS", "done", started=time.monotonic() - 30
        )
        actual = dt.datetime.fromisoformat(result.started_at)
        assert 29.9 < (before - actual).total_seconds() < 30.1
        assert 29900 <= result.duration_ms <= 30100
    finally:
        reporter.logger.close()


def test_measurement_timing_excludes_later_measurements(config_factory, monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(
        "neutron_flux.performance_measurements.time.monotonic", lambda: clock[0]
    )
    runner = PerformanceRunner(
        config_factory(), SimpleNamespace(), mock.Mock(), SimpleNamespace(lifecycle={})
    )

    def measure():
        clock[0] += 2
        return "result"

    assert runner._capture_measurement({}, ("tcp-throughput",), measure) == "result"
    clock[0] += 50
    assert runner._measurement_timings["tcp-throughput"]["duration_ms"] == 2000


def test_blocked_chain_reports_root_once(config_factory):
    from neutron_flux.check_ledger import check_ledger, finish_checks, resolve_checks

    reporter = Reporter(config_factory(), "blocked-chain")
    reporter.plan = SimpleNamespace(
        tests=[],
        checks=[
            {
                "id": name,
                "title": title,
                "condition": "required",
                "kind": "functional",
                "stage": "after-migration",
                "prerequisites": dependencies,
            }
            for name, title, dependencies in (
                ("migration", "Migrate endpoint", []),
                ("tcp", "Check TCP", ["migration"]),
                ("perf", "Measure TCP", ["tcp"]),
            )
        ],
    )
    try:
        resolve_checks(
            reporter,
            {"migration": ("BLOCKED", "compute5 is down; no migration submitted")},
        )
        finish_checks(reporter, {"tcp", "perf"}, reason="required step unavailable")
        rows = {row["id"]: row for row in check_ledger(reporter)}
        assert rows["tcp"]["reason"] == rows["perf"]["reason"]
        assert rows["perf"]["reason"].count("Blocked by") == 1
        assert rows["perf"]["outcome"] == "BLOCKED"
    finally:
        reporter.logger.close()


@pytest.mark.parametrize("complete", [True, False])
def test_zone_recovery_files_follow_verified_final_cleanup(
    config_factory, tmp_path, monkeypatch, complete
):
    import neutron_flux.multi_zone as multi_zone
    from neutron_flux.cleanup_components.recovery import CleanupRecoveryMixin

    reporter = Reporter(config_factory(action="run"), "zone-recovery")
    scoped = multi_zone.ScopedReporter(reporter, "az2", availability_zone="az2")
    scoped.run_dir.mkdir(parents=True, exist_ok=True)
    for name in ("recovery.md", "recovery.sh"):
        (scoped.run_dir / name).write_text("stale operation")
    scoped.cleanup_summary.update(
        errors=["temporary timeout"], unresolved_operations=["operation-1"]
    )
    cleanup = CleanupRecoveryMixin()
    cleanup.reporter = scoped
    cleanup.logger = reporter.logger
    cleanup.cleanup = lambda **kwargs: False

    class ParentCleanup:
        def __init__(self, *args, **kwargs):
            pass

        def cleanup(self, **kwargs):
            reporter.cleanup_summary.update(
                complete=complete, errors=[], leftovers=[] if complete else ["port:one"]
            )
            return complete

    monkeypatch.setattr(multi_zone, "CleanupManager", ParentCleanup)
    orchestrator = object.__new__(multi_zone.MultiZoneOrchestrator)
    orchestrator.config = reporter.config
    orchestrator.reporter = reporter
    orchestrator.logger = reporter.logger
    orchestrator.zone_plan = SimpleNamespace(parallel_workers=1)
    orchestrator.lanes = {
        "az2": SimpleNamespace(reporter=scoped, cleanup_manager=cleanup)
    }
    orchestrator.shared_security_cleanup = None
    orchestrator.shared_security_builder = None
    orchestrator.cloud_operation_coordinator = None
    orchestrator.lifecycle_lock = None
    try:
        assert orchestrator.cleanup_all() is complete
        assert (scoped.run_dir / "recovery.md").exists() is not complete
        assert (scoped.run_dir / "recovery.sh").exists() is not complete
        if complete:
            assert (
                reporter.cleanup_summary["zones"]["az2"]["unresolved_operations"] == []
            )
        else:
            assert scoped.cleanup_summary["unresolved_operations"] == ["operation-1"]
    finally:
        reporter.logger.close()


def test_report_counts_planned_checks_separately_from_samples(config_factory):
    from neutron_flux.report_exports import render_incident_summary

    from .test_report_workflow import _payload

    payload = _payload()
    payload["results"] = payload["results"] * 3
    payload["planned_check_ledger"] = [
        {"id": "one", "outcome": "PASSED"},
        {"id": "two", "outcome": "BLOCKED"},
    ]
    report = render_incident_summary(payload)
    assert "Planned checks: 2 total; BLOCKED=1, PASSED=1" in report
    assert "Evidence records: 3 total; PASS=3" in report


def test_cross_zone_diagnostics_use_each_endpoints_controller(config_factory, tmp_path):
    from neutron_flux.multi_zone import _CrossZonePerformanceControl

    path = _resolved_path()
    calls = []
    owners = {}
    for endpoint in (path.source, path.destination):

        def ssh(target, command, *, timeout, expected=endpoint.server_id):
            assert target.server_id == expected
            calls.append(target.server_id)
            return subprocess.CompletedProcess([], 0, "guest", "")

        owners[endpoint.server_id] = SimpleNamespace(
            availability_zone=endpoint.availability_zone,
            ssh_endpoint=ssh,
            osc=SimpleNamespace(
                json=lambda *a, **k: {},
                run=lambda *a, **k: subprocess.CompletedProcess([], 0, "console", ""),
            ),
        )
    result = capture_execution_diagnostics(
        _CrossZonePerformanceControl(owners),
        SimpleNamespace(config=config_factory(), run_dir=tmp_path),
        "cross-zone",
        (path.source, path.destination),
        SSHExecutionError("timeout"),
    )
    assert calls == [path.source.server_id, path.destination.server_id]
    assert len(result["execution_diagnostics"]["endpoints"]) == 2
