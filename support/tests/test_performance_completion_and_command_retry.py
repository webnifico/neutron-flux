from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.diagnostics import DiagnosticCollector
from neutron_flux.errors import RunCancelledError, SuiteError
from neutron_flux.models import (
    Endpoint,
    Plan,
    ProbeResult,
)
from neutron_flux.models import (
    TestSpec as FluxTestSpec,
)
from neutron_flux.performance import PerformanceRunner
from neutron_flux.reporting import Reporter
from neutron_flux.reporting_components.html import _performance_coverage


def _endpoint() -> Endpoint:
    return Endpoint(
        label="Flux runner",
        server_id="runner",
        server_name="runner",
        management_port_id=None,
        management_ip="10.0.3.107",
        test_port_id=None,
        test_mac=None,
        fixed_ips={},
        host="runner",
        availability_zone=None,
        volume_id=None,
        side="A",
        metadata={},
    )


def _performance_rows(
    *,
    path_id: str,
    directions: list[str],
    measurements: list[str],
) -> list[dict[str, object]]:
    return [
        {
            "status": "PASS",
            "details": {
                "performance": True,
                "measurement": measurement,
                "path": {
                    "path_id": path_id,
                    "source_category": "floating-ip",
                    "directions": directions,
                },
            },
        }
        for measurement in measurements
    ]


def test_forward_only_performance_path_is_complete():
    measurements = [
        "tcp-throughput",
        "latency",
        "udp",
        "mtu-mss",
        "concurrency",
        "repeatability",
    ]
    coverage = _performance_coverage(
        [],
        _performance_rows(
            path_id="FIP-FORWARD",
            directions=["forward"],
            measurements=measurements,
        ),
    )
    assert coverage["completed"] == 1
    assert coverage["incomplete"] == 0


def test_bidirectional_performance_path_still_requires_asymmetry():
    measurements = [
        "tcp-throughput",
        "latency",
        "udp",
        "mtu-mss",
        "concurrency",
        "repeatability",
    ]
    coverage = _performance_coverage(
        [],
        _performance_rows(
            path_id="BIDIRECTIONAL",
            directions=["forward", "reverse"],
            measurements=measurements,
        ),
    )
    assert coverage["completed"] == 0
    assert coverage["incomplete"] == 1


def test_generic_probe_timeout_is_not_mislabeled_as_result_status():
    timed_out = ProbeResult(
        outcome="blocked",
        success=False,
        elapsed_ms=1000,
        attempts=1,
        stderr="Connection timed out",
    )
    unknown = ProbeResult(
        outcome="blocked",
        success=False,
        elapsed_ms=1000,
        attempts=1,
        stderr="probe ended without a recognized symptom",
    )
    assert DiagnosticCollector._classify(timed_out) == "UNATTRIBUTED"
    assert DiagnosticCollector._classify(unknown) == "UNATTRIBUTED"


def test_transient_performance_command_is_retried_once(monkeypatch):
    runner = PerformanceRunner.__new__(PerformanceRunner)
    runner.builder = SimpleNamespace(
        ssh_endpoint=mock.Mock(
            side_effect=[
                subprocess.CompletedProcess(
                    ["ssh"], 1, "", "OSError: [Errno 113] No route to host"
                ),
                subprocess.CompletedProcess(["ssh"], 0, '{"ok": true}\n', ""),
            ]
        )
    )
    runner.reporter = SimpleNamespace(logger=mock.Mock(), event=mock.Mock())
    monkeypatch.setattr("neutron_flux.performance_results.time.sleep", lambda _: None)

    result = runner._run_json_with_transient_retry(
        _endpoint(),
        "print('{}')",
        timeout=10,
    )

    assert result["ok"] is True
    assert result["execution_evidence"]["returncode"] == 0
    assert runner.builder.ssh_endpoint.call_count == 2
    assert (
        runner.reporter.event.call_args_list[0].args[0] == "performance-command-retry"
    )
    assert (
        runner.reporter.event.call_args_list[1].args[0]
        == "performance-command-retry-succeeded"
    )


def test_performance_command_retry_never_swallows_cancellation(monkeypatch):
    runner = PerformanceRunner.__new__(PerformanceRunner)
    runner._run_json = mock.Mock(side_effect=RunCancelledError("cancelled"))
    runner.reporter = SimpleNamespace(logger=mock.Mock(), event=mock.Mock())
    sleep = mock.Mock()
    monkeypatch.setattr("neutron_flux.performance_results.time.sleep", sleep)

    with pytest.raises(RunCancelledError, match="cancelled"):
        runner._run_json_with_transient_retry(
            _endpoint(),
            "print('{}')",
            timeout=10,
        )

    runner._run_json.assert_called_once()
    sleep.assert_not_called()
    runner.reporter.event.assert_not_called()


def test_non_transient_performance_error_is_not_retried(monkeypatch):
    runner = PerformanceRunner.__new__(PerformanceRunner)
    runner._run_json = mock.Mock(side_effect=SuiteError("invalid JSON output"))
    runner.reporter = SimpleNamespace(logger=mock.Mock(), event=mock.Mock())
    sleep = mock.Mock()
    monkeypatch.setattr("neutron_flux.performance_results.time.sleep", sleep)

    with pytest.raises(SuiteError, match="invalid JSON output"):
        runner._run_json_with_transient_retry(
            _endpoint(),
            "print('{}')",
            timeout=10,
        )

    runner._run_json.assert_called_once()
    sleep.assert_not_called()
    runner.reporter.event.assert_not_called()


def test_performance_command_retry_preserves_both_failures(monkeypatch):
    runner = PerformanceRunner.__new__(PerformanceRunner)
    runner.builder = SimpleNamespace(
        ssh_endpoint=mock.Mock(
            side_effect=[
                subprocess.CompletedProcess(["ssh"], 1, "", "No route to host"),
                subprocess.CompletedProcess(
                    ["ssh"], 1, "", "UDP performance server did not return statistics"
                ),
            ]
        )
    )
    runner.reporter = SimpleNamespace(logger=mock.Mock(), event=mock.Mock())
    monkeypatch.setattr("neutron_flux.performance_results.time.sleep", lambda _: None)

    with pytest.raises(SuiteError, match="failed after 2 attempts") as caught:
        runner._run_json_with_transient_retry(
            _endpoint(),
            "print('{}')",
            timeout=10,
        )

    message = str(caught.value)
    assert "No route to host" in message
    assert "UDP performance server did not return statistics" in message
    assert runner.builder.ssh_endpoint.call_count == 2


def test_save_plan_tracks_runtime_planned_result_rows(config_factory, tmp_path):
    reporter = Reporter(
        config_factory(action="run", report_dir=tmp_path / "reports"),
        "runtime-plan-count",
    )
    reporter.plan = Plan([], [], {"test_results": 0}, [], tests=[])
    reporter.plan.tests.extend(
        [
            FluxTestSpec(
                id=test_id,
                category="control",
                operation="probe",
                family=4,
                expectation="reachable",
                expectation_reason="runtime test",
                authoritative=True,
                dependencies=[],
            )
            for test_id in ("A", "B")
        ]
    )

    reporter.save_plan()

    payload = json.loads(reporter.plan_path.read_text(encoding="utf-8"))
    assert reporter.plan.estimated["test_results"] == 2
    assert payload["estimated"]["test_results"] == 2
    reporter.logger.close()
