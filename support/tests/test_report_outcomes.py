from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace

import pytest

from neutron_flux.cli import main
from neutron_flux.comparison import compare_payloads
from neutron_flux.junit_report import build_junit
from neutron_flux.models import ComputeHostInfo, MigrationResult
from neutron_flux.offline_reports import regenerate
from neutron_flux.reporting_components.html import render_html
from neutron_flux.trends import trend_files, trend_payload

from ._shared import _placement_executor, endpoint


def _payload(run_id: str, *, final_status: str = "PASS", status: str = "PASS") -> dict:
    return {
        "schema_version": 1,
        "run": {
            "run_id": run_id,
            "started_at": "2026-01-01T00:00:00Z",
            "final_status": final_status,
        },
        "summary": {"counts": {status: 1} if status else {}},
        "results": [
            {
                "test_id": "T1",
                "category": "connectivity",
                "status": status,
                "details": {},
            }
        ]
        if status
        else [],
        "cleanup": {"complete": True},
    }


def test_comparison_distinguishes_fail_and_error_transitions():
    before = _payload("before", status="FAIL")
    after = _payload("after", status="ERROR")
    assert compare_payloads(before, after)["entries"][0]["assessment"] == "regressed"

    before = _payload("before", status="ERROR")
    after = _payload("after", status="FAIL")
    assert compare_payloads(before, after)["entries"][0]["assessment"] == "improved"


def test_comparison_treats_removed_executed_failure_as_regression():
    before = _payload("before", status="FAIL")
    after = _payload("after", status="")
    comparison = compare_payloads(before, after)
    assert comparison["entries"][0]["assessment"] == "regressed"
    assert comparison["summary"]["lost_coverage"] == 1


def test_trend_accepts_one_directory_with_multiple_runs(tmp_path: Path):
    runs = tmp_path / "runs"
    for index in (1, 2):
        directory = runs / f"run-{index}"
        directory.mkdir(parents=True)
        (directory / "results.json").write_text(
            json.dumps(_payload(f"run-{index}")), encoding="utf-8"
        )
    written = trend_files([runs], destination=tmp_path / "out")
    assert written["json"].is_file()
    assert json.loads(written["json"].read_text())["summary"]["run_count"] == 2


def test_trend_rejects_inputs_that_resolve_to_only_one_run(tmp_path: Path):
    directory = tmp_path / "run"
    directory.mkdir()
    (directory / "results.json").write_text(
        json.dumps(_payload("only")), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="at least two discovered"):
        trend_files([directory], destination=tmp_path / "out")


def test_trend_counts_setup_failed_run_without_result_errors(tmp_path: Path):
    path = tmp_path / "failed.json"
    path.write_text(
        json.dumps(_payload("failed", final_status="SETUP FAILED", status="")),
        encoding="utf-8",
    )
    trend = trend_payload([path])
    assert trend["summary"]["failed_runs"] == 1


def test_report_no_junit_removes_stale_junit(tmp_path: Path):
    source = tmp_path / "results.json"
    source.write_text(json.dumps(_payload("run")), encoding="utf-8")
    output = tmp_path / "out"
    regenerate(source, destination=output, junit=True)
    assert (output / "report.junit.xml").is_file()
    regenerate(source, destination=output, junit=False)
    assert not (output / "report.junit.xml").exists()


def test_non_offline_positional_paths_are_rejected(capsys):
    rc = main(["run", "unexpected.json"])
    captured = capsys.readouterr()
    assert rc != 0
    assert "does not accept positional paths" in captured.err


def test_live_continuity_disabled_does_not_emit_unverified_result(config_factory):
    source = endpoint("source", "A")
    destination = endpoint("destination", "B")
    source.host = destination.host = "compute1"
    target = ComputeHostInfo("compute2", "az1", True, True, {"agg"}, {"agg"})

    def live(moving, selected, stationary):
        old_host = moving.host
        moving.host = selected.host
        return MigrationResult(
            server_id=moving.server_id,
            source_host=old_host,
            destination_host=selected.host,
            source_availability_zone="az1",
            destination_availability_zone="az1",
            confirmed=True,
            automatically_confirmed=False,
            port_binding_verified=True,
            details={
                "migration_mode": "live",
                "continuity": {
                    "available": False,
                    "reason": "Live continuity measurement is disabled",
                },
            },
        )

    builder = SimpleNamespace(
        select_compute_migration_targets=lambda *args, **kwargs: ([target], "eligible"),
        live_migrate_endpoint=live,
    )
    config = config_factory(
        action="run",
        migration_mode="live-only",
        live_migration_continuity=False,
    )
    executor, spec, recorded = _placement_executor(config, source, destination, builder)
    engine = SimpleNamespace(run_specs=lambda specs: None)
    executor._run_compute_placement_validation(
        [spec], engine, dependencies=("placement-group",)
    )
    scenarios = {item.scenario for item in recorded}
    assert "Live migration capability" in scenarios
    assert "Live migration network continuity" not in scenarios


def test_comparison_does_not_hide_small_mtu_changes():
    baseline = _payload("before")
    candidate = _payload("after")
    for payload, mtu in ((baseline, 1500), (candidate, 1490)):
        payload["results"][0].update(
            {
                "category": "network-performance",
                "family": 4,
                "details": {
                    "performance": True,
                    "measurement": "mtu-mss",
                    "path": {
                        "execution_scope": "az1",
                        "source_category": "tenant-routing",
                        "placement": "cross-compute",
                        "availability_scope": "same-az",
                        "stage": "group-local",
                        "source_group_id": "group",
                        "destination_group_id": "group",
                        "source_availability_zone": "az1",
                        "destination_availability_zone": "az1",
                        "source_label": "a",
                        "destination_label": "b",
                    },
                    "metrics": {
                        "forward": {"discovered_mtu": mtu},
                        "reverse": {"discovered_mtu": mtu},
                        "expected_mtu": 1500,
                    },
                },
            }
        )
    comparison = compare_payloads(baseline, candidate)
    entry = comparison["entries"][0]
    assert entry["metrics"]["forward_discovered_mtu"]["assessment"] == "changed"
    assert entry["assessment"] == "changed"


def test_junit_marks_setup_failure_without_results_as_error():
    payload = _payload("failed", final_status="SETUP FAILED", status="")
    payload["setup_failures"] = [{"message": "controller could not boot"}]
    root = ET.fromstring(build_junit(payload))
    assert root.attrib["tests"] == "1"
    assert root.attrib["errors"] == "1"
    case = root.find("testcase")
    assert case is not None
    assert case.attrib["name"] == "RUN-FINAL-STATUS"
    assert case.find("error") is not None


def test_junit_marks_cleanup_incomplete_after_passing_tests_as_error():
    payload = _payload("cleanup", final_status="CLEANUP INCOMPLETE", status="PASS")
    payload["cleanup"] = {
        "complete": False,
        "leftovers": ["server:abc:test"],
        "errors": [],
    }
    root = ET.fromstring(build_junit(payload))
    assert root.attrib["tests"] == "2"
    assert root.attrib["errors"] == "1"
    lifecycle = [
        case
        for case in root.findall("testcase")
        if case.attrib["name"] == "RUN-FINAL-STATUS"
    ]
    assert len(lifecycle) == 1
    assert "cleanup leftover" in (lifecycle[0].find("error").text or "")


def test_html_marks_cleanup_incomplete_and_interrupted_as_bad_statuses():
    for status in ("CLEANUP INCOMPLETE", "INTERRUPTED", "CANCELLED"):
        html = render_html(_payload("run", final_status=status, status="PASS"))
        assert 'const finalIsBad=value=>["ERROR","FAIL","SETUP FAILED",' in html
        assert f'"final_status":"{status}"' in html


def test_comparison_detects_top_level_run_failure_without_result_deltas():
    baseline = _payload("before", final_status="PASS", status="")
    candidate = _payload("after", final_status="SETUP FAILED", status="")
    comparison = compare_payloads(baseline, candidate)
    change = comparison["run_changes"]["final_status"]
    assert change == {
        "baseline": "PASS",
        "candidate": "SETUP FAILED",
        "assessment": "regressed",
    }
    assert comparison["summary"]["run_regressions"] == 1
