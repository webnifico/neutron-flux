from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.comparison import compare_payloads
from neutron_flux.errors import SuiteError
from neutron_flux.models import ComputeHostInfo, MigrationResult, RunCheckpoint
from neutron_flux.reporting import Reporter
from neutron_flux.state import StateStore
from neutron_flux.trends import trend_payload
from neutron_flux.utils import iso_utc

from ._shared import _placement_executor, endpoint


def checkpoint(
    run_id: str,
    report_dir: Path,
    *,
    state: str = "RUNNING",
    cleanup_state: str = "INCOMPLETE",
    updated_at: str | None = None,
) -> RunCheckpoint:
    stamp = updated_at or iso_utc()
    return RunCheckpoint(
        run_id=run_id,
        state=state,
        action="run",
        phase="test",
        current_batch=None,
        started_at=stamp,
        updated_at=stamp,
        last_activity=stamp,
        completed_test_ids=[],
        failed_test_ids=[],
        pending_test_ids=["T1"] if state != "COMPLETED" else [],
        active_group_ids=[],
        manifest_path="",
        report_dir=str(report_dir),
        cleanup_state=cleanup_state,
    )


def result_payload(run_id: str, started_at: str, final_status: str = "PASS") -> dict:
    return {
        "schema_version": 1,
        "run": {
            "run_id": run_id,
            "started_at": started_at,
            "final_status": final_status,
        },
        "summary": {"counts": {}},
        "results": [],
        "cleanup": {"complete": True},
    }


def test_cleanup_does_not_skip_newer_corrupt_checkpoint_behind_completed_run(tmp_path):
    store = StateStore(tmp_path / "reports")
    old = checkpoint("old-incomplete", store.run_dir("old-incomplete"))
    store.save(old)
    corrupt = store.run_dir("newer-corrupt") / "state.json"
    corrupt.write_text("{broken", encoding="utf-8")
    completed = checkpoint(
        "newest-completed",
        store.run_dir("newest-completed"),
        state="COMPLETED",
        cleanup_state="COMPLETE",
    )
    store.save(completed)
    old_mtime = store.state_path(old.run_id).stat().st_mtime
    os.utime(corrupt, (old_mtime + 5, old_mtime + 5))
    os.utime(store.state_path(completed.run_id), (old_mtime + 10, old_mtime + 10))

    with pytest.raises(SuiteError, match="corrupt and cannot be skipped safely"):
        store.latest(incomplete_only=True)


def test_explicit_completed_run_is_not_eligible_for_recovery_cleanup(tmp_path):
    store = StateStore(tmp_path / "reports")
    item = checkpoint(
        "completed",
        store.run_dir("completed"),
        state="COMPLETED",
        cleanup_state="COMPLETE",
    )
    store.save(item)
    with pytest.raises(SuiteError, match="not eligible for recovery cleanup"):
        store.latest(run_id="completed", incomplete_only=True)


def test_checkpoint_order_uses_actual_iso_time_not_text_order(tmp_path):
    store = StateStore(tmp_path / "reports")
    earlier = checkpoint(
        "earlier",
        store.run_dir("earlier"),
        updated_at="2026-01-01T08:30:00+10:00",
    )
    later = checkpoint(
        "later",
        store.run_dir("later"),
        updated_at="2025-12-31T23:00:00Z",
    )
    store.save(earlier)
    store.save(later)
    # save() refreshes timestamps, so write the intended values after saving.
    for item in (earlier, later):
        raw = json.loads(store.state_path(item.run_id).read_text())
        raw["updated_at"] = item.updated_at
        store.state_path(item.run_id).write_text(json.dumps(raw), encoding="utf-8")
    assert store.list()[0].run_id == "later"


def test_checkpoint_identity_must_match_directory(tmp_path):
    store = StateStore(tmp_path / "reports")
    item = checkpoint("actual", store.run_dir("actual"))
    store.save(item)
    raw = json.loads(store.state_path("actual").read_text())
    raw["run_id"] = "different"
    store.state_path("actual").write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(SuiteError, match="does not match directory"):
        store.load("actual")


def test_lock_release_does_not_unlink_replacement_lock(tmp_path):
    store = StateStore(tmp_path / "reports")
    lock_path = store.run_dir("run") / "run.lock"
    with store.lock("run"):
        lock_path.unlink()
        lock_path.write_text("replacement", encoding="utf-8")
    assert lock_path.read_text(encoding="utf-8") == "replacement"


def _config(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "config.yml"
    path.write_text(body, encoding="utf-8")
    return path


def test_online_reporting_removes_disabled_stale_html_and_junit(
    config_factory, tmp_path
):
    config = config_factory(
        report_dir=tmp_path / "reports",
        action="cleanup",
        html_report_enabled=False,
        junit_report_enabled=False,
    )
    reporter = Reporter(config, "stale-output")
    reporter.html_report_path.write_text("old html", encoding="utf-8")
    reporter.junit_report_path.write_text("old junit", encoding="utf-8")
    reporter.cleanup_summary.update({"attempted": True, "complete": True})
    assert reporter.finalize(0) == 0
    assert not reporter.html_report_path.exists()
    assert not reporter.junit_report_path.exists()


def test_structured_report_failure_repairs_results_json_status(
    config_factory, tmp_path, monkeypatch
):
    import neutron_flux.reporting as reporting

    config = config_factory(report_dir=tmp_path / "reports", action="run")
    reporter = Reporter(config, "render-failure")
    reporter.cleanup_summary.update({"attempted": True, "complete": True})
    monkeypatch.setattr(
        reporting,
        "write_structured_reports",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("renderer exploded")),
    )
    assert reporter.finalize(0) != 0
    payload = json.loads(reporter.results_path.read_text(encoding="utf-8"))
    assert payload["run"]["final_status"] == "ERROR"
    assert "renderer exploded" in payload["error"]
    assert not reporter.html_report_path.exists()
    assert not reporter.junit_report_path.exists()


def test_dashboard_model_attribute_error_cannot_destroy_results_json(
    config_factory, tmp_path, monkeypatch
):
    import neutron_flux.reporting_components.html as html

    config = config_factory(report_dir=tmp_path / "reports", action="run")
    reporter = Reporter(config, "dashboard-model-failure")
    reporter.cleanup_summary.update({"attempted": True, "complete": True})
    monkeypatch.setattr(
        html,
        "build_dashboard_model",
        lambda _payload: (_ for _ in ()).throw(AttributeError("bad dashboard shape")),
    )

    assert reporter.finalize(0) != 0
    payload = json.loads(reporter.results_path.read_text(encoding="utf-8"))
    assert payload["run"]["final_status"] == "ERROR"
    assert payload["dashboard"]["available"] is False
    assert "bad dashboard shape" in payload["dashboard"]["error"]
    assert "bad dashboard shape" in payload["error"]
    assert not reporter.html_report_path.exists()
    assert not reporter.junit_report_path.exists()


def test_equal_severity_final_status_transition_is_changed():
    before = result_payload("before", "2026-01-01T00:00:00Z", "ERROR")
    after = result_payload("after", "2026-01-02T00:00:00Z", "SETUP FAILED")
    change = compare_payloads(before, after)["run_changes"]["final_status"]
    assert change["assessment"] == "changed"


def test_trend_invalid_timestamp_cannot_become_latest(tmp_path):
    bad = tmp_path / "bad.json"
    good = tmp_path / "good.json"
    bad.write_text(json.dumps(result_payload("bad", "not-a-time")), encoding="utf-8")
    good.write_text(
        json.dumps(result_payload("good", "2026-01-02T00:00:00Z")),
        encoding="utf-8",
    )
    trend = trend_payload([good, bad])
    assert trend["summary"]["latest_run"] == "good"


def test_trend_rejects_duplicate_run_ids(tmp_path):
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_text(
        json.dumps(result_payload("same", "2026-01-01T00:00:00Z")),
        encoding="utf-8",
    )
    second.write_text(
        json.dumps(result_payload("same", "2026-01-02T00:00:00Z")),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate run IDs"):
        trend_payload([first, second])


def test_live_continuity_incomplete_or_unparseable_evidence_is_unverified(
    config_factory,
):
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
            endpoint_ready=True,
            details={
                "migration_mode": "live",
                "continuity": {
                    "available": True,
                    "health": "warning",
                    "full_migration_window": False,
                    "icmp": {"total": 0, "loss_pct": None, "longest_outage_s": 0},
                    "tcp": {"connected": False, "survived": False},
                    "udp": {"response": {"loss_pct": "invalid"}},
                },
            },
        )

    builder = SimpleNamespace(
        select_compute_migration_targets=lambda *args, **kwargs: ([target], "eligible"),
        live_migrate_endpoint=live,
    )
    config = config_factory(action="run", migration_mode="live-only")
    executor, spec, recorded = _placement_executor(config, source, destination, builder)
    executor._run_compute_placement_validation(
        [spec],
        SimpleNamespace(run_specs=lambda specs: None),
        dependencies=("placement-group",),
    )
    result = next(
        item
        for item in recorded
        if item.scenario == "Live migration network continuity"
    )
    assert result.status == "UNVERIFIED"
    assert result.observed == "continuity-evidence-incomplete"


def test_live_continuity_nonfinite_losses_are_unverified(config_factory):
    source = endpoint("source-nan", "A")
    destination = endpoint("destination-nan", "B")
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
            endpoint_ready=True,
            details={
                "migration_mode": "live",
                "continuity": {
                    "available": True,
                    "full_migration_window": True,
                    "icmp": {"samples": 3, "loss_pct": float("nan")},
                    "tcp": {"connected": True, "survived": True},
                    "udp": {"response": {"loss_pct": float("inf")}},
                },
            },
        )

    builder = SimpleNamespace(
        select_compute_migration_targets=lambda *args, **kwargs: ([target], "eligible"),
        live_migrate_endpoint=live,
    )
    executor, spec, recorded = _placement_executor(
        config_factory(action="run", migration_mode="live-only"),
        source,
        destination,
        builder,
    )
    executor._run_compute_placement_validation(
        [spec],
        SimpleNamespace(run_specs=lambda specs: None),
        dependencies=("placement-group",),
    )
    item = next(
        x for x in recorded if x.scenario == "Live migration network continuity"
    )
    assert item.status == "UNVERIFIED"


def test_underscore_prefixed_generated_run_namespace_remains_valid(tmp_path):
    store = StateStore(tmp_path / "reports")
    assert store.run_dir("_lab-20260101") == store.runs_dir / "_lab-20260101"


def test_symlinked_run_directory_is_rejected(config_factory, tmp_path):
    reports = tmp_path / "reports"
    outside = tmp_path / "outside"
    outside.mkdir()
    runs = reports / "runs"
    runs.mkdir(parents=True)
    (runs / "redirect").symlink_to(outside, target_is_directory=True)
    store = StateStore(reports)
    with pytest.raises(SuiteError, match="symbolic link"):
        store.state_path("redirect")
    with pytest.raises(SuiteError, match="symbolic link"):
        Reporter(config_factory(report_dir=reports), "redirect")


def test_report_directory_file_is_reported_as_suite_error(tmp_path):
    path = tmp_path / "not-a-directory"
    path.write_text("file", encoding="utf-8")
    with pytest.raises(
        SuiteError, match="Could not prepare Neutron Flux report directory"
    ):
        StateStore(path)


def test_failed_run_with_completed_cleanup_is_not_recovery_eligible(tmp_path):
    store = StateStore(tmp_path / "reports")
    item = checkpoint(
        "report-failed",
        store.run_dir("report-failed"),
        state="FAILED",
        cleanup_state="COMPLETE",
    )
    store.save(item)
    with pytest.raises(SuiteError, match="No incomplete"):
        store.latest(incomplete_only=True)


def test_results_loader_rejects_missing_run_id_and_non_object_rows(tmp_path):
    from neutron_flux.results_io import load_results

    missing = tmp_path / "missing.json"
    missing.write_text(
        json.dumps({"schema_version": 1, "run": {}, "results": []}),
        encoding="utf-8",
    )
    with pytest.raises(SuiteError, match="no run.run_id"):
        load_results(missing)

    invalid = tmp_path / "invalid.json"
    invalid.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "run": {"run_id": "run", "final_status": "PASS"},
                "results": ["not-an-object"],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(SuiteError, match="non-object result entries"):
        load_results(invalid)


def test_offline_output_directory_file_returns_controlled_cli_error(tmp_path, capsys):
    source = tmp_path / "results.json"
    source.write_text(
        json.dumps(result_payload("run", "2026-01-01T00:00:00Z")),
        encoding="utf-8",
    )
    output = tmp_path / "output-file"
    output.write_text("not a directory", encoding="utf-8")
    from neutron_flux.cli import main

    rc = main(["report", str(source), "--output-dir", str(output)])
    captured = capsys.readouterr()
    assert rc != 0
    assert "output-file" in captured.err


@pytest.mark.parametrize(
    ("state", "cleanup_state"),
    [("CLEANING", "RUNNING"), ("TESTS_COMPLETE", "NOT_STARTED")],
)
def test_cleanup_crash_states_are_recovery_eligible(tmp_path, state, cleanup_state):
    store = StateStore(tmp_path / "reports")
    item = checkpoint(
        f"recover-{state.lower()}",
        store.run_dir(f"recover-{state.lower()}"),
        state=state,
        cleanup_state=cleanup_state,
    )
    # TESTS_COMPLETE may have no pending tests after all probes finish.
    item.pending_test_ids = []
    store.save(item)
    assert store.latest(incomplete_only=True).run_id == item.run_id


def test_run_lock_is_held_before_reporter_or_checkpoint_writes(
    config_factory, tmp_path, monkeypatch
):
    from contextlib import contextmanager

    from neutron_flux import cli

    lock_state = {"held": False}

    class Store:
        def __init__(self, report_dir):
            self.report_dir = report_dir
            self.saved = []
            self.corrupt_state_files = []

        @contextmanager
        def lock(self, run_id):
            lock_state["held"] = True
            try:
                yield
            finally:
                lock_state["held"] = False

        def save(self, item):
            assert lock_state["held"] is True
            self.saved.append(item)

    class Log:
        def section(self, message):
            pass

        def log(self, message, level="INFO"):
            pass

    class LockedReporter:
        def __init__(self, config, run_id, load_existing=False):
            assert lock_state["held"] is True
            self.run_id = run_id
            self.run_dir = config.report_dir / "runs" / run_id
            self.run_dir.mkdir(parents=True, exist_ok=True)
            self.manifest_path = self.run_dir / "manifest.jsonl"
            self.manifest_path.touch()
            self.logger = Log()
            self.results = []
            self.setup_failed = False
            self.setup_failures = []
            self.error = None
            self.interrupted = False
            self.cleanup_summary = {"complete": True, "errors": [], "leftovers": []}

        def finalize(self, code):
            return code

    class Suite:
        def __init__(self, config, reporter, state_store, checkpoint):
            self.reporter = reporter

        def execute(self):
            return 0

        def cleanup_if_required(self, successful):
            return True

    config = config_factory(action="plan", report_dir=tmp_path / "reports")
    monkeypatch.setattr(cli.Config, "from_args", mock.Mock(return_value=config))
    monkeypatch.setattr(cli, "StateStore", Store)
    monkeypatch.setattr(cli, "Reporter", LockedReporter)
    monkeypatch.setattr(cli, "Suite", Suite)
    monkeypatch.setattr(cli.signal, "signal", lambda *args: None)
    assert cli.main(["plan"]) == 0
    assert lock_state["held"] is False


def test_symlinked_runs_root_is_rejected(config_factory, tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    outside = tmp_path / "outside-runs"
    outside.mkdir()
    (reports / "runs").symlink_to(outside, target_is_directory=True)
    with pytest.raises(SuiteError, match="Runs directory must not be a symbolic link"):
        StateStore(reports)
    with pytest.raises(SuiteError, match="Runs directory must not be a symbolic link"):
        Reporter(config_factory(report_dir=reports), "run")


def test_results_loader_rejects_unknown_statuses_and_malformed_objects(tmp_path):
    from neutron_flux.results_io import load_results

    unknown = result_payload("run", "2026-01-01T00:00:00Z")
    unknown["results"] = [{"test_id": "T1", "status": "MAYBE", "details": {}}]
    path = tmp_path / "unknown.json"
    path.write_text(json.dumps(unknown), encoding="utf-8")
    with pytest.raises(SuiteError, match="invalid status"):
        load_results(path)

    malformed = result_payload("run", "2026-01-01T00:00:00Z")
    malformed["cleanup"] = []
    path.write_text(json.dumps(malformed), encoding="utf-8")
    with pytest.raises(SuiteError, match="cleanup must be an object"):
        load_results(path)

    malformed = result_payload("run", "2026-01-01T00:00:00Z")
    malformed["results"] = [{"test_id": "T1", "status": "PASS", "details": []}]
    path.write_text(json.dumps(malformed), encoding="utf-8")
    with pytest.raises(SuiteError, match="details must be an object"):
        load_results(path)


def test_fabric_cleanup_attempts_every_group_and_keeps_failed_runtime(config_factory):
    from neutron_flux.concurrent_load import ConcurrentLoadRunner
    from neutron_flux.models import PlannedGroup, RuntimeGroup

    def runtime(group_id: str) -> RuntimeGroup:
        plan = PlannedGroup(
            id=group_id,
            kind="provider",
            label=group_id,
            network_id="network",
            network_name="Provider",
            subnet_ids=["subnet"],
            families=[4],
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

    first = runtime("fabric-a")
    second = runtime("fabric-b")
    attempts: list[str] = []
    refreshes: list[list[str]] = []

    def cleanup_group(group_id: str) -> bool:
        attempts.append(group_id)
        if group_id == "fabric-b":
            raise SuiteError("temporary delete failure")
        return True

    executor = SimpleNamespace(
        config=config_factory(),
        plan=SimpleNamespace(groups=[]),
        builder=SimpleNamespace(
            runtime_groups=[first, second],
            stop_group_probes=lambda group_id: None,
        ),
        reporter=SimpleNamespace(cleanup_summary={"errors": []}),
        cleanup_manager=SimpleNamespace(cleanup_group=cleanup_group),
        logger=SimpleNamespace(log=lambda *args: None),
        active={"fabric-a": first, "fabric-b": second},
    )
    executor._refresh_checkpoint = lambda: refreshes.append(list(executor.active))
    runner = ConcurrentLoadRunner(executor)
    runner.runtimes = [first, second]

    runner._cleanup_runtimes()

    assert attempts == ["fabric-b", "fabric-a"]
    assert list(executor.active) == ["fabric-b"]
    assert executor.builder.runtime_groups == [second]
    assert runner.runtimes == [second]
    assert refreshes[-1] == ["fabric-b"]
    assert "temporary delete failure" in executor.reporter.cleanup_summary["errors"][0]
