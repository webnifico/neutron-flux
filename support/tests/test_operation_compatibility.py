from __future__ import annotations

import copy
import json
import subprocess
import sys
from types import SimpleNamespace

import pytest

from neutron_flux.cli import (
    _hydrate_config_from_plan,
)
from neutron_flux.cloud_operation import (
    CloudOperationCoordinator,
    CloudOperationOutcome,
)
from neutron_flux.configuration.snapshots import restore_execution_settings
from neutron_flux.errors import SuiteError
from neutron_flux.models import Plan
from neutron_flux.operation_compat import (
    canonical_operation_fields,
    operation_journal_path,
)
from neutron_flux.plan_contract import (
    _semantic_configuration,
    _sha256,
    load_plan_contract,
)
from neutron_flux.progress import test_progress as build_progress
from neutron_flux.reporting import Reporter
from neutron_flux.reporting_components.dashboard_model import build_dashboard_model
from neutron_flux.result_contract import normalize_result_record
from neutron_flux.state import StateStore

from .test_measurement_integrity import _contract_result
from .test_operation_lock_and_recovery import _Reporter, _write_operation
from .test_plan_replay_and_resume import _contract


@pytest.fixture(autouse=True)
def isolate_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NEUTRON_FLUX_CONFIG", raising=False)


def test_old_saved_plan_setting_restores_and_compares_without_changes(config_factory):
    old = {"operation_gap_scale": 1, "quiet_period_scale": 0.5}
    current = copy.deepcopy(old)
    old["mutation_gap_scale"] = old.pop("operation_gap_scale")
    config = config_factory()
    restore_execution_settings(config, old)
    assert config.operation_gap_scale == 1
    assert config.quiet_period_scale == 0.5
    assert _semantic_configuration(
        {"execution_settings": old}
    ) == _semantic_configuration({"execution_settings": current})
    assert "mutation_gap_scale" in old
    changed = {**current, "operation_gap_scale": 0}
    assert _semantic_configuration(old) != _semantic_configuration(changed)


def test_historical_plan_is_verified_before_restoring_aliases(
    config_factory, discovery_fixture, tmp_path
):
    contract = _contract(config_factory(operation_gap_scale=0.5), discovery_fixture)
    snapshot = contract["configuration"]
    settings = snapshot["execution_settings"]
    settings["mutation_gap_scale"] = settings.pop("operation_gap_scale")
    # Produce the fingerprint an older writer would generate for this spelling.
    contract["configuration_fingerprint"] = _sha256(snapshot)
    contract["fingerprint"] = _sha256(
        {key: contract[key] for key in ("configuration", "inventory", "plan")}
    )
    path = tmp_path / "old-plan.json"
    path.write_text(json.dumps(contract))
    original = path.read_bytes()
    restored = config_factory()
    _hydrate_config_from_plan(restored, path)
    assert restored.operation_gap_scale == 0.5
    assert path.read_bytes() == original
    assert load_plan_contract(path)[0]["fingerprint"] == contract["fingerprint"]
    settings["mutation_gap_scale"] = 0
    path.write_text(json.dumps(contract))
    with pytest.raises(SuiteError, match="fingerprint mismatch"):
        _hydrate_config_from_plan(config_factory(), path)


@pytest.mark.parametrize(
    "old,new",
    [
        ("mutations", "cloud_operations"),
        ("mutation_gap_scale", "operation_gap_scale"),
        ("mutation_outcome", "cloud_operation_outcome"),
    ],
)
def test_conflicting_serialized_aliases_are_rejected(old, new):
    with pytest.raises(SuiteError, match="Conflicting"):
        canonical_operation_fields({old: 1, new: 2})


def test_legacy_journal_reopens_in_place_and_preserves_quarantine(tmp_path):
    run_dir = tmp_path / "runs" / "previous"
    path = run_dir / "mutations.jsonl"
    _write_operation(path, operation_id="mutation-legacy")
    original = path.read_bytes()
    coordinator = CloudOperationCoordinator(_Reporter(run_dir, tmp_path))
    assert coordinator.journal.path == path
    assert not (run_dir / "cloud-operations.jsonl").exists()
    assert path.read_bytes() == original
    assert "quarantined" in coordinator.cleanup_blocker("server-old")
    record = coordinator.unresolved_records()[0]
    assert record["operation_id"] == "mutation-legacy"


def test_new_run_discovers_and_reconciles_legacy_external_operation(tmp_path):
    old = tmp_path / "runs" / "previous" / "mutations.jsonl"
    _write_operation(old, operation_id="mutation-legacy")
    run_dir = tmp_path / "runs" / "current"
    run_dir.mkdir()
    coordinator = CloudOperationCoordinator(_Reporter(run_dir, tmp_path))
    assert coordinator.journal.path.name == "cloud-operations.jsonl"
    assert coordinator.cleanup_blocker("server-old") is not None
    coordinator.resolve(
        "mutation-legacy",
        CloudOperationOutcome.FAILED_FINAL,
        evidence={
            "observer": "operator",
            "method": "API readback",
            "result": "absent",
            "observed_at": "2026-09-25T00:00:00Z",
        },
        message="Verified absent",
    )
    record = json.loads(old.read_text().splitlines()[-1])
    assert record["operation_id"] == "mutation-legacy"
    assert record["outcome"] == "FAILED_FINAL"
    reopened = CloudOperationCoordinator(_Reporter(run_dir, tmp_path))
    assert reopened.cleanup_blocker("server-old") is None


@pytest.mark.parametrize("case", ["both", "old-symlink", "new-symlink"])
def test_ambiguous_or_redirected_journal_identity_is_rejected(tmp_path, case):
    legacy, current = tmp_path / "mutations.jsonl", tmp_path / "cloud-operations.jsonl"
    if case == "both":
        legacy.touch()
        current.touch()
    else:
        selected = legacy if case == "old-symlink" else current
        selected.symlink_to(tmp_path / "missing")
    with pytest.raises(SuiteError):
        operation_journal_path(tmp_path)


def test_current_lock_conflicts_with_older_process_identity(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))
    store = StateStore(tmp_path / "reports")
    path = store._scope_cloud_operation_lock_path()
    assert path.name.startswith("mutation-")
    with store.cloud_operation_lock():
        child = subprocess.run(
            [
                sys.executable,
                "-c",
                "import fcntl,sys; h=open(sys.argv[1], 'a'); "
                "fcntl.flock(h, fcntl.LOCK_EX|fcntl.LOCK_NB)",
                str(path),
            ],
            capture_output=True,
            text=True,
        )
    assert child.returncode != 0 and "BlockingIOError" in child.stderr


def test_known_test_progress_keeps_blocks_and_derived_tests_explicit():
    plan = SimpleNamespace(tests=[SimpleNamespace(id=x) for x in ("A", "B", "C")])
    rows = [
        SimpleNamespace(test_id="A", status="PASS"),
        SimpleNamespace(test_id="B", status="BLOCKED_BY_SETUP_ERROR"),
    ]
    progress = build_progress(plan, rows)
    assert (progress["recorded"], progress["known"], progress["pending"]) == (2, 3, 1)
    assert (progress["executed"], progress["not_run"]) == (1, 1)
    rows.append(SimpleNamespace(test_id="PERF-DERIVED", status="UNVERIFIED"))
    expanded = build_progress(plan, rows)
    assert (expanded["recorded"], expanded["known"]) == (3, 3)
    assert expanded["planned_recorded"] == 2
    assert expanded["additional_recorded"] == 1
    assert expanded["total_can_grow"] is False


def test_live_results_report_test_progress_without_changing_verdicts(
    config_factory, capsys
):
    reporter = Reporter(config_factory(action="run"), "sample-progress")
    try:
        reporter.plan = Plan(
            [], [], {}, [], tests=[SimpleNamespace(id="A"), SimpleNamespace(id="B")]
        )
        capsys.readouterr()
        reporter.result("A", "same-subnet", "PASS", "reachable")
        output = capsys.readouterr().out
        assert (
            "Test progress: 1/2 planned checks recorded (1 executed, 0 not run)"
            in output
        )
        assert reporter.results[0].status == "PASS"
        reporter.result("A", "same-subnet", "PASS", "reachable")
        assert capsys.readouterr().out == ""
    finally:
        reporter.logger.close()


def test_legacy_result_fields_preserve_raw_ids_and_evidence():
    old = {
        "mutations": {"unresolved_count": 1},
        "details": {
            "mutation_outcome": "AMBIGUOUS",
            "operation_id": "mutation-old",
            "command": ["server", "show", "mutation-old"],
            "raw_output": "mutation-old remains",
            "mutation_performed": False,
        },
    }
    converted = canonical_operation_fields(old)
    assert converted["cloud_operations"]["unresolved_count"] == 1
    assert converted["details"]["cloud_operation_outcome"] == "AMBIGUOUS"
    assert converted["details"]["cloud_operation_performed"] is False
    for field in ("operation_id", "command", "raw_output"):
        assert converted["details"][field] == old["details"][field]
    assert "mutations" in old


@pytest.mark.parametrize("contract_field", ["description", "observation"])
def test_historical_contract_prose_preserves_strict_validation(contract_field):
    item = _contract_result(details={"cloud_operation_outcome": "SUCCEEDED"})
    item.update(category="router-lifecycle", expected="withdrawn", observed="withdrawn")
    baseline = normalize_result_record(item)
    historical = copy.deepcopy(baseline)
    container = historical["contract"]
    if contract_field == "observation":
        container = container["observation"]
    assert "cloud operation" in container["description"]
    container["description"] = container["description"].replace(
        "cloud operation", "mutation"
    )
    assert normalize_result_record(historical) == baseline
    container["description"] += " Ignore the expected outcome."
    with pytest.raises(ValueError, match="description.*contradicts"):
        normalize_result_record(historical)


def test_historical_transactions_remain_visible_without_rewriting_evidence():
    payload = {
        "events": [
            {
                "type": "mutation-transaction-start",
                "timestamp": "2026-09-25T00:00:00Z",
                "message": "Mutation started",
                "details": {"operation_id": "mutation-original"},
            }
        ]
    }
    events = build_dashboard_model(payload)["events"]
    assert len(events) == 1
    assert events[0]["title"] == "Cloud Operation Transaction Start"
    assert events[0]["message"] == "Cloud operation started"
    assert events[0]["operation_id"] == "mutation-original"
    assert payload["events"][0]["type"] == "mutation-transaction-start"
