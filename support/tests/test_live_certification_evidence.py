from __future__ import annotations

import json

import pytest

from neutron_flux.result_contract import normalize_result_record

from .test_live_certification import _load_module, _orphan_payload


@pytest.fixture(scope="module")
def live_certify():
    return _load_module()


def _run_evidence(
    report_dir, run_id="run-evidence", *, final_status="PASS WITH WARNINGS"
):
    run_dir = report_dir / "runs" / run_id
    lane_dir = (
        run_dir / "zones" / "az-zone-a" / "state" / "runs" / f"{run_id}-az-zone-a"
    )
    lane_dir.mkdir(parents=True)
    checkpoint = {
        "state": "COMPLETED",
        "cleanup_state": "COMPLETE",
        "pending_test_ids": [],
        "failed_test_ids": [],
        "error": None,
    }
    lane = {**checkpoint, "metadata": {"availability_zone": "zone-a"}}
    payload = {
        "run": {"final_status": final_status},
        "cleanup": {
            "complete": True,
            "errors": [],
            "leftovers": [],
            "unresolved_operations": [],
        },
        "resources": [{"id": "owned-server", "delete_status": "deleted"}],
        "cloud_operations": {
            "unresolved_count": 0,
            "unresolved_operation_ids": [],
            "external_unresolved_operations": [],
        },
        "plan": {
            "tests": [{"id": "check", "metadata": {"availability_zone": "zone-a"}}],
            "checks": [{"id": "check"}, {"id": "conditional"}],
        },
        "planned_check_ledger": [
            {
                "id": "check",
                "outcome": "PASSED",
                "reason": "observed successful probe",
                "evidence_ids": ["sample"],
            },
            {
                "id": "conditional",
                "outcome": "INAPPLICABLE",
                "reason": "fragmentation was unnecessary",
                "evidence_ids": ["conditional-sample"],
            },
        ],
        "coverage_ledger": [
            {"id": "sample", "outcome": "PASSED"},
            {"id": "conditional-sample", "outcome": "INAPPLICABLE"},
        ],
        "results": [
            {"test_id": "sample", "status": "PASS"},
            {"test_id": "conditional-sample", "status": "NOT_APPLICABLE"},
        ],
        "error": None,
        "setup_failures": [],
    }
    for check in payload["plan"]["checks"]:
        check.update(condition="required", kind="network", stage="intra")
    payload["plan"]["tests"] = [
        {
            "id": "sample",
            "metadata": {"availability_zone": "zone-a", "planned_check_id": "check"},
        },
        {
            "id": "conditional-sample",
            "metadata": {
                "availability_zone": "zone-a",
                "planned_check_id": "conditional",
            },
        },
    ]
    for row in payload["planned_check_ledger"]:
        row["result_id"] = row["evidence_ids"][0]
    for row in payload["results"]:
        row.update(
            details={},
            observed="ok",
            message=next(
                check["reason"]
                for check in payload["planned_check_ledger"]
                if check["result_id"] == row["test_id"]
            ),
        )
    for row in payload["coverage_ledger"]:
        row["result_id"] = row["id"]
    return run_dir, lane_dir, checkpoint, lane, payload


def _write_evidence(evidence):
    run_dir, lane_dir, checkpoint, lane, payload = evidence
    (run_dir / "state.json").write_text(json.dumps(checkpoint), encoding="utf-8")
    (run_dir / "results.json").write_text(json.dumps(payload), encoding="utf-8")
    (lane_dir / "state.json").write_text(json.dumps(lane), encoding="utf-8")


def _add_bound_retry(payload, status, *, tool_failure=False):
    details = {"planned_check_id": "check", "check_sample": True}
    if tool_failure:
        details["tool_failure"] = True
    payload["plan"]["tests"].append({"id": "retry", "metadata": details.copy()})
    payload["results"].append(
        {
            "test_id": "retry",
            "status": status,
            "details": details,
            "observed": "earlier-attempt",
            "message": "Earlier supporting attempt",
        }
    )
    payload["planned_check_ledger"][0]["evidence_ids"].append("retry")
    payload["coverage_ledger"].append(
        {
            "id": "retry",
            "result_id": "retry",
            "outcome": {
                "PASS": "PASSED",
                "FAIL": "FAILED",
                "ERROR": "FAILED",
                "UNVERIFIED": "INCONCLUSIVE",
                "NOT_RUN_CANCELLED": "NEVER_RAN",
            }[status],
        }
    )


@pytest.mark.parametrize("status", ["FAIL", "ERROR", "UNVERIFIED", "NOT_RUN_CANCELLED"])
@pytest.mark.parametrize("contracted", [False, True])
def test_live_certification_grades_approved_terminal_check_and_keeps_raw_retry(
    live_certify, tmp_path, status, contracted
):
    evidence = _run_evidence(tmp_path)
    _add_bound_retry(evidence[4], status)
    if contracted:
        evidence[4]["results"] = [
            normalize_result_record(row) for row in evidence[4]["results"]
        ]
    _write_evidence(evidence)
    outcome = live_certify._outcome("successful", tmp_path, "run-evidence", 0)
    live_certify.validate_successful_outcome(outcome)
    assert outcome.evidence_verified is True
    assert (
        json.loads((evidence[0] / "results.json").read_text())["results"][-1]["status"]
        == status
    )


@pytest.mark.parametrize(
    "fault",
    [
        "failed-primary",
        "tool-error",
        "concealed-tool-error",
        "contradictory-support-contract",
        "false-coverage",
        "unapproved-retry",
    ],
)
def test_live_certification_cannot_hide_terminal_or_tool_failure_as_support(
    live_certify, tmp_path, fault
):
    evidence = _run_evidence(tmp_path)
    payload = evidence[4]
    tool_error = fault in {"tool-error", "concealed-tool-error"}
    _add_bound_retry(
        payload, "ERROR" if tool_error else "PASS", tool_failure=tool_error
    )
    if fault == "failed-primary":
        payload["results"][0]["status"] = "FAIL"
        payload["coverage_ledger"][0]["outcome"] = "FAILED"
    elif fault == "false-coverage":
        payload["results"][-1]["status"] = "FAIL"
    elif fault == "concealed-tool-error":
        payload["results"][-1]["contract"] = {"verdict": {"state": "PASS"}}
        payload["coverage_ledger"][-1]["outcome"] = "PASSED"
    elif fault == "contradictory-support-contract":
        payload["results"][-1]["status"] = "FAIL"
        payload["results"][-1]["contract"] = {"verdict": {"state": "PASS"}}
    elif fault == "unapproved-retry":
        payload["plan"]["tests"][-1]["metadata"].pop("check_sample")
    _write_evidence(evidence)
    outcome = live_certify._outcome("successful", tmp_path, "run-evidence", 0)
    assert outcome.evidence_verified is False


def test_live_certification_accepts_proven_warnings_and_explicit_inapplicability(
    live_certify, tmp_path
):
    evidence = _run_evidence(tmp_path)
    _write_evidence(evidence)
    outcome = live_certify._outcome("successful", tmp_path, "run-evidence", 0)
    live_certify.validate_successful_outcome(outcome)
    assert outcome.evidence_verified is True
    assert outcome.final_status == "PASS WITH WARNINGS"


@pytest.mark.parametrize(
    "fault",
    [
        "stale-zone",
        "missing-zone",
        "root-pending",
        "zone-pending",
        "zone-error",
        "unverified-delete",
        "unresolved-operation",
        "missing-check",
        "duplicate-check",
        "blocked-check",
        "missing-evidence",
        "empty-inapplicable-reason",
        "unverified-result",
        "missing-coverage",
        "execution-error",
        "incomplete-cleanup",
    ],
)
def test_live_certification_rejects_false_success_from_durable_report_evidence(
    live_certify, tmp_path, fault
):
    evidence = _run_evidence(tmp_path)
    run_dir, lane_dir, checkpoint, lane, payload = evidence
    if fault == "stale-zone":
        lane.update(state="RUNNING", cleanup_state="NOT_STARTED")
    elif fault == "missing-zone":
        payload["plan"]["tests"][0]["metadata"]["availability_zone"] = "missing-zone"
    elif fault == "root-pending":
        checkpoint["pending_test_ids"] = ["unfinished"]
    elif fault == "zone-pending":
        lane["pending_test_ids"] = ["unfinished"]
    elif fault == "zone-error":
        lane["error"] = "original lane failure"
    elif fault == "unverified-delete":
        payload["resources"][0]["delete_status"] = None
    elif fault == "unresolved-operation":
        payload["cloud_operations"]["external_unresolved_operations"] = [
            "accepted-unresolved"
        ]
    elif fault == "missing-check":
        payload["planned_check_ledger"].pop()
    elif fault == "duplicate-check":
        payload["planned_check_ledger"].append(payload["planned_check_ledger"][0])
    elif fault == "blocked-check":
        payload["planned_check_ledger"][0]["outcome"] = "BLOCKED"
    elif fault == "missing-evidence":
        payload["planned_check_ledger"][0]["evidence_ids"] = ["missing-sample"]
    elif fault == "empty-inapplicable-reason":
        payload["planned_check_ledger"][1]["reason"] = ""
    elif fault == "unverified-result":
        payload["results"][0]["status"] = "UNVERIFIED"
    elif fault == "missing-coverage":
        payload["coverage_ledger"] = []
    elif fault == "execution-error":
        payload["error"] = "tool error"
    elif fault == "incomplete-cleanup":
        payload["cleanup"]["complete"] = False
    _write_evidence(evidence)
    outcome = live_certify._outcome("successful", tmp_path, "run-evidence", 0)
    assert outcome.evidence_verified is False
    with pytest.raises(
        live_certify.CertificationError, match="evidence validation failed"
    ):
        live_certify.validate_successful_outcome(outcome)


def test_live_certification_failure_recovery_preserves_original_state_and_uses_independent_cleanup_proof(
    live_certify, tmp_path
):
    original = _run_evidence(tmp_path, final_status="ERROR")
    original[2].update(
        state="CLEANUP_INCOMPLETE", cleanup_state="INCOMPLETE", error="injected failure"
    )
    original[3].update(
        state="CLEANUP_INCOMPLETE", cleanup_state="INCOMPLETE", error="injected failure"
    )
    original[4]["cleanup"]["complete"] = False
    original[4]["resources"][0]["delete_status"] = None
    _write_evidence(original)
    recovered = _run_evidence(tmp_path, "recovery-cleanup", final_status="PASS")
    recovered[4]["resources"] = []
    recovered[4]["cleanup"].update(_orphan_payload()["cleanup"])
    _write_evidence(recovered)
    outcome = live_certify._outcome(
        "injected",
        tmp_path,
        "run-evidence",
        3,
        target_reached=True,
        injection_point="before-server-delete",
        recovery_cleanup_exit_code=0,
        recovery_cleanup_run_id="recovery-cleanup",
    )
    live_certify.validate_injected_outcome(outcome)
    assert outcome.checkpoint_state == "CLEANUP_INCOMPLETE"
    assert outcome.cleanup_state == "COMPLETE"
    assert (
        json.loads((original[0] / "state.json").read_text())["error"]
        == "injected failure"
    )


def test_live_certification_summary_does_not_claim_execution_resume_validation(
    live_certify, config_factory
):
    summary = live_certify._base_summary(config_factory())
    assert summary["resume_validation"]["tested"] is False
    assert "Execution resume: NOT TESTED" in live_certify._summary_text(summary)


@pytest.mark.parametrize(
    "fault",
    [
        "wrong-binding",
        "wrong-outcome",
        "missing-coverage-row",
        "wrong-coverage-outcome",
    ],
)
def test_live_certification_rejects_cross_bound_or_misreported_evidence(
    live_certify, tmp_path, fault
):
    evidence = _run_evidence(tmp_path)
    payload = evidence[4]
    if fault == "wrong-binding":
        payload["planned_check_ledger"][0].update(
            result_id="conditional-sample", evidence_ids=["conditional-sample"]
        )
    elif fault == "wrong-outcome":
        payload["planned_check_ledger"][1]["outcome"] = "PASSED"
    elif fault == "missing-coverage-row":
        payload["coverage_ledger"].pop()
    elif fault == "wrong-coverage-outcome":
        payload["coverage_ledger"][1]["outcome"] = "PASSED"
    _write_evidence(evidence)
    outcome = live_certify._outcome("successful", tmp_path, "run-evidence", 0)
    assert outcome.evidence_verified is False


def test_live_certification_stages_recovery_cleanup_proof(
    live_certify, config_factory, tmp_path
):
    report_dir = tmp_path / "reports"
    for run_id in ("failed-run", "recovery-run"):
        directory = report_dir / "runs" / run_id
        directory.mkdir(parents=True)
        (directory / "report.txt").write_text(run_id, encoding="utf-8")
    base = config_factory(report_dir=report_dir)
    summary = live_certify._base_summary(base)
    summary["runs"] = [
        {"run_id": "failed-run", "recovery_cleanup_run_id": "recovery-run"}
    ]
    destination = tmp_path / "artifacts"
    live_certify.stage_artifacts(summary, base, destination)
    assert (
        destination / "runs" / "recovery-run" / "report.txt"
    ).read_text() == "recovery-run"


def test_live_certification_accepts_explicit_saved_placement_resolution(
    live_certify, tmp_path
):
    evidence = _run_evidence(tmp_path)
    payload = evidence[4]
    payload["plan"]["checks"].append(
        {
            "id": "placement",
            "condition": "actual placement observed",
            "kind": "placement",
            "stage": "intra",
        }
    )
    payload["planned_check_ledger"].append(
        {
            "id": "placement",
            "outcome": "PASSED",
            "reason": "observed eligible opposite placement",
            "evidence_ids": [],
            "result_id": None,
        }
    )
    _write_evidence(evidence)
    resolution_path = evidence[0] / "check-outcomes.json"
    resolution_path.write_text(
        json.dumps(
            {
                "placement": {
                    "outcome": "PASSED",
                    "reason": "observed eligible opposite placement",
                }
            }
        )
    )
    outcome = live_certify._outcome("successful", tmp_path, "run-evidence", 0)
    live_certify.validate_successful_outcome(outcome)
    resolution_path.unlink()
    outcome = live_certify._outcome("successful", tmp_path, "run-evidence", 0)
    assert outcome.evidence_verified is False
