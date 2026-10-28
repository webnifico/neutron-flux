from __future__ import annotations

import json

import pytest

from neutron_flux.errors import SuiteError
from neutron_flux.results_io import load_results


def payload(status="PASS", *, final_status="PASS"):
    return {
        "schema_version": 1,
        "run": {"run_id": "run", "final_status": final_status},
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


def write(tmp_path, value):
    path = tmp_path / "results.json"
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    return path


@pytest.mark.parametrize("status", ["FAIL", "ERROR", "BLOCKED_BY_SETUP_ERROR"])
def test_green_final_status_cannot_hide_bad_result_rows(tmp_path, status):
    with pytest.raises(SuiteError, match="contradicts"):
        load_results(write(tmp_path, payload(status)))


def test_minimal_schema_synthesizes_summary_counts(tmp_path):
    loaded = load_results(write(tmp_path, payload()))
    assert loaded["summary"]["counts"] == {"PASS": 1}
    assert loaded["summary"]["total_results"] == 1


def test_incomplete_cleanup_requires_matching_final_status(tmp_path):
    value = payload()
    value["cleanup"]["complete"] = False
    with pytest.raises(SuiteError, match="must use CLEANUP INCOMPLETE"):
        load_results(write(tmp_path, value))


def test_cleanup_incomplete_status_requires_cleanup_evidence(tmp_path):
    value = payload(final_status="CLEANUP INCOMPLETE")
    with pytest.raises(SuiteError, match="cleanup.complete=false"):
        load_results(write(tmp_path, value))
