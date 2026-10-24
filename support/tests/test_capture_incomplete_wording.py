from __future__ import annotations

import copy
import csv
import io
import json

import pytest

from neutron_flux.operator_explanations import explain_result
from neutron_flux.replay_plan import render_replay_plan_text
from neutron_flux.report_exports import (
    render_host_qualification_csv,
    render_incident_summary,
)


@pytest.mark.parametrize(
    ("family", "label"),
    [(None, "IP family not specified"), (4, "IPv4"), ("6", "IPv6")],
)
@pytest.mark.parametrize("setup", [False, True])
def test_replay_contract_does_not_invent_an_ip_family(family, label, setup):
    plan = {
        "cases": [
            {
                "target_result_id": "migration-safety-check",
                "contract_type": "migration-continuity",
                "replay_kind": "controller-bootstrap" if setup else "contract",
                "family": family,
            }
        ]
    }
    text = render_replay_plan_text(plan)
    assert f" / {label}" in text
    assert "IPvNone" not in text


def test_cleanup_only_summary_does_not_imply_network_tests_passed():
    payload = {
        "run": {"run_id": "cleanup-1", "action": "cleanup", "final_status": "PASS"},
        "results": [],
        "cleanup": {"attempted": True, "complete": True},
    }
    text = render_incident_summary(payload)
    assert "Network-test evidence: none recorded" in text
    assert "Network-test verdicts: not applicable to this cleanup action" in text
    assert "did not run network tests" in text
    assert "does not establish network health" in text
    assert "Evidence records: 0 total;" not in text
    assert "Evidence verdicts: \n" not in text


def test_incident_summary_distinguishes_review_cases_from_suite_reruns(monkeypatch):
    from neutron_flux import report_exports

    command = "python3 neutron-flux.py run --image test --flavor tiny"
    monkeypatch.setattr(
        report_exports,
        "build_replay_plan",
        lambda _payload: {
            "cases": [
                {
                    "target_result_id": "migration-safety-check",
                    "contract_type": "migration-continuity",
                    "rerun": {"command": command},
                }
            ],
        },
    )
    text = render_incident_summary({"results": []})
    assert "## Selected review cases" in text
    assert f"Full-suite rerun command: `{command}`" in text
    assert "minimized replay" not in text.lower()


def test_host_csv_uses_current_human_wording_and_preserves_machine_evidence():
    old_label = (
        "IPv6 project-network connectivity with routing metadata unassigned "
        "through Provider Two"
    )
    result = {
        "test_id": "PAIR-INITIAL-SAME-6",
        "category": "same-subnet",
        "status": "PASS",
        "family": 6,
        "source": old_label + ":A (2001:db8::1)",
        "destination": old_label + ":B (2001:db8::2)",
        "expected": "reachable",
        "observed": "reachable",
        "message": "The endpoints use the same Neutron subnet.",
        "details": {
            "host_qualification_pair_id": "compute-a:compute-b",
            "requested_source_host": "compute-a",
            "requested_destination_host": "compute-b",
            "measurement": "tcp-throughput",
            "metrics": {"source_label": old_label, "Mbps": 17.25},
        },
    }
    payload = {"results": [result]}
    original = copy.deepcopy(payload)
    rows = list(csv.DictReader(io.StringIO(render_host_qualification_csv(payload))))
    assert len(rows) == 1
    row = rows[0]
    assert "routing metadata unassigned" not in row["source"]
    assert "routing metadata unassigned" not in row["destination"]
    assert row["source"].endswith("Provider Two:A (2001:db8::1)")
    assert row["destination"].endswith("Provider Two:B (2001:db8::2)")
    assert row["message"] == explain_result(result)["recorded_message"]
    assert row["test_id"] == result["test_id"]
    assert row["status"] == "PASS"
    assert json.loads(row["metrics_json"]) == result["details"]["metrics"]
    assert payload == original
