from __future__ import annotations

import copy
from collections import Counter

from neutron_flux.reporting import Reporter
from neutron_flux.reporting_components.dashboard_model import build_dashboard_model
from neutron_flux.reporting_components.report_payload import (
    _compact_cleanup,
    _compact_run,
    _recorded_route_observations,
)
from neutron_flux.results_io import render_results_text
from neutron_flux.utils import utc_now


def _payload(*, complete: bool, action: str = "cleanup") -> dict:
    return {
        "run": {"run_id": "wording-audit", "action": action, "final_status": "PASS"},
        "resources": [
            {
                "resource_type": "server",
                "id": "test-server",
                "name": "flux-test-server",
                "cleanup_state": "DELETED" if complete else "FAILED",
            }
        ],
        "results": [],
        "cleanup": {
            "attempted": True,
            "complete": complete,
            "deleted": 1 if complete else 0,
            "leftovers": []
            if complete
            else [
                "server:test-server:flux-test-server:verification-error",
                "exact-run-inventory:verification-error:server inventory failed",
                "placement-allocation:test-server:verification-error:presence unknown",
            ],
            "errors": [] if complete else ["Server presence could not be verified"],
        },
    }


def test_failed_presence_reads_are_issues_not_a_count_of_present_resources():
    payload = _payload(complete=False)
    original = copy.deepcopy(payload)
    text = render_results_text(payload)
    assert "Unresolved cleanup or verification issues: 3" in text
    assert "Tracked resource records needing cleanup or verification: 1" in text
    assert "may not represent distinct resources confirmed present" in text
    assert "3 resources remain" not in text
    assert payload == original
    model = build_dashboard_model(payload)
    assert model["summary"]["cleanup_present"] == 1  # Legacy field remains compatible.
    assert model["summary"]["cleanup_unresolved_resources"] == 1
    assert model["summary"]["cleanup_verification_issues"] == 3
    compact = _compact_cleanup(payload["cleanup"])
    assert compact["cleanup_issue_count"] == compact["verification_issue_count"] == 3


def test_cleanup_only_pass_does_not_claim_network_tests_passed():
    payload = _payload(complete=True)
    model = build_dashboard_model(payload)
    assert "no network tests ran" in " ".join(model["summary"]["narrative"])
    assert "All executed validations matched" not in " ".join(
        model["summary"]["narrative"]
    )
    assert _compact_run(payload["run"])["action"] == "cleanup"
    text = render_results_text(payload)
    assert "Explicit delete operations completed: 1" in text
    assert "Tracked resource records needing cleanup or verification: 0" in text


def test_incomplete_live_summary_counts_verification_issues(config_factory):
    reporter = Reporter(config_factory(action="cleanup"), "wording-audit")
    reporter.cleanup_summary = _payload(complete=False)["cleanup"]
    text = reporter._summary("CLEANUP INCOMPLETE", utc_now(), Counter())
    assert "INCOMPLETE; 3 unresolved cleanup or verification issues" in text
    assert "3 resources remain" not in text
    assert "UNRESOLVED CLEANUP OR VERIFICATION ISSUES" in text


def test_route_evidence_retains_stdout_after_a_multiclause_command():
    endpoint_route = {
        "command": "route_output=$(ip route get 192.0.2.9); route_rc=$?; printf '%s\\n' \"$route_output\"; exit $route_rc",
        "stdout": "192.0.2.9 via 192.0.2.1 dev ens4 src 192.0.2.7\n",
        "returncode": 0,
    }
    result = {"details": {"probe": {"diagnostics": {"endpoint_route": endpoint_route}}}}
    observations = _recorded_route_observations(result)
    assert len(observations) == 1
    assert endpoint_route["stdout"].strip() in observations[0]["output"]
    assert "exit $route_rc" in observations[0]["output"]
    endpoint_route["stdout"] = ""
    assert _recorded_route_observations(result) == []
