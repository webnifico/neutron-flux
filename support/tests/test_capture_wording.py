from __future__ import annotations

import copy

import pytest

from neutron_flux.operator_explanations import explain_result, lifecycle_explanations
from neutron_flux.result_context import result_context


@pytest.mark.parametrize("measurement", ["tcp-throughput", "latency", "mtu-mss"])
@pytest.mark.parametrize(
    ("directions", "phrase"),
    [
        (["forward"], "from source to destination"),
        (["reverse"], "from destination to source"),
        (["forward", "reverse"], "in both directions"),
        (None, "in the selected directions"),
    ],
)
def test_measurement_expectations_follow_selected_directions(
    measurement, directions, phrase
):
    result = {
        "category": "network-performance",
        "status": "PASS",
        "details": {"measurement": measurement, "path": {"directions": directions}},
    }
    original = copy.deepcopy(result)
    story = explain_result(result)
    assert phrase in story["expected"]
    if directions in (["forward"], ["reverse"], None):
        assert "both directions" not in story["expected"]
    assert result == original


def test_blocked_performance_check_describes_measurement_without_claiming_it_ran():
    result = {
        "category": "network-performance",
        "status": "BLOCKED_BY_PREREQUISITE",
        "expected": "Both TCP directions passed in the same measurement window",
        "reporting_context": {
            "measurement": "tcp-throughput",
            "pair_placement": "opposite",
        },
        "details": {"resolution_only": True},
    }
    original = copy.deepcopy(result)
    story = explain_result(result)
    assert "Complete the requested TCP transfers" in story["expected"]
    assert "did not run" in story["observed"]
    assert story["context"]["timing"] == "Planned after migration"
    assert "Measure how much TCP data" in story["context"]["purpose"]
    assert result == original


def test_local_oversized_rejection_does_not_claim_network_forwarding_limit():
    result = {
        "category": "mtu",
        "status": "PASS",
        "observed": "boundary-confirmed",
        "message": "Confirmed the advertised 1500-byte MTU boundary",
        "details": {
            "network_mtu": 1500,
            "stages": {"oversized_rejection": {"outcome": "local-mtu-rejected"}},
        },
    }
    original = copy.deepcopy(result)
    story = explain_result(result)
    assert "source rejected the larger packet locally" in story["observed"]
    assert "Confirmed the advertised" not in story["observed"]
    assert any(
        "does not establish the network's forwarding limit" in x
        for x in story["limitations"]
    )
    assert result == original


def test_not_submitted_migration_is_an_intended_move_before_migration():
    result = {
        "category": "compute-placement",
        "status": "UNVERIFIED",
        "source": "compute-a",
        "destination": "compute-b",
        "message": "Live migration was not submitted: Nova inventory was unavailable",
        "display_name": "Live-migrate one endpoint",
        "details": {"cloud_operation_outcome": "NOT_SUBMITTED"},
    }
    original = copy.deepcopy(result)
    context = result_context(result)
    story = explain_result(result)
    assert context["execution_state"] == "Migration not submitted"
    assert context["timing"] == "Before migration"
    assert (
        "Intended VM move: compute-a → compute-b; request not submitted"
        in context["lines"]
    )
    assert story["headline"] == "Migration was not submitted"
    assert "does not measure traffic during migration" in story["why_this_status"]
    assert result == original


def test_cleanup_verification_issues_are_not_counted_as_remaining_resources():
    story = lifecycle_explanations(
        {
            "cleanup": {
                "complete": False,
                "leftovers": [{"verification_error": "inventory unavailable"}],
                "errors": [],
            }
        }
    )[0]
    assert (
        "1 unresolved cleanup or verification issue; 0 cleanup errors"
        in story["what_happened"]
    )
    assert "leftover resource" not in story["what_happened"]
