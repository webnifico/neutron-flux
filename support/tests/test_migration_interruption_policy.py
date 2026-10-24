"""Successful migrations retain interruption measurements as observations."""

from __future__ import annotations

from copy import deepcopy

import pytest

from neutron_flux.constants import MIGRATION_DOWNTIME_TOLERANCE_NOTE
from neutron_flux.execution.placement_migration import PlacementMigrationMixin

from ._evidence import complete_continuity


@pytest.mark.parametrize(
    "icmp_loss,udp_loss,outage",
    [(5.0, 0.0, 0.0), (0.0, 5.0, 0.0), (5.0, 5.0, 2.0)],
)
def test_successful_migration_keeps_interruption_breaches_as_observations(
    icmp_loss, udp_loss, outage
):
    value = complete_continuity(icmp_loss=icmp_loss, udp_loss=udp_loss, outage=outage)
    original = deepcopy(value)
    status, observed, message, details = (
        PlacementMigrationMixin._live_continuity_verdict(value)
    )
    assert status == "PASS"
    assert observed == "traffic-continuity-measured"
    assert details["evidence_complete"] is True
    assert all(
        details["migration_outcomes"][component] == "PASS"
        for component in (
            "vm_placement",
            "migration_completion",
            "tcp_session",
            "traffic_recovery",
        )
    )
    assert details["migration_outcomes"]["interruption_tolerance"] == "OBSERVATION"
    assert details["continuity_failure_reasons"] == []
    assert details["interruption_observations"] == details["tolerance_failure_reasons"]
    assert details["interruption_observations"]
    assert details["interruption_tolerance_note"] == MIGRATION_DOWNTIME_TOLERANCE_NOTE
    assert MIGRATION_DOWNTIME_TOLERANCE_NOTE in message
    assert details["health"] == "warning"
    assert details["icmp"] == value["icmp"]
    assert details["udp"] == value["udp"]
    assert value == original


@pytest.mark.parametrize(
    "field",
    [
        "sampling_complete",
        "full_migration_window",
        "ready_before_migration",
        "workers_complete",
        "migration_succeeded",
        "target_server_id",
    ],
)
def test_interruption_policy_never_promotes_missing_required_evidence(field):
    value = complete_continuity(icmp_loss=5.0, udp_loss=5.0, outage=2.0)
    value.pop(field)
    status, _, _, details = PlacementMigrationMixin._live_continuity_verdict(value)
    assert status == "UNVERIFIED"
    assert details["evidence_complete"] is False
    assert details["interruption_observations"] == []


@pytest.mark.parametrize(
    "fault",
    ["migration", "tcp-reset", "tcp-delivery", "unrecovered", "wrong-interface"],
)
def test_real_migration_or_transport_failure_is_not_softened_by_loss_observations(
    fault,
):
    value = complete_continuity(
        icmp_loss=5.0, udp_loss=5.0, outage=2.0, recovered=fault != "unrecovered"
    )
    if fault == "migration":
        value["migration_succeeded"] = False
        value["migration_completion_evidence"]["migration_record_verified"] = False
    elif fault == "tcp-reset":
        value["tcp"].update(survived=False, error="ConnectionResetError")
    elif fault == "tcp-delivery":
        value["tcp"]["server_result"]["bytes"] -= 1
    elif fault == "wrong-interface":
        value["data_path_after"]["verified"] = False
    status, observed, _, details = PlacementMigrationMixin._live_continuity_verdict(
        value
    )
    assert status == "FAIL"
    assert observed == (
        "migration-validation-failed"
        if fault in {"migration", "wrong-interface"}
        else "traffic-interrupted"
    )
    assert details["continuity_failure_reasons"]
    assert details["interruption_observations"] == []


@pytest.mark.parametrize("tcp_reset", [False, True])
def test_completed_move_with_down_port_keeps_validation_and_traffic_distinct(tcp_reset):
    value = complete_continuity(udp_loss=0.02)
    value["migration_succeeded"] = False
    value["migration_completion_evidence"]["port_binding_verified"] = False
    if tcp_reset:
        value["tcp"].update(survived=False, error="ConnectionResetError")
    original = deepcopy(value)
    status, observed, message, details = (
        PlacementMigrationMixin._live_continuity_verdict(value)
    )
    assert status == "FAIL"
    assert observed == (
        "traffic-interrupted" if tcp_reset else "migration-validation-failed"
    )
    assert (
        "Nova migration completed; post-migration validation failed: Neutron port validation"
        in message
    )
    assert details["migration_outcomes"]["vm_placement"] == "PASS"
    assert details["migration_outcomes"]["interruption_tolerance"] == "PASS"
    assert bool(details["transport_failure_reasons"]) is tcp_reset
    assert details["validation_failure_reasons"]
    assert details["migration_outcomes"]["tcp_session"] == (
        "FAIL" if tcp_reset else "PASS"
    )
    assert value == original


@pytest.mark.parametrize(
    "fault",
    [
        "missing-field",
        "empty-proof",
        "contradictory-flag",
        "contradictory-failure-flag",
        "contradictory-assessment",
    ],
)
def test_supplied_completion_proof_must_be_complete_and_consistent(fault):
    value = complete_continuity(icmp_loss=5.0, udp_loss=5.0, outage=2.0)
    if fault == "missing-field":
        value["migration_completion_evidence"].pop("endpoint_ready")
    elif fault == "empty-proof":
        value["migration_completion_evidence"] = None
    elif fault == "contradictory-flag":
        value["migration_completion_evidence"]["migration_record_verified"] = False
    elif fault == "contradictory-failure-flag":
        value["migration_succeeded"] = False
    else:
        value["completion_assessment"] = {"checks": {"placement_verified": False}}
    original = deepcopy(value)
    status, _, _, details = PlacementMigrationMixin._live_continuity_verdict(value)
    assert status == "UNVERIFIED"
    assert details["evidence_complete"] is False
    assert details["migration_outcomes"]["migration_completion"] == "UNVERIFIED"
    assert details["interruption_observations"] == []
    assert value == original


def test_legacy_absent_completion_proof_keeps_explicit_verified_placement_contract():
    value = complete_continuity(icmp_loss=5.0, udp_loss=5.0, outage=2.0)
    value.pop("migration_completion_evidence")
    value["completion_assessment"] = {"checks": {"placement_verified": True}}
    assert PlacementMigrationMixin._live_continuity_verdict(value)[0] == "PASS"
    value["completion_assessment"]["checks"]["placement_verified"] = None
    assert PlacementMigrationMixin._live_continuity_verdict(value)[0] == "UNVERIFIED"
    value["completion_assessment"]["checks"]["placement_verified"] = False
    assert PlacementMigrationMixin._live_continuity_verdict(value)[0] == "FAIL"


@pytest.mark.parametrize("moving_is_receiver", [True, False])
def test_completion_identity_follows_moving_vm_in_both_monitor_directions(
    moving_is_receiver,
):
    value = complete_continuity(icmp_loss=5.0, udp_loss=5.0, outage=2.0)
    moving_id = (
        value["target_server_id"] if moving_is_receiver else "fixture-moving-source"
    )
    value["moving_server_id"] = moving_id
    value["migration_completion_evidence"]["server_id"] = moving_id
    original = deepcopy(value)
    status, _, _, details = PlacementMigrationMixin._live_continuity_verdict(value)
    assert status == "PASS"
    assert details["completion_evidence_consistent"] is True
    assert details["migration_outcomes"]["migration_completion"] == "PASS"
    assert details["interruption_observations"]
    assert value == original

    value["migration_completion_evidence"]["server_id"] = "unrelated-vm"
    original = deepcopy(value)
    status, _, _, details = PlacementMigrationMixin._live_continuity_verdict(value)
    assert status == "UNVERIFIED"
    assert details["completion_evidence_consistent"] is False
    assert details["migration_outcomes"]["migration_completion"] == "UNVERIFIED"
    assert details["interruption_observations"] == []
    assert value == original


def test_opposite_placement_support_row_retains_the_exact_continuity_assessment():
    from contextlib import nullcontext
    from types import SimpleNamespace
    from unittest.mock import Mock

    from neutron_flux.models import MigrationResult
    from neutron_flux.pair_workflow import CoordinatedPairExecutor

    from ._shared import endpoint

    stationary, moving = endpoint("stationary", "A"), endpoint("moving", "B")
    stationary.host = moving.host = "compute1"
    stationary.availability_zone = moving.availability_zone = "az1"
    runtime = SimpleNamespace(endpoints=[stationary, moving])
    executor = CoordinatedPairExecutor.__new__(CoordinatedPairExecutor)
    executor.config = SimpleNamespace(
        compute_host_connectivity_enabled=True,
        live_migration_continuity=True,
        storage="host",
        migration_submission_budget=6,
    )
    executor.scope = {
        "qualification_strategy": "sampled",
        "qualification_profile": "full",
    }
    executor.groups = {
        "g": SimpleNamespace(
            metadata={
                "target_hosts": {"A": "compute1", "B": "compute2"},
                "target_availability_zones": {"A": "az1", "B": "az1"},
            }
        )
    }
    executor.active = {"g": runtime}
    executor.builder = SimpleNamespace()
    executor.performance_lock = nullcontext()
    executor.reporter = Mock()
    executor._verify_runtime = lambda _: None
    spec = SimpleNamespace(
        id="PAIR-TRANSITION",
        category="compute-placement",
        expectation="placement-achieved",
        display_name="Opposite placement",
        scenario="Compute migration and placement lifecycle",
        dependencies=["g"],
        metadata={"transition_from": "initial", "pair_placement": "opposite"},
    )
    lifecycle = SimpleNamespace(
        id="PLACEMENT-SUPPORT",
        category=spec.category,
        expectation=spec.expectation,
        display_name=spec.display_name,
        scenario=spec.scenario,
    )
    measured = complete_continuity(icmp_loss=5.0, udp_loss=5.0, outage=2.0)

    def migrate(**_kwargs):
        moving.host = "compute2"
        migration = MigrationResult(
            moving.server_id,
            "compute1",
            "compute2",
            "az1",
            "az1",
            True,
            False,
            True,
            details={"migration_mode": "live", "continuity": measured},
        )
        return lifecycle, migration, moving, [], [], False, "eligible", None, False

    executor._attempt_configured_migration = migrate
    baseline = [
        SimpleNamespace(
            authoritative=True,
            operation="probe",
            expectation="reachable",
            protocol=protocol,
        )
        for protocol in ("icmp", "tcp", "udp")
    ]
    assert executor._transition(spec, baseline, SimpleNamespace()) is True
    support, logical = executor.reporter.result.call_args_list
    assert support.args[2] == logical.args[2] == "PASS"
    recorded = logical.kwargs["details"]["transitions"][0]["continuity_assessment"]
    assert support.kwargs["details"]["continuity"] == recorded
    assert recorded["interruption_observations"]
    assert recorded["interruption_tolerance_note"] == MIGRATION_DOWNTIME_TOLERANCE_NOTE
