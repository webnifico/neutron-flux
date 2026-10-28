"""Startup is retained, but only post-readiness observations grade continuity."""

from __future__ import annotations

from copy import deepcopy

import pytest

from neutron_flux.continuity_phases import partition_continuity
from neutron_flux.runtime.live_migration import LiveMigrationRuntimeMixin


def payload():
    # Six actual application sends; the first two are startup and both lost.
    return {
        "readiness": {"ready": True, "ready_at_s": 0.5},
        "observation_duration_s": 1.5,
        "icmp": [{"t": i / 4, "sequence": i, "ok": i >= 2} for i in range(6)],
        "udp": {
            "sent": 6,
            "session_id": 42,
            "send_times_s": [i / 4 for i in range(6)],
            "response": {
                "sent": 6,
                "received": 4,
                "session_id": 42,
                "sequence_bitmap_complete": True,
                "received_bitmap_hex": "3c",
            },
        },
    }


def partition(value=None, state=None):
    return partition_continuity(
        value or payload(),
        state
        or {
            "phase_markers_required": True,
            "phase_markers": {"migration_submitted": 0.75, "placement_verified": 1.0},
        },
        LiveMigrationRuntimeMixin._continuity_outage_bounds,
        sample_interval_s=0.25,
    )


def test_every_observation_is_retained_exactly_once_across_phases():
    data = payload()
    before = deepcopy(data)
    result = partition(data)
    assert data == before and result["verified"] is True
    phases = result["phases"]
    assert phases["startup"]["icmp"]["lost"] == 2
    assert phases["startup"]["udp"]["lost"] == 2
    assert phases["protected"]["icmp"]["lost"] == 0
    assert phases["protected"]["udp"]["lost"] == 0
    assert (
        sum(
            phases[name]["icmp"]["samples"]
            for name in ("startup", "pre_submission", "migration", "post_migration")
        )
        == 6
    )
    assert (
        sum(
            phases[name]["udp"]["sent"]
            for name in ("startup", "pre_submission", "migration", "post_migration")
        )
        == 6
    )
    assert result["raw_icmp_observations"] == before["icmp"]


@pytest.mark.parametrize(
    "value", [None, False, -1, "0.5", float("inf"), float("nan"), 2.0]
)
def test_invalid_readiness_cannot_certify_phase(value):
    data = payload()
    data["readiness"]["ready_at_s"] = value
    assert partition(data)["verified"] is False


@pytest.mark.parametrize("value", [None, [], "xx", "", "1c", "fc", "3cff"])
def test_missing_malformed_or_inconsistent_receiver_bitmap_is_not_complete(value):
    data = payload()
    data["udp"]["response"]["received_bitmap_hex"] = value
    assert partition(data)["verified"] is False


@pytest.mark.parametrize(
    "changes",
    [
        {"migration_submitted": None},
        {"migration_submitted": 0.1},
        {"placement_verified": 0.6},
        {"placement_verified": 99},
    ],
)
def test_missing_or_impossible_markers_are_not_complete(changes):
    state = {
        "phase_markers_required": True,
        "phase_markers": {
            "migration_submitted": 0.75,
            "placement_verified": 1.0,
            **changes,
        },
    }
    assert partition(state=state)["verified"] is False


def test_wrong_session_and_count_do_not_become_phase_evidence():
    data = payload()
    data["udp"]["response"]["session_id"] = 99
    assert partition(data)["verified"] is False
    data = payload()
    data["udp"]["send_times_s"].pop()
    assert partition(data)["verified"] is False


def test_in_window_loss_is_not_filtered_with_startup():
    data = payload()
    data["icmp"][3]["ok"] = False
    data["udp"]["response"].update(received=3, received_bitmap_hex="34")
    result = partition(data)
    assert result["verified"] is True
    assert result["phases"]["migration"]["icmp"]["lost"] == 1
    assert result["phases"]["migration"]["udp"]["lost"] == 1
    assert result["phases"]["protected"]["icmp"]["loss_pct"] == 25
    assert result["phases"]["protected"]["udp"]["loss_pct"] == 25


def phase_attested_continuity():
    from ._evidence import complete_continuity

    value = complete_continuity()
    raw = payload()
    value.update(
        measurement_phase_contract=1,
        phase_markers_required=True,
        phase_markers={"migration_submitted": 0.75, "placement_verified": 1.0},
        readiness=raw["readiness"],
        observation_duration_s=raw["observation_duration_s"],
    )
    value["udp"].update(raw["udp"])
    value["udp"]["terminal"] = value["udp"]["identity_verified"] = True
    # Preserve identity fields while using the exact six-sequence fixture.
    value["udp"]["response"].update(
        {
            "probe_id": "fixture-destination",
            "instance_id": "fixture-receiver",
            "local_ip": "192.0.2.20",
            "max_sequence": 5,
            "loss_pct": 100 / 3,
        }
    )
    parts = partition_continuity(
        raw,
        value,
        LiveMigrationRuntimeMixin._continuity_outage_bounds,
        sample_interval_s=0.25,
    )
    value["phase_evidence"] = parts
    value["icmp"] = parts["phases"]["protected"]["icmp"]
    value["udp"]["protected_measurement"] = parts["phases"]["protected"]["udp"]
    return value


def test_startup_loss_with_positive_delivery_can_pass_only_the_protected_window():
    from neutron_flux.execution.placement_migration import PlacementMigrationMixin

    value = phase_attested_continuity()
    status, _, message, details = PlacementMigrationMixin._live_continuity_verdict(
        value
    )
    assert status == "PASS", message
    assert details["phase_evidence_complete"] is True
    assert value["phase_evidence"]["phases"]["startup"]["icmp"]["lost"] == 2
    assert value["udp"]["response"]["received"] == 4
    assert value["udp"]["protected_measurement"]["received"] == 4


@pytest.mark.parametrize(
    "missing", ["readiness", "phase_markers", "observation_duration_s"]
)
def test_missing_phase_boundary_cannot_pass_on_a_claimed_verified_flag(missing):
    from neutron_flux.execution.placement_migration import PlacementMigrationMixin

    value = phase_attested_continuity()
    value.pop(missing)
    value["phase_markers_required"] = False
    status, _, _, details = PlacementMigrationMixin._live_continuity_verdict(value)
    assert status == "UNVERIFIED"
    assert details["phase_evidence_complete"] is False


@pytest.mark.parametrize("part", ["udp", "icmp", "outage", "raw", "bitmap"])
def test_fabricated_phase_summaries_or_missing_raw_data_cannot_pass(part):
    from neutron_flux.execution.placement_migration import PlacementMigrationMixin

    value = deepcopy(phase_attested_continuity())
    if part == "udp":
        value["udp"]["protected_measurement"]["sent"] = 999
    elif part == "icmp":
        value["icmp"]["raw_samples"] = value["icmp"]["raw_samples"][1:]
    elif part == "outage":
        value["icmp"]["outage"]["outage_upper_bound_s"] = 99
    elif part == "raw":
        value["phase_evidence"].pop("raw_icmp_observations")
    else:
        value["udp"]["response"]["received_bitmap_hex"] = "1c"
    status, _, _, details = PlacementMigrationMixin._live_continuity_verdict(value)
    assert status != "PASS"
    assert details["phase_evidence_complete"] is False


def test_missing_nova_record_does_not_hide_independently_satisfied_tolerance():
    from neutron_flux.execution.placement_migration import PlacementMigrationMixin

    value = phase_attested_continuity()
    value["migration_succeeded"] = None
    status, _, _, details = PlacementMigrationMixin._live_continuity_verdict(value)
    assert status == "UNVERIFIED"
    assert details["migration_outcomes"]["migration_completion"] == "UNVERIFIED"
    assert details["migration_outcomes"]["tcp_session"] == "PASS"
    assert details["migration_outcomes"]["interruption_tolerance"] == "PASS"


def test_missing_tcp_acknowledgement_is_not_reported_as_a_known_reset():
    from neutron_flux.execution.placement_migration import PlacementMigrationMixin

    value = phase_attested_continuity()
    value["tcp"].pop("server_result")
    status, _, _, details = PlacementMigrationMixin._live_continuity_verdict(value)
    assert status == "UNVERIFIED"
    assert details["migration_outcomes"]["tcp_session"] == "UNVERIFIED"
