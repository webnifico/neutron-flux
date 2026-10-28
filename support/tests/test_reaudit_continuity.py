"""Incomplete/mistyped outer migration evidence must never select a weaker contract."""

from __future__ import annotations

from copy import deepcopy

import pytest

from neutron_flux.execution.placement_migration import PlacementMigrationMixin

from ._evidence import complete_continuity


def attested_continuity():
    result = complete_continuity()
    token = "1234567890abcdef1234567890abcdef"
    identity = {
        "probe_id": "destination-vm",
        "instance_id": "receiver-process",
        "local_ip": "192.0.2.20",
        "token": token,
    }
    result.update(
        target_server_id="destination-vm",
        target_fixed_ip="192.0.2.20",
        data_path_before={"verified": True},
        data_path_after={"verified": True},
    )
    result["tcp"].update(identity_verified=True, receiver_identity=dict(identity))
    result["tcp"]["server_result"].update(identity)
    result["udp"]["identity_verified"] = True
    result["udp"]["response"].update(
        {key: value for key, value in identity.items() if key != "token"}
    )
    return result


def evaluate(value):
    return PlacementMigrationMixin._live_continuity_verdict(value)


def test_complete_positive_evidence_still_passes():
    status, _, _, details = evaluate(attested_continuity())
    assert status == "PASS" and details["evidence_complete"] is True


@pytest.mark.parametrize(
    "field",
    [
        "available",
        "migration_succeeded",
        "full_migration_window",
        "ready_before_migration",
        "sampling_complete",
        "workers_complete",
    ],
)
@pytest.mark.parametrize("invalid", [None, 1, "true", {}, []])
def test_absent_or_mistyped_required_flags_are_unverified(field, invalid):
    value = attested_continuity()
    value[field] = invalid
    status, _, _, details = evaluate(value)
    assert status == "UNVERIFIED"
    assert details.get("evidence_complete") is not True
    value.pop(field)
    assert evaluate(value)[0] == "UNVERIFIED"


@pytest.mark.parametrize(
    "field",
    ["target_server_id", "target_fixed_ip", "data_path_before", "data_path_after"],
)
@pytest.mark.parametrize("invalid", [None, "", 1, {}, [], False])
def test_target_and_path_proof_are_mandatory_even_when_absent(field, invalid):
    value = attested_continuity()
    value[field] = invalid
    status, _, _, details = evaluate(value)
    assert status == "UNVERIFIED" and details["evidence_complete"] is False
    value.pop(field)
    assert evaluate(value)[0] == "UNVERIFIED"


def test_missing_target_does_not_disable_identity_and_route_checks():
    value = attested_continuity()
    for field in (
        "target_server_id",
        "target_fixed_ip",
        "data_path_before",
        "data_path_after",
    ):
        value.pop(field)
    value["tcp"]["identity_verified"] = False
    value["udp"]["identity_verified"] = False
    status, _, _, details = evaluate(value)
    assert status == "UNVERIFIED" and details["evidence_complete"] is False


@pytest.mark.parametrize("invalid", [[], "not-a-dictionary", True, 42])
def test_malformed_receiver_readiness_cannot_crash_or_pass(invalid):
    value = attested_continuity()
    value["tcp"]["receiver_identity"] = invalid
    assert evaluate(value)[0] == "UNVERIFIED"


def test_proven_migration_failure_remains_fail():
    value = attested_continuity()
    value["migration_succeeded"] = False
    value["migration_completion_evidence"]["migration_record_verified"] = False
    status, _, _, details = evaluate(value)
    assert status == "FAIL"
    assert details["evidence_complete"] is False


def test_proven_management_path_remains_fail():
    value = attested_continuity()
    value["data_path_after"] = {"verified": False, "reason": "management interface"}
    assert evaluate(value)[0] == "FAIL"


def test_malformed_metadata_does_not_hide_proven_transport_failure():
    value = attested_continuity()
    value.pop("migration_succeeded")
    value["tcp"]["survived"] = False
    value["tcp"]["error"] = "ConnectionResetError"
    assert evaluate(value)[0] == "FAIL"


def test_no_verdict_mutates_receiver_evidence():
    value = attested_continuity()
    before = deepcopy(value)
    evaluate(value)
    assert value == before


@pytest.mark.parametrize(
    "record_verified,expected_status",
    [(True, "PASS"), (False, "FAIL"), (None, "UNVERIFIED")],
)
def test_real_migration_runtime_supplies_completion_evidence(
    config_factory, record_verified, expected_status
):
    # Only Nova/SSH/guest boundaries are instrumented. The production migration
    # completion path must construct the new field before the real validator.
    from ._shared import endpoint
    from .test_migration_and_load_evidence import _live_builder_without_reported_az

    builder, moving, target = _live_builder_without_reported_az(config_factory)
    builder.config.live_migration_continuity = True
    payload = attested_continuity()
    payload.pop("migration_succeeded")
    builder._start_live_continuity = lambda *_args: {"available": True}
    builder._stop_live_continuity = lambda *_args: deepcopy(payload)
    builder._verify_nova_migration_record = lambda *_args, **_kwargs: (
        record_verified,
        None if record_verified else "record was not verified",
        {"id": "migration-record"},
    )
    result = builder._live_migrate_endpoint_once(
        moving, target, stationary_peer=endpoint("stationary", "B")
    )
    continuity = result.details["continuity"]
    assert continuity["migration_succeeded"] is record_verified
    assert continuity["migration_completion_evidence"]["server_id"] == moving.server_id
    assert (
        continuity["migration_completion_evidence"]["destination_host"] == target.host
    )
    assert evaluate(continuity)[0] == expected_status
