"""Separate migration validation from durable command settlement.

A moved guest is not proof that Nova finalized the operation. Unknown completion
must not be retried or silently promoted to success by a reporting layer.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def migration_completion(evidence: Mapping[str, Any]) -> dict[str, Any]:
    checks: dict[str, bool | None] = {}
    for key in (
        "migration_record_verified",
        "task_state_cleared",
        "port_binding_verified",
        "volume_attachment_verified",
        "guest_marker_verified",
        "endpoint_ready",
    ):
        value = evidence.get(key)
        checks[key] = value if type(value) is bool else None
    source, destination = evidence.get("source_host"), evidence.get("destination_host")
    source_az = evidence.get("source_availability_zone")
    destination_az = evidence.get("destination_availability_zone")
    identity_known = all(
        isinstance(value, str) and bool(value.strip())
        for value in (
            evidence.get("server_id"),
            source,
            destination,
            source_az,
            destination_az,
        )
    )
    checks["placement_verified"] = (
        source != destination and source_az == destination_az
        if identity_known
        else None
    )
    if "confirmed" in evidence:
        value = evidence["confirmed"]
        checks["handoff_confirmed"] = value if type(value) is bool else None
    failed = [key for key, value in checks.items() if value is False]
    missing = [key for key, value in checks.items() if value is None]
    verified = False if failed else None if missing else True
    return {
        "verified": verified,
        "status": "PASS"
        if verified is True
        else "FAIL"
        if verified is False
        else "UNVERIFIED",
        "checks": checks,
        "failed_checks": failed,
        "missing_checks": missing,
        "resubmission_permitted": False,
    }


def migration_operation_settlement(evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Assess command settlement separately from the migrated guest's health.

    An unhealthy port or failed guest probe does not make a finalized Nova move
    an in-flight request. A failed validation can establish settlement only
    through fresh control-plane observations and unchanged resource ownership.
    This never authorizes a second submission of the same move.
    """
    completion = migration_completion(evidence)
    checks = {
        key: completion["checks"][key]
        for key in (
            "migration_record_verified",
            "task_state_cleared",
            "placement_verified",
            "volume_attachment_verified",
        )
    }
    # A fully verified legacy completion already contains positive server and
    # binding evidence. Failed or sparse completions require the separate,
    # explicit observations emitted by the runtime below.
    legacy_verified = completion["verified"] is True
    status = evidence.get("server_status")
    checks["server_active"] = (
        str(status).strip().upper() == "ACTIVE"
        if status is not None
        else True
        if legacy_verified and "server_status" not in evidence
        else None
    )
    for key in ("port_ownership_verified", "operation_inventory_verified"):
        value = evidence.get(key)
        checks[key] = (
            value
            if type(value) is bool
            else True
            if legacy_verified and key not in evidence
            else None
        )
    if "handoff_confirmed" in completion["checks"]:
        checks["handoff_confirmed"] = completion["checks"]["handoff_confirmed"]
    failed = [key for key, value in checks.items() if value is False]
    missing = [key for key, value in checks.items() if value is None]
    verified = False if failed else None if missing else True
    return {
        "verified": verified,
        "status": "SETTLED" if verified is True else "UNSETTLED",
        "checks": checks,
        "failed_checks": failed,
        "missing_checks": missing,
        "validation_status": completion["status"],
        "resubmission_permitted": False,
    }
