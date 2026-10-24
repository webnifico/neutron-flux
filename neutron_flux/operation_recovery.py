"""Read-only recovery of interrupted operations; never infer failure from silence."""

from __future__ import annotations

import json
import uuid
from typing import Any

from .cloud_operation import CloudOperationOutcome
from .cloud_operation_command import OpenStackCloudOperationCommand
from .errors import RunCancelledError, SuiteError
from .migration_operation_recovery import (
    recover_validation_only_migration,
)
from .utils import iso_utc, normalized_map, pick


def _show(osc: Any, resource: tuple[str, ...], identity: str):
    result = osc.run(*resource, "show", identity, "-f", "json", check=False, timeout=60)
    if osc.is_not_found_result(result, expected_resource=" ".join(resource)):
        return None, True
    if result.returncode:
        raise SuiteError(result.stderr or result.stdout or "Resource inspection failed")
    detail = json.loads(result.stdout)
    if not isinstance(detail, dict):
        raise SuiteError("Resource inspection did not return an object")
    return detail, False


def _migration_outcome(osc, record, server_id, detail):
    fields = normalized_map(detail)
    # Hidden task state and VERIFY_RESIZE cannot prove completion.
    task_key = next((key for key in fields if key.endswith("task_state")), None)
    if task_key is None or str(fields[task_key]).lower() not in {"", "none", "null"}:
        return None
    if str(fields.get("status", "")).upper() not in {"ACTIVE", "SHUTOFF", "ERROR"}:
        return None
    before = record.get("pre_state") or {}
    baseline = before.get("migration_ids")
    if not isinstance(baseline, list):
        return None
    rows = osc.json("server", "migration", "list", "--server", server_id, timeout=60)
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        return None
    new = [
        row
        for row in rows
        if str(pick(row, "id", "uuid", "migration_id", default=""))
        not in set(map(str, baseline))
    ]
    # Several new records cannot be unambiguously tied to this command.
    if len(new) != 1:
        return None
    row = new[0]
    source = str(pick(row, "source_compute", "source_host", default=""))
    target = str(pick(row, "dest_compute", "dest_host", "destination_host", default=""))
    if not source or source != str(
        record.get("source_host") or before.get("source_host") or ""
    ):
        return None
    expected = str(record.get("destination_host") or "")
    if not target or not expected or target != expected:
        return None
    status = str(pick(row, "status", default="")).lower()
    host = str(pick(detail, "OS-EXT-SRV-ATTR:host", "host", default=""))
    if status in {"completed", "confirmed"} and host == target:
        return CloudOperationOutcome.SUCCEEDED, {"server": detail, "migration": row}
    if (
        status in {"error", "failed", "cancelled", "canceled", "reverted"}
        and host == source
    ):
        return CloudOperationOutcome.FAILED_FINAL, {"server": detail, "migration": row}
    return None


def recover_operations(osc, coordinator, logger) -> list[str]:
    """Resolve only independently verified terminal outcomes, preserving journals.

    Missing resources resolve an interrupted delete. A missing resource can also
    retire a historical mutation of that UUID; it does not resolve an ambiguous
    create, whose delayed response could still produce a new resource.
    """
    for record in coordinator.unresolved_records():
        operation_id = str(record.get("operation_id") or "")
        evidence = record.get("evidence")
        if (
            record.get("kind") == "migration"
            and isinstance(evidence, dict)
            and "completion_assessment" in evidence
        ):
            try:
                recover_validation_only_migration(osc, coordinator, record)
            except RunCancelledError:
                raise
            except (SuiteError, OSError, ValueError, TypeError) as exc:
                logger.log(
                    f"Operation {operation_id} remains unresolved: {exc}", "WARNING"
                )
            # A failed strict observation must never fall back to the legacy
            # migration recovery path below.
            continue
        matched = OpenStackCloudOperationCommand._matched_command(
            record.get("command") or ()
        )
        if matched is None:
            continue
        phrase, _, tail = matched
        positionals, _ = OpenStackCloudOperationCommand._parsed_arguments(tail)
        if not positionals:
            continue
        action_index = next(
            (
                index
                for index, word in enumerate(phrase)
                if word
                in {
                    "create",
                    "delete",
                    "set",
                    "unset",
                    "migrate",
                    "migration",
                    "start",
                    "stop",
                    "reboot",
                    "add",
                    "remove",
                }
            ),
            None,
        )
        if action_index is None:
            continue
        resource = tuple(phrase[:action_index])
        verb = phrase[action_index]
        if (
            resource == ("server",)
            and verb in {"migration", "migrate"}
            and len(phrase) > 2
            and phrase[-1] not in {"confirm", "revert"}
        ):
            continue
        if resource not in {
            ("server",),
            ("server", "group"),
            ("port",),
            ("volume",),
            ("network",),
            ("subnet",),
            ("router",),
            ("floating", "ip"),
            ("security", "group"),
            ("keypair",),
        }:
            continue
        identities = (
            positionals
            if verb == "delete"
            else positionals[:1]
            if verb in {"add", "remove"}
            else positionals[-1:]
        )
        try:
            observations = [_show(osc, resource, identity) for identity in identities]
            resolution = None
            if verb == "create" and len(observations) == 1:
                detail, absent = observations[0]
                name = identities[0]
                identity_field = "name" if resource == ("keypair",) else "id"
                # The journal's exact create name remains authoritative when
                # replaying a historical prefix. Keypairs expose their name
                # as identity rather than a resource UUID.
                if (
                    not absent
                    and detail
                    and str(pick(detail, "name", default="")) == name
                    and pick(detail, identity_field)
                    and str(pick(detail, "status", default="ACTIVE")).upper()
                    in {"ACTIVE", "DOWN", "AVAILABLE", "ERROR"}
                ):
                    fields = normalized_map(detail)
                    task = next(
                        (
                            value
                            for key, value in fields.items()
                            if key.endswith("task_state")
                        ),
                        None,
                    )
                    if str(task).lower() in {"", "none", "null"}:
                        resolution = (
                            CloudOperationOutcome.FAILED_FINAL
                            if str(pick(detail, "status", default="")).upper()
                            == "ERROR"
                            else CloudOperationOutcome.SUCCEEDED,
                            {"created_resource": detail},
                        )
            elif all(absent for _, absent in observations):
                if verb != "delete":
                    for identity in identities:
                        uuid.UUID(identity)
                resolution = (
                    CloudOperationOutcome.SUCCEEDED
                    if verb == "delete"
                    else CloudOperationOutcome.FAILED_FINAL,
                    {
                        "resource": list(resource),
                        "identities": identities,
                        "verified_absent": True,
                    },
                )
            elif (
                record.get("kind") == "migration"
                and len(observations) == 1
                and observations[0][0]
            ):
                resolution = _migration_outcome(
                    osc, record, identities[0], observations[0][0]
                )
            if resolution:
                outcome, evidence = resolution
                coordinator.resolve(
                    operation_id,
                    outcome,
                    evidence={
                        "observed_at": iso_utc(),
                        "automatic_recovery": True,
                        **evidence,
                    },
                    message="Terminal state independently verified during automatic recovery",
                )
                logger.log(
                    f"Recovered historical operation {operation_id}: {outcome.value}"
                )
        except RunCancelledError:
            raise
        except (SuiteError, OSError, ValueError, TypeError) as exc:
            logger.log(f"Operation {operation_id} remains unresolved: {exc}", "WARNING")
    unresolved = [
        str(record.get("operation_id")) for record in coordinator.unresolved_records()
    ]
    if unresolved:
        logger.log(
            "Cloud operations still require verified terminal state: "
            + ", ".join(unresolved)
            + ". Let active operations finish, then rerun cleanup or run --resume. "
            "If the service cannot expose a terminal state, inspect the operation journal and recovery.md before repairing the affected resource in OpenStack.",
            "WARNING",
        )
    return unresolved
