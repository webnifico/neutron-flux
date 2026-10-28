"""Conservative cleanup recovery for port-health-only migration ambiguity."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .cancellation import raise_if_cancelled
from .cloud_operation import CloudOperationOutcome
from .errors import SuiteError
from .migration_completion import migration_operation_settlement
from .utils import iso_utc, list_value, nova_task_state_cleared, pick

_TERMINAL = {
    "confirmed",
    "finished",
    "completed",
    "done",
    "cancelled",
    "canceled",
    "error",
    "failed",
    "reverted",
}


def is_validation_only_migration(record: Mapping[str, Any]) -> bool:
    """Recognize recorded port-health ambiguity without broadening ordinary recovery."""
    evidence = record.get("evidence")
    assessment = (
        evidence.get("completion_assessment") if isinstance(evidence, dict) else None
    )
    return bool(
        record.get("kind") == "migration"
        and record.get("outcome") == "AMBIGUOUS"
        and record.get("submitted") is True
        and record.get("accepted") is True
        and isinstance(assessment, dict)
        and assessment.get("status") == "FAIL"
        and assessment.get("failed_checks") == ["port_binding_verified"]
        and assessment.get("missing_checks") == []
        and isinstance(evidence, dict)
        and evidence.get("port_binding_verified") is False
    )


def _ids(value: Any) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(v, str) or not v for v in value
    ):
        raise SuiteError(
            "Migration recovery lacks a complete resource identity inventory"
        )
    if len(set(value)) != len(value):
        raise SuiteError("Migration recovery resource identities are duplicated")
    return value


def _object(osc: Any, *args: str) -> dict[str, Any]:
    detail = osc.json(*args, timeout=60)
    if not isinstance(detail, dict):
        raise SuiteError(
            "Migration recovery could not read authoritative resource detail"
        )
    return detail


def _rows(osc: Any, *args: str) -> list[dict[str, Any]]:
    rows = osc.json(*args, timeout=60)
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise SuiteError(
            "Migration recovery could not read authoritative resource inventory"
        )
    return rows


def _fixed_ips(value: Any) -> list[list[str]]:
    output = []
    for item in list_value(value):
        if isinstance(item, dict) and item.get("subnet_id") and item.get("ip_address"):
            output.append([str(item["subnet_id"]), str(item["ip_address"])])
        elif isinstance(item, (list, tuple)) and len(item) == 2 and all(item):
            output.append([str(item[0]), str(item[1])])
        else:
            raise SuiteError("Migration recovery encountered incomplete port addresses")
    return sorted(output)


def recover_validation_only_migration(
    osc: Any, coordinator: Any, record: Mapping[str, Any]
) -> bool:
    """Append settlement only after three matching fresh ownership observations.

    This exceptional path keeps the original failed port-health validation. It
    does not repair port status, resubmit migration, or waive a cleanup guard.
    Missing, changed or inaccessible resource state leaves the operation blocked.
    """
    if not is_validation_only_migration(record):
        return False
    with coordinator.lock:
        pending = {
            str(item.get("operation_id")): item
            for item in coordinator.unresolved_records()
        }
        current = pending.get(str(record.get("operation_id")))
        if (
            current is None
            or current.get("outcome") != record.get("outcome")
            or current.get("command") != record.get("command")
        ):
            return False
        scope = record.get("scope")
        if (
            not isinstance(scope, dict)
            or not scope
            or scope != coordinator.journal.scope
            or record.get("scope_fingerprint") != coordinator.journal.scope_fingerprint
        ):
            raise SuiteError(
                "Migration recovery cannot verify the journal's cloud scope"
            )
        before = record.get("pre_state")
        evidence = record.get("evidence")
        if not isinstance(before, dict) or not isinstance(evidence, dict):
            return False
        server_id = str(evidence.get("server_id") or "")
        source = str(record.get("source_host") or "")
        target = str(record.get("destination_host") or "")
        zone = str(record.get("availability_zone") or "")
        selection = before.get("destination_selection")
        if not isinstance(selection, dict) or not all(
            (server_id, source, target, zone)
        ):
            return False
        if (
            source == target
            or any(
                evidence.get(key) != value
                for key, value in {
                    "source_host": source,
                    "destination_host": target,
                    "source_availability_zone": zone,
                    "destination_availability_zone": zone,
                }.items()
            )
            or any(
                selection.get(key) != value
                for key, value in {
                    "server_id": server_id,
                    "source_host": source,
                    "destination_host": target,
                    "availability_zone": zone,
                    "migration_type": "live",
                }.items()
            )
        ):
            return False
        command = record.get("command")
        if (
            not isinstance(command, list)
            or not all(isinstance(word, str) and word for word in command)
            or command[:4] != ["--os-compute-api-version", "2.56", "server", "migrate"]
            and command[:4]
            != ["--os-compute-api-version", "2.latest", "server", "migrate"]
            or command[-1:] != [server_id]
            or "--live-migration" not in command
            or command.count("--host") != 1
            or command.index("--host") + 1 >= len(command)
            or command[command.index("--host") + 1] != target
        ):
            return False
        port_ids = _ids(before.get("migration_port_ids"))
        volume_ids = _ids(before.get("migration_volume_ids"))
        baseline = _ids(before.get("migration_ids"))
        resources = _ids(before.get("migration_resource_ids"))
        if (
            not port_ids
            or len({server_id, *port_ids, *volume_ids})
            != 1 + len(port_ids) + len(volume_ids)
            or set(resources) != {server_id, *port_ids, *volume_ids}
        ):
            return False
        if set(_ids(record.get("resource_ids"))) != set(resources):
            return False
        stable_before = before.get("stable_observations")
        if not isinstance(stable_before, list) or len(stable_before) != 3:
            return False
        expected_ports = (
            stable_before[0].get("ports")
            if isinstance(stable_before[0], dict)
            else None
        )
        if not isinstance(expected_ports, dict) or set(expected_ports) != set(port_ids):
            return False
        if any(
            not isinstance(item, dict)
            or item.get("ports") != expected_ports
            or item.get("migration_ids") != baseline
            or item.get("source_host") != source
            or str(item.get("status", "")).lower() != "active"
            or item.get("task_state_cleared") is not True
            or str(item.get("power_state", "")) != "1"
            for item in stable_before
        ):
            return False
        token = _object(osc, "token", "issue")
        project_id = str(pick(token, "project_id", default="") or "")
        if not project_id or (
            scope.get("OS_PROJECT_ID") and scope["OS_PROJECT_ID"] != project_id
        ):
            return False
        prefix = tuple(command[:2])
        observations: list[dict[str, Any]] = []
        for index in range(3):
            raise_if_cancelled()
            server = _object(osc, "server", "show", server_id)
            if (
                pick(server, "id") != server_id
                or pick(server, "project_id", "tenant_id") != project_id
                or str(pick(server, "status", default="")).upper() != "ACTIVE"
                or not nova_task_state_cleared(server)
                or str(
                    pick(server, "OS-EXT-STS:power_state", "power_state", default="")
                )
                != "1"
                or pick(server, "OS-EXT-SRV-ATTR:host", "host") != target
                or pick(server, "OS-EXT-AZ:availability_zone", "availability_zone")
                != zone
            ):
                return False
            migrations = _rows(
                osc, *prefix, "server", "migration", "list", "--server", server_id
            )
            identities = [
                str(pick(row, "id", "uuid", "migration_id", default="") or "")
                for row in migrations
            ]
            if any(not identity for identity in identities) or len(
                set(identities)
            ) != len(identities):
                return False
            if not set(baseline).issubset(identities) or any(
                str(pick(row, "status", default="")).lower() not in _TERMINAL
                for row in migrations
            ):
                return False
            new = [
                row
                for row, identity in zip(migrations, identities, strict=True)
                if identity not in baseline
            ]
            if len(new) != 1:
                return False
            migration = new[0]
            if (
                pick(migration, "server_uuid", "server_id", "instance_uuid")
                != server_id
                or pick(migration, "source_compute", "source_host") != source
                or pick(
                    migration, "dest_compute", "destination_compute", "destination_host"
                )
                != target
                or str(pick(migration, "type", "migration_type", default="")).lower()
                != "live-migration"
                or str(pick(migration, "status", default="")).lower() != "completed"
            ):
                return False
            ports = {}
            listed_ports = _rows(osc, "port", "list", "--server", server_id)
            if len(listed_ports) != len(port_ids) or {
                str(pick(row, "id", default="")) for row in listed_ports
            } != set(port_ids):
                return False
            for port_id in port_ids:
                port = _object(osc, "port", "show", port_id)
                expected = expected_ports[port_id]
                if not isinstance(expected, dict):
                    return False
                actual = {
                    "device_id": pick(port, "device_id"),
                    "binding_host": pick(port, "binding_host_id", "binding:host_id"),
                    "mac_address": pick(port, "mac_address"),
                    "fixed_ips": _fixed_ips(pick(port, "fixed_ips", default=None)),
                    "security_groups": sorted(
                        map(
                            str,
                            list_value(
                                pick(
                                    port,
                                    "security_group_ids",
                                    "security_groups",
                                    default=None,
                                )
                            ),
                        )
                    ),
                }
                if (
                    pick(port, "id") != port_id
                    or not str(pick(port, "device_owner", default="")).startswith(
                        "compute:"
                    )
                    or pick(port, "project_id", "tenant_id") != project_id
                    or actual["device_id"] != server_id
                    or actual["binding_host"] != target
                    or expected.get("device_id") != server_id
                    or expected.get("binding_host") != source
                    or not expected.get("mac_address")
                    or not expected.get("fixed_ips")
                    or actual["mac_address"] != expected["mac_address"]
                    or actual["fixed_ips"] != _fixed_ips(expected.get("fixed_ips"))
                    or "security_groups" not in expected
                    or pick(port, "security_group_ids", "security_groups", default=None)
                    is None
                    or actual["security_groups"] != sorted(expected["security_groups"])
                ):
                    return False
                ports[port_id] = actual
            attached = _rows(osc, "server", "volume", "list", server_id)
            if len(attached) != len(volume_ids) or {
                str(pick(row, "id", "volume_id", default="")) for row in attached
            } != set(volume_ids):
                return False
            for volume_id in volume_ids:
                volume = _object(osc, "volume", "show", volume_id)
                attachments = pick(volume, "attachments", default=None)
                if (
                    pick(volume, "id") != volume_id
                    or str(pick(volume, "status", default="")).lower() != "in-use"
                    or not isinstance(attachments, list)
                    or len(attachments) != 1
                    or not isinstance(attachments[0], dict)
                    or pick(attachments[0], "server_id", "server_uuid", "instance_uuid")
                    != server_id
                ):
                    return False
            observation = {
                "migration_id": str(pick(migration, "id", "uuid", "migration_id")),
                "ports": ports,
                "volumes": sorted(volume_ids),
            }
            if observations and observation != observations[-1]:
                return False
            observations.append(observation)
            if index < 2:
                coordinator.settle(
                    "migration",
                    "verify stable migration ownership before cleanup recovery",
                    seconds=1.0,
                    fresh=True,
                )
        settled = {
            **evidence,
            "server_status": "ACTIVE",
            "port_ownership_verified": True,
            "operation_inventory_verified": True,
        }
        assessment = migration_operation_settlement(settled)
        if assessment["verified"] is not True:
            return False
        coordinator.resolve(
            str(record["operation_id"]),
            CloudOperationOutcome.SUCCEEDED,
            evidence={
                **settled,
                "automatic_recovery": True,
                "observed_at": iso_utc(),
                "operation_settlement_assessment": assessment,
                "recovery_observations": observations,
                "original_validation_preserved": True,
            },
            message="Nova migration settlement and resource ownership independently verified during cleanup; the recorded port-health validation remains failed",
        )
        return True
