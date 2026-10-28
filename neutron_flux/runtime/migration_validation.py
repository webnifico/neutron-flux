from __future__ import annotations

import re
import shlex
import time
import uuid
from typing import Any

from ..cancellation import raise_if_cancelled
from ..cloud_operation import CloudOperationOutcome
from ..errors import (
    AmbiguousCloudOperationError,
    PlacementUnavailableError,
    RunCancelledError,
    SuiteError,
    UnverifiableMigrationError,
)
from ..models import ComputeHostInfo, Endpoint
from ..scheduling import READ_WORKERS, bounded_map
from ..utils import (
    list_value,
    normalized_map,
    nova_task_state_cleared,
    optional_text,
    pick,
    safe_name,
)


class MigrationValidationMixin:
    """Migration observation, barriers, and state verification."""

    _SETTLED_MIGRATION_STATES = {
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

    def _settled_migration_ids(
        self: Any, rows: list[dict[str, Any]] | None, error: str | None
    ) -> set[str]:
        """Require a correlatable, terminal inventory immediately before a move."""
        if rows is None:
            raise UnverifiableMigrationError(
                "Nova migration inventory was unavailable before submission: "
                + str(error or "unknown error")
            )
        identities = [self._migration_row_id(row) for row in rows]
        if any(not identity for identity in identities) or len(set(identities)) != len(
            identities
        ):
            raise UnverifiableMigrationError(
                "Nova migration inventory lacks distinct record IDs; migration was not submitted"
            )
        if any(
            str(pick(row, "status", default="") or "").lower()
            not in self._SETTLED_MIGRATION_STATES
            for row in rows
        ):
            raise UnverifiableMigrationError(
                "Nova exposes an active migration or an unknown migration state; no new migration was submitted"
            )
        return set(identities)

    @staticmethod
    def _migration_request_error_is_transient(message: str) -> bool:
        lowered = message.lower()
        return any(
            marker in lowered
            for marker in (
                "timed out",
                "timeout",
                "connection aborted",
                "connection reset",
                "connection error",
                "service unavailable",
                "internal server error",
                "bad gateway",
                "gateway timeout",
                "http 500",
                "http 502",
                "http 503",
                "http 504",
            )
        )

    @staticmethod
    def _port_security_groups(port: dict[str, Any]) -> set[str]:
        value = pick(port, "security_group_ids", "security_groups", default=[])
        return {str(item).strip() for item in list_value(value) if str(item).strip()}

    def _server_volume_ids(self: Any, server_id: str) -> set[str] | None:
        try:
            rows = self._json_with_transient_retry(
                "server",
                "volume",
                "list",
                server_id,
                check=False,
                timeout=min(60, self.config.resource_timeout),
                context=f"reading volume attachments for server {server_id}",
            )
        except RunCancelledError:
            raise
        except SuiteError as exc:
            self.logger.log(str(exc), "WARNING")
            return None
        if rows is None or not isinstance(rows, list):
            return None
        output: set[str] = set()
        for row in rows:
            if not isinstance(row, dict):
                return None
            volume_id = optional_text(pick(row, "id", "volume_id", default=None))
            if volume_id:
                output.add(volume_id)
        return output

    def _verify_expected_volume_attachment(
        self: Any, volume_id: str, server_id: str
    ) -> tuple[bool | None, str | None, dict[str, Any]]:
        """Verify that a known root volume remains attached to the same server.

        This is a fallback for clouds where ``server volume list`` is hidden or
        incomplete. A positive attachment from ``volume show`` is authoritative;
        missing attachment fields remain unverified rather than being guessed.
        """
        try:
            detail = self._json_with_transient_retry(
                "volume",
                "show",
                volume_id,
                check=False,
                timeout=min(60, self.config.resource_timeout),
                context=f"reading root volume {volume_id} after migration",
            )
        except RunCancelledError:
            raise
        except SuiteError as exc:
            return None, str(exc), {}
        if not isinstance(detail, dict):
            return None, "Cinder returned no usable root-volume detail", {}

        raw_attachments = pick(detail, "attachments", default=None)
        if raw_attachments is None:
            return (
                None,
                "Cinder did not expose root-volume attachment details",
                detail,
            )
        attachments = list_value(raw_attachments)
        attached_servers: set[str] = set()
        malformed = False
        for attachment in attachments:
            if not isinstance(attachment, dict):
                malformed = True
                continue
            attached_server = optional_text(
                pick(
                    attachment,
                    "server_id",
                    "server id",
                    "server_uuid",
                    "instance_uuid",
                    default=None,
                )
            )
            if attached_server:
                attached_servers.add(attached_server)
        if malformed or any(
            not isinstance(attachment, dict)
            or not pick(attachment, "server_id", "server_uuid", "instance_uuid")
            for attachment in attachments
        ):
            return (
                None,
                "Cinder exposed malformed or incomplete volume ownership",
                detail,
            )
        if attached_servers == {server_id} and len(attachments) == 1:
            return True, None, detail
        if server_id in attached_servers:
            return (
                False,
                f"Root volume {volume_id} has multiple attachments; exclusive server ownership is not verified",
                detail,
            )
        if attached_servers:
            return (
                False,
                f"Root volume {volume_id} is attached to {sorted(attached_servers)}, not server {server_id}",
                detail,
            )
        if malformed:
            return (
                None,
                "Cinder exposed malformed root-volume attachment entries",
                detail,
            )
        return (
            False,
            f"Root volume {volume_id} has no attachment to server {server_id}",
            detail,
        )

    def _migration_volume_evidence(
        self: Any,
        endpoint: Endpoint,
        before_ids: set[str] | None,
        after_ids: set[str] | None,
    ) -> tuple[bool | None, str | None, dict[str, Any]]:
        """Compare Nova identities and verify each Cinder attachment independently."""
        if before_ids is None or after_ids is None:
            return None, "Volume attachment inventory was unavailable", {}
        if before_ids != after_ids:
            return (
                False,
                f"Volume attachments changed: before={sorted(before_ids)}, after={sorted(after_ids)}",
                {},
            )
        if not endpoint.volume_id or endpoint.volume_id not in before_ids:
            return (
                None,
                "Original root-volume identity is absent from attachment inventory",
                {},
            )
        details: dict[str, Any] = {}
        for volume_id in sorted(before_ids):
            verified, error, detail = self._verify_expected_volume_attachment(
                volume_id, endpoint.server_id
            )
            details[volume_id] = detail
            if verified is not True:
                return verified, error, details
        return True, None, details

    def _migration_rows(
        self: Any, server_id: str
    ) -> tuple[list[dict[str, Any]] | None, str | None]:
        """Read Nova migration inventory and negotiate a safe CLI microversion.

        The server filter is always supplied as ``--server``.  Targeted live and
        cold migration require Nova microversion features beyond the base 2.1
        API, so an unversioned inventory command may be used only as read-only
        evidence.  It is never promoted into a cloud operation command.

        Some OpenStackClient releases reject a literal ``2.56`` selector even
        though they support the documented ``2.latest`` form.  We therefore
        probe both forms before falling back to unversioned observation.
        """
        cached = getattr(self, "_migration_compute_api_prefix", None)
        has_cached = hasattr(self, "_migration_compute_api_prefix")
        if has_cached:
            prefixes: list[tuple[str, ...]] = (
                [cached] if isinstance(cached, tuple) else [()]
            )
        else:
            prefixes = [
                ("--os-compute-api-version", "2.56"),
                ("--os-compute-api-version", "2.latest"),
                (),
            ]

        failures: list[str] = []
        for prefix in prefixes:
            try:
                rows = self._json_with_transient_retry(
                    *prefix,
                    "server",
                    "migration",
                    "list",
                    "--server",
                    server_id,
                    check=False,
                    timeout=min(60, self.config.resource_timeout),
                    context=f"reading migration records for server {server_id}",
                )
            except RunCancelledError:
                raise
            except SuiteError as exc:
                message = str(exc)
                failures.append(message)
                lowered = message.lower()
                selector_rejected = bool(prefix) and any(
                    marker in lowered
                    for marker in (
                        "not in supported versions",
                        "compute version",
                        "microversion is not supported",
                        "requested microversion",
                        "unrecognized arguments",
                        "invalid api version",
                    )
                )
                if has_cached or not selector_rejected:
                    break
                continue
            if rows is None:
                failures.append(
                    f"compute selector {' '.join(prefix) if prefix else 'unversioned'} unavailable"
                )
                if has_cached:
                    break
                continue
            if not isinstance(rows, list):
                return None, "server migration list returned an unexpected payload"
            if any(not isinstance(row, dict) for row in rows):
                return None, "server migration list contained malformed records"

            if prefix:
                self._migration_compute_api_prefix = prefix
                if prefix[-1] == "2.latest":
                    self.logger.log(
                        "OpenStackClient rejected literal compute microversion 2.56; "
                        "using the documented 2.latest selector for Nova migration "
                        "inventory and all related cloud operation commands",
                        "WARNING",
                    )
            else:
                # Preserve read-only visibility, but record that no safe selector
                # was negotiated.  _migration_command_args will refuse cloud_operation.
                self._migration_compute_api_prefix = None
                self.logger.log(
                    "Nova migration inventory is readable only without an explicit "
                    "compute microversion. Targeted migration is disabled because "
                    "running it at the base 2.1 API could change --host semantics",
                    "WARNING",
                )
            return list(rows), None

        detail = "; ".join(item for item in failures if item)
        return (
            None,
            "server migration record commands are unavailable"
            + (f": {detail}" if detail else ""),
        )

    def _migration_command_args(
        self: Any, server_id: str, *args: str
    ) -> tuple[str, ...]:
        """Return migration arguments using the negotiated safe CLI selector.

        An explicit literal ``2.56`` or ``2.latest`` selector must have passed a
        read-only migration-inventory command first.  Unversioned cloud operation is
        deliberately rejected: targeted live migration requires at least 2.30
        and targeted cold migration requires at least 2.56.
        """
        if not hasattr(self, "_migration_compute_api_prefix"):
            # Internal callers and focused tests that bypass the mandatory
            # inventory barrier retain the strict literal selector. Production
            # execution always negotiates and caches a form first.
            prefix: tuple[str, ...] | None = (
                "--os-compute-api-version",
                "2.56",
            )
        else:
            prefix = getattr(self, "_migration_compute_api_prefix", None)
        if not isinstance(prefix, tuple) or not prefix:
            raise PlacementUnavailableError(
                "Targeted migration is unavailable because OpenStackClient did "
                "not accept a safe compute microversion selector (2.56 or "
                "2.latest); no migration command was submitted"
            )
        return (*prefix, *args)

    @staticmethod
    def _migration_row_id(row: dict[str, Any]) -> str:
        return str(pick(row, "id", "uuid", "migration_id", default="") or "").strip()

    def _create_guest_migration_marker(self: Any, endpoint: Endpoint) -> dict[str, str]:
        filename = f".neutron-flux-migration-{safe_name(endpoint.server_id, 48)}.marker"
        token = f"{self.reporter.run_id}:{endpoint.server_id}:{uuid.uuid4().hex}"
        command = (
            f'umask 077; marker_path="$HOME/{filename}"; '
            f"printf '%s\\n' {shlex.quote(token)} > \"$marker_path\"; "
            'sha256sum "$marker_path"; printf \'%s\\n\' "$marker_path"'
        )
        result = self.ssh_endpoint(endpoint, command)
        if result.returncode != 0:
            raise SuiteError(
                f"Could not create persistent guest migration marker on {endpoint.label}: "
                f"{(result.stderr or result.stdout).strip()}"
            )
        lines = (result.stdout or "").strip().splitlines()
        checksum = lines[0].split()[0] if lines else ""
        path = lines[-1].strip() if len(lines) >= 2 else ""
        if not re.fullmatch(r"[0-9a-fA-F]{64}", checksum):
            raise SuiteError(
                f"Guest migration marker on {endpoint.label} returned no valid SHA-256 checksum"
            )
        if not path.startswith("/"):
            raise SuiteError(
                f"Guest migration marker on {endpoint.label} returned no absolute path"
            )
        return {"path": path, "token": token, "sha256": checksum.lower()}

    def _verify_guest_migration_marker(
        self: Any, endpoint: Endpoint, marker: dict[str, str]
    ) -> tuple[bool, str | None]:
        path = marker["path"]
        command = f"sha256sum {shlex.quote(path)} && cat {shlex.quote(path)}"
        result = self.ssh_endpoint(endpoint, command)
        if result.returncode != 0:
            return False, (
                f"Persistent guest migration marker is unreadable after migration: "
                f"{(result.stderr or result.stdout).strip()}"
            )
        lines = (result.stdout or "").splitlines()
        actual_hash = lines[0].split()[0].lower() if lines else ""
        actual_token = "\n".join(lines[1:]).strip()
        if actual_hash != marker["sha256"]:
            return False, (
                f"Guest migration marker checksum changed: expected {marker['sha256']}, "
                f"observed {actual_hash or 'missing'}"
            )
        if actual_token != marker["token"]:
            return (
                False,
                "Guest migration marker contents changed during cold migration",
            )
        return True, None

    def _verify_nova_migration_record(
        self: Any,
        endpoint: Endpoint,
        source_host: str,
        target_host: str,
        before_ids: set[str] | None,
        *,
        expected_types: set[str] | None = None,
        migration_label: str = "cold migration",
    ) -> tuple[bool | None, str | None, dict[str, Any]]:
        """Wait for the new record to settle independently of server ACTIVE.

        A transitional or not-yet-visible record is incomplete evidence, never
        proof that a migration failed. Identity/type/terminal errors still fail.
        """
        budget = max(
            0.0, float(getattr(getattr(self, "config", None), "resource_timeout", 0))
        )
        deadline = time.monotonic() + budget
        history: list[dict[str, Any]] = []
        while True:
            raise_if_cancelled()
            verified, error, row = self._observe_nova_migration_record(
                endpoint,
                source_host,
                target_host,
                before_ids,
                expected_types=expected_types,
                migration_label=migration_label,
            )
            status = str(pick(row, "status", default="") or "").lower()
            history.append(
                {
                    "status": status or "not-visible",
                    "record_id": self._migration_row_id(row) if row else None,
                    "elapsed_s": max(0.0, budget - (deadline - time.monotonic())),
                }
            )
            transitional = status in {
                "queued",
                "preparing",
                "pre-migrating",
                "started",
                "confirming",
                "running",
                "migrating",
                "post-migrating",
                "accepted",
            }
            pending = (
                not row
                and before_ids is not None
                and error
                and "no migration record" in error
            ) or (
                transitional
                and error == f"Nova migration record validation failed: status={status}"
            )
            if not pending:
                return (
                    verified,
                    error,
                    {**row, "validation_observations": history} if row else row,
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return (
                    None,
                    f"Nova migration record did not reach a terminal state within {budget:g}s (last status: {status or 'not visible'}); migration completion is unverified",
                    {**row, "validation_observations": history},
                )
            time.sleep(min(2.0, remaining))

    def _observe_nova_migration_record(
        self: Any,
        endpoint: Endpoint,
        source_host: str,
        target_host: str,
        before_ids: set[str] | None,
        *,
        expected_types: set[str] | None = None,
        migration_label: str = "cold migration",
    ) -> tuple[bool | None, str | None, dict[str, Any]]:
        if before_ids is None:
            return (
                None,
                "Pre-migration record IDs are unavailable; no record can be proven new",
                {},
            )
        rows, error = self._migration_rows(endpoint.server_id)
        if rows is None:
            return None, error, {}
        if before_ids is not None:
            candidates = [
                row
                for row in rows
                if self._migration_row_id(row)
                and self._migration_row_id(row) not in before_ids
            ]
        else:
            candidates = list(rows)
        if not candidates:
            return (
                None if before_ids is None else False,
                f"Nova exposed no migration record that could be proven new for the completed {migration_label}",
                {},
            )
        if len(candidates) != 1:
            return (
                None,
                "Multiple new Nova migration records cannot be correlated to one submission",
                {},
            )

        def record_hosts(row: dict[str, Any]) -> tuple[str, str]:
            source = str(
                pick(
                    row,
                    "source_compute",
                    "source_host",
                    "source_node",
                    default="",
                )
                or ""
            )
            destination = str(
                pick(
                    row,
                    "dest_compute",
                    "destination_compute",
                    "dest_host",
                    "destination_host",
                    "dest_node",
                    "destination_node",
                    default="",
                )
                or ""
            )
            return source, destination

        row = candidates[0]
        identity_verified, identity_error = self._migration_record_server_identity(
            row, endpoint.server_id
        )
        if identity_verified is not True:
            return identity_verified, identity_error, row

        # Completed live migrations and cold migrations are only available
        # through the migration list. The show endpoint serves in-progress live
        # migrations and must not discard valid terminal evidence with a 404.
        source, destination = record_hosts(row)
        migration_type = str(
            pick(row, "migration_type", "type", default="") or ""
        ).lower()
        status = str(pick(row, "status", default="") or "").lower()
        missing: list[str] = []
        if not source:
            missing.append("source host")
        if not destination:
            missing.append("destination host")
        if not migration_type:
            missing.append("migration type")
        if not status:
            missing.append("terminal status")
        if missing:
            return (
                None,
                "Nova migration record did not expose " + ", ".join(missing),
                row,
            )

        problems: list[str] = []
        if source != source_host:
            problems.append(f"source={source}, expected {source_host}")
        if destination != target_host:
            problems.append(f"destination={destination}, expected {target_host}")
        allowed_types = expected_types or {
            "resize",
            "migration",
            "cold migration",
            "cold_migration",
        }
        if migration_type not in allowed_types:
            problems.append(
                f"type={migration_type}, expected one of {sorted(allowed_types)}"
            )
        if status not in {"confirmed", "finished", "completed", "done"}:
            problems.append(f"status={status}")
        if problems:
            return (
                False,
                "Nova migration record validation failed: " + "; ".join(problems),
                row,
            )
        return True, None, row

    def _migration_record_server_identity(
        self: Any, row: dict[str, Any], server_id: str
    ) -> tuple[bool | None, str | None]:
        """Reject explicit foreign identities despite Nova's server filter.

        Some older CLI responses omit server UUID entirely. The scoped query
        remains usable in that case, but an exposed identity must agree.
        """
        normalized = normalized_map(row)
        for field in ("server_uuid", "server_id", "instance_uuid", "instance_id"):
            if field not in normalized:
                continue
            recorded = optional_text(normalized[field])
            if not recorded:
                return None, "Nova migration record exposed an empty server identity"
            if recorded != server_id:
                return (
                    False,
                    "Nova migration record belongs to server "
                    f"{recorded}, not submitted server {server_id}",
                )
        return True, None

    def _capture_endpoint_migration_state(
        self: Any, endpoint: Endpoint
    ) -> dict[str, Any]:
        ports: dict[str, dict[str, Any]] = {}
        port_ids = [
            port_id
            for port_id in (endpoint.management_port_id, endpoint.test_port_id)
            if port_id
        ]

        def read_port(port_id: str) -> Any:
            return self._json_with_transient_retry(
                "port",
                "show",
                port_id,
                check=False,
                timeout=min(60, self.config.resource_timeout),
                context=f"reading Neutron port {port_id} before migration",
            )

        details = bounded_map(read_port, port_ids, workers=READ_WORKERS)
        for port_id, detail in zip(port_ids, details, strict=True):
            if not isinstance(detail, dict):
                raise SuiteError(
                    f"Could not read Neutron port {port_id} before migration"
                )
            if getattr(self, "cloud_operation_coordinator", None) is not None:
                if not all(
                    self._migration_field_visible(detail, *fields)
                    for fields in (
                        ("device_id",),
                        ("status",),
                        ("binding_host_id", "binding:host_id"),
                        ("fixed_ips",),
                        ("mac_address",),
                        ("security_group_ids", "security_groups"),
                    )
                ) or (
                    pick(detail, "device_id") != endpoint.server_id
                    or str(pick(detail, "status", default="")).upper() != "ACTIVE"
                    or pick(detail, "binding_host_id", "binding:host_id")
                    != endpoint.host
                ):
                    raise UnverifiableMigrationError(
                        f"Fresh port {port_id} identity or source ownership changed after the safety barrier; migration was not submitted"
                    )
            ports[port_id] = {
                "mac_address": str(pick(detail, "mac_address", default="") or ""),
                "fixed_ips": self._fixed_ips(detail),
                "security_groups": sorted(self._port_security_groups(detail)),
            }
        migration_rows, migration_error = self._migration_rows(endpoint.server_id)
        migration_ids = self._settled_migration_ids(migration_rows, migration_error)
        volume_ids = (
            set()
            if self.config.storage == "host"
            else self._server_volume_ids(endpoint.server_id)
        )
        if volume_ids is None:
            raise UnverifiableMigrationError(
                "Volume attachment inventory was unavailable while capturing "
                f"the migration baseline for {endpoint.label}; migration was "
                "not submitted"
            )
        if (
            self.config.storage != "host"
            and getattr(self, "cloud_operation_coordinator", None) is not None
        ):
            verified, error, _ = self._migration_volume_evidence(
                endpoint, volume_ids, volume_ids
            )
            if verified is not True:
                raise UnverifiableMigrationError(
                    f"Original root-volume ownership was not verified before migration: {error}"
                )
        migration_resource_ids = [
            endpoint.server_id,
            *ports.keys(),
            *sorted(volume_ids),
        ]
        coordinator = getattr(self, "cloud_operation_coordinator", None)
        if coordinator is not None:
            coordinator.annotate_current_transaction(
                resource_ids=migration_resource_ids,
                pre_state={
                    "migration_ids": sorted(migration_ids)
                    if migration_ids is not None
                    else None,
                    "source_host": endpoint.host,
                    "migration_resource_ids": migration_resource_ids,
                    "migration_port_ids": sorted(ports),
                    "migration_volume_ids": sorted(volume_ids),
                },
            )
        return {
            "server_id": endpoint.server_id,
            "source_host": endpoint.host,
            "source_availability_zone": endpoint.availability_zone,
            "ports": ports,
            "volume_ids": volume_ids,
            "migration_ids": migration_ids,
            "migration_inventory_error": migration_error,
            "guest_marker": self._create_guest_migration_marker(endpoint),
        }

    @staticmethod
    def _migration_field_visible(detail: dict[str, Any], *candidate_keys: str) -> bool:
        visible = {
            str(item).lower().replace("-", "_").replace(":", "_") for item in detail
        }
        return any(
            key.lower().replace("-", "_").replace(":", "_") in visible
            for key in candidate_keys
        )

    def _record_migration_destination(
        self: Any,
        endpoint: Endpoint,
        target: ComputeHostInfo,
        *,
        migration_type: str,
    ) -> dict[str, Any]:
        """Persist the once-resolved destination and compatibility decision."""
        effective_storage = str(
            getattr(self.config, "effective_migration_storage", "auto")
        )
        selection = {
            "server_id": endpoint.server_id,
            "source_host": endpoint.host,
            "destination_host": target.host,
            "availability_zone": target.availability_zone,
            "aggregate_ids": sorted(target.aggregate_ids),
            "aggregate_names": sorted(target.aggregate_names),
            "migration_type": migration_type,
            "storage_mode": effective_storage,
            "storage_compatible": (
                endpoint.availability_zone is not None
                and endpoint.availability_zone == target.availability_zone
            ),
            "transport": (
                "block-live"
                if migration_type == "live" and effective_storage == "host"
                else "shared-or-volume-live"
                if migration_type == "live"
                else "cold-resize"
            ),
        }
        coordinator = getattr(self, "cloud_operation_coordinator", None)
        if coordinator is not None:
            coordinator.annotate_current_transaction(
                resource_ids=[
                    endpoint.server_id,
                    endpoint.management_port_id,
                    endpoint.test_port_id or "",
                ],
                source_host=endpoint.host,
                destination_host=target.host,
                availability_zone=target.availability_zone,
                pre_state={"destination_selection": selection},
            )
        self.reporter.event(
            "migration-destination-resolved",
            f"Migration destination resolved once for {endpoint.label}",
            **selection,
        )
        return selection

    def _pre_migration_control_plane_barrier(
        self: Any, endpoint: Endpoint, source_host: str
    ) -> dict[str, Any]:
        """Require three identical, authoritative safe-state observations."""
        if getattr(self, "cloud_operation_coordinator", None) is None:
            # Focused compatibility tests construct partial runtime objects.
            # Production builders always have the coordinator.
            return {}
        expected_ports = [
            item
            for item in (
                endpoint.management_port_id,
                endpoint.test_port_id,
            )
            if item
        ]
        previous: dict[str, Any] | None = None
        observations: list[dict[str, Any]] = []
        for observation_number in range(1, 4):
            detail = self._json_with_transient_retry(
                "server",
                "show",
                endpoint.server_id,
                check=False,
                timeout=min(60, self.config.resource_timeout),
                context=(
                    f"pre-migration safety observation {observation_number} "
                    f"for {endpoint.label}"
                ),
            )
            if not isinstance(detail, dict):
                raise UnverifiableMigrationError(
                    f"Nova returned no server detail during the pre-migration "
                    f"safety barrier for {endpoint.label}"
                )
            required_server_fields = (
                ("status",),
                ("os_ext_sts_task_state", "task_state"),
                ("os_ext_sts_power_state", "power_state"),
                ("os_ext_srv_attr_host", "host"),
            )
            if not all(
                self._migration_field_visible(detail, *fields)
                for fields in required_server_fields
            ):
                raise UnverifiableMigrationError(
                    "Nova hid one or more required pre-migration fields "
                    "(status, task_state, power_state, or host); migration "
                    f"was not submitted for {endpoint.label}"
                )
            status = str(pick(detail, "status", default="") or "").lower()
            task_state = pick(detail, "os_ext_sts_task_state", "task_state")
            task_state_cleared = nova_task_state_cleared(detail)
            power_state = str(
                pick(
                    detail,
                    "os_ext_sts_power_state",
                    "power_state",
                    default="",
                )
                or ""
            ).lower()
            host = str(pick(detail, "os_ext_srv_attr_host", "host", default="") or "")
            if (
                status != "active"
                or task_state_cleared is not True
                or power_state not in {"1", "running", "active"}
                or host != source_host
            ):
                raise UnverifiableMigrationError(
                    f"Pre-migration server state was not safe for "
                    f"{endpoint.label}: status={status or 'hidden'}, "
                    f"task_state={task_state!r} (cleared={task_state_cleared}), "
                    f"power_state={power_state or 'hidden'}, "
                    f"host={host or 'hidden'}"
                )

            rows, migration_error = self._migration_rows(endpoint.server_id)
            if rows is None:
                raise UnverifiableMigrationError(
                    "Nova migration inventory was unavailable during the "
                    f"pre-migration barrier: {migration_error or 'unknown error'}"
                )
            self._settled_migration_ids(rows, migration_error)

            ports: dict[str, dict[str, Any]] = {}

            def read_port(port_id: str) -> Any:
                return self._json_with_transient_retry(
                    "port",
                    "show",
                    port_id,
                    check=False,
                    timeout=min(60, self.config.resource_timeout),
                    context=f"pre-migration port observation for {port_id}",
                )

            # Each round completes before the next observation. Parallel reads
            # concern distinct ports in this round, never a later migration stage.
            port_rows = bounded_map(read_port, expected_ports, workers=READ_WORKERS)
            for port_id, port in zip(expected_ports, port_rows, strict=True):
                if not isinstance(port, dict):
                    raise UnverifiableMigrationError(
                        f"Expected port {port_id} was not visible before migration"
                    )
                if not all(
                    self._migration_field_visible(port, *fields)
                    for fields in (
                        ("status",),
                        ("device_id",),
                        ("binding_host_id", "binding:host_id"),
                        ("fixed_ips",),
                        ("mac_address",),
                        (
                            "security_group_ids",
                            "security_groups",
                            "security_group",
                        ),
                    )
                ):
                    raise UnverifiableMigrationError(
                        f"Neutron hid status, binding host, fixed IPs, MAC, or "
                        f"security groups for "
                        f"port {port_id}; migration was not submitted"
                    )
                port_status = str(pick(port, "status", default="") or "").upper()
                device_id = str(pick(port, "device_id", default="") or "")
                binding_host = str(
                    pick(
                        port,
                        "binding_host_id",
                        "binding:host_id",
                        default="",
                    )
                    or ""
                )
                if (
                    port_status != "ACTIVE"
                    or binding_host != source_host
                    or device_id != endpoint.server_id
                ):
                    raise UnverifiableMigrationError(
                        f"Port {port_id} is not stably ACTIVE on {source_host}: "
                        f"status={port_status or 'hidden'}, "
                        f"binding_host={binding_host or 'hidden'}, device_id={device_id or 'hidden'}"
                    )
                ports[port_id] = {
                    "status": port_status,
                    "device_id": device_id,
                    "binding_host": binding_host,
                    "fixed_ips": sorted(self._fixed_ips(port).items()),
                    "mac_address": str(pick(port, "mac_address", default="") or ""),
                    "security_groups": sorted(self._port_security_groups(port)),
                }

            if not self._wait_for_ssh(
                endpoint.management_ip,
                proxy=True,
                timeout=min(30, self.config.convergence_timeout),
            ):
                raise UnverifiableMigrationError(
                    f"SSH was not reachable during the pre-migration barrier "
                    f"for {endpoint.label}"
                )
            probe_ready, probe_evidence = self._existing_probe_service_ready(endpoint)
            if not probe_ready:
                raise UnverifiableMigrationError(
                    f"The existing TCP/UDP probe process was not healthy before "
                    f"migration of {endpoint.label}: {probe_evidence}"
                )
            observation = {
                "status": status,
                "task_state": task_state,
                "task_state_cleared": task_state_cleared,
                "power_state": power_state,
                "source_host": host,
                "ports": ports,
                "migration_ids": sorted(
                    self._migration_row_id(row)
                    for row in rows
                    if self._migration_row_id(row)
                ),
                "probe_ready": True,
            }
            if previous is not None and observation != previous:
                raise UnverifiableMigrationError(
                    f"Pre-migration control-plane state changed between "
                    f"observations for {endpoint.label}; migration was not submitted"
                )
            observations.append(observation)
            previous = observation
            self.reporter.event(
                "migration-safety-observation",
                (
                    f"Pre-migration safety observation {observation_number}/3 "
                    f"was stable for {endpoint.label}"
                ),
                server_id=endpoint.server_id,
                observation=observation_number,
                source_host=source_host,
                expected_ports=expected_ports,
            )
            if observation_number < 3:
                time.sleep(2)

        baseline = {
            "stable_observations": observations,
            "observation_count": len(observations),
        }
        coordinator = getattr(self, "cloud_operation_coordinator", None)
        if coordinator is not None:
            coordinator.annotate_current_transaction(pre_state=baseline)
        return baseline

    def _wait_for_migration_acceptance(
        self: Any,
        endpoint: Endpoint,
        target_host: str,
        before: dict[str, Any],
    ) -> dict[str, Any]:
        """Observe an ambiguous submission; never turn missing evidence into retry."""
        started = time.monotonic()
        deadline = started + min(120, max(15, int(self.config.resource_timeout)))
        baseline_ids = before.get("migration_ids")
        last_evidence: dict[str, Any] = {}
        while time.monotonic() < deadline:
            detail = self._json_with_transient_retry(
                "server",
                "show",
                endpoint.server_id,
                check=False,
                timeout=min(15, max(1, int(deadline - time.monotonic()))),
                context=(
                    f"observing ambiguous migration acceptance for {endpoint.label}"
                ),
            )
            detail = detail if isinstance(detail, dict) else {}
            host = str(pick(detail, "os_ext_srv_attr_host", "host", default="") or "")
            raw_task_state = pick(detail, "os_ext_sts_task_state", "task_state")
            task_state = str(raw_task_state).lower()
            task_state_cleared = nova_task_state_cleared(detail)
            rows, migration_error = self._migration_rows(endpoint.server_id)
            new_rows = []
            if rows is not None and baseline_ids is not None:
                new_rows = [
                    row
                    for row in rows
                    if self._migration_row_id(row)
                    and self._migration_row_id(row) not in baseline_ids
                ]
            port_bindings: dict[str, str] = {}
            for port_id in (
                endpoint.management_port_id,
                endpoint.test_port_id,
            ):
                if not port_id:
                    continue
                try:
                    port = self._json_with_transient_retry(
                        "port",
                        "show",
                        port_id,
                        check=False,
                        timeout=min(15, max(1, int(deadline - time.monotonic()))),
                        context=(
                            f"observing port {port_id} during ambiguous "
                            "migration acceptance"
                        ),
                    )
                except RunCancelledError:
                    raise
                except SuiteError:
                    port = None
                if isinstance(port, dict):
                    port_bindings[port_id] = str(
                        pick(
                            port,
                            "binding_host_id",
                            "binding:host_id",
                            default="",
                        )
                        or ""
                    )
            migrating_task = task_state_cleared is False and any(
                marker in task_state
                for marker in ("migrat", "resize", "confirm", "revert")
            )
            binding_transition = any(
                binding and binding != before.get("source_host")
                for binding in port_bindings.values()
            )
            accepted = bool(
                new_rows
                or migrating_task
                or (host and host != before.get("source_host"))
                or binding_transition
            )
            last_evidence = {
                "server_host": host or None,
                "target_host": target_host,
                "task_state": raw_task_state,
                "task_state_cleared": task_state_cleared,
                "new_migration_ids": [self._migration_row_id(row) for row in new_rows],
                "migration_inventory_error": migration_error,
                "port_bindings": port_bindings,
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
            if accepted:
                self.reporter.event(
                    "migration-acceptance-detected",
                    f"Nova acceptance evidence appeared for {endpoint.label}",
                    server_id=endpoint.server_id,
                    **last_evidence,
                )
                return last_evidence
            elapsed = time.monotonic() - started
            interval = 2 if elapsed < 15 else 5 if elapsed < 60 else 10
            time.sleep(min(interval, max(0.0, deadline - time.monotonic())))
        self.reporter.event(
            "migration-acceptance-ambiguous",
            f"Migration acceptance remained ambiguous for {endpoint.label}",
            server_id=endpoint.server_id,
            **last_evidence,
        )
        raise AmbiguousCloudOperationError(
            "Migration submission outcome remains ambiguous after the bounded "
            f"acceptance window for {endpoint.label}; no retry is permitted"
        )

    def _authoritative_migration_failure(
        self: Any, endpoint: Endpoint, before: dict[str, Any] | None
    ) -> tuple[bool, dict[str, Any]]:
        """Return true only for a provably new terminal failed migration record."""
        if not before or before.get("migration_ids") is None:
            return False, {"reason": "pre-migration record IDs were unavailable"}
        rows, error = self._migration_rows(endpoint.server_id)
        if rows is None:
            return False, {"reason": error or "migration records unavailable"}
        baseline_ids = set(before["migration_ids"])
        new_rows = [
            row
            for row in rows
            if self._migration_row_id(row)
            and self._migration_row_id(row) not in baseline_ids
        ]
        if not new_rows:
            return False, {"reason": "no provably new migration record exists"}
        failed_statuses = {
            "cancelled",
            "canceled",
            "error",
            "failed",
            "reverted",
        }
        running_statuses = {
            "accepted",
            "confirming",
            "migrating",
            "post-migrating",
            "pre-migrating",
            "preparing",
            "queued",
            "reverting",
            "running",
            "started",
        }
        statuses = [
            str(pick(row, "status", default="") or "").lower() for row in new_rows
        ]
        evidence = {
            "new_migration_ids": [self._migration_row_id(row) for row in new_rows],
            "statuses": statuses,
            "migration_records": new_rows,
        }
        for row in new_rows:
            identity_verified, identity_error = self._migration_record_server_identity(
                row, endpoint.server_id
            )
            if identity_verified is not True:
                return False, {**evidence, "reason": identity_error}
        expected_type = before.get("migration_type")
        allowed_types = (
            {"live", "live migration", "live-migration", "live_migration"}
            if expected_type == "live"
            else {"resize", "migration", "cold migration", "cold_migration"}
        )
        if expected_type in {"live", "cold"} and (
            len(new_rows) != 1
            or pick(new_rows[0], "source_compute", "source_host")
            != before.get("source_host")
            or pick(new_rows[0], "dest_compute", "destination_compute", "dest_host")
            != before.get("target_host")
            or str(pick(new_rows[0], "type", "migration_type", default="")).lower()
            not in allowed_types
        ):
            return False, {
                **evidence,
                "reason": "new migration does not match the submitted move",
            }
        if any(status in running_statuses or not status for status in statuses):
            return False, {
                **evidence,
                "reason": "a new migration is running or has an unknown status",
            }
        if not all(status in failed_statuses for status in statuses):
            return False, {
                **evidence,
                "reason": "the new migration record is not terminal-failed",
            }
        return True, evidence

    def _current_command_was_rejected(self) -> bool:
        coordinator = getattr(self, "cloud_operation_coordinator", None)
        if coordinator is None:
            # Production ResourceBuilder instances always install the durable
            # coordinator. Partial compatibility harnesses cannot inspect its
            # journal, so preserve their historical deterministic-error path.
            return True
        records = coordinator.current_transaction_records()
        return bool(
            records
            and records[-1].get("outcome") == "COMMAND_REJECTED"
            and records[-1].get("accepted") is False
        )

    def _mark_current_migration_failed_retryable(
        self: Any, evidence: dict[str, Any]
    ) -> None:
        coordinator = getattr(self, "cloud_operation_coordinator", None)
        if coordinator is None:
            return
        records = coordinator.current_transaction_records()
        if not records:
            return
        record = records[-1]
        if record.get("outcome") not in {"AMBIGUOUS", "IN_PROGRESS"}:
            return
        coordinator.resolve(
            str(record["operation_id"]),
            CloudOperationOutcome.FAILED_RETRYABLE,
            evidence=evidence,
            message=(
                "Authoritative Nova evidence proves the migration failed "
                "terminally and the retry barrier passed"
            ),
        )

    def _mark_current_migration_succeeded(self: Any, evidence: dict[str, Any]) -> None:
        """Commit a proven migration before non-cloud reporting can fail.

        Nova and Neutron settlement is the authority for whether deletion is
        safe. A later local result-rendering failure must not leave an already
        completed migration quarantined as IN_PROGRESS.
        """
        from ..migration_completion import (
            migration_completion,
            migration_operation_settlement,
        )

        coordinator = getattr(self, "cloud_operation_coordinator", None)
        if coordinator is None:
            return
        completion = migration_completion(evidence)
        settlement = migration_operation_settlement(evidence)
        records = coordinator.current_transaction_records()
        if not records:
            return
        record = records[-1]
        if record.get("outcome") not in {"AMBIGUOUS", "IN_PROGRESS"}:
            return
        assessments = {
            **evidence,
            "completion_assessment": completion,
            "operation_settlement_assessment": settlement,
        }
        if settlement["verified"] is not True:
            reason = (
                "Migration handoff was observed but operation settlement is not verified; "
                "no resubmission is permitted: "
                + ", ".join(settlement["failed_checks"] + settlement["missing_checks"])
            )
            coordinator.keep_current_ambiguity(reason)
            coordinator.resolve(
                str(record["operation_id"]),
                CloudOperationOutcome.AMBIGUOUS,
                evidence=assessments,
                message=reason,
            )
            return
        coordinator.resolve(
            str(record["operation_id"]),
            CloudOperationOutcome.SUCCEEDED,
            evidence=assessments,
            message=(
                "Authoritative Nova and Neutron settlement proved the migration "
                "operation completed before result publication; "
                f"migration validation is {completion['status']}"
            ),
        )

    def _migration_operation_evidence(
        self: Any,
        endpoint: Endpoint,
        target_host: str,
        before: dict[str, Any],
        evidence: dict[str, Any],
        port_details: dict[str, Any],
        server_detail: dict[str, Any],
        *,
        migration_type: str,
    ) -> dict[str, Any]:
        """Retain failed validation while proving whether its command settled.

        Only the exceptional validation-failure path performs another bounded
        settlement read. Neutron ACTIVE is a health assertion; unchanged port
        identity, server ownership and destination binding prove the handoff.
        """
        from ..migration_completion import migration_completion

        completion = migration_completion(evidence)
        expected_ports = before.get("ports")
        ownership: bool | None = None
        if evidence.get("port_binding_verified") is True:
            ownership = True
        elif isinstance(expected_ports, dict) and expected_ports:
            if set(port_details) == set(expected_ports):
                ownership = all(
                    isinstance(actual, dict)
                    and actual.get("device_id") == endpoint.server_id
                    and actual.get("binding_host_id") == target_host
                    and bool(expected.get("mac_address"))
                    and actual.get("mac_address") == expected.get("mac_address")
                    and "fixed_ips" in actual
                    and actual["fixed_ips"] == expected.get("fixed_ips")
                    and "security_groups" in actual
                    and sorted(actual["security_groups"])
                    == sorted(expected.get("security_groups", ()))
                    for port_id, expected in expected_ports.items()
                    for actual in (port_details[port_id],)
                )
        output = {
            **evidence,
            "server_status": pick(server_detail, "status"),
            "port_ownership_verified": ownership,
            "operation_inventory_verified": True
            if completion["verified"] is True
            else None,
        }
        if completion["verified"] is True:
            return output
        if not (
            getattr(self, "cloud_operation_coordinator", None) is not None
            and ownership is True
            and evidence.get("migration_record_verified") is True
            and evidence.get("task_state_cleared") is True
            and evidence.get("volume_attachment_verified") is True
            and completion["checks"]["placement_verified"] is True
        ):
            return output
        try:
            settled_server = self._wait_for_server_settlement(
                endpoint.server_id,
                list(expected_ports or {}),
                expected_statuses={"active"},
                expected_host=target_host,
                display_name=endpoint.server_name,
                stable_observations=3,
                require_power_state=True,
            )
            verified, error, record = self._verify_nova_migration_record(
                endpoint,
                evidence["source_host"],
                target_host,
                before.get("migration_ids"),
                **(
                    {
                        "expected_types": self._LIVE_TYPES,
                        "migration_label": "live migration",
                    }
                    if migration_type == "live"
                    else {}
                ),
            )
        except RunCancelledError:
            raise
        except SuiteError as exc:
            output["operation_inventory_error"] = str(exc)
            return output
        output.update(
            operation_inventory_verified=verified,
            operation_inventory_error=error,
            operation_migration_record=record,
            operation_server_detail=settled_server,
            server_status=pick(settled_server, "status"),
            task_state_cleared=nova_task_state_cleared(settled_server),
        )
        return output

    def _mark_current_migration_failed_final(
        self: Any, evidence: dict[str, Any]
    ) -> None:
        coordinator = getattr(self, "cloud_operation_coordinator", None)
        if coordinator is None:
            return
        records = coordinator.current_transaction_records()
        if not records:
            return
        record = records[-1]
        if record.get("outcome") not in {"AMBIGUOUS", "IN_PROGRESS"}:
            return
        coordinator.resolve(
            str(record["operation_id"]),
            CloudOperationOutcome.FAILED_FINAL,
            evidence=evidence,
            message=(
                "Cancellation reconciliation proved the migration terminally "
                "failed; no retry was scheduled"
            ),
        )

    def _wait_for_migration_handoff(
        self: Any, endpoint: Endpoint, target_host: str
    ) -> tuple[dict[str, Any], bool]:
        """Wait for VERIFY_RESIZE, or detect cloud-side automatic confirmation.

        The caller confirms immediately on the first VERIFY_RESIZE observation.
        ``True`` in the return tuple means Nova had already auto-confirmed.
        """
        started = time.monotonic()
        deadline = started + self.config.resource_timeout
        next_progress = started
        last_status = ""
        while time.monotonic() < deadline:
            detail = (
                self._json_with_transient_retry(
                    "server",
                    "show",
                    endpoint.server_id,
                    check=False,
                    timeout=min(15, max(1, int(deadline - time.monotonic()))),
                    context=f"polling cold migration handoff for {endpoint.label}",
                )
                or {}
            )
            status = str(pick(detail, "status", default="") or "").lower()
            host = str(pick(detail, "os_ext_srv_attr_host", "host", default="") or "")
            now = time.monotonic()
            if status != last_status and status:
                self.logger.log(
                    f"Cold migration for {endpoint.label}: status={status.upper()}, "
                    f"host={host or 'unknown'}, elapsed={int(now - started)}s"
                )
                last_status = status
                next_progress = now + self.config.progress_interval
            elif now >= next_progress:
                self.logger.log(
                    f"Still waiting for cold migration handoff for {endpoint.label}: "
                    f"status={status.upper() or 'UNKNOWN'}, host={host or 'unknown'}, "
                    f"target={target_host}, elapsed={int(now - started)}s/{self.config.resource_timeout}s"
                )
                next_progress = now + self.config.progress_interval
            if status == "verify_resize":
                return detail, False
            if status == "active" and host == target_host:
                return detail, True
            if status == "error":
                fault = pick(detail, "fault", default=None)
                raise SuiteError(
                    f"Cold migration placed {endpoint.label} into ERROR"
                    + (f": fault={fault}" if fault else "")
                )
            time.sleep(2)
        raise SuiteError(
            f"Timed out waiting for {endpoint.label} to reach VERIFY_RESIZE or ACTIVE on {target_host}"
        )

    def _wait_for_active_on_target(
        self: Any, endpoint: Endpoint, target_host: str
    ) -> dict[str, Any]:
        started = time.monotonic()
        deadline = started + self.config.resource_timeout
        last_status = ""
        last_host = ""
        while time.monotonic() < deadline:
            detail = (
                self._json_with_transient_retry(
                    "server",
                    "show",
                    endpoint.server_id,
                    check=False,
                    timeout=min(15, max(1, int(deadline - time.monotonic()))),
                    context=f"waiting for {endpoint.label} to become ACTIVE on {target_host}",
                )
                or {}
            )
            status = str(pick(detail, "status", default="") or "").lower()
            host = str(pick(detail, "os_ext_srv_attr_host", "host", default="") or "")
            last_status, last_host = status, host
            if status == "active" and host == target_host:
                return detail
            if status == "error":
                fault = pick(detail, "fault", default=None)
                raise SuiteError(
                    f"Cold migration placed {endpoint.label} into ERROR"
                    + (f": fault={fault}" if fault else "")
                )
            time.sleep(2)
        raise SuiteError(
            f"Timed out waiting for {endpoint.label} to become ACTIVE on {target_host}: "
            f"status={last_status or 'unknown'}, host={last_host or 'unknown'}"
        )
