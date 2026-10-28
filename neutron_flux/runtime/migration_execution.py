from __future__ import annotations

import time
from typing import Any

from ..cancellation import cancellation_reconciliation
from ..errors import (
    AmbiguousCloudOperationError,
    CommandTimeoutError,
    PlacementUnavailableError,
    PortValidationError,
    RetryableMigrationError,
    RunCancelledError,
    SuiteError,
    UnsafeMigrationStateError,
    UnverifiableMigrationError,
)
from ..migration_completion import migration_completion, migration_operation_settlement
from ..models import ComputeHostInfo, Endpoint, MigrationResult
from ..utils import normalized_map, nova_task_state_cleared, optional_text, pick
from .context import serialized_lifecycle


class MigrationExecutionMixin:
    """Cold-migration execution and recovery sequencing."""

    def _confirm_cold_migration(
        self: Any, endpoint: Endpoint, target_host: str
    ) -> bool:
        """Confirm immediately and reconcile local timeout races safely.

        Returns ``True`` only when Nova had already auto-confirmed before an
        explicit confirmation could be observed. A local CLI timeout is never
        treated as proof that the remote confirmation failed.
        """
        commands = (
            ("server", "migration", "confirm", endpoint.server_id),
            ("server", "migrate", "confirm", endpoint.server_id),
        )
        errors: list[str] = []
        for command in commands:
            try:
                result = self.osc.run(
                    *self._migration_command_args(endpoint.server_id, *command),
                    check=False,
                    timeout=min(60, self.config.resource_timeout),
                )
            except CommandTimeoutError as exc:
                errors.append(str(exc))
                self.logger.log(
                    f"Confirmation command timed out for {endpoint.label}; "
                    "reconciling Nova state without another command spelling",
                    "WARNING",
                )
                detail = (
                    self._json_with_transient_retry(
                        "server",
                        "show",
                        endpoint.server_id,
                        check=False,
                        timeout=min(30, self.config.resource_timeout),
                        context=f"reconciling confirmation timeout for {endpoint.label}",
                    )
                    or {}
                )
                status = str(pick(detail, "status", default="") or "").lower()
                host = str(
                    pick(detail, "os_ext_srv_attr_host", "host", default="") or ""
                )
                if status == "active" and host == target_host:
                    self.logger.log(
                        f"Cold migration confirmation for {endpoint.label} completed remotely despite the local timeout",
                        "WARNING",
                    )
                    return False
                if status == "error":
                    raise SuiteError(
                        f"Cold migration confirmation timed out and {endpoint.label} entered ERROR"
                    ) from exc
                if status != "verify_resize":
                    raise AmbiguousCloudOperationError(
                        f"Cold migration confirmation timed out with uncertain state for {endpoint.label}: "
                        f"status={status or 'unknown'}, host={host or 'unknown'}"
                    ) from exc
                raise AmbiguousCloudOperationError(
                    f"Cold migration confirmation timed out while {endpoint.label} "
                    "remains in VERIFY_RESIZE; acceptance is ambiguous, so no "
                    "alternate confirmation or revert was submitted"
                ) from exc
            if result.returncode == 0:
                self.logger.log(
                    f"Immediately confirmed cold migration for {endpoint.label}"
                )
                return False
            errors.append((result.stderr or result.stdout).strip())
            if not self._current_command_was_rejected():
                raise AmbiguousCloudOperationError(
                    f"Cold migration confirmation for {endpoint.label} returned "
                    "an ambiguous client/API result; no alternate command "
                    "spelling or revert was submitted"
                )

        detail = (
            self._json_with_transient_retry(
                "server",
                "show",
                endpoint.server_id,
                check=False,
                timeout=min(30, self.config.resource_timeout),
                context=f"checking confirmation result for {endpoint.label}",
            )
            or {}
        )
        status = str(pick(detail, "status", default="") or "").lower()
        host = str(pick(detail, "os_ext_srv_attr_host", "host", default="") or "")
        if status == "active" and host == target_host:
            self.logger.log(
                f"Cold migration for {endpoint.label} was automatically confirmed before explicit confirmation completed",
                "WARNING",
            )
            return True

        if status == "verify_resize":
            revert_errors: list[str] = []
            for command in (
                ("server", "migration", "revert", endpoint.server_id),
                ("server", "migrate", "revert", endpoint.server_id),
            ):
                try:
                    result = self.osc.run(
                        *self._migration_command_args(endpoint.server_id, *command),
                        check=False,
                        timeout=min(60, self.config.resource_timeout),
                    )
                except CommandTimeoutError as exc:
                    raise AmbiguousCloudOperationError(
                        f"Cold migration revert timed out for {endpoint.label}; "
                        "no alternate revert command was submitted"
                    ) from exc
                if result.returncode == 0:
                    self._wait_for_status(
                        "server",
                        endpoint.server_id,
                        {"active"},
                        {"error"},
                        display_name=endpoint.server_name,
                    )
                    recovered = (
                        self._json_with_transient_retry(
                            "server",
                            "show",
                            endpoint.server_id,
                            check=False,
                            timeout=min(60, self.config.resource_timeout),
                            context=f"reading reverted server {endpoint.label}",
                        )
                        or {}
                    )
                    endpoint.host = (
                        optional_text(
                            pick(
                                recovered, "os_ext_srv_attr_host", "host", default=None
                            )
                        )
                        or endpoint.host
                    )
                    endpoint.availability_zone = (
                        optional_text(
                            pick(
                                recovered,
                                "os_ext_az_availability_zone",
                                "availability_zone",
                                default=None,
                            )
                        )
                        or endpoint.availability_zone
                    )
                    if self._wait_for_ssh(
                        endpoint.management_ip,
                        proxy=True,
                        timeout=self.config.convergence_timeout,
                    ):
                        try:
                            self.reconfigure_endpoint(endpoint, reuse_probe=True)
                        except TypeError as exc:
                            if "reuse_probe" not in str(exc):
                                raise
                            self.reconfigure_endpoint(endpoint)
                    raise SuiteError(
                        f"Could not confirm cold migration for {endpoint.label}; "
                        "the pending migration was reverted immediately: "
                        + " | ".join(item for item in errors if item)
                    )
                revert_errors.append((result.stderr or result.stdout).strip())
                if not self._current_command_was_rejected():
                    raise AmbiguousCloudOperationError(
                        f"Cold migration revert for {endpoint.label} returned "
                        "an ambiguous result; no alternate revert command was "
                        "submitted"
                    )
            errors.extend(revert_errors)

        raise SuiteError(
            f"Could not confirm cold migration for {endpoint.label}: "
            + " | ".join(item for item in errors if item)
        )

    def _verify_migrated_ports(
        self: Any,
        endpoint: Endpoint,
        target_host: str,
        before: dict[str, Any],
    ) -> tuple[bool | None, dict[str, Any]]:
        deadline = time.monotonic() + self.config.convergence_timeout
        last_details: dict[str, Any] = {}
        binding_fields_visible = False
        status_fields_visible = False
        stable_reads = 0
        previous_signature: tuple[Any, ...] | None = None
        required_stable_reads = (
            3 if getattr(self, "cloud_operation_coordinator", None) is not None else 1
        )
        started = time.monotonic()
        while time.monotonic() < deadline:
            all_ready = True
            all_binding_visible = True
            all_status_visible = True
            for port_id, expected in before["ports"].items():
                try:
                    detail = self._json_with_transient_retry(
                        "port",
                        "show",
                        port_id,
                        check=False,
                        timeout=min(60, self.config.resource_timeout),
                        context=f"reading Neutron port {port_id} after migration",
                    )
                except RunCancelledError:
                    raise
                except SuiteError as exc:
                    raise PortValidationError(str(exc), ports=last_details) from exc
                if not isinstance(detail, dict):
                    raise PortValidationError(
                        f"Could not read Neutron port {port_id} after migration",
                        ports=last_details,
                    )
                normalized = normalized_map(detail)
                binding_visible = "binding_host_id" in normalized
                ownership_visible = "device_id" in normalized
                status_visible = "status" in normalized
                binding_fields_visible = binding_fields_visible or binding_visible
                status_fields_visible = status_fields_visible or status_visible
                all_binding_visible = (
                    all_binding_visible and binding_visible and ownership_visible
                )
                all_status_visible = all_status_visible and status_visible
                binding_host = str(normalized.get("binding_host_id") or "")
                status = str(normalized.get("status") or "").upper()
                actual = {
                    "role": (
                        "management"
                        if port_id == endpoint.management_port_id
                        else "test"
                        if port_id == endpoint.test_port_id
                        else "endpoint"
                    ),
                    "mac_address": str(normalized.get("mac_address") or ""),
                    "fixed_ips": self._fixed_ips(detail),
                    # Result evidence is persisted as JSON. Keep the comparison
                    # deterministic and never let the internal set returned by
                    # _port_security_groups escape into a MigrationResult.
                    "security_groups": sorted(self._port_security_groups(detail)),
                    "binding_host_id": binding_host or None,
                    "status": status or None,
                    "device_id": str(normalized.get("device_id") or "")
                    if ownership_visible
                    else None,
                }
                last_details[port_id] = actual
                if ownership_visible and actual["device_id"] != endpoint.server_id:
                    raise PortValidationError(
                        f"Neutron port {port_id} is owned by {actual['device_id'] or 'no server'}, not {endpoint.server_id}",
                        ports=last_details,
                    )
                if actual["mac_address"] != expected["mac_address"]:
                    raise PortValidationError(
                        f"Neutron port {port_id} MAC address changed during migration",
                        ports=last_details,
                    )
                if actual["fixed_ips"] != expected["fixed_ips"]:
                    raise PortValidationError(
                        f"Neutron port {port_id} fixed IP allocation changed during migration",
                        ports=last_details,
                    )
                if set(actual["security_groups"]) != set(expected["security_groups"]):
                    raise PortValidationError(
                        f"Neutron port {port_id} security groups changed during migration",
                        ports=last_details,
                    )
                if not status_visible or status != "ACTIVE":
                    all_ready = False
                if not binding_visible or binding_host != target_host:
                    all_ready = False
            if all_ready and all_binding_visible and all_status_visible:
                signature = tuple(
                    (
                        port_id,
                        details.get("mac_address"),
                        tuple(sorted((details.get("fixed_ips") or {}).items())),
                        tuple(sorted(details.get("security_groups") or ())),
                        details.get("binding_host_id"),
                        details.get("status"),
                        details.get("device_id"),
                    )
                    for port_id, details in sorted(last_details.items())
                )
                if signature == previous_signature:
                    stable_reads += 1
                else:
                    stable_reads = 1
                previous_signature = signature
                if stable_reads >= required_stable_reads:
                    return True, last_details
                time.sleep(2)
                continue
            stable_reads = 0
            previous_signature = None
            # Policy-hidden fields can never become authoritative. Preserve
            # identity checks and return UNVERIFIED without waiting the entire
            # convergence timeout once every visible field is otherwise ready.
            visible_values_ready = all(
                (details.get("status") in {None, "ACTIVE"})
                and (details.get("binding_host_id") in {None, target_host})
                for details in last_details.values()
            )
            if visible_values_ready and (
                not all_binding_visible or not all_status_visible
            ):
                return None, last_details
            elapsed = time.monotonic() - started
            interval = 2 if elapsed < 10 else 5 if elapsed < 30 else 10
            time.sleep(min(interval, self.config.convergence_interval))
        if binding_fields_visible or status_fields_visible:
            bindings = {
                port_id: {
                    "binding_host_id": details.get("binding_host_id"),
                    "status": details.get("status"),
                }
                for port_id, details in last_details.items()
            }
            raise PortValidationError(
                f"Neutron ports did not become ACTIVE and bind to destination host {target_host}: {bindings}",
                ports=last_details,
            )
        return None, last_details

    def _cold_migrate_endpoint_once(
        self: Any, endpoint: Endpoint, target: ComputeHostInfo
    ) -> MigrationResult:
        """Perform one cold-migration attempt and full destination validation."""
        if not endpoint.host:
            raise PlacementUnavailableError(
                f"Nova did not expose the source compute host for {endpoint.label}"
            )
        source_host = endpoint.host
        source_az = endpoint.availability_zone
        target_az = target.availability_zone
        if not source_az:
            source_info = self.compute_host_inventory(refresh=True).get(source_host)
            source_az = source_info.availability_zone if source_info else None
            endpoint.availability_zone = source_az
        if source_host == target.host:
            raise PlacementUnavailableError(
                f"Cold migration target for {endpoint.label} equals its current host {source_host}"
            )
        if not source_az or not target_az:
            raise PlacementUnavailableError(
                "Source or destination availability zone is unknown"
            )
        if source_az != target_az:
            raise PlacementUnavailableError(
                f"Cross-AZ cold migration is disabled by design ({source_az} -> {target_az})"
            )

        self._record_migration_destination(
            endpoint,
            target,
            migration_type="cold",
        )
        self._pre_migration_control_plane_barrier(endpoint, source_host)
        before = self._capture_endpoint_migration_state(endpoint)
        before["target_host"] = target.host
        before["migration_type"] = "cold"
        endpoint.metadata["_migration_attempt_baseline"] = before
        self.probe_service.stop(endpoint)
        self.logger.log(
            f"Cold-migrating {endpoint.label} from {source_host} to {target.host}; "
            f"availability_zone={source_az}"
        )
        request_error: str | None = None
        try:
            request = self.osc.run(
                *self._migration_command_args(
                    endpoint.server_id,
                    "server",
                    "migrate",
                    "--host",
                    target.host,
                    endpoint.server_id,
                ),
                check=False,
                timeout=min(60, self.config.resource_timeout),
            )
        except CommandTimeoutError as exc:
            request = None
            request_error = str(exc)
            self.logger.log(
                f"Cold migration request timed out locally for {endpoint.label}; reconciling Nova state before classifying the attempt",
                "WARNING",
            )
        if request is not None and request.returncode != 0:
            request_error = (request.stderr or request.stdout).strip()
            lowered = request_error.lower()
            unavailable_markers = (
                "no valid host",
                "not supported",
                "microversion",
                "policy doesn't allow",
                "forbidden",
                "http 403",
            )
            if (
                any(marker in lowered for marker in unavailable_markers)
                and self._current_command_was_rejected()
            ):
                raise PlacementUnavailableError(
                    f"Nova could not provide targeted cold migration coverage: {request_error}"
                )
            if self._migration_request_error_is_transient(request_error):
                self.logger.log(
                    f"Cold migration client returned a transient error for "
                    f"{endpoint.label}; reconciling Nova state before classifying "
                    f"the attempt: {request_error}",
                    "WARNING",
                )
            else:
                raise SuiteError(
                    f"Nova rejected cold migration of {endpoint.label}: {request_error}"
                )
        if request_error:
            self._wait_for_migration_acceptance(endpoint, target.host, before)

        try:
            _, automatically_confirmed = self._wait_for_migration_handoff(
                endpoint, target.host
            )
        except RunCancelledError:
            raise
        except SuiteError as exc:
            if request_error:
                raise SuiteError(
                    f"Cold migration client error was {request_error!r}; Nova state "
                    f"did not reconcile on {target.host}: {exc}"
                ) from exc
            raise
        if not automatically_confirmed:
            # Confirmation is deliberately immediate. Holding VERIFY_RESIZE
            # consumes allocations on both hosts and can stall unattended runs.
            automatically_confirmed = self._confirm_cold_migration(
                endpoint, target.host
            )
        self._wait_for_status(
            "server",
            endpoint.server_id,
            {"active"},
            {"error"},
            display_name=endpoint.server_name,
        )
        server_detail = self._wait_for_active_on_target(endpoint, target.host)
        if getattr(self, "lifecycle_settlement_enabled", False):
            server_detail = self._wait_for_server_settlement(
                endpoint.server_id,
                [endpoint.management_port_id, endpoint.test_port_id or ""],
                expected_statuses={"active"},
                expected_host=target.host,
                display_name=endpoint.server_name,
                stable_observations=3,
                require_power_state=True,
            )
        destination_host = str(
            pick(server_detail, "os_ext_srv_attr_host", "host", default="") or ""
        )
        reported_destination_az = (
            str(
                pick(
                    server_detail,
                    "os_ext_az_availability_zone",
                    "availability_zone",
                    default="",
                )
                or ""
            )
            or None
        )
        destination_az = reported_destination_az or target_az
        destination_az_source = (
            "server-show" if reported_destination_az else "target-host-inventory"
        )
        raw_task_state = pick(
            server_detail,
            "os_ext_sts_task_state",
            "task_state",
            default=None,
        )
        task_state_cleared = nova_task_state_cleared(server_detail)
        if task_state_cleared is False:
            raise SuiteError(
                f"Nova migration completed but task_state remains {raw_task_state!r} for {endpoint.label}"
            )
        if destination_host != target.host:
            raise SuiteError(
                f"Nova reported migration complete but {endpoint.label} is on {destination_host or 'unknown'}, not requested host {target.host}"
            )
        if destination_az != source_az:
            raise SuiteError(
                f"Migration changed availability zone for {endpoint.label}: {source_az} -> {destination_az}"
            )

        migration_record_verified, migration_record_error, migration_record = (
            self._verify_nova_migration_record(
                endpoint,
                source_host,
                target.host,
                before.get("migration_ids"),
            )
        )

        port_binding_verified: bool | None
        port_details: dict[str, Any]
        port_validation_error: str | None = None
        try:
            port_binding_verified, port_details = self._verify_migrated_ports(
                endpoint, target.host, before
            )
        except RunCancelledError:
            raise
        except SuiteError as exc:
            # The Nova move itself succeeded. Preserve that verdict and return
            # the Neutron validation failure separately so the executor can
            # identify the actual failing layer.
            port_binding_verified = False
            port_details = getattr(exc, "ports", {})
            port_validation_error = str(exc)
        volume_detail: dict[str, Any] = {}
        volume_attachment_verified: bool | None
        volume_validation_error: str | None = None
        if self.config.storage == "host":
            after_volumes: set[str] | None = set()
            volume_attachment_verified = True
        else:
            after_volumes = self._server_volume_ids(endpoint.server_id)
            if before["volume_ids"] is not None and after_volumes is not None:
                if before["volume_ids"] != after_volumes:
                    volume_attachment_verified = False
                    volume_validation_error = (
                        f"Volume attachments changed during migration of {endpoint.label}: "
                        f"before={sorted(before['volume_ids'])}, after={sorted(after_volumes)}"
                    )
                else:
                    (
                        volume_attachment_verified,
                        volume_validation_error,
                        volume_detail,
                    ) = self._migration_volume_evidence(
                        endpoint, before["volume_ids"], after_volumes
                    )
            elif endpoint.volume_id:
                (
                    volume_attachment_verified,
                    volume_validation_error,
                    volume_detail,
                ) = self._verify_expected_volume_attachment(
                    endpoint.volume_id, endpoint.server_id
                )
            else:
                volume_attachment_verified = None
                volume_validation_error = (
                    "No expected root-volume ID was available and Nova attachment inventory "
                    "was unavailable before or after migration"
                )

        endpoint.host = destination_host
        endpoint.availability_zone = destination_az
        endpoint_ready = False
        endpoint_recovery_error: str | None = None
        guest_marker_verified: bool | None = None
        guest_marker_error: str | None = None
        if not self._wait_for_ssh(
            endpoint.management_ip,
            proxy=True,
            timeout=self.config.convergence_timeout,
        ):
            endpoint_recovery_error = (
                f"Migrated endpoint {endpoint.label} did not regain SSH reachability"
            )
        else:
            guest_marker = before.get("guest_marker")
            if guest_marker:
                guest_marker_verified, guest_marker_error = (
                    self._verify_guest_migration_marker(endpoint, guest_marker)
                )
            else:
                guest_marker_verified = None
            if guest_marker_verified is False:
                endpoint_recovery_error = guest_marker_error
            else:
                try:
                    try:
                        self.reconfigure_endpoint(endpoint, reuse_probe=True)
                    except TypeError as exc:
                        if "reuse_probe" not in str(exc):
                            raise
                        self.reconfigure_endpoint(endpoint)
                    endpoint_ready = True
                except RunCancelledError:
                    raise
                except SuiteError as exc:
                    endpoint_recovery_error = str(exc)
        history = endpoint.metadata.setdefault("migration_history", [])
        history.append(
            {
                "source_host": source_host,
                "destination_host": destination_host,
                "request_error": request_error,
                "availability_zone": destination_az,
                "availability_zone_source": destination_az_source,
                "confirmed_immediately": not automatically_confirmed,
                "automatically_confirmed": automatically_confirmed,
                "migration_record_verified": migration_record_verified,
                "migration_record_error": migration_record_error,
                "task_state_cleared": task_state_cleared,
                "volume_attachment_verified": volume_attachment_verified,
                "volume_validation_error": volume_validation_error,
                "guest_marker_verified": guest_marker_verified,
                "guest_marker_error": guest_marker_error,
                "port_binding_verified": port_binding_verified,
                "port_validation_error": port_validation_error,
                "endpoint_ready": endpoint_ready,
                "endpoint_recovery_error": endpoint_recovery_error,
            }
        )
        completion_evidence = {
            "server_id": endpoint.server_id,
            "source_host": source_host,
            "destination_host": destination_host,
            "source_availability_zone": source_az,
            "destination_availability_zone": destination_az,
            "server_status": "ACTIVE",
            "migration_record_verified": migration_record_verified,
            "task_state_cleared": task_state_cleared,
            "port_binding_verified": port_binding_verified,
            "volume_attachment_verified": volume_attachment_verified,
            "guest_marker_verified": guest_marker_verified,
            "endpoint_ready": endpoint_ready,
        }
        completion_evidence = self._migration_operation_evidence(
            endpoint,
            target.host,
            before,
            completion_evidence,
            port_details,
            server_detail,
            migration_type="cold",
        )
        completion = migration_completion(completion_evidence)
        settlement = migration_operation_settlement(completion_evidence)
        self._mark_current_migration_succeeded(completion_evidence)
        self.reporter.event(
            "cold-migration-complete"
            if completion["verified"] is True
            else "cold-migration-assessed",
            f"Cold migration completed for {endpoint.label}"
            if completion["verified"] is True
            else f"Cold migration handoff observed for {endpoint.label}; completion {completion['status']}",
            completion_assessment=completion,
            operation_settlement_assessment=settlement,
            server_id=endpoint.server_id,
            source_host=source_host,
            destination_host=destination_host,
            request_error=request_error,
            availability_zone=destination_az,
            availability_zone_source=destination_az_source,
            confirmed_immediately=not automatically_confirmed,
            automatically_confirmed=automatically_confirmed,
            migration_record_verified=migration_record_verified,
            migration_record_error=migration_record_error,
            task_state_cleared=task_state_cleared,
            volume_attachment_verified=volume_attachment_verified,
            volume_validation_error=volume_validation_error,
            guest_marker_verified=guest_marker_verified,
            guest_marker_error=guest_marker_error,
            port_binding_verified=port_binding_verified,
            port_validation_error=port_validation_error,
            endpoint_ready=endpoint_ready,
            endpoint_recovery_error=endpoint_recovery_error,
        )
        endpoint.metadata.pop("_migration_attempt_baseline", None)
        return MigrationResult(
            server_id=endpoint.server_id,
            source_host=source_host,
            destination_host=destination_host,
            source_availability_zone=source_az,
            destination_availability_zone=destination_az,
            confirmed=True,
            automatically_confirmed=automatically_confirmed,
            port_binding_verified=port_binding_verified,
            migration_record_verified=migration_record_verified,
            migration_record_error=migration_record_error,
            task_state_cleared=task_state_cleared,
            volume_attachment_verified=volume_attachment_verified,
            volume_validation_error=volume_validation_error,
            guest_marker_verified=guest_marker_verified,
            guest_marker_error=guest_marker_error,
            port_validation_error=port_validation_error,
            endpoint_ready=endpoint_ready,
            endpoint_recovery_error=endpoint_recovery_error,
            details={
                "completion_assessment": completion,
                "operation_settlement_assessment": settlement,
                "destination_availability_zone_source": destination_az_source,
                "request_error": request_error,
                "ports": port_details,
                "volume_ids_before": sorted(before["volume_ids"] or []),
                "volume_ids_after": sorted(after_volumes or []),
                "migration_record": migration_record,
                "root_volume_detail": volume_detail,
                "migration_inventory_error_before": before.get(
                    "migration_inventory_error"
                ),
                "guest_marker_path": (before.get("guest_marker") or {}).get("path"),
            },
        )

    def _recover_endpoint_after_failed_migration(
        self: Any,
        endpoint: Endpoint,
        original_host: str,
        original_availability_zone: str | None,
        before: dict[str, Any] | None = None,
    ) -> tuple[bool, str]:
        """Restore a failed attempt before allowing another target to be tried.

        A retry is safe only after Nova shows the server ACTIVE on its original
        host and the guest endpoint has regained SSH plus its transient probe.
        An instance on a different host, in ERROR, or without guest readiness is
        intentionally treated as unsafe so retries cannot conceal partial moves.
        """
        try:
            detail = (
                self._json_with_transient_retry(
                    "server",
                    "show",
                    endpoint.server_id,
                    check=False,
                    timeout=min(60, self.config.resource_timeout),
                    context=f"checking failed migration state for {endpoint.label}",
                )
                or {}
            )
        except RunCancelledError:
            raise
        except SuiteError as exc:
            return (
                False,
                f"could not determine server state after failed migration: {exc}",
            )
        status = str(pick(detail, "status", default="") or "").lower()
        host = str(pick(detail, "os_ext_srv_attr_host", "host", default="") or "")

        if status == "verify_resize":
            revert_errors: list[str] = []
            reverted = False
            for command in (
                ("server", "migration", "revert", endpoint.server_id),
                ("server", "migrate", "revert", endpoint.server_id),
            ):
                try:
                    result = self.osc.run(
                        *self._migration_command_args(endpoint.server_id, *command),
                        check=False,
                        timeout=min(60, self.config.resource_timeout),
                    )
                except CommandTimeoutError as exc:
                    return (
                        False,
                        f"revert submission timed out and remains ambiguous; "
                        f"no alternate command was submitted: {exc}",
                    )
                except RunCancelledError:
                    raise
                except SuiteError as exc:
                    return (
                        False,
                        "revert submission was blocked or failed before a safe "
                        f"result; no alternate command was submitted: {exc}",
                    )
                if result.returncode == 0:
                    reverted = True
                    break
                revert_errors.append((result.stderr or result.stdout).strip())
                if not self._current_command_was_rejected():
                    return (
                        False,
                        "revert command outcome is ambiguous; no alternate "
                        "command was submitted",
                    )
            if not reverted:
                return (
                    False,
                    "server remained in VERIFY_RESIZE and automatic recovery could not revert it: "
                    + " | ".join(item for item in revert_errors if item),
                )
            try:
                self._wait_for_status(
                    "server",
                    endpoint.server_id,
                    {"active"},
                    {"error"},
                    display_name=endpoint.server_name,
                )
            except RunCancelledError:
                raise
            except SuiteError as exc:
                return False, f"revert was requested but ACTIVE recovery failed: {exc}"
            try:
                detail = (
                    self._json_with_transient_retry(
                        "server",
                        "show",
                        endpoint.server_id,
                        check=False,
                        timeout=min(60, self.config.resource_timeout),
                        context=f"checking reverted migration state for {endpoint.label}",
                    )
                    or {}
                )
            except RunCancelledError:
                raise
            except SuiteError as exc:
                return (
                    False,
                    f"revert completed but final server state could not be read: {exc}",
                )
            status = str(pick(detail, "status", default="") or "").lower()
            host = str(pick(detail, "os_ext_srv_attr_host", "host", default="") or "")

        if status != "active":
            return False, f"server status after failed attempt is {status or 'unknown'}"
        if host != original_host:
            return (
                False,
                f"server is ACTIVE on {host or 'an unknown host'}, not original host {original_host}",
            )
        task_state = pick(detail, "os_ext_sts_task_state", "task_state")
        task_state_cleared = nova_task_state_cleared(detail)
        if task_state_cleared is not True:
            return (
                False,
                f"Nova task_state is not verified clear: {task_state!r} "
                f"(cleared={task_state_cleared})",
            )
        if before is not None:
            if not self._migration_field_visible(
                detail, "os_ext_sts_task_state", "task_state"
            ) or not self._migration_field_visible(
                detail, "os_ext_sts_power_state", "power_state"
            ):
                return (
                    False,
                    "Nova hid task_state or power_state during failed-migration "
                    "reconciliation",
                )
            power_state = str(
                pick(
                    detail,
                    "os_ext_sts_power_state",
                    "power_state",
                    default="",
                )
                or ""
            ).lower()
            if power_state not in {"1", "running", "active"}:
                return False, f"Nova power_state is {power_state or 'unknown'}"
            try:
                binding_verified, _ = self._verify_migrated_ports(
                    endpoint, original_host, before
                )
            except RunCancelledError:
                raise
            except SuiteError as exc:
                return False, f"port bindings did not recover safely: {exc}"
            if binding_verified is not True:
                return (
                    False,
                    "Neutron did not expose every recovered port binding on the "
                    "original host",
                )

        recovered_az = (
            str(
                pick(
                    detail,
                    "os_ext_az_availability_zone",
                    "availability_zone",
                    default="",
                )
                or original_availability_zone
                or ""
            )
            or None
        )
        if before is not None:
            if recovered_az != original_availability_zone:
                return (
                    False,
                    "Server availability zone changed during failed-migration recovery",
                )
            volume_ids = (
                set()
                if self.config.storage == "host"
                else self._server_volume_ids(endpoint.server_id)
            )
            if (
                volume_ids is None
                or before.get("volume_ids") is None
                or volume_ids != set(before["volume_ids"])
            ):
                return (
                    False,
                    "Volume attachments changed or could not be verified during failed-migration recovery",
                )
            for volume_id in sorted(volume_ids):
                verified, error, _ = self._verify_expected_volume_attachment(
                    volume_id, endpoint.server_id
                )
                if verified is not True:
                    return (
                        False,
                        f"Volume {volume_id} ownership did not recover: {error or 'unverified attachment'}",
                    )
        endpoint.host = original_host
        endpoint.availability_zone = recovered_az
        if not self._wait_for_ssh(
            endpoint.management_ip,
            proxy=True,
            timeout=self.config.convergence_timeout,
        ):
            return False, "server returned to its original host but SSH did not recover"
        if before is not None:
            marker = before.get("guest_marker")
            if not marker:
                return (
                    False,
                    "Original guest marker is unavailable during failed-migration recovery",
                )
            verified, error = self._verify_guest_migration_marker(endpoint, marker)
            if verified is not True:
                return (
                    False,
                    f"Original guest identity did not recover: {error or 'unverified guest marker'}",
                )
        try:
            try:
                self.reconfigure_endpoint(endpoint, reuse_probe=True)
            except TypeError as exc:
                if "reuse_probe" not in str(exc):
                    raise
                self.reconfigure_endpoint(endpoint)
        except RunCancelledError:
            raise
        except SuiteError as exc:
            return (
                False,
                f"server returned to its original host but endpoint recovery failed: {exc}",
            )
        return True, "server and endpoint were restored on the original host"

    @serialized_lifecycle
    def cold_migrate_endpoint(
        self: Any, endpoint: Endpoint, target: ComputeHostInfo
    ) -> MigrationResult:
        """Run one migration attempt and classify whether another attempt is safe."""
        original_host = endpoint.host
        original_az = endpoint.availability_zone
        if not original_host:
            raise PlacementUnavailableError(
                f"Nova did not expose the source compute host for {endpoint.label}"
            )
        try:
            return self._cold_migrate_endpoint_once(endpoint, target)
        except (RetryableMigrationError, UnsafeMigrationStateError):
            raise
        except RunCancelledError:
            before = endpoint.metadata.pop("_migration_attempt_baseline", None)
            with cancellation_reconciliation():
                proven, evidence = self._authoritative_migration_failure(
                    endpoint, before
                )
                recovered, recovery_reason = (
                    self._recover_endpoint_after_failed_migration(
                        endpoint,
                        original_host,
                        original_az,
                        before,
                    )
                )
                if proven and recovered:
                    self._mark_current_migration_failed_final(
                        {**evidence, "recovery": recovery_reason}
                    )
                else:
                    self.logger.log(
                        "Cancellation reconciliation could not prove the cold "
                        "migration terminal and safe; its journal entry remains "
                        "ambiguous and cleanup will skip the endpoint",
                        "WARNING",
                    )
            raise
        except UnverifiableMigrationError:
            raise
        except PlacementUnavailableError as exc:
            before = endpoint.metadata.pop("_migration_attempt_baseline", None)
            recovered, recovery_reason = self._recover_endpoint_after_failed_migration(
                endpoint,
                original_host,
                original_az,
                before,
            )
            if recovered:
                raise RetryableMigrationError(
                    f"{exc}; {recovery_reason}",
                    unavailable=True,
                    proven_failure=True,
                    accepted=False,
                    target_unsuitable=exc.target_unsuitable,
                    evidence={"command_rejected": True},
                ) from exc
            raise UnsafeMigrationStateError(
                f"{exc}; migration retries stopped because {recovery_reason}"
            ) from exc
        except SuiteError as exc:
            before = endpoint.metadata.pop("_migration_attempt_baseline", None)
            command_rejected = self._current_command_was_rejected()
            proven_failure, evidence = (
                (True, {"command_rejected": True})
                if command_rejected
                else self._authoritative_migration_failure(endpoint, before)
            )
            recovered, recovery_reason = self._recover_endpoint_after_failed_migration(
                endpoint,
                original_host,
                original_az,
                before,
            )
            if recovered and proven_failure:
                if not command_rejected:
                    self._mark_current_migration_failed_retryable(evidence)
                raise RetryableMigrationError(
                    f"{exc}; {recovery_reason}",
                    unavailable=False,
                    proven_failure=True,
                    accepted=False if command_rejected else True,
                    evidence=evidence,
                ) from exc
            if recovered and not proven_failure:
                raise UnsafeMigrationStateError(
                    f"{exc}; the endpoint recovered, but that does not prove "
                    "the migration request failed. The submission remains "
                    f"AMBIGUOUS and no retry or cleanup is permitted: "
                    f"{evidence.get('reason', 'no terminal failure evidence')}"
                ) from exc
            raise UnsafeMigrationStateError(
                f"{exc}; migration retries stopped because {recovery_reason}"
            ) from exc
