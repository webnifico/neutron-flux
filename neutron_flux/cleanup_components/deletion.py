from __future__ import annotations

import ast
import threading
import time

# mypy: disable-error-code="attr-defined"
from contextlib import nullcontext
from typing import Any

from ..errors import CloudOperationBlockedError, RunCancelledError, SuiteError
from ..failure_injection import inject_failure
from ..models import ResourceRecord
from ..openstack import PresenceResult
from ..resources import ResourceBuilder
from ..scheduling import (
    ACTIVITY,
    LIFECYCLE_WORKERS,
    READ_WORKERS,
    admission,
    bounded_map,
    timed,
)
from ..utils import list_value, optional_text, pick


class ResourceDeletionMixin:
    """Compatibility mixin for this cleanup concern."""

    def _delete_all_types(self) -> None:
        # Dependency-safe ordering: FIPs before servers, router interfaces
        # before routers, and ports/subnets before networks.
        self._delete_type("floating_ip", self._delete_floating_ip)
        self._delete_type("server", self._delete_server)
        self._delete_type("router", self._delete_router)
        self._delete_type("port", self._delete_port)
        self._delete_type("subnet", self._delete_subnet)
        self._delete_type("network", self._delete_network)
        self._delete_type("volume", self._delete_volume)
        self._delete_type("security_group", self._delete_security_group)
        self._delete_type("server_group", self._delete_server_group)
        self._delete_type("keypair", self._delete_keypair)

    def _records(self, resource_type: str) -> list[ResourceRecord]:
        return sorted(
            [
                item
                for item in self.reporter.resources
                if item.resource_type == resource_type
                and item.delete_status not in {"deleted", "already-absent"}
            ],
            key=lambda item: item.sequence,
            reverse=True,
        )

    def _delete_type(self, resource_type: str, handler: Any) -> None:
        self._delete_selected(self._records(resource_type), handler)

    def _delete_selected(self, records: list[ResourceRecord], handler: Any) -> None:
        independent = bool(records) and all(
            item.resource_type in {"server", "port", "volume"} for item in records
        )

        def remove(resource: ResourceRecord) -> None:
            with admission("lifecycle", self.reporter):
                self._delete_record(resource, handler)

        bounded_map(remove, records, workers=LIFECYCLE_WORKERS if independent else 1)

    def _delete_record(self, resource: ResourceRecord, handler: Any) -> None:
        coordinator = getattr(self, "cloud_operation_coordinator", None)
        if coordinator is not None:
            with (
                ACTIVITY.scope(reporter=self.reporter, label="resource cleanup"),
                ACTIVITY.resources([resource.id]),
                timed(self.reporter, "resource-cleanup", resource.resource_type),
            ):
                self._delete_record_serialized(resource, handler)
            return
        lock = getattr(self, "lifecycle_lock", None)
        if lock is None:
            lock = threading.RLock()
            self.lifecycle_lock = lock
        with lock:
            self._delete_record_serialized(resource, handler)

    def _delete_record_serialized(self, resource: ResourceRecord, handler: Any) -> None:
        try:
            resource.cleanup_attempts += 1
            presence_method = getattr(self.osc, "presence", None)
            if callable(presence_method):
                presence = presence_method(resource.resource_type, resource.id)
                presence_state = getattr(presence, "state", None)
                if presence_state == "absent":
                    resource.cleanup_state = "DELETED"
                    self.tracker.mark_deleted(resource, "already-absent")
                    return
                if presence_state == "unknown":
                    raise SuiteError(
                        f"Could not positively identify {resource.resource_type} "
                        f"{resource.id} before cleanup: {presence.detail}"
                    )
                if presence_state != "present" and not self.osc.exists(
                    resource.resource_type, resource.id
                ):
                    resource.cleanup_state = "DELETED"
                    self.tracker.mark_deleted(resource, "already-absent")
                    return
            elif not self.osc.exists(resource.resource_type, resource.id):
                resource.cleanup_state = "DELETED"
                self.tracker.mark_deleted(resource, "already-absent")
                return

            coordinator = getattr(self, "cloud_operation_coordinator", None)
            blocker = (
                coordinator.cleanup_blocker(
                    resource.id,
                    wait_for_active=True,
                    timeout=self.config.resource_timeout,
                )
                if coordinator is not None
                else None
            )
            if blocker:
                resource.cleanup_state = "QUARANTINED"
                resource.delete_status = "leftover"
                resource.cleanup_error = blocker
                self.reporter.update_resource(resource)
                marker = f"{resource.resource_type}:{resource.id}:QUARANTINED:{blocker}"
                if marker not in self.reporter.cleanup_summary["leftovers"]:
                    self.reporter.cleanup_summary["leftovers"].append(marker)
                event = getattr(self.reporter, "event", None)
                if callable(event):
                    event(
                        "cleanup-cloud-operation-skipped",
                        f"Skipped cleanup of quarantined {resource.resource_type}",
                        resource_type=resource.resource_type,
                        resource_id=resource.id,
                        cleanup_state="QUARANTINED",
                        reason=blocker,
                    )
                self.logger.log(
                    f"Skipping {resource.resource_type} {resource.name} "
                    f"({resource.id}): {blocker}",
                    "WARNING",
                )
                return

            kind = (
                "server-delete"
                if resource.resource_type == "server"
                else "port-delete"
                if resource.resource_type == "port"
                else "cleanup"
            )
            transaction = (
                coordinator.transaction(
                    kind,
                    f"cleanup {resource.resource_type} {resource.name}",
                    resource_ids=[resource.id],
                    max_attempts=2 if resource.resource_type == "server" else 1,
                    conflicts=("all-cloud-operations",),
                    final_cooldown=(
                        8.0 if resource.resource_type == "server" else None
                    ),
                )
                if coordinator is not None
                else nullcontext()
            )
            with transaction:
                resource.cleanup_state = "DELETE_REQUESTED"
                resource.cleanup_error = None
                self.reporter.update_resource(resource)
                handler(resource)
                resource.cleanup_state = "WAITING"
                self.reporter.update_resource(resource)
                if resource.resource_type == "server":
                    # A fresh post-delete observation selects the timeout and
                    # starts polling. Never reuse pre-delete absence evidence.
                    initial = self._cleanup_observation("server", resource.id)
                    deleted = self._wait_absent(
                        resource.resource_type,
                        resource.id,
                        self._deletion_timeout(resource, initial[1] or {}),
                        resource.name,
                        initial,
                    )
                else:
                    deleted = self._wait_absent(
                        resource.resource_type,
                        resource.id,
                        self._deletion_timeout(resource),
                        resource.name,
                    )
                if not deleted and resource.resource_type == "server":
                    deleted = self._server_delete_fallback(resource)
                if deleted:
                    resource.cleanup_state = "DELETED"
                    self.tracker.mark_deleted(resource)
                    with getattr(self.reporter, "_lock", threading.RLock()):
                        self.reporter.cleanup_summary["deleted"] += 1
                else:
                    if coordinator is not None:
                        coordinator.keep_current_ambiguity(
                            f"Absence of {resource.resource_type} {resource.id} was not verified before the deletion deadline"
                        )
                    resource.cleanup_state = "FAILED"
                    resource.delete_status = "leftover"
                    resource.cleanup_error = "deletion timeout"
                    self.reporter.update_resource(resource)
        except RunCancelledError:
            # A cleanup abort is a process-level lifecycle event, not a failed
            # delete for this resource. Keep the last durably recorded state so
            # confirmed deletion evidence is never replaced by a false error.
            raise
        except CloudOperationBlockedError as exc:
            resource.cleanup_state = "QUARANTINED"
            resource.delete_status = "leftover"
            resource.cleanup_error = str(exc)
            self.reporter.update_resource(resource)
            marker = f"{resource.resource_type}:{resource.id}:QUARANTINED:{exc}"
            if marker not in self.reporter.cleanup_summary["leftovers"]:
                self.reporter.cleanup_summary["leftovers"].append(marker)
            self.logger.log(
                f"Cleanup cloud operation skipped for {resource.resource_type} "
                f"{resource.name} ({resource.id}): {exc}",
                "WARNING",
            )
        except Exception as exc:
            resource.cleanup_state = "FAILED"
            resource.delete_status = "delete-error"
            resource.cleanup_error = str(exc)
            self.reporter.update_resource(resource)
            message = f"{resource.resource_type} {resource.name} ({resource.id}): {exc}"
            self.reporter.cleanup_summary["errors"].append(message)
            self.logger.log(message, "ERROR")

    def _deletion_timeout(
        self, resource: ResourceRecord, observed: dict[str, Any] | None = None
    ) -> int:
        base = int(self.config.cleanup_timeouts.get(resource.resource_type, 90))
        if resource.resource_type != "server":
            return base
        # Give Nova time to complete VIF teardown before any
        # fallback is considered.  Ordinary deletes receive at least three
        # minutes, while an already accepted delete receives five minutes.
        details = (
            observed
            if observed is not None
            else self._cleanup_progress_details("server", resource.id)
        )
        if str(details.get("task_state") or "").lower() == "deleting":
            return max(base, 300)
        return max(base, 180)

    def _wait_absent(
        self,
        resource_type: str,
        resource_id: str,
        timeout: int,
        resource_name: str | None = None,
        initial_observation: tuple[bool, dict[str, Any] | None] | None = None,
    ) -> bool:
        started = time.monotonic()
        deadline = started + timeout
        next_progress = started + self.config.progress_interval
        label = resource_name or resource_id
        while time.monotonic() < deadline:
            if initial_observation is not None:
                present, observed = initial_observation
                initial_observation = None
            else:
                present, observed = self._cleanup_observation(
                    resource_type, resource_id
                )
            if not present:
                elapsed = int(time.monotonic() - started)
                self.logger.log(
                    f"Deleted {resource_type} {label} ({resource_id}) after {elapsed}s"
                )
                return True
            now = time.monotonic()
            if now >= next_progress:
                elapsed = int(now - started)
                details = (
                    observed
                    if observed is not None
                    else self._cleanup_progress_details(resource_type, resource_id)
                )
                rendered = ", ".join(
                    f"{key}={value}"
                    for key, value in details.items()
                    if value not in (None, "")
                )
                suffix = f", {rendered}" if rendered else ""
                self.logger.log(
                    f"Still deleting {resource_type} {label} ({resource_id}): "
                    f"elapsed={elapsed}s/{timeout}s{suffix}"
                )
                next_progress = now + self.config.progress_interval
            time.sleep(2)
        present, observed = self._cleanup_observation(resource_type, resource_id)
        absent = not present
        if not absent:
            details = (
                observed
                if observed is not None
                else self._cleanup_progress_details(resource_type, resource_id)
            )
            rendered = ", ".join(
                f"{key}={value}"
                for key, value in details.items()
                if value not in (None, "")
            )
            self.logger.log(
                f"Timed out deleting {resource_type} {label} ({resource_id}) after {timeout}s"
                + (f": {rendered}" if rendered else ""),
                "ERROR",
            )
        return absent

    def _cleanup_observation(
        self, resource_type: str, resource_id: str
    ) -> tuple[bool, dict[str, Any] | None]:
        """One fresh read supplies presence and progress; never cache absence."""
        presence = getattr(self.osc, "presence", None)
        if resource_type in {"server", "volume"} and callable(presence):
            observation = presence(resource_type, resource_id, include_data=True)
            if isinstance(observation, PresenceResult):
                if observation.unknown:
                    raise SuiteError(
                        f"Could not determine whether {resource_type} {resource_id} exists: "
                        f"{observation.detail}"
                    )
                return observation.present, self._cleanup_progress_fields(
                    resource_type, observation.data or {}
                )
        # Embedded adapters that expose only exists retain their old behavior.
        return self.osc.exists(resource_type, resource_id), None

    @staticmethod
    def _cleanup_progress_fields(
        resource_type: str, detail: dict[str, Any]
    ) -> dict[str, Any]:
        if resource_type == "server":
            return {
                "status": pick(detail, "status"),
                "task_state": pick(detail, "os_ext_sts_task_state", "task_state"),
                "power_state": pick(detail, "os_ext_sts_power_state", "power_state"),
                "host": pick(detail, "os_ext_srv_attr_host", "host"),
                "instance_name": pick(
                    detail, "os_ext_srv_attr_instance_name", "instance_name"
                ),
            }
        if resource_type == "volume":
            return {
                "status": pick(detail, "status"),
                "attachments": pick(detail, "attachments"),
            }
        return {}

    def _cleanup_progress_details(
        self, resource_type: str, resource_id: str
    ) -> dict[str, Any]:
        try:
            if resource_type in {"server", "volume"}:
                detail = (
                    self.osc.json(
                        resource_type, "show", resource_id, check=False, timeout=30
                    )
                    or {}
                )
                return self._cleanup_progress_fields(resource_type, detail)
        except RunCancelledError:
            raise
        except SuiteError as exc:
            return {"inspection_error": str(exc)}
        return {}

    def _delete_floating_ip(self, resource: ResourceRecord) -> None:
        self.logger.log(f"Deleting floating IP {resource.name} ({resource.id})")
        self.osc.run(
            "floating",
            "ip",
            "delete",
            resource.id,
            check=False,
            timeout=min(60, self.config.resource_timeout),
        )

    def _wait_server_settled_before_delete(
        self, resource: ResourceRecord, *, timeout: int = 180
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        stable_reads = 0
        previous: tuple[str, str, str] | None = None
        last: dict[str, Any] = {}
        while time.monotonic() < deadline:
            detail = (
                self.osc.json(
                    "server",
                    "show",
                    resource.id,
                    check=False,
                    timeout=30,
                )
                or {}
            )
            if not isinstance(detail, dict):
                time.sleep(self.config.convergence_interval)
                continue
            if not detail and not self.osc.exists("server", resource.id):
                return {}
            last = detail
            status = str(pick(detail, "status", default="") or "").lower()
            task_state = str(
                pick(detail, "os_ext_sts_task_state", "task_state", default="") or ""
            ).lower()
            host = str(pick(detail, "os_ext_srv_attr_host", "host", default="") or "")
            if task_state == "deleting":
                return detail
            signature = (status, task_state, host)
            settled = task_state in {"", "none", "null"} and status not in {
                "build",
                "migrating",
                "rebuild",
                "resize",
                "revert_resize",
                "verify_resize",
            }
            if settled and signature == previous:
                stable_reads += 1
            elif settled:
                stable_reads = 1
            else:
                stable_reads = 0
            previous = signature
            if stable_reads >= 2:
                self.logger.log(
                    f"Server deletion barrier settled for {resource.name} "
                    f"({resource.id}): status={status or 'unknown'}, "
                    f"task_state={task_state or 'none'}, host={host or 'unknown'}"
                )
                return detail
            time.sleep(self.config.convergence_interval)
        summary = self._cleanup_progress_details("server", resource.id)
        self.logger.log(
            f"Server {resource.name} ({resource.id}) did not fully settle before "
            f"delete after {timeout}s; submitting a normal delete only: {summary}",
            "WARNING",
        )
        return last

    def _delete_server(self, resource: ResourceRecord) -> None:
        inject_failure(self.config, "before-server-delete")
        detail = self._wait_server_settled_before_delete(resource)
        task_state = str(
            pick(detail, "os_ext_sts_task_state", "task_state", default="") or ""
        ).lower()
        if task_state == "deleting":
            self.logger.log(
                f"Server {resource.name} ({resource.id}) is already deleting; "
                "waiting without submitting another delete request"
            )
            return
        self.logger.log(
            f"Deleting server {resource.name} ({resource.id}) with normal Nova delete"
        )
        result = self.osc.run(
            "server",
            "delete",
            resource.id,
            check=False,
            timeout=min(60, self.config.resource_timeout),
        )
        if result.returncode != 0 and self.osc.exists("server", resource.id):
            error = (result.stderr or result.stdout).strip()
            raise SuiteError(f"Server delete request failed for {resource.id}: {error}")

    def _server_delete_fallback(self, resource: ResourceRecord) -> bool:
        if not self.osc.exists("server", resource.id):
            return True
        details = self._cleanup_progress_details("server", resource.id)
        if str(details.get("task_state") or "").lower() == "deleting":
            self.logger.log(
                f"Nova is still deleting server {resource.name} ({resource.id}); "
                "waiting an additional 180s before considering force-delete",
                "WARNING",
            )
            if self._wait_absent("server", resource.id, 180, resource.name):
                return True
        if not self.osc.exists("server", resource.id):
            return True
        self.logger.log(
            f"Normal deletion of server {resource.name} ({resource.id}) did not "
            "complete after the extended settlement window; using force-delete "
            "as the final fallback",
            "WARNING",
        )
        result = self.osc.run(
            "--os-compute-api-version",
            "2.latest",
            "server",
            "delete",
            "--force",
            resource.id,
            check=False,
            timeout=min(60, self.config.resource_timeout),
        )
        if result.returncode != 0 and self.osc.exists("server", resource.id):
            error = (result.stderr or result.stdout).strip()
            self.logger.log(
                f"Final force-delete request failed for server {resource.id}: {error}",
                "ERROR",
            )
            return False
        return self._wait_absent("server", resource.id, 300, resource.name)

    def _delete_router(self, resource: ResourceRecord) -> None:
        self.logger.log(f"Deleting router {resource.name} ({resource.id})")
        for attempt in range(1, 6):
            if not self.osc.exists("router", resource.id):
                return
            # Static routes must be cleared before any interface carrying their
            # nexthop can be removed. This also covers nested-router topologies.
            self._clear_router_routes(resource.id)
            self.osc.run(
                "router",
                "unset",
                "--external-gateway",
                resource.id,
                check=False,
                timeout=min(60, self.config.resource_timeout),
            )
            ports = (
                self.osc.json(
                    "port",
                    "list",
                    "--router",
                    resource.id,
                    check=False,
                    timeout=min(60, self.config.resource_timeout),
                )
                or []
            )
            valid_ports = []
            for row in ports:
                if optional_text(pick(row, "id")):
                    valid_ports.append(row)
                else:
                    self.logger.log(
                        "Skipping router port row without an ID during cleanup",
                        "WARNING",
                    )

            def read_port(row: dict[str, Any]) -> Any:
                return (
                    self.osc.json(
                        "port",
                        "show",
                        str(pick(row, "id")),
                        check=False,
                        timeout=min(60, self.config.resource_timeout),
                    )
                    or row
                )

            details = bounded_map(read_port, valid_ports, workers=READ_WORKERS)
            for row, detail in zip(valid_ports, details, strict=True):
                port_id = str(pick(row, "id"))
                owner = str(pick(detail, "device_owner", default="") or "")
                if owner in {
                    "network:router_interface",
                    "network:router_interface_distributed",
                    "network:ha_router_replicated_interface",
                }:
                    removed = self.osc.run(
                        "router",
                        "remove",
                        "port",
                        resource.id,
                        port_id,
                        check=False,
                        timeout=min(60, self.config.resource_timeout),
                    )
                    if removed.returncode != 0:
                        for subnet_id in ResourceBuilder._fixed_ips(detail):
                            self.osc.run(
                                "router",
                                "remove",
                                "subnet",
                                resource.id,
                                subnet_id,
                                check=False,
                                timeout=min(60, self.config.resource_timeout),
                            )
            result = self.osc.run(
                "router",
                "delete",
                resource.id,
                check=False,
                timeout=min(60, self.config.resource_timeout),
            )
            if result.returncode == 0:
                return
            self.logger.log(
                f"Router delete attempt {attempt} failed: {result.stderr.strip()}",
                "WARNING",
            )
            time.sleep(2)
        if self.osc.exists("router", resource.id):
            raise SuiteError(
                f"Router still exists after route, gateway, and interface cleanup: {resource.id}"
            )

    def _clear_router_routes(self, router_id: str) -> None:
        detail = (
            self.osc.json(
                "router",
                "show",
                router_id,
                check=False,
                timeout=min(60, self.config.resource_timeout),
            )
            or {}
        )
        routes = pick(detail, "routes", default=[])
        if isinstance(routes, str):
            try:
                routes = ast.literal_eval(routes)
            except (ValueError, SyntaxError):
                routes = []
        for route in routes if isinstance(routes, list) else []:
            if not isinstance(route, dict):
                continue
            destination = pick(route, "destination")
            gateway = pick(route, "nexthop", "gateway")
            if not destination or not gateway:
                continue
            self.osc.run(
                "router",
                "remove",
                "route",
                "--route",
                f"destination={destination},gateway={gateway}",
                router_id,
                check=False,
                timeout=min(60, self.config.resource_timeout),
            )

    def _wait_port_detached(
        self, resource: ResourceRecord, detail: dict[str, Any], *, timeout: int = 120
    ) -> dict[str, Any]:
        owner = str(pick(detail, "device_owner", default="") or "")
        device_id = str(pick(detail, "device_id", default="") or "")
        binding_host = str(
            pick(
                detail,
                "binding_host_id",
                "binding:host_id",
                "binding_host",
                default="",
            )
            or ""
        )
        server_exists = bool(device_id and self.osc.exists("server", device_id))
        compute_related = (
            owner.startswith("compute:") or bool(binding_host) or server_exists
        )
        if not compute_related:
            return detail
        if server_exists:
            raise SuiteError(
                f"Port {resource.id} remains attached to existing server {device_id}; "
                "the port will be retained for final cleanup"
            )

        deadline = time.monotonic() + timeout
        stable_reads = 0
        previous: tuple[str, str, str, str] | None = None
        last = detail
        while time.monotonic() < deadline:
            current = (
                self.osc.json(
                    "port",
                    "show",
                    resource.id,
                    check=False,
                    timeout=min(30, self.config.resource_timeout),
                )
                or {}
            )
            if not isinstance(current, dict):
                time.sleep(self.config.convergence_interval)
                continue
            last = current
            current_owner = str(pick(current, "device_owner", default="") or "")
            current_device = str(pick(current, "device_id", default="") or "")
            binding_host = str(
                pick(
                    current,
                    "binding_host_id",
                    "binding:host_id",
                    "binding_host",
                    default="",
                )
                or ""
            )
            status = str(pick(current, "status", default="") or "").lower()
            signature = (current_owner, current_device, binding_host, status)
            detached = (
                not current_owner.startswith("compute:")
                and not current_device
                and not binding_host
            )
            if detached and signature == previous:
                stable_reads += 1
            elif detached:
                stable_reads = 1
            else:
                stable_reads = 0
            previous = signature
            if stable_reads >= 2:
                self.logger.log(
                    f"Port detachment settled for {resource.name} ({resource.id}): "
                    f"status={status or 'unknown'}"
                )
                return current
            time.sleep(self.config.convergence_interval)
        raise SuiteError(
            f"Port {resource.id} still has compute ownership or binding after its "
            f"server disappeared; refusing aggressive explicit deletion: "
            f"device_owner={pick(last, 'device_owner')}, "
            f"device_id={pick(last, 'device_id')}, "
            f"binding_host={pick(last, 'binding_host_id', 'binding:host_id')}"
        )

    def _delete_port(self, resource: ResourceRecord) -> None:
        detail = (
            self.osc.json(
                "port",
                "show",
                resource.id,
                check=False,
                timeout=min(60, self.config.resource_timeout),
            )
            or {}
        )
        detail = self._wait_port_detached(resource, detail)
        owner = str(pick(detail, "device_owner", default="") or "")
        device_id = str(pick(detail, "device_id", default="") or "")
        if (
            owner
            in {
                "network:router_interface",
                "network:router_interface_distributed",
                "network:ha_router_replicated_interface",
            }
            and device_id
        ):
            self._clear_router_routes(device_id)
            removed = self.osc.run(
                "router",
                "remove",
                "port",
                device_id,
                resource.id,
                check=False,
                timeout=min(60, self.config.resource_timeout),
            )
            if removed.returncode != 0:
                for subnet_id in ResourceBuilder._fixed_ips(detail):
                    self.osc.run(
                        "router",
                        "remove",
                        "subnet",
                        device_id,
                        subnet_id,
                        check=False,
                        timeout=min(60, self.config.resource_timeout),
                    )
            return
        if owner in {"network:dhcp", "network:router_ha_interface"}:
            return
        self.logger.log(f"Deleting port {resource.name} ({resource.id})")
        self.osc.run(
            "port",
            "delete",
            resource.id,
            check=False,
            timeout=min(60, self.config.resource_timeout),
        )

    def _delete_subnet(self, resource: ResourceRecord) -> None:
        self.logger.log(f"Deleting subnet {resource.name} ({resource.id})")
        self.osc.run(
            "subnet",
            "delete",
            resource.id,
            check=False,
            timeout=min(60, self.config.resource_timeout),
        )

    def _delete_network(self, resource: ResourceRecord) -> None:
        self.logger.log(f"Deleting network {resource.name} ({resource.id})")
        # Remove residual non-service ports created during an interrupted server
        # build before deleting the network.
        ports = (
            self.osc.json(
                "port",
                "list",
                "--network",
                resource.id,
                check=False,
                timeout=min(60, self.config.resource_timeout),
            )
            or []
        )
        valid_ports = []
        for row in ports:
            if optional_text(pick(row, "id")):
                valid_ports.append(row)
            else:
                self.logger.log(
                    "Skipping network port row without an ID during cleanup", "WARNING"
                )

        def read_port(row: dict[str, Any]) -> Any:
            return (
                self.osc.json(
                    "port",
                    "show",
                    str(pick(row, "id")),
                    check=False,
                    timeout=min(60, self.config.resource_timeout),
                )
                or row
            )

        details = bounded_map(read_port, valid_ports, workers=READ_WORKERS)
        for row, detail in zip(valid_ports, details, strict=True):
            port_id = str(pick(row, "id"))
            owner = str(pick(detail, "device_owner", default="") or "")
            if not owner or owner.startswith("compute:"):
                temporary = ResourceRecord(
                    sequence=0,
                    resource_type="port",
                    id=port_id,
                    name=optional_text(pick(detail, "name")) or port_id,
                    parent_id=resource.id,
                    metadata={"adopted_during_network_cleanup": True},
                    created_at="",
                )
                self._delete_port(temporary)
        self.osc.run(
            "network",
            "delete",
            resource.id,
            check=False,
            timeout=min(60, self.config.resource_timeout),
        )

    def _delete_volume(self, resource: ResourceRecord) -> None:
        self.logger.log(f"Deleting volume {resource.name} ({resource.id})")
        detail = (
            self.osc.json(
                "volume",
                "show",
                resource.id,
                check=False,
                timeout=30,
            )
            or {}
        )
        attachments = list_value(pick(detail, "attachments", default=[]))
        for attachment in attachments:
            if not isinstance(attachment, dict):
                continue
            server_id = optional_text(
                pick(attachment, "server_id", "server id", "server_uuid")
            )
            if server_id and self.osc.exists("server", server_id):
                raise SuiteError(
                    f"Volume {resource.id} remains attached to existing server "
                    f"{server_id}; refusing orphan deletion"
                )
        status_result = self.osc.value_result(
            "volume",
            "show",
            resource.id,
            column="status",
            timeout=30,
        )
        if status_result.returncode != 0:
            if self.osc.is_not_found_result(status_result, expected_resource="volume"):
                return
            detail = (
                status_result.stderr or status_result.stdout
            ).strip() or "unknown OpenStack error"
            raise SuiteError(
                f"Could not read volume {resource.id} before deletion: {detail}"
            )
        status = status_result.stdout.strip().lower()
        args = ["volume", "delete"]
        if status in {
            "error",
            "error_deleting",
            "error_restoring",
            "error_extending",
        }:
            args.append("--force")
        result = self.osc.run(*args, resource.id, check=False, timeout=60)
        if result.returncode != 0 and self.osc.exists("volume", resource.id):
            raise SuiteError(
                f"Volume delete request failed for {resource.id}: {(result.stderr or result.stdout).strip()}"
            )

    def _delete_security_group(self, resource: ResourceRecord) -> None:
        self.logger.log(f"Deleting security group {resource.name} ({resource.id})")
        self.osc.run(
            "security",
            "group",
            "delete",
            resource.id,
            check=False,
            timeout=min(60, self.config.resource_timeout),
        )

    def _delete_server_group(self, resource: ResourceRecord) -> None:
        self.logger.log(f"Deleting server group {resource.name} ({resource.id})")
        self.osc.run(
            "server",
            "group",
            "delete",
            resource.id,
            check=False,
            timeout=min(60, self.config.resource_timeout),
        )

    def _delete_keypair(self, resource: ResourceRecord) -> None:
        self.logger.log(f"Deleting keypair {resource.name}")
        self.osc.run(
            "keypair",
            "delete",
            resource.name,
            check=False,
            timeout=min(60, self.config.resource_timeout),
        )
