from __future__ import annotations

import re
import threading
from typing import Any

from .cancellation import hard_abort_reason
from .cleanup_components.deletion import ResourceDeletionMixin
from .cleanup_components.orphans import OrphanCleanupMixin
from .cleanup_components.recovery import CleanupRecoveryMixin
from .cleanup_components.verification import CleanupVerificationMixin
from .cloud_operation import CloudOperationCoordinator
from .config import Config
from .errors import RunCancelledError, SuiteError
from .migration_operation_recovery import (
    is_validation_only_migration,
    recover_validation_only_migration,
)
from .models import ResourceRecord
from .openstack import OpenStack
from .reporting import Reporter, ResourceTracker


class CleanupManager(
    OrphanCleanupMixin,
    ResourceDeletionMixin,
    CleanupVerificationMixin,
    CleanupRecoveryMixin,
):
    lifecycle_lock: Any = None
    cloud_operation_coordinator: CloudOperationCoordinator | None = None
    _RUN_ID_RE = re.compile(r"^(?P<run>[A-Za-z0-9_.-]+-\d{14}-[0-9a-fA-F]{6})$")
    _SCOPED_RUN_TAG_RE = re.compile(
        r"^(?P<run>[A-Za-z0-9_.-]+?-\d{14}-[0-9a-fA-F]{6})(?:-|$)"
    )
    _LEGACY_NAME_RE = re.compile(r"^(?P<run>nflux-\d{14}-[0-9a-fA-F]{6})(?:-|$)")
    _FINAL_EXACT_RUN_SWEEP_PASSES = 5
    _FINAL_EXACT_RUN_STABLE_SCANS = 2
    _FINAL_EXACT_RUN_SETTLEMENT_FLOOR_SECONDS = 5.0
    _FINAL_EXACT_RUN_SETTLEMENT_CAP_SECONDS = 30.0

    cleanup_project_id: str | None = None

    def __init__(
        self,
        osc: OpenStack,
        reporter: Reporter,
        tracker: ResourceTracker,
        config: Config,
        lifecycle_lock: Any | None = None,
        cloud_operation_coordinator: CloudOperationCoordinator | None = None,
    ):
        self.osc = osc
        self.reporter = reporter
        self.tracker = tracker
        self.config = config
        self.logger = reporter.logger
        self.cloud_operation_coordinator = cloud_operation_coordinator
        self.lifecycle_lock = (
            cloud_operation_coordinator.lock
            if cloud_operation_coordinator is not None
            else (lifecycle_lock or threading.RLock())
        )

    def _wait_for_exact_run_inventory_settlement(self, next_pass: int) -> float:
        """Leave a real visibility window between authoritative inventories.

        Every production entry point supplies the shared cloud operation coordinator,
        which provides a cancellation-aware, durably recorded wait. Keeping
        this operation in one method also gives deterministic tests an explicit
        seam for advancing simulated cloud visibility without sleeping.
        """
        coordinator = self.cloud_operation_coordinator
        if coordinator is None:
            return 0.0
        configured = float(getattr(self.config, "convergence_interval", 0) or 0)
        seconds = min(
            max(configured, self._FINAL_EXACT_RUN_SETTLEMENT_FLOOR_SECONDS),
            self._FINAL_EXACT_RUN_SETTLEMENT_CAP_SECONDS,
        )
        return coordinator.settle(
            "network-topology",
            "allow exact-run OpenStack inventory visibility to settle before "
            f"cleanup verification pass {next_pass}",
            seconds=seconds,
            fresh=True,
        )

    def _unresolved_cleanup_operation_ids(
        self, *, include_historical: bool = False
    ) -> list[str]:
        coordinator = self.cloud_operation_coordinator
        return (
            sorted(
                {
                    str(record["operation_id"])
                    for record in coordinator.unresolved_records(
                        include_historical=include_historical
                    )
                }
            )
            if coordinator is not None
            else []
        )

    def _record_unresolved_cleanup_operations(
        self, *, include_historical: bool = False
    ) -> list[str]:
        unresolved = self._unresolved_cleanup_operation_ids(
            include_historical=include_historical
        )
        summary = self.reporter.cleanup_summary
        summary["unresolved_operations"] = unresolved
        summary["leftovers"] = [
            item
            for item in summary.get("leftovers", [])
            if not str(item).startswith("cloud-operation:unresolved:")
        ] + [f"cloud-operation:unresolved:{identity}" for identity in unresolved]
        if unresolved:
            summary["complete"] = False
            summary["scope_verification"] = "unresolved-cloud-operations"
            self.logger.log(
                "Cleanup cannot be verified while cloud submissions remain unresolved: "
                + ", ".join(unresolved),
                "ERROR",
            )
        elif summary.get("scope_verification") == "unresolved-cloud-operations":
            summary.pop("scope_verification", None)
        return unresolved

    def _final_exact_run_sweep(
        self,
        *,
        run_tag: str,
        name_prefix: str,
    ) -> tuple[int, bool, list[dict[str, Any]], list[str]]:
        """Reach a bounded, authoritatively observed exact-run fixed point.

        Two consecutive complete inventories with no newly adopted resources
        are required. This prevents a resource which settles into list output
        after the first cleanup pass from being mistaken for an empty run.
        """
        total_adopted = 0
        stable_scans = 0
        passes: list[dict[str, Any]] = []
        last_errors: list[str] = []
        for pass_number in range(1, self._FINAL_EXACT_RUN_SWEEP_PASSES + 1):
            discovery_errors: list[str] = []
            inventory_state: dict[str, Any] = {}
            adopted = self._adopt_orphans(
                run_tag,
                name_prefix,
                discovery_errors=discovery_errors,
                inventory_state=inventory_state,
            )
            discovery_errors = list(dict.fromkeys(discovery_errors))
            visible_resources = list(inventory_state.get("visible_resources") or [])
            total_adopted += adopted
            if visible_resources:
                self._delete_all_types()
            if visible_resources or discovery_errors:
                stable_scans = 0
            else:
                stable_scans += 1
            passes.append(
                {
                    "pass": pass_number,
                    "adopted": adopted,
                    "visible_resources": visible_resources,
                    "visible_count": len(visible_resources),
                    "discovery_errors": discovery_errors,
                    "consecutive_clean_scans": stable_scans,
                    "settlement_seconds_after_pass": 0.0,
                }
            )
            if discovery_errors:
                self.logger.log(
                    "Exact-run cleanup inventory pass "
                    f"{pass_number} was uncertain: " + " | ".join(discovery_errors),
                    "WARNING",
                )
            elif adopted:
                self.logger.log(
                    "Exact-run cleanup inventory pass "
                    f"{pass_number} adopted {adopted} late-visible resource(s)",
                    "WARNING",
                )
            elif visible_resources:
                self.logger.log(
                    "Exact-run cleanup inventory pass "
                    f"{pass_number} still saw {len(visible_resources)} "
                    "tracked resource(s); cleanup was retried",
                    "WARNING",
                )
            if stable_scans >= self._FINAL_EXACT_RUN_STABLE_SCANS:
                return total_adopted, True, passes, []
            last_errors = discovery_errors
            if pass_number < self._FINAL_EXACT_RUN_SWEEP_PASSES:
                passes[-1]["settlement_seconds_after_pass"] = (
                    self._wait_for_exact_run_inventory_settlement(pass_number + 1)
                )

        unresolved = last_errors or [
            "exact-run inventory did not produce two consecutive clean scans "
            f"within {self._FINAL_EXACT_RUN_SWEEP_PASSES} passes"
        ]
        return total_adopted, False, passes, unresolved

    def _record_interrupted_cleanup(self, reason: str) -> bool:
        """Persist a concise unknown state without inventing cloud leftovers."""
        summary = self.reporter.cleanup_summary
        remaining = [
            item
            for item in self.reporter.resources
            if item.delete_status not in {"deleted", "already-absent"}
        ]
        confirmed_deleted = len(
            {
                (item.resource_type, item.id)
                for item in self.reporter.resources
                if item.delete_status in {"deleted", "already-absent"}
            }
        )
        explicit_deleted = len(
            {
                (item.resource_type, item.id)
                for item in self.reporter.resources
                if item.delete_status == "deleted"
            }
        )
        # Only retain leftovers that were positively classified before the
        # interruption. A killed verification command proves nothing about
        # whether its target still exists.
        known_leftovers = [
            item
            for item in summary.get("leftovers", [])
            if ":QUARANTINED:" in str(item)
        ]
        summary.update(
            {
                "attempted": True,
                "complete": None,
                "interrupted": True,
                "interruption_reason": reason or hard_abort_reason(),
                "scope_verification": "interrupted-before-final-verification",
                "deleted": explicit_deleted,
                "confirmed_deleted_count": confirmed_deleted,
                "unverified_resource_count": len(remaining),
                "leftovers": list(dict.fromkeys(known_leftovers)),
                "errors": [
                    item
                    for item in dict.fromkeys(summary.get("errors", []))
                    if "received signal" not in str(item).lower()
                ],
            }
        )
        event = getattr(self.reporter, "event", None)
        if callable(event):
            event(
                "cleanup-interrupted",
                "Cleanup stopped before final OpenStack inventory verification",
                confirmed_deleted=confirmed_deleted,
                unverified_resources=len(remaining),
                reason=summary["interruption_reason"],
            )
        self.logger.log(
            "Cleanup interrupted before final verification: "
            f"{confirmed_deleted} resource(s) are confirmed absent; "
            f"{len(remaining)} tracked resource(s) require a resumed cleanup "
            "inventory",
            "WARNING",
        )
        return False

    def cleanup(
        self,
        *,
        run_tag: str | None = None,
        name_prefix: str | None = None,
        adopt_discovered: bool = True,
        clear_recovery_artifacts: bool = True,
        completion_message: str
        | None = "Cleanup complete; no recognized resources remain in the eligible run scope",
    ) -> bool:
        summary = self.reporter.cleanup_summary
        summary["attempted"] = True
        self.logger.section("Cleaning every managed OpenStack resource")
        verification_uncertain = bool(self.reporter.manifest_errors)
        if self.reporter.manifest_errors:
            for error in self.reporter.manifest_errors:
                marker = f"manifest:verification-error:{error}"
                if marker not in summary["leftovers"]:
                    summary["leftovers"].append(marker)
        selected_run_tag = run_tag or self.reporter.run_tag
        selected_name_prefix = name_prefix or self.reporter.name_prefix
        adopted = 0
        try:
            initial_discovery_errors: list[str] = []
            if adopt_discovered:
                adopted = self._adopt_orphans(
                    selected_run_tag,
                    selected_name_prefix,
                    discovery_errors=initial_discovery_errors,
                )
            coordinator = self.cloud_operation_coordinator
            if coordinator is not None and not self.config.cleanup_dry_run:
                for record in coordinator.unresolved_records():
                    if is_validation_only_migration(record) and set(
                        record.get("resource_ids") or ()
                    ).issubset({item.id for item in self.reporter.resources}):
                        try:
                            recover_validation_only_migration(
                                self.osc, coordinator, record
                            )
                        except RunCancelledError:
                            raise
                        except (SuiteError, OSError, ValueError, TypeError) as exc:
                            self.logger.log(
                                f"Migration cleanup recovery remains blocked: {exc}",
                                "WARNING",
                            )
            self._delete_all_types()
            self._remove_local_keys()
            if adopt_discovered:
                (
                    late_adopted,
                    fixed_point,
                    exact_run_passes,
                    unresolved_discovery,
                ) = self._final_exact_run_sweep(
                    run_tag=selected_run_tag,
                    name_prefix=selected_name_prefix,
                )
                adopted += late_adopted
                summary["exact_run_verification"] = {
                    "initial_discovery_errors": list(
                        dict.fromkeys(initial_discovery_errors)
                    ),
                    "passes": exact_run_passes,
                    "fixed_point": fixed_point,
                    "stable_scans_required": self._FINAL_EXACT_RUN_STABLE_SCANS,
                    "max_passes": self._FINAL_EXACT_RUN_SWEEP_PASSES,
                    "settlement_floor_seconds": (
                        self._FINAL_EXACT_RUN_SETTLEMENT_FLOOR_SECONDS
                    ),
                    "settlement_cap_seconds": (
                        self._FINAL_EXACT_RUN_SETTLEMENT_CAP_SECONDS
                    ),
                }
                if not fixed_point:
                    verification_uncertain = True
                    for error in unresolved_discovery:
                        marker = f"exact-run-inventory:verification-error:{error}"
                        if marker not in summary["leftovers"]:
                            summary["leftovers"].append(marker)
                        summary["errors"].append(error)
            summary["adopted_orphans"] = adopted
        except RunCancelledError as exc:
            return self._record_interrupted_cleanup(str(exc))
        except Exception as exc:
            verification_uncertain = True
            summary["adopted_orphans"] = adopted
            summary["errors"].append(str(exc))
            self.logger.log(f"Cleanup exception: {exc}", "ERROR")

        leftovers: list[str] = []
        for resource in self.reporter.resources:
            if resource.delete_status in {"deleted", "already-absent"}:
                continue
            try:
                if self.osc.exists(resource.resource_type, resource.id):
                    leftovers.append(
                        f"{resource.resource_type}:{resource.id}:{resource.name}"
                    )
                elif resource.delete_status not in {"deleted", "already-absent"}:
                    self.tracker.mark_deleted(resource, "already-absent")
            except RunCancelledError as exc:
                return self._record_interrupted_cleanup(str(exc))
            except Exception as exc:
                verification_uncertain = True
                leftovers.append(
                    f"{resource.resource_type}:{resource.id}:{resource.name}:verification-error"
                )
                summary["errors"].append(str(exc))
        try:
            placement_leftovers = self._verify_placement_allocations()
        except RunCancelledError as exc:
            return self._record_interrupted_cleanup(str(exc))
        except Exception as exc:
            verification_uncertain = True
            placement_leftovers = [f"placement-allocation:verification-error:{exc}"]
            summary["errors"].append(str(exc))
            self.logger.log(
                f"Placement allocation cleanup verification failed: {exc}", "ERROR"
            )
        self._record_unresolved_cleanup_operations()
        confirmed_absent = {
            (resource.resource_type, resource.id)
            for resource in self.reporter.resources
            if resource.delete_status in {"deleted", "already-absent"}
        }
        for marker in summary.get("leftovers", []):
            fields = str(marker).split(":", 3)
            if (
                len(fields) == 4
                and fields[2] == "QUARANTINED"
                and (fields[0], fields[1]) in confirmed_absent
            ):
                # A later cleanup pass may have independently proved absence
                # after the operation which quarantined this resource settled.
                # Keep unresolved operation/inventory markers, but retire the
                # old resource leftover once its deletion is verified.
                continue
            leftovers.append(marker)
        leftovers.extend(placement_leftovers)
        leftovers = list(dict.fromkeys(leftovers))
        if verification_uncertain and not leftovers:
            leftovers.append(
                "cleanup-verification:unknown:OpenStack inventory could not be verified"
            )
        summary["leftovers"] = leftovers
        # Transient delete errors that were recovered do not make an otherwise
        # verified cleanup incomplete. They remain in the report as history.
        summary["recovered_errors"] = (
            list(summary.get("errors", []))
            if not leftovers and not verification_uncertain
            else []
        )
        summary["complete"] = not leftovers and not verification_uncertain
        if summary["complete"]:
            if clear_recovery_artifacts:
                self._clear_recovery_artifacts()
            delayed = summary.get("delayed_groups") or []
            if delayed:
                self.logger.log(
                    f"Group cleanup was delayed for {len(delayed)} group(s); final cleanup succeeded"
                )
            if completion_message:
                self.logger.log(completion_message)
        else:
            for leftover in leftovers:
                self.logger.log(
                    f"Unresolved cleanup or verification issue: {leftover}", "ERROR"
                )
            self._write_recovery_artifacts()
        return bool(summary["complete"])

    def cleanup_group(self, group_id: str) -> bool:
        records = [
            item
            for item in self.reporter.resources
            if item.metadata.get("group_id") == group_id
            and item.delete_status not in {"deleted", "already-absent"}
        ]
        if not records:
            return True
        self.logger.section(f"Releasing completed endpoint group {group_id}")
        handlers = [
            ("floating_ip", self._delete_floating_ip),
            ("server", self._delete_server),
            ("router", self._delete_router),
            ("port", self._delete_port),
            ("subnet", self._delete_subnet),
            ("network", self._delete_network),
            ("volume", self._delete_volume),
            ("server_group", self._delete_server_group),
        ]
        for resource_type, handler in handlers:
            selected = sorted(
                [item for item in records if item.resource_type == resource_type],
                key=lambda item: item.sequence,
                reverse=True,
            )
            self._delete_selected(selected, handler)
        leftovers: list[ResourceRecord] = []
        for item in records:
            if item.delete_status in {"deleted", "already-absent"}:
                continue
            try:
                if self.osc.exists(item.resource_type, item.id):
                    leftovers.append(item)
                else:
                    self.tracker.mark_deleted(item, "already-absent")
            except RunCancelledError:
                raise
            except SuiteError as exc:
                item.cleanup_error = str(exc)
                leftovers.append(item)
                self.reporter.cleanup_summary["errors"].append(
                    f"{item.resource_type} {item.id}: {exc}"
                )
        if leftovers:
            for item in leftovers:
                self.logger.log(
                    f"Group cleanup or verification unresolved: {item.resource_type}:{item.id}:{item.name}",
                    "ERROR",
                )
            self.reporter.cleanup_summary.setdefault("delayed_groups", []).append(
                {
                    "group_id": group_id,
                    "leftovers": [
                        f"{item.resource_type}:{item.id}:{item.name}"
                        for item in leftovers
                    ],
                }
            )
            self.logger.log(
                f"Group cleanup delayed for {group_id}; resources remain journaled for final cleanup",
                "WARNING",
            )
            return False
        coordinator = getattr(self, "cloud_operation_coordinator", None)
        if coordinator is not None:
            coordinator.settle(
                "network-topology",
                f"quiet interval after releasing endpoint group {group_id}",
                seconds=15.0,
            )
        self.logger.log(f"Released endpoint group {group_id}")
        return True

    def cleanup_group_side(self, group_id: str, side: str) -> bool:
        """Delete one endpoint side while preserving the peer and shared topology."""

        normalized_side = side.upper()
        records = [
            item
            for item in self.reporter.resources
            if item.metadata.get("group_id") == group_id
            and str(item.metadata.get("endpoint_side") or "").upper() == normalized_side
            and item.delete_status not in {"deleted", "already-absent"}
        ]
        # Older floating-IP records identify their owned test port rather than
        # the endpoint side. Release those associations before deleting the port.
        ports = {item.id for item in records if item.resource_type == "port"}
        records.extend(
            item
            for item in self.reporter.resources
            if item.resource_type == "floating_ip"
            and item.metadata.get("group_id") == group_id
            and item.parent_id in ports
            and item not in records
            and item.delete_status not in {"deleted", "already-absent"}
        )
        if not records:
            return True
        self.logger.section(
            f"Rotating endpoint side {normalized_side} for group {group_id}"
        )
        handlers = [
            ("floating_ip", self._delete_floating_ip),
            ("server", self._delete_server),
            ("port", self._delete_port),
            ("volume", self._delete_volume),
        ]
        for resource_type, handler in handlers:
            selected = sorted(
                [item for item in records if item.resource_type == resource_type],
                key=lambda item: item.sequence,
                reverse=True,
            )
            self._delete_selected(selected, handler)
        leftovers: list[ResourceRecord] = []
        for item in records:
            if item.delete_status in {"deleted", "already-absent"}:
                continue
            try:
                if self.osc.exists(item.resource_type, item.id):
                    leftovers.append(item)
                else:
                    self.tracker.mark_deleted(item, "already-absent")
            except RunCancelledError:
                raise
            except SuiteError as exc:
                item.cleanup_error = str(exc)
                leftovers.append(item)
                self.reporter.cleanup_summary["errors"].append(
                    f"{item.resource_type} {item.id}: {exc}"
                )
        if leftovers:
            self.logger.log(
                f"Endpoint-side cleanup for {group_id}:{normalized_side} "
                "did not converge; replacement is blocked",
                "ERROR",
            )
            return False
        coordinator = getattr(self, "cloud_operation_coordinator", None)
        if coordinator is not None:
            coordinator.settle(
                "endpoint-rotation",
                f"prove Nova/Neutron deletion convergence for "
                f"{group_id}:{normalized_side}",
                seconds=15.0,
            )
        self.reporter.event(
            "endpoint-side-released",
            f"Released endpoint side {normalized_side}",
            group_id=group_id,
            side=normalized_side,
            resources=len(records),
        )
        return True
