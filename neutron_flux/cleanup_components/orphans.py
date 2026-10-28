from __future__ import annotations

import ast
import datetime as dt
import json
import sys
from typing import Any

# mypy: disable-error-code="attr-defined"
from ..errors import RunCancelledError, SuiteError
from ..operation_recovery import recover_operations
from ..scheduling import READ_WORKERS, bounded_map
from ..state import StateStore
from ..utils import list_value, optional_text, pick

_UNREAD_SERVER_DETAIL = object()


class OrphanCleanupMixin:
    """Compatibility mixin for this cleanup concern."""

    def cleanup_orphans(self) -> bool:
        """Delete stale project resources to a verified fixed point."""
        self.logger.section(
            "Discovering orphaned Neutron Flux resources in the current OpenStack project"
        )
        token = self.osc.json(
            "token",
            "issue",
            check=False,
            timeout=min(60, self.config.resource_timeout),
        )
        project_id = (
            optional_text(pick(token, "project_id", "project id"))
            if isinstance(token, dict)
            else None
        )
        if not project_id:
            raise SuiteError(
                "Cleanup requires a project-scoped token exposing project_id; no resources were changed"
            )
        self.cleanup_project_id = project_id
        self.logger.log(f"Cleanup project scope: {project_id}")

        coordinator = getattr(self, "cloud_operation_coordinator", None)
        if coordinator is not None and not self.config.cleanup_dry_run:
            recover_operations(self.osc, coordinator, self.logger)
        initial = self._discover_project_orphans()
        if not initial["candidates"] and not self.config.cleanup_dry_run:
            # An empty first read can precede a delayed create becoming visible.
            # Keep the same fresh visibility window used by exact-run cleanup.
            self._wait_for_exact_run_inventory_settlement(2)
            initial = self._discover_project_orphans()
        candidates = list(initial["candidates"])
        protected = list(initial["protected"])
        unknown = list(initial.get("unknown") or [])
        runs = initial["runs"]
        sweep = {
            "grace_minutes": self.config.orphan_grace_minutes,
            "include_active": self.config.cleanup_include_active,
            "dry_run": self.config.cleanup_dry_run,
            "project_id": project_id,
            "passes": [],
            "initial_candidate_runs": sorted(
                run_id for run_id, detail in runs.items() if detail.get("selected")
            ),
            "initial_protected_runs": sorted(
                run_id for run_id, detail in runs.items() if detail.get("protected")
            ),
        }
        self.reporter.cleanup_summary["orphan_sweep"] = sweep
        self._record_orphan_inventory_summary(initial, phase="initial")

        if not candidates and not self.config.cleanup_dry_run:
            unknown_markers = [
                f"{item['resource_type']}:{item['id']}:{item['name']}"
                for item in unknown
            ]
            self.reporter.cleanup_summary.update(
                {
                    "attempted": False,
                    "complete": not unknown,
                    "leftovers": unknown_markers,
                }
            )
            unresolved = self._record_unresolved_cleanup_operations(
                include_historical=True
            )
            sweep.update(
                {
                    "stale_resources_remaining": 0,
                    "protected_resources_remaining": len(protected),
                    "unknown_resources_remaining": len(unknown),
                    "project_resources_remaining": len(protected) + len(unknown),
                    "protected_runs": sorted(
                        run_id
                        for run_id, detail in runs.items()
                        if detail.get("protected")
                    ),
                    "protected_run_details": {
                        run_id: {
                            "resource_count": detail.get("resource_count", 0),
                            "reason": detail.get("reason"),
                            "states": sorted(detail.get("states") or []),
                            "heartbeat_age_seconds": detail.get(
                                "heartbeat_age_seconds"
                            ),
                        }
                        for run_id, detail in sorted(runs.items())
                        if detail.get("protected")
                    },
                }
            )
            if unknown or unresolved:
                if unknown:
                    self.logger.log(
                        f"Found {len(unknown)} Flux-like resource(s) without trustworthy run ownership; manual review is required",
                        "ERROR",
                    )
                for marker in unknown_markers:
                    self.logger.log(f"Unclassified Flux resource: {marker}", "ERROR")
                self._write_recovery_artifacts()
                return False
            if protected:
                self.logger.log(
                    "No orphaned resources are eligible for deletion; "
                    f"{len(protected)} resource(s) belonging to active run(s) remain protected"
                )
            else:
                self.logger.log("No Neutron Flux resources were found in the project")
            return True

        counts: dict[str, int] = {}
        for item in candidates:
            counts[item["resource_type"]] = counts.get(item["resource_type"], 0) + 1
        self.logger.log(
            "Orphan cleanup candidates: "
            + (
                ", ".join(
                    f"{resource_type}={count}"
                    for resource_type, count in sorted(counts.items())
                )
                or "none"
            )
        )
        for run_id, detail in sorted(runs.items()):
            if detail.get("selected"):
                self.logger.log(
                    f"Orphan run {run_id}: resources={detail.get('resource_count', 0)}, "
                    f"classification={detail.get('reason') or 'stale ownership markers'}"
                )

        known = {
            (item.resource_type, item.id): item for item in self.reporter.resources
        }
        for item in candidates:
            key = (item["resource_type"], item["id"])
            if key in known:
                if known[key].delete_status in {"deleted", "already-absent"}:
                    self.tracker.mark_present(known[key])
                continue
            known[key] = self.tracker.add(
                item["resource_type"],
                item["id"],
                item["name"],
                orphan_adopted=True,
                orphan_run_id=item["run_id"],
                ownership_evidence=item["evidence"],
                cloud_discovered=True,
            )

        if self.config.cleanup_dry_run:
            candidate_markers = [
                f"{item['resource_type']}:{item['id']}:{item['name']}"
                for item in candidates
            ]
            unknown_markers = [
                f"{item['resource_type']}:{item['id']}:{item['name']}"
                for item in unknown
            ]
            self.reporter.cleanup_summary.update(
                {
                    "attempted": False,
                    "complete": None,
                    "leftovers": unknown_markers,
                    "dry_run": True,
                    "dry_run_candidates": candidate_markers,
                    "dry_run_unknown": unknown_markers,
                    "unresolved_operations": self._unresolved_cleanup_operation_ids(
                        include_historical=True
                    ),
                }
            )
            sweep.update(
                {
                    "stale_resources_remaining": len(candidates),
                    "protected_resources_remaining": len(protected),
                    "unknown_resources_remaining": len(unknown),
                    "project_resources_remaining": (
                        len(candidates) + len(protected) + len(unknown)
                    ),
                }
            )
            self.logger.log(
                "Dry run complete; no OpenStack resources were changed. "
                f"Preview: orphaned={len(candidates)}, protected={len(protected)}, "
                f"unknown={len(unknown)}. "
                "Rerun without --dry-run to delete "
                "all eligible orphaned resources."
            )
            return True

        if not self.config.cleanup_assume_yes:
            if not sys.stdin.isatty():
                raise SuiteError(
                    "cleanup requires an interactive terminal or --yes; "
                    "use --dry-run to preview safely"
                )
            answer = (
                input(
                    f"Delete {len(candidates)} Neutron Flux resource(s), including active runs and orphans, "
                    "from the current project? [y/N] "
                )
                .strip()
                .lower()
            )
            if answer not in {"y", "yes"}:
                self.reporter.cleanup_summary.update(
                    {
                        "attempted": False,
                        "complete": True,
                        "leftovers": [],
                        "cancelled": True,
                    }
                )
                self.logger.log("Orphan cleanup cancelled; no resources were changed")
                return True

        previous_remaining: set[tuple[str, str]] | None = None
        final_inventory = initial
        all_passes_verified = True
        max_passes = 5
        for pass_number in range(1, max_passes + 1):
            inventory = (
                initial if pass_number == 1 else self._discover_project_orphans()
            )
            pass_candidates = list(inventory["candidates"])
            for item in pass_candidates:
                key = (item["resource_type"], item["id"])
                if key in known:
                    if known[key].delete_status in {"deleted", "already-absent"}:
                        self.tracker.mark_present(known[key])
                    continue
                known[key] = self.tracker.add(
                    item["resource_type"],
                    item["id"],
                    item["name"],
                    orphan_adopted=True,
                    orphan_run_id=item["run_id"],
                    ownership_evidence=item["evidence"],
                    cloud_discovered=True,
                )
            if not pass_candidates:
                final_inventory = inventory
                break

            deleted_before = int(self.reporter.cleanup_summary.get("deleted", 0))
            self.reporter.cleanup_summary["leftovers"] = []
            pass_verified = self.cleanup(
                adopt_discovered=False,
                completion_message=None,
            )
            all_passes_verified = all_passes_verified and pass_verified
            final_inventory = self._discover_project_orphans()
            if not final_inventory["candidates"]:
                self._wait_for_exact_run_inventory_settlement(pass_number + 1)
                final_inventory = self._discover_project_orphans()
            remaining = {
                (item["resource_type"], item["id"])
                for item in final_inventory["candidates"]
            }
            deleted_delta = (
                int(self.reporter.cleanup_summary.get("deleted", 0)) - deleted_before
            )
            sweep["passes"].append(
                {
                    "pass": pass_number,
                    "candidates": len(pass_candidates),
                    "deleted": deleted_delta,
                    "remaining_stale": len(remaining),
                }
            )
            self.logger.log(
                f"Orphan cleanup pass {pass_number}: candidates={len(pass_candidates)}, "
                f"deleted={deleted_delta}, remaining_stale={len(remaining)}"
            )
            if not remaining:
                break
            if previous_remaining == remaining and deleted_delta == 0:
                all_passes_verified = False
                self.logger.log(
                    "Orphan cleanup reached a fixed point with stale resources still present",
                    "ERROR",
                )
                break
            previous_remaining = remaining

        final_inventory = self._discover_project_orphans()
        self._record_orphan_inventory_summary(final_inventory, phase="final")
        stale = list(final_inventory["candidates"])
        protected = list(final_inventory["protected"])
        unknown = list(final_inventory.get("unknown") or [])
        stale_markers = [
            f"{item['resource_type']}:{item['id']}:{item['name']}" for item in stale
        ]
        unknown_markers = [
            f"{item['resource_type']}:{item['id']}:{item['name']}" for item in unknown
        ]
        self.reporter.cleanup_summary["leftovers"] = stale_markers + unknown_markers
        unresolved = self._record_unresolved_cleanup_operations(include_historical=True)
        # Fixed-point cleanup is authoritative by its final project
        # rediscovery.  A dependency conflict or timeout in an earlier pass is
        # a recovered delay when a later pass removes the resource and the
        # final inventory is clean.
        complete = not stale and not unknown and not unresolved
        self.reporter.cleanup_summary["complete"] = complete
        if complete and not all_passes_verified:
            recovered = list(
                dict.fromkeys(
                    [
                        *self.reporter.cleanup_summary.get("recovered_errors", []),
                        *self.reporter.cleanup_summary.get("errors", []),
                    ]
                )
            )
            self.reporter.cleanup_summary["recovered_errors"] = recovered
            self.reporter.cleanup_summary["errors"] = []
            self.logger.log(
                "Earlier cleanup-pass conflicts were recovered; final project "
                "rediscovery is clean",
                "WARNING",
            )
        sweep.update(
            {
                "candidate_runs": sorted(
                    set(sweep.get("initial_candidate_runs") or [])
                    | {
                        run_id
                        for run_id, detail in final_inventory["runs"].items()
                        if detail.get("selected")
                    }
                ),
                "protected_runs": sorted(
                    run_id
                    for run_id, detail in final_inventory["runs"].items()
                    if detail.get("protected")
                ),
                "protected_run_details": {
                    run_id: {
                        "resource_count": detail.get("resource_count", 0),
                        "reason": detail.get("reason"),
                        "states": sorted(detail.get("states") or []),
                        "heartbeat_age_seconds": detail.get("heartbeat_age_seconds"),
                    }
                    for run_id, detail in sorted(final_inventory["runs"].items())
                    if detail.get("protected")
                },
                "stale_resources_remaining": len(stale),
                "protected_resources_remaining": len(protected),
                "unknown_resources_remaining": len(unknown),
                "project_resources_remaining": (
                    len(stale) + len(protected) + len(unknown)
                ),
            }
        )
        if complete:
            self._clear_recovery_artifacts()
            if protected:
                self.logger.log(
                    "Orphan cleanup complete: no orphaned resources remain; "
                    f"{len(protected)} resource(s) belonging to active run(s) remain protected"
                )
            else:
                self.logger.log(
                    "Orphan cleanup complete; final project rediscovery found no "
                    "Neutron Flux resources"
                )
        else:
            for marker in stale_markers:
                self.logger.log(f"Orphan cleanup leftover: {marker}", "ERROR")
            for marker in unknown_markers:
                self.logger.log(f"Unclassified Flux resource: {marker}", "ERROR")
            self._write_recovery_artifacts()
        return complete

    def _record_orphan_inventory_summary(
        self, inventory: dict[str, Any], *, phase: str
    ) -> None:
        protected = list(inventory.get("protected") or [])
        candidates = list(inventory.get("candidates") or [])
        unknown = list(inventory.get("unknown") or [])
        runs = inventory.get("runs") or {}
        self.reporter.cleanup_summary.setdefault("orphan_inventories", []).append(
            {
                "phase": phase,
                "stale_resources": len(candidates),
                "protected_resources": len(protected),
                "unknown_resources": len(unknown),
                "unknown": [
                    {
                        "resource_type": item.get("resource_type"),
                        "id": item.get("id"),
                        "name": item.get("name"),
                        "reason": item.get("reason"),
                    }
                    for item in unknown
                ],
                "runs": {
                    run_id: {
                        "resource_count": detail.get("resource_count", 0),
                        "selected": bool(detail.get("selected")),
                        "protected": bool(detail.get("protected")),
                        "previously_retained": bool(detail.get("retained_state")),
                        "reason": detail.get("reason"),
                        "states": sorted(detail.get("states") or []),
                        "latest_heartbeat": (
                            detail.get("latest_heartbeat").isoformat()
                            if isinstance(detail.get("latest_heartbeat"), dt.datetime)
                            else None
                        ),
                        "heartbeat_age_seconds": detail.get("heartbeat_age_seconds"),
                    }
                    for run_id, detail in sorted(runs.items())
                },
            }
        )
        if protected:
            self.logger.log(
                f"Protected {len(protected)} resource(s) belonging to active run(s)"
            )
            for run_id, detail in sorted(runs.items()):
                if detail.get("protected"):
                    self.logger.log(
                        f"Protected run {run_id}: resources={detail.get('resource_count', 0)}, "
                        f"reason={detail.get('reason')}, states="
                        + ",".join(sorted(detail.get("states") or ["unknown"]))
                    )

    def _local_orphan_run_states(self) -> dict[str, dict[str, Any]]:
        """Load same-report-root lifecycle and lock evidence for orphan classification."""
        try:
            store = StateStore(self.config.report_dir)
            checkpoints = store.list()
        except SuiteError as exc:
            self.logger.log(
                f"Could not inspect local run checkpoints during orphan discovery: {exc}",
                "WARNING",
            )
            return {}
        output: dict[str, dict[str, Any]] = {}
        for checkpoint in checkpoints:
            try:
                active_lock = store.active_lock(checkpoint.run_id)
            except SuiteError as exc:
                self.logger.log(
                    f"Could not validate local lock for {checkpoint.run_id}: {exc}",
                    "WARNING",
                )
                active_lock = True
            state = str(checkpoint.state or "").upper()
            cleanup_state = str(checkpoint.cleanup_state or "").upper()
            retained = (
                cleanup_state == "RETAINED" or checkpoint.phase == "resources-retained"
            )
            terminal = state in {
                "CANCELLED",
                "FAILED",
                "INTERRUPTED",
                "CLEANUP_INCOMPLETE",
                "COMPLETED",
            } or cleanup_state in {"INCOMPLETE", "RETAINED", "COMPLETE"}
            output[checkpoint.run_id] = {
                "state": state,
                "cleanup_state": cleanup_state,
                "phase": checkpoint.phase,
                "terminal": terminal,
                "retained": retained,
                "active_lock": active_lock,
                "updated_at": checkpoint.updated_at,
            }
        return output

    def _discover_project_orphans(self) -> dict[str, Any]:
        specs: list[tuple[str, list[str], list[str]]] = [
            (
                "floating_ip",
                ["floating", "ip", "list", "--long"],
                ["floating", "ip", "list"],
            ),
            ("server", ["server", "list", "--long"], ["server", "list"]),
            ("router", ["router", "list", "--long"], ["router", "list"]),
            ("port", ["port", "list", "--long"], ["port", "list"]),
            ("subnet", ["subnet", "list", "--long"], ["subnet", "list"]),
            ("network", ["network", "list", "--long"], ["network", "list"]),
            (
                "security_group",
                ["security", "group", "list", "--long"],
                ["security", "group", "list"],
            ),
            ("volume", ["volume", "list", "--long"], ["volume", "list"]),
            ("server_group", ["server", "group", "list"], ["server", "group", "list"]),
            ("keypair", ["keypair", "list"], ["keypair", "list"]),
        ]
        discovered: list[dict[str, Any]] = []
        unknown: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        unknown_seen: set[tuple[str, str]] = set()
        project_id = getattr(self, "cleanup_project_id", None)

        def read_family(spec: tuple[str, list[str], list[str]]) -> list[dict[str, Any]]:
            resource_type, preferred, fallback = spec
            if project_id and resource_type in {
                "floating_ip",
                "router",
                "port",
                "subnet",
                "network",
                "security_group",
            }:
                preferred = [*preferred, "--project", project_id]
                fallback = [*fallback, "--project", project_id]
            return self._orphan_list(preferred, fallback)

        inventories = bounded_map(read_family, specs, workers=READ_WORKERS)
        server_ids = list(
            dict.fromkeys(
                str(pick(row, "id"))
                for (resource_type, _, _), rows in zip(specs, inventories, strict=True)
                if resource_type == "server"
                for row in rows
                if optional_text(pick(row, "id"))
                and (
                    not project_id
                    or not optional_text(
                        pick(row, "project_id", "project", "tenant_id")
                    )
                    or optional_text(pick(row, "project_id", "project", "tenant_id"))
                    == project_id
                )
            )
        )

        def read_server(identity: str) -> Any:
            return self.osc.json(
                "server",
                "show",
                identity,
                check=False,
                timeout=min(60, self.config.resource_timeout),
            )

        server_details = dict(
            zip(
                server_ids,
                bounded_map(read_server, server_ids, workers=READ_WORKERS),
                strict=True,
            )
        )
        # Merge on the caller thread so classification and protected-run
        # decisions keep their original ordering and failure semantics.
        for (resource_type, _, _), rows in zip(specs, inventories, strict=True):
            for row in rows:
                row_project = optional_text(
                    pick(row, "project_id", "project", "tenant_id")
                )
                if project_id and row_project and row_project != project_id:
                    continue
                candidate = self._owned_orphan_candidate(resource_type, row)
                evidence_row = row
                if candidate is None and resource_type == "server":
                    resource_id = optional_text(pick(row, "id"))
                    if resource_id:
                        detail = server_details[resource_id]
                        if isinstance(detail, dict):
                            evidence_row = detail
                            candidate = self._owned_orphan_candidate(
                                resource_type, detail
                            )
                if candidate is None:
                    unidentified = self._unclassified_flux_resource(
                        resource_type, evidence_row
                    )
                    if unidentified is not None:
                        key = (resource_type, unidentified["id"])
                        if key not in unknown_seen:
                            unknown_seen.add(key)
                            unknown.append(unidentified)
                    continue
                key = (resource_type, candidate["id"])
                if key in seen:
                    continue
                seen.add(key)
                if resource_type == "server":
                    candidate = self._enrich_orphan_server(
                        candidate, row, detail=server_details[candidate["id"]]
                    )
                discovered.append(candidate)

        grace_seconds = self.config.orphan_grace_minutes * 60
        now = dt.datetime.now(dt.timezone.utc)
        runs: dict[str, dict[str, Any]] = {}
        for item in discovered:
            detail = runs.setdefault(
                item["run_id"],
                {
                    "resource_count": 0,
                    "latest_activity": None,
                    "fresh_heartbeat": False,
                    "latest_heartbeat": None,
                    "heartbeat_age_seconds": None,
                    "active_state": False,
                    "terminal_state": False,
                    "retained_state": False,
                    "local_active_lock": False,
                    "local_checkpoint": None,
                    "states": set(),
                },
            )
            detail["resource_count"] += 1
            activity = item.get("activity")
            if isinstance(activity, dt.datetime):
                previous = detail.get("latest_activity")
                if not isinstance(previous, dt.datetime) or activity > previous:
                    detail["latest_activity"] = activity
            heartbeat = item.get("heartbeat")
            if isinstance(heartbeat, dt.datetime):
                previous_heartbeat = detail.get("latest_heartbeat")
                if (
                    not isinstance(previous_heartbeat, dt.datetime)
                    or heartbeat > previous_heartbeat
                ):
                    detail["latest_heartbeat"] = heartbeat
                if max(0.0, (now - heartbeat).total_seconds()) <= grace_seconds:
                    detail["fresh_heartbeat"] = True
            run_state = str(item.get("run_state") or "").strip().lower()
            if run_state:
                detail["states"].add(run_state)
            if run_state in {
                "active",
                "running",
                "initializing",
                "testing",
                "cleaning",
            }:
                detail["active_state"] = True
            if run_state in {
                "cancelled",
                "completed",
                "failed",
                "interrupted",
                "cleanup_incomplete",
                "cleanup-incomplete",
                "retained",
            }:
                detail["terminal_state"] = True
            if run_state == "retained":
                detail["retained_state"] = True

        local_states = self._local_orphan_run_states()
        for run_id, local in local_states.items():
            detail = runs.get(run_id)
            if detail is None:
                continue
            detail["local_checkpoint"] = local
            detail["local_active_lock"] = bool(local.get("active_lock"))
            if local.get("terminal"):
                detail["terminal_state"] = True
            if local.get("retained"):
                detail["retained_state"] = True
            local_state = str(local.get("state") or "").strip().lower()
            local_cleanup = str(local.get("cleanup_state") or "").strip().lower()
            if local_state:
                detail["states"].add(f"local:{local_state}")
            if local_cleanup:
                detail["states"].add(f"local-cleanup:{local_cleanup}")

        for detail in runs.values():
            heartbeat = detail.get("latest_heartbeat")
            if isinstance(heartbeat, dt.datetime):
                detail["heartbeat_age_seconds"] = max(
                    0.0, (now - heartbeat).total_seconds()
                )

        selected_runs: set[str] = set()
        protected_runs: set[str] = set()
        for run_id, detail in runs.items():
            latest = detail.get("latest_activity")
            recent_legacy_activity = bool(
                isinstance(latest, dt.datetime)
                and max(0.0, (now - latest).total_seconds()) <= grace_seconds
            )
            explicit_terminal = bool(detail.get("terminal_state"))
            explicit_active = bool(detail.get("active_state"))
            local_active_lock = bool(detail.get("local_active_lock"))
            retained = bool(detail.get("retained_state"))
            if local_active_lock:
                active = True
            elif explicit_terminal:
                active = False
            elif explicit_active:
                active = bool(detail.get("fresh_heartbeat")) or recent_legacy_activity
            else:
                active = recent_legacy_activity

            if local_active_lock and not self.config.cleanup_include_active:
                detail["protected"] = True
                detail["reason"] = "a live local Neutron Flux run lock is present"
                protected_runs.add(run_id)
            elif active and not self.config.cleanup_include_active:
                detail["protected"] = True
                detail["reason"] = (
                    "explicit active state with fresh heartbeat or recent legacy activity"
                )
                protected_runs.add(run_id)
            else:
                detail["selected"] = True
                if active:
                    detail["reason"] = "active-run override requested"
                elif detail.get("local_checkpoint") and explicit_terminal:
                    detail["reason"] = (
                        "terminal local checkpoint overrides fresh or missing cloud heartbeat"
                    )
                elif retained:
                    detail["reason"] = (
                        "terminal run previously retained resources; orphan cleanup selects all inactive Flux resources"
                    )
                else:
                    detail["reason"] = "stale or missing cloud heartbeat"
                selected_runs.add(run_id)

        return {
            "candidates": [
                item for item in discovered if item["run_id"] in selected_runs
            ],
            "protected": [
                item for item in discovered if item["run_id"] in protected_runs
            ],
            "unknown": unknown,
            "runs": runs,
        }

    def _orphan_list(
        self, preferred: list[str], fallback: list[str]
    ) -> list[dict[str, Any]]:
        try:
            rows = self.osc.json(
                *preferred,
                check=False,
                timeout=min(90, self.config.resource_timeout),
            )
            if rows is None and preferred != fallback:
                rows = self.osc.json(
                    *fallback,
                    check=False,
                    timeout=min(90, self.config.resource_timeout),
                )
        except RunCancelledError:
            raise
        except SuiteError as exc:
            self.logger.log(
                f"Extended orphan inventory failed for {' '.join(preferred)}: {exc}; "
                "retrying with the basic list command",
                "WARNING",
            )
            rows = self.osc.json(
                *fallback,
                check=False,
                timeout=min(90, self.config.resource_timeout),
            )
        if not isinstance(rows, list) or any(
            not isinstance(item, dict) for item in rows
        ):
            raise SuiteError(
                "Could not verify cleanup inventory for "
                + " ".join(fallback)
                + "; unavailable or malformed inventory does not prove absence"
            )
        return rows

    @classmethod
    def _extract_run_id(cls, value: Any) -> str | None:
        text = optional_text(value)
        if not text:
            return None
        scoped_tag = text.startswith("neutron-flux-")
        if scoped_tag:
            text = text[len("neutron-flux-") :]
        match = cls._RUN_ID_RE.fullmatch(text)
        if match:
            return match.group("run")
        if scoped_tag:
            scoped = cls._SCOPED_RUN_TAG_RE.match(text)
            if scoped:
                return scoped.group("run")
        return None

    @staticmethod
    def _mapping(value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return {}
            for parser in (json.loads, ast.literal_eval):
                try:
                    parsed = parser(text)
                except (ValueError, TypeError, SyntaxError, json.JSONDecodeError):
                    continue
                if isinstance(parsed, dict):
                    return parsed
            output: dict[str, Any] = {}
            for part in text.split(","):
                if "=" not in part:
                    continue
                key, raw = part.split("=", 1)
                output[key.strip()] = raw.strip().strip("'\"")
            return output
        return {}

    def _owned_orphan_candidate(
        self, resource_type: str, row: dict[str, Any]
    ) -> dict[str, Any] | None:
        name = str(
            pick(
                row,
                "name",
                "floating_ip_address",
                "floating ip address",
                default="",
            )
            or ""
        )
        resource_id = (
            name
            if resource_type == "keypair"
            else str(pick(row, "id", default="") or "")
        )
        if not resource_id:
            return None
        properties = self._mapping(
            pick(row, "properties", "metadata", "property", default={})
        )
        tags = [str(item) for item in list_value(pick(row, "tags", default=[]))]
        description = str(pick(row, "description", default="") or "")
        explicit_values = [
            properties.get("neutron_flux_run_id"),
            properties.get("neutron_flux_run"),
            properties.get("neutron-flux-run"),
            description,
            *tags,
        ]
        run_id = next(
            (
                value
                for item in explicit_values
                if (value := self._extract_run_id(item))
            ),
            None,
        )
        evidence = "explicit Neutron Flux tag/property"
        if run_id is None:
            legacy = self._LEGACY_NAME_RE.match(name)
            if legacy:
                run_id = legacy.group("run")
                evidence = "strict legacy nflux run-name prefix"
        if run_id is None:
            return None
        return {
            "resource_type": resource_type,
            "id": resource_id,
            "name": name or resource_id,
            "run_id": run_id,
            "evidence": evidence,
            "activity": self._latest_timestamp(row),
            "heartbeat": self._parse_timestamp(
                properties.get("neutron_flux_heartbeat")
            ),
            "run_state": properties.get("neutron_flux_state"),
        }

    def _unclassified_flux_resource(
        self, resource_type: str, row: dict[str, Any]
    ) -> dict[str, Any] | None:
        name = str(
            pick(
                row,
                "name",
                "floating_ip_address",
                "floating ip address",
                default="",
            )
            or ""
        )
        resource_id = (
            name
            if resource_type == "keypair"
            else str(pick(row, "id", default="") or "")
        )
        if not resource_id:
            return None
        properties = self._mapping(
            pick(row, "properties", "metadata", "property", default={})
        )
        tags = [str(item) for item in list_value(pick(row, "tags", default=[]))]
        description = str(pick(row, "description", default="") or "")
        text_values = [
            name,
            description,
            *tags,
            *[str(value) for value in properties.values()],
        ]
        looks_managed = name.startswith("nflux-") or any(
            "neutron-flux" in value.lower() or "neutron_flux" in value.lower()
            for value in text_values
        )
        if not looks_managed:
            return None
        return {
            "resource_type": resource_type,
            "id": resource_id,
            "name": name or resource_id,
            "reason": "Flux-like ownership markers were found but no valid run ID could be established",
            "activity": self._latest_timestamp(row),
        }

    def _enrich_orphan_server(
        self,
        candidate: dict[str, Any],
        row: dict[str, Any],
        *,
        detail: Any = _UNREAD_SERVER_DETAIL,
    ) -> dict[str, Any]:
        if detail is _UNREAD_SERVER_DETAIL:
            detail = self.osc.json(
                "server",
                "show",
                candidate["id"],
                check=False,
                timeout=min(60, self.config.resource_timeout),
            )
        if not isinstance(detail, dict):
            detail = row
        properties = self._mapping(pick(detail, "properties", "metadata", default={}))
        explicit_run = self._extract_run_id(
            properties.get("neutron_flux_run_id") or properties.get("neutron_flux_run")
        )
        if explicit_run:
            candidate["run_id"] = explicit_run
            candidate["evidence"] = "explicit Nova server metadata"
        candidate["heartbeat"] = self._parse_timestamp(
            properties.get("neutron_flux_heartbeat")
        )
        candidate["run_state"] = properties.get("neutron_flux_state")
        activity = self._latest_timestamp(detail)
        if activity is not None:
            candidate["activity"] = activity
        return candidate

    @classmethod
    def _latest_timestamp(cls, row: dict[str, Any]) -> dt.datetime | None:
        values = [
            pick(row, "updated", "updated_at", "updated at"),
            pick(row, "created", "created_at", "created at"),
        ]
        parsed = [item for value in values if (item := cls._parse_timestamp(value))]
        return max(parsed) if parsed else None

    @staticmethod
    def _parse_timestamp(value: Any) -> dt.datetime | None:
        text = optional_text(value)
        if not text:
            return None
        try:
            parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc)

    def _exact_orphan_evidence(
        self,
        resource_type: str,
        row: dict[str, Any],
        *,
        resource_id: str,
        name: str,
        run_tag: str | None,
        name_prefix: str | None,
        filtered: bool,
        server_detail: Any = _UNREAD_SERVER_DETAIL,
    ) -> str | None:
        tags = {str(value) for value in list_value(pick(row, "tags", default=[]))}
        description = str(pick(row, "description", default="") or "")
        properties = self._mapping(
            pick(row, "properties", "metadata", "property", default={})
        )
        if resource_type == "server" and not properties:
            detail = (
                self.osc.json(
                    "server",
                    "show",
                    resource_id,
                    check=False,
                    timeout=min(60, self.config.resource_timeout),
                )
                if server_detail is _UNREAD_SERVER_DETAIL
                else server_detail
            )
            if isinstance(detail, dict):
                properties = self._mapping(
                    pick(detail, "properties", "metadata", "property", default={})
                )
                tags.update(
                    str(value) for value in list_value(pick(detail, "tags", default=[]))
                )
                description = str(
                    pick(detail, "description", default=description) or description
                )
        explicit_run = next(
            (
                value
                for raw in (
                    properties.get("neutron_flux_run_id"),
                    properties.get("neutron_flux_run"),
                    properties.get("neutron-flux-run"),
                )
                if (value := self._extract_run_id(raw))
            ),
            None,
        )
        if explicit_run is not None:
            return (
                "exact-run-metadata" if explicit_run == self.reporter.run_id else None
            )
        tagged_run_ids = {
            value
            for raw in [description, *tags]
            if (value := self._extract_run_id(raw))
        }
        if self.reporter.run_id in tagged_run_ids:
            return "exact-run-scoped-tag"
        if run_tag and (run_tag in tags or description == run_tag):
            return "exact-run-tag"
        if filtered:
            return "exact-run-filter"
        if name_prefix and (name == name_prefix or name.startswith(f"{name_prefix}-")):
            return "exact-run-name-prefix"
        return None

    def _adopt_orphans(
        self,
        run_tag: str | None,
        name_prefix: str | None,
        *,
        discovery_errors: list[str] | None = None,
        inventory_state: dict[str, Any] | None = None,
    ) -> int:
        """Journal exact-run resources that escaped the create/track window.

        Exact-run cleanup must prove that every managed resource family was
        inventoried.  A successful filtered query is not sufficient by itself:
        resources created before their ownership metadata settled may only be
        identifiable by the run's exact name prefix.  Therefore each family is
        also listed without a filter and the two result sets are merged.

        Callers performing a bounded final sweep can supply ``discovery_errors``
        to collect per-family uncertainty while still adopting every resource
        that was visible.  Direct callers retain fail-closed behavior.
        """
        if not run_tag and not name_prefix:
            return 0
        known = {
            (item.resource_type, item.id): item for item in self.reporter.resources
        }
        adopted = 0
        local_errors: list[str] = []
        visible: list[dict[str, str]] = []
        specs: list[tuple[str, list[str] | None, list[str]]] = [
            (
                "floating_ip",
                ["floating", "ip", "list", "--tags", str(run_tag)] if run_tag else None,
                ["floating", "ip", "list", "--long"],
            ),
            ("server", None, ["server", "list"]),
            (
                "router",
                ["router", "list", "--tags", str(run_tag)] if run_tag else None,
                ["router", "list"],
            ),
            (
                "port",
                ["port", "list", "--tags", str(run_tag)] if run_tag else None,
                ["port", "list"],
            ),
            (
                "subnet",
                ["subnet", "list", "--tags", str(run_tag)] if run_tag else None,
                ["subnet", "list"],
            ),
            (
                "network",
                ["network", "list", "--tags", str(run_tag)] if run_tag else None,
                ["network", "list"],
            ),
            (
                "security_group",
                ["security", "group", "list", "--tags", str(run_tag)]
                if run_tag
                else None,
                ["security", "group", "list"],
            ),
            (
                "volume",
                ["volume", "list", "--property", f"neutron_flux_run={run_tag}"]
                if run_tag
                else None,
                ["volume", "list"],
            ),
            ("server_group", None, ["server", "group", "list"]),
            ("keypair", None, ["keypair", "list"]),
        ]

        def read_family(
            spec: tuple[str, list[str] | None, list[str]],
        ) -> tuple[list[tuple[dict[str, Any], bool]], list[str]]:
            resource_type, filtered_args, fallback_args = spec
            family_errors: list[str] = []
            rows: list[tuple[dict[str, Any], bool]] = []
            if filtered_args:
                try:
                    queried = self.osc.json(
                        *filtered_args,
                        check=False,
                        timeout=min(60, self.config.resource_timeout),
                    )
                except RunCancelledError:
                    raise
                except (SuiteError, OSError, TypeError, ValueError):
                    # The unfiltered inventory below is authoritative for this
                    # resource family, so a filtered-query failure alone does
                    # not make final verification uncertain.
                    queried = None
                if isinstance(queried, list):
                    if any(not isinstance(row, dict) for row in queried):
                        family_errors.append(
                            f"{resource_type} filtered inventory contained "
                            "a non-object row"
                        )
                    rows.extend((row, True) for row in queried if isinstance(row, dict))
            fallback_failed = False
            try:
                queried = self.osc.json(
                    *fallback_args,
                    check=False,
                    timeout=min(60, self.config.resource_timeout),
                )
            except RunCancelledError:
                raise
            except (SuiteError, OSError, TypeError, ValueError) as exc:
                family_errors.append(
                    f"{resource_type} inventory failed: "
                    f"{str(exc).strip() or type(exc).__name__}"
                )
                queried = None
                fallback_failed = True
            if isinstance(queried, list):
                if any(not isinstance(row, dict) for row in queried):
                    family_errors.append(
                        f"{resource_type} inventory contained a non-object row"
                    )
                rows.extend((row, False) for row in queried if isinstance(row, dict))
            elif not fallback_failed:
                family_errors.append(
                    f"{resource_type} inventory returned no authoritative list"
                )

            return rows, family_errors

        # Fetch independent inventories concurrently; ownership decisions and
        # journal updates stay in deterministic resource-family order below.
        inventories = bounded_map(read_family, specs, workers=READ_WORKERS)
        server_ids = list(
            dict.fromkeys(
                str(pick(row, "id"))
                for (resource_type, _, _), (rows, _) in zip(
                    specs, inventories, strict=True
                )
                if resource_type == "server"
                for row, _ in rows
                if optional_text(pick(row, "id"))
                and ("server", str(pick(row, "id"))) not in known
                and not self._mapping(
                    pick(row, "properties", "metadata", "property", default={})
                )
            )
        )

        def read_server(identity: str) -> tuple[Any, Exception | None]:
            try:
                return self.osc.json(
                    "server",
                    "show",
                    identity,
                    check=False,
                    timeout=min(60, self.config.resource_timeout),
                ), None
            except RunCancelledError:
                raise
            except (SuiteError, OSError, TypeError, ValueError) as exc:
                return None, exc

        server_reads = dict(
            zip(
                server_ids,
                bounded_map(read_server, server_ids, workers=READ_WORKERS),
                strict=True,
            )
        )
        for (resource_type, _, _), (rows, family_errors) in zip(
            specs, inventories, strict=True
        ):
            local_errors.extend(family_errors)
            seen_rows: set[tuple[str, str]] = set()
            for row, filtered in rows:
                name = str(
                    pick(
                        row,
                        "name",
                        "floating_ip_address",
                        "floating ip address",
                        default="",
                    )
                    or ""
                )
                resource_id = (
                    name
                    if resource_type == "keypair"
                    else str(pick(row, "id", default="") or "")
                )
                if not resource_id:
                    tags = {
                        str(value)
                        for value in list_value(pick(row, "tags", default=[]))
                    }
                    exact_name = bool(
                        name_prefix
                        and (name == name_prefix or name.startswith(f"{name_prefix}-"))
                    )
                    if (
                        resource_type == "floating_ip"
                        or filtered
                        or exact_name
                        or (run_tag and run_tag in tags)
                    ):
                        local_errors.append(
                            f"{resource_type} exact-run inventory row has no usable ID"
                        )
                    continue
                row_identity = (resource_type, resource_id)
                if row_identity in seen_rows:
                    continue
                seen_rows.add(row_identity)
                if row_identity in known:
                    record = known[row_identity]
                    if record.delete_status in {"deleted", "already-absent"}:
                        self.tracker.mark_present(record)
                    visible.append(
                        {
                            "resource_type": resource_type,
                            "id": resource_id,
                            "name": name or resource_id,
                        }
                    )
                    continue
                try:
                    server_detail = _UNREAD_SERVER_DETAIL
                    if resource_type == "server" and resource_id in server_reads:
                        server_detail, read_error = server_reads[resource_id]
                        if read_error is not None:
                            raise read_error
                    evidence = self._exact_orphan_evidence(
                        resource_type,
                        row,
                        resource_id=resource_id,
                        name=name,
                        run_tag=run_tag,
                        name_prefix=name_prefix,
                        filtered=filtered,
                        server_detail=server_detail,
                    )
                except RunCancelledError:
                    raise
                except (SuiteError, OSError, TypeError, ValueError) as exc:
                    local_errors.append(
                        f"{resource_type} {resource_id} ownership verification "
                        f"failed: {str(exc).strip() or type(exc).__name__}"
                    )
                    continue
                if evidence is None:
                    if resource_type == "floating_ip":
                        # FIPs have no generated name prefix. Without both
                        # ownership fields, a skipped row could hide this run's
                        # description or tag, even when the other field is empty.
                        fields = {str(key).lower(): value for key, value in row.items()}
                        description = fields.get("description")
                        raw_tags = fields.get("tags")
                        description_visible = "description" in fields and (
                            description is None or isinstance(description, str)
                        )
                        tags_visible = "tags" in fields and (
                            raw_tags is None
                            or isinstance(raw_tags, str)
                            or (
                                isinstance(raw_tags, (list, tuple))
                                and all(isinstance(tag, str) for tag in raw_tags)
                            )
                        )
                        if not description_visible or not tags_visible:
                            local_errors.append(
                                f"floating_ip {resource_id} inventory lacks usable "
                                "description or tags for ownership verification"
                            )
                    continue
                visible.append(
                    {
                        "resource_type": resource_type,
                        "id": resource_id,
                        "name": name or resource_id,
                    }
                )
                record = self.tracker.add(
                    resource_type,
                    resource_id,
                    name or resource_id,
                    orphan_adopted=True,
                    discovered_by=evidence,
                )
                known[row_identity] = record
                adopted += 1
                self.logger.log(
                    f"Adopted cleanup orphan {resource_type} {name or resource_id} ({resource_id})",
                    "WARNING",
                )
        local_errors = list(dict.fromkeys(local_errors))
        if discovery_errors is not None:
            discovery_errors.extend(local_errors)
        elif local_errors:
            raise SuiteError(
                "Exact-run cleanup inventory could not be verified: "
                + " | ".join(local_errors)
            )
        if inventory_state is not None:
            inventory_state["visible_resources"] = visible
            inventory_state["visible_count"] = len(visible)
        return adopted
