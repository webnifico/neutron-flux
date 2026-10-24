from __future__ import annotations

import dataclasses
import time
from collections import defaultdict
from typing import Any

# mypy: disable-error-code="attr-defined"
from ..aggregate_policy import AggregatePolicy, resolve_aggregate_policy
from ..errors import (
    CommandError,
    CommandTimeoutError,
    PlacementUnavailableError,
    SuiteError,
)
from ..models import ComputeHostInfo, Endpoint
from ..utils import iso_utc, list_value, pick


class ComputeRuntimeMixin:
    """Compatibility mixin for the compute runtime subsystem."""

    def compute_host_inventory(
        self, *, refresh: bool = False
    ) -> dict[str, ComputeHostInfo]:
        """Return explicit nova-compute health, AZ, and aggregate membership.

        Unknown service health is never treated as healthy. Aggregate inventory
        is tracked as complete, partial, or unavailable so placement reporting
        cannot confuse incomplete API visibility with genuine lack of shared
        aggregate membership.
        """
        if self._compute_host_inventory_cache is not None and not refresh:
            return dict(self._compute_host_inventory_cache)

        self._compute_host_inventory_cache = None
        self._aggregate_inventory_count = None
        self._aggregate_inventory_state = "unknown"
        self._aggregate_inventory_available = False
        self._aggregate_inventory_errors = []
        try:
            services = self.osc.json(
                "compute",
                "service",
                "list",
                "--service",
                "nova-compute",
                timeout=min(60, self.config.resource_timeout),
            )
        except (CommandError, CommandTimeoutError) as exc:
            raise PlacementUnavailableError(
                f"Nova compute-service inventory is unavailable: {exc}"
            ) from exc
        if not isinstance(services, list):
            raise PlacementUnavailableError(
                "Nova compute-service inventory returned no list; host placement cannot be verified"
            )

        grouped_services: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for raw in services:
            if not isinstance(raw, dict):
                continue
            host = str(pick(raw, "host", default="") or "").strip()
            if not host:
                continue
            grouped_services[host].append(raw)

        inventory: dict[str, ComputeHostInfo] = {}
        for host, records in grouped_services.items():
            statuses = {
                str(pick(raw, "status", default="") or "").strip().lower()
                for raw in records
            }
            states = {
                str(pick(raw, "state", default="") or "").strip().lower()
                for raw in records
            }
            zones = {
                str(pick(raw, "zone", "availability_zone", default="") or "").strip()
                for raw in records
            }
            zones.discard("")
            blockers: list[str] = []
            if len(records) != 1:
                blockers.append(
                    f"Nova returned {len(records)} nova-compute service rows "
                    f"for canonical host {host}"
                )
            if len(zones) != 1:
                blockers.append(
                    f"Nova did not expose one unambiguous availability zone for {host}"
                )
            short = host.split(".", 1)[0]
            inventory[host] = ComputeHostInfo(
                host=host,
                availability_zone=next(iter(zones), None),
                enabled=len(records) == 1 and statuses == {"enabled"},
                up=len(records) == 1 and states == {"up"},
                service_ids=[
                    str(pick(raw, "id", default=f"{host}:{index}") or f"{host}:{index}")
                    for index, raw in enumerate(records, start=1)
                ],
                service_records=list(records),
                aliases={host, host.casefold(), short, short.casefold()},
                blockers=blockers,
            )

        self._aggregate_inventory_errors = []
        try:
            aggregate_rows = self.osc.json(
                "aggregate",
                "list",
                check=False,
                timeout=min(60, self.config.resource_timeout),
            )
        except (CommandError, CommandTimeoutError) as exc:
            aggregate_rows = None
            self._aggregate_inventory_state = "unavailable"
            self._aggregate_inventory_errors.append(str(exc))

        if not isinstance(aggregate_rows, list):
            if self._aggregate_inventory_state != "unavailable":
                self._aggregate_inventory_state = "unavailable"
                self._aggregate_inventory_errors.append(
                    "Nova aggregate list is unsupported or returned no list"
                )
        else:
            self._aggregate_inventory_count = len(aggregate_rows)
            self._aggregate_inventory_state = "complete"
            for row in aggregate_rows:
                if not isinstance(row, dict):
                    self._aggregate_inventory_state = "partial"
                    self._aggregate_inventory_errors.append(
                        "Nova aggregate list contained a non-object row"
                    )
                    continue
                aggregate_id = str(pick(row, "id", default="") or "").strip()
                if not aggregate_id:
                    self._aggregate_inventory_state = "partial"
                    self._aggregate_inventory_errors.append(
                        "Nova aggregate list contained an entry without an ID"
                    )
                    continue
                try:
                    detail = self.osc.json(
                        "aggregate",
                        "show",
                        aggregate_id,
                        check=False,
                        timeout=min(60, self.config.resource_timeout),
                    )
                except (CommandError, CommandTimeoutError) as exc:
                    self._aggregate_inventory_state = "partial"
                    self._aggregate_inventory_errors.append(
                        f"aggregate {aggregate_id}: {exc}"
                    )
                    continue
                if not isinstance(detail, dict):
                    self._aggregate_inventory_state = "partial"
                    self._aggregate_inventory_errors.append(
                        f"aggregate {aggregate_id}: details unavailable"
                    )
                    continue
                if not isinstance(pick(detail, "hosts"), (list, tuple, str)):
                    self._aggregate_inventory_state = "partial"
                    self._aggregate_inventory_errors.append(
                        f"aggregate {aggregate_id}: host membership unavailable"
                    )
                    continue
                aggregate_name = str(
                    pick(
                        detail, "name", default=pick(row, "name", default=aggregate_id)
                    )
                    or aggregate_id
                )
                for host_value in list_value(pick(detail, "hosts", default=[])):
                    host = str(host_value).strip()
                    if host not in inventory:
                        continue
                    inventory[host].aggregate_ids.add(aggregate_id)
                    inventory[host].aggregate_names.add(aggregate_name)

        self._aggregate_inventory_available = (
            self._aggregate_inventory_state == "complete"
        )
        self._compute_host_inventory_cache = inventory
        return dict(inventory)

    def compute_aggregate_policy(self) -> AggregatePolicy:
        return resolve_aggregate_policy(
            self.config.require_shared_compute_aggregate,
            getattr(
                self,
                "_aggregate_inventory_state",
                "complete"
                if getattr(self, "_aggregate_inventory_available", False)
                else "unavailable",
            ),
            getattr(self, "_aggregate_inventory_count", None),
        )

    def aggregate_inventory_reason(self) -> str:
        errors = getattr(self, "_aggregate_inventory_errors", [])
        state = getattr(
            self,
            "_aggregate_inventory_state",
            "complete"
            if getattr(self, "_aggregate_inventory_available", False)
            else "unavailable",
        )
        if state == "complete":
            return "host aggregate inventory is complete"
        detail = errors[0] if errors else "no additional detail"
        return f"host aggregate inventory is {state}: {detail}"

    def select_compute_migration_targets(
        self,
        endpoint: Endpoint,
        peer: Endpoint,
        *,
        desired_relation: str,
    ) -> tuple[list[ComputeHostInfo], str]:
        """Return ordered same-AZ migration targets allowed by aggregate policy.

        ``desired_relation`` is ``same`` or ``different`` relative to ``peer``.
        Cross-AZ migration is deliberately never attempted, even when a generic
        host aggregate spans multiple availability zones. For ``different``, all
        eligible targets are returned so the executor can rotate through hosts
        before retrying a destination. For ``same``, the peer host is the only
        target that can create the requested relationship for this endpoint.
        """
        if desired_relation not in {"same", "different"}:
            raise ValueError(f"Unknown desired compute relation: {desired_relation}")
        if not endpoint.host or not peer.host:
            return (
                [],
                "Nova did not expose the current compute host for both endpoints",
            )

        try:
            inventory = self.compute_host_inventory(refresh=True)
        except PlacementUnavailableError as exc:
            return [], str(exc)
        source = inventory.get(endpoint.host)
        peer_host = inventory.get(peer.host)
        reporter = getattr(self, "reporter", None)
        if reporter is not None:
            reporter.event(
                "migration-candidate-inventory",
                "Fresh compute-service and aggregate evidence before destination selection; no migration submitted",
                captured_at=iso_utc(),
                source_host=endpoint.host,
                availability_zone=endpoint.availability_zone,
                hosts=[
                    {
                        "host": item.host,
                        "availability_zone": item.availability_zone,
                        "enabled": item.enabled,
                        "up": item.up,
                        "aggregate_ids": sorted(item.aggregate_ids),
                        "service_records": item.service_records,
                        "blockers": item.blockers,
                    }
                    for item in inventory.values()
                    if item.availability_zone in {endpoint.availability_zone, None}
                    or item.host == endpoint.host
                ],
            )
        if source is None or peer_host is None:
            return (
                [],
                "One or both current compute hosts are absent from nova-compute service inventory",
            )
        if not source.enabled or not source.up:
            return [], f"Current compute host {source.host} is not enabled and up"

        source_az = source.availability_zone
        peer_az = peer.availability_zone or peer_host.availability_zone
        if not source_az:
            return [], f"Availability zone for current host {source.host} is unknown"
        if endpoint.availability_zone and endpoint.availability_zone != source_az:
            return [], (
                f"Current host {source.host} availability zone changed or disagrees "
                f"with endpoint evidence ({endpoint.availability_zone} -> {source_az})"
            )

        policy = self.compute_aggregate_policy()
        reporter = getattr(self, "reporter", None)
        if reporter is not None:
            reporter.event(
                "migration-aggregate-policy",
                f"Migration aggregate policy: {policy.requested} -> {policy.resolution}",
                **dataclasses.asdict(policy),
            )

        def eligible(target: ComputeHostInfo) -> tuple[bool, str]:
            if not target.enabled or not target.up:
                return False, f"target host {target.host} is not enabled and up"
            target_az = target.availability_zone
            if not target_az:
                return (
                    False,
                    f"availability zone for target host {target.host} is unknown",
                )
            if target_az != source_az:
                return (
                    False,
                    f"target host {target.host} is in availability zone {target_az}, not {source_az}",
                )
            if policy.requires_shared:
                if policy.discovery_blocked:
                    return False, self.aggregate_inventory_reason()
                shared = source.aggregate_ids.intersection(target.aggregate_ids)
                if not shared:
                    return (
                        False,
                        f"source host {source.host} and target host {target.host} share no host aggregate",
                    )
            return True, "eligible"

        if desired_relation == "same":
            if endpoint.host == peer.host:
                return [], "Endpoints are already on the same compute host"
            if peer_az and peer_az != source_az:
                return (
                    [],
                    f"same-host placement would require crossing availability zones ({source_az} -> {peer_az}), which the suite will not attempt",
                )
            valid, reason = eligible(peer_host)
            return ([peer_host], "eligible") if valid else ([], reason)

        candidates: list[ComputeHostInfo] = []
        rejected: list[str] = []
        evaluations = []
        excluded_other_zones = 0
        for candidate in sorted(inventory.values(), key=lambda item: item.host):
            if candidate.host == endpoint.host:
                continue
            if candidate.availability_zone and candidate.availability_zone != source_az:
                excluded_other_zones += 1
                continue
            valid, reason = eligible(candidate)
            evaluations.append(
                {"host": candidate.host, "eligible": valid, "reason": reason}
            )
            if valid:
                candidates.append(candidate)
            else:
                rejected.append(reason)
        if reporter is not None:
            reporter.event(
                "migration-candidate-selection",
                "Same-AZ migration destination eligibility",
                availability_zone=source_az,
                candidates=evaluations,
                excluded_other_zones=excluded_other_zones,
                migration_submitted=False,
            )
        if not candidates:
            suffix = (
                "; rejected candidates: " + "; ".join(rejected)
                if rejected
                else "; no other hosts were visible in this availability zone"
            )
            return (
                [],
                f"No second enabled compute host in availability zone {source_az} satisfies migration policy {policy.resolution}{suffix}. No migration was submitted",
            )
        # Prefer a host other than the peer host when possible. When both VMs
        # currently share a host, every valid candidate is necessarily different.
        candidates.sort(key=lambda item: (item.host == peer.host, item.host))
        return candidates, "eligible"

    def select_compute_migration_target(
        self,
        endpoint: Endpoint,
        peer: Endpoint,
        *,
        desired_relation: str,
    ) -> tuple[ComputeHostInfo | None, str]:
        """Compatibility wrapper returning the first ordered target."""
        targets, reason = self.select_compute_migration_targets(
            endpoint,
            peer,
            desired_relation=desired_relation,
        )
        return (targets[0], reason) if targets else (None, reason)

    def _json_with_transient_retry(
        self,
        *args: str,
        check: bool = False,
        timeout: int | None = None,
        context: str,
    ) -> Any:
        """Read structured OpenStack state with bounded transient retries."""
        budget = max(1, int(timeout or min(60, self.config.resource_timeout)))
        deadline = time.monotonic() + budget
        last_error: BaseException | None = None
        while time.monotonic() < deadline:
            remaining = max(1, int(deadline - time.monotonic()))
            try:
                return self.osc.json(
                    *args,
                    check=check,
                    timeout=min(30, remaining),
                )
            except (CommandError, CommandTimeoutError) as exc:
                if not self.osc.is_transient_exception(exc):
                    raise
                last_error = exc
                self.logger.log(
                    f"Transient OpenStack error while {context}: {exc}; retrying",
                    "WARNING",
                )
                time.sleep(min(2, max(0.1, deadline - time.monotonic())))
        raise SuiteError(
            f"Timed out while {context}"
            + (f": last error={last_error}" if last_error else "")
        )
