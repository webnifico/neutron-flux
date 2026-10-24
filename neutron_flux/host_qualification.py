from __future__ import annotations

import dataclasses
import hashlib
import itertools
import json
from collections import defaultdict
from typing import Any

from .aggregate_policy import resolve_aggregate_policy
from .config import Config
from .errors import CommandError, CommandTimeoutError, SuiteError
from .log import Logger
from .models import (
    Discovery,
    HostQualificationHost,
    HostQualificationPair,
    HostQualificationPlan,
    Plan,
)
from .openstack import OpenStack
from .utils import iso_utc, list_value, normalized_map, pick, safe_name


def _host_aliases(host: str) -> set[str]:
    """Return conservative aliases without inventing a physical identity."""
    text = host.strip()
    short = text.split(".", 1)[0]
    return {item for item in {text, text.casefold(), short, short.casefold()} if item}


def _pair_id(source: str, destination: str) -> str:
    raw = f"{source}\x1f{destination}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:10]
    readable = safe_name(f"{source}-to-{destination}", 52)
    return f"HQ-{readable}-{digest}".upper()


class HostQualificationPlanner:
    """Resolve an immutable host snapshot and its exact pair matrix.

    This class is intentionally read-only. It queries Nova and Cinder inventory
    but never changes service state, aggregate membership, or placement.
    """

    def __init__(
        self,
        config: Config,
        discovery: Discovery,
        plan: Plan,
        osc: OpenStack,
        logger: Logger,
    ):
        self.config = config
        self.discovery = discovery
        self.plan = plan
        self.osc = osc
        self.logger = logger
        self.aggregate_inventory_state = "unknown"
        self.aggregate_inventory_count: int | None = None

    def build(self) -> HostQualificationPlan | None:
        if not self.config.host_qualification_enabled:
            return None
        self.logger.section("Resolving targeted compute-host qualification scope")
        services = self._service_inventory()
        aliases = self._alias_index(services)
        aggregates, aggregate_warnings = self._aggregate_inventory(services, aliases)
        aggregate_policy = resolve_aggregate_policy(
            self.config.require_shared_compute_aggregate,
            self.aggregate_inventory_state,
            self.aggregate_inventory_count,
        )
        requested_aggregate_ids, requested_aggregate_names, aggregate_hosts = (
            self._resolve_aggregates(aggregates)
        )

        requested_names = list(self.config.target_hosts)
        for source, destination in self.config.target_host_pairs:
            requested_names.extend((source, destination))
        canonical_requested: list[str] = []
        unknown_requested: list[str] = []
        for value in requested_names:
            resolved = self._resolve_host(value, services, aliases)
            if resolved is None:
                unknown_requested.append(value)
            elif resolved not in canonical_requested:
                canonical_requested.append(resolved)
        selected_hosts = list(
            dict.fromkeys([*canonical_requested, *sorted(aggregate_hosts)])
        )

        cinder_zones = self._cinder_zones()
        host_rows: list[HostQualificationHost] = []
        for host in selected_hosts:
            row = services[host]
            blockers = list(row["blockers"])
            if self.config.storage == "volume" and cinder_zones == set():
                blockers.append("Cinder exposes no available volume AZs")
            zone = row["availability_zone"]
            blockers.extend(self._network_blockers(host, zone))
            host_rows.append(
                HostQualificationHost(
                    host=host,
                    availability_zone=zone,
                    enabled=bool(row["enabled"]),
                    up=bool(row["up"]),
                    aggregate_ids=sorted(row["aggregate_ids"]),
                    aggregate_names=sorted(row["aggregate_names"]),
                    service_ids=list(row["service_ids"]),
                    aliases=sorted(row["aliases"]),
                    blockers=list(dict.fromkeys(blockers)),
                )
            )
        for value in unknown_requested:
            host_rows.append(
                HostQualificationHost(
                    host=value,
                    availability_zone=None,
                    enabled=False,
                    up=False,
                    aliases=[value],
                    blockers=[
                        "No nova-compute service matched this exact host or a unique alias"
                    ],
                )
            )

        by_host = {row.host: row for row in host_rows}
        pair_names = self._requested_pairs(
            canonical_requested,
            unknown_requested,
            aggregate_hosts,
            services,
            aliases,
        )
        if not pair_names:
            selected = list(
                dict.fromkeys(
                    [*canonical_requested, *unknown_requested, *sorted(aggregate_hosts)]
                )
            )
            detail = (
                f"resolved hosts: {', '.join(selected)}"
                if selected
                else "no hosts resolved"
            )
            raise SuiteError(
                "Target-host qualification produced no executable host pairs "
                f"({detail}). Select a resolvable host with --target-hosts, "
                "an aggregate containing available hosts, or an explicit "
                "HOST:HOST entry with --target-host-pairs."
            )

        pairs: list[HostQualificationPair] = []
        for source, destination in pair_names:
            source_row = by_host[source]
            destination_row = by_host[destination]
            blockers = [
                *[f"{source}: {item}" for item in source_row.blockers],
                *[f"{destination}: {item}" for item in destination_row.blockers],
            ]
            same_host = source == destination
            same_az = bool(
                source_row.availability_zone
                and source_row.availability_zone == destination_row.availability_zone
            )
            pairs.append(
                HostQualificationPair(
                    pair_id=_pair_id(source, destination),
                    source_host=source,
                    destination_host=destination,
                    source_availability_zone=source_row.availability_zone,
                    destination_availability_zone=destination_row.availability_zone,
                    same_host=same_host,
                    same_availability_zone=same_az,
                    execution_mode=(
                        "exact-same-host"
                        if same_host
                        else "exact-same-az"
                        if same_az
                        else "independent-cross-az"
                    ),
                    status=("BLOCKED_BY_PREREQUISITE" if blockers else "PLANNED"),
                    blockers=list(dict.fromkeys(blockers)),
                )
            )

        strategy = self.config.qualification_strategy
        if strategy == "auto":
            exact_pair_migrations = bool(
                self.config.target_host_pairs
                and self.config.qualification_profile in {"full", "performance"}
                and self.config.compute_host_connectivity_enabled
            )
            if exact_pair_migrations:
                strategy = "rolling"
            else:
                strategy = "stable" if len(host_rows) <= 4 else "rolling"
        eligible_hosts = sum(1 for row in host_rows if row.eligible)
        eligible_pairs = sum(1 for pair in pairs if pair.eligible)
        base_specs = self._base_host_sensitive_specs()
        cycles = self.config.qualification_cycles
        peak_endpoints = (
            eligible_hosts * 2 if strategy == "stable" else min(2, eligible_pairs * 2)
        )
        endpoint_boots = (
            eligible_hosts * 2 if strategy == "stable" else eligible_pairs * cycles * 2
        )
        performance_seconds = (
            int(self.plan.estimated.get("performance_estimated_seconds", 0))
            if self.config.performance_enabled
            and self.config.qualification_profile in {"full", "performance"}
            else 0
        )
        provider_topologies = len(
            {spec.dependencies[0] for spec in base_specs if spec.dependencies}
        )
        targeted_migrations = (
            sum(
                1
                for pair in pairs
                if pair.eligible
                and pair.same_availability_zone
                and not pair.same_host
                and not aggregate_policy.discovery_blocked
                and (
                    not aggregate_policy.requires_shared
                    or set(by_host[pair.source_host].aggregate_ids).intersection(
                        by_host[pair.destination_host].aggregate_ids
                    )
                )
            )
            * cycles
            * provider_topologies
            if strategy == "rolling"
            and self.config.target_host_pairs
            and self.config.qualification_profile in {"full", "performance"}
            and self.config.compute_host_connectivity_enabled
            else 0
        )
        estimates = {
            "selected_hosts": len(host_rows),
            "eligible_hosts": eligible_hosts,
            "pair_scenarios": len(pairs),
            "eligible_pairs": eligible_pairs,
            "blocked_pairs": len(pairs) - eligible_pairs,
            "measurement_cycles": cycles,
            "host_sensitive_tests_per_pair": len(base_specs),
            "planned_host_sensitive_results": len(base_specs) * len(pairs) * cycles,
            "peak_endpoint_instances": peak_endpoints,
            "endpoint_vm_boots": endpoint_boots * provider_topologies,
            "estimated_performance_seconds": performance_seconds
            * eligible_pairs
            * cycles,
            "targeted_migrations": targeted_migrations,
            "cross_az_placements": sum(
                1 for pair in pairs if pair.eligible and not pair.same_availability_zone
            ),
        }
        fingerprint = self._fingerprint(
            host_rows,
            pairs,
            requested_aggregate_ids,
            dataclasses.asdict(aggregate_policy)
            if aggregate_policy.requested == "auto"
            else None,
        )
        warnings = list(aggregate_warnings)
        if unknown_requested:
            warnings.append(
                "Unknown requested hosts are retained as blocked prerequisite "
                "rows instead of being silently omitted"
            )
        if cinder_zones is None and self.config.storage == "volume":
            warnings.append(
                "Cinder availability-zone inventory was unavailable; exact "
                "volume placement will be verified during boot"
            )
        if (
            self.config.qualification_strategy == "stable"
            and self.config.target_host_pairs
            and self.config.qualification_profile in {"full", "performance"}
            and self.config.compute_host_connectivity_enabled
        ):
            warnings.append(
                "Explicit stable strategy keeps exact host-pair connectivity and "
                "performance coverage but does not migrate those endpoints; use "
                "auto or rolling for exact pair migration coverage"
            )

        result = HostQualificationPlan(
            enabled=True,
            generated_at=iso_utc(),
            inventory_fingerprint=fingerprint,
            strategy=strategy,
            profile=self.config.qualification_profile,
            cycles=cycles,
            include_same_host=self.config.include_same_host,
            requested_hosts=list(self.config.target_hosts),
            requested_aggregates=list(self.config.target_aggregates),
            requested_pairs=[
                [source, destination]
                for source, destination in self.config.target_host_pairs
            ],
            resolved_aggregate_ids=requested_aggregate_ids,
            resolved_aggregate_names=requested_aggregate_names,
            hosts=host_rows,
            pairs=pairs,
            warnings=warnings,
            estimates=estimates,
            aggregate_policy=dataclasses.asdict(aggregate_policy),
        )
        self._log_plan(result)
        return result

    def _service_inventory(self) -> dict[str, dict[str, Any]]:
        try:
            rows = self.osc.json(
                "compute",
                "service",
                "list",
                "--service",
                "nova-compute",
                timeout=min(60, self.config.resource_timeout),
            )
        except (CommandError, CommandTimeoutError) as exc:
            raise SuiteError(
                f"Nova compute-service inventory is unavailable: {exc}"
            ) from exc
        if not isinstance(rows, list):
            raise SuiteError("Nova compute-service inventory did not return a list")
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for raw in rows:
            if not isinstance(raw, dict):
                continue
            host = str(pick(raw, "host", default="") or "").strip()
            if host:
                grouped[host].append(raw)
        inventory: dict[str, dict[str, Any]] = {}
        for host, records in grouped.items():
            statuses = {
                str(pick(record, "status", default="") or "").strip().lower()
                for record in records
            }
            states = {
                str(pick(record, "state", default="") or "").strip().lower()
                for record in records
            }
            zones = {
                str(pick(record, "zone", "availability_zone", default="") or "").strip()
                for record in records
            }
            zones.discard("")
            blockers: list[str] = []
            if len(records) != 1:
                blockers.append(
                    f"Nova returned {len(records)} nova-compute service rows for the canonical host"
                )
            if statuses != {"enabled"}:
                blockers.append("nova-compute service is not unambiguously enabled")
            if states != {"up"}:
                blockers.append("nova-compute service is not unambiguously up")
            if len(zones) != 1:
                blockers.append("Nova did not expose one unambiguous availability zone")
            aliases = _host_aliases(host)
            service_ids = [
                str(
                    pick(
                        record,
                        "id",
                        default=f"{host}:{index}",
                    )
                    or f"{host}:{index}"
                )
                for index, record in enumerate(records, start=1)
            ]
            inventory[host] = {
                "host": host,
                "availability_zone": next(iter(zones), None),
                "enabled": statuses == {"enabled"} and len(records) == 1,
                "up": states == {"up"} and len(records) == 1,
                "service_ids": service_ids,
                "aliases": aliases,
                "records": records,
                "aggregate_ids": set(),
                "aggregate_names": set(),
                "blockers": blockers,
            }
        if not inventory:
            raise SuiteError("No nova-compute service hosts were discovered")
        return inventory

    @staticmethod
    def _alias_index(
        services: dict[str, dict[str, Any]],
    ) -> dict[str, set[str]]:
        aliases: dict[str, set[str]] = defaultdict(set)
        for host, row in services.items():
            for alias in row["aliases"]:
                aliases[alias.casefold()].add(host)
        return aliases

    def _aggregate_inventory(
        self,
        services: dict[str, dict[str, Any]],
        aliases: dict[str, set[str]],
    ) -> tuple[list[dict[str, Any]], list[str]]:
        warnings: list[str] = []
        self.aggregate_inventory_state = "unavailable"
        self.aggregate_inventory_count = None
        try:
            rows = self.osc.json(
                "aggregate",
                "list",
                check=False,
                timeout=min(60, self.config.resource_timeout),
            )
        except (CommandError, CommandTimeoutError) as exc:
            if self.config.target_aggregates:
                raise SuiteError(
                    f"Nova aggregate inventory is unavailable: {exc}"
                ) from exc
            return [], [f"Nova aggregate inventory is unavailable: {exc}"]
        if not isinstance(rows, list):
            if self.config.target_aggregates:
                raise SuiteError("Nova aggregate inventory did not return a list")
            return [], ["Nova aggregate inventory was not available"]
        self.aggregate_inventory_state = "complete"
        self.aggregate_inventory_count = len(rows)
        output: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict) or not pick(row, "id"):
                self.aggregate_inventory_state = "partial"
                warnings.append(
                    "Nova aggregate list contained an invalid row or missing ID"
                )
                continue
            aggregate_id = str(pick(row, "id")).strip()
            try:
                detail = self.osc.json(
                    "aggregate",
                    "show",
                    aggregate_id,
                    check=False,
                    timeout=min(60, self.config.resource_timeout),
                )
            except (CommandError, CommandTimeoutError) as exc:
                detail = None
                warnings.append(f"Aggregate {aggregate_id}: {exc}")
            if not isinstance(detail, dict):
                self.aggregate_inventory_state = "partial"
                warnings.append(f"Aggregate {aggregate_id} details were unavailable")
                continue
            if not isinstance(pick(detail, "hosts"), (list, tuple, str)):
                self.aggregate_inventory_state = "partial"
                warnings.append(
                    f"Aggregate {aggregate_id} host membership was unavailable"
                )
                continue
            name = str(
                pick(detail, "name", default=pick(row, "name", default=aggregate_id))
                or aggregate_id
            ).strip()
            members: list[str] = []
            for value in list_value(pick(detail, "hosts", default=[])):
                resolved = self._resolve_host(
                    str(value), services, aliases, allow_ambiguous=False
                )
                if resolved and resolved not in members:
                    members.append(resolved)
                elif resolved is None:
                    warnings.append(
                        f"Aggregate {name} contains host {value!s} with no matching nova-compute service"
                    )
            for host in members:
                services[host]["aggregate_ids"].add(aggregate_id)
                services[host]["aggregate_names"].add(name)
            output.append(
                {
                    "id": aggregate_id,
                    "name": name,
                    "hosts": members,
                }
            )
        return output, warnings

    def _resolve_aggregates(
        self, aggregates: list[dict[str, Any]]
    ) -> tuple[list[str], list[str], list[str]]:
        ids: list[str] = []
        names: list[str] = []
        hosts: list[str] = []
        for selector in self.config.target_aggregates:
            exact = [row for row in aggregates if selector in {row["id"], row["name"]}]
            folded = [
                row
                for row in aggregates
                if selector.casefold() in {row["id"].casefold(), row["name"].casefold()}
            ]
            matches = exact or folded
            if len(matches) != 1:
                if len(matches) > 1:
                    raise SuiteError(f"Aggregate selector {selector!r} is ambiguous")
                raise SuiteError(
                    f"Aggregate selector {selector!r} did not match a visible Nova aggregate"
                )
            row = matches[0]
            if row["id"] not in ids:
                ids.append(row["id"])
                names.append(row["name"])
            for host in row["hosts"]:
                if host not in hosts:
                    hosts.append(host)
        return ids, names, hosts

    def _resolve_host(
        self,
        selector: str,
        services: dict[str, dict[str, Any]],
        aliases: dict[str, set[str]],
        *,
        allow_ambiguous: bool = True,
    ) -> str | None:
        text = selector.strip()
        if text in services:
            return text
        matches = aliases.get(text.casefold(), set())
        if len(matches) == 1:
            return next(iter(matches))
        if len(matches) > 1 and allow_ambiguous:
            raise SuiteError(
                f"Compute-host alias {selector!r} is ambiguous: "
                + ", ".join(sorted(matches))
            )
        return None

    def _requested_pairs(
        self,
        canonical_requested: list[str],
        unknown_requested: list[str],
        aggregate_hosts: list[str],
        services: dict[str, dict[str, Any]],
        aliases: dict[str, set[str]],
    ) -> list[tuple[str, str]]:
        if self.config.target_host_pairs:
            output: list[tuple[str, str]] = []
            for source, destination in self.config.target_host_pairs:
                resolved_source = (
                    self._resolve_host(source, services, aliases) or source
                )
                resolved_destination = (
                    self._resolve_host(destination, services, aliases) or destination
                )
                pair = (resolved_source, resolved_destination)
                reverse = (resolved_destination, resolved_source)
                if pair not in output and reverse not in output:
                    output.append(pair)
            return output
        selected = list(
            dict.fromkeys(
                [*canonical_requested, *unknown_requested, *sorted(aggregate_hosts)]
            )
        )
        output = list(itertools.combinations(selected, 2))
        if self.config.include_same_host or len(selected) == 1:
            output.extend((host, host) for host in selected)
        return output

    def _network_blockers(self, host: str, zone: str | None) -> list[str]:
        blockers: list[str] = []
        if not zone:
            return blockers
        for network in self.discovery.networks:
            normalized = normalized_map(network.raw)
            status = str(normalized.get("status") or "").strip().upper()
            if status and status != "ACTIVE":
                blockers.append(
                    f"selected network {network.name} is {status}, not ACTIVE"
                )
            if normalized.get("admin_state_up") is False:
                blockers.append(
                    f"selected network {network.name} has admin_state_up=False"
                )
            # Neutron AZs locate network services, not eligible Nova hosts.
            # Only actual binding/connectivity can prove host network usability.
        return blockers

    def _cinder_zones(self) -> set[str] | None:
        if self.config.storage != "volume":
            return None
        try:
            rows = self.osc.optional_json(
                "availability",
                "zone",
                "list",
                "--volume",
                timeout=min(60, self.config.resource_timeout),
            )
        except CommandError:
            return None
        if not isinstance(rows, list):
            return None
        zones: set[str] = set()
        for row in rows:
            if not isinstance(row, dict):
                continue
            normalized = normalized_map(row)
            zone = str(
                normalized.get("zone_name")
                or normalized.get("name")
                or normalized.get("zone")
                or ""
            ).strip()
            status = (
                str(
                    normalized.get(
                        "zone_status",
                        normalized.get("status", normalized.get("available", "")),
                    )
                )
                .strip()
                .lower()
            )
            if zone and status not in {
                "not available",
                "false",
                "unavailable",
                "down",
                "disabled",
            }:
                zones.add(zone)
        return zones

    def _base_host_sensitive_specs(self) -> list[Any]:
        operations = {"probe", "mtu-scenario"}
        if self.config.qualification_profile == "connectivity":
            operations = {"probe"}
        return [
            spec
            for spec in self.plan.tests
            if spec.operation in operations
            and spec.expectation == "reachable"
            and len(spec.dependencies) == 1
            and self.plan.group(spec.dependencies[0]).kind == "provider"
        ]

    @staticmethod
    def _fingerprint(
        hosts: list[HostQualificationHost],
        pairs: list[HostQualificationPair],
        aggregate_ids: list[str],
        aggregate_policy: dict[str, Any] | None = None,
    ) -> str:
        payload = {
            "hosts": [dataclasses.asdict(row) for row in hosts],
            "pairs": [dataclasses.asdict(row) for row in pairs],
            "aggregates": sorted(aggregate_ids),
        }
        if aggregate_policy is not None:
            payload["aggregate_policy"] = aggregate_policy
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _log_plan(self, plan: HostQualificationPlan) -> None:
        self.logger.log(
            f"Host qualification inventory fingerprint: {plan.inventory_fingerprint}"
        )
        self.logger.log(
            f"Host qualification strategy={plan.strategy}, profile={plan.profile}, "
            f"cycles={plan.cycles}, hosts={len(plan.hosts)}, pairs={len(plan.pairs)}"
        )
        self.logger.log(f"Host qualification aggregate policy: {plan.aggregate_policy}")
        for host in plan.hosts:
            state = "eligible" if host.eligible else "blocked"
            self.logger.log(
                f"Host {host.host}: az={host.availability_zone or 'unknown'}, "
                f"state={state}, aggregates={','.join(host.aggregate_names) or 'none'}"
            )
            for blocker in host.blockers:
                self.logger.log(f"  Host {host.host} blocked: {blocker}", "WARNING")
        for pair in plan.pairs:
            self.logger.log(
                f"Pair {pair.source_host} <-> {pair.destination_host}: "
                f"{pair.execution_mode}, status={pair.status}"
            )
        for key, value in plan.estimates.items():
            self.logger.log(
                f"Estimated host qualification {key.replace('_', ' ')}: {value}"
            )


__all__ = ["HostQualificationPlanner"]
