from __future__ import annotations

import dataclasses
import shutil
from collections import defaultdict
from typing import Any

from .aggregate_policy import resolve_aggregate_policy
from .az_policy import (
    discover_neutron_zones,
    select_neutron_zone,
    select_volume_zone,
    validate_delegated_volume_zones,
)
from .config import Config
from .errors import PlacementUnavailableError, SuiteError
from .models import (
    ComputeHostInfo,
    Discovery,
    Plan,
    ZoneCapability,
    ZoneExecutionPlan,
)
from .openstack import OpenStack
from .reporting import Reporter, ResourceTracker
from .resources import LaunchSelection, ResourceBuilder
from .utils import list_value, normalized_map, optional_text


def _string_list(value: Any) -> list[str]:
    output: list[str] = []
    for item in list_value(value):
        text = str(item).strip()
        if text and text.lower() not in {"none", "null"} and text not in output:
            output.append(text)
    return output


def _network_zones(raw: dict[str, Any]) -> tuple[list[str], list[str]]:
    normalized = normalized_map(raw)
    actual = _string_list(normalized.get("availability_zones"))
    hints = _string_list(normalized.get("availability_zone_hints"))
    return actual, hints


def _network_status(raw: dict[str, Any]) -> tuple[str | None, bool | None]:
    normalized = normalized_map(raw)
    status = optional_text(normalized.get("status"))
    admin = normalized.get("admin_state_up")
    return status.upper() if status else None, admin if isinstance(
        admin, bool
    ) else None


class ZonePreflight:
    """Resolve requested AZs and prove that the selected scope can run safely.

    This preflight is deliberately strict for an explicit multi-zone request. It
    fails before any cloud resource is created when the selected provider
    networks, compute hosts, migration cohorts, Cinder AZs, or quotas cannot
    satisfy the requested execution mode.
    """

    def __init__(
        self,
        config: Config,
        discovery: Discovery,
        plan: Plan,
        osc: OpenStack,
        reporter: Reporter,
        launch_selection: LaunchSelection,
    ):
        self.config = config
        self.discovery = discovery
        self.plan = plan
        self.osc = osc
        self.reporter = reporter
        self.logger = reporter.logger
        self.launch_selection = launch_selection
        self.aggregate_inventory_state = "unknown"
        self.aggregate_inventory_count: int | None = None

    def build(self) -> ZoneExecutionPlan:
        self.logger.section("Validating availability-zone execution scope")
        tracker = ResourceTracker(self.reporter)
        probe_builder = ResourceBuilder(
            self.config,
            self.discovery,
            self.plan,
            self.osc,
            self.reporter,
            tracker,
            launch_selection=self.launch_selection,
        )
        try:
            inventory = probe_builder.compute_host_inventory(refresh=True)
            aggregate_state = probe_builder._aggregate_inventory_state
            self.aggregate_inventory_state = aggregate_state
            self.aggregate_inventory_count = getattr(
                probe_builder, "_aggregate_inventory_count", None
            )
            volume_zones = (
                probe_builder._volume_availability_zone_inventory()
                if self.config.storage == "volume"
                else None
            )
        except PlacementUnavailableError as exc:
            raise SuiteError(
                f"Could not validate requested availability zones: {exc}"
            ) from exc
        finally:
            shutil.rmtree(probe_builder.work_dir, ignore_errors=True)

        by_zone: dict[str, list[ComputeHostInfo]] = defaultdict(list)
        for host in inventory.values():
            zone = optional_text(host.availability_zone)
            if (
                not zone
                or zone.lower() == "internal"
                or not host.enabled
                or not host.up
            ):
                continue
            by_zone[zone].append(host)
        if not by_zone:
            raise SuiteError("No enabled/up compute availability zones were discovered")

        explicit = bool(
            self.config.availability_zones or self.config.availability_zones_all
        )
        if self.config.availability_zones_all:
            zones = sorted(by_zone)
        elif self.config.availability_zones:
            zones = list(self.config.availability_zones)
        else:
            zones = [self._best_zone(by_zone)]

        missing = [zone for zone in zones if zone not in by_zone]
        if missing:
            raise SuiteError(
                "Requested availability zones have no enabled/up nova-compute hosts: "
                + ", ".join(missing)
            )
        if len(zones) == 1 and self.config.availability_zones_all:
            self.config.zone_mode = "per-zone"
        if self.config.zone_mode in {"cross-zone", "both"} and len(zones) < 2:
            raise SuiteError(
                f"zone mode {self.config.zone_mode} requires at least two usable availability zones"
            )

        folded_zones: dict[str, str] = {}
        for zone in zones:
            folded = zone.casefold()
            previous = folded_zones.get(folded)
            if previous is not None and previous != zone:
                raise SuiteError(
                    "Availability-zone names differ only by letter case and cannot "
                    f"produce unambiguous scoped test IDs: {previous}, {zone}"
                )
            folded_zones[folded] = zone

        selected_networks = {item.id: item for item in self.discovery.networks}
        neutron_zones = (
            discover_neutron_zones(
                self.discovery, self.osc, timeout=min(60, self.config.resource_timeout)
            )
            if not self.config.allow_cross_az_networking
            else {"network": {}, "router": {}}
        )
        validate_delegated_volume_zones(
            self.config,
            volume_zones,
            self.launch_selection.volume_type_availability_zones,
        )
        capabilities: dict[str, ZoneCapability] = {}
        network_failures: list[str] = []
        warnings: list[str] = []

        for zone in zones:
            for resource_type in ("network", "router"):
                select_neutron_zone(
                    self.config, self.discovery, neutron_zones, resource_type, zone
                )
            hosts = by_zone[zone]
            cohort_size = self._largest_migration_cohort(hosts)
            different_host_available = cohort_size >= 2
            zone_warnings: list[str] = []
            if (
                self.config.zone_mode in {"per-zone", "both"}
                and self.config.compute_host_connectivity_enabled
                and not different_host_available
            ):
                if len(hosts) < 2:
                    warning = (
                        f"Availability zone {zone} has only {len(hosts)} enabled/up compute host(s); "
                        "intra-compute coverage will run and unavailable inter-compute migration coverage will be reported as UNVERIFIED"
                    )
                elif self._aggregate_policy().discovery_blocked:
                    warning = (
                        f"Availability zone {zone}: aggregate inventory is {aggregate_state}; "
                        "migration eligibility cannot be verified"
                    )
                elif self._aggregate_policy().requires_shared:
                    warning = (
                        f"Availability zone {zone} has no shared aggregate cohort containing at least two enabled/up compute hosts; "
                        "existing placement coverage will run and the unavailable opposite-host migration relationship will be reported as UNVERIFIED"
                    )
                else:
                    warning = (
                        f"Availability zone {zone} cannot currently produce different-host coverage; "
                        "existing placement coverage will run and the unavailable relationship will be reported as UNVERIFIED"
                    )
                zone_warnings.append(warning)
                warnings.append(warning)

            cinder_available: bool | None = None
            volume_type_available: bool | None = None
            if self.config.storage == "volume":
                cinder_available = (
                    zone in volume_zones if volume_zones is not None else None
                )
                volume_type_zones = self.launch_selection.volume_type_availability_zones
                if volume_type_zones is not None:
                    volume_type_available = zone in volume_type_zones
                volume_choice = select_volume_zone(
                    self.config, volume_zones, volume_type_zones, zone
                )
                if volume_choice["requested_availability_zone"] is None:
                    warning = (
                        f"Compute AZ {zone}: root volumes will use Cinder defaults "
                        f"({volume_choice['selection_reason']}); Nova attachment policy will be enforced"
                    )
                    zone_warnings.append(warning)
                    warnings.append(warning)

            network_availability: dict[str, bool | None] = {}
            for network in selected_networks.values():
                status, admin_up = _network_status(network.raw)
                if status not in {None, "ACTIVE"}:
                    network_failures.append(
                        f"{network.name} ({network.id}) status is {status}, not ACTIVE"
                    )
                    network_availability[network.id] = False
                    continue
                if admin_up is False:
                    network_failures.append(
                        f"{network.name} ({network.id}) has admin_state_up=False"
                    )
                    network_availability[network.id] = False
                    continue

                # Equal Neutron/Nova names do not prove host reachability; unequal
                # names do not disprove it. Preserve metadata only as evidence.
                actual, hints = _network_zones(network.raw)
                network_availability[network.id] = None
                note = (
                    f"Network {network.name} ({network.id}) usability in compute AZ {zone} "
                    "will be verified by AZ-pinned boot, port binding, and connectivity; "
                    f"Neutron AZs={','.join(actual) or 'not exposed'}, hints={','.join(hints) or 'none'}"
                )
                self.logger.log(note)

            capabilities[zone] = ZoneCapability(
                name=zone,
                enabled_hosts=sorted(item.host for item in hosts),
                migration_cohort_size=cohort_size,
                cinder_available=cinder_available,
                network_availability=network_availability,
                warnings=zone_warnings,
                different_host_coverage_available=different_host_available,
                volume_type_available=volume_type_available,
            )

        if network_failures:
            raise SuiteError(
                "Selected external networks do not satisfy the requested availability-zone scope: "
                + " | ".join(dict.fromkeys(network_failures))
            )

        self._validate_parallel_quota(len(zones))
        # Every selected AZ is an active lane. Cross-zone tests rely on all
        # peer endpoints existing concurrently, and per-zone suites run in
        # parallel rather than being serialized behind a worker throttle.
        workers = max(1, len(zones))
        zone_plan = ZoneExecutionPlan(
            zones=zones,
            mode=self.config.zone_mode,
            capabilities=capabilities,
            explicit_selection=explicit,
            parallel_workers=workers,
            warnings=warnings,
        )
        self.logger.log(
            f"Availability-zone scope ready: mode={zone_plan.mode}, zones={','.join(zones)}, parallel_workers={workers}"
        )
        self.logger.log(
            "Selected networks passed status/admin checks; Neutron AZ metadata was recorded as advisory. "
            "AZ-pinned boot, port binding, and connectivity checks determine actual usability: "
            + ", ".join(item.name for item in self.discovery.networks)
        )
        for zone in zones:
            capability = capabilities[zone]
            cinder_status = (
                "not-applicable"
                if self.config.storage != "volume"
                else "matching-az"
                if select_volume_zone(
                    self.config,
                    volume_zones,
                    self.launch_selection.volume_type_availability_zones,
                    zone,
                )["requested_availability_zone"]
                else "scheduler-default"
            )
            self.logger.log(
                f"Zone {zone}: enabled_hosts={len(capability.enabled_hosts)}, "
                f"largest_migration_cohort={capability.migration_cohort_size}, "
                f"different_host_coverage={'available' if capability.different_host_coverage_available else 'unavailable'}, "
                f"cinder={cinder_status}"
            )
        for warning in warnings:
            self.logger.log(warning, "WARNING")
        self.reporter.event(
            "availability-zone-scope-validated",
            "Validated requested compute/storage dependencies and recorded advisory Neutron AZ metadata for every selected availability zone",
            mode=zone_plan.mode,
            zones=zones,
            parallel_workers=workers,
            aggregate_inventory=aggregate_state,
            aggregate_policy=dataclasses.asdict(self._aggregate_policy()),
            capabilities={
                zone: dataclasses.asdict(capability)
                for zone, capability in capabilities.items()
            },
        )
        return zone_plan

    def _best_zone(self, by_zone: dict[str, list[ComputeHostInfo]]) -> str:
        def score(item: tuple[str, list[ComputeHostInfo]]) -> tuple[int, int, int, str]:
            zone, hosts = item
            return (
                int(zone.lower() != "nova"),
                self._largest_migration_cohort(hosts),
                len(hosts),
                zone,
            )

        return max(by_zone.items(), key=score)[0]

    def _aggregate_policy(self):
        return resolve_aggregate_policy(
            self.config.require_shared_compute_aggregate,
            self.aggregate_inventory_state,
            self.aggregate_inventory_count,
        )

    def _largest_migration_cohort(self, hosts: list[ComputeHostInfo]) -> int:
        if not hosts:
            return 0
        policy = self._aggregate_policy()
        if not policy.requires_shared:
            return len({host.host for host in hosts})
        if policy.discovery_blocked:
            return 1

        cohorts: dict[str, set[str]] = defaultdict(set)
        for host in hosts:
            if host.aggregate_ids:
                for aggregate_id in host.aggregate_ids:
                    cohorts[aggregate_id].add(host.host)
            else:
                # Unaggregated hosts are independent placement cohorts when the
                # migration policy requires a real shared aggregate.
                cohorts[f"__unaggregated__:{host.host}"].add(host.host)
        return max((len(values) for values in cohorts.values()), default=0)

    def _validate_parallel_quota(self, zone_count: int) -> None:
        peak_instances = max(1, int(self.plan.estimated.get("peak_instances", 3)))
        requirements = {
            "instances": peak_instances * zone_count,
            "cores": peak_instances * zone_count * self.launch_selection.flavor_vcpus,
            "ram": peak_instances * zone_count * self.launch_selection.flavor_ram_mb,
            "ports": max(
                1, int(self.plan.estimated.get("peak_ports", peak_instances * 2))
            )
            * zone_count,
            "networks": max(1, int(self.plan.estimated.get("peak_created_networks", 1)))
            * zone_count,
            "subnets": max(1, int(self.plan.estimated.get("peak_created_subnets", 1)))
            * zone_count,
            "routers": max(0, int(self.plan.estimated.get("peak_created_routers", 0)))
            * zone_count,
            "floating_ips": max(0, int(self.plan.estimated.get("peak_floating_ips", 0)))
            * zone_count,
            # Neutron security groups are project-wide rather than AZ-scoped.
            # Multi-zone execution creates one shared controller/management/A/B
            # bundle instead of multiplying the same groups in every lane.
            "security_groups": max(
                4, int(self.plan.estimated.get("security_groups_created", 4))
            ),
            "security_group_rules": max(
                24, int(self.plan.estimated.get("security_group_rules_peak", 24))
            )
            + (zone_count if self.config.zone_mode in {"per-zone", "both"} else 0),
            "key_pairs": zone_count,
        }
        if self.config.storage == "volume":
            requirements["volumes"] = (
                max(1, int(self.plan.estimated.get("peak_volumes", peak_instances)))
                * zone_count
            )
            requirements["gigabytes"] = (
                requirements["volumes"] * self.config.volume_size
            )
        shortages: list[str] = []
        for resource, required in requirements.items():
            quota = self.discovery.quota_info.get(resource)
            if quota and quota.available is not None and quota.available < required:
                shortages.append(
                    f"{resource}: need parallel peak {required}, available {quota.available}"
                )
        if shortages:
            raise SuiteError(
                "Selected availability-zone parallelism exceeds available quota: "
                + "; ".join(shortages)
            )
