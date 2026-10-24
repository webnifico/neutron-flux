from __future__ import annotations

from typing import Any

from ..az_policy import (
    discover_neutron_zones,
    select_neutron_zone,
    select_volume_zone,
    validate_delegated_volume_zones,
)

# mypy: disable-error-code="attr-defined"
from ..errors import (
    CommandError,
    CommandTimeoutError,
    PlacementUnavailableError,
    SuiteError,
)
from ..models import ComputeHostInfo
from ..scheduling import READ_WORKERS, bounded_map
from ..utils import list_value, normalized_map, optional_text


class AvailabilityRuntimeMixin:
    """Compatibility mixin for the availability runtime subsystem."""

    def _neutron_az_selection(self, resource_type: str) -> dict[str, Any]:
        inventory = (
            {"network": {}, "router": {}}
            if self.config.allow_cross_az_networking
            else discover_neutron_zones(
                self.discovery, self.osc, timeout=min(60, self.config.resource_timeout)
            )
        )
        return select_neutron_zone(
            self.config,
            self.discovery,
            inventory,
            resource_type,
            optional_text(getattr(self, "selected_availability_zone", None))
            or optional_text(
                getattr(self, "discovered_compute_availability_zone", None)
            ),
        )

    def _prepare_neutron_placement(self) -> None:
        # Read-only and before keypair creation, including automatic single-AZ
        # runs. Unsupported optional extensions do not invent a compute hint.
        for resource_type in ("network", "router"):
            choice = self._neutron_az_selection(resource_type)
            self.logger.log(
                f"Neutron {resource_type} AZ: "
                f"{choice['requested_availability_zone'] or 'cloud scheduling'}; "
                f"compute AZ={choice['compute_availability_zone'] or 'Nova-selected'}; "
                f"reason={choice['selection_reason']}"
            )
            self.reporter.event(
                "neutron-az-selected", "Independent Neutron AZ selection", **choice
            )
        if self.config.storage == "volume":
            choice = self._volume_az_selection(self.selected_availability_zone)
            self.logger.log(
                f"Cinder volume AZ: {choice['requested_availability_zone'] or 'cloud scheduling'}; "
                f"reason={choice['selection_reason']}"
            )
            self.reporter.event(
                "volume-az-selected", "Independent Cinder AZ selection", **choice
            )

    def _availability_zone_hint_args(self, resource_type: str = "network") -> list[str]:
        zone = self._neutron_az_selection(resource_type)["requested_availability_zone"]
        return ["--availability-zone-hint", zone] if zone else []

    def _validate_controller_network_zone(self, compute_zone: str | None) -> None:
        """Do not move a controller away from its already-created AZ hints."""
        resources = getattr(getattr(self, "reporter", None), "resources", [])
        for resource in resources if isinstance(resources, list) else []:
            if resource.resource_type not in {"network", "router"}:
                continue
            if resource.delete_status in {"deleted", "already-absent"}:
                continue
            previous = resource.metadata.get("neutron_az_placement")
            if not isinstance(previous, dict):
                continue
            choice = select_neutron_zone(
                self.config,
                self.discovery,
                {resource.resource_type: previous.get("advertised_zones", {})},
                resource.resource_type,
                compute_zone,
            )
            expected = choice["requested_availability_zone"]
            accepted = previous.get("requested_availability_zone")
            if expected != accepted:
                raise PlacementUnavailableError(
                    f"Compute AZ {compute_zone} needs {resource.resource_type} AZ "
                    f"{expected or 'cloud default'}, but existing {resource.resource_type} "
                    f"{resource.id} was created for {accepted or 'cloud default'}; "
                    "cannot reuse that topology for controller AZ fallback"
                )

    @staticmethod
    def _resource_zone_values(
        detail: dict[str, Any],
    ) -> tuple[bool, list[str], bool, list[str]]:
        normalized = normalized_map(detail)
        actual = [
            str(item).strip()
            for item in list_value(normalized.get("availability_zones"))
            if str(item).strip()
        ]
        hints = [
            str(item).strip()
            for item in list_value(normalized.get("availability_zone_hints"))
            if str(item).strip()
        ]
        return (
            "availability_zones" in normalized,
            actual,
            "availability_zone_hints" in normalized,
            hints,
        )

    @staticmethod
    def _created_network_metadata(detail: dict[str, Any]) -> dict[str, Any]:
        """Retain attributes exposed by Neutron, including explicit nulls."""
        normalized = normalized_map(detail)
        values: dict[str, Any] = {}
        for field, names in (
            ("network_type", ("provider_network_type", "network_type")),
            ("physical_network", ("provider_physical_network", "physical_network")),
            ("segmentation_id", ("provider_segmentation_id", "segmentation_id")),
            ("mtu", ("mtu",)),
        ):
            present = next((name for name in names if name in normalized), None)
            if present is None:
                continue
            value = normalized[present]
            if field in {"network_type", "physical_network"}:
                if value is not None and not isinstance(value, str):
                    continue
                value = optional_text(value)
            elif field == "mtu" and value is not None:
                if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                    continue
            elif field == "segmentation_id" and (
                isinstance(value, bool) or not isinstance(value, (str, int, type(None)))
            ):
                continue
            values[field] = value
        return values

    def _validate_created_resource_zone(
        self,
        resource_type: str,
        resource_id: str,
        detail: dict[str, Any],
        *,
        selection: dict[str, Any] | None = None,
        after_scheduling: bool = False,
    ) -> None:
        choice = (
            selection
            if selection is not None
            else self._neutron_az_selection(resource_type)
        )
        zone = choice["requested_availability_zone"]
        actual_exposed, actual, hints_exposed, hints = self._resource_zone_values(
            detail
        )
        network_metadata = (
            self._created_network_metadata(detail) if resource_type == "network" else {}
        )
        # Validate the accepted request first. An empty actual AZ list at create
        # time is normal: DHCP/gateway scheduling may require subnets and ports
        # that have not been created yet. Never wait for them before creating them.
        if zone and (not hints_exposed or not hints):
            shown = self.osc.json(
                resource_type,
                "show",
                resource_id,
                timeout=min(60, self.config.resource_timeout),
            )
            if isinstance(shown, dict):
                actual_exposed, actual, hints_exposed, hints = (
                    self._resource_zone_values(shown)
                )
                if resource_type == "network":
                    network_metadata.update(self._created_network_metadata(shown))
        if zone and set(hints) != {zone}:
            raise SuiteError(
                f"Created {resource_type} {resource_id} did not retain requested Neutron AZ hint "
                f"{zone}; availability_zone_hints={','.join(hints) or 'not exposed'}"
            )
        if zone and actual and set(actual) != {zone}:
            raise SuiteError(
                f"Created {resource_type} {resource_id} was scheduled outside requested Neutron AZ "
                f"{zone}; availability_zones={','.join(actual)}"
            )
        evidence = {
            **choice,
            "resource_id": resource_id,
            "availability_zones": actual,
            "availability_zone_hints": hints,
            "actual_az_exposed": actual_exposed,
            "hint_verified": bool(zone and set(hints) == {zone}),
            "placement_verified": bool(zone and actual and set(actual) == {zone}),
            "verification_stage": "after-scheduling" if after_scheduling else "created",
        }
        key = f"{resource_type}:{resource_id}"
        if not hasattr(self, "pending_neutron_az_validation"):
            self.pending_neutron_az_validation = {}
        if not after_scheduling and not actual:
            self.pending_neutron_az_validation[key] = choice
        else:
            self.pending_neutron_az_validation.pop(key, None)
        reporter = getattr(self, "reporter", None)
        if reporter is not None:
            resources = getattr(reporter, "resources", [])
            for resource in resources if isinstance(resources, list) else []:
                if (
                    resource.resource_type == resource_type
                    and resource.id == resource_id
                ):
                    resource.metadata.update(network_metadata)
                    resource.metadata["neutron_az_placement"] = evidence
                    resource.metadata["availability_zone_hints"] = hints
                    resource.metadata["neutron_availability_zones"] = actual
                    reporter.update_resource(resource)
                    break
            reporter.event(
                "neutron-az-placement", "Neutron placement evidence", **evidence
            )
        if after_scheduling and zone and not actual:
            self.logger.log(
                f"Neutron {resource_type} {resource_id} retained AZ hint {zone} but exposes no "
                "actual scheduled AZ; placement remains unverified (not inferred from the hint)",
                "WARNING",
            )

    def _refresh_neutron_placements(self, group_id: str | None = None) -> None:
        resources = {
            f"{item.resource_type}:{item.id}": item
            for item in getattr(getattr(self, "reporter", None), "resources", [])
        }
        pending: list[tuple[str, str, dict[str, Any]]] = []
        for key, choice in list(
            getattr(self, "pending_neutron_az_validation", {}).items()
        ):
            resource = resources.get(key)
            if resource is not None:
                if resource.delete_status in {"deleted", "already-absent"}:
                    self.pending_neutron_az_validation.pop(key, None)
                    continue
                if group_id is not None and resource.metadata.get("group_id") not in {
                    None,
                    group_id,
                }:
                    continue
            resource_type, resource_id = key.split(":", 1)
            pending.append((resource_type, resource_id, dict(choice)))

        def read_placement(item: tuple[str, str, dict[str, Any]]) -> Any:
            resource_type, resource_id, _ = item
            return self.osc.json(
                resource_type,
                "show",
                resource_id,
                timeout=min(60, self.config.resource_timeout),
            )

        details = bounded_map(read_placement, pending, workers=READ_WORKERS)
        # Finish the read batch and check its shape before changing placement
        # evidence. Validation and reporter updates stay on the caller thread.
        for (resource_type, resource_id, _), shown in zip(
            pending, details, strict=True
        ):
            if not isinstance(shown, dict):
                raise SuiteError(
                    f"Could not read Neutron placement for {resource_type} {resource_id}"
                )
        for (resource_type, resource_id, choice), shown in zip(
            pending, details, strict=True
        ):
            self._validate_created_resource_zone(
                resource_type,
                resource_id,
                shown,
                selection=choice,
                after_scheduling=True,
            )

    @staticmethod
    def _availability_zone_is_internal(zone: str | None) -> bool:
        return not zone or zone.strip().lower() == "internal"

    def _availability_zone_score(
        self, zone: str, hosts: list[ComputeHostInfo]
    ) -> tuple[int, int, int, int]:
        enabled_hosts = [item for item in hosts if item.enabled and item.up]
        if not self.compute_aggregate_policy().requires_shared:
            largest_migration_cohort = len({item.host for item in enabled_hosts})
        else:
            largest_migration_cohort = 1 if enabled_hosts else 0
            if self._aggregate_inventory_state == "complete":
                aggregate_counts: dict[str, int] = {}
                for host in enabled_hosts:
                    for aggregate_id in host.aggregate_ids:
                        aggregate_counts[aggregate_id] = (
                            aggregate_counts.get(aggregate_id, 0) + 1
                        )
                largest_migration_cohort = max(
                    aggregate_counts.values(), default=1 if enabled_hosts else 0
                )
        # Prefer zones that can actually create inter-compute coverage, then the
        # largest policy-eligible migration cohort, then total enabled capacity.
        # Literal ``nova`` is deliberately the final fallback when another usable
        # AZ exists.
        non_default = 0 if zone.strip().lower() == "nova" else 1
        migration_capable = int(largest_migration_cohort >= 2)
        return (
            non_default,
            migration_capable,
            largest_migration_cohort,
            len(enabled_hosts),
        )

    def _volume_availability_zone_inventory(self) -> set[str] | None:
        """Return enabled Cinder AZ names, or ``None`` when not observable.

        Compute and Block Storage expose separate inventories. Prefer matching
        names when available; otherwise let Cinder use its configured defaults.
        Nova remains authoritative about whether the volume can be attached.
        """
        osc = getattr(self, "osc", None)
        if osc is None:
            self.volume_availability_zone_inventory_reason = (
                "Cinder availability-zone inventory was not queried"
            )
            return None
        self.logger.log(
            "Querying Cinder availability-zone inventory for volume-backed boot"
        )
        try:
            rows = osc.optional_json(
                "availability",
                "zone",
                "list",
                "--volume",
                timeout=min(60, self.config.resource_timeout),
            )
        except (CommandError, CommandTimeoutError) as exc:
            self.volume_availability_zone_inventory_reason = (
                f"Cinder availability-zone inventory failed: {exc}"
            )
            self.logger.log(self.volume_availability_zone_inventory_reason, "WARNING")
            return None
        if rows is None:
            self.volume_availability_zone_inventory_reason = (
                "OpenStackClient does not expose Cinder availability-zone inventory"
            )
            return None
        if not isinstance(rows, list):
            self.volume_availability_zone_inventory_reason = (
                "Cinder availability-zone inventory returned an unexpected payload"
            )
            self.logger.log(self.volume_availability_zone_inventory_reason, "WARNING")
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
            if not zone or self._availability_zone_is_internal(zone):
                continue
            if status in {"false", "unavailable", "not available", "down", "disabled"}:
                continue
            zones.add(zone)
        self.volume_availability_zone_inventory_reason = f"Cinder availability-zone inventory is available ({len(zones)} usable zone(s))"
        self.logger.log(
            "Cinder availability zones available for volume-backed boot: "
            + (", ".join(sorted(zones)) if zones else "none")
        )
        return zones

    def _select_run_availability_zone(self) -> None:
        """Select a deterministic compute AZ and discover independent storage AZs.

        The controller is used as the scheduling probe. Candidate zones are
        ranked once, and an authoritative ``NoValidHost`` on controller boot
        advances to the next candidate. Once the controller boots, the chosen
        AZ is locked for every endpoint and migration.
        """
        self.discovered_compute_availability_zone = None
        if self.config.storage == "host":
            self.volume_availability_zones = None
            self.volume_availability_zone_inventory_reason = (
                "Cinder availability-zone inventory was intentionally not queried "
                "because storage=host"
            )
            self.logger.log(
                "Storage mode is host; skipping Cinder availability-zone discovery"
            )
        else:
            self.volume_availability_zones = self._volume_availability_zone_inventory()
        launch_selection = getattr(self, "launch_selection", None)
        validate_delegated_volume_zones(
            self.config,
            self.volume_availability_zones,
            launch_selection.volume_type_availability_zones
            if launch_selection is not None
            else None,
        )

        self.logger.log(
            "Querying enabled nova-compute services, host AZs, and aggregate membership"
        )
        try:
            inventory = self.compute_host_inventory(refresh=True)
        except PlacementUnavailableError as exc:
            if self.config.availability_zones:
                raise SuiteError(
                    f"Could not validate configured placement.availability_zones: {exc}"
                ) from exc
            self.selected_availability_zone = None
            self.availability_zone_candidates = [None]
            self.selected_availability_zone_reason = "compute-service inventory was unavailable; Nova and Cinder defaults will be used"
            self.logger.log(
                "Compute availability-zone inventory is unavailable; omitting explicit AZ selection so Nova and Cinder apply their configured defaults",
                "WARNING",
            )
            return
        self.logger.log(
            f"Compute placement inventory ready: {len(inventory)} host record(s); "
            f"aggregate_inventory={self._aggregate_inventory_state}, "
            f"aggregate_count={getattr(self, '_aggregate_inventory_count', None)}, "
            f"aggregate_policy={self.compute_aggregate_policy().resolution}"
        )

        by_zone: dict[str, list[ComputeHostInfo]] = {}
        for host in inventory.values():
            if (
                not host.enabled
                or not host.up
                or self._availability_zone_is_internal(host.availability_zone)
            ):
                continue
            zone = str(host.availability_zone)
            by_zone.setdefault(zone, []).append(host)

        configured = [
            zone
            for zone in self.config.availability_zones
            if not self._availability_zone_is_internal(zone)
        ]
        if self.config.availability_zones and not configured:
            raise SuiteError(
                "placement.availability_zones contains only the reserved internal availability zone"
            )
        if configured:
            missing = [zone for zone in configured if zone not in by_zone]
            candidates = [zone for zone in configured if zone in by_zone]
            if not candidates:
                raise SuiteError(
                    "None of the configured placement.availability_zones has an explicitly enabled/up nova-compute host: "
                    + ", ".join(configured)
                )
            if missing:
                self.logger.log(
                    "Ignoring configured availability zones without enabled/up compute capacity: "
                    + ", ".join(missing),
                    "WARNING",
                )
            origin = "configured allowlist"
            order = {zone: index for index, zone in enumerate(configured)}
        else:
            candidates = list(by_zone)
            if not candidates:
                self.selected_availability_zone = None
                self.availability_zone_candidates = [None]
                self.selected_availability_zone_reason = "no non-internal compute AZ was exposed; Nova and Cinder defaults will be used"
                self.logger.log(
                    "No non-internal compute availability zone was exposed; omitting explicit AZ selection",
                    "WARNING",
                )
                return
            origin = "automatic compute inventory"
            order = {zone: index for index, zone in enumerate(sorted(candidates))}

        volume_zones = self.volume_availability_zones

        def score(zone: str) -> tuple[int, int, int, int, int]:
            storage_match = int(
                self.config.storage == "host"
                or self._volume_az_selection(zone)["requested_availability_zone"]
                is not None
            )
            return (storage_match, *self._availability_zone_score(zone, by_zone[zone]))

        # Highest score first. Preserve configured order for equal candidates;
        # automatic selection is deterministic by AZ name.
        ranked = sorted(
            candidates,
            key=lambda zone: (
                tuple(-item for item in score(zone)),
                order.get(zone, 999999),
                zone,
            ),
        )
        selected = ranked[0]
        # Retain the discovered compute name for independent Neutron matching
        # even when the controller request intentionally leaves Nova's AZ unset.
        # Observed controller placement takes precedence after boot.
        self.discovered_compute_availability_zone = selected
        # For an automatic ephemeral run whose only visible choice is Nova's
        # conventional default AZ, omit --availability-zone for the controller.
        # The actual AZ returned by Nova is then locked for every endpoint.
        # Volume-backed runs retain an explicit compute AZ. Cinder independently
        # requests a matching AZ where available, otherwise its defaults apply.
        default_probe = (
            not configured
            and self.config.storage == "host"
            and selected.strip().lower() == "nova"
            and not any(zone.strip().lower() != "nova" for zone in ranked)
        )
        self.availability_zone_candidates = [None] if default_probe else list(ranked)
        if default_probe:
            selected_for_request: str | None = None
        else:
            selected_for_request = selected
        hosts = by_zone[selected]
        az_score = self._availability_zone_score(selected, hosts)
        storage_note = (
            "host storage; Cinder not used"
            if self.config.storage == "host"
            else self._volume_az_selection(selected)["selection_reason"]
        )
        self.selected_availability_zone = selected_for_request
        self.selected_availability_zone_reason = (
            f"selected from {origin}; enabled_hosts={az_score[3]}, "
            f"largest_policy_eligible_migration_cohort={az_score[2]}; {storage_note}"
        )
        self.logger.log(
            f"Selected run availability zone candidate: {selected_for_request or 'Nova default'} "
            f"({self.selected_availability_zone_reason})"
        )
        self.reporter.event(
            "availability-zone-selected",
            f"Controller scheduling will begin in availability zone {selected_for_request or 'Nova default'}",
            availability_zone=selected_for_request,
            discovered_compute_availability_zone=selected,
            candidates=self.availability_zone_candidates,
            reason=self.selected_availability_zone_reason,
            configured_allowlist=configured,
            cinder_availability_zones=sorted(volume_zones or []),
            cinder_inventory_observed=volume_zones is not None,
        )

    @staticmethod
    def _is_no_valid_host_message(text: str) -> bool:
        lowered = text.lower()
        return any(
            marker in lowered
            for marker in (
                "no valid host",
                "novalidhost",
                "no suitable host",
                "failed to find a host",
            )
        )

    @staticmethod
    def _is_cinder_placement_unavailable_message(text: str) -> bool:
        lowered = text.lower()
        permanent_markers = (
            "unauthorized",
            "forbidden",
            "http 401",
            "http 403",
            "service catalog",
            "endpoint",
            "authentication",
            "policy doesn't allow",
        )
        if any(marker in lowered for marker in permanent_markers):
            return False
        return any(
            marker in lowered
            for marker in (
                "availability zone",
                "invalid az",
                "no valid backend",
                "no valid host",
                "could not find any available weighted backend",
                "scheduler failed",
                "failed to schedule volume",
            )
        )

    def _volume_az_selection(self, compute_zone: str | None) -> dict[str, Any]:
        launch = getattr(self, "launch_selection", None)
        return select_volume_zone(
            self.config,
            getattr(self, "volume_availability_zones", None),
            launch.volume_type_availability_zones if launch is not None else None,
            compute_zone,
        )

    def _validate_created_volume_availability_zone(
        self,
        requested_az: str | None,
        actual_az: str,
        volume_name: str,
        volume_id: str,
        volume_record: Any | None,
        *,
        selection: dict[str, Any] | None = None,
    ) -> None:
        choice = selection or {
            "compute_availability_zone": requested_az,
            "requested_availability_zone": (
                None if self.config.allow_cross_az_volumes else requested_az
            ),
            "selection_reason": "explicit-scheduler-default"
            if self.config.allow_cross_az_volumes
            else "compute-name-match",
        }
        requested_volume_az = choice["requested_availability_zone"]
        launch = getattr(self, "launch_selection", None)
        allowed = launch.volume_type_availability_zones if launch is not None else None
        if not actual_az or (allowed is not None and actual_az not in allowed):
            self._discard_failed_boot_volume(volume_id, volume_record)
            raise PlacementUnavailableError(
                f"Cinder volume {volume_name} has an unknown or volume-type-incompatible AZ: {actual_az or 'UNKNOWN'}"
            )
        if requested_volume_az and actual_az != requested_volume_az:
            self._discard_failed_boot_volume(volume_id, volume_record)
            raise PlacementUnavailableError(
                f"Cinder created root volume {volume_name} in availability zone {actual_az} "
                f"after {requested_volume_az} was requested; requested placement was not honoured"
            )
        evidence = {
            **choice,
            "volume_id": volume_id,
            "volume_availability_zone": actual_az,
            "requested_volume_availability_zone": requested_volume_az,
            "matches_compute_zone": (
                actual_az == choice["compute_availability_zone"]
                if choice["compute_availability_zone"]
                else None
            ),
        }
        if volume_record is not None:
            volume_record.metadata["volume_az_placement"] = evidence
            self.reporter.update_resource(volume_record)
        self.logger.log(
            f"Cinder volume AZ={actual_az}; compute AZ={choice['compute_availability_zone'] or 'Nova-selected'}; "
            f"reason={choice['selection_reason']}; Nova attachment policy still applies"
        )
        self.reporter.event(
            "volume-availability-zone-selected", "Cinder volume placement", **evidence
        )
