"""Independent, read-only Neutron AZ discovery and placement decisions.

Neutron AZs describe network services, not the Nova hosts allowed to use a
provider network. Never infer physical locality from equal (or unequal) names.
"""

from __future__ import annotations

from typing import Any

from .config import Config
from .errors import SuiteError
from .models import Discovery
from .utils import normalized_map

RESOURCE_TYPES = ("network", "router")


def validate_delegated_volume_zones(
    config: Config,
    available: set[str] | None,
    type_zones: frozenset[str] | set[str] | None = None,
) -> None:
    """Default placement still requires usable, type-compatible storage."""
    if config.storage != "volume":
        return
    if available is not None and not available:
        raise SuiteError("Cinder exposes no available volume AZs")
    if (
        available is not None
        and type_zones is not None
        and not available.intersection(type_zones)
    ):
        raise SuiteError(
            f"Cinder volume type {config.volume_type} has no compatible available volume AZ"
        )


def select_volume_zone(
    config: Config,
    available: set[str] | None,
    type_zones: frozenset[str] | set[str] | None,
    compute_zone: str | None,
) -> dict[str, Any]:
    """Request a verified compute-name match, otherwise use Cinder defaults."""
    validate_delegated_volume_zones(config, available, type_zones)
    selected = None
    if config.allow_cross_az_volumes:
        reason = "explicit-scheduler-default"
    elif available is None:
        reason = "inventory-unavailable-scheduler-default"
    elif compute_zone in available and (
        type_zones is None or compute_zone in type_zones
    ):
        selected = compute_zone
        reason = "compute-name-match"
    else:
        reason = "no-compatible-match-scheduler-default"
    return {
        "resource_type": "volume",
        "compute_availability_zone": compute_zone,
        "requested_availability_zone": selected,
        "selection_reason": reason,
        "advertised_zones": sorted(available) if available is not None else None,
        "volume_type_zones": sorted(type_zones) if type_zones is not None else None,
    }


def discover_neutron_zones(
    discovery: Discovery, osc: Any, *, timeout: int
) -> dict[str, dict[str, bool]]:
    """Keep unavailable zones too: an outage must not enable sole-AZ fallback."""
    if discovery.neutron_availability_zones is not None:
        return discovery.neutron_availability_zones
    inventory: dict[str, dict[str, bool]] = {kind: {} for kind in RESOURCE_TYPES}
    extensions = set(discovery.network_extensions)
    if any(f"{kind}_availability_zone" in extensions for kind in RESOURCE_TYPES):
        # --long is essential: without Zone Resource a network row cannot be
        # distinguished from a router row with the same name.
        rows = osc.json(
            "availability", "zone", "list", "--network", "--long", timeout=timeout
        )
        if not isinstance(rows, list):
            raise SuiteError(
                "Neutron availability-zone inventory did not return a list"
            )
        for row in rows:
            if not isinstance(row, dict):
                raise SuiteError(
                    "Neutron availability-zone inventory contains an invalid row"
                )
            fields = normalized_map(row)
            name = str(fields.get("zone_name") or fields.get("name") or "").strip()
            kind = (
                str(fields.get("zone_resource") or fields.get("resource") or "")
                .strip()
                .lower()
            )
            status = fields.get(
                "zone_status", fields.get("state", fields.get("available"))
            )
            state = str(status).strip().lower()
            if not name or not kind:
                raise SuiteError(
                    "Neutron AZ inventory is missing Zone Name or Zone Resource (--long)"
                )
            if kind not in inventory:
                continue
            if state not in {
                "available",
                "unavailable",
                "not available",
                "true",
                "false",
                "up",
                "down",
                "enabled",
                "disabled",
            }:
                raise SuiteError(
                    f"Neutron {kind} AZ {name} has unknown availability: {status!r}"
                )
            available = state in {"available", "true", "up", "enabled"}
            inventory[kind][name] = inventory[kind].get(name, True) and available
    discovery.neutron_availability_zones = inventory
    return inventory


def select_neutron_zone(
    config: Config,
    discovery: Discovery,
    inventory: dict[str, dict[str, bool]],
    resource_type: str,
    compute_zone: str | None,
) -> dict[str, Any]:
    """Match compute independently for each service, then use available defaults."""
    if resource_type not in RESOURCE_TYPES:
        raise SuiteError(f"Not a Neutron AZ resource: {resource_type}")
    supported = f"{resource_type}_availability_zone" in discovery.network_extensions
    zones = inventory.get(resource_type, {})
    selected: str | None = None
    if config.allow_cross_az_networking:
        reason = "explicit-scheduler-default"
    elif not supported:
        reason = "az-extension-not-advertised"
    elif not zones:
        reason = "no-resource-az-advertised"
    elif compute_zone is not None and zones.get(compute_zone, False):
        selected = compute_zone
        reason = "compute-name-match"
    else:
        available = [name for name, up in zones.items() if up]
        if not available:
            raise SuiteError(f"Neutron {resource_type} exposes no available AZs")
        if len(available) == 1:
            selected, reason = available[0], "sole-available-az"
        else:
            reason = "ambiguous-scheduler-default"
    return {
        "resource_type": resource_type,
        "compute_availability_zone": compute_zone,
        "requested_availability_zone": selected,
        "selection_reason": reason,
        "advertised_zones": dict(sorted(zones.items())),
        "matching_zone_unavailable": compute_zone in zones and not zones[compute_zone],
    }
