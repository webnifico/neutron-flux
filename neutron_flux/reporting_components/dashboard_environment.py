from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from typing import Any

from .dashboard_topology import _network_label, _network_role, _project_role_label


def _created_network_name(metadata: dict[str, Any]) -> str:
    role = str(metadata.get("role") or "")
    side = str(metadata.get("scenario_side") or "").lower()
    side_label = (
        "A"
        if side in {"a", "project-a", "tenant-a", "endpoint-a"}
        else "B"
        if side in {"b", "project-b", "tenant-b", "endpoint-b"}
        else None
    )
    if role == "management":
        return "Flux management network"
    if role == "transit" or side == "transit":
        return "Router transit network"
    if side_label and role in {
        "one-router-project-networks",
        "tenant-router-pair",
    }:
        return f"Project network {side_label} in one-router topology"
    if side_label and role in {
        "two-router-static-routing",
        "extra-route-pair",
    }:
        return f"Project network {side_label} in two-router static-routing topology"
    if side_label:
        return f"Project network {side_label}"
    return _project_role_label(role)


def build_network_inventory(
    discovery: dict[str, Any],
    resources: list[dict[str, Any]],
    allocation: dict[str, Any],
    results: Iterable[dict[str, Any]] = (),
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    network_cidrs = allocation.get("network_cidrs") or {}
    # Older runs did not retain create-response attributes in resource metadata,
    # but may already contain an authoritative network SHOW in MTU evidence.
    # Join only the exact recorded network UUID; labels and CIDRs are not identity.
    recorded: dict[str, dict[str, Any]] = {}
    for result in results:
        path = (result.get("details") or {}).get("path") or {}
        for side in ("source", "destination"):
            evidence = path.get(f"{side}_mtu_evidence") or {}
            network_id = str(evidence.get("resource_id") or "")
            if (
                not network_id
                or evidence.get("resource_type") != "network"
                or evidence.get("source") != "openstack network show"
            ):
                continue
            facts = recorded.setdefault(network_id, {})
            for attribute in ("network_type", "physical_network", "segmentation_id"):
                if attribute in evidence:
                    facts[attribute] = evidence[attribute]
            if evidence.get("reported_mtu") is not None:
                facts["mtu"] = evidence["reported_mtu"]
    inventory: list[dict[str, Any]] = []
    names: dict[str, str] = {}
    for network in discovery.get("networks") or []:
        network_id = str(network.get("id") or "")
        name = str(network.get("name") or network_id or "Network")
        cidrs = list(network_cidrs.get(network_id) or [])
        names[network_id] = name
        inventory.append(
            {
                "id": network_id,
                "name": name,
                "label": _network_label(name, cidrs),
                "subnet_cidrs": cidrs,
                "subnet_summary": " / ".join(cidrs)
                if cidrs
                else "No subnet CIDR recorded",
                "role": _network_role(network),
                "external": network.get("external")
                if "external" in network
                else (network.get("raw") or {}).get("router:external")
                if isinstance(network.get("raw"), dict)
                else network.get("is_router_external"),
                "shared": network.get("shared"),
                "network_type": network.get("network_type"),
                "physical_network": network.get("physical_network"),
                "segmentation_id": network.get("segmentation_id"),
                "mtu": network.get("mtu"),
                "availability_zone_hints": network.get("availability_zone_hints")
                or (network.get("raw") or {}).get("availability_zone_hints")
                or [],
            }
        )
    for resource in resources:
        if resource.get("resource_type") != "network":
            continue
        resource_id = str(resource.get("id") or "")
        if not resource_id:
            continue
        metadata = dict(recorded.get(resource_id) or {})
        metadata.update(resource.get("metadata") or {})
        display_name = _created_network_name(metadata)
        names.setdefault(resource_id, display_name)
        if any(row.get("id") == resource_id for row in inventory):
            continue
        cidrs = list(network_cidrs.get(resource_id) or [])
        inventory.append(
            {
                "id": resource_id,
                "name": display_name,
                "label": _network_label(display_name, cidrs),
                "subnet_cidrs": cidrs,
                "subnet_summary": " / ".join(cidrs)
                if cidrs
                else "No subnet CIDR recorded",
                "role": _project_role_label(metadata.get("role")),
                "external": False,
                "shared": False,
                "network_type": metadata.get("network_type"),
                "physical_network": metadata.get("physical_network"),
                "segmentation_id": metadata.get("segmentation_id"),
                "mtu": metadata.get("mtu"),
                "availability_zone_hints": list(
                    metadata.get("availability_zone_hints") or []
                ),
                "availability_zones": list(
                    metadata.get("neutron_availability_zones") or []
                ),
                "az_placement": metadata.get("neutron_az_placement") or {},
                "source": "Flux-created network",
                "generation": metadata.get("generation"),
                "group_id": metadata.get("group_id"),
            }
        )
    duplicate_labels = Counter(str(row.get("label") or "") for row in inventory)
    for row in inventory:
        label = str(row.get("label") or "")
        if duplicate_labels[label] > 1 and row.get("generation") is not None:
            row["label"] = f"{label} · generation {row['generation']}"
    inventory.sort(
        key=lambda row: (not bool(row.get("external")), str(row.get("label") or ""))
    )
    return inventory, names


def build_environment_summary(
    *,
    discovery: dict[str, Any],
    zones: set[str],
    host_aliases: list[dict[str, str]],
    resources: list[dict[str, Any]],
    allocation: dict[str, Any],
    network_inventory: list[dict[str, Any]],
    paths: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the compact operator-facing environment inventory."""

    endpoints = []
    for resource in resources:
        if resource.get("resource_type") != "server":
            continue
        metadata = resource.get("metadata") or {}
        endpoints.append(
            {
                "name": resource.get("name"),
                "role": metadata.get("role") or "server",
                "side": metadata.get("endpoint_side"),
                "zone": metadata.get("availability_zone"),
                "requested_host": metadata.get("requested_host"),
                "group_id": metadata.get("group_id"),
                "cleanup_state": resource.get("cleanup_state"),
            }
        )

    discovered_subnet_ids = {
        str(item.get("id"))
        for item in (discovery.get("subnets") or [])
        if isinstance(item, dict) and item.get("id")
    }
    created_subnet_ids = {
        str(resource.get("id"))
        for resource in resources
        if resource.get("resource_type") == "subnet" and resource.get("id")
    }
    discovered_subnet_count = len(discovered_subnet_ids) or int(
        discovery.get("subnet_count") or 0
    )
    created_subnet_count = len(created_subnet_ids)
    total_subnet_count = len(discovered_subnet_ids | created_subnet_ids)
    if not discovered_subnet_ids:
        total_subnet_count = discovered_subnet_count + created_subnet_count

    return {
        "cloud": discovery.get("cloud"),
        "region_name": discovery.get("region_name"),
        "project_name": discovery.get("project_name"),
        "zones": sorted(zones),
        "hosts": host_aliases,
        "host_count": sum(
            1 for host in host_aliases if host["alias"] not in {"runner", "localhost"}
        ),
        "control_host_count": sum(
            1 for host in host_aliases if host["alias"] in {"runner", "localhost"}
        ),
        "networks": network_inventory,
        "network_count": len(network_inventory),
        "subnet_count": total_subnet_count,
        "discovered_subnet_count": discovered_subnet_count,
        "created_subnet_count": created_subnet_count,
        "subnet_pools": allocation.get("subnet_pools") or [],
        "subnet_pool_count": len(allocation.get("subnet_pools") or []),
        "address_scopes": allocation.get("address_scopes") or [],
        "address_scope_count": len(allocation.get("address_scopes") or []),
        "subnets": allocation.get("subnets") or [],
        "endpoints": endpoints,
        "endpoint_count": sum(
            1 for endpoint in endpoints if endpoint["role"] == "endpoint"
        ),
        "path_count": len(paths),
        "measured_path_count": sum(
            1 for path in paths if path.get("is_measurement_path")
        ),
        "address_families": sorted(
            {path["family_label"] for path in paths if path.get("family")}
        ),
    }


__all__ = ["build_environment_summary", "build_network_inventory"]
