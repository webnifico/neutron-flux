from __future__ import annotations

import ipaddress
from collections import defaultdict
from typing import Any

_ONE_ROUTER_ROLES = {"one-router-project-networks", "tenant-router-pair"}
_TWO_ROUTER_ROLES = {"two-router-static-routing", "extra-route-pair"}


def _project_role_label(role: Any) -> str:
    value = str(role or "").lower()
    if value == "management":
        return "Flux management network"
    if value in {
        "project-network",
        "routing-unassigned-project-network",
        "tenant-pool",
        "tenant-no-routing-group",
    }:
        return "Project network"
    if value == "private-translation-project-network":
        return "Flux-created private network used only for IPv4 translation tests"
    if value in {"one-router-project-networks", "tenant-router-pair"}:
        return "Project network used by the one-router test suite"
    if value in {"two-router-static-routing", "extra-route-pair"}:
        return "Project network used by the static-route test suite"
    if value == "transit":
        return "Transit network used by the static-route test suite"
    if value:
        return value.replace("tenant", "project").replace("-", " ").title()
    return "Project network"


def _network_label(name: Any, cidrs: list[str] | tuple[str, ...] | None = None) -> str:
    base = str(name or "Network").strip() or "Network"
    values = [str(value) for value in (cidrs or []) if value]
    return f"{base} — {' / '.join(values)}" if values else base


def _network_cidrs(allocation: dict[str, Any]) -> dict[str, list[str]]:
    output: dict[str, list[str]] = defaultdict(list)
    for subnet in allocation.get("subnets") or []:
        network_id = str(subnet.get("network_id") or "")
        cidr = str(subnet.get("cidr") or "")
        if network_id and cidr and cidr not in output[network_id]:
            output[network_id].append(cidr)
    for values in output.values():
        values.sort(key=lambda value: (":" in value, value))
    return dict(output)


def _network_role(network: dict[str, Any]) -> str:
    external = network.get("external")
    if external is None:
        raw = network.get("raw") or {}
        external = raw.get("router:external")
    network_type = str(
        network.get("network_type")
        or (network.get("raw") or {}).get("provider:network_type")
        or ""
    )
    if external and network_type:
        return "External provider network"
    if external:
        return "External network"
    if network_type:
        return "Provider network"
    if network.get("shared"):
        return "Shared project network"
    return "Project network"


def _allocation_model(
    payload: dict[str, Any], resources: list[dict[str, Any]]
) -> dict[str, Any]:
    plan = payload.get("plan") or {}
    discovery = payload.get("discovery") or {}
    group_rows = list(
        plan.get("project_network_groups") or plan.get("tenant_groups") or []
    )
    pools: dict[str, dict[str, Any]] = {}
    scopes: dict[str, dict[str, Any]] = {}

    for group in group_rows:
        pool_id = str(group.get("pool_id") or "")
        if not pool_id:
            continue
        family = int((group.get("families") or [0])[0] or 0)
        pool = pools.setdefault(
            pool_id,
            {
                "id": pool_id,
                "name": group.get("pool_name") or pool_id,
                "family": family,
                "family_label": f"IPv{family}" if family else "IP family unavailable",
                "address_scope_id": group.get("address_scope_id"),
                "allocation_prefix_lengths": set(),
                "allocated_subnets": [],
                "topology_uses": set(),
                "source": "OpenStack subnet pool",
            },
        )
        if group.get("prefix_length") is not None:
            pool["allocation_prefix_lengths"].add(int(group["prefix_length"]))
        pool["topology_uses"].add(_project_role_label(group.get("kind")))
        scope_id = str(group.get("address_scope_id") or "")
        if scope_id:
            scope = scopes.setdefault(
                scope_id,
                {
                    "id": scope_id,
                    "name": f"IPv{family} address scope" if family else "Address scope",
                    "families": set(),
                    "subnet_pool_ids": set(),
                },
            )
            if family:
                scope["families"].add(family)
            scope["subnet_pool_ids"].add(pool_id)

    subnets: list[dict[str, Any]] = []
    for resource in resources:
        if resource.get("resource_type") != "subnet":
            continue
        metadata = resource.get("metadata") or {}
        pool_id = str(metadata.get("pool_id") or "")
        row = {
            "id": resource.get("id"),
            "name": resource.get("name") or resource.get("id"),
            "cidr": metadata.get("cidr"),
            "network_id": resource.get("parent_id"),
            "subnet_pool_id": pool_id or None,
            "address_scope_id": metadata.get("scope_id")
            or metadata.get("routing_group_id"),
            "allocation_method": (
                "Automatically allocated by Neutron from a subnet pool"
                if pool_id
                else "Explicitly configured CIDR"
            ),
            "requested_prefix_length": (
                int(str(metadata.get("cidr")).split("/")[-1])
                if metadata.get("cidr") and "/" in str(metadata.get("cidr"))
                else None
            ),
            "group_id": metadata.get("group_id"),
            "scenario_side": metadata.get("scenario_side"),
            "availability_zone": metadata.get("availability_zone"),
            "gateway_ip": metadata.get("gateway_ip"),
            "gateway_disabled": bool(metadata.get("gateway_disabled", False)),
            "gateway_ip_source": (
                "Recorded from Neutron" if metadata.get("gateway_ip") else None
            ),
            "allocation_pools": metadata.get("allocation_pools") or [],
            "source": "Flux-created subnet",
        }
        subnets.append(row)
        if pool_id and pool_id in pools:
            pools[pool_id]["allocated_subnets"].append(row)

    for subnet in discovery.get("subnets") or []:
        subnetpool_id = str(subnet.get("subnetpool_id") or "")
        row = {
            "id": subnet.get("id"),
            "name": subnet.get("name") or subnet.get("id"),
            "cidr": subnet.get("cidr"),
            "network_id": subnet.get("network_id"),
            "subnet_pool_id": subnetpool_id or None,
            "address_scope_id": subnet.get("address_scope_id"),
            "allocation_method": (
                "Allocated from an OpenStack subnet pool"
                if subnetpool_id
                else "Existing explicitly configured CIDR"
            ),
            "requested_prefix_length": (
                int(str(subnet.get("cidr")).split("/")[-1])
                if subnet.get("cidr") and "/" in str(subnet.get("cidr"))
                else None
            ),
            "gateway_ip": subnet.get("gateway_ip"),
            "gateway_disabled": not bool(subnet.get("gateway_ip")),
            "gateway_ip_source": (
                "Recorded from Neutron"
                if subnet.get("gateway_ip")
                else "No gateway configured"
            ),
            "allocation_pools": subnet.get("allocation_pools") or [],
            "source": "Discovered existing subnet",
        }
        subnets.append(row)
        if subnetpool_id and subnetpool_id in pools:
            pools[subnetpool_id]["allocated_subnets"].append(row)

    # Merge duplicate journal/discovery rows for the same OpenStack subnet,
    # preferring the richest recorded metadata. Missing gateway values stay
    # missing: the report must not reconstruct them from a CIDR.
    merged_subnets: dict[str, dict[str, Any]] = {}
    for subnet in subnets:
        key = str(
            subnet.get("id") or f"{subnet.get('network_id')}:{subnet.get('cidr')}"
        )
        existing = merged_subnets.get(key)
        if existing is None:
            merged_subnets[key] = dict(subnet)
            continue
        for field, value in subnet.items():
            if value not in (None, "", [], {}) and existing.get(field) in (
                None,
                "",
                [],
                {},
            ):
                existing[field] = value
    subnets = list(merged_subnets.values())
    # Rebuild pool allocations after subnet de-duplication.
    for pool in pools.values():
        pool["allocated_subnets"] = [
            subnet
            for subnet in subnets
            if str(subnet.get("subnet_pool_id") or "") == str(pool.get("id") or "")
        ]

    pool_rows = []
    for pool in pools.values():
        pool["allocation_prefix_lengths"] = sorted(pool["allocation_prefix_lengths"])
        pool["topology_uses"] = sorted(pool["topology_uses"])
        pool["allocated_subnet_count"] = len(pool["allocated_subnets"])
        pool["run_allocation_footprint"] = [
            row.get("cidr") for row in pool["allocated_subnets"] if row.get("cidr")
        ]
        pool_rows.append(pool)
    pool_rows.sort(key=lambda row: (row.get("family") or 0, str(row.get("name") or "")))

    scope_rows = []
    for scope in scopes.values():
        scope["families"] = sorted(scope["families"])
        scope["subnet_pool_ids"] = sorted(scope["subnet_pool_ids"])
        scope_rows.append(scope)
    scope_rows.sort(key=lambda row: str(row.get("name") or ""))
    output = {
        "subnet_pools": pool_rows,
        "address_scopes": scope_rows,
        "subnets": subnets,
    }
    output["network_cidrs"] = _network_cidrs(output)
    return output


def _attach_path_allocation_context(
    paths: list[dict[str, Any]],
    allocation: dict[str, Any],
    network_names: dict[str, str] | None = None,
) -> None:
    pools = {
        str(row.get("id") or ""): row for row in allocation.get("subnet_pools") or []
    }
    candidates: list[tuple[ipaddress._BaseNetwork, dict[str, Any]]] = []
    for subnet in allocation.get("subnets") or []:
        cidr = str(subnet.get("cidr") or "")
        if not cidr:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        candidates.append((network, subnet))

    def context(value: Any) -> dict[str, Any] | None:
        try:
            address = ipaddress.ip_address(str(value or ""))
        except ValueError:
            return None
        matches = [
            (network.prefixlen, subnet)
            for network, subnet in candidates
            if network.version == address.version and address in network
        ]
        if not matches:
            return None
        # Prefer the most-specific recorded subnet.  If a run created the same
        # CIDR more than once over time, pool provenance remains identical and
        # the dashboard does not pretend it can identify a deleted generation
        # from an IP address alone.
        _, subnet = sorted(matches, key=lambda item: item[0], reverse=True)[0]
        pool = pools.get(str(subnet.get("subnet_pool_id") or "")) or {}
        network_id = str(subnet.get("network_id") or "")
        network_name = (network_names or {}).get(network_id)
        return {
            "subnet_id": subnet.get("id"),
            "subnet_name": subnet.get("name"),
            "cidr": subnet.get("cidr"),
            "network_id": network_id or None,
            "network_name": network_name,
            "network_label": _network_label(network_name, [subnet.get("cidr")])
            if network_name
            else None,
            "gateway_ip": subnet.get("gateway_ip"),
            "gateway_ip_source": subnet.get("gateway_ip_source"),
            "allocation_method": subnet.get("allocation_method"),
            "subnet_pool_id": subnet.get("subnet_pool_id"),
            "subnet_pool_name": pool.get("name"),
            "address_scope_id": subnet.get("address_scope_id")
            or pool.get("address_scope_id"),
            "requested_prefix_length": subnet.get("requested_prefix_length"),
        }

    for path in paths:
        path["source_addressing"] = context(path.get("source_ip"))
        path["destination_addressing"] = context(path.get("destination_ip"))
        source = path.get("source") or {}
        destination = path.get("destination") or {}
        if path.get("source_addressing") and isinstance(source, dict):
            source["network_label"] = path["source_addressing"].get("network_label")
            source["subnet_cidr"] = path["source_addressing"].get("cidr")
        if path.get("destination_addressing") and isinstance(destination, dict):
            destination["network_label"] = path["destination_addressing"].get(
                "network_label"
            )
            destination["subnet_cidr"] = path["destination_addressing"].get("cidr")
