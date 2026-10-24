from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
from typing import Any

from .config import Config
from .errors import CommandError, CommandTimeoutError, SuiteError
from .log import Logger
from .models import Discovery, NetworkInfo, PoolInfo, QuotaInfo, SegmentInfo, SubnetInfo
from .openstack import OpenStack
from .scheduling import READ_WORKERS, bounded_map
from .utils import list_value, optional_text, pick


class Discoverer:
    def __init__(self, osc: OpenStack, logger: Logger, config: Config | None = None):
        self.osc = osc
        self.logger = logger
        self.config = config

    def _external_subnet_details(self, network_id: str) -> list[dict[str, Any]]:
        rows = (
            self.osc.json("subnet", "list", "--network", network_id, check=False) or []
        )
        details: list[dict[str, Any]] = []
        for row in rows if isinstance(rows, list) else []:
            subnet_id = str(pick(row, "id", default="") or "")
            if not subnet_id:
                continue
            detail = self.osc.json("subnet", "show", subnet_id, check=False) or row
            if isinstance(detail, dict):
                details.append(detail)
        return details

    def _external_network_details(
        self, item: tuple[dict[str, Any], str]
    ) -> tuple[dict[str, Any], list[tuple[str, dict[str, Any]]] | None]:
        row, network_id = item
        detail = self.osc.json("network", "show", network_id) or row
        segment_rows = self._network_segment_rows(network_id)
        segments: list[tuple[str, dict[str, Any]]] | None = None
        if isinstance(segment_rows, list):
            segments = []
            for segment_row in segment_rows:
                segment_id = str(pick(segment_row, "id", default="") or "")
                if segment_id:
                    segments.append(
                        (
                            segment_id,
                            self.osc.json(
                                "network", "segment", "show", segment_id, check=False
                            )
                            or segment_row,
                        )
                    )
        return detail, segments

    def _project_inventory(self, kind: str) -> Any:
        if kind == "scopes":
            return self.osc.json("address", "scope", "list") or []
        if kind == "extensions":
            return self.osc.json("extension", "list", "--network", check=False) or []
        return (
            self.osc.json("quota", "show", "--usage", check=False)
            or self.osc.json("quota", "show", check=False)
            or {}
        )

    def _network_segment_rows(self, network_id: str) -> list[dict[str, Any]] | None:
        """Return segment inventory when the optional Neutron API is available."""
        try:
            rows = self.osc.json(
                "network",
                "segment",
                "list",
                "--network",
                network_id,
                check=False,
            )
        except CommandError as exc:
            detail_text = (exc.stderr or exc.stdout or str(exc)).lower()
            result = subprocess.CompletedProcess(
                exc.command, exc.returncode, exc.stdout, exc.stderr
            )
            optional_segment_api = self.osc.is_unsupported_result(result) or (
                "404" in detail_text
                and any(
                    marker in detail_text
                    for marker in (
                        "the resource could not be found",
                        "resource could not be found",
                        "notfoundexception",
                    )
                )
            )
            if not optional_segment_api:
                raise
            self.logger.log(
                f"Neutron segment inventory is unavailable for network {network_id}; "
                "using provider fields from network show instead",
                "WARNING",
            )
            return None
        if rows is None:
            return None
        if not isinstance(rows, list):
            self.logger.log(
                f"Neutron segment inventory returned an unexpected payload for network {network_id}; "
                "using provider fields from network show instead",
                "WARNING",
            )
            return None
        return [row for row in rows if isinstance(row, dict)]

    def discover(self) -> Discovery:
        self.logger.section("Discovering OpenStack project and external networking")
        token = self.osc.json("token", "issue") or {}
        project_id = str(
            pick(
                token,
                "project_id",
                "project id",
                default=os.getenv("OS_PROJECT_ID", ""),
            )
            or ""
        )
        project_name = str(
            os.getenv("OS_PROJECT_NAME")
            or pick(token, "project_name", default=project_id)
            or project_id
        )
        cloud = os.getenv("OS_CLOUD")
        region_name = self._region_name()

        external_rows = self.osc.json("network", "list", "--external") or []
        if not isinstance(external_rows, list):
            external_rows = []

        # Classify provider subnet pools from every visible external network
        # before include/exclude selection is applied. Selection determines what
        # gets tested; it must not change what a subnet pool fundamentally is.
        external_subnet_cache: dict[str, list[dict[str, Any]]] = {}
        provider_pool_ids: set[str] = set()
        inventory_network_ids = []
        for row in external_rows:
            if not isinstance(row, dict):
                continue
            inventory_network_id = str(pick(row, "id", default="") or "")
            if inventory_network_id:
                inventory_network_ids.append(inventory_network_id)
        inventories = bounded_map(
            self._external_subnet_details,
            inventory_network_ids,
            workers=READ_WORKERS,
        )
        for inventory_network_id, details in zip(
            inventory_network_ids, inventories, strict=True
        ):
            for subnet_detail in details:
                pool_id = pick(
                    subnet_detail,
                    "subnetpool_id",
                    "subnet_pool_id",
                    default=None,
                )
                if pool_id:
                    provider_pool_ids.add(str(pool_id))
            external_subnet_cache[inventory_network_id] = details

        network_rows = self._select_external_network_rows(external_rows)
        networks: list[NetworkInfo] = []
        subnets: list[SubnetInfo] = []
        segments: list[SegmentInfo] = []

        selected_networks = []
        for row in network_rows:
            network_id = optional_text(pick(row, "id"))
            if not network_id:
                self.logger.log(
                    "Skipping external network row without an ID", "WARNING"
                )
                continue
            selected_networks.append((row, network_id))
        network_details = bounded_map(
            self._external_network_details, selected_networks, workers=READ_WORKERS
        )
        for (_, network_id), (detail, segment_rows) in zip(
            selected_networks, network_details, strict=True
        ):
            network_segments: list[SegmentInfo] = []
            if isinstance(segment_rows, list):
                for segment_id, segment_detail in segment_rows:
                    segment = SegmentInfo(
                        id=segment_id,
                        network_id=network_id,
                        name=str(pick(segment_detail, "name", default="") or "")
                        or None,
                        network_type=pick(
                            segment_detail,
                            "network_type",
                            "provider_network_type",
                        ),
                        physical_network=pick(
                            segment_detail,
                            "physical_network",
                            "provider_physical_network",
                        ),
                        segmentation_id=pick(
                            segment_detail,
                            "segmentation_id",
                            "provider_segmentation_id",
                        ),
                        raw=segment_detail,
                    )
                    network_segments.append(segment)
                    segments.append(segment)
            network = NetworkInfo(
                id=network_id,
                name=str(pick(detail, "name", default=network_id)),
                external=bool(
                    pick(detail, "router_external", "external", default=True)
                ),
                shared=bool(pick(detail, "shared", default=False)),
                network_type=pick(
                    detail,
                    "provider_network_type",
                    "network_type",
                ),
                physical_network=pick(
                    detail,
                    "provider_physical_network",
                    "physical_network",
                ),
                segmentation_id=pick(
                    detail,
                    "provider_segmentation_id",
                    "segmentation_id",
                ),
                mtu=(
                    int(pick(detail, "mtu"))
                    if pick(detail, "mtu") not in (None, "")
                    else None
                ),
                port_security_enabled=pick(detail, "port_security_enabled"),
                raw=detail,
                segment_ids=[item.id for item in network_segments],
            )
            networks.append(network)

            for subnet_detail in external_subnet_cache.get(network_id, []):
                subnet_id = str(pick(subnet_detail, "id", default="") or "")
                cidr = str(pick(subnet_detail, "subnet", "cidr", default="") or "")
                if not cidr:
                    self.logger.log(
                        f"Skipping subnet {subnet_id}: no CIDR",
                        "WARNING",
                    )
                    continue
                pool_id = pick(
                    subnet_detail,
                    "subnetpool_id",
                    "subnet_pool_id",
                    default=None,
                )
                pool_id = str(pool_id) if pool_id else None
                segment_id = pick(subnet_detail, "segment_id")
                service_types = [
                    str(item).strip()
                    for item in list_value(
                        pick(
                            subnet_detail,
                            "service_types",
                            "service types",
                            default=[],
                        )
                    )
                    if str(item).strip()
                ]
                subnet = SubnetInfo(
                    id=subnet_id,
                    name=str(pick(subnet_detail, "name", default=subnet_id)),
                    network_id=network_id,
                    cidr=cidr,
                    ip_version=int(
                        pick(
                            subnet_detail,
                            "ip_version",
                            default=ipaddress.ip_network(cidr).version,
                        )
                    ),
                    gateway_ip=(
                        str(pick(subnet_detail, "gateway_ip"))
                        if pick(subnet_detail, "gateway_ip")
                        else None
                    ),
                    dhcp_enabled=bool(
                        pick(
                            subnet_detail,
                            "enable_dhcp",
                            "dhcp_enabled",
                            default=False,
                        )
                    ),
                    allocation_pools=list_value(
                        pick(subnet_detail, "allocation_pools", default=[])
                    ),
                    subnetpool_id=pool_id,
                    ipv6_address_mode=pick(
                        subnet_detail,
                        "ipv6_address_mode",
                    ),
                    ipv6_ra_mode=pick(subnet_detail, "ipv6_ra_mode"),
                    dns_nameservers=[
                        str(item)
                        for item in list_value(
                            pick(
                                subnet_detail,
                                "dns_nameservers",
                                default=[],
                            )
                        )
                    ],
                    # Retained as an empty compatibility field for callers that
                    # deserialize SubnetInfo. Flux must not infer an operator
                    # network role from the numeric prefix.
                    address_class="",
                    raw=subnet_detail,
                    segment_id=str(segment_id) if segment_id else None,
                    service_types=service_types,
                )
                subnets.append(subnet)

        occupied_cidrs = {item.cidr for item in subnets}
        all_subnet_rows = self.osc.json("subnet", "list", "--long", check=False) or []
        if isinstance(all_subnet_rows, list):

            def subnet_cidr(row: dict[str, Any]) -> str | None:
                cidr = pick(row, "subnet", "cidr")
                if not cidr:
                    subnet_id = str(pick(row, "id", default="") or "")
                    detail = (
                        self.osc.json(
                            "subnet",
                            "show",
                            subnet_id,
                            check=False,
                        )
                        if subnet_id
                        else None
                    )
                    cidr = pick(detail or {}, "subnet", "cidr")
                return str(cidr) if cidr else None

            for cidr in bounded_map(subnet_cidr, all_subnet_rows, workers=READ_WORKERS):
                if cidr:
                    occupied_cidrs.add(cidr)

        pool_rows = self.osc.json("subnet", "pool", "list", "--long") or []
        pools: list[PoolInfo] = []
        selected_pools = []
        for row in pool_rows:
            pool_id = optional_text(pick(row, "id"))
            if not pool_id:
                self.logger.log("Skipping subnet pool row without an ID", "WARNING")
                continue
            selected_pools.append((row, pool_id))
        pool_details = bounded_map(
            lambda item: self.osc.json("subnet", "pool", "show", item[1]) or item[0],
            selected_pools,
            workers=READ_WORKERS,
        )
        for (_, pool_id), detail in zip(selected_pools, pool_details, strict=True):
            ip_version = int(pick(detail, "ip_version", default=4))
            default_length = int(
                pick(
                    detail,
                    "default_prefix_length",
                    "default_prefixlen",
                    default=24 if ip_version == 4 else 64,
                )
            )
            min_length = int(
                pick(
                    detail,
                    "min_prefix_length",
                    "min_prefixlen",
                    default=default_length,
                )
            )
            max_length = int(
                pick(
                    detail,
                    "max_prefix_length",
                    "max_prefixlen",
                    default=default_length,
                )
            )
            scope_id = pick(detail, "address_scope_id")
            pools.append(
                PoolInfo(
                    id=pool_id,
                    name=str(pick(detail, "name", default=pool_id)),
                    ip_version=ip_version,
                    address_scope_id=str(scope_id) if scope_id else None,
                    prefixes=[
                        str(item)
                        for item in list_value(pick(detail, "prefixes", default=[]))
                    ],
                    default_prefix_length=default_length,
                    min_prefix_length=min_length,
                    max_prefix_length=max_length,
                    shared=bool(pick(detail, "shared", default=False)),
                    project_id=(
                        str(pick(detail, "project_id"))
                        if pick(detail, "project_id")
                        else None
                    ),
                    provider_pool=pool_id in provider_pool_ids,
                    raw=detail,
                )
            )

        pool_map = {pool.id: pool for pool in pools}
        for subnet in subnets:
            pool = pool_map.get(subnet.subnetpool_id or "")
            subnet.address_scope_id = pool.address_scope_id if pool else None

        scopes, extension_rows, quotas = bounded_map(
            self._project_inventory,
            ("scopes", "extensions", "quotas"),
            workers=READ_WORKERS,
        )
        network_extensions = (
            sorted(
                {
                    str(
                        pick(
                            item,
                            "alias",
                            "name",
                            default="",
                        )
                        or ""
                    )
                    .strip()
                    .lower()
                    for item in extension_rows
                    if str(
                        pick(
                            item,
                            "alias",
                            "name",
                            default="",
                        )
                        or ""
                    ).strip()
                }
            )
            if isinstance(extension_rows, list)
            else []
        )
        quotas = self._quota_payload(quotas)
        quota_info = self._quota_info(quotas)
        discovery = Discovery(
            project_id=project_id,
            project_name=project_name,
            cloud=cloud,
            region_name=region_name,
            networks=networks,
            subnets=subnets,
            pools=pools,
            address_scopes=scopes,
            quotas=quotas if isinstance(quotas, dict) else {},
            segments=segments,
            quota_info=quota_info,
            occupied_cidrs=sorted(occupied_cidrs),
            network_extensions=network_extensions,
        )
        self._print_summary(discovery)
        return discovery

    def _region_name(self) -> str | None:
        """Capture the effective region during discovery, never during replay.

        Request just the region column, so credentials cannot enter the report.
        Missing optional CLI metadata must not prevent network discovery.
        """
        fallback = os.getenv("OS_REGION_NAME", "").strip() or None
        try:
            response = self.osc.run(
                "configuration",
                "show",
                "-c",
                "region_name",
                "-f",
                "json",
                check=False,
                timeout=15,
            )
            value = json.loads(response.stdout) if response.returncode == 0 else None
        except (
            CommandError,
            CommandTimeoutError,
            subprocess.TimeoutExpired,
            json.JSONDecodeError,
        ):
            return fallback
        if isinstance(value, dict):
            region = value.get("region_name")
            if isinstance(region, str) and region.strip():
                return region.strip()
        return fallback

    @staticmethod
    def _row_identity(row: dict[str, Any]) -> tuple[str, str]:
        network_id = str(pick(row, "id", default="") or "")
        network_name = str(pick(row, "name", default=network_id) or network_id)
        return network_id, network_name

    def _select_external_network_rows(
        self, external_rows: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        include = list(self.config.external_networks) if self.config else []
        exclude = list(self.config.exclude_external_networks) if self.config else []

        # Preserve OpenStack discovery order while eliminating duplicate rows.
        external_by_id: dict[str, dict[str, Any]] = {}
        external_order: list[str] = []
        for row in external_rows:
            if not isinstance(row, dict):
                continue
            network_id, _ = self._row_identity(row)
            if not network_id or network_id in external_by_id:
                continue
            external_by_id[network_id] = row
            external_order.append(network_id)

        if exclude:
            raise SuiteError(
                "plan and run require an explicit external network list; "
                "exclusion-only selection is not supported"
            )
        if not include:
            raise SuiteError(
                "No external networks were explicitly selected. Supply --external-networks "
                "with comma-separated network names or UUIDs."
            )
        if not external_order:
            raise SuiteError("No OpenStack-visible external networks were discovered")

        all_rows = self.osc.json("network", "list", check=False) or []
        if not isinstance(all_rows, list):
            all_rows = []
        # Include the external rows even when a restrictive policy or older
        # client returns incomplete data for the unrestricted list operation.
        combined_by_id: dict[str, dict[str, Any]] = {}
        for row in [*all_rows, *external_rows]:
            if not isinstance(row, dict):
                continue
            network_id, _ = self._row_identity(row)
            if network_id:
                combined_by_id.setdefault(network_id, row)

        name_index: dict[str, list[str]] = {}
        for network_id, row in combined_by_id.items():
            _, name = self._row_identity(row)
            name_index.setdefault(name, []).append(network_id)

        def resolve(reference: str) -> str:
            if reference in combined_by_id:
                matched_id = reference
            else:
                matches = name_index.get(reference, [])
                if not matches:
                    raise SuiteError(
                        f"Configured external network {reference!r} was not found "
                        "among OpenStack-visible networks"
                    )
                if len(matches) > 1:
                    raise SuiteError(
                        f"Configured external network name {reference!r} is ambiguous; "
                        f"matching IDs: {', '.join(sorted(matches))}. Use a network UUID."
                    )
                matched_id = matches[0]
            if matched_id not in external_by_id:
                _, name = self._row_identity(combined_by_id[matched_id])
                raise SuiteError(
                    f"Configured network {name!r} ({matched_id}) is not external"
                )
            return matched_id

        configured = include
        resolved: list[str] = []
        seen: set[str] = set()
        for reference in configured:
            network_id = resolve(reference)
            if network_id in seen:
                continue
            seen.add(network_id)
            resolved.append(network_id)

        selected_ids = resolved
        mode = "explicit"
        self.logger.log(
            "External network selection: explicit list; only requested networks will be tested"
        )

        if not selected_ids:
            raise SuiteError(
                "External network selection removed every discovered external network"
            )

        self.logger.log(f"External network selection mode: {mode}")
        self.logger.log(
            "Selected external networks: "
            + ", ".join(
                f"{self._row_identity(external_by_id[item])[1]} ({item})"
                for item in selected_ids
            )
        )
        return [external_by_id[item] for item in selected_ids]

    @staticmethod
    def _quota_payload(quotas: Any) -> dict[str, Any]:
        """Accept OSC's legacy ShowOne and current Lister JSON shapes."""

        def normalize(row: dict[str, Any]) -> dict[str, Any]:
            return {
                re.sub(r"[\s-]+", "_", str(key).strip().lower()): value
                for key, value in row.items()
            }

        if isinstance(quotas, dict):
            return normalize(quotas)
        if not isinstance(quotas, list):
            return {}
        output: dict[str, Any] = {}
        for raw in quotas:
            if not isinstance(raw, dict):
                raise SuiteError("OpenStack quota inventory contains a malformed row")
            row = normalize(raw)
            resource = optional_text(row.get("resource"))
            if not resource:
                raise SuiteError("OpenStack quota inventory row has no resource name")
            resource = re.sub(r"[\s-]+", "_", resource.lower())
            if resource in output:
                raise SuiteError(
                    f"OpenStack quota inventory repeats resource {resource}"
                )
            output[resource] = row
        return output

    @staticmethod
    def _quota_info(quotas: Any) -> dict[str, QuotaInfo]:
        quotas = Discoverer._quota_payload(quotas)
        output: dict[str, QuotaInfo] = {}
        aliases = {
            "instances": ("instances",),
            "cores": ("cores",),
            "ram": ("ram",),
            "ports": ("ports",),
            "networks": ("networks",),
            "subnets": ("subnets",),
            "routers": ("routers",),
            "floating_ips": ("floating_ips", "floating-ips"),
            "security_groups": (
                "secgroups",
                "security_groups",
                "security_group",
            ),
            "security_group_rules": (
                "secgroup_rules",
                "secgroup_rule",
                "security_group_rules",
                "security_group_rule",
            ),
            "volumes": ("volumes",),
            "gigabytes": ("gigabytes",),
            "key_pairs": ("key_pairs", "key-pairs"),
        }
        normalized = quotas
        usage = normalized.get("usage")
        reservation = normalized.get("reservation", normalized.get("reserved"))
        usage = Discoverer._quota_payload(usage) if isinstance(usage, dict) else {}
        reservation = (
            Discoverer._quota_payload(reservation)
            if isinstance(reservation, dict)
            else {}
        )

        def integer(value: Any) -> int | None:
            if value in (None, "") or isinstance(value, (bool, float)):
                return None
            try:
                return int(value)
            except (TypeError, ValueError):
                return None

        for resource, keys in aliases.items():
            selected = next((key for key in keys if key in normalized), None)
            value = normalized.get(selected) if selected else None
            limit: int | None = None
            used: int | None = None
            reserved = 0
            if isinstance(value, dict):
                value = Discoverer._quota_payload(value)
                raw_limit = value.get("limit")
                raw_used = value.get("in_use", value.get("used"))
                limit = integer(raw_limit)
                used = integer(raw_used)
                reserved_value = integer(value.get("reserved", 0))
            elif value not in (None, ""):
                limit = integer(value)
                used = integer(usage.get(selected)) if selected else None
                reserved_value = (
                    integer(reservation.get(selected, 0)) if selected else 0
                )
            else:
                reserved_value = 0
            if (
                reserved_value is None
                or reserved_value < 0
                or (used is not None and used < 0)
            ):
                used = None
            else:
                reserved = reserved_value
            output[resource] = QuotaInfo(resource, limit, used, reserved)
        return output

    def _print_summary(self, discovery: Discovery) -> None:
        self.logger.log(f"Project: {discovery.project_name} ({discovery.project_id})")
        self.logger.log(f"OpenStack adapter: {self.osc.backend_name}")
        group_names: dict[str, str] = {}
        for item in discovery.address_scopes:
            if not isinstance(item, dict):
                continue
            scope_id = optional_text(pick(item, "id"))
            if not scope_id:
                continue
            group_names[scope_id] = (
                optional_text(pick(item, "name", default=scope_id)) or scope_id
            )

        def routing_metadata_text(group_id: str | None) -> str:
            if not group_id:
                return "Unassigned"
            name = group_names.get(group_id)
            return f"Assigned ({name})" if name else "Assigned"

        for network in discovery.networks:
            families = sorted(
                {s.ip_version for s in discovery.subnets_for_network(network.id)}
            )
            self.logger.log(
                f"External network {network.name} ({network.id}): "
                f"type={network.network_type or 'unknown'}, physnet={network.physical_network or 'none'}, "
                f"segments={len(network.segment_ids) or 1}, families={','.join('IPv' + str(x) for x in families) or 'none'}"
            )
            for subnet in discovery.subnets_for_network(network.id):
                addressing = (
                    "automatic IPv6"
                    if subnet.ip_version == 6
                    and (subnet.ipv6_address_mode or subnet.ipv6_ra_mode)
                    else "explicit fixed address"
                )
                self.logger.log(
                    f"  subnet {subnet.name}: {subnet.cidr}, gateway={subnet.gateway_ip or 'none'}, "
                    f"routing metadata: {routing_metadata_text(subnet.address_scope_id)}, "
                    f"segment={subnet.segment_id or 'default'}, "
                    f"addressing={addressing}, "
                    f"service_types={','.join(subnet.service_types) if subnet.service_types else 'unrestricted'}"
                )
        for pool in discovery.pools:
            self.logger.log(
                f"Subnet pool {pool.name} ({pool.id}): IPv{pool.ip_version}, "
                f"routing metadata: {routing_metadata_text(pool.address_scope_id)}, "
                "observed facts: "
                f"backs_visible_external_subnet={pool.provider_pool}, "
                f"shared={pool.shared}, default={pool.is_default}"
            )
