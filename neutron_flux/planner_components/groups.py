from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Iterator

# mypy: disable-error-code="attr-defined"
from ..errors import UnsupportedTopologyError
from ..models import PlannedGroup, PoolInfo, SubnetInfo
from ..network_contract import (
    FLOATING_IP_TARGET_CONTRACT,
    ONE_ROUTER_PROJECT_NETWORKS,
    PRIVATE_TRANSLATION_PROJECT_NETWORK,
    PROJECT_NETWORK,
    ROUTING_UNASSIGNED_PROJECT_NETWORK,
    TWO_ROUTER_STATIC_ROUTING,
)
from ..policy import TopologyPolicy


class GroupPlannerMixin:
    """Compatibility mixin for this planning concern."""

    def _is_project_usable_pool(self, pool: PoolInfo) -> bool:
        """Return whether API facts allow project subnet allocation from a pool.

        A pool that backs a visible external subnet is normally excluded from
        project-network tests. Neutron can, however, deliberately publish that
        same pool as both shared and default. That explicit combination makes
        the pool dual-use; merely seeing it on an external subnet does not erase
        its project-facing contract.
        """

        accessible = (
            pool.shared
            or not pool.project_id
            or pool.project_id == self.discovery.project_id
        )
        return accessible and (not pool.provider_pool or pool.shared_default)

    def _provider_groups(self, skipped: list[dict[str, str]]) -> list[PlannedGroup]:
        output: list[PlannedGroup] = []
        for network in self.discovery.networks:
            usable: list[SubnetInfo] = []
            for subnet in self.discovery.subnets_for_network(network.id):
                resource = f"{network.name}/{subnet.name}"
                if subnet.ip_version == 6 and (
                    subnet.ipv6_address_mode or subnet.ipv6_ra_mode
                ):
                    skipped.append(
                        {
                            "resource": resource,
                            "reason": (
                                "automatic IPv6 address assignment is configured; "
                                "Neutron Flux tests statically configured IPv6 only"
                            ),
                        }
                    )
                    continue
                if not subnet.has_assignable_addresses:
                    skipped.append(
                        {
                            "resource": resource,
                            "reason": (
                                "the subnet has no allocation pool for disposable "
                                "provider endpoint addresses"
                            ),
                        }
                    )
                    continue
                if not subnet.supports_compute_endpoint:
                    skipped.append(
                        {
                            "resource": resource,
                            "reason": (
                                "subnet service types do not permit compute:nova "
                                "endpoint allocation"
                            ),
                        }
                    )
                    continue
                usable.append(subnet)
            if not usable:
                skipped.append(
                    {
                        "resource": network.name,
                        "reason": "no compute-endpoint-eligible provider subnet",
                    }
                )
                continue
            by_segment: dict[str | None, list[SubnetInfo]] = defaultdict(list)
            for subnet in usable:
                by_segment[subnet.segment_id].append(subnet)
            for segment_id, subnets in sorted(
                by_segment.items(),
                key=lambda item: str(item[0] or ""),
            ):
                segment = self.discovery.segment(segment_id)
                suffix = f"-segment-{segment_id}" if segment_id else ""
                label_suffix = f"/{segment.name or segment.id}" if segment else ""
                output.append(
                    PlannedGroup(
                        id=f"provider-{network.id}{suffix}",
                        kind="provider",
                        label=f"Provider {network.name}{label_suffix}",
                        network_id=network.id,
                        network_name=network.name,
                        subnet_ids=[item.id for item in subnets],
                        families=sorted({item.ip_version for item in subnets}),
                        segment_id=segment_id,
                        physical_network=(
                            segment.physical_network
                            if segment
                            else network.physical_network
                        ),
                        relationship="provider",
                        expected_routing="reachable",
                        metadata={
                            "coverage_scope": "all eligible selected provider subnets",
                            "service_type_policy": "compute:nova or unrestricted",
                        },
                    )
                )
        return output

    def _tenant_groups(
        self,
        providers: list[PlannedGroup],
        skipped: list[dict[str, str]],
    ) -> list[PlannedGroup]:
        candidates = sorted(
            [
                pool
                for pool in self.discovery.pools
                if self._is_project_usable_pool(pool)
            ],
            key=lambda item: (item.ip_version, item.name, item.id),
        )

        gateway_subnets: list[SubnetInfo] = []
        for subnet in self.discovery.subnets:
            automatic_ipv6 = subnet.ip_version == 6 and (
                subnet.ipv6_address_mode or subnet.ipv6_ra_mode
            )
            if automatic_ipv6:
                continue
            if (
                subnet.gateway_ip
                and subnet.has_assignable_addresses
                and subnet.supports_router_gateway
                and self.discovery.network(subnet.network_id).external
            ):
                gateway_subnets.append(subnet)

        output: list[PlannedGroup] = []
        existing_no_group_family: set[int] = set()
        provider_endpoint_subnet_ids = {
            subnet_id for group in providers for subnet_id in group.subnet_ids
        }

        for pool in candidates:
            same_family = [
                item for item in gateway_subnets if item.ip_version == pool.ip_version
            ]
            if not same_family:
                skipped.append(
                    {
                        "resource": pool.name,
                        "reason": (
                            f"no IPv{pool.ip_version} external subnet is eligible "
                            "for a router gateway"
                        ),
                    }
                )
                continue

            for external_subnet in sorted(
                same_family,
                key=lambda item: (
                    self.discovery.network(item.network_id).name,
                    item.name,
                    item.id,
                ),
            ):
                relationship = TopologyPolicy.routing_relationship(
                    pool.address_scope_id,
                    external_subnet.address_scope_id,
                )
                outbound = TopologyPolicy.project_expectation(
                    relationship,
                    pool.ip_version,
                    source_is_project=True,
                )
                inbound = TopologyPolicy.project_expectation(
                    relationship, pool.ip_version
                )
                expected = (
                    outbound.expectation
                    if outbound.expectation == inbound.expectation
                    else "directional-default-snat"
                )
                if relationship == TopologyPolicy.UNASSIGNED:
                    existing_no_group_family.add(pool.ip_version)

                external_network = self.discovery.network(external_subnet.network_id)
                fixed_ip_cross_test_available = (
                    external_subnet.id in provider_endpoint_subnet_ids
                )
                if not fixed_ip_cross_test_available:
                    skipped.append(
                        {
                            "resource": (
                                f"{pool.name} through "
                                f"{external_network.name}/{external_subnet.name}"
                            ),
                            "reason": (
                                "project-network router topology will be created, "
                                "but project/provider fixed-IP validations are omitted "
                                "because the router-gateway subnet is not also "
                                "eligible for a compute:nova provider endpoint"
                            ),
                        }
                    )
                output.append(
                    PlannedGroup(
                        id=(f"project-network-{pool.id}-external-{external_subnet.id}"),
                        kind=PROJECT_NETWORK,
                        label=(
                            f"IPv{pool.ip_version} project network with matching "
                            f"address scope through {external_network.name}"
                            if relationship == TopologyPolicy.DIRECT
                            else f"IPv{pool.ip_version} project network with a "
                            f"different address scope through {external_network.name}"
                            if relationship == TopologyPolicy.ISOLATED
                            else f"IPv{pool.ip_version} project-network connectivity "
                            f"through {external_network.name}"
                        ),
                        network_id=None,
                        network_name=None,
                        subnet_ids=[],
                        families=[pool.ip_version],
                        pool_id=pool.id,
                        pool_name=pool.name,
                        external_network_id=external_network.id,
                        external_network_name=external_network.name,
                        external_subnet_id=external_subnet.id,
                        floating_subnet_id=None,
                        address_scope_id=pool.address_scope_id,
                        prefix_length=self._choose_prefix(pool),
                        relationship=relationship,
                        expected_routing=expected,
                        metadata={
                            "coverage_scope": (
                                "all usable project subnet pools x all same-family "
                                "router-gateway-eligible external subnets"
                            ),
                            "router_gateway_subnet_id": external_subnet.id,
                            "floating_ip_subnet_id": None,
                            "floating_ip_eligible": False,
                            "floating_ip_target_allowed": False,
                            "subnet_pool_fixed_ip_only": True,
                            "routing_policy_outbound": outbound.metadata(),
                            "routing_policy_inbound": inbound.metadata(),
                            "fixed_address_role": "subnet-pool-derived",
                            "routed_fixed_ip_topology": (
                                relationship == TopologyPolicy.DIRECT
                            ),
                            "source_nat_mode": (
                                "cloud-default"
                                if pool.ip_version == 4
                                else "not-applicable"
                            ),
                            "source_nat_controlled_by_flux": False,
                            "source_nat_default_expected": (pool.ip_version == 4),
                            "fixed_ip_cross_test_available": (
                                fixed_ip_cross_test_available
                            ),
                            "router_gateway_service_types": list(
                                external_subnet.service_types
                            ),
                        },
                    )
                )

        if self.config.include_no_routing_group_controls:
            synthetic = self._synthetic_cidrs(gateway_subnets)
            for family in (4, 6):
                if family in existing_no_group_family:
                    continue
                external = next(
                    (item for item in gateway_subnets if item.ip_version == family),
                    None,
                )
                if not external:
                    continue
                cidr = synthetic.get(family)
                if not cidr:
                    skipped.append(
                        {
                            "resource": (f"IPv{family} routing-metadata control"),
                            "reason": (
                                "no non-overlapping OpenStack-visible control "
                                "CIDR was available"
                            ),
                        }
                    )
                    continue
                network = self.discovery.network(external.network_id)
                output.append(
                    PlannedGroup(
                        id=(
                            f"routing-unassigned-project-network-ipv{family}-"
                            f"external-{external.id}"
                        ),
                        kind=ROUTING_UNASSIGNED_PROJECT_NETWORK,
                        label=(
                            "Private IPv6 same-subnet connectivity; external routing not tested"
                            if family == 6
                            else f"IPv{family} project-network connectivity with routing metadata unassigned "
                            f"through {network.name}"
                        ),
                        network_id=None,
                        network_name=None,
                        subnet_ids=[],
                        families=[family],
                        external_network_id=network.id,
                        external_network_name=network.name,
                        external_subnet_id=external.id,
                        floating_subnet_id=None,
                        address_scope_id=None,
                        prefix_length=ipaddress.ip_network(cidr).prefixlen,
                        synthetic_cidr=cidr,
                        relationship=TopologyPolicy.UNASSIGNED,
                        expected_routing=(
                            "directional-default-snat"
                            if family == 4
                            else "not-applicable"
                        ),
                        metadata={
                            "coverage_scope": (
                                "one synthetic routing-metadata-unassigned control per "
                                "family only when discovery has no natural "
                                "unassigned pairing"
                            ),
                            "router_gateway_subnet_id": external.id,
                            "floating_ip_subnet_id": None,
                            "floating_ip_target_allowed": False,
                            "fixed_address_role": "routing-metadata-control",
                            "source_nat_mode": (
                                "cloud-default" if family == 4 else "not-applicable"
                            ),
                            "source_nat_controlled_by_flux": False,
                            "source_nat_default_expected": family == 4,
                        },
                    )
                )
        return output

    def _private_translation_groups(
        self,
        skipped: list[dict[str, str]],
    ) -> list[PlannedGroup]:
        """Plan ordinary IPv4 SNAT/FIP tests on an isolated fixed subnet.

        A subnet allocated from an operator-provided subnet pool can represent
        routed public address space, ordinary project address space, or a role
        that discovery cannot prove.  It is therefore never a floating-IP
        target.  Translation tests instead receive a dedicated, synthetic
        IPv4 subnet whose role is explicit because Flux creates it itself.
        """

        external_subnets = sorted(
            [
                subnet
                for subnet in self.discovery.subnets
                if subnet.ip_version == 4
                and subnet.gateway_ip
                and subnet.has_assignable_addresses
                and subnet.supports_router_gateway
                and self.discovery.network(subnet.network_id).external
            ],
            key=lambda item: (
                self.discovery.network(item.network_id).name,
                item.name,
                item.id,
            ),
        )
        floating_by_network: dict[str, list[SubnetInfo]] = defaultdict(list)
        for subnet in self.discovery.subnets:
            if (
                subnet.ip_version == 4
                and subnet.has_assignable_addresses
                and subnet.supports_floating_ip
                and self.discovery.network(subnet.network_id).external
            ):
                floating_by_network[subnet.network_id].append(subnet)

        cidrs = iter(self._private_translation_ipv4_cidrs())
        output: list[PlannedGroup] = []
        for gateway_subnet in external_subnets:
            network = self.discovery.network(gateway_subnet.network_id)
            floating_candidates = sorted(
                floating_by_network.get(network.id, []),
                key=lambda item: (
                    item.id != gateway_subnet.id,
                    item.name,
                    item.id,
                ),
            )
            if not floating_candidates:
                skipped.append(
                    {
                        "resource": (
                            f"Private IPv4 translation through "
                            f"{network.name}/{gateway_subnet.name}"
                        ),
                        "reason": (
                            "the selected external network has no assignable "
                            "network:floatingip-eligible IPv4 subnet"
                        ),
                    }
                )
                continue
            try:
                cidr = next(cidrs)
            except StopIteration as exc:
                raise UnsupportedTopologyError(
                    "No non-overlapping IPv4 /24 remained for a disposable "
                    "private translation suite"
                ) from exc
            floating_subnet = floating_candidates[0]
            output.append(
                PlannedGroup(
                    id=(f"private-translation-ipv4-external-{gateway_subnet.id}"),
                    kind=PRIVATE_TRANSLATION_PROJECT_NETWORK,
                    label=f"Private IPv4 translation through {network.name}",
                    network_id=None,
                    network_name=None,
                    subnet_ids=[],
                    families=[4],
                    pool_id=None,
                    pool_name=None,
                    external_network_id=network.id,
                    external_network_name=network.name,
                    external_subnet_id=gateway_subnet.id,
                    floating_subnet_id=floating_subnet.id,
                    address_scope_id=None,
                    prefix_length=24,
                    synthetic_cidr=cidr,
                    relationship="private-translation",
                    expected_routing="reachable",
                    metadata={
                        "scenario": PRIVATE_TRANSLATION_PROJECT_NETWORK,
                        "coverage_scope": (
                            "one disposable private IPv4 translation topology "
                            "per router-gateway-eligible selected external subnet"
                        ),
                        "router_gateway_subnet_id": gateway_subnet.id,
                        "floating_ip_subnet_id": floating_subnet.id,
                        "floating_ip_eligible": True,
                        "floating_ip_target_allowed": True,
                        "floating_ip_target_contract": (FLOATING_IP_TARGET_CONTRACT),
                        "floating_ip_endpoint_side": "A",
                        "fixed_address_role": "disposable-private",
                        "source_nat_mode": "cloud-default",
                        "source_nat_controlled_by_flux": False,
                        "source_nat_default_expected": True,
                        "translation_fixed_ip_topology": True,
                        "router_gateway_service_types": list(
                            gateway_subnet.service_types
                        ),
                    },
                )
            )
        return output

    def _private_translation_ipv4_cidrs(self) -> Iterator[str]:
        used = self._synthetic_used_networks()
        for base_text in ("10.128.0.0/12", "192.168.192.0/19"):
            base = ipaddress.ip_network(base_text)
            for candidate in base.subnets(new_prefix=24):
                if not any(
                    candidate.overlaps(item) for item in used if item.version == 4
                ):
                    used.append(candidate)
                    yield str(candidate)

    def _synthetic_used_networks(self) -> list[ipaddress._BaseNetwork]:
        existing = getattr(self, "_reserved_synthetic_networks", None)
        if existing is not None:
            return existing
        used = [
            ipaddress.ip_network(cidr, strict=False)
            for cidr in (
                self.discovery.occupied_cidrs
                or [item.cidr for item in self.discovery.subnets]
            )
        ]
        for pool in self.discovery.pools:
            for prefix in pool.prefixes:
                used.append(ipaddress.ip_network(prefix, strict=False))
        self._reserved_synthetic_networks = used
        return used

    def _routing_scenario_groups(
        self, skipped: list[dict[str, str]], selected_families: set[int]
    ) -> list[PlannedGroup]:
        """Create gateway-independent internal router scenarios in each family."""
        candidates = sorted(
            [
                pool
                for pool in self.discovery.pools
                if self._is_project_usable_pool(pool)
            ],
            key=lambda item: (item.ip_version, item.name, item.id),
        )
        output: list[PlannedGroup] = []
        by_family = {
            family: [item for item in candidates if item.ip_version == family]
            for family in (4, 6)
        }
        static_route_extension_aliases = {
            "extraroute",
            "extraroute-atomic",
            "router-extraroutes",
        }
        extension_discovery_available = bool(self.discovery.network_extensions)
        static_routes_supported = bool(
            static_route_extension_aliases.intersection(
                self.discovery.network_extensions
            )
        )

        for family in (4, 6):
            if family not in selected_families:
                skipped.append(
                    {
                        "resource": f"IPv{family} project-network router scenarios",
                        "reason": (
                            f"IPv{family} internal router coverage was not requested"
                        ),
                    }
                )
                continue
            if not by_family[family]:
                output.extend(
                    self._private_routing_scenario_groups(
                        family,
                        static_routes_supported or not extension_discovery_available,
                    )
                )
                if extension_discovery_available and not static_routes_supported:
                    skipped.append(
                        {
                            "resource": f"IPv{family} two-router static-routing scenario",
                            "reason": "the Neutron router static-route (extraroute API) extension is not available",
                        }
                    )
                continue
            for pool in by_family[family]:
                common = dict(
                    network_id=None,
                    network_name=None,
                    subnet_ids=[],
                    families=[family],
                    pool_id=pool.id,
                    pool_name=pool.name,
                    address_scope_id=pool.address_scope_id,
                    prefix_length=self._choose_prefix(pool),
                    relationship="internal-router",
                    expected_routing="reachable",
                )
                output.append(
                    PlannedGroup(
                        id=(f"one-router-project-networks-ipv{family}-{pool.id}"),
                        kind=ONE_ROUTER_PROJECT_NETWORKS,
                        label=(
                            f"IPv{family} project networks from {pool.name} "
                            "on one Neutron router"
                        ),
                        metadata={
                            "scenario": ONE_ROUTER_PROJECT_NETWORKS,
                            "coverage_scope": "usable project subnet pools in the selected IP families",
                        },
                        **common,
                    )
                )
                if static_routes_supported or not extension_discovery_available:
                    output.append(
                        PlannedGroup(
                            id=(f"two-router-static-routing-ipv{family}-{pool.id}"),
                            kind=TWO_ROUTER_STATIC_ROUTING,
                            label=(
                                f"IPv{family} two-router static-routing "
                                f"topology from {pool.name}"
                            ),
                            metadata={
                                "scenario": TWO_ROUTER_STATIC_ROUTING,
                                "coverage_scope": "usable project subnet pools in the selected IP families",
                                "extension_support": (
                                    "confirmed"
                                    if static_routes_supported
                                    else "not-discoverable"
                                ),
                            },
                            **common,
                        )
                    )
                else:
                    skipped.append(
                        {
                            "resource": (
                                f"{pool.name} IPv{family} two-router "
                                "static-routing scenario"
                            ),
                            "reason": (
                                "the Neutron router static-route (extraroute API) "
                                "extension is not available"
                            ),
                        }
                    )
        return output

    def _private_routing_scenario_groups(
        self, family: int, static_routes: bool
    ) -> list[PlannedGroup]:
        """Allocate disjoint internal prefixes when no project pool is available."""
        used = self._synthetic_used_networks()
        prefix = 24 if family == 4 else 64
        bases = (
            ("10.240.0.0/16", "192.168.224.0/20")
            if family == 4
            else ("fd42:4e46:100::/48", "fd42:4e46:200::/48")
        )
        candidates = (
            candidate
            for base in bases
            for candidate in ipaddress.ip_network(base).subnets(new_prefix=prefix)
        )
        output = []
        for kind, sides in (
            (ONE_ROUTER_PROJECT_NETWORKS, ("a", "b")),
            (TWO_ROUTER_STATIC_ROUTING, ("project-a", "project-b", "transit")),
        ):
            if kind == TWO_ROUTER_STATIC_ROUTING and not static_routes:
                continue
            cidrs = {}
            for side in sides:
                candidate = next(
                    (
                        network
                        for network in candidates
                        if not any(
                            network.overlaps(existing)
                            for existing in used
                            if existing.version == family
                        )
                    ),
                    None,
                )
                if candidate is None:
                    raise UnsupportedTopologyError(
                        f"No disjoint IPv{family} prefix remains for internal routing"
                    )
                used.append(candidate)
                cidrs[side] = str(candidate)
            output.append(
                PlannedGroup(
                    id=f"{kind}-ipv{family}-generated",
                    kind=kind,
                    label=f"IPv{family} {'one-router' if kind == ONE_ROUTER_PROJECT_NETWORKS else 'two-router static'} private fixed-IP routing",
                    network_id=None,
                    network_name=None,
                    subnet_ids=[],
                    families=[family],
                    prefix_length=prefix,
                    relationship="internal-router",
                    expected_routing="reachable",
                    metadata={
                        "scenario": kind,
                        "coverage_scope": "generated internal fixed-IP topology in the selected IP families",
                        "generated_subnet_cidrs": cidrs,
                        "floating_ip_target_allowed": False,
                    },
                )
            )
        return output

    def _choose_prefix(self, pool: PoolInfo) -> int:
        desired = int(pool.default_prefix_length)
        return min(
            max(desired, pool.min_prefix_length),
            pool.max_prefix_length,
        )

    def _synthetic_cidrs(self, external_subnets: list[SubnetInfo]) -> dict[int, str]:
        used = self._synthetic_used_networks()

        configured = {
            4: self.config.no_routing_group_ipv4_cidr,
            6: self.config.no_routing_group_ipv6_cidr,
        }
        pools = {
            4: ["10.250.0.0/16", "192.168.240.0/20"],
            6: ["fd7a:6e66:6c75::/48", "fd42:4e46:4c58::/48"],
        }
        output: dict[int, str] = {}
        for family in (4, 6):
            if configured[family]:
                candidate = ipaddress.ip_network(str(configured[family]), strict=False)
                if any(
                    candidate.overlaps(item) for item in used if item.version == family
                ):
                    raise UnsupportedTopologyError(
                        f"Configured routing-metadata-unassigned IPv{family} CIDR overlaps OpenStack-visible address space: {candidate}"
                    )
                output[family] = str(candidate)
                used.append(candidate)
                continue
            prefix_length = 24 if family == 4 else 64
            found: str | None = None
            for base_text in pools[family]:
                base = ipaddress.ip_network(base_text)
                for candidate in base.subnets(new_prefix=prefix_length):
                    if not any(
                        candidate.overlaps(item)
                        for item in used
                        if item.version == family
                    ):
                        found = str(candidate)
                        used.append(candidate)
                        break
                if found:
                    break
            if found:
                output[family] = found
        return output
