from __future__ import annotations

import dataclasses
import ipaddress

# mypy: disable-error-code="attr-defined"
from ..cancellation import raise_if_cancelled
from ..errors import (
    CommandError,
    ControllerUnavailableError,
    ProbeServiceError,
    RunCancelledError,
    SuiteError,
)
from ..models import Endpoint, PlannedGroup, RuntimeGroup
from ..network_contract import (
    NESTED_PUBLIC_PROJECT_NETWORK,
    ONE_ROUTER_PROJECT_NETWORKS,
    PRIVATE_TRANSLATION_PROJECT_NETWORK,
    PROJECT_NETWORK,
    PROVIDER_NETWORK,
    ROUTING_UNASSIGNED_PROJECT_NETWORK,
    TWO_ROUTER_STATIC_ROUTING,
    canonical_group_kind,
)
from ..resource_naming import (
    claim_runtime_resource_name,
    endpoint_resource_stem,
    resource_name,
)
from ..scheduling import LIFECYCLE_WORKERS, admission, bounded_map, timed
from ..translation_safety import validate_tenant_group_before_build
from ..utils import optional_text, pick, required_text
from .context import serialized_lifecycle


class TopologyRuntimeMixin:
    """Compatibility mixin for the topology runtime subsystem."""

    def build_group(
        self,
        group: PlannedGroup,
        *,
        sides: tuple[str, ...] = ("A", "B"),
        defer_endpoints: bool = False,
    ) -> RuntimeGroup | None:
        requested = {item.upper() for item in sides}
        existing = next(
            (
                item
                for item in self.runtime_groups
                if item.plan.id == group.id
                and {endpoint.side.upper() for endpoint in item.endpoints} == requested
            ),
            None,
        )
        if existing is not None:
            return existing
        generation = self.allocate_group_generation(group.id)
        deferred = {"defer_endpoints": True} if defer_endpoints else {}
        try:
            if getattr(self, "_controller_recheck_required", False):
                self._require_controller_ssh()
            group_kind = canonical_group_kind(group.kind)
            if group_kind == PROVIDER_NETWORK:
                runtime = self._build_provider_group(
                    group,
                    sides=sides,
                    generation=generation,
                    **deferred,
                )
            elif group_kind == NESTED_PUBLIC_PROJECT_NETWORK:
                raise SuiteError(
                    "Legacy nested project-external plans are not executable. "
                    "Flux models project-member behavior and never creates an "
                    "external project network or controls router source NAT. "
                    "Create a new plan with this release."
                )
            elif group_kind == ONE_ROUTER_PROJECT_NETWORKS:
                runtime = self._build_tenant_router_pair(
                    group,
                    sides=sides,
                    generation=generation,
                    **deferred,
                )
            elif group_kind == TWO_ROUTER_STATIC_ROUTING:
                runtime = self._build_static_route_topology(
                    group,
                    sides=sides,
                    generation=generation,
                    **deferred,
                )
            else:
                runtime = self._build_tenant_group(
                    group,
                    sides=sides,
                    generation=generation,
                    **deferred,
                )
            self._refresh_neutron_placements(group.id)
        except RunCancelledError:
            raise
        except ControllerUnavailableError:
            # The shared control path is required by every group in this lane.
            # Preserve this root cause and let scope-level handling stop new work.
            raise
        except ProbeServiceError as exc:
            message = f"Could not create {group.label}: {exc}"
            self.group_failures[group.id] = message
            self.group_failure_types[group.id] = "transient-probe-startup"
            self.reporter.record_setup_failure(
                message,
                group_id=group.id,
                sides=list(sides),
                generation=generation,
                failure_type="transient-probe-startup",
            )
            # The same transient probe implementation is required by every
            # endpoint. Continuing would only repeat the same setup failure and
            # skip the entire suite, so abort after preserving the exact cause.
            raise
        except (CommandError, SuiteError) as exc:
            detail = str(exc).strip() or type(exc).__name__
            message = f"Could not create {group.label}: {detail}"
            self.group_failures[group.id] = message
            self.group_failure_types[group.id] = (
                "two-router-topology-construction"
                if canonical_group_kind(group.kind) == TWO_ROUTER_STATIC_ROUTING
                else "endpoint-or-topology-setup"
            )
            self.logger.log(message, "ERROR")
            self.reporter.event(
                "group-create-failed",
                message,
                group_id=group.id,
                sides=list(sides),
                generation=generation,
                command=exc.command if isinstance(exc, CommandError) else None,
                stderr=exc.stderr if isinstance(exc, CommandError) else None,
            )
            return None
        self.runtime_groups.append(runtime)
        self.reporter.event(
            "group-topology-ready" if defer_endpoints else "group-ready",
            f"Prepared network topology for {group.label}"
            if defer_endpoints
            else f"Created endpoint group {group.label}",
            group_id=group.id,
            generation=generation,
            sides=[endpoint.side for endpoint in runtime.endpoints],
            servers=[endpoint.server_id for endpoint in runtime.endpoints],
        )
        return runtime

    def complete_group_endpoints(
        self, runtime: RuntimeGroup, *, sides: tuple[str, ...]
    ) -> RuntimeGroup | None:
        """Populate a prepared topology; callers join peers before cleanup."""
        if runtime.endpoints:
            raise SuiteError(f"Endpoint group {runtime.plan.id} is already populated")
        try:
            networks = runtime.metadata.get("network_ids") or {}
            subnets = runtime.metadata.get("side_subnet_ids") or {}
            bindings = {}
            for side in sides:
                subnet_ids = subnets.get(side, runtime.subnet_ids)
                bindings[side] = (
                    networks.get(side, runtime.network_id),
                    [subnet_ids] if isinstance(subnet_ids, str) else list(subnet_ids),
                )
            runtime.endpoints = self._create_endpoints(
                runtime.plan,
                runtime.network_id,
                runtime.subnet_ids,
                sides=sides,
                generation=runtime.generation,
                side_networks=bindings,
            )
        except (RunCancelledError, ControllerUnavailableError):
            raise
        except ProbeServiceError as exc:
            message = f"Could not create {runtime.plan.label}: {exc}"
            self.group_failures[runtime.plan.id] = message
            self.group_failure_types[runtime.plan.id] = "transient-probe-startup"
            self.reporter.record_setup_failure(
                message,
                group_id=runtime.plan.id,
                sides=list(sides),
                generation=runtime.generation,
                failure_type="transient-probe-startup",
            )
            raise
        except (CommandError, SuiteError) as exc:
            message = f"Could not create {runtime.plan.label}: {str(exc).strip() or type(exc).__name__}"
            self.group_failures[runtime.plan.id] = message
            self.group_failure_types[runtime.plan.id] = "endpoint-or-topology-setup"
            self.logger.log(message, "ERROR")
            self.reporter.event(
                "group-create-failed",
                message,
                group_id=runtime.plan.id,
                sides=list(sides),
                generation=runtime.generation,
                command=exc.command if isinstance(exc, CommandError) else None,
                stderr=exc.stderr if isinstance(exc, CommandError) else None,
            )
            return None
        return runtime

    def finalize_group_endpoints(self, runtime: RuntimeGroup) -> None:
        """Publish placement evidence after all provisioning workers have joined."""
        self._refresh_neutron_placements(runtime.plan.id)
        self.reporter.event(
            "group-ready",
            f"Created endpoint group {runtime.plan.label}",
            group_id=runtime.plan.id,
            generation=runtime.generation,
            sides=[endpoint.side for endpoint in runtime.endpoints],
            servers=[endpoint.server_id for endpoint in runtime.endpoints],
        )

    def build_group_side(
        self,
        runtime: RuntimeGroup,
        group: PlannedGroup,
        side: str,
    ) -> Endpoint:
        """Recreate one endpoint while retaining the existing network topology."""

        normalized_side = side.upper()
        if runtime.endpoint(normalized_side) is not None:
            raise SuiteError(
                f"Endpoint side {normalized_side} already exists in {group.id}"
            )
        network_id = runtime.metadata.get("network_ids", {}).get(
            normalized_side, runtime.network_id
        )
        subnet_ids = runtime.metadata.get("side_subnet_ids", {}).get(
            normalized_side, runtime.subnet_ids
        )
        if isinstance(subnet_ids, str):
            subnet_ids = [subnet_ids]
        runtime_plan = dataclasses.replace(
            runtime.plan, metadata={**runtime.plan.metadata, **group.metadata}
        )
        generation = self.allocate_group_generation(group.id)
        endpoints = self._create_endpoints(
            runtime_plan,
            network_id,
            subnet_ids,
            sides=(normalized_side,),
            generation=generation,
        )
        if len(endpoints) != 1:
            raise SuiteError(
                f"Endpoint rotation for {group.id}:{normalized_side} "
                f"created {len(endpoints)} endpoints"
            )
        endpoint = endpoints[0]
        runtime.endpoints.append(endpoint)
        runtime.plan = runtime_plan
        runtime.generation = generation
        self.reporter.event(
            "endpoint-side-ready",
            f"Prepared endpoint side {normalized_side} for {group.label}",
            group_id=group.id,
            side=normalized_side,
            server_id=endpoint.server_id,
            requested_host=endpoint.metadata.get("requested_host"),
            observed_host=endpoint.host,
            generation=generation,
        )
        return endpoint

    def _build_provider_group(
        self,
        group: PlannedGroup,
        *,
        sides: tuple[str, ...],
        generation: int,
        defer_endpoints: bool = False,
    ) -> RuntimeGroup:
        if not group.network_id or not group.network_name:
            raise SuiteError(f"Provider group lacks network identity: {group.label}")
        endpoints = (
            []
            if defer_endpoints
            else self._create_endpoints(
                group,
                group.network_id,
                group.subnet_ids,
                sides=sides,
                generation=generation,
            )
        )
        return RuntimeGroup(
            plan=group,
            network_id=group.network_id,
            network_name=group.network_name,
            subnet_ids=list(group.subnet_ids),
            router_id=None,
            endpoints=endpoints,
            source_nat_enabled=None,
            fips={},
            generation=generation,
        )

    def _create_generated_tenant_network(
        self,
        group: PlannedGroup,
        *,
        generation: int,
        suffix: str,
        no_gateway: bool = False,
    ) -> tuple[str, str, str, str]:
        generated_cidrs = (getattr(group, "metadata", None) or {}).get(
            "generated_subnet_cidrs"
        ) or {}
        generated_cidr = generated_cidrs.get(suffix)
        if not (group.pool_id and group.prefix_length) and not generated_cidr:
            raise SuiteError(
                f"Generated routing scenario requires a subnet pool or an explicit private prefix: {group.label}"
            )
        if generated_cidr:
            networks = [ipaddress.ip_network(cidr) for cidr in generated_cidrs.values()]
            if (
                group.pool_id
                or any(network.version != group.families[0] for network in networks)
                or any(
                    a.overlaps(b)
                    for i, a in enumerate(networks)
                    for b in networks[i + 1 :]
                )
            ):
                raise SuiteError(f"Invalid generated routing prefixes: {group.label}")
        network_name = resource_name(
            self,
            group,
            generation=generation,
            role=suffix,
            resource_type="network",
        )
        subnet_name = resource_name(
            self,
            group,
            generation=generation,
            role=suffix,
            resource_type="subnet",
        )
        claim_runtime_resource_name(
            self,
            network_name,
            resource_type="network",
        )
        network_args = [
            "network",
            "create",
            "--tag",
            self.run_tag,
            *self._availability_zone_hint_args(),
            network_name,
        ]
        network = self.osc.json(*network_args) or {}
        network_id = required_text(
            network, "id", context=f"Network create for {network_name}"
        )
        self.tracker.add(
            "network",
            network_id,
            network_name,
            role=group.kind,
            pool_id=group.pool_id,
            group_id=group.id,
            generation=generation,
            scenario_side=suffix,
        )
        self._validate_created_resource_zone("network", network_id, network)
        subnet_args = [
            "subnet",
            "create",
            "--network",
            network_id,
            "--ip-version",
            str(group.families[0]),
            "--no-dhcp",
        ]
        if generated_cidr:
            subnet_args.extend(["--subnet-range", generated_cidr])
        else:
            subnet_args.extend(
                [
                    "--subnet-pool",
                    str(group.pool_id),
                    "--prefix-length",
                    str(group.prefix_length),
                ]
            )
        if no_gateway:
            subnet_args.extend(["--gateway", "none"])
        subnet_args.extend(["--tag", self.run_tag, subnet_name])
        claim_runtime_resource_name(
            self,
            subnet_name,
            resource_type="subnet",
        )
        subnet = self.osc.json(*subnet_args) or {}
        subnet_id = required_text(
            subnet, "id", context=f"Subnet create for {subnet_name}"
        )
        cidr = required_text(
            subnet, "subnet", "cidr", context=f"Subnet create for {subnet_name}"
        )
        gateway_ip = optional_text(pick(subnet, "gateway_ip", default=None))
        self.tracker.add(
            "subnet",
            subnet_id,
            subnet_name,
            parent_id=network_id,
            cidr=cidr,
            pool_id=group.pool_id,
            routing_group_id=group.address_scope_id,
            group_id=group.id,
            generation=generation,
            scenario_side=suffix,
            static_addressing=True,
            gateway_ip=gateway_ip,
            gateway_disabled=no_gateway,
        )
        return network_id, network_name, subnet_id, cidr

    def _create_scenario_router(
        self,
        group: PlannedGroup,
        *,
        generation: int,
        suffix: str,
    ) -> tuple[str, str]:
        name = resource_name(
            self,
            group,
            generation=generation,
            role=suffix,
            resource_type="router",
        )
        claim_runtime_resource_name(
            self,
            name,
            resource_type="router",
        )
        detail = (
            self.osc.json(
                "router",
                "create",
                "--tag",
                self.run_tag,
                *self._availability_zone_hint_args("router"),
                name,
            )
            or {}
        )
        router_id = required_text(detail, "id", context=f"Router create for {name}")
        self.tracker.add(
            "router",
            router_id,
            name,
            role=group.kind,
            group_id=group.id,
            generation=generation,
            scenario_side=suffix,
        )
        self._validate_created_resource_zone("router", router_id, detail)
        return router_id, name

    def _build_tenant_router_pair(
        self,
        group: PlannedGroup,
        *,
        sides: tuple[str, ...],
        generation: int,
        defer_endpoints: bool = False,
    ) -> RuntimeGroup:
        network_a, name_a, subnet_a, cidr_a = self._create_generated_tenant_network(
            group, generation=generation, suffix="a"
        )
        network_b, name_b, subnet_b, cidr_b = self._create_generated_tenant_network(
            group, generation=generation, suffix="b"
        )
        router_id, router_name = self._create_scenario_router(
            group, generation=generation, suffix="east-west"
        )
        router_interfaces: list[dict[str, str]] = []
        for subnet_id, network_id, purpose in (
            (subnet_a, network_a, "project subnet A"),
            (subnet_b, network_b, "project subnet B"),
        ):
            result = self.osc.run(
                "router",
                "add",
                "subnet",
                router_id,
                subnet_id,
                check=False,
                timeout=min(60, self.config.resource_timeout),
            )
            if result.returncode != 0:
                raise SuiteError(
                    f"Could not attach generated subnet {subnet_id} to {router_name}: "
                    f"{(result.stderr or result.stdout).strip()}"
                )
            interface_ip = self._optional_router_interface_ip(router_id, subnet_id)
            if interface_ip:
                router_interfaces.append(
                    {
                        "subnet_id": subnet_id,
                        "network_id": network_id,
                        "ip_address": interface_ip,
                        "purpose": purpose,
                    }
                )
        self._record_router_addresses(router_id, interface_addresses=router_interfaces)
        endpoints = (
            []
            if defer_endpoints
            else self._create_endpoints(
                group,
                network_a,
                [subnet_a],
                sides=sides,
                generation=generation,
                side_networks={
                    "A": (network_a, [subnet_a]),
                    "B": (network_b, [subnet_b]),
                },
            )
        )
        runtime_plan = dataclasses.replace(
            group,
            network_id=network_a,
            network_name=name_a,
            subnet_ids=[subnet_a, subnet_b],
        )
        return RuntimeGroup(
            plan=runtime_plan,
            network_id=network_a,
            network_name=name_a,
            subnet_ids=[subnet_a, subnet_b],
            router_id=router_id,
            endpoints=endpoints,
            source_nat_enabled=None,
            fips={},
            generation=generation,
            metadata={
                "side_subnet_ids": {"A": subnet_a, "B": subnet_b},
                "network_ids": {"A": network_a, "B": network_b},
                "network_names": {"A": name_a, "B": name_b},
                "cidrs": {"A": cidr_a, "B": cidr_b},
                "router_interface_subnet_id": subnet_b,
                "logical_router_attachment": True,
            },
        )

    def _build_static_route_topology(
        self,
        group: PlannedGroup,
        *,
        sides: tuple[str, ...],
        generation: int,
        defer_endpoints: bool = False,
    ) -> RuntimeGroup:
        network_a, name_a, subnet_a, cidr_a = self._create_generated_tenant_network(
            group, generation=generation, suffix="project-a"
        )
        network_b, name_b, subnet_b, cidr_b = self._create_generated_tenant_network(
            group, generation=generation, suffix="project-b"
        )
        # A transit subnet shared by two routers must not have a single gateway
        # address. Each router receives a separately allocated Neutron port.
        transit_network, transit_name, transit_subnet, transit_cidr = (
            self._create_generated_tenant_network(
                group,
                generation=generation,
                suffix="transit",
                no_gateway=True,
            )
        )
        router_a, router_a_name = self._create_scenario_router(
            group, generation=generation, suffix="a"
        )
        router_b, router_b_name = self._create_scenario_router(
            group, generation=generation, suffix="b"
        )

        project_router_interfaces: dict[str, list[dict[str, str]]] = {
            router_a: [],
            router_b: [],
        }
        for router_id, router_name, subnet_id, network_id, purpose in (
            (router_a, router_a_name, subnet_a, network_a, "project subnet A"),
            (router_b, router_b_name, subnet_b, network_b, "project subnet B"),
        ):
            result = self.osc.run(
                "router",
                "add",
                "subnet",
                router_id,
                subnet_id,
                check=False,
                timeout=min(60, self.config.resource_timeout),
            )
            if result.returncode != 0:
                raise SuiteError(
                    f"Could not attach project subnet {subnet_id} to {router_name}: "
                    f"{(result.stderr or result.stdout).strip()}"
                )
            interface_ip = self._optional_router_interface_ip(router_id, subnet_id)
            if interface_ip:
                project_router_interfaces[router_id].append(
                    {
                        "subnet_id": subnet_id,
                        "network_id": network_id,
                        "ip_address": interface_ip,
                        "purpose": purpose,
                    }
                )

        transit_port_a_name = resource_name(
            self,
            group,
            generation=generation,
            role="transit-a",
            resource_type="port",
        )
        transit_port_b_name = resource_name(
            self,
            group,
            generation=generation,
            role="transit-b",
            resource_type="port",
        )
        transit_port_a, transit_a = self._create_router_interface_port(
            network_id=transit_network,
            subnet_id=transit_subnet,
            name=transit_port_a_name,
            group=group,
            generation=generation,
            side="A",
        )
        transit_port_b, transit_b = self._create_router_interface_port(
            network_id=transit_network,
            subnet_id=transit_subnet,
            name=transit_port_b_name,
            group=group,
            generation=generation,
            side="B",
        )
        if transit_a == transit_b:
            raise SuiteError(
                f"Neutron allocated the same transit address {transit_a} to both router interface ports"
            )
        self._attach_router_port(
            router_a, router_a_name, transit_port_a, transit_port_a_name
        )
        self._attach_router_port(
            router_b, router_b_name, transit_port_b, transit_port_b_name
        )
        project_router_interfaces[router_a].append(
            {
                "subnet_id": transit_subnet,
                "network_id": transit_network,
                "ip_address": transit_a,
                "purpose": "transit interface toward Router B",
            }
        )
        project_router_interfaces[router_b].append(
            {
                "subnet_id": transit_subnet,
                "network_id": transit_network,
                "ip_address": transit_b,
                "purpose": "transit interface toward Router A",
            }
        )
        self._record_router_addresses(
            router_a, interface_addresses=project_router_interfaces[router_a]
        )
        self._record_router_addresses(
            router_b, interface_addresses=project_router_interfaces[router_b]
        )

        routes = {
            "A": {"router_id": router_a, "destination": cidr_b, "gateway": transit_b},
            "B": {"router_id": router_b, "destination": cidr_a, "gateway": transit_a},
        }
        endpoints = (
            []
            if defer_endpoints
            else self._create_endpoints(
                group,
                network_a,
                [subnet_a],
                sides=sides,
                generation=generation,
                side_networks={
                    "A": (network_a, [subnet_a]),
                    "B": (network_b, [subnet_b]),
                },
            )
        )
        runtime_plan = dataclasses.replace(
            group,
            network_id=network_a,
            network_name=name_a,
            subnet_ids=[subnet_a, subnet_b],
        )
        return RuntimeGroup(
            plan=runtime_plan,
            network_id=network_a,
            network_name=name_a,
            subnet_ids=[subnet_a, subnet_b],
            router_id=router_a,
            endpoints=endpoints,
            source_nat_enabled=None,
            fips={},
            generation=generation,
            metadata={
                "side_subnet_ids": {"A": subnet_a, "B": subnet_b},
                "network_ids": {
                    "A": network_a,
                    "B": network_b,
                    "transit": transit_network,
                },
                "network_names": {"A": name_a, "B": name_b, "transit": transit_name},
                "cidrs": {"A": cidr_a, "B": cidr_b, "transit": transit_cidr},
                "transit_subnet_id": transit_subnet,
                "transit_port_ids": {"A": transit_port_a, "B": transit_port_b},
                "transit_ips": {"A": transit_a, "B": transit_b},
                "routers": {"A": router_a, "B": router_b},
                "routes": routes,
                "routes_installed": False,
            },
        )

    # Legacy direct runtime integration compatibility.
    _build_extra_route_pair = _build_static_route_topology

    def _build_tenant_group(
        self,
        group: PlannedGroup,
        *,
        sides: tuple[str, ...],
        generation: int,
        defer_endpoints: bool = False,
    ) -> RuntimeGroup:
        validate_tenant_group_before_build(group)
        group_kind = canonical_group_kind(group.kind)
        if (
            not all(
                [
                    group.external_network_id,
                    group.external_network_name,
                    group.external_subnet_id,
                    group.prefix_length,
                ]
            )
            or (group_kind == PROJECT_NETWORK and not group.pool_id)
            or (
                group_kind == ROUTING_UNASSIGNED_PROJECT_NETWORK
                and not group.synthetic_cidr
            )
            or (
                group_kind == PRIVATE_TRANSLATION_PROJECT_NETWORK
                and (group.pool_id or not group.synthetic_cidr)
            )
        ):
            raise SuiteError(f"Incomplete project-network group plan: {group.label}")
        network_name = resource_name(
            self,
            group,
            generation=generation,
            role="project",
            resource_type="network",
        )
        subnet_name = resource_name(
            self,
            group,
            generation=generation,
            role="project",
            resource_type="subnet",
        )
        router_name = resource_name(
            self,
            group,
            generation=generation,
            role="project",
            resource_type="router",
        )
        claim_runtime_resource_name(
            self,
            network_name,
            resource_type="network",
        )
        network = (
            self.osc.json(
                "network",
                "create",
                "--tag",
                self.run_tag,
                *self._availability_zone_hint_args(),
                network_name,
            )
            or {}
        )
        network_id = required_text(
            network, "id", context=f"Network create for {network_name}"
        )
        self.tracker.add(
            "network",
            network_id,
            network_name,
            role=group.kind,
            pool_id=group.pool_id,
            external_subnet_id=group.external_subnet_id,
            group_id=group.id,
            generation=generation,
        )
        self._validate_created_resource_zone("network", network_id, network)
        subnet_args = [
            "subnet",
            "create",
            "--network",
            network_id,
            "--ip-version",
            str(group.families[0]),
            "--no-dhcp",
            "--tag",
            self.run_tag,
        ]
        if group_kind == PROJECT_NETWORK:
            subnet_args.extend(
                [
                    "--subnet-pool",
                    str(group.pool_id),
                    "--prefix-length",
                    str(group.prefix_length),
                ]
            )
        else:
            subnet_args.extend(["--subnet-range", str(group.synthetic_cidr)])
        # IPv6 is intentionally static in Neutron Flux environments. Do not
        # request SLAAC or DHCPv6 address modes.
        subnet_args.append(subnet_name)
        claim_runtime_resource_name(
            self,
            subnet_name,
            resource_type="subnet",
        )
        subnet = self.osc.json(*subnet_args) or {}
        subnet_id = required_text(
            subnet, "id", context=f"Subnet create for {subnet_name}"
        )
        subnet_cidr = required_text(
            subnet, "subnet", "cidr", context=f"Subnet create for {subnet_name}"
        )
        subnet_gateway_ip = optional_text(pick(subnet, "gateway_ip", default=None))
        self.tracker.add(
            "subnet",
            subnet_id,
            subnet_name,
            parent_id=network_id,
            cidr=subnet_cidr,
            pool_id=group.pool_id,
            scope_id=group.address_scope_id,
            group_id=group.id,
            generation=generation,
            static_addressing=True,
            gateway_ip=subnet_gateway_ip,
            gateway_disabled=False,
        )

        claim_runtime_resource_name(
            self,
            router_name,
            resource_type="router",
        )
        router = (
            self.osc.json(
                "router",
                "create",
                "--tag",
                self.run_tag,
                *self._availability_zone_hint_args("router"),
                router_name,
            )
            or {}
        )
        router_id = required_text(
            router, "id", context=f"Router create for {router_name}"
        )
        self.tracker.add(
            "router",
            router_id,
            router_name,
            role=group.kind,
            external_network_id=group.external_network_id,
            external_subnet_id=group.external_subnet_id,
            floating_subnet_id=group.floating_subnet_id,
            pool_id=group.pool_id,
            group_id=group.id,
            generation=generation,
        )
        self._validate_created_resource_zone("router", router_id, router)
        expected_source_nat = group.kind == PRIVATE_TRANSLATION_PROJECT_NETWORK
        gateway_snapshot = self.configure_router_external_gateway_default(
            router_id,
            router_name,
            external_network_id=str(group.external_network_id),
            external_subnet_id=str(group.external_subnet_id),
            ip_version=group.families[0],
            require_source_nat=expected_source_nat,
        )
        actual_gateway = gateway_snapshot.get("external_gateway_info") or {}

        interface_result = self.osc.run(
            "router",
            "add",
            "subnet",
            router_id,
            subnet_id,
            check=False,
            timeout=min(60, self.config.resource_timeout),
        )
        if interface_result.returncode != 0:
            raise SuiteError(
                f"Could not attach project subnet {subnet_id} to router {router_name}: "
                f"{(interface_result.stderr or interface_result.stdout).strip()}"
            )
        internal_interface_ip = self._optional_router_interface_ip(router_id, subnet_id)
        interface_addresses = (
            [
                {
                    "subnet_id": subnet_id,
                    "network_id": network_id,
                    "ip_address": internal_interface_ip,
                    "purpose": "router-connected project subnet",
                }
            ]
            if internal_interface_ip
            else []
        )
        self._record_router_addresses(
            router_id,
            interface_addresses=interface_addresses,
            external_gateway_info=actual_gateway,
        )
        original_router_state = self.capture_router_state(router_id)
        observed_source_nat = self._gateway_info(
            original_router_state.get("external_gateway_info") or {}
        ).get("enable_snat")
        if expected_source_nat and not observed_source_nat:
            raise SuiteError(
                f"Router {router_name}'s default source NAT state changed during setup"
            )

        runtime_plan = dataclasses.replace(
            group,
            network_id=network_id,
            network_name=network_name,
            subnet_ids=[subnet_id],
        )
        endpoints = (
            []
            if defer_endpoints
            else self._create_endpoints(
                runtime_plan,
                network_id,
                [subnet_id],
                sides=sides,
                generation=generation,
            )
        )
        runtime = RuntimeGroup(
            plan=runtime_plan,
            network_id=network_id,
            network_name=network_name,
            subnet_ids=[subnet_id],
            router_id=router_id,
            endpoints=endpoints,
            source_nat_enabled=(observed_source_nat if group.families == [4] else None),
            fips={},
            generation=generation,
            original_router_state=original_router_state,
            metadata=(
                {
                    "side_subnet_ids": {side.upper(): subnet_id for side in sides},
                    "network_ids": {side.upper(): network_id for side in sides},
                    "network_names": {side.upper(): network_name for side in sides},
                    "cidrs": {side.upper(): subnet_cidr for side in sides},
                    "floating_ip_endpoint_side": "A",
                    "floating_ip_fixed_subnet_id": subnet_id,
                    "floating_ip_subnet_id": group.floating_subnet_id,
                    "source_nat_configuration": "neutron-default-observed",
                    "source_nat_controlled_by_flux": False,
                }
                if group_kind == PRIVATE_TRANSLATION_PROJECT_NETWORK
                else {}
            ),
        )
        # Floating IPs are created lazily by the first floating-IP assertion.
        return runtime

    @serialized_lifecycle
    def _create_endpoints(
        self,
        group: PlannedGroup,
        test_network_id: str,
        test_subnet_ids: list[str],
        *,
        sides: tuple[str, ...],
        generation: int,
        side_networks: dict[str, tuple[str, list[str]]] | None = None,
    ) -> list[Endpoint]:
        endpoints: list[Endpoint] = []
        coordinator = getattr(self, "cloud_operation_coordinator", None)
        if (
            coordinator is not None
            and canonical_group_kind(group.kind) != PROVIDER_NETWORK
        ):
            coordinator.settle(
                "network-topology",
                f"allow topology for {group.label} to settle before endpoint port creation",
                seconds=15.0,
            )
        normalized_sides = tuple(item.upper() for item in sides)
        if len(set(normalized_sides)) != len(normalized_sides) or any(
            side not in {"A", "B"} for side in normalized_sides
        ):
            raise SuiteError(f"Invalid endpoint sides for {group.id}")
        bindings = side_networks or {
            side: (test_network_id, test_subnet_ids) for side in normalized_sides
        }
        if any(
            side not in bindings or not bindings[side][0] or not bindings[side][1]
            for side in normalized_sides
        ):
            raise SuiteError(f"Incomplete endpoint network bindings for {group.id}")
        target_hosts = group.metadata.get("target_hosts") or {}
        target_zones = group.metadata.get("target_availability_zones") or {}
        if not isinstance(target_hosts, dict) or not isinstance(target_zones, dict):
            raise SuiteError(f"Invalid exact-placement metadata for group {group.id}")

        def create_endpoint(item: tuple[int, str]) -> Endpoint:
            index, side = item
            endpoint_network, endpoint_subnets = bindings[side]
            raise_if_cancelled()
            endpoint_label = f"{group.label}:{side}"
            self.logger.log(
                f"Creating endpoint {endpoint_label} ({index}/{len(normalized_sides)})"
            )
            base_name = endpoint_resource_stem(
                self,
                group,
                generation=generation,
                side=side,
            )
            metadata = {
                "group_id": group.id,
                "generation": generation,
                "endpoint_side": side,
            }
            mgmt_port = self._create_port(
                resource_name(
                    self,
                    group,
                    generation=generation,
                    role=f"project-{side.lower()}-mgmt",
                    resource_type="port",
                ),
                self.management_network_id,
                [self.management_subnet_id],
                self.endpoint_management_sg_id,
                role="endpoint-management",
                **metadata,
            )
            data_security_group_id = self.test_sg_ids.get(side, self.test_sg_id)
            test_port = self._create_port(
                resource_name(
                    self,
                    group,
                    generation=generation,
                    role=f"project-{side.lower()}-data",
                    resource_type="port",
                ),
                endpoint_network,
                endpoint_subnets,
                data_security_group_id,
                role="endpoint-test",
                **metadata,
            )
            mgmt_port_id = required_text(
                mgmt_port, "id", context=f"Management port create for {endpoint_label}"
            )
            test_port_id = required_text(
                test_port, "id", context=f"Test port create for {endpoint_label}"
            )
            mgmt_ip = self._fixed_ips(mgmt_port).get(self.management_subnet_id)
            fixed_ips = self._fixed_ips(test_port)
            test_mac = optional_text(pick(test_port, "mac_address", default="")) or ""
            if not mgmt_ip or not fixed_ips or not test_mac:
                raise SuiteError(
                    f"Endpoint ports lack expected allocations: {endpoint_label}"
                )
            self._require_ipv4(mgmt_ip, f"management address for {endpoint_label}")
            server = self._create_server(
                base_name,
                [mgmt_port_id, test_port_id],
                role="endpoint",
                group_id=group.id,
                endpoint_side=side,
                target_host=optional_text(target_hosts.get(side)),
                target_availability_zone=optional_text(target_zones.get(side)),
            )
            table_base = 100 + (index * 20)
            endpoint = Endpoint(
                label=endpoint_label,
                server_id=server["server_id"],
                server_name=server["server_name"],
                management_port_id=mgmt_port_id,
                management_ip=mgmt_ip,
                test_port_id=test_port_id,
                test_mac=test_mac,
                fixed_ips=fixed_ips,
                host=server["host"],
                availability_zone=server["availability_zone"],
                volume_id=server["volume_id"],
                side=side,
                port_security_enabled=bool(
                    pick(test_port, "port_security_enabled", default=True)
                ),
                network_table_base=table_base,
                metadata={
                    **metadata,
                    "data_security_group_id": data_security_group_id,
                    "requested_host": server.get("requested_host"),
                    "placement_method": server.get("placement_method"),
                    "host_qualification_pair_id": group.metadata.get(
                        "host_qualification_pair_id"
                    ),
                    "host_qualification_cycle": group.metadata.get(
                        "host_qualification_cycle"
                    ),
                },
            )
            if not self._wait_for_ssh(mgmt_ip, proxy=True):
                raise SuiteError(
                    f"Endpoint never became reachable through controller: {endpoint_label} ({mgmt_ip})"
                )
            raise_if_cancelled()
            self._configure_endpoint(endpoint, endpoint.network_table_base)
            return endpoint

        def provision(item: tuple[int, str]) -> Endpoint:
            with (
                admission("lifecycle", getattr(self, "reporter", None)),
                timed(
                    getattr(self, "reporter", None),
                    "endpoint-setup",
                    f"{group.id}:{item[1]}",
                ),
            ):
                return create_endpoint(item)

        endpoints = bounded_map(
            provision,
            enumerate(normalized_sides, start=1),
            # The standalone fallback holds a thread-owned lifecycle lock.
            # Its nested port/server methods must run on that same thread.
            workers=(
                min(LIFECYCLE_WORKERS, max(1, self.config.max_active_endpoints))
                if coordinator is not None
                else 1
            ),
        )
        return endpoints
