from __future__ import annotations

import ipaddress
import time
from typing import Any

# mypy: disable-error-code="attr-defined"
from ...errors import SuiteError
from ...models import Endpoint
from ...resource_naming import claim_runtime_resource_name, managed_resource_name
from ...utils import pick, required_text
from ..context import serialized_lifecycle


class ControllerRuntimeMixin:
    """Compatibility mixin for this control-plane concern."""

    def _require_network_path_failure_before_bastion(
        self,
        address: str,
        *,
        network_name: str,
        diagnostics: dict[str, Any],
    ) -> dict[str, Any]:
        """Allow a bastion only when the direct provider path actually failed.

        A completed or refused TCP connection proves that the selected provider
        address was reached.  If SSH then stalls before its banner, the problem
        is guest/SSH readiness (or the established flow), not lack of a route;
        creating a floating-IP bastion on the same provider network cannot
        repair that condition.
        """

        assessment = self._ssh_path_assessment(
            address,
            proxy=False,
            diagnostics=diagnostics,
        )
        classification = str(assessment.get("classification") or "undetermined")
        readiness = assessment.get("readiness", {})
        transport = assessment.get("transport", {})
        if not isinstance(readiness, dict):
            readiness = {}
        if not isinstance(transport, dict):
            transport = {}
        last_error = str(
            readiness.get("last_error") or transport.get("error") or "unknown"
        )
        if classification == "tcp-reachable-ssh-not-ready":
            self.reporter.event(
                "controller-direct-ssh-service-not-ready",
                "The runner reached the controller provider IPv4 over TCP, but the controller did not complete SSH readiness; a bastion was not created because the provider path was demonstrably reachable",
                address=address,
                network=network_name,
                assessment=assessment,
                authoritative=True,
                tool_failure=True,
            )
            raise SuiteError(
                f"Controller provider IPv4 {address} on {network_name} was TCP-reachable, "
                "but the controller SSH service did not become ready; no management "
                "bastion was created because this was not a provider-path failure. "
                f"Last SSH error: {last_error}"
            )
        if classification != "network-path-unavailable":
            self.reporter.event(
                "controller-direct-ssh-path-undetermined",
                "The controller SSH failure did not prove that the provider path was unavailable; a bastion was not created",
                address=address,
                network=network_name,
                assessment=assessment,
                authoritative=False,
                tool_failure=True,
            )
            raise SuiteError(
                f"Controller SSH readiness at provider IPv4 {address} on {network_name} "
                "failed without proving that the provider path was unavailable; no "
                f"management bastion was created. Last SSH error: {last_error}"
            )
        self.reporter.event(
            "controller-direct-network-path-unavailable",
            "The runner could not establish a TCP path to the controller provider IPv4; management-bastion fallback is permitted",
            address=address,
            network=network_name,
            assessment=assessment,
            authoritative=False,
        )
        return assessment

    def _choose_management_cidr(self) -> str:
        if self.config.mgmt_cidr:
            candidate = ipaddress.ip_network(self.config.mgmt_cidr, strict=False)
            if candidate.version != 4:
                raise SuiteError("network.management_cidr must be IPv4")
            return str(candidate)
        used: list[ipaddress._BaseNetwork] = []
        for cidr in self.discovery.occupied_cidrs or [
            item.cidr for item in self.discovery.subnets
        ]:
            used.append(ipaddress.ip_network(cidr, strict=False))
        for pool in self.discovery.pools:
            for prefix in pool.prefixes:
                used.append(ipaddress.ip_network(prefix, strict=False))
        # Address text never establishes network role. In particular, 172/8 may
        # be operator-routed public space, so Flux does not borrow it for a
        # synthetic management network.
        bases = ["10.254.0.0/16", "192.168.240.0/20"]
        for base_text in bases:
            base = ipaddress.ip_network(base_text)
            for candidate in base.subnets(new_prefix=24):
                if not any(
                    candidate.overlaps(item) for item in used if item.version == 4
                ):
                    return str(candidate)
        raise SuiteError(
            "Could not select a non-overlapping management CIDR; set network.management_cidr in neutron-flux.yml"
        )

    @serialized_lifecycle
    def _create_management_network(self) -> None:
        cidr = self._choose_management_cidr()
        self.management_cidr = cidr
        net_name = managed_resource_name(
            self,
            identity="management-network",
            role="management",
            resource_type="network",
        )
        subnet_name = managed_resource_name(
            self,
            identity=f"management-subnet:{cidr}",
            role="management",
            resource_type="subnet",
        )
        claim_runtime_resource_name(self, net_name, resource_type="network")
        network = (
            self.osc.json(
                "network",
                "create",
                "--tag",
                self.run_tag,
                *self._availability_zone_hint_args(),
                net_name,
            )
            or {}
        )
        self.management_network_id = required_text(
            network, "id", context="Management network create"
        )
        self.tracker.add(
            "network", self.management_network_id, net_name, role="management"
        )
        self._validate_created_resource_zone(
            "network", self.management_network_id, network
        )
        claim_runtime_resource_name(self, subnet_name, resource_type="subnet")
        subnet_args = [
            "subnet",
            "create",
            "--network",
            self.management_network_id,
            "--subnet-range",
            cidr,
            "--ip-version",
            "4",
        ]
        subnet_args.extend(["--gateway", "none"])
        subnet_args.extend(["--dhcp", "--tag", self.run_tag, subnet_name])
        subnet = self.osc.json(*subnet_args) or {}
        self.management_subnet_id = required_text(
            subnet, "id", context="Management subnet create"
        )
        self.tracker.add(
            "subnet",
            self.management_subnet_id,
            subnet_name,
            parent_id=self.management_network_id,
            cidr=cidr,
        )

    def _controller_probe_specs(self) -> list[dict[str, Any]]:
        """Select one provider IPv4 port for the runner control path.

        Static IPv6 tests are executed from endpoint VMs. Keeping the
        controller on a single provider attachment avoids combining ports from
        provider segments that may not be schedulable on the same Nova host.
        """
        for group in self.plan.provider_groups:
            if not group.network_id or not group.network_name:
                continue
            ipv4_subnet = next(
                (
                    subnet_id
                    for subnet_id in group.subnet_ids
                    if self.discovery.subnet(subnet_id).ip_version == 4
                ),
                None,
            )
            if ipv4_subnet:
                self.controller_probe_mode = "provider-ipv4-control"
                return [
                    {
                        "network_id": group.network_id,
                        "network_name": group.network_name,
                        "subnet_ids": [ipv4_subnet],
                        "families": [4],
                    }
                ]
        raise SuiteError(
            "No external IPv4 provider subnet is available for the runner control path"
        )

    def _create_controller_probe_ports(self) -> list[str]:
        port_ids: list[str] = []
        self.controller_probe_ports = []
        self.controller_probe_sources = {}
        self.controller_probe_subnets = {}
        for index, spec in enumerate(self._controller_probe_specs(), start=1):
            port_name = managed_resource_name(
                self,
                identity=(
                    f"controller-probe:{index}:{spec['network_id']}:"
                    f"{','.join(str(item) for item in spec['subnet_ids'])}"
                ),
                role="controller-probe",
                resource_type="port",
            )
            port = self._create_port(
                port_name,
                str(spec["network_id"]),
                list(spec["subnet_ids"]),
                self.controller_sg_id,
                role="controller-probe",
                families=list(spec["families"]),
            )
            fixed_ips = self._fixed_ips(port)
            descriptor = {
                **spec,
                "port_id": required_text(
                    port, "id", context=f"Controller probe port create for {port_name}"
                ),
                "port_name": port_name,
                "mac_address": str(pick(port, "mac_address", default="") or ""),
                "fixed_ips": fixed_ips,
            }
            if not descriptor["mac_address"] or not fixed_ips:
                raise SuiteError(
                    f"Controller probe port lacks expected allocations: {port_name}"
                )
            self.controller_probe_ports.append(descriptor)
            port_ids.append(str(descriptor["port_id"]))
            for subnet_id, address in fixed_ips.items():
                family = ipaddress.ip_address(address).version
                self.controller_probe_sources.setdefault(family, address)
                self.controller_probe_subnets.setdefault(family, subnet_id)

        if self.controller_probe_ports:
            rendered = []
            for item in self.controller_probe_ports:
                addresses = ",".join(item["fixed_ips"].values())
                rendered.append(f"{item['network_name']}[{addresses}]")
            self.logger.log(
                f"Controller control path ({self.controller_probe_mode}): "
                + " + ".join(rendered)
            )
        return port_ids

    def _create_controller(self) -> None:
        self.logger.section("Creating dynamic SSH controller")
        port_name = managed_resource_name(
            self,
            identity="controller-management-port",
            role="controller-management",
            resource_type="port",
        )
        port = self._create_port(
            port_name,
            self.management_network_id,
            [self.management_subnet_id],
            self.management_sg_id,
            role="controller-management",
        )
        mgmt_port_id = required_text(
            port, "id", context="Controller management port create"
        )
        mgmt_ip = self._fixed_ips(port).get(self.management_subnet_id)
        if not mgmt_ip:
            raise SuiteError(
                "Controller management port did not receive an IPv4 address"
            )
        self._require_ipv4(mgmt_ip, "controller management address")

        # Direct provider observation and management access have distinct roles.
        probe_port_ids = self._create_controller_probe_ports()
        controller_name = managed_resource_name(
            self,
            identity="probe-controller",
            role="controller",
            resource_type="server",
        )
        controller = self._create_server(
            controller_name,
            [*probe_port_ids, mgmt_port_id],
            role="controller-probe",
            allow_az_fallback=True,
        )
        self.controller = Endpoint(
            label="controller",
            server_id=controller["server_id"],
            server_name=controller["server_name"],
            management_port_id=mgmt_port_id,
            management_ip=mgmt_ip,
            test_port_id=None,
            test_mac=None,
            fixed_ips={},
            host=controller["host"],
            availability_zone=controller["availability_zone"],
            volume_id=controller["volume_id"],
        )

        direct_addresses = list(
            dict.fromkeys(
                address
                for item in self.controller_probe_ports
                for address in item["fixed_ips"].values()
                if ipaddress.ip_address(address).version == 4
            )
        )
        for address in direct_addresses:
            network_name = next(
                (
                    str(item.get("network_name") or "")
                    for item in self.controller_probe_ports
                    if address in item.get("fixed_ips", {}).values()
                ),
                "selected provider network",
            )
            self.logger.log(
                f"Trying direct controller SSH at provider fixed IPv4 {address} "
                f"on {network_name}"
            )
            if self._wait_for_ssh(
                address,
                proxy=False,
                timeout=self.config.convergence_timeout,
            ):
                self._set_control_address(address)
                self.controller_command_address = address
                self.controller_via_proxy = False
                self._configure_controller_probe_ports()
                self._record_controller_ssh_result(
                    mode="provider-fixed-ipv4",
                    destination=address,
                    management_ip=mgmt_ip,
                )
                return
            diagnostics = self._collect_ssh_failure_diagnostics(
                address,
                proxy=False,
            )
            self._require_network_path_failure_before_bastion(
                address,
                network_name=network_name,
                diagnostics=diagnostics,
            )

        self.logger.log(
            "The runner could not establish a TCP path to any selected controller "
            "provider IPv4; creating a separate management bastion",
        )
        self._create_management_bastion()
        self.controller_command_address = mgmt_ip
        self.controller_via_proxy = True
        if not self._wait_for_ssh(
            mgmt_ip,
            proxy=True,
            timeout=self.config.convergence_timeout,
        ):
            self._collect_ssh_failure_diagnostics(mgmt_ip, proxy=True)
            raise SuiteError(
                "The management bastion became reachable, but it could not reach the probe controller "
                f"at {mgmt_ip}"
            )
        self._configure_controller_probe_ports()
        self._record_controller_ssh_result(
            mode="management-bastion",
            destination=self.control_address,
            management_ip=mgmt_ip,
        )

    def _record_controller_ssh_result(
        self,
        *,
        mode: str,
        destination: str,
        management_ip: str,
    ) -> None:
        messages = {
            "provider-fixed-ipv4": (
                "Runner reached the probe controller through its provider fixed IPv4"
            ),
            "management-bastion": (
                "Runner reached a dedicated management bastion and then the probe controller"
            ),
        }
        message = messages.get(mode, "Runner reached the probe controller over SSH")
        self.reporter.result(
            "CONTROL-SSH",
            "controller-bootstrap",
            "PASS",
            message,
            family=4,
            destination=destination,
            details={
                "control_path": mode,
                "floating_ip_used_by_controller": False,
                "bastion_used": mode == "management-bastion",
                "observation_mode": self.controller_probe_mode,
                "probe_sources": dict(self.controller_probe_sources),
                "controller_management_ip": management_ip,
            },
            expected="reachable",
            observed="reachable",
            authoritative=True,
            display_name="Reach the probe controller over SSH",
            scenario="Controller readiness",
        )

    def _choose_access_cidr(self) -> str:
        used = [
            ipaddress.ip_network(cidr, strict=False)
            for cidr in (
                self.discovery.occupied_cidrs
                or [item.cidr for item in self.discovery.subnets]
            )
        ]
        used.extend(
            ipaddress.ip_network(prefix, strict=False)
            for pool in self.discovery.pools
            for prefix in pool.prefixes
        )
        used.append(ipaddress.ip_network(self.management_cidr, strict=False))
        for base_text in ("10.253.0.0/16", "192.168.224.0/20"):
            base = ipaddress.ip_network(base_text)
            for candidate in base.subnets(new_prefix=24):
                if not any(
                    candidate.overlaps(item) for item in used if item.version == 4
                ):
                    return str(candidate)
        raise SuiteError("Could not select a non-overlapping bastion access CIDR")

    def _selected_bastion_external_subnet(self):
        selected_network_ids: list[str] = []
        for item in self.controller_probe_ports:
            network_id = str(item.get("network_id") or "").strip()
            if network_id:
                selected_network_ids.append(network_id)
        for requested in self.config.external_networks:
            match = next(
                (
                    network
                    for network in self.discovery.networks
                    if network.id == requested or network.name == requested
                ),
                None,
            )
            if match is not None:
                selected_network_ids.append(match.id)

        for network_id in dict.fromkeys(selected_network_ids):
            try:
                network = self.discovery.network(network_id)
            except StopIteration:
                continue
            if not network.external:
                continue
            subnets = self.discovery.subnets_for_network(network_id)
            preferred_subnet_ids = {
                str(subnet_id)
                for item in self.controller_probe_ports
                if str(item.get("network_id") or "") == network_id
                for subnet_id in item.get("subnet_ids") or []
            }
            subnets = sorted(
                subnets,
                key=lambda subnet: (
                    subnet.id not in preferred_subnet_ids,
                    subnet.name,
                    subnet.id,
                ),
            )
            for subnet in subnets:
                if (
                    subnet.ip_version == 4
                    and subnet.gateway_ip
                    and subnet.supports_router_gateway
                    and subnet.supports_floating_ip
                ):
                    return network, subnet
        requested = ", ".join(self.config.external_networks) or "none"
        raise SuiteError(
            "No IPv4 router-gateway/floating-IP subnet exists on the explicitly "
            f"selected external network(s): {requested}"
        )

    def _select_bastion_target_host(self) -> tuple[str | None, str | None]:
        controller_host = self.controller.host if self.controller else None
        selected_az = (
            self.controller.availability_zone
            if self.controller and self.controller.availability_zone
            else getattr(self, "selected_availability_zone", None)
        )
        if not controller_host or not selected_az:
            self.reporter.event(
                "management-bastion-placement-unverified",
                "Controller placement was incomplete, so a different fallback host could not be selected explicitly",
                controller_host=controller_host,
                availability_zone=selected_az,
                authoritative=False,
            )
            return None, selected_az
        try:
            inventory = self.compute_host_inventory(refresh=True)
        except (SuiteError, OSError, ValueError, TypeError) as exc:
            self.reporter.event(
                "management-bastion-placement-inventory-unavailable",
                "Nova compute inventory was unavailable, so the fallback host could not be selected explicitly",
                controller_host=controller_host,
                availability_zone=selected_az,
                error=f"{type(exc).__name__}: {exc}",
                authoritative=False,
            )
            return None, selected_az
        candidates = sorted(
            host.host
            for host in inventory.values()
            if host.eligible
            and host.availability_zone == selected_az
            and host.host != controller_host
        )
        if not candidates:
            self.reporter.event(
                "management-bastion-independent-host-unavailable",
                "No second eligible compute host was available in the controller availability zone",
                controller_host=controller_host,
                availability_zone=selected_az,
                authoritative=True,
            )
            return None, selected_az
        target_host = candidates[0]
        self.reporter.event(
            "management-bastion-target-host-selected",
            "Selected a different eligible compute host for the fallback management bastion",
            controller_host=controller_host,
            bastion_target_host=target_host,
            availability_zone=selected_az,
            eligible_alternative_hosts=candidates,
            authoritative=True,
        )
        return target_host, selected_az

    @serialized_lifecycle
    def _create_bastion_access_topology(
        self,
        *,
        external_network: Any,
        external_subnet: Any,
        access_cidr: str,
        network_name: str,
        subnet_name: str,
        router_name: str,
    ) -> tuple[str, str]:
        claim_runtime_resource_name(self, network_name, resource_type="network")
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
        self.tracker.add("network", network_id, network_name, role="bastion-access")
        self._validate_created_resource_zone("network", network_id, network)

        claim_runtime_resource_name(self, subnet_name, resource_type="subnet")
        subnet = (
            self.osc.json(
                "subnet",
                "create",
                "--network",
                network_id,
                "--subnet-range",
                access_cidr,
                "--ip-version",
                "4",
                "--dhcp",
                "--tag",
                self.run_tag,
                subnet_name,
            )
            or {}
        )
        subnet_id = required_text(
            subnet, "id", context=f"Subnet create for {subnet_name}"
        )
        self.tracker.add(
            "subnet",
            subnet_id,
            subnet_name,
            parent_id=network_id,
            cidr=access_cidr,
            role="bastion-access",
        )

        claim_runtime_resource_name(self, router_name, resource_type="router")
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
            role="bastion-access",
            external_network_id=external_network.id,
            external_subnet_id=external_subnet.id,
        )
        self._validate_created_resource_zone("router", router_id, router)
        self.configure_router_external_gateway_default(
            router_id,
            router_name,
            external_network_id=external_network.id,
            external_subnet_id=external_subnet.id,
            ip_version=4,
        )
        self.osc.run("router", "add", "subnet", router_id, subnet_id)
        return network_id, subnet_id

    @serialized_lifecycle
    def _create_bastion_floating_ip(
        self,
        *,
        external_network_id: str,
        external_subnet_id: str,
        access_port_id: str,
    ) -> str:
        floating = (
            self.osc.json(
                "floating",
                "ip",
                "create",
                "--subnet",
                external_subnet_id,
                "--port",
                access_port_id,
                "--description",
                f"neutron-flux-{getattr(getattr(self, 'reporter', None), 'run_id', None) or self.run_tag}",
                "--tag",
                self.run_tag,
                external_network_id,
            )
            or {}
        )
        floating_id = required_text(
            floating, "id", context="Management bastion floating IP create"
        )
        floating_address = str(
            pick(
                floating,
                "floating_ip_address",
                "floating_ip",
                "address",
                default="",
            )
            or ""
        )
        if not floating_id or not floating_address:
            raise SuiteError("Management bastion floating IP allocation failed")
        self.tracker.add(
            "floating_ip",
            floating_id,
            floating_address,
            parent_id=access_port_id,
            role="bastion-access",
            address=floating_address,
        )
        return floating_address

    def _create_management_bastion(self) -> None:
        external_network, external_subnet = self._selected_bastion_external_subnet()
        access_cidr = self._choose_access_cidr()
        access_network_name = managed_resource_name(
            self,
            identity="bastion-access-network",
            role="bastion-access",
            resource_type="network",
        )
        access_subnet_name = managed_resource_name(
            self,
            identity=f"bastion-access-subnet:{access_cidr}",
            role="bastion-access",
            resource_type="subnet",
        )
        access_router_name = managed_resource_name(
            self,
            identity=(
                f"bastion-access-router:{external_network.id}:{external_subnet.id}"
            ),
            role="bastion-access",
            resource_type="router",
        )
        access_port_name = managed_resource_name(
            self,
            identity="bastion-access-port",
            role="bastion-access",
            resource_type="port",
        )
        mgmt_port_name = managed_resource_name(
            self,
            identity="bastion-management-port",
            role="bastion-management",
            resource_type="port",
        )

        network_id, subnet_id = self._create_bastion_access_topology(
            external_network=external_network,
            external_subnet=external_subnet,
            access_cidr=access_cidr,
            network_name=access_network_name,
            subnet_name=access_subnet_name,
            router_name=access_router_name,
        )

        access_port = self._create_port(
            access_port_name,
            network_id,
            [subnet_id],
            self.controller_sg_id,
            role="bastion-access",
        )
        management_port = self._create_port(
            mgmt_port_name,
            self.management_network_id,
            [self.management_subnet_id],
            self.endpoint_management_sg_id,
            role="bastion-management",
        )
        access_port_id = required_text(
            access_port, "id", context=f"Access port create for {access_port_name}"
        )
        management_port_id = required_text(
            management_port,
            "id",
            context=f"Management port create for {mgmt_port_name}",
        )
        management_ip = self._fixed_ips(management_port).get(self.management_subnet_id)
        if not management_ip:
            raise SuiteError("Bastion management port did not receive an IPv4 address")
        bastion_name = managed_resource_name(
            self,
            identity="management-bastion",
            role="management-bastion",
            resource_type="server",
        )
        bastion_target_host, bastion_target_az = self._select_bastion_target_host()
        server = self._create_server(
            bastion_name,
            [access_port_id, management_port_id],
            role="management-bastion",
            target_host=bastion_target_host,
            target_availability_zone=(
                bastion_target_az if bastion_target_host else None
            ),
        )
        self.bastion = Endpoint(
            label="management-bastion",
            server_id=server["server_id"],
            server_name=server["server_name"],
            management_port_id=management_port_id,
            management_ip=management_ip,
            test_port_id=access_port_id,
            test_mac=str(pick(access_port, "mac_address", default="") or ""),
            fixed_ips=self._fixed_ips(access_port),
            host=server["host"],
            availability_zone=server["availability_zone"],
            volume_id=server["volume_id"],
        )
        controller_host = self.controller.host if self.controller else None
        bastion_host = self.bastion.host
        placement_independent: bool | None = None
        if controller_host and bastion_host:
            placement_independent = bastion_host != controller_host
        if placement_independent is True:
            placement_message = (
                "The fallback management bastion is on a different compute host "
                "from the controller"
            )
        elif placement_independent is False:
            placement_message = (
                "The fallback management bastion shares the controller compute host"
            )
        else:
            placement_message = (
                "The fallback management bastion placement could not be verified"
            )
        self.reporter.event(
            "management-bastion-placement",
            placement_message,
            controller_host=controller_host,
            bastion_host=bastion_host,
            placement_independent=placement_independent,
            requested_bastion_host=bastion_target_host,
            authoritative=placement_independent is not None,
        )
        floating_address = self._create_bastion_floating_ip(
            external_network_id=external_network.id,
            external_subnet_id=external_subnet.id,
            access_port_id=access_port_id,
        )
        self._set_control_address(floating_address)
        if not self._wait_for_ssh(
            floating_address,
            proxy=False,
            timeout=self.config.convergence_timeout,
        ):
            self._collect_ssh_failure_diagnostics(floating_address, proxy=False)
            raise SuiteError(
                f"Management bastion did not become reachable at floating IP {floating_address}"
            )
        self.reporter.event(
            "management-bastion-ready",
            "Created a dedicated management bastion because provider fixed IPv4 SSH was unreachable",
            bastion_floating_ip=floating_address,
            controller_management_ip=(
                self.controller.management_ip if self.controller else None
            ),
            external_network=external_network.name,
            external_subnet=external_subnet.name,
            controller_host=controller_host,
            bastion_host=bastion_host,
            placement_independent=placement_independent,
        )

    def _configure_controller_probe_ports(self) -> None:
        if not self.controller_probe_ports:
            self.reporter.result(
                "CONTROL-OBSERVATION-PORTS",
                "controller-bootstrap",
                "NOT_APPLICABLE",
                "No provider family was available for controller observation ports",
                display_name="Configure the OpenStack probe controller",
                scenario="Controller readiness",
            )
            return
        for _index, item in enumerate(self.controller_probe_ports, start=1):
            self._verify_fixed_ip_interface(
                label=f"controller:{item['network_name']}",
                mac_address=str(item["mac_address"]),
                fixed_ips=dict(item["fixed_ips"]),
                executor=self.ssh_controller,
            )
        self.reporter.result(
            "CONTROL-OBSERVATION-PORTS",
            "controller-bootstrap",
            "PASS",
            "OpenStack-provided controller networking is usable for runner access",
            details={
                "mode": self.controller_probe_mode,
                "ports": self.controller_probe_ports,
                "sources": dict(self.controller_probe_sources),
            },
            expected="reachable",
            observed="reachable",
            authoritative=True,
            display_name="Configure the OpenStack probe controller",
            scenario="Controller readiness",
        )

    @staticmethod
    def _require_ipv4(address: str, label: str) -> None:
        try:
            family = ipaddress.ip_address(address).version
        except ValueError as exc:
            raise SuiteError(f"{label} is not an IP address: {address}") from exc
        if family != 4:
            raise SuiteError(f"{label} must be IPv4, got {address}")

    def _set_control_address(self, address: str) -> None:
        self._require_ipv4(address, "runner-to-controller SSH address")
        self.control_address = address

    def _network_port_security_enabled(self, network_id: str) -> bool:
        known = next(
            (item for item in self.discovery.networks if item.id == network_id), None
        )
        if known is not None and known.port_security_enabled is not None:
            return bool(known.port_security_enabled)
        detail = self.osc.json("network", "show", network_id, check=False) or {}
        value = pick(detail, "port_security_enabled", default=True)
        if isinstance(value, str):
            return value.strip().lower() not in {"false", "0", "no", "off"}
        return bool(value)

    def _wait_for_port_attachment_ready(
        self, port_id: str, name: str, *, timeout: int | None = None
    ) -> dict[str, Any]:
        """Require a newly created Neutron port to settle before Nova uses it."""

        limit = timeout or min(60, max(15, int(self.config.convergence_timeout)))
        deadline = time.monotonic() + limit
        stable_reads = 0
        previous: tuple[str, str, str, str, str] | None = None
        last_summary = "no port inventory returned"
        while time.monotonic() < deadline:
            detail = (
                self.osc.json(
                    "port",
                    "show",
                    port_id,
                    check=False,
                    timeout=min(30, self.config.resource_timeout),
                )
                or {}
            )
            if not isinstance(detail, dict):
                stable_reads = 0
                previous = None
                time.sleep(self.config.convergence_interval)
                continue
            owner = str(pick(detail, "device_owner", default="") or "")
            device_id = str(pick(detail, "device_id", default="") or "")
            binding_host = str(
                pick(
                    detail,
                    "binding_host_id",
                    "binding:host_id",
                    "binding_host",
                    default="",
                )
                or ""
            )
            status = str(pick(detail, "status", default="") or "").lower()
            fixed_ips = repr(pick(detail, "fixed_ips", default=[]))
            signature = (owner, device_id, binding_host, status, fixed_ips)
            ready = not owner and not device_id and not binding_host
            last_summary = (
                f"status={status or 'unknown'}, owner={owner or 'none'}, "
                f"device_id={device_id or 'none'}, "
                f"binding_host={binding_host or 'none'}"
            )
            if ready and signature == previous:
                stable_reads += 1
            elif ready:
                stable_reads = 1
            else:
                stable_reads = 0
            previous = signature
            if stable_reads >= 2:
                self.logger.log(
                    f"Port attachment barrier settled for {name} ({port_id}): "
                    f"{last_summary}, stable_reads={stable_reads}"
                )
                return detail
            time.sleep(self.config.convergence_interval)
        raise SuiteError(
            f"Timed out waiting for newly created port {name} ({port_id}) to "
            f"settle before Nova attachment after {limit}s: {last_summary}"
        )

    @serialized_lifecycle
    def _create_port(
        self,
        name: str,
        network_id: str,
        subnet_ids: list[str],
        security_group_id: str | None,
        **metadata: Any,
    ) -> dict[str, Any]:
        port_security_enabled = self._network_port_security_enabled(network_id)
        args = ["port", "create", "--network", network_id]
        if port_security_enabled and security_group_id:
            args.extend(["--security-group", security_group_id])
        else:
            args.append("--no-security-group")
        args.extend(["--tag", self.run_tag])
        for subnet_id in subnet_ids:
            args.extend(["--fixed-ip", f"subnet={subnet_id}"])
        args.append(name)
        claim_runtime_resource_name(self, name, resource_type="port")
        data = self.osc.json(*args) or {}
        resource_id = required_text(data, "id", context=f"OpenStack create for {name}")
        if not resource_id:
            raise SuiteError(f"Port creation returned no ID: {name}")
        actual_port_security = pick(
            data, "port_security_enabled", default=port_security_enabled
        )
        if isinstance(actual_port_security, str):
            actual_port_security = actual_port_security.strip().lower() not in {
                "false",
                "0",
                "no",
                "off",
            }
        metadata.setdefault("port_security_enabled", bool(actual_port_security))
        metadata.setdefault(
            "security_group_id",
            security_group_id if bool(actual_port_security) else None,
        )
        self.tracker.add("port", resource_id, name, parent_id=network_id, **metadata)
        data["port_security_enabled"] = bool(actual_port_security)
        if getattr(self, "lifecycle_settlement_enabled", False):
            self._wait_for_port_attachment_ready(resource_id, name)
        return data
