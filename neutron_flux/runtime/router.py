from __future__ import annotations

import ast
import json
import time
from typing import Any

# mypy: disable-error-code="attr-defined"
from ..errors import SuiteError
from ..failure_injection import inject_failure
from ..models import Endpoint, PlannedGroup, RuntimeGroup
from ..resource_naming import claim_runtime_resource_name
from ..utils import iso_utc, optional_text, pick
from .types import RouterSnapshot


class RouterRuntimeMixin:
    """Compatibility mixin for the router runtime subsystem."""

    def _record_router_addresses(
        self,
        router_id: str,
        *,
        interface_addresses: list[dict[str, Any]] | None = None,
        external_gateway_info: dict[str, Any] | None = None,
    ) -> None:
        """Persist router IP information for reporting and cleanup evidence.

        Router addresses are dataplane-significant facts.  Store exact addresses
        returned by Neutron whenever Flux observes them so offline dashboards do
        not need to infer router interfaces from names or CIDRs.
        """
        reporter = getattr(self, "reporter", None)
        resources = getattr(reporter, "resources", None)
        if reporter is None or resources is None:
            return
        record = next(
            (
                item
                for item in resources
                if item.resource_type == "router" and item.id == router_id
            ),
            None,
        )
        if record is None:
            return
        changed = False
        if interface_addresses is not None:
            normalized = [
                {
                    "subnet_id": str(item.get("subnet_id") or ""),
                    "network_id": str(item.get("network_id") or "") or None,
                    "ip_address": str(item.get("ip_address") or ""),
                    "purpose": str(item.get("purpose") or "router interface"),
                }
                for item in interface_addresses
                if item.get("subnet_id") and item.get("ip_address")
            ]
            if normalized != record.metadata.get("interface_addresses"):
                record.metadata["interface_addresses"] = normalized
                changed = True
        if external_gateway_info is not None:
            gateway = self._gateway_info(external_gateway_info)
            fixed_ips = [
                {
                    "subnet_id": str(item.get("subnet_id") or ""),
                    "ip_address": str(item.get("ip_address") or ""),
                }
                for item in gateway.get("external_fixed_ips") or []
                if isinstance(item, dict) and item.get("subnet_id")
            ]
            if fixed_ips != record.metadata.get("external_gateway_addresses"):
                record.metadata["external_gateway_addresses"] = fixed_ips
                changed = True
            network_id = str(gateway.get("network_id") or "")
            if network_id and network_id != record.metadata.get("external_network_id"):
                record.metadata["external_network_id"] = network_id
                changed = True
        if changed:
            self.reporter.update_resource(record)

    def _router_interface_ip(self, router_id: str, subnet_id: str) -> str:
        ports = (
            self.osc.json("port", "list", "--device-id", router_id, check=False) or []
        )
        for row in ports if isinstance(ports, list) else []:
            port_id = str(pick(row, "id", default="") or "")
            detail = (
                self.osc.json("port", "show", port_id, check=False) or row
                if port_id
                else row
            )
            address = self._fixed_ips(detail).get(subnet_id)
            if address:
                return address
        raise SuiteError(
            f"Could not find router {router_id} interface address on subnet {subnet_id}"
        )

    def _optional_router_interface_ip(
        self, router_id: str, subnet_id: str
    ) -> str | None:
        """Best-effort reporting lookup that must not invalidate a topology.

        Router-interface creation is already verified by the authoritative
        OpenStack cloud operation result.  Address capture enriches offline reports,
        but a transient read failure must not turn a valid topology into a
        setup failure.
        """
        try:
            return self._router_interface_ip(router_id, subnet_id)
        except SuiteError as exc:
            logger = getattr(self, "logger", None)
            if logger is not None and hasattr(logger, "log"):
                logger.log(
                    f"Router interface address was not captured for reporting: {exc}",
                    "WARNING",
                )
            return None

    def _create_router_interface_port(
        self,
        *,
        network_id: str,
        subnet_id: str,
        name: str,
        group: PlannedGroup,
        generation: int,
        side: str,
    ) -> tuple[str, str]:
        claim_runtime_resource_name(self, name, resource_type="port")
        detail = (
            self.osc.json(
                "port",
                "create",
                "--network",
                network_id,
                "--fixed-ip",
                f"subnet={subnet_id}",
                "--no-security-group",
                "--tag",
                self.run_tag,
                name,
            )
            or {}
        )
        port_id = str(pick(detail, "id", default="") or "")
        if not port_id:
            raise SuiteError(
                f"OpenStack did not return an ID for router interface port {name}"
            )
        address = self._fixed_ips(detail).get(subnet_id)
        if not address:
            shown = self.osc.json("port", "show", port_id, check=False) or {}
            address = self._fixed_ips(shown).get(subnet_id)
        if not address:
            raise SuiteError(
                f"Router interface port {name} has no dynamically allocated address on subnet {subnet_id}"
            )
        self.tracker.add(
            "port",
            port_id,
            name,
            parent_id=network_id,
            role="router-transit-interface",
            group_id=group.id,
            generation=generation,
            scenario_side=side,
            subnet_id=subnet_id,
            fixed_ip=address,
        )
        return port_id, address

    def _attach_router_port(
        self, router_id: str, router_name: str, port_id: str, port_name: str
    ) -> None:
        result = self.osc.run(
            "router",
            "add",
            "port",
            router_id,
            port_id,
            check=False,
            timeout=min(60, self.config.resource_timeout),
        )
        if result.returncode != 0:
            raise SuiteError(
                f"Could not attach transit port {port_name} to {router_name}: "
                f"{(result.stderr or result.stdout).strip()}"
            )
        detail = self.osc.json("port", "show", port_id, check=False) or {}
        actual_router = str(pick(detail, "device_id", default="") or "")
        if actual_router and actual_router != router_id:
            raise SuiteError(
                f"Transit port {port_name} attached to unexpected router {actual_router}, expected {router_id}"
            )

    def wait_router_route(
        self,
        router_id: str,
        destination: str,
        gateway: str,
        *,
        present: bool,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + self.config.convergence_timeout
        attempts = 0
        last_present = False
        while time.monotonic() < deadline:
            attempts += 1
            detail = self.osc.json("router", "show", router_id, check=False) or {}
            routes = pick(detail, "routes", default=[])
            if isinstance(routes, str):
                try:
                    routes = ast.literal_eval(routes)
                except (ValueError, SyntaxError):
                    routes = []
            last_present = any(
                isinstance(item, dict)
                and str(item.get("destination") or "") == destination
                and str(item.get("nexthop") or item.get("gateway") or "") == gateway
                for item in routes
                if isinstance(routes, list)
            )
            if last_present == present:
                return {
                    "matched": True,
                    "present": last_present,
                    "attempts": attempts,
                    "router_id": router_id,
                    "destination": destination,
                    "gateway": gateway,
                }
            time.sleep(self.config.convergence_interval)
        return {
            "matched": False,
            "present": last_present,
            "attempts": attempts,
            "router_id": router_id,
            "destination": destination,
            "gateway": gateway,
        }

    def set_static_routes(self, runtime: RuntimeGroup, *, enabled: bool) -> None:
        routes = runtime.metadata.get("routes") or {}
        operation = "add" if enabled else "remove"
        errors: list[str] = []
        for side in ("A", "B"):
            route = routes.get(side) or {}
            router_id = route.get("router_id")
            destination = route.get("destination")
            gateway = route.get("gateway")
            if not all((router_id, destination, gateway)):
                errors.append(f"route metadata missing for side {side}")
                continue
            result = self.osc.run(
                "router",
                operation,
                "route",
                "--route",
                f"destination={destination},gateway={gateway}",
                str(router_id),
                check=False,
                timeout=min(60, self.config.resource_timeout),
            )
            state = self.wait_router_route(
                str(router_id), str(destination), str(gateway), present=enabled
            )
            if result.returncode != 0 and state.get("matched"):
                continue
            if result.returncode != 0:
                errors.append((result.stderr or result.stdout).strip())
                continue
            if not state.get("matched"):
                errors.append(
                    f"OpenStack did not confirm route {destination} via {gateway} "
                    f"was {'added' if enabled else 'removed'} on router {router_id}"
                )
        if errors:
            raise SuiteError(
                f"Could not {operation} OpenStack router static routes: "
                + "; ".join(errors)
            )
        runtime.metadata["routes_installed"] = enabled

    def set_one_static_route(
        self, runtime: RuntimeGroup, *, side: str, enabled: bool
    ) -> None:
        route = (runtime.metadata.get("routes") or {}).get(side.upper()) or {}
        if not route:
            raise SuiteError(f"Router static-route metadata missing for side {side}")
        operation = "add" if enabled else "remove"
        result = self.osc.run(
            "router",
            operation,
            "route",
            "--route",
            f"destination={route['destination']},gateway={route['gateway']}",
            str(route["router_id"]),
            check=False,
            timeout=min(60, self.config.resource_timeout),
        )
        state = self.wait_router_route(
            str(route["router_id"]),
            str(route["destination"]),
            str(route["gateway"]),
            present=enabled,
        )
        if result.returncode != 0 and not state.get("matched"):
            raise SuiteError(
                f"Could not {operation} route {route['destination']} via {route['gateway']}: "
                f"{(result.stderr or result.stdout).strip()}"
            )
        if not state.get("matched"):
            raise SuiteError(
                f"OpenStack did not confirm route {route['destination']} via {route['gateway']} "
                f"was {'added' if enabled else 'removed'}"
            )
        if not enabled:
            runtime.metadata["routes_installed"] = False

    # Legacy runtime integration compatibility.
    set_extra_routes = set_static_routes
    set_one_extra_route = set_one_static_route

    def wait_router_interface(
        self,
        router_id: str,
        subnet_id: str,
        *,
        present: bool,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + self.config.convergence_timeout
        attempts = 0
        last_present = False
        while time.monotonic() < deadline:
            attempts += 1
            ports = (
                self.osc.json("port", "list", "--device-id", router_id, check=False)
                or []
            )
            last_present = False
            for row in ports if isinstance(ports, list) else []:
                if not isinstance(row, dict):
                    continue
                if subnet_id in self._fixed_ips(row):
                    last_present = True
                    break
                port_id = optional_text(pick(row, "id"))
                if not port_id:
                    continue
                detail = self.osc.json("port", "show", port_id, check=False) or row
                if subnet_id in self._fixed_ips(detail):
                    last_present = True
                    break
            if last_present == present:
                return {
                    "matched": True,
                    "present": last_present,
                    "attempts": attempts,
                    "router_id": router_id,
                    "subnet_id": subnet_id,
                }
            time.sleep(self.config.convergence_interval)
        return {
            "matched": False,
            "present": last_present,
            "attempts": attempts,
            "router_id": router_id,
            "subnet_id": subnet_id,
        }

    @staticmethod
    def _gateway_info(value: Any) -> dict[str, Any]:
        """Normalize OSC external_gateway_info output into a stable dictionary."""
        if isinstance(value, dict):
            parsed = dict(value)
        elif not value:
            return {}
        else:
            text = str(value).strip()
            parsed = {}
            for parser in (json.loads, ast.literal_eval):
                try:
                    candidate = parser(text)
                except (ValueError, SyntaxError, json.JSONDecodeError, TypeError):
                    continue
                if isinstance(candidate, dict):
                    parsed = dict(candidate)
                    break
            if not parsed:
                return {}

        fixed_ips = parsed.get("external_fixed_ips") or []
        if isinstance(fixed_ips, str):
            for parser in (json.loads, ast.literal_eval):
                try:
                    candidate = parser(fixed_ips)
                except (ValueError, SyntaxError, json.JSONDecodeError, TypeError):
                    continue
                if isinstance(candidate, list):
                    fixed_ips = candidate
                    break
        normalized_fixed: list[dict[str, str]] = []
        for item in fixed_ips if isinstance(fixed_ips, list) else []:
            if not isinstance(item, dict):
                continue
            subnet_id = item.get("subnet_id") or item.get("subnet")
            ip_address = item.get("ip_address") or item.get("ip-address")
            normalized: dict[str, str] = {}
            if subnet_id:
                normalized["subnet_id"] = str(subnet_id)
            if ip_address:
                normalized["ip_address"] = str(ip_address)
            if normalized:
                normalized_fixed.append(normalized)
        normalized_fixed.sort(
            key=lambda item: (item.get("subnet_id", ""), item.get("ip_address", ""))
        )
        source_nat_value = parsed.get("enable_snat")
        if isinstance(source_nat_value, str):
            source_nat_enabled = source_nat_value.strip().lower() not in {
                "false",
                "0",
                "no",
                "off",
                "",
            }
        else:
            source_nat_enabled = (
                None if source_nat_value is None else bool(source_nat_value)
            )
        return {
            "network_id": str(parsed.get("network_id") or ""),
            "enable_snat": source_nat_enabled,
            "external_fixed_ips": normalized_fixed,
        }

    def capture_router_state(self, router_id: str) -> RouterSnapshot:
        detail = self.osc.json("router", "show", router_id) or {}
        gateway = self._gateway_info(pick(detail, "external_gateway_info", default={}))
        routes = pick(detail, "routes", default=[])
        if isinstance(routes, str):
            try:
                routes = ast.literal_eval(routes)
            except (ValueError, SyntaxError):
                routes = []
        return RouterSnapshot(
            router_id=router_id,
            external_gateway_info=gateway,
            routes=routes if isinstance(routes, list) else [],
            admin_state_up=bool(pick(detail, "admin_state_up", default=True)),
            revision_number=pick(
                detail, "revision_number", "revision number", default=None
            ),
        )

    def configure_router_external_gateway_default(
        self,
        router_id: str,
        router_name: str,
        *,
        external_network_id: str,
        external_subnet_id: str,
        ip_version: int,
        require_source_nat: bool = True,
    ) -> RouterSnapshot:
        """Set only the gateway network and verify Neutron's member default.

        Project members can normally select an external gateway network, but
        Neutron's default policy does not allow them to choose ``enable_snat``
        or an external fixed gateway IP. Flux therefore omits both fields in
        every mode and observes the resulting state before continuing.
        """

        result = self.osc.run(
            "router",
            "set",
            "--external-gateway",
            external_network_id,
            router_id,
            check=False,
            timeout=min(60, self.config.resource_timeout),
        )
        if result.returncode != 0:
            raise SuiteError(
                f"Could not configure the external gateway on router {router_name}: "
                f"{(result.stderr or result.stdout).strip()}"
            )

        if ip_version == 4 and require_source_nat:
            observed = self.wait_router_source_nat(router_id, True)
            if not observed.get("matched"):
                raise SuiteError(
                    f"Neutron's default source NAT setting was not enabled on "
                    f"IPv4 router {router_name}. Flux did not override it because "
                    "the suite follows the project-member contract: "
                    + "; ".join(
                        observed.get("differences")
                        or ["default source NAT state was not enabled"]
                    )
                )
            snapshot = observed.get("state") or {}
        elif ip_version in {4, 6}:
            snapshot = self.capture_router_state(router_id)
        else:
            raise SuiteError(
                f"Unsupported router gateway IP version for {router_name}: {ip_version}"
            )

        gateway = self._gateway_info(snapshot.get("external_gateway_info") or {})
        if gateway.get("network_id") != external_network_id:
            raise SuiteError(
                f"Neutron attached router {router_name} to external network "
                f"{gateway.get('network_id') or 'unknown'}, not planned network "
                f"{external_network_id}"
            )
        external_subnets = {
            str(item.get("subnet_id") or "")
            for item in gateway.get("external_fixed_ips") or []
            if isinstance(item, dict)
        }
        if external_subnet_id not in external_subnets:
            raise SuiteError(
                f"Neutron did not allocate router {router_name}'s default gateway "
                f"from planned external subnet {external_subnet_id}. Flux did not "
                f"request an administrative fixed gateway IP: {gateway}"
            )
        self._record_router_addresses(router_id, external_gateway_info=gateway)
        self.logger.log(
            f"Router {router_name} external gateway ready; source_nat="
            f"{gateway.get('enable_snat') if ip_version == 4 else 'not applicable (IPv6)'}; "
            f"external_fixed_ips={gateway.get('external_fixed_ips')}"
        )
        snapshot["external_gateway_info"] = gateway
        return snapshot

    def wait_router_source_nat(
        self,
        router_id: str,
        enabled: bool,
        *,
        expected_gateway: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + self.config.convergence_timeout
        attempts = 0
        last_state: dict[str, Any] = {}
        last_differences: list[str] = []
        while time.monotonic() < deadline:
            attempts += 1
            last_state = self.capture_router_state(router_id)
            gateway = last_state.get("external_gateway_info") or {}
            snat_matches = gateway.get("enable_snat") is bool(enabled)
            gateway_matches = True
            if expected_gateway is not None:
                expected = self._gateway_info(expected_gateway)
                current = self._gateway_info(gateway)
                # The source-NAT bit is the only field allowed to differ from
                # the saved gateway while the cloud operation is active.
                expected["enable_snat"] = bool(enabled)
                gateway_matches = current == expected
                if not gateway_matches:
                    last_differences = [
                        f"current gateway={current}, expected gateway={expected}"
                    ]
            if snat_matches and gateway_matches:
                self._record_router_addresses(router_id, external_gateway_info=gateway)
                return {
                    "matched": True,
                    "attempts": attempts,
                    "state": last_state,
                    "differences": [],
                }
            time.sleep(self.config.convergence_interval)
        return {
            "matched": False,
            "attempts": attempts,
            "state": last_state,
            "differences": last_differences
            or [f"enable_snat did not become {bool(enabled)}"],
        }

    def wait_floating_ip_association(
        self,
        floating_ip_id: str,
        *,
        expected_port_id: str | None,
        expected_fixed_ip: str | None = None,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + self.config.convergence_timeout
        attempts = 0
        last: dict[str, Any] = {}
        while time.monotonic() < deadline:
            attempts += 1
            detail = (
                self.osc.json("floating", "ip", "show", floating_ip_id, check=False)
                or {}
            )
            port_id = str(pick(detail, "port_id", "port", default="") or "") or None
            fixed_ip = (
                str(pick(detail, "fixed_ip_address", "fixed_ip", default="") or "")
                or None
            )
            port_matches = port_id == expected_port_id
            fixed_matches = expected_fixed_ip is None or fixed_ip == expected_fixed_ip
            last = {
                "floating_ip_id": floating_ip_id,
                "floating_ip_address": pick(
                    detail, "floating_ip_address", default=None
                ),
                "observed_at": iso_utc(),
                "matched": port_matches and fixed_matches,
                "port_id": port_id,
                "fixed_ip_address": fixed_ip,
                "expected_port_id": expected_port_id,
                "expected_fixed_ip": expected_fixed_ip,
                "attempts": attempts,
                "read_evidence": detail.get("_read_evidence", "floating ip show"),
            }
            if last["matched"]:
                return last
            time.sleep(self.config.convergence_interval)
        return last or {
            "matched": False,
            "port_id": None,
            "fixed_ip_address": None,
            "expected_port_id": expected_port_id,
            "expected_fixed_ip": expected_fixed_ip,
            "attempts": attempts,
        }

    def _verify_fixed_ip_interface(
        self,
        *,
        label: str,
        mac_address: str,
        fixed_ips: dict[str, str],
        executor: Any,
    ) -> dict[str, Any]:
        """Read and validate guest networking without changing the VM."""
        inject_failure(self.config, "before-guest-network-verify")
        details = self.guest_network.verify(
            label=label,
            mac_address=mac_address,
            fixed_ips=fixed_ips,
            executor=executor,
        )
        inject_failure(self.config, "after-guest-network-verify")
        return details

    def _configure_endpoint(
        self, endpoint: Endpoint, table_base: int, *, reuse_probe: bool = False
    ) -> None:
        # The method name is retained for checkpoint compatibility.  It performs
        # no guest network configuration; it only verifies what OpenStack and
        # the selected cloud image configured during boot.
        self.logger.log(
            f"Verifying OpenStack-provided networking on {endpoint.label}: "
            f"test_interface={endpoint.test_mac}, addresses={','.join(endpoint.fixed_ips.values())}"
        )
        details = self._verify_fixed_ip_interface(
            label=endpoint.label,
            mac_address=endpoint.test_mac or "",
            fixed_ips=endpoint.fixed_ips,
            executor=lambda command: self.ssh_endpoint(endpoint, command),
        )
        endpoint.metadata = getattr(endpoint, "metadata", {})
        endpoint.metadata["guest_network_verification"] = details
        inject_failure(self.config, "before-probe-service")
        self._start_probe_server(endpoint, reuse_existing=reuse_probe)
        inject_failure(self.config, "after-probe-service")
        self.logger.log(
            f"Endpoint {endpoint.label} is ready; no network configuration was written inside the VM"
        )

    def reconfigure_endpoint(
        self, endpoint: Endpoint, *, reuse_probe: bool = False
    ) -> None:
        """Re-verify guest networking and ensure the transient probe is ready.

        Live migration may preserve the remote process even if its original SSH
        control channel disappeared.  In that case reuse the verified listener
        instead of starting a duplicate process on the same ports.
        """
        self._configure_endpoint(
            endpoint, endpoint.network_table_base, reuse_probe=reuse_probe
        )
