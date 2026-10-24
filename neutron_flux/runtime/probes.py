from __future__ import annotations

import ipaddress
import json
import re
import shlex
import subprocess
import time
import uuid
from typing import Any

# mypy: disable-error-code="attr-defined"
from ..cancellation import raise_if_cancelled, run_cancellable
from ..errors import ProbeServiceError, SSHExecutionError, SuiteError
from ..failure_injection import inject_failure
from ..models import Endpoint, RuntimeGroup
from ..mtu_contract import positive_mtu
from ..translation_safety import validate_runtime_floating_ip_target
from ..utils import pick, required_text


class ProbeRuntimeMixin:
    """Compatibility mixin for the probes runtime subsystem."""

    def inspect_endpoint_route(
        self,
        endpoint: Endpoint,
        source_ip: str,
        destination_ip: str,
        family: int,
    ) -> dict[str, Any]:
        flag = "-6" if family == 6 else "-4"
        command = (
            f"ip {flag} route get {shlex.quote(destination_ip)} "
            f"from {shlex.quote(source_ip)}"
        )
        # Read routes and interface addresses in one guest call. Names alone
        # are not proof: compare the actual egress MAC to the Neutron data port.
        inventory_command = (
            command + "; route_rc=$?; printf '\\nNF_ROUTE_INTERFACES\\n'; "
            'ip -j address show; exit "$route_rc"'
        )
        result = self.ssh_endpoint(endpoint, inventory_command)
        text, marker, inventory_text = (result.stdout or "").partition(
            "NF_ROUTE_INTERFACES\n"
        )
        text = text.strip()
        device_match = re.search(r"(?:^|\s)dev\s+(\S+)", text)
        source_match = re.search(r"(?:^|\s)(?:src|from)\s+(\S+)", text)
        interfaces = None
        if marker:
            try:
                parsed = json.loads(inventory_text)
                if isinstance(parsed, list):
                    interfaces = parsed
            except (TypeError, ValueError):
                pass
        return {
            "returncode": result.returncode,
            "stdout": text,
            "stderr": (result.stderr or "").strip(),
            "via_gateway": bool(re.search(r"(?:^|\s)via\s+\S+", text)),
            "device": device_match.group(1) if device_match else None,
            "source": source_match.group(1) if source_match else None,
            "interfaces": interfaces,
            "command": inventory_command,
        }

    def _runtime_subnet(self, subnet_id: str) -> dict[str, Any]:
        for subnet in self.discovery.subnets:
            if subnet.id == subnet_id:
                network = self.discovery.network(subnet.network_id)
                mtu = positive_mtu(network.mtu)
                return {
                    "cidr": subnet.cidr,
                    "gateway": subnet.gateway_ip,
                    "mtu": mtu,
                    "mtu_authoritative": mtu is not None,
                    "mtu_authority": (
                        "Neutron discovery network.mtu"
                        if mtu is not None
                        else "Neutron network.mtu unavailable"
                    ),
                    "mtu_source": "discovery inventory",
                    "mtu_resource_id": network.id,
                }
        detail = self.osc.json("subnet", "show", subnet_id) or {}
        network_id = str(pick(detail, "network_id", "network", default="") or "")
        network_detail = (
            self.osc.json("network", "show", network_id, check=False)
            if network_id
            else {}
        )
        mtu = positive_mtu(pick(network_detail or {}, "mtu", default=None))
        return {
            "cidr": required_text(
                detail, "subnet", "cidr", context=f"Subnet show for {subnet_id}"
            ),
            "gateway": pick(detail, "gateway_ip"),
            "mtu": mtu,
            "mtu_authoritative": mtu is not None,
            "mtu_authority": (
                "live Neutron network.mtu"
                if mtu is not None
                else "Neutron network.mtu unavailable"
            ),
            "mtu_source": "openstack network show",
            "mtu_resource_id": network_id or None,
        }

    def _existing_probe_service_ready(
        self, endpoint: Endpoint
    ) -> tuple[bool, dict[str, Any]]:
        addresses: dict[int, str] = {}
        candidate_addresses = [endpoint.management_ip, *endpoint.fixed_ips.values()]
        for value in candidate_addresses:
            try:
                family = ipaddress.ip_address(value).version
            except ValueError:
                continue
            # The transient server binds wildcard sockets.  Verify it through
            # guest loopback so provider routing, policy routing, or a Neutron
            # hairpin path cannot make a healthy surviving listener look absent.
            addresses.setdefault(family, "::1" if family == 6 else "127.0.0.1")
        code = f"""
import json
import socket

ADDRESSES = {addresses!r}
TCP_PORT = {int(self.config.tcp_port)}
UDP_PORT = {int(self.config.udp_port)}
PROBE_ID = {endpoint.server_id!r}
REQUEST = ('NF-HEALTH ' + PROBE_ID).encode('utf-8')
results = {{}}
for family_number, address in ADDRESSES.items():
    family = socket.AF_INET6 if int(family_number) == 6 else socket.AF_INET
    item = {{'tcp': False, 'udp': False, 'instance_id': None, 'errors': []}}
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(3)
            sock.connect((address, TCP_PORT))
            sock.sendall(REQUEST + b'\\n')
            received = bytearray()
            while len(received) < 4096:
                chunk = sock.recv(4096 - len(received))
                if not chunk:
                    break
                received += chunk
                if received.endswith(b'\\n'):
                    break
            prefix = b'NF-HEALTH-OK '
            if bytes(received).startswith(prefix):
                health = json.loads(bytes(received)[len(prefix):].decode('utf-8'))
                item['tcp'] = health.get('probe_id') == PROBE_ID
                item['instance_id'] = health.get('instance_id')
    except BaseException as exc:
        item['errors'].append('tcp:' + type(exc).__name__ + ':' + str(exc))
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.sendto(REQUEST, (address, UDP_PORT))
            received, _ = sock.recvfrom(4096)
            prefix = b'NF-HEALTH-OK '
            if received.startswith(prefix):
                health = json.loads(received[len(prefix):].decode('utf-8'))
                item['udp'] = (
                    health.get('probe_id') == PROBE_ID
                    and health.get('instance_id') == item['instance_id']
                )
    except BaseException as exc:
        item['errors'].append('udp:' + type(exc).__name__ + ':' + str(exc))
    results[str(family_number)] = item
identities = {{
    item.get('instance_id')
    for item in results.values()
    if item.get('tcp') and item.get('udp') and item.get('instance_id')
}}
service_identity = (
    {{'probe_id': PROBE_ID, 'instance_id': next(iter(identities))}}
    if len(identities) == 1 and all(
        item.get('tcp') and item.get('udp') for item in results.values()
    )
    else None
)
payload = {{
    'listeners': results,
    'processes': [],
    'service_identity': service_identity,
    'inspection_complete': True,
}}
print(json.dumps(payload, separators=(',', ':')))
"""
        result = self.ssh_endpoint(
            endpoint,
            "python3 -c " + shlex.quote(code),
            timeout=20,
        )
        if result.returncode != 0:
            return False, {
                "returncode": result.returncode,
                "stderr": (result.stderr or "").strip(),
                "stdout": (result.stdout or "").strip(),
            }
        try:
            payload = json.loads((result.stdout or "").strip().splitlines()[-1])
        except (IndexError, json.JSONDecodeError):
            return False, {"stdout": (result.stdout or "").strip()}
        if not isinstance(payload, dict):
            return False, {"stdout": (result.stdout or "").strip()}
        listeners = payload.get("listeners")
        identity = payload.get("service_identity")
        ready = (
            isinstance(listeners, dict)
            and bool(listeners)
            and set(listeners) == {str(family) for family in addresses}
            and isinstance(identity, dict)
            and identity.get("probe_id") == endpoint.server_id
            and bool(identity.get("instance_id"))
            and payload.get("inspection_complete") is True
            and all(
                isinstance(item, dict)
                and item.get("tcp") is True
                and item.get("udp") is True
                and item.get("instance_id") == identity["instance_id"]
                for item in listeners.values()
            )
        )
        return ready, payload

    @staticmethod
    def _probe_process_identity(
        evidence: dict[str, Any],
    ) -> tuple[tuple[Any, Any], ...]:
        service_identity = evidence.get("service_identity")
        if isinstance(service_identity, dict):
            probe_id = service_identity.get("probe_id")
            instance_id = service_identity.get("instance_id")
            if probe_id and instance_id:
                return ((probe_id, instance_id),)
        processes = evidence.get("processes")
        if not isinstance(processes, list):
            return ()
        return tuple(
            sorted(
                (
                    item.get("pid"),
                    item.get("start_ticks"),
                )
                for item in processes
                if isinstance(item, dict)
                and item.get("pid") is not None
                and item.get("start_ticks") is not None
            )
        )

    def _stable_existing_probe_service(
        self, endpoint: Endpoint
    ) -> tuple[bool, dict[str, Any]]:
        first_ready, first = self._existing_probe_service_ready(endpoint)
        time.sleep(1)
        second_ready, second = self._existing_probe_service_ready(endpoint)
        first_identity = self._probe_process_identity(first)
        second_identity = self._probe_process_identity(second)
        stable_identity = bool(first_identity) and first_identity == second_identity
        absence_proven = bool(
            not first_ready
            and not second_ready
            and first.get("inspection_complete") is True
            and second.get("inspection_complete") is True
            and not first_identity
            and not second_identity
        )
        return (
            first_ready and second_ready and stable_identity,
            {
                "first": first,
                "second": second,
                "process_identity": list(second_identity),
                "stable_identity": stable_identity,
                "absence_proven": absence_proven,
            },
        )

    def _adopt_probe_service(
        self, endpoint: Endpoint, evidence: dict[str, Any]
    ) -> None:
        endpoint.metadata.setdefault("probe_service", {}).update(
            {
                "mode": (
                    "foreground-ssh"
                    if self.probe_service.is_running(endpoint)
                    else "adopted-surviving-process"
                ),
                "ready": True,
                "tcp_port": self.config.tcp_port,
                "control_tcp_ports": dict(self.security_control_ports),
                "udp_port": self.config.udp_port,
                "reuse_evidence": evidence,
            }
        )
        self.logger.log(
            f"Reusing the surviving transient TCP/UDP probe process on {endpoint.label}"
        )

    def _start_probe_server(
        self, endpoint: Endpoint, *, reuse_existing: bool = False
    ) -> None:
        raise_if_cancelled()
        if reuse_existing:
            ready, evidence = self._stable_existing_probe_service(endpoint)
            if ready:
                self._adopt_probe_service(endpoint, evidence)
                return
            if not evidence.get("absence_proven"):
                raise ProbeServiceError(
                    f"Probe state on {endpoint.label} is not stable enough to "
                    "adopt or replace safely; no start command was submitted"
                )
            self.logger.log(
                f"Two stable checks proved no reusable probe service survived "
                f"on {endpoint.label}; starting one replacement",
                "WARNING",
            )
        self.logger.log(
            f"Starting SSH-held transient token-echo TCP/UDP process on {endpoint.label}"
        )
        try:
            self.probe_service.start(endpoint, self._launch_probe_process)
        except ProbeServiceError as exc:
            lowered = str(exc).lower()
            if "address already in use" not in lowered and "eaddrinuse" not in lowered:
                raise
            ready, evidence = self._stable_existing_probe_service(endpoint)
            if not ready:
                raise
            self._adopt_probe_service(endpoint, evidence)
            self.logger.log(
                f"Probe start on {endpoint.label} reported EADDRINUSE; "
                "stable token and process checks proved a surviving listener "
                "was safe to adopt",
                "WARNING",
            )
            return
        self.logger.log(
            f"Transient token-echo process ready on {endpoint.label}: "
            f"TCP/{self.config.tcp_port}, UDP/{self.config.udp_port}"
        )

    def _launch_probe_process(
        self, endpoint: Endpoint, command: str
    ) -> subprocess.Popen[str]:
        """Hold a foreground remote Python probe open over a dedicated SSH session."""
        args = [*self._ssh_base(endpoint.management_ip, proxy=True), command]
        try:
            return subprocess.Popen(
                args,
                text=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,
                start_new_session=True,
            )
        except OSError as exc:
            raise ProbeServiceError(
                f"Could not launch probe SSH session for {endpoint.label}: {exc}"
            ) from exc

    def stop_endpoint_probe(self, endpoint: Endpoint) -> None:
        """Stop only the retiring VM's listener; keep reused peers serving."""
        self.probe_service.stop(endpoint)

    def stop_group_probes(self, group_id: str) -> int:
        stopped = self.probe_service.stop_group(group_id)
        if stopped:
            self.logger.log(
                f"Stopped {stopped} transient probe process(es) for endpoint group {group_id}"
            )
        return stopped

    def stop_all_probes(self) -> int:
        stopped = self.probe_service.stop_all()
        if stopped:
            self.logger.log(f"Stopped {stopped} remaining transient probe process(es)")
        return stopped

    def group_failure_reason(self, group_id: str) -> str | None:
        return self.group_failures.get(group_id)

    def group_failure_type(self, group_id: str) -> str | None:
        return self.group_failure_types.get(group_id)

    def _run_ssh_command(
        self,
        address: str,
        command: str,
        *,
        proxy: bool,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        marker = f"NFLUX_SSH_{uuid.uuid4().hex}"
        wrapped_command = (
            f"printf '\\n{marker}:started\\n' >&2\n(\n{command}\n)\n"
            "neutron_flux_ssh_status=$?\n"
            f"printf '\\n{marker}:completed:%s\\n' \"$neutron_flux_ssh_status\" >&2\n"
            'exit "$neutron_flux_ssh_status"'
        )
        args = [*self._ssh_base(address, proxy=proxy), wrapped_command]
        command_timeout = timeout or min(
            self.config.resource_timeout,
            max(120, (self.config.ssh_timeout * 4) + 30),
        )
        try:
            raise_if_cancelled()
            result = run_cancellable(
                args,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=command_timeout,
                check=False,
            )
            result.stderr, _ = self._ssh_command_progress(result.stderr, marker)
            return result
        except subprocess.TimeoutExpired as exc:
            stderr, progress = self._ssh_command_progress(exc.stderr, marker)
            stdout = exc.stdout or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode(errors="replace")
            controller = getattr(self, "control_address", None) if proxy else None
            route = (
                f" via controller {controller or 'unavailable'}"
                if proxy
                else " directly"
            )
            raise SSHExecutionError(
                f"SSH command timed out after {command_timeout}s to endpoint {address}{route}",
                evidence={
                    "endpoint_address": address,
                    "controller_address": controller,
                    "command": command,
                    "timeout_seconds": command_timeout,
                    "returncode": None,
                    "stdout": stdout[-16000:],
                    "stderr": stderr[-16000:],
                    **progress,
                },
            ) from exc

    @staticmethod
    def _ssh_command_progress(
        stderr: str | bytes | None, marker: str
    ) -> tuple[str, dict[str, Any]]:
        text = stderr or ""
        if isinstance(text, bytes):
            text = text.decode(errors="replace")
        started = f"\n{marker}:started\n"
        completed = re.search(rf"\n{marker}:completed:(\d+)\n", text)
        progress = {
            "remote_command_started": started in text,
            "remote_command_completed": completed is not None,
            "remote_returncode": int(completed[1]) if completed else None,
            "last_observed_stage": (
                "remote-command-completed"
                if completed
                else "remote-command-started"
                if started in text
                else "ssh-command-launched"
            ),
        }
        text = text.replace(started, "")
        if completed:
            text = text.replace(completed[0], "")
        return text, progress

    def ssh_controller(
        self, command: str, *, timeout: int | None = None
    ) -> subprocess.CompletedProcess[str]:
        if not self.controller_command_address:
            raise SuiteError(
                "Controller SSH requested before its control path was selected"
            )
        return self._run_ssh_command(
            self.controller_command_address,
            command,
            proxy=self.controller_via_proxy,
            timeout=timeout,
        )

    def ssh_endpoint(
        self,
        endpoint: Endpoint,
        command: str,
        *,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        try:
            return self._run_ssh_command(
                endpoint.management_ip, command, proxy=True, timeout=timeout
            )
        except SSHExecutionError as exc:
            exc.evidence["endpoint"] = {
                "label": endpoint.label,
                "server_id": endpoint.server_id,
                "management_ip": endpoint.management_ip,
                "compute_host": endpoint.host,
                "availability_zone": endpoint.availability_zone,
            }
            raise

    def ensure_group_fips(
        self, runtime: RuntimeGroup, *, side: str = "A", allow_create: bool = True
    ) -> None:
        endpoint_side, fixed_subnet_id = validate_runtime_floating_ip_target(
            runtime, side
        )
        endpoint = runtime.endpoint(endpoint_side)
        if endpoint is None:
            raise SuiteError(
                f"Floating IPv4 setup requires endpoint {endpoint_side} for "
                f"{runtime.plan.label}"
            )
        original = endpoint.metadata.get("floating_ip_identity")
        current = {
            **runtime.fips.get(endpoint.label, {}),
            "allocation": dict(runtime.fips.get(endpoint.label, {})),
            "server_id": endpoint.server_id,
            "port_id": endpoint.test_port_id,
            "fixed_ip": endpoint.fixed_ips.get(fixed_subnet_id),
            "router_id": runtime.router_id,
        }
        if original is not None and current != original:
            raise SuiteError(
                f"Original floating-IP mapping changed for {endpoint.label}; "
                "refusing to replace or repair it during validation"
            )
        if endpoint.label in runtime.fips:
            endpoint.metadata.setdefault("floating_ip_identity", current)
            return
        if not allow_create:
            raise SuiteError(
                f"No existing floating-IP mapping is available for read-only validation of {endpoint.label}"
            )
        if runtime.plan.families != [4]:
            raise SuiteError(
                "Floating IPs are supported only for IPv4 project-network "
                f"groups, not {runtime.plan.label}"
            )
        if not runtime.router_id:
            raise SuiteError(
                f"Floating IPv4 setup requires a Neutron router for {runtime.plan.label}"
            )
        router_state = self.capture_router_state(runtime.router_id)
        gateway = router_state.get("external_gateway_info") or {}
        source_nat_enabled = bool(gateway.get("enable_snat", True))
        self.logger.log(
            f"Creating floating IPv4 for {runtime.plan.label} after fixed-IP tests; "
            "router source NAT is "
            f"{'enabled' if source_nat_enabled else 'disabled'} and does not gate "
            "floating-IP allocation"
        )
        if endpoint_side == "A":
            self._create_group_fips(runtime)
        else:
            self._create_group_fips(runtime, side=endpoint_side)
        if endpoint.label not in runtime.fips:
            raise SuiteError(
                f"OpenStack did not allocate a floating IPv4 for {endpoint.label}"
            )
        endpoint.metadata["floating_ip_identity"] = {
            **runtime.fips[endpoint.label],
            "allocation": dict(runtime.fips[endpoint.label]),
            "server_id": endpoint.server_id,
            "port_id": endpoint.test_port_id,
            "fixed_ip": endpoint.fixed_ips.get(fixed_subnet_id),
            "router_id": runtime.router_id,
        }

    def _create_group_fips(self, runtime: RuntimeGroup, *, side: str = "A") -> None:
        endpoint_side, subnet_id = validate_runtime_floating_ip_target(runtime, side)
        floating_subnet_id = runtime.plan.floating_subnet_id
        if not floating_subnet_id:
            raise SuiteError(
                f"No network:floatingip-eligible external subnet was planned for "
                f"{runtime.plan.label}"
            )
        endpoints = [
            item for item in runtime.endpoints if item.side.upper() == endpoint_side
        ]
        for endpoint in endpoints:
            fixed_ip = endpoint.fixed_ips.get(subnet_id)
            if not fixed_ip:
                continue
            pending_fips = runtime.metadata.setdefault("pending_floating_ips", {})
            pending = pending_fips.get(endpoint.label)
            if pending is None:
                inject_failure(self.config, "before-fip-association")
                fip = self.osc.json(
                    "floating",
                    "ip",
                    "create",
                    "--subnet",
                    str(floating_subnet_id),
                    "--port",
                    str(endpoint.test_port_id),
                    "--fixed-ip-address",
                    fixed_ip,
                    "--description",
                    f"neutron-flux-{getattr(getattr(self, 'reporter', None), 'run_id', None) or self.run_tag}",
                    "--tag",
                    self.run_tag,
                    str(runtime.plan.external_network_id),
                    check=False,
                )
                if not fip:
                    self.logger.log(
                        f"Floating IP allocation failed for {endpoint.label}; dependent tests will be skipped",
                        "WARNING",
                    )
                    continue
                fip_id = required_text(fip, "id", context="Floating IP create")
                address = str(fip.get("floating_ip_address") or "")
                # Journal immediately: address validation or association reads
                # can fail after Neutron has already allocated the resource.
                self.tracker.add(
                    "floating_ip",
                    fip_id,
                    address or fip_id,
                    parent_id=str(endpoint.test_port_id),
                    role="endpoint",
                    group_id=runtime.plan.id,
                    endpoint_side=endpoint.side.upper(),
                    floating_subnet_id=str(floating_subnet_id),
                    router_gateway_subnet_id=str(runtime.plan.external_subnet_id),
                )
                pending = {
                    "id": fip_id,
                    "address": address,
                    "fixed_ip": fixed_ip,
                    "port_id": str(endpoint.test_port_id),
                }
                pending_fips[endpoint.label] = pending
            fip_id = pending["id"]
            address = pending["address"]
            if (
                pending["port_id"] != str(endpoint.test_port_id)
                or pending["fixed_ip"] != fixed_ip
            ):
                raise SuiteError(
                    f"Pending floating IP {fip_id} belongs to a different endpoint; "
                    "cleanup is required before another allocation"
                )
            try:
                floating_subnet = self.discovery.subnet(str(floating_subnet_id))
            except (AttributeError, StopIteration):
                floating_subnet = None
            floating_cidr = (
                floating_subnet.cidr
                if floating_subnet is not None
                else str(runtime.plan.metadata.get("runtime_public_cidr") or "")
            )
            try:
                allocated_in_requested_subnet = ipaddress.ip_address(
                    address
                ) in ipaddress.ip_network(
                    floating_cidr,
                    strict=False,
                )
            except ValueError:
                allocated_in_requested_subnet = False
            if not allocated_in_requested_subnet:
                raise SuiteError(
                    f"OpenStack allocated floating address {address!r} outside "
                    f"the requested subnet "
                    f"{floating_subnet.name if floating_subnet else floating_subnet_id} "
                    f"({floating_cidr or 'CIDR unavailable'})"
                )
            association = self.wait_floating_ip_association(
                fip_id,
                expected_port_id=str(endpoint.test_port_id),
                expected_fixed_ip=fixed_ip,
            )
            if not association.get("matched"):
                raise SuiteError(
                    f"OpenStack did not confirm floating IP {address} associated with "
                    f"port {endpoint.test_port_id} and fixed IP {fixed_ip}: {association}"
                )
            runtime.fips[endpoint.label] = {
                "id": fip_id,
                "address": address,
                "fixed_ip": fixed_ip,
                "port_id": str(endpoint.test_port_id),
            }
            endpoint.metadata["floating_ip_association"] = dict(association)
            del pending_fips[endpoint.label]
