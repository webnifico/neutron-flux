from __future__ import annotations

import dataclasses
import errno
import ipaddress
import json
import re
import shlex
import socket
import subprocess
import time
import uuid
from collections.abc import Callable

from .models import Endpoint, ProbeResult
from .mtu_probes import boundary_probe_code, parse_boundary_result

RemoteExecutor = Callable[[Endpoint, str], object]
ControllerExecutor = Callable[[str], object]


def _completed_fields(result: object) -> tuple[int, str, str]:
    return (
        int(getattr(result, "returncode", 1)),
        str(getattr(result, "stdout", "") or ""),
        str(getattr(result, "stderr", "") or ""),
    )


_NETWORK_FAILURE_PATTERNS = (
    "timed out",
    "timeout",
    "connection refused",
    "no route to host",
    "network is unreachable",
    "host is unreachable",
    "destination host unreachable",
    "destination unreachable",
    "100% packet loss",
    "errno 101",
    "errno 110",
    "errno 111",
    "errno 113",
    "connectionreseterror",
    "message too long",
)
_EXECUTION_FAILURE_PATTERNS = (
    "command not found",
    "no such file or directory",
    "permission denied",
    "operation not permitted",
    "cannot assign requested address",
    "errno 13",
    "errno 99",
    "syntaxerror",
    "nameerror",
    "modulenotfounderror",
    "importerror",
    "stdio forwarding failed",
    "could not resolve hostname",
    "host key verification failed",
    "connection closed by remote host",
)


def classify_command_outcome(
    returncode: int,
    stdout: str,
    stderr: str,
    *,
    token_mismatch_code: int | None = None,
) -> str:
    """Classify a remote command as reachable, blocked, or execution error.

    A negative routing/security test must not pass merely because SSH, Python,
    ping, source binding, or the generated command itself was broken.
    """
    if returncode == 0:
        return "reachable"
    if token_mismatch_code is not None and returncode == token_mismatch_code:
        return "error"
    text = f"{stdout}\n{stderr}".lower()
    if any(pattern in text for pattern in _EXECUTION_FAILURE_PATTERNS):
        return "error"
    if returncode == 255 or text.lstrip().startswith("ssh:"):
        return "error"
    if any(pattern in text for pattern in _NETWORK_FAILURE_PATTERNS):
        return "blocked"
    # ping uses a conventional non-zero result for packet loss even when its
    # output does not contain the exact distro-specific wording above.
    if " packets transmitted" in text and " received" in text:
        return "blocked"
    # Python socket exceptions are printed as tracebacks.  Unknown exceptions
    # are execution errors; only known network exceptions become BLOCKED.
    if "traceback" in text or "error" in text or "exception" in text:
        return "error"
    return "error"


@dataclasses.dataclass
class ProbeContext:
    endpoint_executor: RemoteExecutor
    controller_executor: ControllerExecutor
    tcp_port: int
    udp_port: int
    timeout: int = 5


class ProbeAdapter:
    protocol = "unknown"

    def __init__(self, context: ProbeContext):
        self.context = context

    @staticmethod
    def _result(
        *,
        outcome: str,
        start: float,
        attempts: int,
        stdout: str,
        stderr: str,
        command: str,
        source_ip: str | None,
        destination_ip: str,
        protocol: str,
    ) -> ProbeResult:
        return ProbeResult(
            outcome=outcome,
            success=outcome == "reachable",
            elapsed_ms=int((time.monotonic() - start) * 1000),
            attempts=attempts,
            stdout=stdout,
            stderr=stderr,
            command=command,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
        )


class ICMPProbe(ProbeAdapter):
    protocol = "icmp"

    def endpoint(
        self,
        source: Endpoint,
        source_ip: str,
        destination_ip: str,
        family: int,
        *,
        payload_token: str | None = None,
    ) -> ProbeResult:
        flag = "-6" if family == 6 else "-4"
        pattern = f" -p {payload_token}" if payload_token else ""
        if payload_token and not re.fullmatch(r"[0-9a-f]{32}", payload_token):
            raise ValueError(
                "ICMP token must be exactly 16 random bytes in hexadecimal"
            )
        command = f"ping {flag} -n -c 3 -W 2{pattern} -I {shlex.quote(source_ip)} {shlex.quote(destination_ip)}"
        start = time.monotonic()
        result = self.context.endpoint_executor(source, command)
        code, stdout, stderr = _completed_fields(result)
        return self._result(
            outcome=classify_command_outcome(code, stdout, stderr),
            start=start,
            attempts=3,
            stdout=stdout,
            stderr=stderr,
            command=command,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=self.protocol,
        )

    def controller(
        self, source_ip: str, destination_ip: str, family: int
    ) -> ProbeResult:
        flag = "-6" if family == 6 else "-4"
        command = f"ping {flag} -n -c 3 -W 2 -I {shlex.quote(source_ip)} {shlex.quote(destination_ip)}"
        start = time.monotonic()
        result = self.context.controller_executor(command)
        code, stdout, stderr = _completed_fields(result)
        return self._result(
            outcome=classify_command_outcome(code, stdout, stderr),
            start=start,
            attempts=3,
            stdout=stdout,
            stderr=stderr,
            command=command,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=self.protocol,
        )


class TCPProbe(ProbeAdapter):
    protocol = "tcp"

    @staticmethod
    def _attempt_code(
        source_ip: str,
        destination_ip: str,
        family: int,
        port: int,
        token: str,
    ) -> str:
        return f"""
import json
import socket
import sys
import time

diag={{
    'connected': False,
    'token_sent': False,
    'echo_received': False,
    'echo_validated': False,
    'failure_phase': None,
    'error_type': None,
    'error': None,
    'local_address': None,
    'peer_address': None,
}}
phase='socket-create'
returncode=4
sock=None
try:
    family=socket.AF_INET6 if {family} == 6 else socket.AF_INET
    sock=socket.socket(family,socket.SOCK_STREAM)
    sock.settimeout(5)
    phase='source-bind'
    sock.bind(({source_ip!r},0))
    diag['local_address']=list(sock.getsockname()[:2])
    phase='connect'
    sock.connect(({destination_ip!r},{port}))
    diag['connected']=True
    diag['peer_address']=list(sock.getpeername()[:2])
    phase='send-token'
    sock.sendall({token!r}.encode()+b'\\n')
    diag['token_sent']=True
    phase='receive-echo'
    expected={token!r}.encode()+b'\\n'
    received=bytearray()
    deadline=time.monotonic()+5.0
    while not received.endswith(b'\\n'):
        remaining=deadline-time.monotonic()
        if remaining <= 0:
            raise TimeoutError('TCP echo frame deadline exceeded')
        sock.settimeout(remaining)
        chunk=sock.recv(min(4096, len(expected)+1-len(received)))
        if not chunk:
            break
        received.extend(chunk)
        if len(received) > len(expected):
            break
    diag['echo_received']=bool(received)
    diag['echo_bytes_received']=len(received)
    diag['echo_bytes_expected']=len(expected)
    phase='validate-echo'
    diag['echo_validated']=bytes(received)==expected
    returncode=0 if diag['echo_validated'] else 3
    if returncode != 0:
        diag['failure_phase']='validate-echo'
except BaseException as exc:
    diag['failure_phase']=phase
    diag['error_type']=type(exc).__name__
    diag['error']=str(exc)
finally:
    if sock is not None:
        try:
            sock.close()
        except BaseException:
            pass
    print('NFLUX_TCP '+json.dumps(diag,separators=(',',':')))
sys.exit(returncode)
"""

    @staticmethod
    def _attempt_diagnostics(stdout: str) -> dict[str, object]:
        for line in reversed(str(stdout or "").splitlines()):
            if not line.startswith("NFLUX_TCP "):
                continue
            try:
                value = json.loads(line[len("NFLUX_TCP ") :])
            except (TypeError, ValueError, json.JSONDecodeError):
                return {}
            return value if isinstance(value, dict) else {}
        return {}

    def _run_tcp_probe(
        self,
        executor: Callable[[str], object],
        *,
        source_ip: str,
        destination_ip: str,
        family: int,
        port: int,
    ) -> ProbeResult:
        started = time.monotonic()
        evidence: list[dict[str, object]] = []
        commands: list[str] = []
        outputs: list[str] = []
        errors: list[str] = []
        outcomes: list[str] = []
        maximum_attempts = 3
        stopped_after_first_pre_handshake_failure = False

        for attempt in range(1, maximum_attempts + 1):
            token = f"nflux-{uuid.uuid4().hex}"
            code = self._attempt_code(
                source_ip,
                destination_ip,
                family,
                port,
                token,
            )
            command = "python3 -c " + shlex.quote(code)
            commands.append(command)
            result = executor(command)
            return_code, stdout, stderr = _completed_fields(result)
            diagnostics = self._attempt_diagnostics(stdout)
            outcome = classify_command_outcome(
                return_code,
                stdout,
                stderr,
                token_mismatch_code=3,
            )
            evidence.append(
                {
                    "attempt": attempt,
                    "outcome": outcome,
                    "returncode": return_code,
                    "diagnostics": diagnostics,
                }
            )
            outputs.append(stdout)
            errors.append(stderr)
            outcomes.append(outcome)
            connected = bool(diagnostics.get("connected"))
            if attempt == 1:
                if outcome == "reachable":
                    break
                failure_phase = str(diagnostics.get("failure_phase") or "")
                if not connected and failure_phase in {
                    "socket-create",
                    "source-bind",
                    "connect",
                }:
                    # A failed TCP handshake is already a complete dataplane
                    # observation. Do not create two more fresh flows against a
                    # path that may be unhealthy.
                    stopped_after_first_pre_handshake_failure = True
                    break
                # Unknown execution failures are not network observations and
                # are not retried. Network failures and failures after a
                # completed TCP handshake receive two controlled fresh-flow
                # confirmations. Once confirmation begins, both fresh flows
                # are collected even if the first confirmation succeeds.
                if outcome == "error" and not connected:
                    break

        final_outcome = outcomes[-1] if outcomes else "error"
        if len(outcomes) > 1:
            if "reachable" in outcomes and any(
                item != "reachable" for item in outcomes
            ):
                final_outcome = "inconclusive"
            elif len(set(outcomes)) > 1:
                final_outcome = "inconclusive"
            else:
                phases = {
                    str((item.get("diagnostics") or {}).get("failure_phase") or "")
                    for item in evidence
                }
                if len(phases) > 1:
                    final_outcome = "inconclusive"
        probe = self._result(
            outcome=final_outcome,
            start=started,
            attempts=len(outcomes),
            stdout="\n".join(item for item in outputs if item),
            stderr="\n".join(item for item in errors if item),
            command=commands[0] if commands else "",
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=self.protocol,
        )
        probe.diagnostics.update(
            {
                "destination_port": port,
                "attempt_evidence": evidence,
                "confirmation_attempts": max(0, len(outcomes) - 1),
                "fresh_flow_confirmation": len(outcomes) > 1,
                "transient_first_attempt_failure": bool(
                    len(outcomes) > 1
                    and outcomes[0] != "reachable"
                    and "reachable" in outcomes[1:]
                ),
                "stopped_after_first_pre_handshake_failure": (
                    stopped_after_first_pre_handshake_failure
                ),
            }
        )
        if evidence:
            probe.diagnostics.update(
                {
                    key: value
                    for key, value in (evidence[-1].get("diagnostics") or {}).items()
                    if key not in probe.diagnostics
                }
            )
        return probe

    def endpoint(
        self, source: Endpoint, source_ip: str, destination_ip: str, family: int
    ) -> ProbeResult:
        return self.endpoint_port(
            source, source_ip, destination_ip, family, self.context.tcp_port
        )

    def endpoint_port(
        self,
        source: Endpoint,
        source_ip: str,
        destination_ip: str,
        family: int,
        port: int,
    ) -> ProbeResult:
        return self._run_tcp_probe(
            lambda command: self.context.endpoint_executor(source, command),
            source_ip=source_ip,
            destination_ip=destination_ip,
            family=family,
            port=port,
        )

    @staticmethod
    def _peer_identity_attempt_code(
        source_ip: str,
        destination_ip: str,
        family: int,
        port: int,
        token: str,
        *,
        datagram: bool = False,
    ) -> str:
        return f"""
import json
import socket
import sys
import time

diag={{
    'connected': False,
    'request_sent': False,
    'response_received': False,
    'response_validated': False,
    'failure_phase': None,
    'error_type': None,
    'error': None,
    'local_address': None,
    'peer_address': None,
    'observed_peer_ip': None,
    'observer_probe_id': None,
    'observer_instance_id': None,
    'observer_local_ip': None,
}}
phase='socket-create'
returncode=4
sock=None
try:
    family=socket.AF_INET6 if {family} == 6 else socket.AF_INET
    sock=socket.socket(family,socket.{"SOCK_DGRAM" if datagram else "SOCK_STREAM"})
    sock.settimeout(5)
    phase='source-bind'
    sock.bind(({source_ip!r},0))
    diag['local_address']=list(sock.getsockname()[:2])
    phase='connect'
    sock.connect(({destination_ip!r},{port}))
    diag['connected']=True
    diag['peer_address']=list(sock.getpeername()[:2])
    phase='send-peer-request'
    sock.sendall(('NF-PEER '+{token!r}+'\\n').encode())
    diag['request_sent']=True
    phase='receive-peer-response'
    data=b''
    response_deadline=time.monotonic()+5.0
    while len(data) < 65536 and not data.endswith(b'\\n'):
        remaining=response_deadline-time.monotonic()
        if remaining<=0:
            raise TimeoutError('Peer response deadline exceeded')
        sock.settimeout(remaining)
        chunk=sock.recv(min(4096,65536-len(data)))
        if not chunk:
            break
        data+=chunk
        if {datagram!r}:
            break
    diag['response_received']=bool(data)
    phase='validate-peer-response'
    prefix=b'NF-PEER-OK '
    if not data.startswith(prefix):
        raise ValueError('observer returned an unexpected response')
    payload=json.loads(data[len(prefix):].decode(errors='replace'))
    if payload.get('token') != {token!r}:
        raise ValueError('observer returned a mismatched token')
    diag['observed_peer_ip']=payload.get('peer_ip')
    diag['observer_probe_id']=payload.get('probe_id')
    diag['observer_instance_id']=payload.get('instance_id')
    diag['observer_local_ip']=payload.get('local_ip')
    diag['response_validated']=bool(diag['observed_peer_ip'])
    returncode=0 if diag['response_validated'] else 3
    if returncode != 0:
        diag['failure_phase']='validate-peer-response'
except BaseException as exc:
    diag['failure_phase']=phase
    diag['error_type']=type(exc).__name__
    diag['error']=str(exc)
finally:
    if sock is not None:
        try:
            sock.close()
        except BaseException:
            pass
    print('NFLUX_{"UDP" if datagram else "TCP"}_PEER '+json.dumps(diag,separators=(',',':')))
sys.exit(returncode)
"""

    @staticmethod
    def _peer_identity_diagnostics(
        stdout: str, *, datagram: bool = False
    ) -> dict[str, object]:
        prefix = "NFLUX_UDP_PEER " if datagram else "NFLUX_TCP_PEER "
        for line in reversed(str(stdout or "").splitlines()):
            if not line.startswith(prefix):
                continue
            try:
                value = json.loads(line[len(prefix) :])
            except (TypeError, ValueError, json.JSONDecodeError):
                return {}
            return value if isinstance(value, dict) else {}
        return {}

    def endpoint_peer_identity(
        self,
        source: Endpoint,
        source_ip: str,
        destination_ip: str,
        family: int,
        *,
        port: int | None = None,
    ) -> ProbeResult:
        """Reach an endpoint probe and return the source address it observed.

        The standard transient probe service answers ``NF-PEER`` requests on the
        normal TCP data-plane port. This avoids opening an unrelated listener on
        the Flux runner and lets translated egress be observed from a provider
        VM that is already part of the approved test topology.
        """

        selected_port = int(port or self.context.tcp_port)
        started = time.monotonic()
        evidence: list[dict[str, object]] = []
        commands: list[str] = []
        outputs: list[str] = []
        errors: list[str] = []
        outcomes: list[str] = []
        stopped_after_first_pre_handshake_failure = False

        for attempt in range(1, 4):
            token = f"nflux-peer-{uuid.uuid4().hex}"
            code = self._peer_identity_attempt_code(
                source_ip,
                destination_ip,
                family,
                selected_port,
                token,
            )
            command = "python3 -c " + shlex.quote(code)
            commands.append(command)
            result = self.context.endpoint_executor(source, command)
            return_code, stdout, stderr = _completed_fields(result)
            diagnostics = self._peer_identity_diagnostics(stdout)
            outcome = classify_command_outcome(
                return_code,
                stdout,
                stderr,
                token_mismatch_code=3,
            )
            evidence.append(
                {
                    "attempt": attempt,
                    "outcome": outcome,
                    "returncode": return_code,
                    "diagnostics": diagnostics,
                }
            )
            outputs.append(stdout)
            errors.append(stderr)
            outcomes.append(outcome)
            connected = bool(diagnostics.get("connected"))
            if attempt == 1:
                if outcome == "reachable":
                    break
                failure_phase = str(diagnostics.get("failure_phase") or "")
                if not connected and failure_phase in {
                    "socket-create",
                    "source-bind",
                    "connect",
                }:
                    stopped_after_first_pre_handshake_failure = True
                    break
                if outcome == "error" and not connected:
                    break

        final_outcome = outcomes[-1] if outcomes else "error"
        if len(outcomes) > 1:
            if "reachable" in outcomes and any(
                item != "reachable" for item in outcomes
            ):
                final_outcome = "inconclusive"
            elif len(set(outcomes)) > 1:
                final_outcome = "inconclusive"
            else:
                phases = {
                    str((item.get("diagnostics") or {}).get("failure_phase") or "")
                    for item in evidence
                }
                if len(phases) > 1:
                    final_outcome = "inconclusive"

        probe = self._result(
            outcome=final_outcome,
            start=started,
            attempts=len(outcomes),
            stdout="\n".join(item for item in outputs if item),
            stderr="\n".join(item for item in errors if item),
            command=commands[0] if commands else "",
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=self.protocol,
        )
        probe.diagnostics.update(
            {
                "destination_port": selected_port,
                "attempt_evidence": evidence,
                "confirmation_attempts": max(0, len(outcomes) - 1),
                "fresh_flow_confirmation": len(outcomes) > 1,
                "observer_mode": "provider-endpoint-probe-service",
                "stopped_after_first_pre_handshake_failure": (
                    stopped_after_first_pre_handshake_failure
                ),
            }
        )
        if evidence:
            probe.diagnostics.update(
                {
                    key: value
                    for key, value in (evidence[-1].get("diagnostics") or {}).items()
                    if key not in probe.diagnostics
                }
            )
        return probe

    def controller(
        self, source_ip: str, destination_ip: str, family: int
    ) -> ProbeResult:
        return self._run_tcp_probe(
            self.context.controller_executor,
            source_ip=source_ip,
            destination_ip=destination_ip,
            family=family,
            port=self.context.tcp_port,
        )


class UDPProbe(ProbeAdapter):
    protocol = "udp"

    def endpoint(
        self, source: Endpoint, source_ip: str, destination_ip: str, family: int
    ) -> ProbeResult:
        return self.endpoint_peer_identity(source, source_ip, destination_ip, family)

    def endpoint_peer_identity(
        self, source: Endpoint, source_ip: str, destination_ip: str, family: int
    ) -> ProbeResult:
        code = TCPProbe._peer_identity_attempt_code(
            source_ip,
            destination_ip,
            family,
            self.context.udp_port,
            f"nflux-peer-{uuid.uuid4().hex}",
            datagram=True,
        )
        command = "python3 -c " + shlex.quote(code)
        start = time.monotonic()
        result = self.context.endpoint_executor(source, command)
        return_code, stdout, stderr = _completed_fields(result)
        probe = self._result(
            outcome=classify_command_outcome(
                return_code, stdout, stderr, token_mismatch_code=3
            ),
            start=start,
            attempts=1,
            stdout=stdout,
            stderr=stderr,
            command=command,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=self.protocol,
        )
        probe.diagnostics.update(
            TCPProbe._peer_identity_diagnostics(stdout, datagram=True)
        )
        probe.diagnostics["destination_port"] = self.context.udp_port
        if (
            not probe.success
            and not probe.stderr
            and probe.diagnostics.get("error_type")
        ):
            probe.stderr = f"{probe.diagnostics['error_type']}: {probe.diagnostics.get('error') or probe.diagnostics.get('failure_phase')}"
        return probe


class MTUProbe(ProbeAdapter):
    protocol = "mtu"

    def endpoint(
        self,
        source: Endpoint,
        source_ip: str,
        destination_ip: str,
        family: int,
        network_mtu: int,
        *,
        oversized: bool = False,
    ) -> ProbeResult:
        header = 48 if family == 6 else 28
        payload = max(0, network_mtu - header + (1 if oversized else 0))
        code = boundary_probe_code(source_ip, destination_ip, family, payload)
        command = "python3 -c " + shlex.quote(code)
        start = time.monotonic()
        result = self.context.endpoint_executor(source, command)
        return_code, raw_stdout, raw_stderr = _completed_fields(result)
        parsed = parse_boundary_result(raw_stdout)
        if return_code == 0 and parsed is not None:
            ping = parsed.get("ping") if isinstance(parsed.get("ping"), dict) else {}
            stdout = str(ping.get("stdout") or "")
            stderr = str(ping.get("stderr") or "")
            classification = str(parsed.get("classification") or "error")
            outcome = (
                "reachable"
                if classification == "success"
                else "local-mtu-rejected"
                if classification == "local-mtu-rejected"
                else "packet-too-big"
                if classification == "packet-too-big"
                else "inconclusive"
                if classification == "mixed"
                else classify_command_outcome(
                    int(ping.get("returncode") or 1), stdout, stderr
                )
            )
        else:
            stdout = raw_stdout
            stderr = raw_stderr
            parsed = None
            # The wrapper itself exits zero after recording either successful
            # or failed ping evidence. Its process status cannot substitute for
            # the structured packet result if that result is absent/corrupt.
            outcome = "error"
            stderr = (
                stderr + "\nMTU probe returned no valid structured packet evidence"
            ).strip()
        probe = self._result(
            outcome=outcome,
            start=start,
            attempts=2,
            stdout=stdout,
            stderr=stderr,
            command=command,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol="mtu+1" if oversized else self.protocol,
        )
        packet_size = payload + header
        probe.diagnostics.update(
            {
                "network_mtu": network_mtu,
                "header_bytes": header,
                "payload": payload,
                "packet_size": packet_size,
                "oversized": oversized,
                "packet_transmitted": (
                    parsed.get("packet_transmitted") if parsed is not None else None
                ),
                "local_mtu_evidence": (
                    parsed.get("local_mtu_evidence") if parsed is not None else None
                ),
                "packet_too_big_feedback": (
                    parsed.get("packet_too_big_feedback", [])
                    if parsed is not None
                    else []
                ),
                "interpretation": (
                    "local oversized-packet rejection"
                    if oversized
                    else "valid end-to-end MTU boundary"
                ),
            }
        )
        return probe


class RunnerFIPProbe(ProbeAdapter):
    """Probe a floating IPv4 address from the Neutron Flux runner.

    The result is authoritative only when Linux selects a source outside the
    floating-IP subnet and the route explicitly uses a gateway.  This avoids
    mistaking same-link ARP behavior for routed floating-IP ingress.
    """

    protocol = "fip"

    def run(
        self,
        destination_ip: str,
        target_cidr: str | None = None,
        *,
        protocol: str = "tcp",
    ) -> tuple[ProbeResult, bool]:
        route_command = ["ip", "-4", "route", "get", destination_ip]
        try:
            route = subprocess.run(
                route_command,
                text=True,
                capture_output=True,
                timeout=max(5, self.context.timeout),
                check=False,
            )
        except FileNotFoundError:
            probe = ProbeResult(
                outcome="error",
                success=False,
                elapsed_ms=0,
                attempts=0,
                stderr="runner route inspection requires the ip command",
                command=shlex.join(route_command),
                destination_ip=destination_ip,
                protocol=protocol,
                diagnostics={"target_cidr": target_cidr, "authoritative_route": False},
            )
            return probe, False
        except subprocess.TimeoutExpired:
            probe = ProbeResult(
                outcome="error",
                success=False,
                elapsed_ms=max(5, self.context.timeout) * 1000,
                attempts=1,
                stderr="runner route inspection timed out",
                command=shlex.join(route_command),
                destination_ip=destination_ip,
                protocol=protocol,
                diagnostics={"target_cidr": target_cidr, "authoritative_route": False},
            )
            return probe, False

        route_text = (route.stdout or "").strip()
        source_match = re.search(r"(?:^|\s)src\s+(\S+)", route_text)
        source_ip = source_match.group(1) if source_match else None
        outside_target_subnet = False
        if source_ip and target_cidr:
            try:
                outside_target_subnet = ipaddress.ip_address(
                    source_ip
                ) not in ipaddress.ip_network(target_cidr, strict=False)
            except ValueError:
                outside_target_subnet = False
        routed_via_gateway = bool(re.search(r"(?:^|\s)via\s+\S+", route_text))
        authoritative = (
            route.returncode == 0 and outside_target_subnet and routed_via_gateway
        )

        start = time.monotonic()
        stdout = ""
        stderr = ""
        outcome = "error"
        command_description = ""
        if route.returncode != 0:
            stderr = (
                route.stderr or route.stdout or "runner has no route to floating IP"
            ).strip()
            outcome = classify_command_outcome(
                route.returncode, route.stdout or "", route.stderr or ""
            )
        elif protocol == "icmp":
            command = [
                "ping",
                "-4",
                "-n",
                "-c",
                "3",
                "-W",
                "2",
                *(["-I", source_ip] if source_ip else []),
                destination_ip,
            ]
            command_description = shlex.join(command)
            try:
                result = subprocess.run(
                    command,
                    text=True,
                    capture_output=True,
                    timeout=max(10, self.context.timeout * 3),
                    check=False,
                )
                stdout, stderr = result.stdout or "", result.stderr or ""
                outcome = classify_command_outcome(result.returncode, stdout, stderr)
            except FileNotFoundError:
                stderr = "runner ICMP probe requires the ping command"
                outcome = "error"
            except subprocess.TimeoutExpired:
                stderr = "runner ICMP probe timed out"
                outcome = "blocked"
        elif protocol in {"tcp", "udp"}:
            if protocol == "tcp":

                def local_executor(command: str) -> object:
                    try:
                        return subprocess.run(
                            shlex.split(command),
                            text=True,
                            capture_output=True,
                            timeout=max(10, self.context.timeout * 2),
                            check=False,
                        )
                    except subprocess.TimeoutExpired as exc:
                        return subprocess.CompletedProcess(
                            args=command,
                            returncode=124,
                            stdout=str(exc.stdout or ""),
                            stderr="runner TCP probe command timed out",
                        )

                probe = TCPProbe(self.context)._run_tcp_probe(
                    local_executor,
                    # Probe source selector, not a listening socket bind.
                    source_ip=str(source_ip or "0.0.0.0"),  # nosec B104
                    destination_ip=destination_ip,
                    family=4,
                    port=self.context.tcp_port,
                )
                probe.command = shlex.join(route_command) + "; " + probe.command
                probe.diagnostics.update(
                    {
                        "runner_route": route_text,
                        "runner_route_returncode": route.returncode,
                        "target_cidr": target_cidr,
                        "outside_target_subnet": outside_target_subnet,
                        "routed_via_gateway": routed_via_gateway,
                        "authoritative_route": authoritative,
                        "observer_mode": "runner",
                    }
                )
                return probe, authoritative

            token = f"nflux-{uuid.uuid4().hex}"
            sock: socket.socket | None = None
            try:
                socket_type = socket.SOCK_DGRAM
                port = self.context.udp_port
                sock = socket.socket(socket.AF_INET, socket_type)
                sock.settimeout(self.context.timeout)
                if source_ip:
                    sock.bind((source_ip, 0))
                sock.sendto(token.encode(), (destination_ip, port))
                data, _ = sock.recvfrom(4096)
                stdout = data.decode(errors="replace").strip()
                outcome = "reachable" if stdout == token else "error"
                if outcome == "error":
                    stderr = "floating-IP probe returned an unexpected token"
                command_description = (
                    f"{protocol.upper()} token probe to {destination_ip}:{port}"
                )
            except OSError as exc:
                stderr = str(exc)
                outcome = (
                    "blocked"
                    if getattr(exc, "errno", None)
                    in {
                        errno.ECONNREFUSED,
                        errno.ENETUNREACH,
                        errno.EHOSTUNREACH,
                        errno.ETIMEDOUT,
                        errno.ECONNRESET,
                    }
                    or isinstance(exc, TimeoutError)
                    else "error"
                )
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
        else:
            stderr = f"unsupported runner floating-IP protocol: {protocol}"
            outcome = "error"

        probe = self._result(
            outcome=outcome,
            start=start,
            attempts=3 if protocol == "icmp" else 1,
            stdout=stdout,
            stderr=stderr,
            command=shlex.join(route_command) + "; " + command_description,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
        )
        probe.diagnostics.update(
            {
                "runner_route": route_text,
                "runner_route_returncode": route.returncode,
                "target_cidr": target_cidr,
                "outside_target_subnet": outside_target_subnet,
                "routed_via_gateway": routed_via_gateway,
                "authoritative_route": authoritative,
            }
        )
        return probe, authoritative


class ProbeRegistry:
    def __init__(self, context: ProbeContext):
        self.icmp = ICMPProbe(context)
        self.tcp = TCPProbe(context)
        self.udp = UDPProbe(context)
        self.mtu = MTUProbe(context)
        self.runner_fip = RunnerFIPProbe(context)

    def endpoint(
        self,
        protocol: str,
        source: Endpoint,
        source_ip: str,
        destination_ip: str,
        family: int,
        *,
        network_mtu: int | None = None,
    ) -> ProbeResult:
        if protocol == "icmp":
            return self.icmp.endpoint(source, source_ip, destination_ip, family)
        if protocol == "tcp":
            return self.tcp.endpoint(source, source_ip, destination_ip, family)
        if protocol == "udp":
            return self.udp.endpoint(source, source_ip, destination_ip, family)
        if protocol == "mtu":
            return self.mtu.endpoint(
                source, source_ip, destination_ip, family, network_mtu or 1500
            )
        if protocol == "mtu+1":
            return self.mtu.endpoint(
                source,
                source_ip,
                destination_ip,
                family,
                network_mtu or 1500,
                oversized=True,
            )
        raise ValueError(f"Unknown probe protocol: {protocol}")

    def controller(
        self, protocol: str, source_ip: str, destination_ip: str, family: int
    ) -> ProbeResult:
        if protocol == "icmp":
            return self.icmp.controller(source_ip, destination_ip, family)
        if protocol == "tcp":
            return self.tcp.controller(source_ip, destination_ip, family)
        raise ValueError(f"Controller does not support protocol {protocol}")
