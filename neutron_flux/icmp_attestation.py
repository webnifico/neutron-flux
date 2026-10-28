"""Correlate NAT ICMP probes with requests seen on the destination data port.

The bounded, read-only observer is held over SSH. It installs no packages,
changes no networking, writes no guest files, and needs root or passwordless
sudo for an AF_PACKET capture socket. Missing capture evidence cannot PASS.
"""

from __future__ import annotations

import inspect
import ipaddress
import json
import queue
import secrets
import shlex
import socket
import subprocess
import threading
import time
from collections.abc import Callable
from typing import Any

from .cancellation import raise_if_cancelled, register_process, unregister_process
from .errors import SuiteError
from .models import Endpoint, ProbeResult


def parse_icmp_request(
    packet: bytes, token: bytes, destination: str
) -> dict[str, Any] | None:
    """AF_PACKET/SOCK_DGRAM delivers the IPv4 datagram without Ethernet headers."""
    if len(packet) < 28 or packet[0] >> 4 != 4:
        return None
    header = (packet[0] & 15) * 4
    length = int.from_bytes(packet[2:4], "big")
    if header < 20 or length < header + 8 or length > len(packet):
        return None
    if packet[9] != 1 or packet[header] != 8 or packet[header + 1] != 0:
        return None
    if int.from_bytes(packet[6:8], "big") & 0x3FFF:
        return None
    local = socket.inet_ntoa(packet[16:20])
    if local != destination or token not in packet[header + 8 : length]:
        return None
    return {
        "peer_ip": socket.inet_ntoa(packet[12:16]),
        "local_ip": local,
        "identifier": int.from_bytes(packet[header + 4 : header + 6], "big"),
        "sequence": int.from_bytes(packet[header + 6 : header + 8], "big"),
    }


def observer_code(endpoint: Endpoint, fixed_ip: str, token: str) -> str:
    if not endpoint.test_mac or ipaddress.ip_address(fixed_ip).version != 4:
        raise SuiteError(
            "ICMP NAT attestation requires the destination data MAC and IPv4 address"
        )
    parser = inspect.getsource(parse_icmp_request)
    return (
        "from __future__ import annotations\n"
        "import json, pathlib, socket, time\n"
        "from typing import Any\n"
        + parser
        + f"""
MAC={endpoint.test_mac.lower()!r}
FIXED={fixed_ip!r}
TOKEN={token!r}
PROBE_ID={endpoint.server_id!r}
interfaces=[path.parent.name for path in pathlib.Path('/sys/class/net').glob('*/address')
            if path.read_text().strip().lower()==MAC]
if len(interfaces)!=1:
    raise RuntimeError('Destination data MAC was not uniquely found')
device=interfaces[0]
records=[]
seen=set()
with socket.socket(socket.AF_PACKET,socket.SOCK_DGRAM,socket.htons(0x0800)) as sock:
    sock.bind((device,0x0800))
    sock.settimeout(0.25)
    print('NF_ICMP_READY '+json.dumps({{'device':device,'probe_id':PROBE_ID,'token':TOKEN}}),flush=True)
    deadline=time.monotonic()+15.0
    while time.monotonic()<deadline and len(records)<3:
        try: packet,address=sock.recvfrom(65535)
        except socket.timeout: continue
        if address[2]==socket.PACKET_OUTGOING: continue
        match=parse_icmp_request(packet,bytes.fromhex(TOKEN),FIXED)
        if match is None: continue
        key=(match['peer_ip'],match['identifier'],match['sequence'])
        if key in seen: continue
        seen.add(key)
        records.append(match)
print('NF_ICMP_RESULT '+json.dumps({{'complete':True,'device':device,'probe_id':PROBE_ID,
      'token':TOKEN,'requests':records}}),flush=True)
"""
    )


def attested_icmp(
    launcher: Callable[[Endpoint, str], subprocess.Popen[str]],
    destination: Endpoint,
    fixed_ip: str,
    probe: Callable[[str], ProbeResult],
) -> ProbeResult:
    """Start a ready observer, issue one tokenized ping check, collect evidence."""
    token = secrets.token_hex(16)
    code = observer_code(destination, fixed_ip, token)
    invocation = "python3 -u -c " + shlex.quote(code)
    command = (
        'if [ "$(id -u)" -eq 0 ]; then exec '
        + invocation
        + "; else exec sudo -n "
        + invocation
        + "; fi"
    )
    process = launcher(destination, command)
    register_process(process)
    events: queue.Queue[tuple[str, str | None]] = queue.Queue()
    errors: list[str] = []

    def read(stream: Any, name: str) -> None:
        try:
            for line in stream:
                events.put((name, line.rstrip()))
        finally:
            events.put((name, None))

    if process.stdout is None or process.stderr is None:
        process.terminate()
        unregister_process(process)
        raise SuiteError("ICMP observer did not provide stdout/stderr streams")
    readers = [
        threading.Thread(target=read, args=(process.stdout, "stdout"), daemon=True),
        threading.Thread(target=read, args=(process.stderr, "stderr"), daemon=True),
    ]
    for thread in readers:
        thread.start()

    def receive(prefix: str, timeout: float) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            raise_if_cancelled()
            try:
                stream, line = events.get(timeout=0.1)
            except queue.Empty:
                if process.poll() is not None:
                    break
                continue
            if stream == "stderr" and line:
                errors.append(line)
            if stream == "stdout" and line and line.startswith(prefix):
                payload = json.loads(line[len(prefix) :])
                if (
                    not isinstance(payload, dict)
                    or payload.get("token") != token
                    or payload.get("probe_id") != destination.server_id
                ):
                    raise SuiteError("ICMP observer returned mismatched identity/token")
                return payload
        raise SuiteError(
            "ICMP destination observation unavailable: "
            + ("; ".join(errors) or "deadline exceeded")
        )

    try:
        ready = receive("NF_ICMP_READY ", 10)
        result = probe(token)
        try:
            observation = receive("NF_ICMP_RESULT ", 18)
        except SuiteError as exc:
            result.diagnostics["icmp_destination_attestation"] = {
                "ready": ready,
                "error": str(exc),
                "command": command,
            }
            if result.success:
                result.outcome, result.success = "inconclusive", False
                result.stderr = str(exc)
            return result
        observation["command"] = command
        result.diagnostics["icmp_destination_attestation"] = observation
        requests = observation.get("requests") or []
        peers = {row.get("peer_ip") for row in requests if isinstance(row, dict)}
        result.diagnostics["observer_probe_id"] = observation.get("probe_id")
        result.diagnostics["observer_local_ip"] = fixed_ip if requests else None
        result.diagnostics["observed_peer_ip"] = (
            next(iter(peers)) if len(peers) == 1 else None
        )
        requests_valid = bool(requests) and all(
            isinstance(row, dict)
            and row.get("local_ip") == fixed_ip
            and row.get("identifier") is not None
            and row.get("sequence") is not None
            for row in requests
        )
        if result.success and (
            not requests_valid
            or len(peers) != 1
            or observation.get("complete") is not True
            or observation.get("device") != ready.get("device")
        ):
            result.outcome, result.success = "wrong-destination", False
            result.stderr = "Successful ping lacked matching requests on the intended destination data port"
        return result
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        unregister_process(process)
        for thread in readers:
            thread.join(timeout=1)
        for stream in (process.stdout, process.stderr):
            stream.close()
