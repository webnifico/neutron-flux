"""Production TCP and UDP measurement clients, shared with manual reproduction."""

from __future__ import annotations

import inspect

from .performance_metrics import udp_statistics_error


def tcp_client_code(
    source_ip: str,
    destination_ip: str,
    family: int,
    port: int,
    duration: int,
    streams: int,
) -> str:
    return f"""
import json
import math
import secrets
import socket
import struct
import threading
import time

SOURCE = {source_ip!r}
DESTINATION = {destination_ip!r}
FAMILY = socket.AF_INET6 if {family} == 6 else socket.AF_INET
PORT = {port}
DURATION = {duration}
STREAMS = {streams}
BLOCK = b'x' * 262144
results = []
errors = []
lock = threading.Lock()

def recv_line(sock):
    data = bytearray()
    deadline = time.monotonic() + DURATION + 20
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Performance response frame deadline exceeded')
        sock.settimeout(remaining)
        chunk = sock.recv(1)
        if not chunk or chunk == b'\\n':
            return bytes(data)
        data.extend(chunk)
        if len(data) > 65536:
            raise ValueError('Performance response frame exceeds size limit')

def total_retransmissions(sock):
    option = getattr(socket, 'TCP_INFO', None)
    if option is None:
        return None
    try:
        info = sock.getsockopt(socket.IPPROTO_TCP, option, 104)
    except OSError:
        return None
    if len(info) < 104:
        return None
    # Linux struct tcp_info: tcpi_total_retrans is the 24th u32 after
    # the initial eight bytes of u8 state fields.
    return struct.unpack_from('=I', info, 100)[0]

def worker():
    try:
        sock = socket.socket(FAMILY, socket.SOCK_STREAM)
        sock.settimeout(DURATION + 20)
        sock.bind((SOURCE, 0))
        sock.connect((DESTINATION, PORT))
        client_mss = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
        token = secrets.token_hex(16)
        request = json.dumps({{'mode': 'upload', 'duration': DURATION, 'token': token}}, separators=(',', ':')).encode()
        sock.sendall(b'NF-PERF ' + request + b'\\n')
        ready = recv_line(sock)
        if ready != b'READY':
            raise RuntimeError('performance server did not become ready: ' + ready.decode(errors='replace'))
        started = time.perf_counter()
        deadline = started + DURATION
        sent = 0
        while time.perf_counter() < deadline:
            sock.sendall(BLOCK)
            sent += len(BLOCK)
        sock.shutdown(socket.SHUT_WR)
        response = recv_line(sock)
        retransmissions = total_retransmissions(sock)
        sock.close()
        if not response.startswith(b'RESULT '):
            raise RuntimeError('invalid performance response: ' + response.decode(errors='replace'))
        server = json.loads(response[len(b'RESULT '):])
        if not isinstance(server, dict) or server.get('token') != token:
            raise ValueError('TCP performance response correlation token mismatch')
        if server.get('bytes') != sent or sent <= 0:
            raise ValueError('TCP performance receiver did not acknowledge complete delivery')
        if not math.isfinite(float(server.get('elapsed_s', 0))) or float(server.get('elapsed_s', 0)) <= 0:
            raise ValueError('TCP performance receiver returned an invalid duration')
        server['client_bytes'] = sent
        server['client_mss'] = client_mss
        server['retransmissions'] = retransmissions
        with lock:
            results.append(server)
    except BaseException as exc:
        with lock:
            errors.append(type(exc).__name__ + ': ' + str(exc))

threads = [threading.Thread(target=worker) for _ in range(STREAMS)]
started = time.perf_counter()
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
elapsed = max(time.perf_counter() - started, 1e-9)
if errors:
    raise RuntimeError(' | '.join(errors))
print(json.dumps({{
    'streams': STREAMS,
    'elapsed_s': elapsed,
    'bytes': sum(item['bytes'] for item in results),
    'mbps': sum(item['bytes'] for item in results) * 8.0 / elapsed / 1_000_000.0,
    'client_mss': min(item['client_mss'] for item in results),
    'server_mss': min(item['mss'] for item in results),
    'retransmissions': (
        sum(item['retransmissions'] for item in results if item.get('retransmissions') is not None)
        if any(item.get('retransmissions') is not None for item in results)
        else None
    ),
    'stream_retransmissions': [item.get('retransmissions') for item in results],
    'stream_mbps': [item['mbps'] for item in results],
    'intervals_mbps': [value for item in results for value in item.get('intervals_mbps', [])],
    'peer_ips': sorted({{str(item.get('peer_ip')) for item in results if item.get('peer_ip')}}),
    'peer_ip': (
        str(results[0].get('peer_ip'))
        if results and all(item.get('peer_ip') == results[0].get('peer_ip') for item in results)
        else None
    ),
}}, separators=(',', ':')))
"""


def udp_client_code(
    source_ip: str,
    destination_ip: str,
    family: int,
    port: int,
    duration: int,
    rate_mbps: int,
    packet_size: int,
) -> str:
    return f"""
from __future__ import annotations

import errno
import json
import secrets
import socket
import struct
import time
from typing import Any

{inspect.getsource(udp_statistics_error)}

SOURCE = {source_ip!r}
DESTINATION = {destination_ip!r}
FAMILY = socket.AF_INET6 if {family} == 6 else socket.AF_INET
PORT = {port}
DURATION = {duration}
RATE_MBPS = {rate_mbps}
PACKET_SIZE = {packet_size}
HEADER = struct.Struct('!4sQIQ')
END = struct.Struct('!4sQIQ')
SESSION = secrets.randbits(63)
PAYLOAD = b'u' * max(0, PACKET_SIZE - HEADER.size)
interval_ns = max(1, int(PACKET_SIZE * 8.0 / (RATE_MBPS * 1_000_000.0) * 1_000_000_000.0))
sock = socket.socket(FAMILY, socket.SOCK_DGRAM)
sock.settimeout(5)
sock.bind((SOURCE, 0))
sock.connect((DESTINATION, PORT))
started_ns = time.monotonic_ns()
deadline_ns = started_ns + int(DURATION * 1_000_000_000)
next_send_ns = started_ns
sequence = 0
size_error = None
kernel_path_mtu = None
while time.monotonic_ns() < deadline_ns:
    now_ns = time.monotonic_ns()
    if now_ns < next_send_ns:
        remaining = next_send_ns - now_ns
        if remaining > 200_000:
            time.sleep(remaining / 1_000_000_000.0)
        continue
    try:
        sock.send(HEADER.pack(b'NFP1', SESSION, sequence, now_ns) + PAYLOAD)
    except OSError as exc:
        if exc.errno != errno.EMSGSIZE:
            raise
        size_error = {{'errno': exc.errno, 'message': str(exc)}}
        # Linux exposes the connected socket's current route PMTU. This is a
        # local send constraint, not proof of delivery or a fresh path boundary.
        try:
            level = socket.IPPROTO_IPV6 if FAMILY == socket.AF_INET6 else socket.IPPROTO_IP
            option = getattr(socket, 'IPV6_MTU', 24) if FAMILY == socket.AF_INET6 else getattr(socket, 'IP_MTU', 14)
            value = int(sock.getsockopt(level, option))
            kernel_path_mtu = value if value > 0 else None
        except (OSError, ValueError):
            pass
        break
    sequence += 1
    next_send_ns += interval_ns
send_finished_ns = time.monotonic_ns()
sender_elapsed_ns = max(send_finished_ns - started_ns, 1)
end = END.pack(b'NFE1', SESSION, sequence, sender_elapsed_ns)
response = None
control_error = None
for _ in range(5):
    try:
        sock.send(end)
        data = sock.recv(65535)
    except socket.timeout:
        continue
    except OSError as exc:
        if size_error is None:
            raise
        control_error = str(exc)
        break
    if data.startswith(b'NFR1'):
        response = json.loads(data[4:])
        if not isinstance(response, dict) or response.get('session_id') != SESSION:
            raise ValueError('UDP performance response session mismatch')
        if response.get('sent') != sequence:
            raise ValueError('UDP performance response sender count mismatch')
        statistics_error = udp_statistics_error(response, require_complete=True)
        if statistics_error:
            raise ValueError(statistics_error)
        break
if response is None:
    if size_error is None:
        raise RuntimeError('UDP performance server did not return statistics')
    response = {{'sent': sequence, 'session_id': SESSION,
                'control_statistics_available': False,
                'control_statistics_error': control_error or 'UDP performance server did not return statistics'}}
else:
    response['control_statistics_available'] = True
elapsed = max((send_finished_ns - started_ns) / 1_000_000_000.0, 1e-9)
response['sender_elapsed_s'] = elapsed
response['sender_mbps'] = sequence * PACKET_SIZE * 8.0 / elapsed / 1_000_000.0
response['packet_size_supported'] = size_error is None
if size_error is not None:
    response.update(packet_size_status='local-pmtu-rejection',
                    packet_size_error=size_error, kernel_path_mtu=kernel_path_mtu,
                    packet_size_rejected=PACKET_SIZE)
sock.close()
print(json.dumps(response, separators=(',', ':')))
"""
