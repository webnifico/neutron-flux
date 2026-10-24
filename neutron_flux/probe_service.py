from __future__ import annotations

import dataclasses
import ipaddress
import json
import queue
import shlex
import subprocess
import textwrap
import threading
import time
from collections.abc import Callable
from typing import TextIO

from .cancellation import register_process, unregister_process
from .errors import ProbeServiceError
from .models import Endpoint


@dataclasses.dataclass
class _ProbeProcess:
    endpoint: Endpoint
    process: subprocess.Popen[str]
    stdout: list[str] = dataclasses.field(default_factory=list)
    stderr: list[str] = dataclasses.field(default_factory=list)


class ProbeServiceManager:
    """Manage foreground SSH sessions that host transient token-echo probes.

    The remote Python process stays in the foreground of a dedicated SSH
    channel.  Neutron Flux holds that SSH process open for as long as the VM is
    being tested and closes it when the endpoint group is released.

    Nothing is installed or persisted in the guest: no files, systemd units,
    user data, config drive, route changes, address changes, or boot settings.
    """

    READY_PREFIX = "NEUTRON_FLUX_READY "
    ERROR_PREFIX = "NEUTRON_FLUX_ERROR "

    def __init__(
        self,
        tcp_port: int,
        udp_port: int,
        *,
        startup_timeout: int = 20,
        stop_timeout: int = 5,
    ):
        self.tcp_port = tcp_port
        self.control_tcp_ports: dict[int, int] = {4: tcp_port + 2, 6: tcp_port + 2}
        self.udp_port = udp_port
        self.startup_timeout = startup_timeout
        self.stop_timeout = stop_timeout
        self._processes: dict[str, _ProbeProcess] = {}

    def set_control_ports(self, ports: dict[int, int]) -> None:
        normalized = {
            int(family): int(port)
            for family, port in ports.items()
            if int(family) in {4, 6}
        }
        if not normalized:
            raise ValueError("At least one IPv4 or IPv6 control TCP port is required")
        self.control_tcp_ports.update(normalized)

    @staticmethod
    def _families(endpoint: Endpoint) -> tuple[bool, bool]:
        addresses = [endpoint.management_ip, *endpoint.fixed_ips.values()]
        has_ipv4 = any(address and _ip_version(address) == 4 for address in addresses)
        has_ipv6 = any(address and _ip_version(address) == 6 for address in addresses)
        return has_ipv4 or not has_ipv6, has_ipv6

    def _server_code(self, endpoint: Endpoint) -> str:
        has_ipv4, has_ipv6 = self._families(endpoint)
        families: list[str] = []
        if has_ipv4:
            families.append("socket.AF_INET")
        if has_ipv6:
            families.append("socket.AF_INET6")
        family_literal = "[" + ",".join(families) + "]"
        control_ports_literal = (
            "{socket.AF_INET: "
            + str(int(self.control_tcp_ports[4]))
            + ", socket.AF_INET6: "
            + str(int(self.control_tcp_ports[6]))
            + "}"
        )
        probe_id_literal = json.dumps(str(endpoint.server_id))
        template = r"""\
import json
import secrets
import signal
import socket
import struct
import threading
import time
import zlib

TCP_PORT = __TCP_PORT__
CONTROL_TCP_PORTS = __CONTROL_PORTS__
UDP_PORT = __UDP_PORT__
FAMILIES = __FAMILIES__
UDP_DATA = struct.Struct('!4sQIQ')
UDP_END = struct.Struct('!4sQIQ')
UDP_FINALIZE_GRACE_NS = 500_000_000
UDP_SOCKET_TICK_S = 0.05
# Track packet sequences in sparse 8 KiB chunks. A corrupted or hostile
# uint32 sequence must never trigger a single allocation proportional to its
# absolute value. Each chunk covers 65,536 packet numbers.
UDP_SEQUENCE_CHUNK_BITS = 16
UDP_SEQUENCE_CHUNK_SIZE = 1 << UDP_SEQUENCE_CHUNK_BITS
UDP_SEQUENCE_CHUNK_BYTES = UDP_SEQUENCE_CHUNK_SIZE >> 3
SO_RXQ_OVFL = getattr(socket, 'SO_RXQ_OVFL', 40)
PROBE_ID = __PROBE_ID__
INSTANCE_ID = secrets.token_hex(16)
HEALTH_REQUEST = ('NF-HEALTH ' + PROBE_ID + '\n').encode('utf-8')
HEALTH_UDP_REQUEST = HEALTH_REQUEST.rstrip(b'\n')
PEER_REQUEST_PREFIX = b'NF-PEER '


def health_response():
    payload = json.dumps(
        {'probe_id': PROBE_ID, 'instance_id': INSTANCE_ID},
        separators=(',', ':'),
    ).encode('utf-8')
    return b'NF-HEALTH-OK ' + payload + b'\n'


def bind_address(family):
    return '::' if family == socket.AF_INET6 else '0.0.0.0'


def prepare_socket(family, socket_type, port):
    sock = socket.socket(family, socket_type)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((bind_address(family), port))
    if socket_type == socket.SOCK_STREAM:
        sock.listen(64)
    else:
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
        else:
            sock.setsockopt(socket.IPPROTO_IP, getattr(socket, 'IP_PKTINFO', 8), 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, SO_RXQ_OVFL, 1)
        except OSError:
            pass
    return sock


def udp_kernel_counters(family):
    try:
        if family == socket.AF_INET6:
            values = {}
            with open('/proc/net/snmp6', 'r', encoding='utf-8') as handle:
                for line in handle:
                    parts = line.split()
                    if len(parts) == 2:
                        values[parts[0]] = parts[1]
            return {
                'InErrors': int(values['Udp6InErrors']),
                'RcvbufErrors': int(values['Udp6RcvbufErrors']),
            }
        with open('/proc/net/snmp', 'r', encoding='utf-8') as handle:
            lines = [line.strip().split() for line in handle if line.startswith('Udp:')]
        if len(lines) < 2:
            return {}
        values = dict(zip(lines[-2][1:], lines[-1][1:]))
        return {
            'InErrors': int(values['InErrors']),
            'RcvbufErrors': int(values['RcvbufErrors']),
        }
    except (KeyError, OSError, ValueError):
        return {}


def recv_line(conn, limit=65536):
    data = bytearray()
    while len(data) < limit:
        chunk = conn.recv(1)
        if not chunk:
            break
        data.extend(chunk)
        if chunk == b'\n':
            break
    return bytes(data)


def handle_tcp(conn):
    try:
        peer_ip = str(conn.getpeername()[0])
        conn.settimeout(30)
        first = recv_line(conn)
        if first == HEALTH_REQUEST:
            conn.sendall(health_response())
            return
        if first.startswith(PEER_REQUEST_PREFIX):
            token = first[len(PEER_REQUEST_PREFIX):].decode(
                'utf-8', errors='replace'
            ).strip()
            payload = json.dumps(
                {
                    'probe_id': PROBE_ID,
                    'instance_id': INSTANCE_ID,
                    'peer_ip': peer_ip,
                    'local_ip': str(conn.getsockname()[0]),
                    'token': token,
                },
                separators=(',', ':'),
            ).encode('utf-8')
            conn.sendall(b'NF-PEER-OK ' + payload + b'\n')
            return
        if not first.startswith(b'NF-PERF '):
            conn.sendall(first)
            return
        request = json.loads(first[len(b'NF-PERF '):].decode('utf-8'))
        continuity = request.get('continuity') is True
        token = request.get('token')
        if continuity and (not isinstance(token, str) or len(token) != 32
                           or any(ch not in '0123456789abcdef' for ch in token)):
            raise ValueError('Continuity requires a 16-byte correlation token')
        # A migration observer can outlive a benchmark. Do not close its
        # established stream at the benchmark's 75-second idle timeout.
        duration = max(0.25, min(float(request.get('duration', 3.0)),
                                 86400.0 if continuity else 60.0))
        conn.settimeout(duration + 15)
        mss = conn.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
        identity = {'probe_id': PROBE_ID, 'instance_id': INSTANCE_ID,
                    'local_ip': str(conn.getsockname()[0]), 'peer_ip': peer_ip,
                    'token': token}
        conn.sendall(b'READY ' + json.dumps(identity).encode() + b'\n'
                     if continuity else b'READY\n')
        started = time.perf_counter()
        interval_started = started
        interval_bytes = 0
        total_bytes = 0
        intervals = []
        while True:
            chunk = conn.recv(262144)
            if not chunk:
                break
            total_bytes += len(chunk)
            interval_bytes += len(chunk)
            now = time.perf_counter()
            interval_elapsed = now - interval_started
            if interval_elapsed >= 1.0:
                intervals.append((interval_bytes * 8.0) / interval_elapsed / 1_000_000.0)
                interval_started = now
                interval_bytes = 0
        finished = time.perf_counter()
        elapsed = max(finished - started, 1e-9)
        if interval_bytes:
            intervals.append((interval_bytes * 8.0) / max(finished - interval_started, 1e-9) / 1_000_000.0)
        response = {
            **identity,
            'bytes': total_bytes,
            'elapsed_s': elapsed,
            'mbps': (total_bytes * 8.0) / elapsed / 1_000_000.0,
            'mss': mss,
            'intervals_mbps': intervals,
            'peer_ip': peer_ip,
        }
        conn.sendall(b'RESULT ' + json.dumps(response, separators=(',', ':')).encode('utf-8') + b'\n')
    except BaseException as exc:
        try:
            conn.sendall(b'ERROR ' + (type(exc).__name__ + ': ' + str(exc)).encode('utf-8', errors='replace') + b'\n')
        except BaseException:
            pass
    finally:
        conn.close()


def tcp_loop(sock):
    while True:
        conn, _ = sock.accept()
        threading.Thread(target=handle_tcp, args=(conn,), daemon=True).start()


def udp_reply(sock, payload, peer, local_ip, interface_index):
    # Select the request's local destination as the reply source. Never allow
    # wildcard source selection (or connect this shared, multi-peer socket).
    try:
        if not local_ip:
            raise ValueError('destination packet-info metadata is missing')
        address = socket.inet_pton(sock.family, local_ip)
        if sock.family == socket.AF_INET6:
            # Only link-local sources require the receiving interface scope.
            # Global sources retain normal source-policy return-route selection.
            scope = interface_index if address[0] == 0xfe and address[1] & 0xc0 == 0x80 else 0
            ancillary = [(socket.IPPROTO_IPV6, socket.IPV6_PKTINFO,
                          struct.pack('=16sI', address, scope))]
        else:
            ancillary = [(socket.IPPROTO_IP, getattr(socket, 'IP_PKTINFO', 8),
                          struct.pack('=I4s4s', 0, address, b'\x00' * 4))]
        sent = sock.sendmsg([payload], ancillary, 0, peer)
        if sent != len(payload):
            raise OSError('incomplete datagram send')
        return True
    except (OSError, ValueError) as exc:
        # Do not kill the shared receiver or retry using an unrelated source.
        print('NEUTRON_FLUX_ERROR UDP reply: ' + type(exc).__name__ + ': ' + str(exc), flush=True)
        return False


def finalize_udp(sock, key, state, request, completed, now_ns):
    peer = key[0]
    state = state or {
        'received': 0,
        'wire_received': 0,
        'bytes': 0,
        'first_ns': now_ns,
        'last_ns': now_ns,
        'duplicates': 0,
        'out_of_order': 0,
        'jitter_ms': 0.0,
        'kernel_counters_start': {},
        'socket_rxq_overflow_start': 0,
        'socket_rxq_overflow_last': 0,
    }
    sent_count = int(request['sent_count'])
    sender_elapsed = max(int(request['sender_elapsed_ns']) / 1_000_000_000.0, 1e-9)
    receiver_elapsed = max(
        (state['last_ns'] - state['first_ns']) / 1_000_000_000.0,
        0.0,
    )
    received = int(state['received'])
    loss = max(sent_count - received, 0)
    kernel_start = state.get('kernel_counters_start') or {}
    kernel_end = udp_kernel_counters(sock.family)
    kernel_deltas = {
        key: max(int(kernel_end.get(key, 0)) - int(kernel_start.get(key, 0)), 0)
        for key in ('InErrors', 'RcvbufErrors')
        if key in kernel_start and key in kernel_end
    }
    socket_overflow = max(
        int(state.get('socket_rxq_overflow_last', 0))
        - int(state.get('socket_rxq_overflow_start', 0)),
        0,
    )
    response = {
        'sent': sent_count,
        'session_id': int(key[1]),
        'max_sequence': int(state.get('max_sequence', -1)),
        'probe_id': PROBE_ID,
        'instance_id': INSTANCE_ID,
        'local_ip': state.get('local_ip', request.get('local_ip')),
        'received': received,
        'application_received': received,
        'socket_dequeued': int(state.get('wire_received', received)),
        # Historical compatibility alias. This counts datagrams dequeued from
        # the socket by the Python receiver; it is not a wire-level counter.
        'wire_received': int(state.get('wire_received', received)),
        'duplicates': int(state.get('duplicates', 0)),
        'lost': loss,
        'loss_pct': (loss * 100.0 / sent_count) if sent_count else 0.0,
        'jitter_ms': float(state['jitter_ms']),
        'out_of_order': int(state['out_of_order']),
        'out_of_order_pct': (
            int(state['out_of_order']) * 100.0 / received if received else 0.0
        ),
        'elapsed_s': sender_elapsed,
        'sender_elapsed_s': sender_elapsed,
        'receiver_active_elapsed_s': receiver_elapsed,
        'pps': received / sender_elapsed,
        'mbps': (int(state['bytes']) * 8.0) / sender_elapsed / 1_000_000.0,
        'finalization_grace_s': UDP_FINALIZE_GRACE_NS / 1_000_000_000.0,
        'peer_ip': str(peer[0]),
        'receiver_kernel_udp_deltas': kernel_deltas,
        'receiver_kernel_udp_counter_scope': (
            'guest-wide-/proc/net/snmp6'
            if sock.family == socket.AF_INET6
            else 'guest-wide-/proc/net/snmp'
        ),
        'receiver_socket_rxq_overflow': socket_overflow,
        'receiver_socket_rxq_overflow_scope': (
            'shared-probe-socket-cumulative-delta'
        ),
        'receiver_drop_attribution_scope': (
            'shared-receiver-socket-and-guest-wide-kernel-counters'
        ),
        'receiver_drop_attribution': (
            'receiver-drop-counters-increased'
            if socket_overflow > 0
            or int(kernel_deltas.get('InErrors', 0)) > 0
            or int(kernel_deltas.get('RcvbufErrors', 0)) > 0
            else 'no-receiver-kernel-drop-evidence-observed'
            if kernel_deltas
            else 'receiver-kernel-drop-attribution-unavailable'
        ),
    }
    if request.get('include_sequence_bitmap'):
        # Continuity only: bounded receiver-backed delivery identities permit
        # phase accounting. Ordinary performance response format is unchanged.
        complete = 0 <= sent_count <= 131072
        bits = bytearray((sent_count + 7) // 8) if complete else bytearray()
        if complete:
            for chunk_index, chunk in (state.get('seen_chunks') or {}).items():
                offset = chunk_index * UDP_SEQUENCE_CHUNK_BYTES
                if offset < len(bits):
                    size = min(len(chunk), len(bits) - offset)
                    bits[offset:offset + size] = chunk[:size]
        response['sequence_bitmap_complete'] = complete
        response['received_bitmap_hex'] = bits.hex() if complete else None
    if request.get('include_sequence_bitmap'):
        # NFC2 negotiates bounded compressed statistics without fragmentation;
        # ordinary NFE1 performance replies retain the original NFR1 format.
        rendered = b'NFR2' + zlib.compress(json.dumps(response, separators=(',', ':')).encode('utf-8'))
        if len(rendered) > 1200:
            response.update(sequence_bitmap_complete=False, received_bitmap_hex=None,
                            phase_evidence_error='receiver bitmap exceeds bounded control datagram')
            rendered = b'NFR2' + zlib.compress(json.dumps(response, separators=(',', ':')).encode('utf-8'))
        if len(rendered) > 1200:
            print('NEUTRON_FLUX_ERROR continuity statistics exceed safe datagram size', flush=True)
            return
    else:
        rendered = b'NFR1' + json.dumps(response, separators=(',', ':')).encode('utf-8')
    reply_source = (request.get('local_ip'), request.get('interface_index', 0))
    completed[key] = (now_ns, rendered, reply_source)
    udp_reply(sock, rendered, peer, *reply_source)


def udp_loop(sock):
    sessions = {}
    pending = {}
    completed = {}
    last_cleanup_ns = 0
    last_socket_overflow = 0
    sock.settimeout(UDP_SOCKET_TICK_S)
    while True:
        overflow_value = None
        local_ip = None
        interface_index = 0
        try:
            data, ancdata, flags, peer = sock.recvmsg(65535, 256)
            for level, kind, value in ancdata:
                if level == socket.IPPROTO_IP and kind == getattr(socket, 'IP_PKTINFO', 8) and len(value)>=12:
                    # IPv4/global IPv6 session identity must not change when
                    # a valid return/arrival route changes interface.
                    local_ip = socket.inet_ntop(socket.AF_INET, value[8:12])
                elif level == socket.IPPROTO_IPV6 and kind == socket.IPV6_PKTINFO and len(value)>=20:
                    local_ip = socket.inet_ntop(socket.AF_INET6, value[:16])
                    if value[0] == 0xfe and value[1] & 0xc0 == 0x80:
                        interface_index = struct.unpack('=I', value[16:20])[0]
                if level == socket.SOL_SOCKET and kind == SO_RXQ_OVFL and len(value) >= 4:
                    overflow_value = struct.unpack('I', value[:4])[0]
            if flags & socket.MSG_CTRUNC:
                local_ip = None
        except socket.timeout:
            data = None
            peer = None
        now_ns = time.monotonic_ns()
        if now_ns - last_cleanup_ns >= 10_000_000_000:
            sessions = {
                key: value
                for key, value in sessions.items()
                if now_ns - value['last_ns'] < 120_000_000_000
            }
            pending = {
                key: value
                for key, value in pending.items()
                if now_ns - value['created_ns'] < 120_000_000_000
            }
            completed = {
                key: value
                for key, value in completed.items()
                if now_ns - value[0] < 10_000_000_000
            }
            last_cleanup_ns = now_ns

        for key, request in list(pending.items()):
            state = sessions.get(key)
            if now_ns >= int(request['deadline_ns']):
                pending.pop(key, None)
                state = sessions.pop(key, None)
                finalize_udp(sock, key, state, request, completed, now_ns)

        if data is None or peer is None:
            continue
        if local_ip is None:
            print('NEUTRON_FLUX_ERROR UDP reply: destination packet-info metadata is missing or truncated', flush=True)
            continue

        previous_socket_overflow = last_socket_overflow
        if overflow_value is not None:
            last_socket_overflow = max(last_socket_overflow, int(overflow_value))

        if data == HEALTH_UDP_REQUEST:
            udp_reply(sock, health_response().rstrip(b'\n'), peer, local_ip, interface_index)
            continue

        if data.startswith(b'NF-PEER '):
            token = data[len(b'NF-PEER '):].decode(errors='replace').strip()
            response = {
                'token': token, 'peer_ip': str(peer[0]), 'local_ip': local_ip,
                'probe_id': PROBE_ID, 'instance_id': INSTANCE_ID,
            }
            udp_reply(sock, b'NF-PEER-OK ' + json.dumps(response).encode() + b'\n', peer, local_ip, interface_index)
            continue

        if len(data) >= UDP_DATA.size and data[:4] == b'NFP1':
            _, session, sequence, sent_ns = UDP_DATA.unpack_from(data)
            key = (peer, session, local_ip, interface_index)
            state = sessions.get(key)
            if state is None:
                # A setdefault default is evaluated even for an existing key.
                # Read /proc only at session boundaries, never per datagram.
                state = {
                    'received': 0,
                    'local_ip': local_ip,
                    'wire_received': 0,
                    'bytes': 0,
                    'first_ns': now_ns,
                    'last_ns': now_ns,
                    'max_sequence': -1,
                    'seen_chunks': {},
                    'duplicates': 0,
                    'out_of_order': 0,
                    'previous_sent_ns': None,
                    'previous_received_ns': None,
                    'jitter_ms': 0.0,
                    'kernel_counters_start': udp_kernel_counters(sock.family),
                    'socket_rxq_overflow_start': int(previous_socket_overflow),
                    'socket_rxq_overflow_last': int(last_socket_overflow),
                }
                sessions[key] = state
            if overflow_value is not None:
                state['socket_rxq_overflow_last'] = max(
                    int(state.get('socket_rxq_overflow_last', 0)),
                    int(overflow_value),
                )
            state['wire_received'] += 1
            chunk_index = sequence >> UDP_SEQUENCE_CHUNK_BITS
            chunk_offset = sequence & (UDP_SEQUENCE_CHUNK_SIZE - 1)
            byte_index = chunk_offset >> 3
            bit_mask = 1 << (chunk_offset & 7)
            seen_chunks = state['seen_chunks']
            seen_bits = seen_chunks.get(chunk_index)
            if seen_bits is None:
                seen_bits = bytearray(UDP_SEQUENCE_CHUNK_BYTES)
                seen_chunks[chunk_index] = seen_bits
            if seen_bits[byte_index] & bit_mask:
                state['duplicates'] += 1
                state['last_ns'] = now_ns
                continue
            seen_bits[byte_index] |= bit_mask
            if sequence < state['max_sequence']:
                state['out_of_order'] += 1
            else:
                state['max_sequence'] = sequence
            previous_sent = state['previous_sent_ns']
            previous_received = state['previous_received_ns']
            if previous_sent is not None and previous_received is not None:
                send_interval = sent_ns - previous_sent
                receive_interval = now_ns - previous_received
                delta_ms = abs(receive_interval - send_interval) / 1_000_000.0
                state['jitter_ms'] += (delta_ms - state['jitter_ms']) / 16.0
            state['previous_sent_ns'] = sent_ns
            state['previous_received_ns'] = now_ns
            state['received'] += 1
            state['bytes'] += len(data)
            state['last_ns'] = now_ns
            continue

        if len(data) >= UDP_END.size and data[:4] in (b'NFE1', b'NFC2'):
            _, session, sent_count, sender_elapsed_ns = UDP_END.unpack_from(data)
            key = (peer, session, local_ip, interface_index)
            state = sessions.get(key)
            if state is not None and overflow_value is not None:
                state['socket_rxq_overflow_last'] = max(
                    int(state.get('socket_rxq_overflow_last', 0)),
                    int(last_socket_overflow),
                )
            cached = completed.get(key)
            if cached is not None and now_ns - cached[0] < 10_000_000_000:
                udp_reply(sock, cached[1], peer, *cached[2])
                continue
            request = {
                'local_ip': local_ip,
                'interface_index': interface_index,
                'include_sequence_bitmap': data[:4] == b'NFC2',
                'sent_count': int(sent_count),
                'sender_elapsed_ns': max(int(sender_elapsed_ns), 1),
                'created_ns': now_ns,
                'deadline_ns': (pending.get(key) or {}).get('deadline_ns', now_ns + UDP_FINALIZE_GRACE_NS),
            }
            pending[key] = request
            continue

        udp_reply(sock, data, peer, local_ip, interface_index)


try:
    jobs = []
    for family in FAMILIES:
        jobs.append((tcp_loop, prepare_socket(family, socket.SOCK_STREAM, TCP_PORT)))
        jobs.append((tcp_loop, prepare_socket(family, socket.SOCK_STREAM, CONTROL_TCP_PORTS[family])))
        jobs.append((udp_loop, prepare_socket(family, socket.SOCK_DGRAM, UDP_PORT)))
    for target, sock in jobs:
        threading.Thread(target=target, args=(sock,), daemon=True).start()
    names = ','.join('IPv6' if family == socket.AF_INET6 else 'IPv4' for family in FAMILIES)
    print(
        'NEUTRON_FLUX_READY '
        f'tcp={TCP_PORT} control_tcp_v4={CONTROL_TCP_PORTS.get(socket.AF_INET)} '
        f'control_tcp_v6={CONTROL_TCP_PORTS.get(socket.AF_INET6)} '
        f'udp={UDP_PORT} performance=builtin families={names}',
        flush=True,
    )
    signal.pause()
except BaseException as exc:
    print(f'NEUTRON_FLUX_ERROR {type(exc).__name__}: {exc}', flush=True)
    raise
"""
        return (
            textwrap.dedent(template)
            .replace("__TCP_PORT__", str(self.tcp_port))
            .replace("__CONTROL_PORTS__", control_ports_literal)
            .replace("__UDP_PORT__", str(self.udp_port))
            .replace("__FAMILIES__", family_literal)
            .replace("__PROBE_ID__", probe_id_literal)
        )

    def command(self, endpoint: Endpoint) -> str:
        """Return the remote foreground command used for one endpoint."""
        return (
            "exec python3 -u -c "
            + shlex.quote(self._server_code(endpoint))
            + " neutron-flux-transient-probe"
        )

    def start(
        self,
        endpoint: Endpoint,
        launcher: Callable[[Endpoint, str], subprocess.Popen[str]],
    ) -> None:
        """Launch and verify a transient probe process for ``endpoint``."""
        self.stop(endpoint)
        command = self.command(endpoint)
        try:
            process = launcher(endpoint, command)
            register_process(process)
        except OSError as exc:
            raise ProbeServiceError(
                f"Could not launch the transient probe SSH session on {endpoint.label}: {exc}"
            ) from exc

        if process.stdout is None or process.stderr is None:
            self._terminate(process)
            raise ProbeServiceError(
                f"Could not start the transient probe process on {endpoint.label}: "
                "launcher did not provide stdout and stderr pipes"
            )

        record = _ProbeProcess(endpoint=endpoint, process=process)
        output_events: queue.Queue[tuple[str, str | None]] = queue.Queue()
        self._start_reader(process.stdout, "stdout", output_events)
        self._start_reader(process.stderr, "stderr", output_events)

        deadline = time.monotonic() + self.startup_timeout
        ready_line = ""
        while time.monotonic() < deadline:
            if process.poll() is not None and output_events.empty():
                break
            remaining = max(0.05, min(0.5, deadline - time.monotonic()))
            try:
                stream_name, line = output_events.get(timeout=remaining)
            except queue.Empty:
                continue
            if line is None:
                continue
            normalized = line.rstrip("\r\n")
            if stream_name == "stdout":
                record.stdout.append(normalized)
            else:
                record.stderr.append(normalized)
            if normalized.startswith(self.READY_PREFIX):
                ready_line = normalized
                break
            if normalized.startswith(self.ERROR_PREFIX):
                break

        if ready_line and process.poll() is None:
            endpoint.metadata.setdefault("probe_service", {})
            endpoint.metadata["probe_service"].update(
                {
                    "mode": "foreground-ssh",
                    "ready": True,
                    "ready_line": ready_line,
                    "tcp_port": self.tcp_port,
                    "control_tcp_ports": dict(self.control_tcp_ports),
                    "udp_port": self.udp_port,
                    "probe_id": endpoint.server_id,
                }
            )
            self._processes[endpoint.server_id] = record
            return

        # Drain any immediately available output so the exception contains the
        # actual Python/SSH failure rather than a generic readiness message.
        drain_deadline = time.monotonic() + 0.5
        while time.monotonic() < drain_deadline:
            try:
                stream_name, line = output_events.get_nowait()
            except queue.Empty:
                break
            if line is None:
                continue
            normalized = line.rstrip("\r\n")
            (record.stdout if stream_name == "stdout" else record.stderr).append(
                normalized
            )

        returncode = process.poll()
        self._terminate(process)
        details = self._failure_details(record)
        if returncode is None:
            details = f"startup timed out after {self.startup_timeout}s; {details}"
        else:
            details = f"process exited with status {returncode}; {details}"
        raise ProbeServiceError(
            f"Could not start the transient probe process on {endpoint.label}: {details}"
        )

    def stop(self, endpoint: Endpoint) -> None:
        record = self._processes.pop(endpoint.server_id, None)
        if record is not None:
            self._terminate(record.process)
            endpoint.metadata.setdefault("probe_service", {})["ready"] = False

    def stop_group(self, group_id: str) -> int:
        selected = [
            server_id
            for server_id, record in self._processes.items()
            if str(record.endpoint.metadata.get("group_id") or "") == group_id
        ]
        for server_id in selected:
            record = self._processes.pop(server_id)
            self._terminate(record.process)
            record.endpoint.metadata.setdefault("probe_service", {})["ready"] = False
        return len(selected)

    def stop_all(self) -> int:
        selected = list(self._processes.values())
        self._processes.clear()
        for record in selected:
            self._terminate(record.process)
            record.endpoint.metadata.setdefault("probe_service", {})["ready"] = False
        return len(selected)

    def is_running(self, endpoint: Endpoint) -> bool:
        record = self._processes.get(endpoint.server_id)
        return bool(record and record.process.poll() is None)

    @property
    def active_count(self) -> int:
        return sum(
            1 for record in self._processes.values() if record.process.poll() is None
        )

    @staticmethod
    def _start_reader(
        stream: TextIO,
        stream_name: str,
        output_events: queue.Queue[tuple[str, str | None]],
    ) -> None:
        def reader() -> None:
            try:
                for line in iter(stream.readline, ""):
                    output_events.put((stream_name, line))
            finally:
                output_events.put((stream_name, None))

        threading.Thread(target=reader, daemon=True).start()

    def _terminate(self, process: subprocess.Popen[str]) -> None:
        try:
            if process.poll() is not None:
                return
            process.terminate()
            try:
                process.wait(timeout=self.stop_timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    process.wait(timeout=self.stop_timeout)
                except subprocess.TimeoutExpired:
                    # The OpenStack VM cleanup will still terminate the remote
                    # process. Avoid blocking the operator indefinitely here.
                    pass
        finally:
            unregister_process(process)

    @staticmethod
    def _failure_details(record: _ProbeProcess) -> str:
        lines = [*record.stderr, *record.stdout]
        meaningful = [line for line in lines if line.strip()]
        if not meaningful:
            return "no stdout or stderr was returned by the SSH-held process"
        return " | ".join(meaningful[-8:])


def _ip_version(address: str) -> int | None:
    try:
        return ipaddress.ip_address(address).version
    except ValueError:
        return None
