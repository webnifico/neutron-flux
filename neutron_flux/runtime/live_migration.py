from __future__ import annotations

import ipaddress
import json
import math
import shlex
import time
from typing import Any

from ..cancellation import cancellation_reconciliation, raise_if_cancelled
from ..constants import MIGRATION_DOWNTIME_TOLERANCE_NOTE
from ..continuity_phases import continuity_outage_bounds, partition_continuity
from ..errors import (
    CommandTimeoutError,
    PlacementUnavailableError,
    RetryableMigrationError,
    RunCancelledError,
    SuiteError,
    UnsafeMigrationStateError,
    UnverifiableMigrationError,
)
from ..failure_injection import inject_failure
from ..migration_completion import migration_completion, migration_operation_settlement
from ..models import ComputeHostInfo, Endpoint, MigrationResult
from ..network_contract import PRIVATE_TRANSLATION_PROJECT_NETWORK
from ..path_evidence import data_route_evidence
from ..utils import nova_task_state_cleared, pick
from .context import serialized_lifecycle
from .live_migration_retry import LiveMigrationRetryMixin


class LiveMigrationRuntimeMixin(LiveMigrationRetryMixin):
    """Tenant-visible live-migration validation and continuity measurement."""

    _LIVE_TYPES = {
        "live migration",
        "live_migration",
        "live-migration",
        "live",
    }

    def _live_migration_storage_args(self) -> list[str]:
        mode = str(self.config.effective_migration_storage or "auto")
        if mode == "host":
            return ["--block-migration"]
        if mode == "shared":
            return ["--shared-migration"]
        return []

    @staticmethod
    def _shared_endpoint_family(
        stationary: Endpoint, moving: Endpoint
    ) -> tuple[int, str, str] | None:
        for family in (4, 6):
            for subnet_id, stationary_address in stationary.fixed_ips.items():
                moving_address = moving.fixed_ips.get(subnet_id)
                if not moving_address:
                    continue
                try:
                    if (
                        ipaddress.ip_address(stationary_address).version == family
                        and ipaddress.ip_address(moving_address).version == family
                    ):
                        return family, stationary_address, moving_address
                except ValueError:
                    continue

        # Routed test pairs do not necessarily share a subnet. Fall back to a
        # common address family only after exhausting same-subnet choices.
        stationary_by_family: dict[int, list[str]] = {4: [], 6: []}
        moving_by_family: dict[int, list[str]] = {4: [], 6: []}
        for endpoint, target in (
            (stationary, stationary_by_family),
            (moving, moving_by_family),
        ):
            for address in endpoint.fixed_ips.values():
                try:
                    target[ipaddress.ip_address(address).version].append(address)
                except ValueError:
                    continue
        for family in (4, 6):
            if stationary_by_family[family] and moving_by_family[family]:
                return (
                    family,
                    stationary_by_family[family][0],
                    moving_by_family[family][0],
                )
        return None

    def _live_continuity_code(
        self,
        *,
        source_ip: str,
        destination_ip: str,
        family: int,
        stop_path: str,
        result_path: str,
        maximum_seconds: int,
        ready_path: str = "continuity.ready",
        expected_probe_id: str | None = None,
        expected_fixed_ip: str | None = None,
        expected_source_ips: tuple[str, ...] | None = None,
    ) -> str:
        return f"""
import json
import os
import socket
import struct
import subprocess
import threading
import time
import zlib

SOURCE={source_ip!r}
DESTINATION={destination_ip!r}
FAMILY=socket.AF_INET6 if {family} == 6 else socket.AF_INET
TCP_PORT={int(self.config.tcp_port)}
UDP_PORT={int(self.config.udp_port)}
STOP=os.environ.get('NEUTRON_FLUX_CONTINUITY_STOP', {stop_path!r})
RESULT=os.environ.get('NEUTRON_FLUX_CONTINUITY_RESULT', {result_path!r})
READY=os.environ.get('NEUTRON_FLUX_CONTINUITY_READY', {ready_path!r})
MAXIMUM={int(maximum_seconds)}
SAMPLE_INTERVAL=0.25
PROBE_DEADLINE=0.20
READINESS_TIMEOUT=10.0
ACK_TIMEOUT=15.0
FINALIZATION_TIMEOUT=20.0
MAX_RESPONSE_BYTES=1_048_576
EXPECTED_PROBE_ID={expected_probe_id!r}
EXPECTED_FIXED_IP={expected_fixed_ip!r}
EXPECTED_SOURCE_IPS={expected_source_ips!r}
TOKEN=os.urandom(16).hex()
started=time.monotonic()
stop=threading.Event()
icmp=[]
tcp={{'connected':False,'survived':False,'bytes_sent':0,'error':None,'terminal':False}}
udp={{'sent':0,'response':None,'error':None,'terminal':False,'send_times_s':[]}}


def should_stop():
    return stop.is_set() or os.path.exists(STOP) or (time.monotonic()-started)>=MAXIMUM


def atomic_json(path, payload):
    temporary=path+'.tmp'
    with open(temporary,'w',encoding='utf-8') as handle:
        json.dump(payload,handle,separators=(',',':'),allow_nan=False)
    os.replace(temporary,path)


def icmp_worker():
    command=['ping','-n','-c','1','-W','1','-I',SOURCE,DESTINATION]
    if FAMILY == socket.AF_INET6:
        command.insert(1,'-6')
    sequence=0
    next_sample=started
    while not should_stop():
        now=time.monotonic()
        if now < next_sample:
            stop.wait(min(next_sample-now,0.05))
            continue
        scheduled=next_sample
        launched=time.monotonic()
        process=None
        timed_out=False
        returncode=None
        try:
            process=subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env={{**os.environ,'LC_ALL':'C','LANG':'C'}},
            )
            deadline=launched+PROBE_DEADLINE
            while process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.005)
            if process.poll() is None:
                timed_out=True
                process.kill()
                process.wait(timeout=1)
            returncode=process.returncode
        except BaseException:
            if process is not None:
                try: process.kill()
                except BaseException: pass
        completed=time.monotonic()
        icmp.append({{
            'sequence':sequence,
            'scheduled_t':scheduled-started,
            'started_t':launched-started,
            'completed_t':completed-started,
            't':scheduled-started,
            'ok':returncode == 0 and not timed_out,
            'returncode':returncode,
            'timed_out':timed_out,
            'late_by_s':max(0.0,launched-scheduled),
            'probe_duration_s':max(0.0,completed-launched),
        }})
        sequence+=1
        next_sample=started+(sequence*SAMPLE_INTERVAL)
        # Do not fire a catch-up burst if the VM was descheduled. Skip elapsed
        # slots and preserve that fact in the sequence/timing evidence.
        now=time.monotonic()
        if now-next_sample >= SAMPLE_INTERVAL:
            skipped=int((now-next_sample)//SAMPLE_INTERVAL)+1
            sequence+=skipped
            next_sample=started+(sequence*SAMPLE_INTERVAL)


def tcp_worker():
    sock=None
    phase='socket-create'
    try:
        sock=socket.socket(FAMILY,socket.SOCK_STREAM)
        sock.settimeout(10)
        phase='source-bind'
        sock.bind((SOURCE,0))
        tcp['local_address']=list(sock.getsockname()[:2])
        phase='connect'
        sock.connect((DESTINATION,TCP_PORT))
        tcp['peer_address']=list(sock.getpeername()[:2])
        phase='ready'
        request=json.dumps({{'duration':MAXIMUM,'continuity':True,'token':TOKEN}},separators=(',',':')).encode()
        sock.sendall(b'NF-PERF '+request+b'\\n')
        ready=b''
        ready_deadline=time.monotonic()+READINESS_TIMEOUT
        while not ready.endswith(b'\\n'):
            remaining=ready_deadline-time.monotonic()
            if remaining <= 0:
                raise TimeoutError('TCP READY deadline exceeded')
            sock.settimeout(remaining)
            chunk=sock.recv(1)
            if not chunk:
                raise ConnectionError('TCP probe closed before READY')
            ready+=chunk
            if len(ready)>65536:
                raise ValueError('TCP READY frame exceeds size limit')
        if ready.startswith(b'READY '):
            identity=json.loads(ready[len(b'READY '):])
            if identity.get('token') != TOKEN:
                raise RuntimeError('TCP READY token does not match the original connection')
            if EXPECTED_PROBE_ID is not None and (
                identity.get('probe_id') != EXPECTED_PROBE_ID
                or identity.get('local_ip') != EXPECTED_FIXED_IP
                or not identity.get('instance_id')
            ):
                raise RuntimeError('TCP READY came from the wrong destination identity/address')
            if EXPECTED_SOURCE_IPS is not None and identity.get('peer_ip') not in EXPECTED_SOURCE_IPS:
                raise RuntimeError('TCP READY observed the wrong translated source')
            tcp['receiver_identity']=identity
        elif ready.strip()!=b'READY' or EXPECTED_PROBE_ID is not None:
            raise RuntimeError('TCP probe did not return an identity-verified READY')
        tcp['connected']=True
        tcp['connected_at_s']=time.monotonic()-started
        sock.settimeout(0.25)
        tcp['write_stalls']=[]
        stall=None
        payload=b'x'*16384
        interval=0.1
        next_send=time.monotonic()
        tcp['target_mbps']=len(payload)*8.0/interval/1_000_000.0
        phase='send'
        while not should_stop():
            now=time.monotonic()
            if now < next_send:
                stop.wait(min(next_send-now,0.05))
                continue
            offset=0
            while offset < len(payload) and not should_stop():
                try:
                    sent=sock.send(payload[offset:])
                except socket.timeout:
                    if stall is None:
                        stall={{'started_at_s':time.monotonic()-started}}
                        tcp['write_stalls'].append(stall)
                    continue
                if sent == 0:
                    raise ConnectionError('TCP stream closed during send')
                offset+=sent
                tcp['bytes_sent']+=sent
                if stall is not None:
                    stall['recovered_at_s']=time.monotonic()-started
                    stall['duration_s']=stall['recovered_at_s']-stall['started_at_s']
                    stall['recovery_basis']='original socket accepted more bytes'
                    stall=None
            tcp['unsent_tail_bytes']=len(payload)-offset
            # Resume the rate without replaying a partial write or catch-up burst.
            next_send=time.monotonic()+interval
        phase='shutdown-write'
        sock.shutdown(socket.SHUT_WR)
        response=b''
        phase='acknowledgement'
        response_deadline=time.monotonic()+ACK_TIMEOUT
        while not response.endswith(b'\\n'):
            remaining=response_deadline-time.monotonic()
            if remaining <= 0:
                raise TimeoutError('TCP final acknowledgement deadline exceeded')
            sock.settimeout(min(0.25,remaining))
            try:
                chunk=sock.recv(min(65536,MAX_RESPONSE_BYTES-len(response)))
            except socket.timeout:
                continue
            if not chunk:
                raise ConnectionError('TCP closed before a complete final RESULT')
            response+=chunk
            if len(response)>=MAX_RESPONSE_BYTES:
                raise ValueError('TCP final RESULT exceeds size limit')
        if not response.startswith(b'RESULT '):
            raise RuntimeError('TCP probe did not return final RESULT')
        phase='receiver-delivery'
        tcp['server_result']=json.loads(response[len(b'RESULT '):])
        identity=tcp.get('receiver_identity')
        if identity is not None and any(
            tcp['server_result'].get(key) != identity.get(key)
            for key in ('token','probe_id','instance_id','local_ip','peer_ip')
        ):
            raise RuntimeError('TCP final RESULT does not match the original receiver/session')
        tcp['identity_verified']=bool(EXPECTED_PROBE_ID is not None and identity is not None)
        receiver_bytes=tcp['server_result'].get('bytes')
        if (type(receiver_bytes) is not int or receiver_bytes<=0
                or receiver_bytes != tcp['bytes_sent']):
            raise RuntimeError('TCP receiver byte count does not match the original stream')
        tcp['receiver_delivery_verified']=True
        if stall is not None:
            stall['recovered_at_s']=time.monotonic()-started
            stall['duration_s']=stall['recovered_at_s']-stall['started_at_s']
            stall['recovery_basis']='receiver acknowledged all accepted bytes'
        tcp['survived']=True
    except BaseException as exc:
        tcp['error']=type(exc).__name__+': '+str(exc)
        tcp['failure_phase']=phase
        tcp['failure_kind']=(
            'stream-reset' if isinstance(exc,(ConnectionResetError,BrokenPipeError))
            else 'incomplete-delivery' if phase=='receiver-delivery'
            else 'acknowledgement-timeout' if phase=='acknowledgement' and isinstance(exc,socket.timeout)
            else 'missing-acknowledgement' if phase=='acknowledgement'
            else 'write-stall-timeout' if phase=='send' and isinstance(exc,socket.timeout)
            else 'stream-error'
        )
        tcp['failed_at_s']=time.monotonic()-started
    finally:
        if sock is not None:
            try: sock.close()
            except BaseException: pass
        tcp['terminal']=True


def udp_worker():
    header=struct.Struct('!4sQIQ')
    end=struct.Struct('!4sQIQ')
    session=int(time.monotonic_ns() & ((1<<63)-1))
    sock=None
    sequence=0
    try:
        sock=socket.socket(FAMILY,socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.bind((SOURCE,0))
        sock.connect((DESTINATION,UDP_PORT))
        udp['session_id']=session
        payload=b'u'*max(0,128-header.size)
        send_started=time.monotonic_ns()
        next_send=time.monotonic()
        while not should_stop():
            now=time.monotonic()
            if now < next_send:
                stop.wait(min(next_send-now,0.05))
                continue
            sent_at=time.monotonic()-started
            sock.send(header.pack(b'NFP1',session,sequence,time.monotonic_ns())+payload)
            udp['send_times_s'].append(sent_at)
            sequence+=1
            udp['sent']=sequence
            if sequence == 1:
                udp['started_at_s']=time.monotonic()-started
            next_send+=0.05
        elapsed=max(time.monotonic_ns()-send_started,1)
        marker=end.pack(b'NFC2',session,sequence,elapsed)
        for _ in range(5):
            sock.send(marker)
            try:
                data=sock.recv(65535)
            except socket.timeout:
                continue
            if data.startswith((b'NFR1', b'NFR2')):
                encoded=data[4:]
                if data.startswith(b'NFR2'):
                    decoder=zlib.decompressobj()
                    encoded=decoder.decompress(encoded,65537)
                    if len(encoded)>65536 or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                        raise ValueError('Invalid or oversized continuity statistics envelope')
                response=json.loads(encoded)
                if response.get('session_id') != session:
                    continue
                udp['response']=response
                if EXPECTED_PROBE_ID is not None and (
                    response.get('probe_id') != EXPECTED_PROBE_ID
                    or response.get('local_ip') != EXPECTED_FIXED_IP
                    or not response.get('instance_id')
                    or response.get('instance_id') != (tcp.get('receiver_identity') or {{}}).get('instance_id')
                ):
                    raise RuntimeError('UDP statistics came from the wrong destination/service')
                if EXPECTED_SOURCE_IPS is not None and response.get('peer_ip') not in EXPECTED_SOURCE_IPS:
                    raise RuntimeError('UDP statistics observed the wrong translated source')
                udp['identity_verified']=EXPECTED_PROBE_ID is not None
                break
        udp['sent']=sequence
        if udp['response'] is None:
            raise RuntimeError('UDP probe did not return final statistics')
    except BaseException as exc:
        udp['sent']=sequence
        udp['error']=type(exc).__name__+': '+str(exc)
    finally:
        if sock is not None:
            try: sock.close()
            except BaseException: pass
        udp['terminal']=True


threads=[
    threading.Thread(target=icmp_worker,daemon=True),
    threading.Thread(target=tcp_worker,daemon=True),
    threading.Thread(target=udp_worker,daemon=True),
]
for thread in threads: thread.start()
readiness_deadline=started+READINESS_TIMEOUT
ready=False
while not should_stop() and time.monotonic() < readiness_deadline:
    ready=(
        tcp.get('connected') is True
        and sum(1 for sample in icmp if sample.get('ok') is True) >= 2
        and int(udp.get('sent') or 0) > 0
    )
    if ready:
        break
    time.sleep(0.05)
readiness={{
    'ready':ready,
    'started_monotonic_s':started,
    'ready_at_s':time.monotonic()-started if ready else None,
    'tcp_connected':bool(tcp.get('connected')),
    'icmp_successful':sum(1 for sample in icmp if sample.get('ok') is True),
    'udp_sent':int(udp.get('sent') or 0),
    'sample_interval_s':SAMPLE_INTERVAL,
    'probe_deadline_s':PROBE_DEADLINE,
}}
atomic_json(READY,readiness)
if not ready:
    stop.set()
while not should_stop():
    time.sleep(0.05)
observation_finished=time.monotonic()
stop.set()
finalization_deadline=time.monotonic()+FINALIZATION_TIMEOUT
for thread in threads:
    thread.join(max(0.0,finalization_deadline-time.monotonic()))
workers_complete=not any(thread.is_alive() for thread in threads)
if not workers_complete:
    for name, thread, evidence in zip(('icmp','tcp','udp'),threads,(None,tcp,udp)):
        if thread.is_alive() and evidence is not None:
            evidence['error']=name.upper()+' monitor finalization deadline exceeded'
            evidence['failure_kind']='monitor-finalization-timeout'
            evidence['failure_phase']='finalization'
            evidence['terminal']=False
            if name=='tcp': evidence['survived']=False
finished=time.monotonic()
payload={{
    'source_ip':SOURCE,
    'destination_ip':DESTINATION,
    'family':{family},
    'duration_s':finished-started,
    'observation_duration_s':observation_finished-started,
    'readiness':readiness,
    'workers_complete':workers_complete,
    'finalization_timeout_s':FINALIZATION_TIMEOUT,
    'acknowledgement_timeout_s':ACK_TIMEOUT,
    'sample_interval_s':SAMPLE_INTERVAL,
    'probe_deadline_s':PROBE_DEADLINE,
    'icmp':icmp,
    'tcp':tcp,
    'udp':udp,
}}
atomic_json(RESULT,payload)
"""

    def _start_live_continuity(
        self, stationary: Endpoint, moving: Endpoint
    ) -> dict[str, Any]:
        observer, destination = stationary, moving
        owners = {
            endpoint.server_id: runtime
            for runtime in getattr(self, "runtime_groups", [])
            for endpoint in runtime.endpoints
        }
        moving_group = owners.get(moving.server_id)
        stationary_group = owners.get(stationary.server_id)
        if (
            moving_group is not None
            and stationary_group is not None
            and moving_group.plan.kind == PRIVATE_TRANSLATION_PROJECT_NETWORK
            and (
                stationary_group.plan.kind == "provider"
                or stationary.metadata.get("floating_ip_identity")
            )
            and moving_group.source_nat_enabled is True
            and not moving.metadata.get("floating_ip_identity")
        ):
            # A new reverse flow to a private fixed IP has no DNAT mapping.
            # Keep the tested SNAT direction even when its source VM moves.
            observer, destination = moving, stationary
        selected = self._shared_endpoint_family(observer, destination)
        source_fip = observer.metadata.get("floating_ip_identity")
        target_fip = destination.metadata.get("floating_ip_identity")
        if target_fip:
            source_ip = (
                source_fip["fixed_ip"]
                if source_fip
                else next(
                    (
                        ip
                        for ip in observer.fixed_ips.values()
                        if ipaddress.ip_address(ip).version == 4
                    ),
                    None,
                )
            )
            selected = (4, source_ip, target_fip["address"]) if source_ip else None
        if selected is None:
            return {
                "available": False,
                "reason": "No common IPv4 or IPv6 fixed-address family was available",
            }
        family, source_ip, destination_ip = selected
        destination_fixed = target_fip.get("fixed_ip") if target_fip else destination_ip
        if destination_fixed not in destination.fixed_ips.values():
            return {
                "available": False,
                "reason": "Continuity destination is not the intended data address",
            }
        try:
            route_observation = self.inspect_endpoint_route(
                observer, source_ip, destination_ip, family
            )
        except RunCancelledError:
            raise
        except (OSError, SuiteError, ValueError, TypeError) as exc:
            return {
                "available": False,
                "reason": "Continuity data route unavailable: " + str(exc),
            }
        route_before = data_route_evidence(
            observer, source_ip, destination_ip, route_observation
        )
        if route_before["verified"] is not True:
            return {
                "available": False,
                "reason": route_before["reason"],
                "data_path_before": route_before,
            }
        observer_group = owners.get(observer.server_id)
        destination_group = owners.get(destination.server_id)
        expected_sources = None
        if observer_group is not None and observer_group.plan.kind == "provider":
            expected_sources = (source_ip,)
        elif (
            source_fip
            and observer_group
            and destination_group
            and (observer_group.router_id != destination_group.router_id)
        ):
            expected_sources = (str(source_fip["address"]),)
        elif (
            observer_group
            and observer_group.source_nat_enabled is True
            and not source_fip
            and (
                target_fip
                or (destination_group and destination_group.plan.kind == "provider")
            )
        ):
            try:
                router = self.capture_router_state(observer_group.router_id)
                gateway = self._gateway_info(router.get("external_gateway_info") or {})
                expected_sources = tuple(
                    str(row["ip_address"])
                    for row in gateway.get("external_fixed_ips", [])
                    if row.get("ip_address")
                    and ipaddress.ip_address(row["ip_address"]).version == family
                )
            except RunCancelledError:
                raise
            except (OSError, SuiteError, ValueError, TypeError) as exc:
                return {
                    "available": False,
                    "reason": "Continuity SNAT readback unavailable: " + str(exc),
                }
            if gateway.get("enable_snat") is not True or not expected_sources:
                return {
                    "available": False,
                    "reason": "Continuity source SNAT/gateway could not be verified",
                }
        # The OpenStack client request can consume one resource timeout and a
        # subsequent Nova-state reconciliation can consume another. Keep the
        # guest observer alive across that complete window, while still
        # bounding unattended guest activity.
        maximum = max(
            60,
            (int(self.config.resource_timeout) * 4)
            + (int(self.config.convergence_timeout) * 2)
            + 120,
        )
        code = self._live_continuity_code(
            source_ip=source_ip,
            destination_ip=destination_ip,
            family=family,
            stop_path="continuity.stop",
            result_path="continuity.json",
            ready_path="continuity.ready",
            maximum_seconds=maximum,
            expected_probe_id=destination.server_id,
            expected_fixed_ip=destination_fixed,
            expected_source_ips=expected_sources,
        )
        readiness_check = shlex.quote(
            "import json,sys; data=json.load(open(sys.argv[1])); "
            "sys.exit(0 if data.get('ready') is True else 1)"
        )
        command = (
            "umask 077; "
            'work_dir=$(mktemp -d "${TMPDIR:-/tmp}/neutron-flux-live.XXXXXX") '
            "|| exit 1; "
            'stop_path="$work_dir/stop"; '
            'result_path="$work_dir/result.json"; '
            'ready_path="$work_dir/ready.json"; '
            'error_path="$work_dir/error.log"; '
            'nohup env NEUTRON_FLUX_CONTINUITY_STOP="$stop_path" '
            'NEUTRON_FLUX_CONTINUITY_RESULT="$result_path" '
            'NEUTRON_FLUX_CONTINUITY_READY="$ready_path" '
            f'python3 -c {shlex.quote(code)} >/dev/null 2>"$error_path" </dev/null & '
            "pid=$!; "
            'for i in $(seq 1 120); do test -s "$ready_path" && break; '
            'kill -0 "$pid" 2>/dev/null || break; sleep 0.125; done; '
            'kill -0 "$pid" 2>/dev/null || { '
            'cat "$error_path" >&2; '
            'rm -f "$stop_path" "$result_path" "$ready_path" "$error_path"; '
            'rmdir "$work_dir" 2>/dev/null || true; exit 1; }; '
            'test -s "$ready_path" || { '
            'printf "%s\n" "continuity monitor did not become ready" >&2; '
            'touch "$stop_path"; kill "$pid" 2>/dev/null || true; '
            'cat "$error_path" >&2 2>/dev/null || true; '
            'rm -f "$stop_path" "$result_path" "$ready_path" "$error_path"; '
            'rmdir "$work_dir" 2>/dev/null || true; exit 1; }; '
            f'python3 -c {readiness_check} "$ready_path" || {{ '
            'cat "$ready_path" >&2; touch "$stop_path"; '
            'kill "$pid" 2>/dev/null || true; '
            'rm -f "$stop_path" "$result_path" "$ready_path" "$error_path"; '
            'rmdir "$work_dir" 2>/dev/null || true; exit 1; }; '
            'printf \'%s\\t%s\\n\' "$pid" "$work_dir"'
        )
        result = self.ssh_endpoint(observer, command)
        if result.returncode != 0:
            return {
                "available": False,
                "reason": (
                    "Could not start guest continuity monitor: "
                    + (result.stderr or result.stdout).strip()
                ),
            }
        output = (result.stdout or "").strip().splitlines()
        identity = output[-1].split("\t", 1) if output else []
        if len(identity) != 2 or not identity[0] or not identity[1].startswith("/"):
            return {
                "available": False,
                "reason": (
                    "Continuity monitor did not return its process and secure "
                    "working-directory identity"
                ),
            }
        pid, work_dir = identity
        return {
            "available": True,
            "measurement_phase_contract": 1,
            "phase_markers_required": True,
            "stationary_server_id": stationary.server_id,
            "stationary_label": stationary.label,
            "moving_server_id": moving.server_id,
            "observer_server_id": observer.server_id,
            "observer_label": observer.label,
            "target_server_id": destination.server_id,
            "target_fixed_ip": destination_fixed,
            "expected_translation_sources": expected_sources,
            "data_path_before": route_before,
            "family": family,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "address_mode": "floating-ip" if target_fip else "fixed-ip",
            "source_floating_ip": source_fip,
            "destination_floating_ip": target_fip,
            "pid": pid,
            "work_dir": work_dir,
            "stop_path": f"{work_dir}/stop",
            "result_path": f"{work_dir}/result.json",
            "ready_path": f"{work_dir}/ready.json",
            "error_path": f"{work_dir}/error.log",
            "started_at": time.monotonic(),
        }

    def _mark_live_continuity_phase(
        self,
        stationary: Endpoint,
        state: dict[str, Any],
        phase: str,
    ) -> bool:
        """Stamp phase boundaries on the same guest clock as packet samples."""
        if not state.get("available") or not state.get("phase_markers_required"):
            return True
        if phase not in {"migration_submitted", "placement_verified"}:
            raise ValueError("Unknown continuity phase")
        observer_id = state.get("observer_server_id", stationary.server_id)
        observer = (
            stationary
            if observer_id == stationary.server_id
            else next(
                (
                    ep
                    for runtime in getattr(self, "runtime_groups", [])
                    for ep in runtime.endpoints
                    if ep.server_id == observer_id
                ),
                None,
            )
        )
        if observer is None:
            state["phase_marker_error"] = "Continuity observer unavailable"
            return False
        code = (
            "import json,time,sys; r=json.load(open(sys.argv[1])); "
            "assert r['ready'] is True; "
            "print(json.dumps({'t':time.monotonic()-r['started_monotonic_s']}))"
        )
        try:
            result = self.ssh_endpoint(
                observer,
                f"python3 -c {shlex.quote(code)} {shlex.quote(str(state['ready_path']))}",
            )
            data = json.loads(result.stdout) if result.returncode == 0 else {}
            value = data.get("t") if isinstance(data, dict) else None
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise ValueError("Guest did not return a valid phase timestamp")
            state.setdefault("phase_markers", {})[phase] = value
            return True
        except RunCancelledError:
            raise
        except (OSError, SuiteError, ValueError, TypeError, KeyError) as exc:
            state["phase_marker_error"] = str(exc)
            return False

    @staticmethod
    def _continuity_outage_bounds(
        samples: list[dict[str, Any]],
        *,
        sample_interval_s: float = 0.25,
    ) -> dict[str, Any]:
        return continuity_outage_bounds(samples, sample_interval_s=sample_interval_s)

    def _stop_live_continuity(
        self, stationary: Endpoint, state: dict[str, Any]
    ) -> dict[str, Any]:
        if not state.get("available"):
            return state
        observer = stationary
        observer_id = state.get("observer_server_id", stationary.server_id)
        if observer_id != stationary.server_id:
            observer = next(
                (
                    endpoint
                    for runtime in getattr(self, "runtime_groups", [])
                    for endpoint in runtime.endpoints
                    if endpoint.server_id == observer_id
                ),
                None,
            )
            if observer is None:
                return {
                    **state,
                    "available": False,
                    "reason": "Original continuity observer is no longer available",
                }
        stop_path = str(state["stop_path"])
        result_path = str(state["result_path"])
        ready_path = str(state.get("ready_path") or "")
        error_path = str(state["error_path"])
        work_dir = str(state.get("work_dir") or "")
        pid = str(state.get("pid") or "")
        remove_work_dir = (
            f"rmdir {shlex.quote(work_dir)} 2>/dev/null || true; " if work_dir else ""
        )
        command = (
            f"touch {shlex.quote(stop_path)}; "
            "for i in $(seq 1 60); do "
            f"test -s {shlex.quote(result_path)} && break; sleep 0.5; done; "
            f"if test ! -s {shlex.quote(result_path)}; then "
            + (f"kill {shlex.quote(pid)} 2>/dev/null || true; " if pid else "")
            + f"printf '%s\\n' 'monitor did not produce a result' >&2; "
            f"cat {shlex.quote(error_path)} >&2 2>/dev/null || true; "
            f"rm -f {shlex.quote(stop_path)} {shlex.quote(result_path)} "
            + (f"{shlex.quote(ready_path)} " if ready_path else "")
            + f"{shlex.quote(error_path)}; "
            + remove_work_dir
            + "exit 1; fi; "
            f"cat {shlex.quote(result_path)}; "
            f"rm -f {shlex.quote(stop_path)} {shlex.quote(result_path)} "
            + (f"{shlex.quote(ready_path)} " if ready_path else "")
            + f"{shlex.quote(error_path)}; "
            + remove_work_dir.rstrip()
        )
        stop_requested_at = time.monotonic()
        result = self.ssh_endpoint(observer, command)
        if (
            state.get("source_ip")
            and state.get("destination_ip")
            and state.get("family")
        ):
            try:
                route_after = self.inspect_endpoint_route(
                    observer,
                    state["source_ip"],
                    state["destination_ip"],
                    state["family"],
                )
            except RunCancelledError:
                raise
            except (OSError, SuiteError, ValueError, TypeError) as exc:
                route_after = {"stderr": str(exc)}
            state = {
                **state,
                "data_path_after": data_route_evidence(
                    observer,
                    state["source_ip"],
                    state["destination_ip"],
                    route_after,
                ),
            }
        if result.returncode != 0:
            return {
                **state,
                "available": False,
                "reason": (
                    "Could not collect guest continuity evidence: "
                    + (result.stderr or result.stdout).strip()
                ),
            }
        try:
            payload = json.loads((result.stdout or "").strip())
        except (TypeError, ValueError) as exc:
            return {
                **state,
                "available": False,
                "reason": f"Continuity monitor returned invalid JSON: {exc}",
            }
        if not isinstance(payload, dict):
            return {
                **state,
                "available": False,
                "reason": "Continuity monitor returned a non-object JSON payload",
            }
        warnings: list[str] = []
        readiness = payload.get("readiness") or {}
        if not isinstance(readiness, dict):
            readiness = {}
            warnings.append("continuity readiness evidence was malformed")
        ready = readiness.get("ready") is True
        if not ready:
            warnings.append(
                "continuity probes were not ready before migration submission"
            )
        try:
            sample_interval = float(payload.get("sample_interval_s") or 0.25)
        except (TypeError, ValueError):
            sample_interval = 0.25
            warnings.append("continuity sample interval was invalid")
        if not math.isfinite(sample_interval) or sample_interval <= 0.0:
            sample_interval = 0.25
            warnings.append("continuity sample interval was invalid")
        try:
            probe_deadline = float(payload.get("probe_deadline_s") or 0.20)
        except (TypeError, ValueError):
            probe_deadline = 0.20
            warnings.append("continuity probe deadline was invalid")
        raw_samples = payload.get("icmp")
        if not isinstance(raw_samples, list):
            raw_samples = []
            warnings.append("ICMP continuity samples were malformed")
        samples = [item for item in raw_samples if isinstance(item, dict)]
        if len(samples) != len(raw_samples):
            warnings.append("ICMP continuity contained malformed sample rows")
        malformed_sample_values = any(
            not isinstance(item.get("ok"), bool)
            or not isinstance(item.get("scheduled_t", item.get("t")), (int, float))
            or isinstance(item.get("scheduled_t", item.get("t")), bool)
            or not math.isfinite(float(item.get("scheduled_t", item.get("t"))))
            for item in samples
        )
        if malformed_sample_values:
            warnings.append("ICMP continuity contained invalid sample values")
        successes = sum(1 for item in samples if item.get("ok") is True)
        total = len(samples)
        late_limit = max(sample_interval * 0.5, 0.05)
        late_samples = [
            item
            for item in samples
            if isinstance(item.get("late_by_s"), (int, float))
            and not isinstance(item.get("late_by_s"), bool)
            and float(item.get("late_by_s") or 0.0) > late_limit
        ]
        sequence_values = [
            int(item["sequence"])
            for item in samples
            if isinstance(item.get("sequence"), int)
            and not isinstance(item.get("sequence"), bool)
            and int(item["sequence"]) >= 0
        ]
        sequence_valid = bool(
            len(sequence_values) == total
            and (
                not sequence_values
                or (
                    sequence_values[0] == 0
                    and all(
                        current > previous
                        for previous, current in zip(
                            sequence_values,
                            sequence_values[1:],
                            strict=False,
                        )
                    )
                )
            )
        )
        skipped_slots = 0
        if sequence_valid and sequence_values:
            skipped_slots = max(sequence_values[-1] + 1 - total, 0)
        elif total:
            warnings.append(
                "ICMP continuity sequence evidence was missing, duplicated, or "
                "out of order"
            )
        tcp = payload.get("tcp") or {}
        udp = payload.get("udp") or {}
        if not isinstance(tcp, dict):
            tcp = {}
            warnings.append("TCP continuity evidence was malformed")
        if not isinstance(udp, dict):
            udp = {}
            warnings.append("UDP continuity evidence was malformed")
        udp_response = udp.get("response") or {}
        if not isinstance(udp_response, dict):
            udp_response = {}
            warnings.append("UDP continuity statistics were malformed")
        icmp_loss = ((total - successes) * 100.0 / total) if total else None
        udp_loss = udp_response.get("loss_pct")
        duration_valid = True
        try:
            monitor_duration = float(payload.get("duration_s") or 0.0)
        except (TypeError, ValueError):
            monitor_duration = 0.0
            duration_valid = False
        if not math.isfinite(monitor_duration) or monitor_duration < 0.0:
            monitor_duration = 0.0
            duration_valid = False
        if not duration_valid:
            warnings.append("Continuity monitor duration was invalid")
        observation_duration_valid = True
        try:
            observation_duration = float(
                payload.get("observation_duration_s")
                if payload.get("observation_duration_s") is not None
                else monitor_duration
            )
        except (TypeError, ValueError):
            observation_duration = 0.0
            observation_duration_valid = False
        if (
            not math.isfinite(observation_duration)
            or observation_duration < 0.0
            or observation_duration > monitor_duration + 0.001
        ):
            observation_duration = 0.0
            observation_duration_valid = False
        if not observation_duration_valid:
            warnings.append("Continuity observation duration was invalid")
        monitor_started_valid = True
        try:
            monitor_started = float(state.get("started_at") or time.monotonic())
        except (TypeError, ValueError):
            monitor_started = time.monotonic()
            monitor_started_valid = False
            warnings.append("Continuity monitor start time was invalid")
        if not math.isfinite(monitor_started):
            monitor_started = time.monotonic()
            monitor_started_valid = False
            warnings.append("Continuity monitor start time was invalid")
        requested_window = max(
            0.0,
            stop_requested_at - monitor_started,
        )
        full_migration_window = (
            monitor_started_valid
            and observation_duration_valid
            and observation_duration + 2.0 >= requested_window
        )
        expected_samples = (
            max(1, int(observation_duration / sample_interval) - 1)
            if observation_duration_valid and observation_duration > 0.0
            else 0
        )
        sample_count_complete = total >= expected_samples if expected_samples else False
        sampling_complete = bool(
            not malformed_sample_values
            and sequence_valid
            and total > 0
            and sample_count_complete
            and not late_samples
            and skipped_slots == 0
        )
        if late_samples:
            warnings.append(
                f"{len(late_samples)} ICMP observation(s) started too late for the "
                "fixed-cadence continuity contract"
            )
        if skipped_slots:
            warnings.append(
                f"{skipped_slots} fixed-cadence ICMP observation slot(s) were skipped"
            )
        if not sample_count_complete:
            warnings.append(
                f"ICMP continuity returned {total} sample(s), below the expected "
                f"minimum {expected_samples}"
            )
        health = "warning" if warnings else "good"
        if not full_migration_window:
            health = "warning"
            warnings.append(
                "the guest continuity monitor ended before Flux completed the "
                "migration and reconciliation window"
            )
        if total == 0:
            health = "warning"
            warnings.append("ICMP continuity produced no samples")
        elif successes < total:
            health = "warning"
            warnings.append(
                f"Whole-monitor ICMP missed {total - successes}/{total} responses; phase-specific counts are recorded separately"
            )
        if not tcp.get("survived"):
            health = "warning"
            warnings.append("the long-lived TCP stream did not survive")
        if udp_response:
            try:
                if (
                    float(udp_loss or 0.0)
                    > self.config.performance_udp_loss_threshold_pct
                ):
                    health = "warning"
                    warnings.append(
                        f"sequenced UDP application-delivery loss was "
                        f"{float(udp_loss):.3f}%"
                    )
            except (TypeError, ValueError):
                health = "warning"
                warnings.append(
                    "sequenced UDP application-delivery loss could not be parsed"
                )
        else:
            health = "warning"
            warnings.append("sequenced UDP continuity returned no statistics")
        outage = self._continuity_outage_bounds(
            samples, sample_interval_s=sample_interval
        )
        thresholds = {
            # A single fixed-cadence userspace observation can be missed because
            # of guest or SSH scheduling even when the established TCP stream
            # survives and no meaningful outage is confirmed. Loss is advisory
            # only within these bounds; each protocol must also recover.
            "icmp_loss_pct": 1.0,
            "udp_loss_pct": float(self.config.performance_udp_loss_threshold_pct),
            "outage_lower_bound_s": 1.0,
            "sample_interval_s": sample_interval,
            "probe_deadline_s": probe_deadline,
        }
        phase_evidence = partition_continuity(
            payload,
            state,
            self._continuity_outage_bounds,
            sample_interval_s=sample_interval,
        )
        protected = phase_evidence["phases"].get("protected")
        if protected is not None:
            samples = protected["icmp"]["raw_samples"]
            total = protected["icmp"]["samples"]
            successes = protected["icmp"]["successful"]
            icmp_loss = protected["icmp"]["loss_pct"]
            outage = protected["icmp"]["outage"]
            udp = {**udp, "protected_measurement": protected["udp"]}
        if phase_evidence["phases"].get("startup", {}).get("icmp", {}).get("lost", 0):
            warnings.append(
                "Startup ICMP failures are retained separately, not attributed to migration"
            )
            health = "warning"
        if (
            state.get("measurement_phase_contract") == 1
            and not phase_evidence["verified"]
        ):
            warnings.append("Migration phase attribution evidence is incomplete")
            health = "warning"
        return {
            **state,
            "available": True,
            "phase_evidence": phase_evidence,
            "health": health,
            "warnings": warnings,
            "duration_s": monitor_duration,
            "observation_duration_s": observation_duration,
            "requested_window_s": requested_window,
            "full_migration_window": full_migration_window,
            "readiness": readiness,
            "ready_before_migration": ready,
            "sampling_complete": sampling_complete,
            "workers_complete": payload.get("workers_complete") is True,
            "finalization_timeout_s": payload.get("finalization_timeout_s"),
            "acknowledgement_timeout_s": payload.get("acknowledgement_timeout_s"),
            "expected_icmp_samples": expected_samples,
            "expected_whole_monitor_icmp_samples": expected_samples,
            "late_icmp_samples": len(late_samples),
            "skipped_icmp_slots": skipped_slots,
            "thresholds": {
                **thresholds,
                "assessment_scope": (
                    "ready-through-post-migration"
                    if protected is not None
                    else "whole-monitor-unattributed"
                ),
                "policy_source": MIGRATION_DOWNTIME_TOLERANCE_NOTE,
            },
            "icmp": {
                "samples": total,
                "successful": successes,
                "lost": total - successes,
                "loss_pct": icmp_loss,
                # Compatibility field: this is the sampled failed-observation
                # span, not a proven continuous outage duration.
                "longest_outage_s": outage["outage_lower_bound_s"],
                "outage": outage,
                "raw_samples": samples,
            },
            "tcp": tcp,
            "udp": udp,
        }

    def _wait_for_live_destination(
        self, endpoint: Endpoint, target_host: str
    ) -> dict[str, Any]:
        deadline = time.monotonic() + self.config.resource_timeout
        last_status = ""
        last_host = ""
        last_error = ""
        before = endpoint.metadata.get("_migration_attempt_baseline")
        while time.monotonic() < deadline:
            raise_if_cancelled()
            if before and before.get("migration_ids") is not None:
                failed, evidence = self._authoritative_migration_failure(
                    endpoint, before
                )
                if failed:
                    message = (
                        f"Nova live migration {evidence['new_migration_ids']} failed "
                        f"with status {evidence['statuses']} while moving "
                        f"{endpoint.label} from {before.get('source_host')} to {target_host}"
                    )
                    self.reporter.event(
                        "live-migration-terminal-failure",
                        message,
                        server_id=endpoint.server_id,
                        **evidence,
                    )
                    raise SuiteError(message)
            try:
                detail = (
                    self._json_with_transient_retry(
                        "server",
                        "show",
                        endpoint.server_id,
                        check=False,
                        timeout=min(15, max(1, int(deadline - time.monotonic()))),
                        context=f"waiting for live migration of {endpoint.label}",
                    )
                    or {}
                )
            except RunCancelledError:
                raise
            except SuiteError as exc:
                last_error = str(exc)
                time.sleep(min(2, max(0, deadline - time.monotonic())))
                continue
            status = str(pick(detail, "status", default="") or "").lower()
            host = str(pick(detail, "os_ext_srv_attr_host", "host", default="") or "")
            task_state_cleared = nova_task_state_cleared(detail)
            last_status, last_host = status, host
            if (
                status == "active"
                and host == target_host
                and task_state_cleared is True
            ):
                return detail
            if status == "error":
                raise SuiteError(f"Live migration placed {endpoint.label} into ERROR")
            time.sleep(2)
        raise SuiteError(
            f"Timed out waiting for live migration of {endpoint.label} to {target_host}: "
            f"status={last_status or 'unknown'}, host={last_host or 'unknown'}"
            + (f"; last read error={last_error}" if last_error else "")
        )

    def _live_migrate_endpoint_once(
        self,
        endpoint: Endpoint,
        target: ComputeHostInfo,
        stationary_peer: Endpoint | None = None,
    ) -> MigrationResult:
        if not endpoint.host:
            raise PlacementUnavailableError(
                f"Nova did not expose the source compute host for {endpoint.label}"
            )
        source_host = endpoint.host
        source_az = endpoint.availability_zone
        target_az = target.availability_zone
        if not source_az:
            source_info = self.compute_host_inventory(refresh=True).get(source_host)
            source_az = source_info.availability_zone if source_info else None
            endpoint.availability_zone = source_az
        if source_host == target.host:
            raise PlacementUnavailableError(
                f"Live migration target for {endpoint.label} equals its current host {source_host}"
            )
        if not source_az or not target_az:
            raise PlacementUnavailableError(
                "Source or destination availability zone is unknown"
            )
        if source_az != target_az:
            raise PlacementUnavailableError(
                f"Cross-AZ live migration is disabled by design ({source_az} -> {target_az})"
            )

        self._record_migration_destination(
            endpoint,
            target,
            migration_type="live",
        )
        retry = endpoint.metadata.pop(self._LIVE_RETRY_KEY, None)
        if retry:
            if retry["target_host"] != target.host:
                raise UnverifiableMigrationError("Live recovery retry target changed")
            try:
                # Recheck after backoff, immediately before any new submission.
                self._live_retry_observation(
                    endpoint, target.host, retry["failed_baseline"]
                )
            except RunCancelledError:
                raise
            except SuiteError as exc:
                raise UnverifiableMigrationError(
                    f"Live recovery retry was not submitted: {exc}"
                ) from exc
            before = retry["next_baseline"]
            coordinator = getattr(self, "cloud_operation_coordinator", None)
            if coordinator is not None:
                coordinator.annotate_current_transaction(
                    resource_ids=[
                        endpoint.server_id,
                        *before["ports"],
                        *sorted(before["volume_ids"]),
                    ],
                    pre_state={
                        "migration_ids": sorted(before["migration_ids"]),
                        "source_host": before["source_host"],
                        "migration_port_ids": sorted(before["ports"]),
                        "migration_volume_ids": sorted(before["volume_ids"]),
                        "recovery_retry": True,
                    },
                )
        else:
            self._pre_migration_control_plane_barrier(endpoint, source_host)
            before = self._capture_endpoint_migration_state(endpoint)
            if getattr(self, "cloud_operation_coordinator", None) is not None:
                before["live_action_ids"] = self._live_action_ids(endpoint)
        before["target_host"] = target.host
        before["migration_type"] = "live"
        endpoint.metadata["_migration_attempt_baseline"] = before
        continuity: dict[str, Any] = {
            "available": False,
            "reason": "Live continuity measurement is disabled or no stationary peer was supplied",
        }
        if retry:
            continuity = {
                "available": False,
                "reason": "Recovery retry after confirmed rollback; the original healthy guest baseline is retained",
                "recovery_retry": True,
            }
        if (
            not retry
            and self.config.live_migration_continuity
            and stationary_peer is not None
        ):
            continuity = self._start_live_continuity(stationary_peer, endpoint)
            if not continuity.get("available"):
                raise UnverifiableMigrationError(
                    "Live migration was not submitted: continuity could not be established: "
                    + str(continuity.get("reason") or "missing readiness evidence")
                )
            endpoint.metadata["_live_continuity_state"] = continuity
        inject_failure(self.config, "before-live-migration")
        storage_args = self._live_migration_storage_args()
        configured_storage_mode = str(self.config.migration_storage or "auto")
        storage_mode = str(self.config.effective_migration_storage or "auto")
        self.logger.log(
            f"Live-migrating {endpoint.label} from {source_host} to {target.host}; "
            f"availability_zone={source_az}; storage_mode={storage_mode}; "
            f"configured_storage_mode={configured_storage_mode}; "
            f"boot_storage={self.config.storage}"
        )
        command = list(
            self._migration_command_args(
                endpoint.server_id,
                "server",
                "migrate",
                "--live-migration",
                "--host",
                target.host,
                *storage_args,
                "--wait",
                endpoint.server_id,
            )
        )
        if stationary_peer is not None and not self._mark_live_continuity_phase(
            stationary_peer, continuity, "migration_submitted"
        ):
            raise UnverifiableMigrationError(
                "Live migration was not submitted: phase timestamp unavailable"
            )
        request = None
        request_error: str | None = None
        try:
            request = self.osc.run(
                *command,
                check=False,
                timeout=self.config.resource_timeout,
            )
        except CommandTimeoutError as exc:
            request_error = str(exc)
            self.logger.log(
                f"Live migration command timed out locally for {endpoint.label}; reconciling Nova state",
                "WARNING",
            )
        if request is not None and request.returncode != 0:
            request_error = (request.stderr or request.stdout).strip()
            lowered = request_error.lower()
            unavailable_markers = (
                "no valid host",
                "not supported",
                "microversion",
                "policy doesn't allow",
                "forbidden",
                "http 403",
                "live migration is not permitted",
                "cannot live migrate",
            )
            if (
                any(marker in lowered for marker in unavailable_markers)
                and self._current_command_was_rejected()
            ):
                raise PlacementUnavailableError(
                    f"Nova could not provide targeted live migration coverage: {request_error}",
                    # A live-only capability/policy rejection says nothing
                    # about this host's suitability for a cold migration.
                    target_unsuitable="no valid host" in lowered,
                )
            if self._migration_request_error_is_transient(request_error):
                self.logger.log(
                    f"Live migration client returned a transient error for "
                    f"{endpoint.label}; reconciling Nova state before classifying "
                    f"the attempt: {request_error}",
                    "WARNING",
                )
            else:
                raise SuiteError(
                    f"Nova rejected live migration of {endpoint.label}: {request_error}"
                )
        if request_error:
            self._wait_for_migration_acceptance(endpoint, target.host, before)
        inject_failure(self.config, "after-live-request")

        try:
            server_detail = self._wait_for_live_destination(endpoint, target.host)
            if getattr(self, "lifecycle_settlement_enabled", False):
                server_detail = self._wait_for_server_settlement(
                    endpoint.server_id,
                    [
                        endpoint.management_port_id,
                        endpoint.test_port_id or "",
                    ],
                    expected_statuses={"active"},
                    expected_host=target.host,
                    display_name=endpoint.server_name,
                    stable_observations=3,
                    require_power_state=True,
                )
        except RunCancelledError:
            raise
        except SuiteError as exc:
            if request_error:
                raise SuiteError(
                    f"Live migration client error was {request_error!r}; Nova state "
                    f"did not reconcile on {target.host}: {exc}"
                ) from exc
            raise
        inject_failure(self.config, "after-live-handoff")
        destination_host = str(
            pick(server_detail, "os_ext_srv_attr_host", "host", default="") or ""
        )
        reported_destination_az = (
            str(
                pick(
                    server_detail,
                    "os_ext_az_availability_zone",
                    "availability_zone",
                    default="",
                )
                or ""
            )
            or None
        )
        destination_az = reported_destination_az or target_az
        destination_az_source = (
            "server-show" if reported_destination_az else "target-host-inventory"
        )
        task_state_cleared = nova_task_state_cleared(server_detail)
        if destination_host != target.host:
            raise SuiteError(
                f"Nova reported live migration complete but {endpoint.label} is on "
                f"{destination_host or 'unknown'}, not requested host {target.host}"
            )
        if destination_az != source_az:
            raise SuiteError(
                f"Live migration changed availability zone for {endpoint.label}: "
                f"{source_az} -> {destination_az}"
            )

        if stationary_peer is not None:
            self._mark_live_continuity_phase(
                stationary_peer, continuity, "placement_verified"
            )
        migration_record_verified, migration_record_error, migration_record = (
            self._verify_nova_migration_record(
                endpoint,
                source_host,
                target.host,
                before.get("migration_ids"),
                expected_types=self._LIVE_TYPES,
                migration_label="live migration",
            )
        )
        try:
            port_binding_verified, port_details = self._verify_migrated_ports(
                endpoint, target.host, before
            )
            port_validation_error = None
        except RunCancelledError:
            raise
        except SuiteError as exc:
            port_binding_verified = False
            port_details = getattr(exc, "ports", {})
            port_validation_error = str(exc)

        volume_detail: dict[str, Any] = {}
        volume_validation_error: str | None = None
        if self.config.storage == "host":
            after_volumes: set[str] | None = set()
            volume_attachment_verified: bool | None = True
        else:
            after_volumes = self._server_volume_ids(endpoint.server_id)
            if before["volume_ids"] is not None and after_volumes is not None:
                volume_attachment_verified = before["volume_ids"] == after_volumes
                if not volume_attachment_verified:
                    volume_validation_error = (
                        f"Volume attachments changed during live migration of {endpoint.label}: "
                        f"before={sorted(before['volume_ids'])}, after={sorted(after_volumes)}"
                    )
                else:
                    (
                        volume_attachment_verified,
                        volume_validation_error,
                        volume_detail,
                    ) = self._migration_volume_evidence(
                        endpoint, before["volume_ids"], after_volumes
                    )
            elif endpoint.volume_id:
                (
                    volume_attachment_verified,
                    volume_validation_error,
                    volume_detail,
                ) = self._verify_expected_volume_attachment(
                    endpoint.volume_id, endpoint.server_id
                )
            else:
                volume_attachment_verified = None
                volume_validation_error = "Volume attachment inventory was unavailable"

        endpoint.host = destination_host
        endpoint.availability_zone = destination_az
        continuity_result = (
            self._stop_live_continuity(stationary_peer, continuity)
            if stationary_peer is not None
            else continuity
        )
        endpoint.metadata.pop("_live_continuity_state", None)
        endpoint_ready = self._wait_for_ssh(
            endpoint.management_ip,
            proxy=True,
            timeout=self.config.convergence_timeout,
        )
        endpoint_recovery_error: str | None = None
        guest_marker = before.get("guest_marker")
        if endpoint_ready and guest_marker:
            guest_marker_verified, guest_marker_error = (
                self._verify_guest_migration_marker(endpoint, guest_marker)
            )
        else:
            guest_marker_verified = None
            guest_marker_error = (
                None
                if not guest_marker
                else "The migrated endpoint did not regain SSH for marker validation"
            )
        if endpoint_ready and guest_marker_verified is not False:
            try:
                try:
                    self.reconfigure_endpoint(endpoint, reuse_probe=True)
                except TypeError as exc:
                    if "reuse_probe" not in str(exc):
                        raise
                    self.reconfigure_endpoint(endpoint)
            except RunCancelledError:
                raise
            except SuiteError as exc:
                endpoint_ready = False
                endpoint_recovery_error = str(exc)
        elif not endpoint_ready:
            endpoint_recovery_error = f"Live-migrated endpoint {endpoint.label} did not regain SSH reachability"
        elif guest_marker_verified is False:
            endpoint_ready = False
            endpoint_recovery_error = guest_marker_error

        completion_evidence = {
            "server_id": endpoint.server_id,
            "source_host": source_host,
            "destination_host": destination_host,
            "source_availability_zone": source_az,
            "destination_availability_zone": destination_az,
            "task_state_cleared": task_state_cleared,
            "migration_record_verified": migration_record_verified,
            "migration_record_error": migration_record_error,
            "port_binding_verified": port_binding_verified,
            "volume_attachment_verified": volume_attachment_verified,
            "guest_marker_verified": guest_marker_verified,
            "endpoint_ready": endpoint_ready,
        }
        completion_evidence = self._migration_operation_evidence(
            endpoint,
            target.host,
            before,
            completion_evidence,
            port_details,
            server_detail,
            migration_type="live",
        )
        completion = migration_completion(completion_evidence)
        settlement = migration_operation_settlement(completion_evidence)
        continuity_result = {
            **continuity_result,
            "migration_succeeded": completion["verified"],
            "migration_completion_evidence": completion_evidence,
            "completion_assessment": completion,
            "operation_settlement_assessment": settlement,
        }

        history = endpoint.metadata.setdefault("migration_history", [])
        history.append(
            {
                "migration_mode": "live",
                "migration_storage": storage_mode,
                "configured_migration_storage": configured_storage_mode,
                "source_host": source_host,
                "destination_host": destination_host,
                "availability_zone": destination_az,
                "availability_zone_source": destination_az_source,
                "migration_record_verified": migration_record_verified,
                "migration_record_error": migration_record_error,
                "volume_attachment_verified": volume_attachment_verified,
                "volume_validation_error": volume_validation_error,
                "guest_marker_verified": guest_marker_verified,
                "guest_marker_error": guest_marker_error,
                "port_binding_verified": port_binding_verified,
                "port_validation_error": port_validation_error,
                "endpoint_ready": endpoint_ready,
                "endpoint_recovery_error": endpoint_recovery_error,
                "continuity_available": bool(continuity_result.get("available")),
                "continuity_health": continuity_result.get("health"),
            }
        )
        details = {
            "migration_mode": "live",
            "completion_assessment": completion,
            "operation_settlement_assessment": settlement,
            "recovery_retry": bool(retry),
            "migration_storage": storage_mode,
            "configured_migration_storage": configured_storage_mode,
            "request_error": request_error,
            "destination_availability_zone_source": destination_az_source,
            "continuity": continuity_result,
            "ports": port_details,
            "volume_ids_before": sorted(before["volume_ids"] or []),
            "volume_ids_after": sorted(after_volumes or []),
            "migration_record": migration_record,
            "root_volume_detail": volume_detail,
            "migration_inventory_error_before": before.get("migration_inventory_error"),
            "guest_marker_path": (before.get("guest_marker") or {}).get("path"),
        }
        self._mark_current_migration_succeeded(completion_evidence)
        self.reporter.event(
            "live-migration-complete"
            if completion["verified"] is True
            else "live-migration-assessed",
            (
                f"Live migration completed for {endpoint.label}"
                if completion["verified"] is True
                else f"Live migration handoff observed for {endpoint.label}; completion {completion['status']}"
            ),
            completion_assessment=completion,
            operation_settlement_assessment=settlement,
            server_id=endpoint.server_id,
            source_host=source_host,
            destination_host=destination_host,
            availability_zone=destination_az,
            availability_zone_source=destination_az_source,
            storage_mode=storage_mode,
            continuity=continuity_result,
            migration_record_verified=migration_record_verified,
            migration_record_error=migration_record_error,
            volume_attachment_verified=volume_attachment_verified,
            volume_validation_error=volume_validation_error,
            guest_marker_verified=guest_marker_verified,
            guest_marker_error=guest_marker_error,
            port_binding_verified=port_binding_verified,
            port_validation_error=port_validation_error,
            endpoint_ready=endpoint_ready,
            endpoint_recovery_error=endpoint_recovery_error,
        )
        endpoint.metadata.pop("_migration_attempt_baseline", None)
        return MigrationResult(
            server_id=endpoint.server_id,
            source_host=source_host,
            destination_host=destination_host,
            source_availability_zone=source_az,
            destination_availability_zone=destination_az,
            confirmed=True,
            automatically_confirmed=False,
            port_binding_verified=port_binding_verified,
            migration_record_verified=migration_record_verified,
            migration_record_error=migration_record_error,
            task_state_cleared=task_state_cleared,
            volume_attachment_verified=volume_attachment_verified,
            volume_validation_error=volume_validation_error,
            guest_marker_verified=guest_marker_verified,
            guest_marker_error=guest_marker_error,
            port_validation_error=port_validation_error,
            endpoint_ready=endpoint_ready,
            endpoint_recovery_error=endpoint_recovery_error,
            details=details,
        )

    @serialized_lifecycle
    def live_migrate_endpoint(
        self,
        endpoint: Endpoint,
        target: ComputeHostInfo,
        stationary_peer: Endpoint | None = None,
    ) -> MigrationResult:
        """Run one live migration and permit retries only after safe recovery."""
        original_host = endpoint.host
        original_az = endpoint.availability_zone
        if not original_host:
            raise PlacementUnavailableError(
                f"Nova did not expose the source compute host for {endpoint.label}"
            )
        try:
            return self._live_migrate_endpoint_once(endpoint, target, stationary_peer)
        except (RetryableMigrationError, UnsafeMigrationStateError):
            raise
        except RunCancelledError:
            before = endpoint.metadata.pop("_migration_attempt_baseline", None)
            with cancellation_reconciliation():
                proven, evidence = self._authoritative_migration_failure(
                    endpoint, before
                )
                recovered, reason = self._recover_endpoint_after_failed_migration(
                    endpoint, original_host, original_az, before
                )
                if proven and recovered:
                    self._mark_current_migration_failed_final(
                        {**evidence, "recovery": reason}
                    )
                else:
                    self.logger.log(
                        "Cancellation reconciliation could not prove the live "
                        "migration terminal and safe; its journal entry remains "
                        "ambiguous and cleanup will skip the endpoint",
                        "WARNING",
                    )
            raise
        except UnverifiableMigrationError:
            raise
        except PlacementUnavailableError as exc:
            before = endpoint.metadata.pop("_migration_attempt_baseline", None)
            recovered, reason = self._recover_endpoint_after_failed_migration(
                endpoint, original_host, original_az, before
            )
            if recovered:
                raise RetryableMigrationError(
                    f"{exc}; {reason}",
                    unavailable=True,
                    proven_failure=True,
                    accepted=False,
                    target_unsuitable=exc.target_unsuitable,
                    evidence={"command_rejected": True},
                ) from exc
            raise UnsafeMigrationStateError(
                f"{exc}; live migration retries stopped because {reason}"
            ) from exc
        except SuiteError as exc:
            before = endpoint.metadata.pop("_migration_attempt_baseline", None)
            command_rejected = self._current_command_was_rejected()
            proven_failure, evidence = (
                (True, {"command_rejected": True})
                if command_rejected
                else self._authoritative_migration_failure(endpoint, before)
            )
            if (
                proven_failure
                and not command_rejected
                and before
                and before.get("live_action_ids") is not None
                and self._live_retry_has_down_ports(endpoint)
            ):
                try:
                    next_baseline, recovery = self._prepare_live_retry(
                        endpoint, target.host, before
                    )
                except RunCancelledError:
                    raise
                except SuiteError as recovery_error:
                    raise UnsafeMigrationStateError(
                        f"{exc}; live retries stopped because {recovery_error}"
                    ) from exc
                evidence = {**evidence, **recovery}
                endpoint.metadata[self._LIVE_RETRY_KEY] = {
                    "target_host": target.host,
                    "failed_baseline": before,
                    "next_baseline": next_baseline,
                }
                self._mark_current_migration_failed_retryable(evidence)
                raise RetryableMigrationError(
                    f"{exc}; destination rollback and stable source ownership verified; "
                    "another live attempt is permitted without claiming network recovery",
                    proven_failure=True,
                    accepted=True,
                    evidence=evidence,
                ) from exc
            recovered, reason = self._recover_endpoint_after_failed_migration(
                endpoint, original_host, original_az, before
            )
            if recovered and proven_failure:
                if not command_rejected:
                    self._mark_current_migration_failed_retryable(evidence)
                raise RetryableMigrationError(
                    f"{exc}; {reason}",
                    unavailable=False,
                    proven_failure=True,
                    accepted=False if command_rejected else True,
                    evidence=evidence,
                ) from exc
            if recovered and not proven_failure:
                raise UnsafeMigrationStateError(
                    f"{exc}; the endpoint recovered, but that does not prove "
                    "the migration request failed. The submission remains "
                    f"AMBIGUOUS and no retry or cleanup is permitted: "
                    f"{evidence.get('reason', 'no terminal failure evidence')}"
                ) from exc
            raise UnsafeMigrationStateError(
                f"{exc}; live migration retries stopped because {reason}"
            ) from exc
        finally:
            state = endpoint.metadata.pop("_live_continuity_state", None)
            if state and stationary_peer is not None:
                try:
                    self._stop_live_continuity(stationary_peer, state)
                except RunCancelledError:
                    raise
                except SuiteError as exc:
                    self.logger.log(
                        f"Could not clean up live-migration continuity monitor for "
                        f"{endpoint.label}: {exc}",
                        "WARNING",
                    )


__all__ = ["LiveMigrationRuntimeMixin"]
