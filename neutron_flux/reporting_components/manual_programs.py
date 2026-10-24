"""Build a portable manual helper from the production wire-protocol programs.

The downloaded file uses only Python's standard library. Generation is lazy:
the performance runner imports reporting while its own module is loading.
"""

from __future__ import annotations

import json


def manual_helper_source() -> str:
    from ..icmp_attestation import observer_code
    from ..measurement_programs import tcp_client_code, udp_client_code
    from ..models import Endpoint
    from ..mtu_probes import performance_probe_code
    from ..probe_service import ProbeServiceManager
    from ..probes import TCPProbe

    endpoint = Endpoint(
        label="manual responder",
        server_id="__NF_ID__",
        server_name="manual",
        management_port_id="",
        management_ip="127.0.0.1",
        test_port_id=None,
        test_mac="__NF_MAC__",
        fixed_ips={"v4": "127.0.0.1", "v6": "::1"},
        host=None,
        availability_zone=None,
        volume_id=None,
    )
    manager = ProbeServiceManager(61501, 61502)
    manager.set_control_ports({4: 61503, 6: 61503})
    server = (
        manager._server_code(endpoint)
        .replace(
            "FAMILIES = [socket.AF_INET,socket.AF_INET6]", "FAMILIES = [__NF_AF__]"
        )
        .replace(
            "return '::' if family == socket.AF_INET6 else '0.0.0.0'",
            "return __NF_BIND__",
        )
    )
    programs = {
        "server": server,
        "tcp": TCPProbe._attempt_code(
            "__NF_SOURCE__", "__NF_DEST__", 8675309, 61501, "__NF_TOKEN__"
        ),
        "peer-tcp": TCPProbe._peer_identity_attempt_code(
            "__NF_SOURCE__", "__NF_DEST__", 8675309, 61501, "__NF_TOKEN__"
        ),
        "peer-udp": TCPProbe._peer_identity_attempt_code(
            "__NF_SOURCE__",
            "__NF_DEST__",
            8675309,
            61501,
            "__NF_TOKEN__",
            datagram=True,
        ),
        "perf-tcp": tcp_client_code(
            "__NF_SOURCE__", "__NF_DEST__", 8675309, 61501, 8675310, 8675311
        ),
        "perf-udp": udp_client_code(
            "__NF_SOURCE__", "__NF_DEST__", 8675309, 61501, 8675310, 8675312, 8675313
        ),
        "mtu": performance_probe_code("__NF_SOURCE__", "__NF_DEST__", 8675309, 8675314),
        "icmp": observer_code(endpoint, "127.0.0.1", "__NF_TOKEN__")
        .replace("FIXED='127.0.0.1'", "FIXED=__NF_BIND__")
        .replace("+15.0", "+__NF_TIMEOUT__"),
    }
    return "#!/usr/bin/env python3\n" + _RUNTIME.replace(
        "__PROGRAMS_JSON__", repr(json.dumps(programs))
    )


_RUNTIME = r'''
"""Neutron Flux manual probes. Python 3 and Linux; no Flux installation needed.

Run responders in separate guest terminals; wait for their READY line before
starting a client. Responders are temporary and end after --lifetime or Ctrl-C.
The helper does not create cloud resources or change guest networking.
"""
import argparse
import ipaddress
import json
import pathlib
import re
import subprocess
import sys

PROGRAMS = json.loads(__PROGRAMS_JSON__)


def ip(value):
    return str(ipaddress.ip_address(value))


def positive(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError('must be a positive integer')
    return number


def port(value):
    number = positive(value)
    if number > 65535:
        raise argparse.ArgumentTypeError('port must be at most 65535')
    return number


def require(condition, message):
    if not condition:
        raise ValueError(message)


def selected_interface(source, destination=None, mac=None):
    if not mac:
        return
    require(bool(re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', mac)), 'invalid data MAC')
    result = subprocess.run(
        ['ip', '-j', '-' + str(ipaddress.ip_address(source).version), 'route', 'get', destination or source, 'from', source],
        text=True, capture_output=True, timeout=10, check=True,
    )
    routes = json.loads(result.stdout)
    device = routes[0].get('dev') if isinstance(routes, list) and routes else None
    require(isinstance(device, str) and '/' not in device, 'selected route has no valid interface')
    actual = pathlib.Path('/sys/class/net', device, 'address').read_text().strip().lower()
    require(actual == mac.lower(), 'route selects ' + device + ' with MAC ' + actual + ', expected ' + mac)


def program(name, args):
    replacements = {
        repr('__NF_SOURCE__'): repr(getattr(args, 'source', '')),
        repr('__NF_DEST__'): repr(getattr(args, 'destination', '')),
        repr('__NF_TOKEN__'): repr(getattr(args, 'token', '')),
        '"__NF_ID__"': repr(getattr(args, 'probe_id', '')),
        repr('__NF_ID__'): repr(getattr(args, 'probe_id', '')),
        repr('__NF_MAC__'): repr((getattr(args, 'data_mac', '') or '').lower()),
        repr('__nf_mac__'): repr((getattr(args, 'data_mac', '') or '').lower()),
        '__NF_BIND__': repr(getattr(args, 'bind', getattr(args, 'local_ip', ''))),
        '__NF_TIMEOUT__': str(getattr(args, 'timeout', 30)),
        '__NF_AF__': 'socket.AF_INET6' if getattr(args, 'bind', '').find(':') >= 0 else 'socket.AF_INET',
        '8675309': str(ipaddress.ip_address(getattr(args, 'source', '127.0.0.1')).version),
        '8675310': repr(getattr(args, 'duration', 3.0)),
        '8675311': str(getattr(args, 'streams', 1)),
        '8675312': str(getattr(args, 'rate_mbps', 10)),
        '8675313': str(getattr(args, 'packet_size', 1200)),
        '8675314': str(getattr(args, 'mtu', 1500)),
        '61501': str(getattr(args, 'tcp_port', getattr(args, 'port', 61501))),
        '61502': str(getattr(args, 'udp_port', 61502)),
        '61503': str(getattr(args, 'control_port', 61503)),
    }
    pattern = '|'.join(re.escape(key) for key in sorted(replacements, key=len, reverse=True))
    return re.sub(pattern, lambda match: replacements[match.group(0)], PROGRAMS[name])


def run_code(code, timeout):
    result = subprocess.run([sys.executable, '-u', '-c', code], text=True, capture_output=True, timeout=timeout, check=False)
    if result.stdout:
        print(result.stdout, end='', flush=True)
    if result.stderr:
        print(result.stderr, end='', file=sys.stderr, flush=True)
    require(result.returncode == 0, 'probe process failed with exit status ' + str(result.returncode))
    return result.stdout


def peer(args):
    text = run_code(program('peer-' + args.protocol, args), 15)
    prefix = 'NFLUX_' + args.protocol.upper() + '_PEER '
    lines = [line[len(prefix):] for line in text.splitlines() if line.startswith(prefix)]
    require(bool(lines), 'peer result missing')
    data = json.loads(lines[-1])
    require(data.get('response_validated') is True, 'peer response was not validated')
    if args.expected_probe_id:
        require(data.get('observer_probe_id') == args.expected_probe_id, 'destination responder identity mismatch')
    if args.expected_peer_ip:
        require(ip(data.get('observed_peer_ip')) == args.expected_peer_ip, 'observed source/NAT address mismatch')
    return data


def serve(args):
    require(args.control_port != args.tcp_port, 'control port must differ from TCP port')
    if args.data_mac:
        links = list(pathlib.Path('/sys/class/net').glob('*/address'))
        require(any(path.read_text().strip().lower() == args.data_mac.lower() for path in links), 'responder data MAC was not found')
    child = subprocess.Popen([sys.executable, '-u', '-c', program('server', args)])
    try:
        child.wait(timeout=args.lifetime)
        require(child.returncode == 0, 'responder exited with status ' + str(child.returncode))
    except subprocess.TimeoutExpired:
        print('NEUTRON_FLUX_STOPPED lifetime reached', flush=True)
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)


def assess_mtu(data):
    confirmed = data.get('reachable') is True and data.get('boundary_confirmed') is True
    observation = confirmed and (
        data.get('discovered_mtu') < data.get('expected_mtu')
        or data.get('above_expected_reachable') is True
    )
    return {
        'outcome': 'PASS_WITH_OBSERVATION' if observation else 'PASS' if confirmed else 'UNVERIFIED',
        'confirmed_mtu': data.get('discovered_mtu') if confirmed else None,
        'expected_mtu': data.get('expected_mtu'),
        'reason': data.get('discovery_reason'),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest='action', required=True)
    server = subs.add_parser('probe-server', help='temporary matching TCP/UDP/performance responder')
    server.add_argument('--bind', type=ip, required=True)
    server.add_argument('--probe-id', required=True)
    server.add_argument('--tcp-port', type=port, required=True)
    server.add_argument('--udp-port', type=port, required=True)
    server.add_argument('--control-port', type=port)
    server.add_argument('--data-mac')
    server.add_argument('--lifetime', type=positive, default=3600)
    client = subs.add_parser('probe-client', help='functional echo or verified peer/NAT observation')
    perf = subs.add_parser('perf-client', help='one recorded TCP or UDP measurement profile')
    mtu = subs.add_parser('mtu-client', help='production no-fragment path-MTU boundary probe')
    for command in (client, perf, mtu):
        command.add_argument('--source', type=ip, required=True)
        command.add_argument('--destination', type=ip, required=True)
        command.add_argument('--data-mac')
    for command in (client, perf):
        command.add_argument('--protocol', choices=('tcp', 'udp', 'icmp') if command is client else ('tcp', 'udp'), required=True)
        command.add_argument('--port', type=port)
        command.add_argument('--expected-probe-id')
        command.add_argument('--expected-peer-ip', type=ip)
        command.add_argument('--token', default='neutron-flux-manual-check')
    perf.add_argument('--duration', type=float, default=3.0)
    perf.add_argument('--streams', type=positive, default=1)
    perf.add_argument('--repeats', type=positive, default=1)
    perf.add_argument('--rate-mbps', type=positive, default=10)
    perf.add_argument('--packet-size', type=positive, default=1200)
    mtu.add_argument('--mtu', type=positive, required=True)
    observer = subs.add_parser('icmp-observer', help='IPv4 NAT request capture; root/CAP_NET_RAW required')
    observer.add_argument('--local-ip', type=ip, required=True)
    observer.add_argument('--data-mac', required=True)
    observer.add_argument('--probe-id', required=True)
    observer.add_argument('--token', required=True)
    observer.add_argument('--timeout', type=positive, default=30)
    observer.add_argument('--expected-peer-ip', type=ip)
    args = parser.parse_args()
    if args.action == 'probe-server':
        args.control_port = args.control_port or args.tcp_port + 2
        require(args.control_port <= 65535, 'choose --control-port below 65536')
        return serve(args)
    if args.action == 'icmp-observer':
        require(ipaddress.ip_address(args.local_ip).version == 4, 'ICMP NAT observer currently supports IPv4')
        require(bool(re.fullmatch(r'[0-9a-fA-F]{32}', args.token)), 'ICMP token must be 32 hexadecimal characters')
        args.token = args.token.lower()
        code = program('icmp', args) + "\nif len(records) < 3:\n    raise ValueError('three matching ICMP requests were not observed')\n"
        if args.expected_peer_ip:
            code += "\nif not all(item['peer_ip'] == " + repr(args.expected_peer_ip) + " for item in records):\n    raise ValueError('observed ICMP source/NAT address mismatch')\n"
        observed = subprocess.run([sys.executable, '-u', '-c', code], timeout=args.timeout + 5, check=False)
        require(observed.returncode == 0, 'ICMP observer failed; inspect its error above (root or CAP_NET_RAW is required)')
        return
    require(ipaddress.ip_address(args.source).version == ipaddress.ip_address(args.destination).version, 'source and destination address families differ')
    selected_interface(args.source, args.destination, args.data_mac)
    if args.action == 'mtu-client':
        require(68 <= args.mtu <= 65535, 'invalid advertised MTU')
        text = run_code(program('mtu', args), 180)
        assessment = assess_mtu(json.loads(text.strip().splitlines()[-1]))
        print('NEUTRON_FLUX_MANUAL_RESULT ' + json.dumps(assessment), flush=True)
        require(assessment['outcome'] != 'UNVERIFIED', 'MTU boundary remains unverified; inspect raw evidence above')
        return
    require('\n' not in args.token and '\r' not in args.token and bool(args.token), 'token must be nonempty and contain no newline')
    if args.protocol == 'icmp':
        require(bool(re.fullmatch(r'[0-9a-fA-F]{32}', args.token)), 'ICMP token must match observer: 32 hex characters')
        result = subprocess.run(['ping', '-' + str(ipaddress.ip_address(args.source).version), '-n', '-c', '3', '-W', '2', '-I', args.source, '-p', args.token, args.destination], check=False)
        require(result.returncode == 0, 'ICMP ping failed')
        return
    require(args.port is not None, '--port is required for TCP/UDP')
    if args.action == 'probe-client':
        if args.protocol == 'udp' or args.expected_probe_id or args.expected_peer_ip:
            peer(args)
        else:
            run_code(program('tcp', args), 15)
        return
    require(0.25 <= args.duration <= 60 and args.streams <= 64 and args.repeats <= 20, 'duration must be 0.25–60 seconds; streams <=64; repeats <=20')
    require(24 <= args.packet_size <= 65507, 'UDP datagram size must be 24–65507 bytes')
    peer(args)
    results = []
    for _ in range(args.repeats):
        text = run_code(program('perf-' + args.protocol, args), args.duration + 35)
        data = json.loads(text.strip().splitlines()[-1])
        if args.protocol == 'udp' and data.get('packet_size_supported') is False:
            print('NEUTRON_FLUX_MANUAL_RESULT ' + json.dumps({
                'outcome': 'UNVERIFIED',
                'reason': 'The guest rejected the requested UDP packet size; this profile did not complete. Review the recorded path MTU before selecting a smaller profile.',
                'protocol': args.protocol, 'repeats': len(results) + 1,
                'samples': results + [data],
            }), flush=True)
            raise SystemExit(2)
        if args.expected_peer_ip:
            addresses = data.get('peer_ips') or [data.get('peer_ip')]
            require(bool(addresses) and all(ip(address) == args.expected_peer_ip for address in addresses), 'measurement observed source/NAT address mismatch')
        if args.protocol == 'udp':
            require(data.get('received', 0) > 0, 'receiver acknowledged no UDP delivery')
        results.append(data)
    print('NEUTRON_FLUX_MANUAL_RESULT ' + json.dumps({'protocol': args.protocol, 'repeats': len(results), 'samples': results}), flush=True)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except (OSError, ValueError, KeyError, IndexError, TypeError, subprocess.SubprocessError) as error:
        print('NEUTRON_FLUX_MANUAL_ERROR ' + type(error).__name__ + ': ' + str(error), file=sys.stderr)
        sys.exit(1)
'''
