from __future__ import annotations

import json
import textwrap
from typing import Any

BOUNDARY_RESULT_MARKER = "NEUTRON_FLUX_MTU_RESULT="


def _remote_helpers() -> str:
    return r"""
import re


def run_command(command):
    environment = os.environ.copy()
    environment['LC_ALL'] = 'C'
    environment['LANG'] = 'C'
    try:
        result = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=environment,
        )
    except FileNotFoundError as exc:
        return {
            'command': command,
            'returncode': 127,
            'stdout': '',
            'stderr': str(exc),
        }
    return {
        'command': command,
        'returncode': int(result.returncode),
        'stdout': result.stdout or '',
        'stderr': result.stderr or '',
    }


def combined_text(result):
    return (str(result.get('stdout') or '') + '\n' + str(result.get('stderr') or '')).strip()


def local_mtu_rejection(result):
    text = combined_text(result).lower()
    return any(marker in text for marker in (
        'message too long',
        'errno 90',
        'emsgsize',
    ))


def unsupported_ping_option(result):
    text = combined_text(result).lower()
    return any(marker in text for marker in (
        'invalid option',
        'illegal option',
        'unknown option',
        'unrecognized option',
        'invalid argument',
        'usage:',
    ))


def no_reply(result):
    text = combined_text(result).lower()
    return (
        int(result.get('returncode') or 0) != 0
        and (
            '100% packet loss' in text
            or (' packets transmitted' in text and ' received' in text)
            or 'destination host unreachable' in text
            or 'destination unreachable' in text
            or 'no route to host' in text
            or 'network is unreachable' in text
            or 'timed out' in text
            or 'timeout' in text
        )
    )


def packet_too_big_feedback(result):
    # Require an ICMP response line, not the local sendmsg/EMSGSIZE diagnostic.
    responses = []
    for line in str(result.get('stdout') or '').splitlines():
        match = re.search(
            r'^From\s+(\S+).*?(?:Frag needed and DF set|Packet too big)'
            r'.*?mtu\s*[=:]?\s*(\d+)', line, re.IGNORECASE,
        )
        if match and 0 < int(match.group(2)) <= 65535:
            responses.append({
                'responder': match.group(1),
                'mtu': int(match.group(2)),
                'output': line,
            })
    return responses


def classify_ping(result):
    feedback = packet_too_big_feedback(result)
    if int(result.get('returncode') or 0) == 0:
        return 'mixed' if feedback else 'success'
    if feedback:
        return 'packet-too-big'
    if local_mtu_rejection(result):
        return 'local-mtu-rejected'
    if unsupported_ping_option(result):
        return 'unsupported'
    if no_reply(result):
        return 'no-reply'
    return 'error'


def compact_result(result):
    return {
        'returncode': int(result.get('returncode') or 0),
        'stdout': str(result.get('stdout') or '')[-700:],
        'stderr': str(result.get('stderr') or '')[-700:],
        'packet_too_big_feedback': packet_too_big_feedback(result),
    }


def local_mtu_evidence():
    evidence = {
        'source_ip': SOURCE,
        'destination_ip': DESTINATION,
        'selected_interface': None,
        'source_interface_mtu': None,
        'route_mtu': None,
        'route_mtu_source': None,
        'route': None,
        'link': None,
        'address': None,
        'errors': [],
    }
    route_command = [
        'ip', '-6' if FAMILY == 6 else '-4', '-j', 'route', 'get',
        DESTINATION, 'from', SOURCE,
    ]
    route_result = run_command(route_command)
    try:
        route_rows = json.loads(route_result['stdout']) if route_result['returncode'] == 0 else []
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        route_rows = []
        evidence['errors'].append('route JSON parse failed: ' + str(exc))
    route = route_rows[0] if isinstance(route_rows, list) and route_rows else None
    if isinstance(route, dict):
        evidence['route'] = route
        evidence['selected_interface'] = route.get('dev')
        route_mtu = route.get('mtu')
        route_mtu_source = 'route.mtu' if route_mtu not in (None, '') else None
        if route_mtu in (None, ''):
            metrics = route.get('metrics')
            metric_rows = metrics if isinstance(metrics, list) else [metrics]
            for index, metric in enumerate(metric_rows):
                if isinstance(metric, dict) and metric.get('mtu') not in (None, ''):
                    route_mtu = metric.get('mtu')
                    route_mtu_source = 'route.metrics[' + str(index) + '].mtu'
                    break
        if route_mtu not in (None, ''):
            try:
                evidence['route_mtu'] = int(route_mtu)
                evidence['route_mtu_source'] = route_mtu_source
            except (TypeError, ValueError):
                evidence['errors'].append('route MTU was not an integer: ' + repr(route_mtu))
    elif route_result['returncode'] != 0:
        evidence['errors'].append('route inspection failed: ' + combined_text(route_result)[-400:])

    interface = evidence.get('selected_interface')
    if interface:
        link_result = run_command(['ip', '-j', 'link', 'show', 'dev', str(interface)])
        address_result = run_command(['ip', '-j', 'address', 'show', 'dev', str(interface)])
        try:
            links = json.loads(link_result['stdout']) if link_result['returncode'] == 0 else []
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            links = []
            evidence['errors'].append('link JSON parse failed: ' + str(exc))
        try:
            addresses = json.loads(address_result['stdout']) if address_result['returncode'] == 0 else []
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            addresses = []
            evidence['errors'].append('address JSON parse failed: ' + str(exc))
        link = links[0] if isinstance(links, list) and links else None
        address = addresses[0] if isinstance(addresses, list) and addresses else None
        evidence['link'] = link
        evidence['address'] = address
        if isinstance(link, dict) and link.get('mtu') not in (None, ''):
            try:
                evidence['source_interface_mtu'] = int(link['mtu'])
            except (TypeError, ValueError):
                evidence['errors'].append('interface MTU was not an integer: ' + repr(link.get('mtu')))
        if evidence['source_interface_mtu'] is None:
            try:
                with open('/sys/class/net/' + str(interface) + '/mtu', encoding='ascii') as handle:
                    evidence['source_interface_mtu'] = int(handle.read().strip())
            except (OSError, ValueError) as exc:
                evidence['errors'].append('sysfs MTU read failed: ' + str(exc))
    return evidence
"""


def _remote_fragment_counter_helpers() -> str:
    return r"""
def read_fragment_counters(family):
    source = '/proc/net/snmp' if family == 4 else '/proc/net/snmp6'
    try:
        if family == 4:
            with open(source, encoding='ascii') as handle:
                lines = [line.split() for line in handle if line.startswith('Ip:')]
            if len(lines) < 2:
                raise ValueError('IPv4 Ip rows were absent')
            raw = dict(zip(lines[-2][1:], lines[-1][1:]))
            names = (
                'FragCreates', 'FragOKs', 'FragFails',
                'ReasmReqds', 'ReasmOKs', 'ReasmFails',
            )
        else:
            raw = {}
            with open(source, encoding='ascii') as handle:
                for line in handle:
                    parts = line.split()
                    if len(parts) == 2:
                        raw[parts[0]] = parts[1]
            names = (
                'Ip6FragCreates', 'Ip6FragOKs', 'Ip6FragFails',
                'Ip6ReasmReqds', 'Ip6ReasmOKs', 'Ip6ReasmFails',
            )
        return {
            'family': int(family),
            'available': True,
            'source': source,
            'counters': {name: int(raw.get(name, 0)) for name in names},
            'error': None,
        }
    except (OSError, ValueError, TypeError) as exc:
        return {
            'family': int(family),
            'available': False,
            'source': source,
            'counters': {},
            'error': str(exc),
        }


def counter_delta(before, after):
    if not before.get('available') or not after.get('available'):
        return {}
    start = before.get('counters') or {}
    end = after.get('counters') or {}
    return {
        key: max(0, int(end.get(key, 0)) - int(start.get(key, 0)))
        for key in sorted(set(start) | set(end))
    }
"""


def fragment_counter_probe_code(family: int) -> str:
    """Return a read-only guest fragment/reassembly counter probe."""
    template = f"""
import json

FAMILY = {family}

{_remote_fragment_counter_helpers()}

print(json.dumps(read_fragment_counters(FAMILY), separators=(',', ':')))
"""
    return textwrap.dedent(template)


def boundary_probe_code(
    source_ip: str,
    destination_ip: str,
    family: int,
    payload: int,
) -> str:
    template = f"""
import json
import os
import subprocess

SOURCE = {source_ip!r}
DESTINATION = {destination_ip!r}
FAMILY = {family}
PAYLOAD = {payload}
FLAG = '-6' if FAMILY == 6 else '-4'
MARKER = {BOUNDARY_RESULT_MARKER!r}

{_remote_helpers()}

ping_result = run_command([
    'ping', FLAG, '-n', '-c', '2', '-W', '2', '-I', SOURCE,
    '-M', 'do', '-s', str(PAYLOAD), DESTINATION,
])
classification = classify_ping(ping_result)
evidence = local_mtu_evidence() if classification == 'local-mtu-rejected' else None
print(MARKER + json.dumps({{
    'ping': compact_result(ping_result),
    'classification': classification,
    'packet_transmitted': classification != 'local-mtu-rejected',
    'local_mtu_evidence': evidence,
    'packet_too_big_feedback': packet_too_big_feedback(ping_result),
}}, separators=(',', ':')))
"""
    return textwrap.dedent(template)


def parse_boundary_result(stdout: str) -> dict[str, Any] | None:
    for line in reversed(str(stdout).splitlines()):
        if line.startswith(BOUNDARY_RESULT_MARKER):
            try:
                value = json.loads(line[len(BOUNDARY_RESULT_MARKER) :])
            except json.JSONDecodeError:
                return None
            return value if isinstance(value, dict) else None
    return None


def fragmentation_probe_code(
    source_ip: str,
    destination_ip: str,
    family: int,
    source_mtu: int,
    path_mtu: int | None,
) -> str:
    """Return a bounded directional fragmentation-capability probe.

    The probe deliberately separates the no-fragment PMTUD contract from the
    ability to carry a packet sized for the source network when the routed path
    is narrower.  IPv4 may be fragmented in transit or at the source.  IPv6
    routers never fragment; any successful oversized probe therefore reflects
    source fragmentation and destination reassembly.
    """
    template = f"""
import json
import os
import subprocess

SOURCE = {source_ip!r}
DESTINATION = {destination_ip!r}
FAMILY = {family}
SOURCE_MTU = {source_mtu}
PATH_MTU = {path_mtu}
HEADER = 48 if FAMILY == 6 else 28
FLAG = '-6' if FAMILY == 6 else '-4'
TRIALS = 3
MAX_PACKET_SIZE = 65535

{_remote_helpers()}
{_remote_fragment_counter_helpers()}


def trial_summary(packet_size, pmtud_mode):
    payload = max(0, int(packet_size) - HEADER)
    results = []
    classifications = []
    for _ in range(TRIALS):
        result = run_command([
            'ping', FLAG, '-n', '-c', '1', '-W', '2', '-I', SOURCE,
            '-M', pmtud_mode, '-s', str(payload), DESTINATION,
        ])
        classification = classify_ping(result)
        results.append(compact_result(result))
        classifications.append(classification)
        if classification == 'unsupported':
            break
    counts = {{}}
    for item in classifications:
        counts[item] = counts.get(item, 0) + 1
    classification = classifications[0] if len(counts) == 1 else 'mixed'
    return {{
        'packet_size': int(packet_size),
        'payload': payload,
        'pmtud_mode': pmtud_mode,
        'classification': classification,
        'counts': counts,
        'trials': results,
    }}


source_packet_size = min(max(int(SOURCE_MTU), HEADER), MAX_PACKET_SIZE)
applicable = (
    SOURCE_MTU > PATH_MTU and source_packet_size > PATH_MTU
    if PATH_MTU is not None else None
)
no_fragment = None
fragmentation_permitted = None
source_counters_before = read_fragment_counters(FAMILY)
source_counters_after_control = source_counters_before
source_counters_after_permitted = source_counters_before
capability = 'not-required' if PATH_MTU is not None else 'unverified'
reason = (
    'the source network MTU does not exceed the confirmed no-fragment path MTU'
    if PATH_MTU is not None else
    'the no-fragment path MTU was not confirmed; fragmentation requirements are unknown'
)

if applicable:
    no_fragment = trial_summary(source_packet_size, 'do')
    source_counters_after_control = read_fragment_counters(FAMILY)
    fragmentation_permitted = trial_summary(source_packet_size, 'dont')
    source_counters_after_permitted = read_fragment_counters(FAMILY)
    permitted_class = fragmentation_permitted['classification']
    no_fragment_class = no_fragment['classification']
    if permitted_class == 'success' and no_fragment_class != 'success':
        capability = 'supported'
        reason = (
            'the source-MTU packet failed or was rejected with fragmentation disabled '
            'and succeeded in every fragmentation-permitted trial'
        )
    elif permitted_class == 'success' and no_fragment_class == 'success':
        capability = 'path-supports-source-mtu'
        reason = (
            'the source-MTU packet succeeded even with fragmentation disabled; the '
            'effective path may be wider than the earlier path-MTU expectation'
        )
    elif permitted_class in {{'unsupported', 'mixed', 'error'}}:
        capability = 'unverified'
        reason = 'the fragmentation-permitted probe did not produce stable executable evidence'
    elif permitted_class in {{'no-reply', 'local-mtu-rejected'}}:
        capability = 'not-supported'
        reason = (
            'the source-MTU packet did not cross the routed path even when fragmentation '
            'or source fragmentation was permitted'
        )
    else:
        capability = 'unverified'
        reason = 'the fragmentation capability could not be classified'

print(json.dumps({{
    'family': FAMILY,
    'source_mtu': SOURCE_MTU,
    'path_mtu': PATH_MTU,
    'tested_packet_size': source_packet_size,
    'header_bytes': HEADER,
    'applicable': applicable,
    'fragmentation_model': (
        'ipv4-fragmentation-permitted'
        if FAMILY == 4
        else 'ipv6-source-fragmentation-only'
    ),
    'router_fragmentation_applicable': FAMILY == 4,
    'capability': capability,
    'reason': reason,
    'no_fragment_control': no_fragment,
    'fragmentation_permitted': fragmentation_permitted,
    'local_mtu_evidence': local_mtu_evidence() if applicable else None,
    'source_fragment_counters': {{
        'before': source_counters_before,
        'after_no_fragment': source_counters_after_control,
        'after_permitted': source_counters_after_permitted,
        'no_fragment_delta': counter_delta(
            source_counters_before, source_counters_after_control
        ),
        'permitted_delta': counter_delta(
            source_counters_after_control, source_counters_after_permitted
        ),
        'total_delta': counter_delta(
            source_counters_before, source_counters_after_permitted
        ),
    }},
}}, separators=(',', ':')))
"""
    return textwrap.dedent(template)


def performance_probe_code(
    source_ip: str,
    destination_ip: str,
    family: int,
    expected_mtu: int,
) -> str:
    template = f"""
import json
import os
import subprocess

SOURCE = {source_ip!r}
DESTINATION = {destination_ip!r}
FAMILY = {family}
EXPECTED = {expected_mtu}
HEADER = 48 if FAMILY == 6 else 28
FLAG = '-6' if FAMILY == 6 else '-4'
TRIALS = 3

{_remote_helpers()}


def ping_once(payload, *, df=True):
    command = [
        'ping', FLAG, '-n', '-c', '1', '-W', '1', '-I', SOURCE,
    ]
    if df:
        command.extend(['-M', 'do'])
    command.extend(['-s', str(payload), DESTINATION])
    return run_command(command)


def trial_summary(payload):
    results = []
    classifications = []
    for _ in range(TRIALS):
        result = ping_once(payload, df=True)
        classification = classify_ping(result)
        results.append(compact_result(result))
        classifications.append(classification)
        if classification == 'unsupported':
            fallback = ping_once(payload, df=False)
            return {{
                'payload': payload,
                'classification': 'unsupported',
                'counts': {{'unsupported': 1}},
                'trials': results,
                'fallback': compact_result(fallback),
                'fallback_reachable': classify_ping(fallback) == 'success',
                'probe_mode': (
                    'native-ipv6-pmtud'
                    if FAMILY == 6
                    else 'fragmentation-permitted-fallback'
                ),
            }}
    counts = {{}}
    for item in classifications:
        counts[item] = counts.get(item, 0) + 1
    classification = classifications[0] if len(counts) == 1 else 'mixed'
    feedback = [
        item for result in results for item in result.get('packet_too_big_feedback', [])
    ]
    reported_mtus = {{item['mtu'] for item in feedback}}
    if (
        'packet-too-big' in counts
        and set(counts) <= {{'packet-too-big', 'local-mtu-rejected'}}
        and len(reported_mtus) == 1
    ):
        # Later local rejections are expected after fresh ICMP feedback updates
        # the guest's PMTU cache. Preserve the network response as the cause.
        classification = 'packet-too-big'
    return {{
        'payload': payload,
        'classification': classification,
        'counts': counts,
        'trials': results,
        'fallback': None,
        'fallback_reachable': None,
        'probe_mode': 'df-pmtud',
        'packet_too_big_feedback': feedback,
        'reported_mtu': next(iter(reported_mtus)) if len(reported_mtus) == 1 else None,
    }}


expected_payload = max(0, EXPECTED - HEADER)
expected_probe = trial_summary(expected_payload)
above_probe = trial_summary(expected_payload + 1)
zero_probe = None
candidate_probes = []
discovered_payload = None
discovery_confidence = 'unstable'
discovery_reason = 'expected payload did not produce a stable MTU classification'
boundary_confirmed = False

if expected_probe['classification'] == 'success':
    discovered_payload = expected_payload
    discovery_confidence = 'expected-confirmed'
    discovery_reason = 'the expected payload succeeded in every repeated DF probe'
    boundary_confirmed = True
elif expected_probe['classification'] in ('packet-too-big', 'local-mtu-rejected', 'no-reply'):
    zero_probe = trial_summary(0)
    if zero_probe['classification'] == 'success':
        low = 0
        high = max(expected_payload - 1, 0)
        unstable = False
        while low < high:
            middle = (low + high + 1) // 2
            candidate = trial_summary(middle)
            candidate_probes.append({{
                'payload': middle,
                'classification': candidate['classification'],
                'counts': candidate['counts'],
            }})
            if candidate['classification'] == 'success':
                low = middle
            elif candidate['classification'] in ('packet-too-big', 'local-mtu-rejected', 'no-reply'):
                high = middle - 1
            else:
                unstable = True
                discovery_reason = (
                    'binary-search candidate payloads produced packet loss, mixed results, '
                    'unsupported ping behavior, or an execution error'
                )
                break
        if not unstable:
            lower_confirmation = trial_summary(low)
            upper_confirmation = trial_summary(low + 1)
            candidate_probes.extend([
                {{
                    'payload': low,
                    'classification': lower_confirmation['classification'],
                    'counts': lower_confirmation['counts'],
                    'confirmation': 'lower',
                }},
                {{
                    'payload': low + 1,
                    'classification': upper_confirmation['classification'],
                    'counts': upper_confirmation['counts'],
                    'confirmation': 'upper',
                }},
            ])
            if (
                lower_confirmation['classification'] == 'success'
                and upper_confirmation['classification']
                in ('packet-too-big', 'local-mtu-rejected', 'no-reply')
            ):
                discovered_payload = low
                discovery_confidence = 'confirmed-lower-boundary'
                discovery_reason = (
                    'the final payload succeeded in every repeated DF trial and the next '
                    'payload consistently failed at the packet-size boundary'
                )
                boundary_confirmed = True
            else:
                discovery_reason = (
                    'the candidate MTU boundary could not be reproduced consistently'
                )
    else:
        discovery_reason = (
            'the expected payload failed, but a zero-byte payload did not succeed '
            'consistently'
        )
elif expected_probe['classification'] == 'unsupported':
    discovery_confidence = 'unsupported'
    discovery_reason = (
        'the guest ping implementation does not support the required DF/PMTUD option'
    )
else:
    zero_probe = trial_summary(0)
    if zero_probe['classification'] != 'success':
        discovery_confidence = 'unreachable'
        discovery_reason = 'even a zero-byte payload did not succeed consistently'

local_rejection = expected_probe['classification'] == 'local-mtu-rejected'
evidence = local_mtu_evidence() if local_rejection else None
local_constraint_classification = None
local_boundary_confirmed = bool(boundary_confirmed and local_rejection)
if local_rejection:
    route_mtu = evidence.get('route_mtu') if isinstance(evidence, dict) else None
    interface_mtu = (
        evidence.get('source_interface_mtu') if isinstance(evidence, dict) else None
    )
    if (
        route_mtu is not None
        and int(route_mtu) < EXPECTED
        and (interface_mtu is None or int(route_mtu) < int(interface_mtu))
    ):
        local_constraint_classification = 'cached-route-pmtu'
        discovery_confidence = 'cached-route-pmtu'
        discovery_reason = (
            'the source guest had a per-destination route PMTU below the advertised '
            'MTU; packets above that cached PMTU were not transmitted, so the current '
            'end-to-end path boundary was not independently measured'
        )
        boundary_confirmed = False
    elif interface_mtu is not None and int(interface_mtu) < EXPECTED:
        local_constraint_classification = 'interface-mtu-constraint'
        discovery_confidence = 'interface-mtu-constraint'
        discovery_reason = (
            'the source interface MTU was below the advertised network MTU; the '
            'packet was rejected before transmission'
        )
        boundary_confirmed = False
    else:
        local_constraint_classification = 'local-mtu-constraint-unverified'
        discovery_confidence = 'local-mtu-constraint-unverified'
        discovery_reason = (
            'the source guest rejected the packet before transmission, but Flux '
            'could not safely attribute the local MTU constraint'
        )
        boundary_confirmed = False
probe_mode = expected_probe.get('probe_mode') or 'df-pmtud'
reachable = (
    expected_probe['classification'] == 'success'
    or (zero_probe is not None and zero_probe['classification'] == 'success')
)
print(json.dumps({{
    'expected_mtu': EXPECTED,
    'reachable': reachable,
    'discovered_payload': discovered_payload,
    'discovered_mtu': (discovered_payload + HEADER) if discovered_payload is not None else None,
    'header_bytes': HEADER,
    'probe_mode': probe_mode,
    'discovery_confidence': discovery_confidence,
    'discovery_reason': discovery_reason,
    'boundary_confirmed': boundary_confirmed,
    'path_boundary_confirmed': boundary_confirmed,
    'local_boundary_confirmed': local_boundary_confirmed,
    'local_constraint_classification': local_constraint_classification,
    'local_mtu_rejected': local_rejection,
    'packet_transmitted_at_expected_size': not local_rejection,
    'expected_size_reachable': expected_probe['classification'] == 'success',
    'above_expected_reachable': above_probe['classification'] == 'success',
    'expected_probe_classification': expected_probe['classification'],
    'above_probe_classification': above_probe['classification'],
    'zero_probe_classification': (
        zero_probe['classification'] if zero_probe is not None else None
    ),
    'expected_trials': expected_probe,
    'packet_too_big_feedback': expected_probe.get('packet_too_big_feedback', []),
    'reported_path_mtu': expected_probe.get('reported_mtu'),
    'above_trials': above_probe,
    'zero_trials': zero_probe,
    'candidate_probes': candidate_probes,
    'local_mtu_evidence': evidence,
    'expected_output': '\\n'.join(
        (item.get('stdout') or '') + '\\n' + (item.get('stderr') or '')
        for item in expected_probe.get('trials') or []
    )[-1200:],
    'above_output': '\\n'.join(
        (item.get('stdout') or '') + '\\n' + (item.get('stderr') or '')
        for item in above_probe.get('trials') or []
    )[-1200:],
}}, separators=(',', ':')))
"""
    return textwrap.dedent(template)
