from __future__ import annotations

import base64
import ipaddress
import json
import shlex
import textwrap
from collections.abc import Callable
from typing import Any

from .errors import SuiteError
from .mtu_contract import positive_mtu


class GuestNetworkVerifier:
    """Verify, but never modify, networking supplied to a VM by OpenStack.

    Neutron Flux deliberately treats the guest network configuration as part of
    the OpenStack image/metadata contract.  The suite may inspect addresses,
    routes, interface state, MTU and IPv6 DAD state, but it must not install
    units, add addresses, change routes, alter sysctls or write network files.
    """

    def __init__(self, subnet_resolver: Callable[[str], dict[str, Any]]):
        self.subnet_resolver = subnet_resolver

    def verify(
        self,
        *,
        label: str,
        mac_address: str,
        fixed_ips: dict[str, str],
        executor: Callable[[str], Any],
    ) -> dict[str, Any]:
        entries: list[dict[str, Any]] = []
        for subnet_id, address in sorted(fixed_ips.items()):
            subnet = self.subnet_resolver(subnet_id)
            network = ipaddress.ip_network(subnet["cidr"], strict=False)
            expected_mtu = positive_mtu(subnet.get("mtu"))
            declared_authority = subnet.get("mtu_authoritative")
            mtu_authoritative = bool(
                expected_mtu is not None
                and (declared_authority is True or declared_authority is None)
            )
            entries.append(
                {
                    "subnet_id": subnet_id,
                    "family": network.version,
                    "address": address,
                    "prefix_length": network.prefixlen,
                    "cidr": str(network),
                    "gateway": subnet.get("gateway"),
                    "mtu": expected_mtu,
                    "mtu_authoritative": mtu_authoritative,
                    "mtu_authority": subnet.get("mtu_authority"),
                    "mtu_source": subnet.get("mtu_source"),
                    "mtu_resource_id": subnet.get("mtu_resource_id"),
                }
            )

        payload = base64.b64encode(json.dumps(entries).encode()).decode()
        script = textwrap.dedent(
            f"""\
            import base64
            import json
            import os
            import subprocess
            import sys

            mac = {mac_address!r}.lower()
            entries = json.loads(base64.b64decode({payload!r}))
            iface = None
            for name in os.listdir('/sys/class/net'):
                path = f'/sys/class/net/{{name}}/address'
                try:
                    value = open(path, encoding='utf-8').read().strip().lower()
                except OSError:
                    continue
                if value == mac:
                    iface = name
                    break
            if not iface:
                print(json.dumps({{'error': f'interface with MAC {{mac}} was not found'}}))
                sys.exit(10)

            def run(*args):
                return subprocess.run(args, text=True, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, check=False)

            link = run('ip', '-j', 'link', 'show', 'dev', iface)
            if link.returncode != 0:
                print(json.dumps({{'error': link.stderr.strip() or 'ip link failed', 'interface': iface}}))
                sys.exit(11)
            try:
                link_data = json.loads(link.stdout)[0]
            except Exception as exc:
                print(json.dumps({{'error': f'could not parse interface state: {{exc}}', 'interface': iface}}))
                sys.exit(12)

            observed = {{
                'interface': iface,
                'mac_address': mac,
                'operstate': link_data.get('operstate'),
                'mtu': link_data.get('mtu'),
                'mtu_contracts': [],
                'addresses': [],
                'routes': [],
            }}
            errors = []

            for entry in entries:
                family = int(entry['family'])
                flag = '-6' if family == 6 else '-4'
                address = entry['address']
                prefix = int(entry['prefix_length'])
                cidr = entry['cidr']
                gateway = entry.get('gateway')
                raw_expected_mtu = entry.get('mtu')
                expected_mtu = (
                    int(raw_expected_mtu)
                    if raw_expected_mtu is not None
                    else None
                )
                mtu_authoritative = bool(
                    entry.get('mtu_authoritative')
                    and expected_mtu is not None
                )

                addr = run('ip', '-j', flag, 'address', 'show', 'dev', iface)
                if addr.returncode != 0:
                    errors.append(f'could not read IPv{{family}} addresses on {{iface}}: {{addr.stderr.strip()}}')
                    continue
                try:
                    addr_data = json.loads(addr.stdout)
                except Exception as exc:
                    errors.append(f'could not parse IPv{{family}} addresses on {{iface}}: {{exc}}')
                    continue

                match = None
                for item in addr_data:
                    for info in item.get('addr_info', []):
                        if info.get('local') == address and int(info.get('prefixlen', -1)) == prefix:
                            match = info
                            break
                    if match:
                        break
                if not match:
                    errors.append(
                        f'OpenStack fixed address {{address}}/{{prefix}} is not configured on {{iface}}'
                    )
                    continue

                flags = [str(value).lower() for value in match.get('flags', [])]
                if family == 6 and ('tentative' in flags or 'dadfailed' in flags):
                    errors.append(
                        f'IPv6 address {{address}} on {{iface}} is not usable (flags={{flags}})'
                    )

                route_args = ['ip', flag, 'route', 'get', address, 'from', address]
                route = run(*route_args)
                observed['addresses'].append({{
                    'subnet_id': entry['subnet_id'],
                    'family': family,
                    'address': address,
                    'prefix_length': prefix,
                    'flags': flags,
                }})
                observed['routes'].append({{
                    'destination': address,
                    'source': address,
                    'returncode': route.returncode,
                    'stdout': route.stdout.strip(),
                    'stderr': route.stderr.strip(),
                }})
                if route.returncode != 0:
                    errors.append(
                        f'the guest has no usable IPv{{family}} route from {{address}} on {{iface}}'
                    )

                if gateway:
                    gateway_route = run('ip', flag, 'route', 'get', str(gateway), 'from', address)
                    observed['routes'].append({{
                        'destination': gateway,
                        'source': address,
                        'returncode': gateway_route.returncode,
                        'stdout': gateway_route.stdout.strip(),
                        'stderr': gateway_route.stderr.strip(),
                    }})
                    if gateway_route.returncode != 0:
                        errors.append(
                            f'no usable guest route lookup exists from {{address}} on {{iface}} to the OpenStack subnet gateway {{gateway}}'
                        )

                actual_mtu = int(link_data.get('mtu') or 0)
                observed['mtu_contracts'].append({{
                    'subnet_id': entry['subnet_id'],
                    'expected_mtu': expected_mtu,
                    'observed_interface_mtu': actual_mtu,
                    'authoritative': mtu_authoritative,
                    'authority': entry.get('mtu_authority'),
                    'source': entry.get('mtu_source'),
                    'resource_id': entry.get('mtu_resource_id'),
                    'assessment': (
                        'met'
                        if mtu_authoritative and actual_mtu == expected_mtu
                        else 'violated'
                        if mtu_authoritative
                        else 'not-evaluated'
                    ),
                }})
                if (
                    mtu_authoritative
                    and expected_mtu is not None
                    and actual_mtu != expected_mtu
                ):
                    errors.append(
                        f'interface {{iface}} MTU is {{actual_mtu}}, but OpenStack network MTU is {{expected_mtu}}'
                    )

            observed['errors'] = errors
            print(json.dumps(observed, sort_keys=True))
            sys.exit(0 if not errors else 20)
            """
        )
        command = "python3 -c " + shlex.quote(script)
        result = executor(command)
        output = (result.stdout or "").strip()
        details: dict[str, Any] = {}
        if output:
            try:
                details = json.loads(output.splitlines()[-1])
            except json.JSONDecodeError:
                details = {"raw_output": output}
        if result.returncode != 0:
            message = (result.stderr or "").strip()
            errors = details.get("errors") if isinstance(details, dict) else None
            if isinstance(errors, list) and errors:
                message = "; ".join(str(item) for item in errors)
            elif isinstance(details, dict) and details.get("error"):
                message = str(details["error"])
            elif not message:
                message = output or "guest network verification failed"
            raise SuiteError(
                f"OpenStack-provided networking is not usable on {label}: {message}"
            )
        return details
