from __future__ import annotations


def route_cache_reset_code(
    source_ip: str,
    destination_ip: str,
    family: int,
    expected_mtu: int,
) -> str:
    """Return guest-side code that flushes and verifies route/PMTU cache state."""

    return f"""
import json
import shutil
import subprocess

FAMILY = {family}
SOURCE = {source_ip!r}
DESTINATION = {destination_ip!r}
EXPECTED_MTU = {expected_mtu}
flag = '-6' if FAMILY == 6 else '-4'

def run(command):
    return subprocess.run(command, text=True, capture_output=True, check=False)

def route_get():
    return run(['ip', flag, 'route', 'get', DESTINATION, 'from', SOURCE])

def route_mtu(text):
    tokens = text.split()
    try:
        position = tokens.index('mtu')
        return int(tokens[position + 1])
    except (ValueError, IndexError, TypeError):
        return None

before = route_get()
flush_commands = []
if shutil.which('sudo'):
    flush_commands.append(['sudo', '-n', 'ip', flag, 'route', 'flush', 'cache'])
flush_commands.append(['ip', flag, 'route', 'flush', 'cache'])
flush = None
for command in flush_commands:
    candidate = run(command)
    flush = candidate
    if candidate.returncode == 0:
        break
after = route_get()
after_text = ((after.stdout or '') + '\\n' + (after.stderr or '')).strip()
tokens = after_text.split()
mtu_after = route_mtu(after_text)
cache_marker = 'cache' in tokens
stale_pmtu = bool(
    cache_marker and mtu_after is not None and mtu_after < EXPECTED_MTU
)
verified = bool(
    flush is not None
    and flush.returncode == 0
    and after.returncode == 0
    and not stale_pmtu
)
print(json.dumps({{
    'attempted': True,
    'verified': verified,
    'family': FAMILY,
    'source_ip': SOURCE,
    'destination_ip': DESTINATION,
    'expected_mtu': EXPECTED_MTU,
    'before_route': (before.stdout or before.stderr or '').strip(),
    'after_route': after_text,
    'flush_returncode': None if flush is None else flush.returncode,
    'flush_stderr': '' if flush is None else (flush.stderr or '').strip(),
    'route_get_returncode': after.returncode,
    'route_mtu_after_reset': mtu_after,
    'cache_marker_after_reset': cache_marker,
    'stale_pmtu_after_reset': stale_pmtu,
}}, separators=(',', ':')))
"""


__all__ = ["route_cache_reset_code"]
