"""Readback polling programs for manual guides; no cloud operations run here."""

from __future__ import annotations

from typing import Any


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _wait_server(status: str, *, host: bool = False) -> str:
    expected_host = ', os.environ["TARGET_HOST"]' if host else ", None"
    return (
        "python3 - <<'NF_WAIT_SERVER'\n"
        "import json, os, subprocess, time\n"
        f"expected, host = {status!r}{expected_host}\n"
        "deadline = time.monotonic() + 300\n"
        "while True:\n"
        "    server = json.loads(subprocess.check_output([\n"
        "        'openstack', 'server', 'show', os.environ['MOVING_SERVER_ID'], '-f', 'json'], text=True))\n"
        "    state = str(server.get('status', '')).upper()\n"
        "    task = server.get('OS-EXT-STS:task_state')\n"
        "    actual = server.get('OS-EXT-SRV-ATTR:host')\n"
        "    if state == expected and task in (None, '', 'None') and (not host or actual == host):\n"
        "        print(json.dumps(server, sort_keys=True)); break\n"
        "    if state == 'ERROR' or time.monotonic() >= deadline:\n"
        "        raise SystemExit('Server did not reach the required state: ' + json.dumps(server))\n"
        "    time.sleep(2)\n"
        "NF_WAIT_SERVER"
    )


def _wait_fip(*, attached: bool) -> str:
    return (
        "python3 - <<'NF_WAIT_FIP'\n"
        "import json, os, subprocess, time\n"
        f"attached = {attached!r}\n"
        "deadline = time.monotonic() + 180\n"
        "while True:\n"
        "    row = json.loads(subprocess.check_output(['openstack', 'floating', 'ip', 'show',\n"
        "        os.environ['FLOATING_IP_ID'], '-f', 'json'], text=True))\n"
        "    port, fixed = row.get('port_id'), row.get('fixed_ip_address')\n"
        "    matched = (port == os.environ['DESTINATION_PORT_ID'] and fixed == os.environ['DESTINATION_FIXED_IP']) if attached else port in (None, '')\n"
        "    if matched: print(json.dumps(row, sort_keys=True)); break\n"
        "    if time.monotonic() >= deadline: raise SystemExit('Floating-IP association did not converge: ' + json.dumps(row))\n"
        "    time.sleep(2)\n"
        "NF_WAIT_FIP"
    )


def _wait_router_interface(*, attached: bool) -> str:
    return (
        "python3 - <<'NF_WAIT_INTERFACE'\n"
        "import json, os, subprocess, time\n"
        f"attached = {attached!r}\n"
        "deadline = time.monotonic() + 180\n"
        "while True:\n"
        "    rows = json.loads(subprocess.check_output(['openstack', 'port', 'list', '--device-id',\n"
        "        os.environ['ROUTER_ID'], '--long', '-f', 'json'], text=True))\n"
        "    found = any(os.environ['SUBNET_ID'] in str(row.get('Fixed IP Addresses', row.get('fixed_ips', ''))) for row in rows)\n"
        "    if found == attached: print(json.dumps(rows, sort_keys=True)); break\n"
        "    if time.monotonic() >= deadline: raise SystemExit('Router interface did not converge')\n"
        "    time.sleep(2)\n"
        "NF_WAIT_INTERFACE"
    )
