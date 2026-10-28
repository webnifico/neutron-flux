"""Bounded evidence after a remote command cannot execute."""

from __future__ import annotations

import json
import time
from typing import Any

from .errors import RunCancelledError, SuiteError
from .results_io import atomic_write_text
from .utils import iso_utc, pick, unique_safe_name


def capture_execution_diagnostics(
    builder: Any,
    reporter: Any,
    test_id: str,
    endpoints: tuple,
    error: BaseException,
    *,
    endpoint_builders: dict[str, Any] | None = None,
) -> dict[str, Any]:
    deadline = time.monotonic() + 30
    payload: dict[str, Any] = {
        "captured_at": iso_utc(),
        "budget_seconds": 30,
        "execution_error": str(error),
        "compute_service_health": {"status": "not-collected"},
        "endpoints": {},
    }

    owners = (
        endpoint_builders
        if endpoint_builders is not None
        else getattr(builder, "builders_by_server", {})
    )
    if not isinstance(owners, dict):
        owners = {}
    inventory_owner = next(iter(owners.values()), builder)

    def capture(operation):
        remaining = int(deadline - time.monotonic())
        if remaining < 1:
            return {"status": "not-collected", "reason": "diagnostic budget exhausted"}
        try:
            value = operation(min(5, remaining))
            return {"status": "collected", "data": value}
        except RunCancelledError:
            raise
        except (RuntimeError, OSError, ValueError, TypeError, AttributeError) as exc:
            text = str(exc)
            denied = any(
                word in text.lower()
                for word in (
                    "403",
                    "401",
                    "forbidden",
                    "not authorized",
                    "policy doesn't allow",
                )
            )
            return {
                "status": "permission-denied" if denied else "unavailable",
                "reason": text[:4000],
            }

    if getattr(inventory_owner, "_diagnostic_compute_permission_denied", False) is True:
        health = {
            "status": "permission-denied",
            "reason": "permission denied earlier in this run",
        }
    else:
        health = capture(
            lambda timeout: inventory_owner.osc.json(
                "compute",
                "service",
                "list",
                "--service",
                "nova-compute",
                timeout=timeout,
            )
        )
        if health["status"] == "permission-denied":
            inventory_owner._diagnostic_compute_permission_denied = True
        if health["status"] == "collected":
            hosts = {endpoint.host for endpoint in endpoints if endpoint.host}
            data = health["data"]
            if isinstance(data, list):
                health["data"] = [
                    row
                    for row in data
                    if isinstance(row, dict) and pick(row, "host", default="") in hosts
                ]
            else:
                health = {
                    "status": "unavailable",
                    "reason": "Nova returned no compute-service list",
                }
    payload["compute_service_health"] = health

    def ssh_result(result):
        return {
            "returncode": result.returncode,
            "stdout": (result.stdout or "")[-8000:],
            "stderr": (result.stderr or "")[-4000:],
        }

    controls: dict[str, Any] = {}
    for endpoint in endpoints:
        if (
            endpoint.metadata.get("performance_local")
            or endpoint.server_id in payload["endpoints"]
        ):
            continue
        owner = owners.get(endpoint.server_id, builder)
        control_key = str(getattr(owner, "availability_zone", None) or "default")
        if control_key not in controls and callable(
            getattr(owner, "ssh_controller", None)
        ):
            controls[control_key] = capture(
                lambda timeout, owner=owner: ssh_result(
                    owner.ssh_controller("true", timeout=timeout)
                )
            )
        row: dict[str, Any] = {
            "label": endpoint.label,
            "management_address": endpoint.management_ip,
        }
        row["compute_host"] = endpoint.host
        row["server"] = capture(
            lambda timeout, endpoint=endpoint, owner=owner: owner.osc.json(
                "server", "show", endpoint.server_id, timeout=timeout
            )
        )
        row["ssh"] = capture(
            lambda timeout, endpoint=endpoint, owner=owner: ssh_result(
                owner.ssh_endpoint(
                    endpoint,
                    "ip -br addr; ip route; ip -6 route; ss -lntu",
                    timeout=timeout,
                )
            )
        )
        for kind, resource_id in (
            ("test_port", endpoint.test_port_id),
            ("management_port", endpoint.management_port_id),
        ):
            if resource_id:
                row[kind] = capture(
                    lambda timeout, resource_id=resource_id, owner=owner: (
                        owner.osc.json("port", "show", resource_id, timeout=timeout)
                    )
                )
        row["console"] = capture(
            lambda timeout, endpoint=endpoint, owner=owner: owner.osc.run(
                "console",
                "log",
                "show",
                "--lines",
                "40",
                endpoint.server_id,
                timeout=timeout,
            ).stdout[-8000:]
        )
        payload["endpoints"][endpoint.server_id] = row
    payload["controller_transport"] = controls
    directory = reporter.run_dir / "failures"
    path = directory / (unique_safe_name(test_id, 120) + "-execution.json")
    if directory.is_symlink() or path.is_symlink():
        raise SuiteError("Diagnostic destination must not be a symbolic link")
    directory.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return {"execution_diagnostics": payload, "execution_diagnostics_file": str(path)}
