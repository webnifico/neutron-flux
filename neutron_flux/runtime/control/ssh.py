from __future__ import annotations

import json
import math
import shlex
import socket
import subprocess
import threading
import time
from contextlib import nullcontext
from typing import Any

# mypy: disable-error-code="attr-defined"
from ...cancellation import raise_if_cancelled, run_cancellable
from ...errors import ControllerUnavailableError, RunCancelledError, SuiteError
from ...utils import iso_utc, pick


class SSHRuntimeMixin:
    """Compatibility mixin for this control-plane concern."""

    _SSH_TCP_REACHABLE_MARKERS = (
        "connection refused",
        "connection reset by peer",
        "connection closed by",
        "closed by remote host",
        "timed out during banner exchange",
        "banner exchange:",
        "kex_exchange_identification",
        "remote host identification has changed",
        "host key verification failed",
        "permission denied",
        "no matching host key type found",
        "no matching key exchange method found",
        "no matching cipher found",
    )
    _SSH_NETWORK_PATH_FAILURE_MARKERS = (
        "network is unreachable",
        "no route to host",
        "host is unreachable",
        "connection timed out",
        "operation timed out",
    )

    def _ssh_base(
        self,
        address: str,
        *,
        proxy: bool,
        connect_timeout: int | None = None,
    ) -> list[str]:
        args = [
            "ssh",
            "-i",
            str(self.key_path),
            *self._ssh_common_options(connect_timeout=connect_timeout),
        ]
        if proxy:
            if not self.control_address:
                raise SuiteError(
                    "SSH proxy requested before controller became reachable"
                )
            self._require_ipv4(self.control_address, "runner-to-controller SSH address")
            self._require_ipv4(address, "guest management SSH address")
            jump_command = [
                "ssh",
                "-i",
                str(self.key_path),
                *self._ssh_common_options(connect_timeout=connect_timeout),
                "-W",
                "%h:%p",
                f"{self.ssh_user}@{self.control_address}",
            ]
            args.extend(["-o", f"ProxyCommand={shlex.join(jump_command)}"])
        args.append(f"{self.ssh_user}@{address}")
        return args

    def _ssh_common_options(
        self,
        *,
        connect_timeout: int | None = None,
    ) -> list[str]:
        selected_timeout = max(
            1,
            int(connect_timeout or self.config.ssh_timeout),
        )
        return [
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={selected_timeout}",
            "-o",
            "ConnectionAttempts=1",
            "-o",
            "NumberOfPasswordPrompts=0",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "CheckHostIP=no",
            "-o",
            "UpdateHostKeys=no",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=3",
            "-o",
            "LogLevel=ERROR",
        ]

    @staticmethod
    def _transport_classification(
        *,
        tcp_connected: bool,
        ssh_banner_observed: bool,
        connection_refused: bool = False,
        error: str | None,
    ) -> str:
        if ssh_banner_observed:
            return "ssh-banner-observed"
        if tcp_connected:
            return "tcp-connected-no-ssh-banner"
        if connection_refused:
            # A refusal is an explicit response from the destination path.  It
            # proves that routing reached the address even though sshd was not
            # listening at that instant.
            return "tcp-reachable-connection-refused"
        if error:
            return "tcp-connect-failed"
        return "not-probed"

    @classmethod
    def _classify_ssh_attempt_error(cls, error: str | None) -> str:
        """Classify OpenSSH evidence without turning SSH readiness into routing.

        OpenSSH's ``Connection timed out during banner exchange`` is emitted
        only after the TCP connection completed.  Likewise, a refusal is a
        response from the destination path.  Neither is evidence that the
        provider address is unreachable, and both must prevent an unrelated
        bastion fallback.
        """

        normalized = str(error or "").strip().lower()
        if not normalized:
            return "unknown"
        if any(marker in normalized for marker in cls._SSH_TCP_REACHABLE_MARKERS):
            return "tcp-reachable-ssh-not-ready"
        if any(
            marker in normalized for marker in cls._SSH_NETWORK_PATH_FAILURE_MARKERS
        ):
            return "network-path-unavailable"
        return "unknown"

    def _ssh_readiness_evidence(self, address: str, *, proxy: bool) -> dict[str, Any]:
        records = dict(getattr(self, "_last_ssh_readiness", {}) or {})
        evidence = records.get(f"{proxy}:{address}", {})
        return dict(evidence) if isinstance(evidence, dict) else {}

    def _ssh_path_assessment(
        self,
        address: str,
        *,
        proxy: bool,
        diagnostics: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Combine bounded readiness and transport evidence for fallback use."""

        readiness = self._ssh_readiness_evidence(address, proxy=proxy)
        transport = (
            diagnostics.get("transport", {}) if isinstance(diagnostics, dict) else {}
        )
        if not isinstance(transport, dict):
            transport = {}
        transport_classification = str(transport.get("classification") or "")
        tcp_reachable = bool(readiness.get("tcp_reachability_observed")) or (
            transport_classification
            in {
                "ssh-banner-observed",
                "tcp-connected-no-ssh-banner",
                "tcp-reachable-connection-refused",
            }
        )
        network_path_failure = bool(readiness.get("network_path_failure_observed"))
        diagnostic_error_classification = self._classify_ssh_attempt_error(
            str(transport.get("error") or "") or None
        )
        if diagnostic_error_classification == "tcp-reachable-ssh-not-ready":
            tcp_reachable = True
        elif diagnostic_error_classification == "network-path-unavailable":
            network_path_failure = True

        if tcp_reachable:
            classification = "tcp-reachable-ssh-not-ready"
            fallback_allowed = False
        elif network_path_failure:
            classification = "network-path-unavailable"
            fallback_allowed = True
        else:
            classification = "undetermined"
            fallback_allowed = False
        return {
            "address": address,
            "proxy": proxy,
            "classification": classification,
            "fallback_allowed": fallback_allowed,
            "tcp_reachability_observed": tcp_reachable,
            "network_path_failure_observed": network_path_failure,
            "readiness": readiness,
            "transport": transport,
        }

    def _probe_direct_ssh_transport(
        self,
        address: str,
        *,
        timeout: float,
        include_ping: bool = False,
    ) -> dict[str, Any]:
        budget = max(0.1, float(timeout))
        evidence: dict[str, Any] = {
            "address": address,
            "tcp_connected": False,
            "ssh_banner_observed": False,
            "connection_refused": False,
            "banner": None,
            "error": None,
            "ping_reachable": None,
        }
        if include_ping:
            try:
                ping = run_cancellable(
                    ["ping", "-n", "-c", "1", "-W", "1", address],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=min(2.0, budget),
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                evidence["ping_error"] = f"{type(exc).__name__}: {exc}"
            else:
                evidence["ping_reachable"] = ping.returncode == 0
                if ping.returncode != 0:
                    lines = (ping.stderr or ping.stdout or "").strip().splitlines()
                    if lines:
                        evidence["ping_error"] = lines[-1]

        socket_timeout = min(2.0, budget)
        try:
            with socket.create_connection(
                (address, 22), timeout=socket_timeout
            ) as sock:
                evidence["tcp_connected"] = True
                sock.settimeout(socket_timeout)
                try:
                    banner = sock.recv(255)
                except TimeoutError:
                    evidence["error"] = (
                        "TCP port 22 connected but no SSH banner arrived"
                    )
                else:
                    text = banner.decode("utf-8", errors="replace").strip()
                    evidence["banner"] = text[:160] or None
                    evidence["ssh_banner_observed"] = text.startswith("SSH-")
                    if not evidence["ssh_banner_observed"]:
                        evidence["error"] = (
                            "TCP port 22 returned data that was not an SSH banner"
                        )
        except ConnectionRefusedError as exc:
            evidence["connection_refused"] = True
            evidence["error"] = f"{type(exc).__name__}: {exc}"
        except OSError as exc:
            evidence["error"] = f"{type(exc).__name__}: {exc}"
        evidence["classification"] = self._transport_classification(
            tcp_connected=bool(evidence["tcp_connected"]),
            ssh_banner_observed=bool(evidence["ssh_banner_observed"]),
            connection_refused=bool(evidence["connection_refused"]),
            error=str(evidence.get("error") or "") or None,
        )
        return evidence

    def _probe_proxy_ssh_transport(
        self,
        address: str,
        *,
        timeout: float,
    ) -> dict[str, Any]:
        control_address = str(getattr(self, "control_address", "") or "")
        if not control_address:
            return {
                "classification": "proxy-control-address-missing",
                "error": "No management bastion address was recorded",
            }
        budget = max(1.0, float(timeout))
        control_transport = self._probe_direct_ssh_transport(
            control_address,
            timeout=min(2.0, budget),
            include_ping=True,
        )
        evidence: dict[str, Any] = {
            "control_address": control_address,
            "destination": address,
            "control_transport": control_transport,
            "tcp_connected": False,
            "ssh_banner_observed": False,
            "banner": None,
            "error": None,
        }
        script = (
            "import json,socket,sys; "
            "out={'tcp_connected':False,'ssh_banner_observed':False,'banner':None,'error':None}; "
            "s=socket.socket(); s.settimeout(float(sys.argv[2])); "
            "\ntry:\n"
            " s.connect((sys.argv[1],22)); out['tcp_connected']=True; "
            " data=s.recv(255); text=data.decode('utf-8','replace').strip(); "
            " out['banner']=text[:160] or None; "
            " out['ssh_banner_observed']=text.startswith('SSH-')\n"
            "except OSError as exc:\n out['error']=type(exc).__name__+': '+str(exc)\n"
            "finally:\n s.close()\n"
            "print(json.dumps(out,sort_keys=True))"
        )
        probe_timeout = max(1.0, min(4.0, budget))
        remote_command = (
            f"python3 -c {shlex.quote(script)} {shlex.quote(address)} "
            f"{probe_timeout:.3f}"
        )
        try:
            result = run_cancellable(
                [
                    *self._ssh_base(
                        control_address,
                        proxy=False,
                        connect_timeout=max(1, int(math.ceil(probe_timeout))),
                    ),
                    remote_command,
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=min(budget, probe_timeout + 3.0),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            evidence["error"] = f"{type(exc).__name__}: {exc}"
        else:
            if result.returncode == 0:
                try:
                    parsed = json.loads((result.stdout or "").strip().splitlines()[-1])
                except (IndexError, json.JSONDecodeError) as exc:
                    evidence["error"] = f"Proxy diagnostic parse failed: {exc}"
                else:
                    if isinstance(parsed, dict):
                        evidence.update(parsed)
            else:
                lines = (result.stderr or result.stdout or "").strip().splitlines()
                evidence["error"] = (
                    lines[-1]
                    if lines
                    else f"Proxy diagnostic command exited {result.returncode}"
                )
        evidence["classification"] = self._transport_classification(
            tcp_connected=bool(evidence["tcp_connected"]),
            ssh_banner_observed=bool(evidence["ssh_banner_observed"]),
            connection_refused=bool(evidence.get("connection_refused")),
            error=str(evidence.get("error") or "") or None,
        )
        return evidence

    def _server_console_log_snapshot(self, server_id: str) -> dict[str, Any]:
        try:
            result = self.osc.run(
                "console",
                "log",
                "show",
                "--lines",
                "200",
                server_id,
                check=False,
                timeout=min(10, self.config.resource_timeout),
            )
        except (
            SuiteError,
            OSError,
            ValueError,
            TypeError,
            subprocess.SubprocessError,
        ) as exc:
            return {"available": False, "error": f"{type(exc).__name__}: {exc}"}
        if result.returncode != 0:
            message = (result.stderr or result.stdout or "").strip()
            return {
                "available": False,
                "returncode": result.returncode,
                "error": message[-1000:] or "console log readback failed",
            }
        output = (result.stdout or "").strip()
        return {
            "available": True,
            "truncated": len(output) > 12000,
            "tail": output[-12000:],
        }

    def _security_group_readback(self, group_ids: set[str]) -> list[dict[str, Any]]:
        snapshots: list[dict[str, Any]] = []
        for group_id in sorted(group_ids):
            try:
                group = self.osc.json(
                    "security",
                    "group",
                    "show",
                    group_id,
                    check=False,
                    timeout=min(5, self.config.resource_timeout),
                )
            except (
                SuiteError,
                OSError,
                ValueError,
                TypeError,
                subprocess.SubprocessError,
            ) as exc:
                snapshots.append(
                    {"id": group_id, "readback_error": f"{type(exc).__name__}: {exc}"}
                )
                continue
            if not isinstance(group, dict):
                snapshots.append({"id": group_id, "readback": "unavailable"})
                continue
            snapshots.append(
                {
                    "id": group_id,
                    "name": pick(group, "name"),
                    "description": pick(group, "description"),
                    "rules": pick(
                        group,
                        "security_group_rules",
                        "rules",
                        default=[],
                    ),
                }
            )
        return snapshots

    def _ssh_resource_snapshot(self, address: str, *, proxy: bool) -> dict[str, Any]:
        controller = getattr(self, "controller", None)
        bastion = getattr(self, "bastion", None)
        endpoint = controller if proxy else None
        if (
            endpoint is None
            and bastion is not None
            and address
            in {
                getattr(self, "control_address", None),
                getattr(bastion, "management_ip", None),
                *(getattr(bastion, "fixed_ips", {}) or {}).values(),
            }
        ):
            endpoint = bastion
        if endpoint is None:
            endpoint = controller
        if endpoint is None:
            return {"endpoint": None}

        snapshot: dict[str, Any] = {
            "endpoint": getattr(endpoint, "label", None),
            "server_id": getattr(endpoint, "server_id", None),
            "recorded_host": getattr(endpoint, "host", None),
            "recorded_availability_zone": getattr(endpoint, "availability_zone", None),
            "ports": [],
        }
        server_id = str(getattr(endpoint, "server_id", "") or "")
        if server_id:
            try:
                server = self.osc.json(
                    "server",
                    "show",
                    server_id,
                    check=False,
                    timeout=min(5, self.config.resource_timeout),
                )
            except (
                SuiteError,
                OSError,
                ValueError,
                TypeError,
                subprocess.SubprocessError,
            ) as exc:
                snapshot["server_readback_error"] = f"{type(exc).__name__}: {exc}"
            else:
                if isinstance(server, dict):
                    snapshot["server"] = {
                        "status": pick(server, "status"),
                        "task_state": pick(
                            server, "os_ext_sts_task_state", "task_state"
                        ),
                        "vm_state": pick(server, "os_ext_sts_vm_state", "vm_state"),
                        "power_state": pick(
                            server, "os_ext_sts_power_state", "power_state"
                        ),
                        "host": pick(server, "os_ext_srv_attr_host", "host"),
                        "availability_zone": pick(
                            server,
                            "os_ext_az_availability_zone",
                            "availability_zone",
                        ),
                        "created": pick(server, "created"),
                        "updated": pick(server, "updated"),
                        "addresses": pick(server, "addresses", default={}),
                        "fault": pick(server, "fault", default=None),
                    }
            snapshot["console_log"] = self._server_console_log_snapshot(server_id)

        port_ids = {
            str(getattr(endpoint, "management_port_id", "") or ""),
            str(getattr(endpoint, "test_port_id", "") or ""),
        }
        if endpoint is controller:
            port_ids.update(
                str(item.get("port_id") or "")
                for item in getattr(self, "controller_probe_ports", []) or []
            )
        port_ids.discard("")
        security_group_ids: set[str] = set()
        for port_id in sorted(port_ids):
            try:
                port = self.osc.json(
                    "port",
                    "show",
                    port_id,
                    check=False,
                    timeout=min(5, self.config.resource_timeout),
                )
            except (
                SuiteError,
                OSError,
                ValueError,
                TypeError,
                subprocess.SubprocessError,
            ) as exc:
                snapshot["ports"].append(
                    {
                        "id": port_id,
                        "readback_error": f"{type(exc).__name__}: {exc}",
                    }
                )
                continue
            if not isinstance(port, dict):
                snapshot["ports"].append({"id": port_id, "readback": "unavailable"})
                continue
            port_security_groups = pick(
                port, "security_group_ids", "security_groups", default=[]
            )
            if isinstance(port_security_groups, list):
                security_group_ids.update(
                    str(group_id) for group_id in port_security_groups if group_id
                )
            snapshot["ports"].append(
                {
                    "id": port_id,
                    "status": pick(port, "status"),
                    "device_id": pick(port, "device_id"),
                    "device_owner": pick(port, "device_owner"),
                    "binding_host": pick(port, "binding_host_id", "binding:host_id"),
                    "binding_vif_type": pick(
                        port, "binding_vif_type", "binding:vif_type"
                    ),
                    "fixed_ips": pick(port, "fixed_ips", default=[]),
                    "security_group_ids": port_security_groups,
                }
            )
        snapshot["security_groups"] = self._security_group_readback(security_group_ids)

        test_port_id = str(getattr(endpoint, "test_port_id", "") or "")
        if endpoint is bastion and test_port_id:
            try:
                floating_ips = self.osc.json(
                    "floating",
                    "ip",
                    "list",
                    "--port",
                    test_port_id,
                    check=False,
                    timeout=min(5, self.config.resource_timeout),
                )
            except (
                SuiteError,
                OSError,
                ValueError,
                TypeError,
                subprocess.SubprocessError,
            ) as exc:
                snapshot["floating_ip_readback_error"] = f"{type(exc).__name__}: {exc}"
            else:
                snapshot["floating_ips"] = (
                    floating_ips if isinstance(floating_ips, list) else []
                )
        return snapshot

    def _remember_ssh_readiness(self, key: str, evidence: dict[str, Any]) -> None:
        coordinator = getattr(self, "cloud_operation_coordinator", None)
        with coordinator.lock if coordinator is not None else nullcontext():
            records = dict(getattr(self, "_last_ssh_readiness", {}) or {})
            records[key] = evidence
            self._last_ssh_readiness = records

    def _control_health_guard(self):
        return self.__dict__.setdefault("_control_health_lock", threading.RLock())

    def _is_controller_connect_error(self, error: str) -> bool:
        address = getattr(self, "control_address", None)
        return bool(
            isinstance(address, str)
            and address
            and f"ssh: connect to host {address} port 22:" in error
        )

    def record_controller_ssh_failure(self, error: str) -> dict[str, Any] | None:
        """Capture the failed jump host once per incident, even if guests are unreachable."""
        if not self._is_controller_connect_error(error):
            return None
        return self._capture_controller_failure(error)

    def _capture_controller_failure(self, error: str) -> dict[str, Any]:
        with self._control_health_guard():
            self._controller_recheck_required = True
            cached = getattr(self, "_controller_failure_diagnostics", None)
            if cached is None:
                cached = {
                    **self._collect_ssh_failure_diagnostics(
                        self.control_address, proxy=False
                    ),
                    "observed_error": error,
                    "captured_at": iso_utc(),
                }
                self._controller_failure_diagnostics = cached
            return dict(cached)

    def _require_controller_ssh(self, *, timeout: float = 30.0) -> None:
        """Share one bounded control-path recovery check across endpoint workers."""
        with self._control_health_guard():
            previous_error = getattr(self, "_controller_access_error", None)
            if previous_error:
                raise ControllerUnavailableError(previous_error)
            if self._wait_for_ssh(self.control_address, proxy=False, timeout=timeout):
                self._controller_recheck_required = False
                self._controller_failure_diagnostics = None
                return
            evidence = self._capture_controller_failure(
                str(
                    self._ssh_readiness_evidence(self.control_address, proxy=False).get(
                        "last_error"
                    )
                    or "SSH readiness failed"
                )
            )
            message = (
                f"Controller SSH at {self.control_address} is unavailable after a "
                f"{timeout:g}s recovery check; endpoint provisioning stopped in this "
                "scope. Controller transport, server, port and console diagnostics "
                "were recorded; no tested-network failure was inferred."
            )
            self._controller_access_error = message
            self.reporter.event(
                "controller-access-lost",
                message,
                address=self.control_address,
                diagnostics=evidence,
                authoritative=False,
                tool_failure=True,
            )
            raise ControllerUnavailableError(message)

    def _collect_ssh_failure_diagnostics(
        self,
        address: str,
        *,
        proxy: bool,
    ) -> dict[str, Any]:
        """Collect bounded evidence after the readiness deadline has ended."""

        try:
            transport = (
                self._probe_proxy_ssh_transport(address, timeout=5.0)
                if proxy
                else self._probe_direct_ssh_transport(
                    address,
                    timeout=3.0,
                    include_ping=True,
                )
            )
        except RunCancelledError:
            raise
        except (
            SuiteError,
            OSError,
            ValueError,
            TypeError,
            subprocess.SubprocessError,
        ) as exc:
            transport = {
                "classification": "diagnostic-error",
                "error": f"{type(exc).__name__}: {exc}",
            }
        snapshot = self._ssh_resource_snapshot(address, proxy=proxy)
        evidence = {
            "address": address,
            "proxy": proxy,
            "transport": transport,
            "openstack_readback": snapshot,
            "controller_host": getattr(getattr(self, "controller", None), "host", None),
            "bastion_host": getattr(getattr(self, "bastion", None), "host", None),
            "authoritative": False,
            "tool_failure": True,
        }
        diagnostics = list(getattr(self, "controller_bootstrap_diagnostics", []) or [])
        diagnostics.append(evidence)
        self.controller_bootstrap_diagnostics = diagnostics
        self.reporter.event(
            "ssh-readiness-diagnostics",
            "Collected bounded SSH transport and OpenStack readback evidence after the readiness deadline; no cloud networking verdict was inferred",
            **evidence,
        )
        return evidence

    def _wait_for_ssh(
        self, address: str, *, proxy: bool, timeout: float | None = None
    ) -> bool:
        total_timeout = max(
            0.0,
            float(timeout if timeout is not None else self.config.resource_timeout),
        )
        started = time.monotonic()
        deadline = started + total_timeout
        next_progress = started
        attempts = 0
        last_error = ""
        attempt_errors: list[str] = []
        tcp_reachability_observed = False
        network_path_failure_observed = False
        route = "through controller" if proxy else "directly"
        while True:
            raise_if_cancelled()
            now = time.monotonic()
            remaining = deadline - now
            if remaining <= 0:
                break
            attempts += 1
            connect_timeout = max(
                1,
                min(self.config.ssh_timeout, int(math.ceil(remaining))),
            )
            attempt_timeout = max(
                0.1,
                min(remaining, float(connect_timeout + 5)),
            )
            try:
                result = run_cancellable(
                    [
                        *self._ssh_base(
                            address,
                            proxy=proxy,
                            connect_timeout=connect_timeout,
                        ),
                        "true",
                    ],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=attempt_timeout,
                    check=False,
                )
                if result.returncode == 0:
                    elapsed = min(total_timeout, max(0.0, time.monotonic() - started))
                    self.logger.log(
                        f"SSH ready {route} at {address} after {int(elapsed)}s "
                        f"({attempts} attempt(s))"
                    )
                    evidence = {
                        "address": address,
                        "proxy": proxy,
                        "attempts": attempts,
                        "elapsed_seconds": elapsed,
                        "ready": True,
                    }
                    self._remember_ssh_readiness(f"{proxy}:{address}", evidence)
                    self.reporter.event(
                        "ssh-readiness-complete",
                        "SSH readiness completed within the configured deadline",
                        **evidence,
                        authoritative=True,
                    )
                    return True
                error_lines = (
                    (result.stderr or result.stdout or "").strip().splitlines()
                )
                last_error = error_lines[-1] if error_lines else "SSH command failed"
                if proxy and self._is_controller_connect_error(result.stderr or ""):
                    self._require_controller_ssh(
                        timeout=min(30.0, max(0.0, deadline - time.monotonic()))
                    )
                attempt_classification = self._classify_ssh_attempt_error(last_error)
                if attempt_classification == "tcp-reachable-ssh-not-ready":
                    tcp_reachability_observed = True
                elif attempt_classification == "network-path-unavailable":
                    network_path_failure_observed = True
                if last_error and last_error not in attempt_errors:
                    attempt_errors.append(last_error)
                    attempt_errors = attempt_errors[-10:]
            except subprocess.TimeoutExpired:
                last_error = "SSH attempt reached the remaining readiness deadline"
            except RunCancelledError:
                raise

            now = time.monotonic()
            if now >= next_progress:
                elapsed = min(total_timeout, max(0.0, now - started))
                self.logger.log(
                    f"Waiting for SSH {route} at {address}: attempts={attempts}, "
                    f"elapsed={int(elapsed)}s/{int(total_timeout)}s"
                    + (f", last_error={last_error}" if last_error else "")
                )
                next_progress = now + self.config.progress_interval
            raise_if_cancelled()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(5.0, remaining))

        elapsed = min(total_timeout, max(0.0, time.monotonic() - started))
        evidence = {
            "address": address,
            "proxy": proxy,
            "timeout_seconds": total_timeout,
            "attempts": attempts,
            "readiness_elapsed_seconds": elapsed,
            "last_error": last_error or None,
            "attempt_errors": attempt_errors,
            "tcp_reachability_observed": tcp_reachability_observed,
            "network_path_failure_observed": network_path_failure_observed,
            "path_classification": (
                "tcp-reachable-ssh-not-ready"
                if tcp_reachability_observed
                else (
                    "network-path-unavailable"
                    if network_path_failure_observed
                    else "undetermined"
                )
            ),
            "ready": False,
        }
        self._remember_ssh_readiness(f"{proxy}:{address}", evidence)
        if tcp_reachability_observed:
            failure_summary = (
                f"TCP reached {address}, but its SSH service did not become ready "
                f"{route} within {int(total_timeout)}s"
            )
        elif network_path_failure_observed:
            failure_summary = (
                f"No TCP path to SSH became available {route} at {address} "
                f"within {int(total_timeout)}s"
            )
        else:
            failure_summary = (
                f"SSH readiness remained undetermined {route} at {address} "
                f"after {int(total_timeout)}s"
            )
        self.logger.log(
            f"{failure_summary}; attempts={attempts}; "
            f"last_error={last_error or 'unknown'}",
            "WARNING",
        )
        self.reporter.event(
            "ssh-readiness-timeout",
            "SSH readiness did not complete within the configured deadline; no cloud networking verdict was inferred",
            **evidence,
            authoritative=False,
            tool_failure=True,
        )
        return False
