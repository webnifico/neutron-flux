from __future__ import annotations

import json
from typing import Any

from .errors import RunCancelledError, SSHExecutionError, SuiteError
from .execution_diagnostics import capture_execution_diagnostics
from .models import Endpoint, ProbeResult, TestSpec
from .operator_evidence import diagnostic_snapshot
from .operator_evidence import text as diagnostic_text
from .results_io import atomic_write_text
from .utils import unique_safe_name


class DiagnosticCollector:
    def __init__(
        self,
        builder: Any,
        reporter: Any,
        *,
        endpoint_builders: dict[str, Any] | None = None,
    ):
        self.builder = builder
        self.reporter = reporter
        self.endpoint_builders = dict(endpoint_builders or {})

    def _builder_for(self, endpoint: Endpoint) -> Any:
        return self.endpoint_builders.get(endpoint.server_id, self.builder)

    @staticmethod
    def _failed_collection_text(
        endpoint: Endpoint,
        error: str,
        *,
        raw_excerpt: str | None = None,
    ) -> str:
        lines = [
            "NEUTRON FLUX DIAGNOSTIC COLLECTION FAILED",
            f"endpoint={endpoint.label}",
            f"server_id={endpoint.server_id}",
            f"management_ip={endpoint.management_ip or 'unavailable'}",
            f"error={error}",
        ]
        if raw_excerpt:
            lines.extend(["", "raw_error_excerpt:", raw_excerpt.strip()[:4000]])
        return "\n".join(lines).rstrip() + "\n"

    def collect(
        self,
        spec: TestSpec,
        probe: ProbeResult,
        source: Endpoint | None,
        destination: Endpoint | None,
    ) -> tuple[str | None, dict[str, Any]]:
        likely = self._classify(probe)
        execution = (getattr(probe, "diagnostics", {}) or {}).get(
            "execution_error"
        ) or {}
        if execution.get("exception_type") == "SSHExecutionError":
            try:
                details = capture_execution_diagnostics(
                    self.builder,
                    self.reporter,
                    spec.id,
                    tuple(endpoint for endpoint in (source, destination) if endpoint),
                    SSHExecutionError(probe.stderr, evidence=execution),
                    endpoint_builders=self.endpoint_builders,
                )
            except RunCancelledError:
                raise
            except (
                RuntimeError,
                OSError,
                ValueError,
                TypeError,
                AttributeError,
            ) as exc:
                details = {"diagnostic_collection_error": str(exc)}
            details["diagnostic_classification"] = {
                "code": "CONTROL_SSH",
                "basis": "SSH command execution did not complete",
                "causal_claim": False,
            }
            return "CONTROL_SSH", details
        failures_dir = self.reporter.run_dir / "failures"
        if failures_dir.is_symlink():
            raise SuiteError(
                f"Failure diagnostics directory must not be a symbolic link: {failures_dir}"
            )
        output_dir = failures_dir / unique_safe_name(spec.id, 120)
        if output_dir.is_symlink():
            raise SuiteError(
                f"Failure diagnostic directory must not be a symbolic link: {output_dir}"
            )
        output_dir.mkdir(parents=True, exist_ok=True)
        payload: dict[str, Any] = {
            "test": spec.id,
            "category": spec.category,
            "diagnostic_classification": {
                "code": likely,
                "basis": "observed probe symptom pattern",
                "causal_claim": False,
            },
            "probe": {
                "outcome": probe.outcome,
                "command": probe.command,
                "stdout": probe.stdout,
                "stderr": probe.stderr,
                "source_ip": probe.source_ip,
                "destination_ip": probe.destination_ip,
                "protocol": probe.protocol,
                "elapsed_ms": probe.elapsed_ms,
                "attempts": probe.attempts,
            },
            "guests": {},
            "openstack": {},
        }
        if likely == "CONTROL_SSH":
            controls = {}
            for endpoint in (source, destination):
                if endpoint is None:
                    continue
                owner = self._builder_for(endpoint)
                capture = getattr(owner, "record_controller_ssh_failure", None)
                if callable(capture):
                    evidence = capture(probe.stderr or "")
                    if isinstance(evidence, dict):
                        controls[str(evidence.get("address"))] = evidence
            if controls:
                payload["control_paths"] = controls
        command = (
            "set +e; "
            "echo '### ip -br addr'; ip -br addr; "
            "echo '### ip route show table all'; ip route show table all; "
            "echo '### ip -6 route show table all'; ip -6 route show table all; "
            "echo '### ip rule'; ip rule; "
            "echo '### ip -6 rule'; ip -6 rule; "
            "echo '### ip neigh'; ip neigh; "
            "echo '### ip -6 neigh'; ip -6 neigh; "
            "echo '### tentative'; ip -6 addr show tentative; "
            "echo '### sockets'; ss -lntup; "
            "echo '### cloud-init'; cloud-init status --long 2>&1 || true"
        )
        for role, endpoint in (("source", source), ("destination", destination)):
            if not endpoint:
                continue
            owner = self._builder_for(endpoint)
            collection: dict[str, Any]
            try:
                result = owner.ssh_endpoint(endpoint, command)
                stdout = result.stdout or ""
                stderr = result.stderr or ""
                raw = (stdout + ("\nSTDERR:\n" + stderr if stderr else "")).strip()
                unusable_forwarding = "stdio forwarding failed" in raw.lower()
                if int(result.returncode) != 0 or unusable_forwarding:
                    reason = (
                        "SSH stdio forwarding failed before guest diagnostics could be collected"
                        if unusable_forwarding
                        else f"SSH diagnostic command exited with status {result.returncode}"
                    )
                    text = self._failed_collection_text(
                        endpoint, reason, raw_excerpt=raw
                    )
                    collection = {
                        "status": "failed",
                        "usable": False,
                        "error": reason,
                        "returncode": int(result.returncode),
                        "raw_error_excerpt": raw[:4000],
                    }
                else:
                    text = raw + ("\n" if raw else "")
                    collection = {
                        "status": "collected",
                        "usable": True,
                        "returncode": int(result.returncode),
                    }
            except RunCancelledError:
                raise
            except Exception as exc:
                reason = f"{type(exc).__name__}: {exc}"
                text = self._failed_collection_text(endpoint, reason)
                collection = {
                    "status": "failed",
                    "usable": False,
                    "error": reason,
                    "returncode": None,
                }
            payload["guests"][role] = {
                "label": endpoint.label,
                "server_id": endpoint.server_id,
                "management_ip": endpoint.management_ip,
                "output_file": f"{role}.txt",
                "output": diagnostic_text(text, 16000),
                "controller_scope": getattr(owner, "availability_zone", None),
                **collection,
            }
            atomic_write_text(output_dir / f"{role}.txt", text)
            for resource_type, resource_id in (
                ("server", endpoint.server_id),
                ("port", endpoint.test_port_id),
                ("port", endpoint.management_port_id),
            ):
                if not resource_id:
                    continue
                key = f"{role}-{resource_type}-{resource_id}"
                try:
                    detail = owner.osc.json(
                        resource_type, "show", resource_id, check=False
                    )
                except RunCancelledError:
                    raise
                except Exception as exc:
                    detail = {"error": str(exc)}
                payload["openstack"][key] = detail
        atomic_write_text(
            output_dir / "diagnostics.json",
            json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n",
        )
        return likely, {
            "diagnostic_directory": str(output_dir),
            "diagnostic_snapshot": diagnostic_snapshot(payload),
            "diagnostic_classification": {
                "code": likely,
                "basis": "observed probe symptom pattern",
                "causal_claim": False,
                "interpretation": (
                    "Diagnostic classification only; this is not a proven root cause."
                ),
            },
        }

    @staticmethod
    def _classify(probe: ProbeResult) -> str:
        text = f"{probe.stdout}\n{probe.stderr}".lower()
        if probe.outcome == "error" and (
            "ssh:" in text or "stdio forwarding failed" in text
        ):
            return "CONTROL_SSH"
        if "no route to host" in text or "network is unreachable" in text:
            return "ROUTING"
        if "destination host unreachable" in text:
            return "ARP" if probe.source_ip and ":" not in probe.source_ip else "NDP"
        if "address unreachable" in text:
            return "NDP"
        if "connection refused" in text:
            return "PROBE_SERVICE"
        if "timed out" in text or "100% packet loss" in text:
            return "UNATTRIBUTED"
        if "permission denied" in text:
            return "CONTROL_SSH"
        return "UNATTRIBUTED"
