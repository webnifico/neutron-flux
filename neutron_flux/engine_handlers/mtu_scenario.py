from __future__ import annotations

import json
import shlex
import subprocess
from typing import Any

from ..errors import RunCancelledError, SuiteError
from ..models import Endpoint, ProbeResult, TestSpec
from ..mtu_contract import positive_mtu, route_mtu_from_evidence
from ..pmtu_cache import route_cache_reset_code


class MTUScenarioHandlerMixin:
    """Run the valid-boundary and oversized checks as one atomic scenario."""

    def _reset_standard_mtu_route_cache(
        self,
        source: Endpoint,
        source_ip: str,
        destination_ip: str,
        family: int,
        expected_mtu: int,
    ) -> dict[str, Any]:
        ssh_endpoint = getattr(getattr(self, "builder", None), "ssh_endpoint", None)
        if not callable(ssh_endpoint):
            # Extracted/offline handler tests do not provide an SSH-capable
            # builder. A real cloud endpoint always does.
            return {
                "attempted": False,
                "verified": True,
                "status": "not-applicable-offline-test-double",
                "family": family,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
            }
        code = route_cache_reset_code(source_ip, destination_ip, family, expected_mtu)
        command = "python3 -c " + shlex.quote(code)
        try:
            result = ssh_endpoint(source, command, timeout=30)
            stdout = (result.stdout or "").strip()
            stderr = (result.stderr or "").strip()
            if result.returncode != 0:
                output_lines = (stderr or stdout).splitlines()
                detail = output_lines[-1] if output_lines else "no command output"
                raise SuiteError(
                    f"route/PMTU cache reset failed on {source.label}: {detail}"
                )
            lines = [line for line in stdout.splitlines() if line.strip()]
            if not lines:
                raise SuiteError(
                    f"route/PMTU cache reset on {source.label} returned no JSON"
                )
            value = json.loads(lines[-1])
            if not isinstance(value, dict):
                raise SuiteError("route/PMTU cache reset JSON must be an object")
            return value
        except RunCancelledError:
            raise
        except (
            json.JSONDecodeError,
            OSError,
            SuiteError,
            subprocess.SubprocessError,
        ) as exc:
            return {
                "attempted": True,
                "verified": False,
                "error": f"{type(exc).__name__}: {exc}",
                "family": family,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
            }

    @staticmethod
    def _mtu_stage(probe: ProbeResult, status: str, message: str) -> dict[str, Any]:
        return {
            "status": status,
            "message": message,
            "outcome": probe.outcome,
            "success": probe.success,
            "attempts": probe.attempts,
            "elapsed_ms": probe.elapsed_ms,
            "command": probe.command,
            "stdout": probe.stdout,
            "stderr": probe.stderr,
            "diagnostics": probe.diagnostics,
        }

    @staticmethod
    def _mtu_not_run(message: str) -> dict[str, Any]:
        return {
            "status": "NOT_RUN",
            "message": message,
            "outcome": "not-run",
            "success": False,
            "attempts": 0,
            "elapsed_ms": 0,
            "command": "",
            "stdout": "",
            "stderr": "",
            "diagnostics": {},
        }

    @staticmethod
    def _local_mtu_message(probe: ProbeResult, *, oversized: bool) -> str:
        packet_size = int(probe.diagnostics.get("packet_size") or 0)
        evidence = probe.diagnostics.get("local_mtu_evidence") or {}
        interface = evidence.get("selected_interface") or "unknown interface"
        interface_mtu = evidence.get("source_interface_mtu")
        route_mtu = evidence.get("route_mtu")
        if oversized:
            return (
                f"The source guest correctly rejected the {packet_size}-byte "
                "oversized DF packet locally before transmission"
            )
        measurements = [f"interface={interface}"]
        if interface_mtu is not None:
            measurements.append(f"interface_mtu={interface_mtu}")
        if route_mtu is not None:
            measurements.append(f"route_mtu={route_mtu}")
        route_mtu = route_mtu_from_evidence(
            evidence if isinstance(evidence, dict) else {}
        )
        if route_mtu is not None:
            return (
                f"The source guest had a cached per-destination route PMTU of "
                f"{route_mtu} bytes and rejected the {packet_size}-byte DF packet "
                "before transmission; the current end-to-end path boundary was "
                f"not independently measured ({', '.join(measurements)})"
            )
        return (
            f"The source guest rejected the valid {packet_size}-byte DF packet "
            "locally before transmission; the current path boundary was not "
            f"independently measured ({', '.join(measurements)})"
        )

    @staticmethod
    def _local_mtu_classification(
        probe: ProbeResult, network_mtu: int
    ) -> tuple[str, str]:
        evidence = probe.diagnostics.get("local_mtu_evidence") or {}
        if not isinstance(evidence, dict):
            evidence = {}
        route_mtu = route_mtu_from_evidence(evidence)
        interface_mtu = positive_mtu(evidence.get("source_interface_mtu"))
        if (
            route_mtu is not None
            and route_mtu < network_mtu
            and (interface_mtu is None or route_mtu < interface_mtu)
        ):
            return "UNVERIFIED", "cached-route-pmtu-observed"
        if interface_mtu is not None and interface_mtu < network_mtu:
            return "PASS", "source-interface-mtu-below-advertised"
        return "UNVERIFIED", "local-mtu-constraint-unverified"

    def _run_mtu_scenario(self, spec: TestSpec) -> None:
        source, source_ip = self._endpoint_address(
            spec.source_group_id, spec.source_side, spec.source_subnet_id
        )
        destination, destination_ip = self._endpoint_address(
            spec.destination_group_id,
            spec.destination_side,
            spec.destination_subnet_id,
        )
        family = int(spec.family)
        observation_resolver = getattr(self, "_network_mtu_observation", None)
        if callable(observation_resolver):
            mtu_observation = dict(
                observation_resolver(spec.source_group_id, spec.source_side)
            )
            network_mtu = int(mtu_observation["effective_mtu"])
        else:
            # Compatibility for extracted handlers and older test harnesses.
            network_mtu = int(self._network_mtu(spec.source_group_id))
            mtu_observation = {
                "effective_mtu": network_mtu,
                "reported_mtu": network_mtu,
                "authoritative": True,
                "authority": "runtime network MTU resolver",
                "fallback_used": False,
            }
        mtu_contract_authoritative = bool(
            mtu_observation.get("authoritative")
            and not mtu_observation.get("fallback_used")
        )

        route_pmtu_cache_reset = self._reset_standard_mtu_route_cache(
            source,
            source_ip,
            destination_ip,
            family,
            network_mtu,
        )
        boundary = self.probes.endpoint(
            "mtu",
            source,
            source_ip,
            destination_ip,
            family,
            network_mtu=network_mtu,
        )
        oversized: ProbeResult | None = None
        likely_failure = None
        diagnostic_details: dict[str, Any] = {}
        advisory = False

        if boundary.outcome == "reachable" and boundary.success:
            boundary_stage = self._mtu_stage(
                boundary,
                "PASS",
                f"The valid {network_mtu}-byte DF packet crossed the VM-to-VM path",
            )
            oversized = self.probes.endpoint(
                "mtu+1",
                source,
                source_ip,
                destination_ip,
                family,
                network_mtu=network_mtu,
            )
            if oversized.outcome == "local-mtu-rejected":
                oversized_stage = self._mtu_stage(
                    oversized,
                    "PASS",
                    self._local_mtu_message(oversized, oversized=True),
                )
                status = "PASS"
                observed = "boundary-confirmed"
                message = (
                    f"The {network_mtu}-byte packet crossed the path; the source "
                    f"rejected the {network_mtu + 1}-byte packet locally before "
                    "transmission. The path above the advertised MTU was not tested."
                )
            elif oversized.outcome == "error":
                oversized_stage = self._mtu_stage(
                    oversized,
                    "ERROR",
                    "The oversized-packet probe could not execute correctly",
                )
                status = "ERROR"
                observed = "oversized-probe-error"
                message = oversized.stderr or "The oversized-packet probe failed"
            elif oversized.outcome == "inconclusive":
                status = "UNVERIFIED"
                observed = "oversized-probe-inconclusive"
                message = "The oversized-packet probe produced ambiguous evidence"
                oversized_stage = self._mtu_stage(oversized, status, message)
            else:
                oversized_stage = self._mtu_stage(
                    oversized,
                    "PASS",
                    (
                        "The oversized packet was not rejected locally; "
                        f"observed outcome was {oversized.outcome}"
                    ),
                )
                status = "PASS"
                advisory = True
                observed = "oversized-not-locally-rejected"
                message = (
                    f"The valid {network_mtu}-byte packet crossed the path, but the "
                    f"{network_mtu + 1}-byte packet was not rejected locally"
                )
        else:
            if boundary.outcome == "packet-too-big":
                feedback = boundary.diagnostics.get("packet_too_big_feedback") or []
                reported = sorted({int(item["mtu"]) for item in feedback})
                boundary_message = (
                    f"The {network_mtu}-byte DF packet received fresh ICMP "
                    f"Packet Too Big / fragmentation-needed feedback reporting MTU "
                    f"{', '.join(map(str, reported)) or 'unknown'} bytes; "
                    "the advertised packet size did not cross the path"
                )
                status = "PASS"
                advisory = True
                observed = "path-mtu-below-advertised"
            elif boundary.outcome == "local-mtu-rejected":
                boundary_message = self._local_mtu_message(boundary, oversized=False)
                status, observed = self._local_mtu_classification(boundary, network_mtu)
                advisory = status == "PASS"
            elif boundary.outcome == "error":
                boundary_message = (
                    "The valid MTU-boundary probe could not execute correctly"
                )
                status = "ERROR"
                observed = "boundary-probe-error"
            elif boundary.outcome == "inconclusive":
                boundary_message = (
                    "The valid MTU-boundary probe produced ambiguous evidence"
                )
                status = "UNVERIFIED"
                observed = "boundary-inconclusive"
            else:
                boundary_message = (
                    f"The valid {network_mtu}-byte DF packet did not cross the path; "
                    f"observed outcome was {boundary.outcome}"
                )
                status = "FAIL"
                observed = "valid-boundary-failed"
            boundary_stage = self._mtu_stage(boundary, status, boundary_message)
            oversized_stage = self._mtu_not_run(
                "The oversized-packet subcheck was unnecessary because the "
                "advertised-size packet did not cross the path"
            )
            message = boundary_message

        if advisory:
            message += "; advisory MTU observation; remaining tests may continue"
        diagnostic_status = status
        if diagnostic_status in {"FAIL", "ERROR"}:
            diagnostic_probe = (
                oversized
                if oversized is not None and diagnostic_status != "PASS"
                else boundary
            )
            likely_failure, diagnostic_details = self.diagnostics.collect(
                spec, diagnostic_probe or boundary, source, destination
            )

        if not mtu_contract_authoritative and status != "ERROR":
            status = "UNVERIFIED"
            message = (
                f"Neutron did not expose an authoritative network MTU; "
                f"{network_mtu} bytes was used only as a diagnostic probe bound. "
                f"Observed diagnostic outcome: {message}"
            )

        details = {
            "phase": spec.phase,
            "address_path": self._address_evidence(spec, boundary, source, destination),
            "expectation_reason": spec.expectation_reason,
            "dependencies": spec.dependencies,
            **spec.metadata,
            "network_mtu": network_mtu,
            "network_mtu_observation": mtu_observation,
            "mtu_contract_authoritative": mtu_contract_authoritative,
            "mtu_advisory": advisory,
            "health": "warning"
            if advisory and status == "PASS"
            else (
                "good"
                if status == "PASS"
                else "unverified"
                if status == "UNVERIFIED"
                else "critical"
            ),
            "warning_reasons": [message] if advisory else [],
            "route_pmtu_cache_reset": route_pmtu_cache_reset,
            "route_pmtu_cache_reset_verified": bool(
                route_pmtu_cache_reset.get("verified")
            ),
            "diagnostic_probe_status": diagnostic_status,
            "source_compute_host": source.host,
            "destination_compute_host": destination.host,
            "source_availability_zone": source.availability_zone,
            "destination_availability_zone": destination.availability_zone,
            "compute_placement": (
                "same compute host"
                if source.host and destination.host and source.host == destination.host
                else "different compute hosts"
                if source.host and destination.host
                else "compute placement unavailable"
            ),
            "stages": {
                "valid_boundary": boundary_stage,
                "oversized_rejection": oversized_stage,
            },
            **diagnostic_details,
        }
        duration_ms = boundary.elapsed_ms + (oversized.elapsed_ms if oversized else 0)
        self.reporter.result(
            spec.id,
            spec.category,
            status,
            message,
            family=family,
            source=f"{source.label} ({source_ip})",
            destination=f"{destination.label} ({destination_ip})",
            duration_ms=duration_ms,
            details=details,
            expected=spec.expectation,
            observed=observed,
            authoritative=(mtu_contract_authoritative and status != "UNVERIFIED"),
            likely_failure=likely_failure,
            display_name=spec.display_name,
            scenario=spec.scenario,
        )
