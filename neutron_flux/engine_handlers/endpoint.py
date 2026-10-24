from __future__ import annotations

# mypy: disable-error-code="attr-defined"
from ..errors import RunCancelledError, SuiteError
from ..models import Endpoint, ProbeResult, TestSpec
from ..network_contract import (
    PROJECT_PROVIDER_CONNECTIVITY,
    ROUTER_STATIC_ROUTING,
    canonical_category,
    static_route_state_key,
)


class EndpointProbeHandlerMixin:
    """Compatibility mixin for this test-operation family."""

    def _destination_tcp_attestation(
        self,
        destination: Endpoint,
        family: int,
    ) -> dict[str, object] | None:
        """Prove the exact destination token service over guest loopback.

        A listening socket in a diagnostic snapshot is not enough to distinguish
        a network block from a stalled Flux echo service. The health exchange
        validates the endpoint-specific probe ID and returns the process instance
        identity used to bracket a blocked remote observation.
        """
        checker = getattr(
            getattr(self, "builder", None), "_existing_probe_service_ready", None
        )
        if not callable(checker):
            # Compatibility for offline handler test doubles. Production resource
            # builders always expose the endpoint health exchange.
            return None
        try:
            overall_ready, evidence = checker(destination)
        except RunCancelledError:
            raise
        except (AttributeError, OSError, SuiteError, TypeError, ValueError) as exc:
            return {
                "status": "unavailable",
                "family": family,
                "endpoint": destination.label,
                "server_id": destination.server_id,
                "inspection_complete": False,
                "error": f"{type(exc).__name__}: {exc}",
            }

        payload = evidence if isinstance(evidence, dict) else {}
        listeners = payload.get("listeners")
        listener = None
        if isinstance(listeners, dict):
            candidate = listeners.get(str(family), listeners.get(family))
            listener = candidate if isinstance(candidate, dict) else None
        inspection_complete = bool(
            payload.get("inspection_complete") is True and listener is not None
        )
        instance_id = listener.get("instance_id") if listener else None
        healthy = bool(listener and listener.get("tcp") and instance_id)
        status = (
            "healthy"
            if healthy
            else "unhealthy"
            if inspection_complete
            else "unavailable"
        )
        return {
            "status": status,
            "family": family,
            "endpoint": destination.label,
            "server_id": destination.server_id,
            "inspection_complete": inspection_complete,
            "instance_id": instance_id,
            "tcp_ready": bool(listener and listener.get("tcp")),
            "overall_tcp_udp_ready": bool(overall_ready),
            "evidence": payload,
        }

    @staticmethod
    def _apply_blocked_tcp_attestation(
        probe: ProbeResult,
        before: dict[str, object] | None,
        after: dict[str, object] | None,
    ) -> None:
        """Accept BLOCKED only when one healthy service instance brackets it."""
        if probe.outcome != "blocked" or before is None:
            return
        before_status = str(before.get("status") or "unavailable")
        after_status = str((after or {}).get("status") or "unavailable")
        before_identity = str(before.get("instance_id") or "")
        after_identity = str((after or {}).get("instance_id") or "")
        stable_identity = bool(
            before_status == "healthy"
            and after_status == "healthy"
            and before_identity
            and before_identity == after_identity
        )
        attestation = {
            "required": True,
            "before": before,
            "after": after,
            "stable_instance_identity": stable_identity,
            "network_observation_accepted": stable_identity,
        }
        probe.diagnostics["destination_tcp_service_attestation"] = attestation
        if stable_identity:
            return

        probe.diagnostics["raw_outcome_before_service_attestation"] = "blocked"
        probe.success = False
        if "unhealthy" in {before_status, after_status}:
            probe.outcome = "error"
            explanation = (
                "destination Flux TCP token service failed its local health "
                "attestation; the remote block is not a valid network verdict"
            )
        else:
            probe.outcome = "inconclusive"
            explanation = (
                "destination Flux TCP token service identity could not be proven "
                "stable around the remote block"
            )
        probe.stderr = "\n".join(
            value for value in (probe.stderr.strip(), explanation) if value
        )

    def _run_endpoint_probe(self, spec: TestSpec) -> None:
        if canonical_category(spec.category) == ROUTER_STATIC_ROUTING:
            state = self.lifecycle.get(
                static_route_state_key(spec.destination_group_id)
            )
            if state is None:
                state = self.lifecycle.get(f"extra-route:{spec.destination_group_id}")
            if not state or not state.get("routes_installed"):
                source, source_ip = self._endpoint_address(
                    spec.source_group_id, spec.source_side, spec.source_subnet_id
                )
                destination, destination_ip = self._endpoint_address(
                    spec.destination_group_id,
                    spec.destination_side,
                    spec.destination_subnet_id,
                )
                spec.authoritative = False
                spec.metadata["authority_required"] = True
                spec.expectation_reason = (
                    "the OpenStack router static routes were not installed "
                    "successfully, so this routed probe is unverified"
                )
                probe = ProbeResult(
                    outcome="inconclusive",
                    success=False,
                    elapsed_ms=0,
                    attempts=0,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    protocol=spec.protocol,
                    diagnostics={
                        "route_setup_error": (state or {}).get("route_setup_error"),
                        "not_executed": True,
                        "blocked_by": "static-route-install",
                    },
                )
                self._record(spec, probe, source, destination)
                return
        source, source_ip = self._endpoint_address(
            spec.source_group_id, spec.source_side, spec.source_subnet_id
        )
        destination, destination_ip = self._endpoint_address(
            spec.destination_group_id, spec.destination_side, spec.destination_subnet_id
        )
        if spec.metadata.get("require_no_floating_ip"):
            source_group = self._group(spec.source_group_id)
            if source_group.fips or source_group.source_nat_enabled is not True:
                raise SuiteError(
                    "Router-SNAT baseline requires enabled source NAT and no floating IP"
                )
        policy = spec.metadata.get("routing_policy") or {}
        if policy.get("basis") == "router-default-snat":
            source_group = self._group(spec.source_group_id)
            if source_group.source_nat_enabled is not True:
                spec.authoritative = False
                spec.expectation = "observation"
                spec.expectation_reason = (
                    "the router's source NAT setting was not verified enabled; "
                    "fixed-IP routing is observed without asserting connectivity"
                )
                spec.metadata["routing_policy"] = {
                    "basis": "source-nat-not-verified",
                    "expectation": "observation",
                    "authoritative": False,
                    "reason": spec.expectation_reason,
                }
        # Only packet-size probes consume the Neutron MTU. Ordinary ICMP,
        # TCP and UDP probes must not issue an unused API read on every run.
        mtu = (
            self._network_mtu(spec.source_group_id, spec.source_side)
            if str(spec.protocol) in {"mtu", "mtu+1"}
            else None
        )
        if str(spec.protocol) == "mtu+1":
            prerequisite_id = spec.id.replace("MTU-LOCAL-LIMIT-", "MTU-BOUNDARY-", 1)
            prerequisite = None
            reporter = getattr(self, "reporter", None)
            if reporter is not None and hasattr(reporter, "get_result"):
                prerequisite = reporter.get_result(prerequisite_id)
            if prerequisite is not None and prerequisite.status != "PASS":
                spec.authoritative = False
                spec.metadata["authority_required"] = True
                spec.expectation_reason = (
                    "the oversized-packet test was not evaluated because the valid "
                    "MTU boundary packet had already failed"
                )
                probe = ProbeResult(
                    outcome="inconclusive",
                    success=False,
                    elapsed_ms=0,
                    attempts=0,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    protocol="mtu+1",
                    diagnostics={
                        "prerequisite_test_id": prerequisite_id,
                        "prerequisite_status": prerequisite.status,
                        "prerequisite_observed": prerequisite.observed,
                    },
                )
                self._record(spec, probe, source, destination)
                return
            if prerequisite is None:
                baseline = self.probes.endpoint(
                    "mtu",
                    source,
                    source_ip,
                    destination_ip,
                    int(spec.family),
                    network_mtu=mtu,
                )
                if not (baseline.success and baseline.outcome == "reachable"):
                    spec.authoritative = False
                    spec.metadata["authority_required"] = True
                    spec.expectation_reason = (
                        "the oversized-packet test was not evaluated because the valid "
                        "MTU boundary packet failed immediately beforehand"
                    )
                    probe = ProbeResult(
                        outcome="inconclusive",
                        success=False,
                        elapsed_ms=baseline.elapsed_ms,
                        attempts=baseline.attempts,
                        stdout=baseline.stdout,
                        stderr=baseline.stderr,
                        command=baseline.command,
                        source_ip=source_ip,
                        destination_ip=destination_ip,
                        protocol="mtu+1",
                        diagnostics={
                            "prerequisite_test_id": prerequisite_id,
                            "inline_prerequisite_outcome": baseline.outcome,
                            "inline_prerequisite_success": baseline.success,
                        },
                    )
                    self._record(spec, probe, source, destination)
                    return
        require_tcp_attestation = bool(
            canonical_category(spec.category) == PROJECT_PROVIDER_CONNECTIVITY
            and str(spec.protocol).lower() == "tcp"
        )
        tcp_attestation_before = (
            self._destination_tcp_attestation(destination, int(spec.family))
            if require_tcp_attestation
            else None
        )
        probe = self.probes.endpoint(
            str(spec.protocol),
            source,
            source_ip,
            destination_ip,
            int(spec.family),
            network_mtu=mtu,
        )
        if require_tcp_attestation:
            if probe.outcome == "blocked":
                tcp_attestation_after = self._destination_tcp_attestation(
                    destination, int(spec.family)
                )
                self._apply_blocked_tcp_attestation(
                    probe,
                    tcp_attestation_before,
                    tcp_attestation_after,
                )
            elif tcp_attestation_before is not None:
                probe.diagnostics["destination_tcp_service_attestation"] = {
                    "required": False,
                    "reason": (
                        "the successful token echo directly proved the destination "
                        "service"
                        if probe.outcome == "reachable"
                        else "the raw probe was already an execution error"
                    ),
                    "before": tcp_attestation_before,
                    "network_observation_accepted": probe.outcome == "reachable",
                }
        message = None
        if probe.outcome == "local-mtu-rejected":
            packet_size = int(probe.diagnostics.get("packet_size") or 0)
            evidence = probe.diagnostics.get("local_mtu_evidence") or {}
            interface = evidence.get("selected_interface") or "unknown interface"
            interface_mtu = evidence.get("source_interface_mtu")
            route_mtu = evidence.get("route_mtu")
            if str(spec.protocol) == "mtu+1":
                message = (
                    f"The source guest correctly rejected the {packet_size}-byte "
                    "oversized DF packet locally before transmission"
                )
            else:
                measurements = [f"interface={interface}"]
                if interface_mtu is not None:
                    measurements.append(f"interface_mtu={interface_mtu}")
                if route_mtu is not None:
                    measurements.append(f"route_mtu={route_mtu}")
                message = (
                    f"The source guest rejected the valid {packet_size}-byte DF "
                    "packet locally before transmission; the effective guest or "
                    f"route MTU is below the Neutron MTU ({', '.join(measurements)})"
                )
        self._record(spec, probe, source, destination, message=message)

    def _run_controller_probe(self, spec: TestSpec) -> None:
        destination, destination_ip = self._endpoint_address(
            spec.destination_group_id, spec.destination_side, spec.destination_subnet_id
        )
        family = int(spec.family)
        source_ip = self.builder.controller_probe_sources.get(family)
        source_subnet_id = self.builder.controller_probe_subnets.get(family)
        if not source_ip:
            probe = ProbeResult(
                outcome="error",
                success=False,
                elapsed_ms=0,
                attempts=0,
                stderr=f"controller has no IPv{family} provider source",
                destination_ip=destination_ip,
                protocol=spec.protocol,
            )
        else:
            same_subnet = bool(
                source_subnet_id
                and spec.destination_subnet_id
                and source_subnet_id == spec.destination_subnet_id
            )
            spec.authoritative = True
            spec.expectation = "reachable"
            spec.expectation_reason = (
                "the controller and destination use the same provider subnet"
                if same_subnet
                else "the explicitly selected provider networks are required to provide controller-to-endpoint connectivity"
            )
            probe = self.probes.controller(
                str(spec.protocol), source_ip, destination_ip, family
            )
            probe.diagnostics.update(
                {
                    "controller_source_subnet_id": source_subnet_id,
                    "destination_subnet_id": spec.destination_subnet_id,
                    "same_provider_subnet": same_subnet,
                }
            )
        self._record(spec, probe, self.builder.controller, destination)

    def _run_egress(self, spec: TestSpec) -> None:
        source, source_ip = self._endpoint_address(
            spec.source_group_id, spec.source_side, spec.source_subnet_id
        )
        target = str(spec.metadata.get("target") or "")
        if not target:
            probe = ProbeResult(
                outcome="error",
                success=False,
                elapsed_ms=0,
                attempts=0,
                stderr="no external destination was configured for this result",
                source_ip=source_ip,
                protocol="icmp",
            )
        else:
            probe = self.probes.endpoint(
                "icmp", source, source_ip, target, int(spec.family)
            )
            probe.diagnostics["external_target"] = target
        self._record(spec, probe, source, None)

    def _execute_endpoint_probe(
        self,
        source: Endpoint,
        source_ip: str,
        destination_ip: str,
        family: int,
        protocol: str,
        *,
        destination_port: int | None = None,
    ) -> ProbeResult:
        if protocol == "tcp-control":
            if destination_port is None:
                raise SuiteError("tcp-control probe requires a destination port")
            return self.probes.tcp.endpoint_port(
                source, source_ip, destination_ip, family, destination_port
            )
        return self.probes.endpoint(protocol, source, source_ip, destination_ip, family)
