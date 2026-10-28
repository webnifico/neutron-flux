from __future__ import annotations

import ipaddress
import time
from typing import Any

# mypy: disable-error-code="attr-defined"
from ..convergence import finish_convergence
from ..errors import SuiteError
from ..failure_injection import inject_failure
from ..models import Endpoint, ProbeResult, TestSpec


class FloatingIPLifecycleHandlerMixin:
    """Compatibility mixin for this test-operation family."""

    def _run_fip_baseline(self, spec: TestSpec) -> None:
        target_group = self._group(spec.destination_group_id)
        target = self._endpoint(target_group, spec.destination_side)
        fixed_ip = self._address(target_group, target, spec.destination_subnet_id)
        fip = self._peer_fip(target_group, target, spec.destination_side, fixed_ip)
        association = fip["association"]

        protocol = str(spec.protocol or "tcp")
        target_cidr = (
            str(spec.metadata.get("target_external_cidr") or "")
            or str(target_group.plan.metadata.get("runtime_public_cidr") or "")
            or None
        )
        runner_probe, runner_authoritative = self.probes.runner_fip.run(
            fip["address"], target_cidr, protocol=protocol
        )
        source: Endpoint | None = None
        source_ip: str | None = runner_probe.source_ip
        probe = runner_probe
        # The runner's default route establishes no upstream reachability
        # contract. Keep that measurement as evidence, separate from local NAT.
        authoritative = False
        source_mode = "runner"
        source_reason = (
            "external runner observation; upstream routing policy is unknown"
        )
        route_details: dict[str, Any] | None = None
        external_observation = {
            "outcome": runner_probe.outcome,
            "source_ip": runner_probe.source_ip,
            "gateway_routed": runner_authoritative,
            "contract": "observation",
            "command": runner_probe.command,
            "stdout": runner_probe.stdout,
            "stderr": runner_probe.stderr,
        }
        if (
            spec.metadata.get("observer_path_contract") == "same-provider-subnet"
            and spec.source_group_id
        ):
            source, source_ip = self._endpoint_address(
                spec.source_group_id, spec.source_side, spec.source_subnet_id
            )
            route_details = self.builder.inspect_endpoint_route(
                source, str(source_ip), fip["address"], 4
            )
            try:
                subnet = ipaddress.ip_network(str(target_cidr), strict=False)
                authoritative = bool(
                    spec.source_subnet_id == spec.metadata.get("floating_ip_subnet_id")
                    and self._group(spec.source_group_id).plan.kind == "provider"
                    and ipaddress.ip_address(str(source_ip)) in subnet
                    and ipaddress.ip_address(fip["address"]) in subnet
                )
            except ValueError:
                authoritative = False
            probe = self._verified_fip_probe(
                protocol,
                source,
                str(source_ip),
                fip["address"],
                target,
                fixed_ip,
                mode="provider-ingress",
                expected_source_ips={str(source_ip)},
            )
            source_mode = "provider-endpoint"
            source_reason = (
                "the source and floating IP occupy the declared provider subnet; "
                "the probe validates local floating-IP translation"
                if authoritative
                else "the controlled floating-IP observer's subnet could not be verified"
            )

        spec.authoritative = authoritative
        spec.expectation = "reachable" if authoritative else "observation"
        spec.expectation_reason = source_reason
        spec.metadata["routing_policy"] = {
            "basis": "controlled-floating-ip"
            if authoritative
            else "routing-relationship-unknown",
            "expectation": spec.expectation,
            "authoritative": authoritative,
            "reason": source_reason,
        }
        key = f"fip:{target_group.plan.id}"
        state = self.lifecycle.get(key) or {
            "id": fip["id"],
            "address": fip["address"],
            "port_id": target.test_port_id,
            "fixed_ip": fixed_ip,
            "source": source,
            "source_ip": source_ip,
            "target": target,
            "runner": source_mode == "runner",
            "target_external_cidr": target_cidr,
            "source_mode": source_mode,
            "detached": False,
            "detach_requested": False,
            "detach_confirmed": False,
            "baseline_by_protocol": {},
            "authoritative_by_protocol": {},
        }
        state["source"] = source
        state["source_ip"] = source_ip
        state["runner"] = source_mode == "runner"
        state["source_mode"] = source_mode
        state["baseline_by_protocol"][protocol] = probe.success
        state["authoritative_by_protocol"][protocol] = authoritative
        if protocol == "tcp":
            state["baseline"] = probe.success
            state["baseline_outcome"] = probe.outcome
            state["authoritative"] = authoritative
        self.lifecycle[key] = state
        probe.diagnostics.update(
            {
                "fip_observer_mode": source_mode,
                "floating_ip_association": association,
                "fip_observer_authoritative": authoritative,
                "observer_authority_basis": source_reason,
                "observer_route": route_details,
                "baseline_protocol": protocol,
                "external_ingress_observation": external_observation,
                "claim_boundary": "local floating-IP translation"
                if authoritative
                else "external observation without a routing contract",
            }
        )
        message = None
        if authoritative and not probe.success:
            observer = (
                f"runner {source_ip or 'source address unavailable'}"
                if source_mode == "runner"
                else f"{source.label} ({source_ip or 'source address unavailable'})"
                if source is not None
                else "provider observer"
            )
            destination_port = probe.diagnostics.get("destination_port")
            target_address = str(fip["address"])
            if destination_port and protocol in {"tcp", "udp"}:
                target_address += f":{destination_port}"
            failure = {
                "tcp": "could not establish a TCP connection to",
                "udp": "received no valid UDP response from",
                "icmp": "received no ICMP reply from",
            }.get(protocol, f"could not complete the {protocol.upper()} probe to")
            message = f"{observer} {failure} floating IP target {target_address}"
        if probe.outcome in {"wrong-destination", "translation-mismatch"}:
            message = probe.stderr
        self._record(spec, probe, source, target, message=message)

    def _run_fip_withdraw(self, spec: TestSpec) -> None:
        state = self._require_state(f"fip:{spec.destination_group_id}")
        if not state.get("authoritative") or not state.get("baseline"):
            spec.authoritative = False
            spec.metadata["authority_required"] = True
            spec.expectation_reason = "floating-IP ingress was not authoritatively reachable before detachment, so withdrawal cannot be measured"
            probe = ProbeResult(
                outcome="inconclusive",
                success=False,
                elapsed_ms=0,
                attempts=0,
                destination_ip=state["address"],
                protocol="tcp",
                diagnostics={
                    "baseline": state.get("baseline"),
                    "baseline_outcome": state.get("baseline_outcome"),
                    "authoritative": state.get("authoritative"),
                    "cloud_operation_performed": False,
                },
            )
            self._record(spec, probe, state["source"], state["target"])
            return

        inject_failure(self.config, "before-fip-withdraw")
        result = self.builder.osc.run(
            "floating", "ip", "unset", "--port", state["id"], check=False, timeout=60
        )
        if result.returncode != 0:
            raise SuiteError(self._concise(result.stderr or result.stdout))
        # The cloud operation command succeeded.  Record that fact before API readback
        # so the restoration phase cannot be skipped merely because Neutron's
        # association view is delayed or the confirmation poll times out.
        state["detach_requested"] = True
        association = self.builder.wait_floating_ip_association(
            state["id"], expected_port_id=None
        )
        state["detach_confirmed"] = bool(
            association.get("matched") is True
            and association.get("port_id") is None
            and association.get("floating_ip_address") == state["address"]
        )
        state["target"].metadata["floating_ip_association"] = dict(association)
        state["detached"] = state["detach_confirmed"]
        if not state["detach_confirmed"]:
            probe = ProbeResult(
                outcome="error",
                success=False,
                elapsed_ms=0,
                attempts=int(association.get("attempts", 0)),
                stderr="OpenStack did not confirm that the floating IP was detached",
                destination_ip=state["address"],
                protocol="tcp",
                diagnostics={"floating_ip_api_state": association},
            )
        else:
            probe = self._wait_fip_state(state, expected=False)
            probe.diagnostics["floating_ip_api_state"] = association
        spec.authoritative = True
        self._record(spec, probe, state["source"], state["target"])

    def _run_fip_return(self, spec: TestSpec) -> None:
        state = self._require_state(f"fip:{spec.destination_group_id}")
        if not state.get("authoritative") or not state.get("baseline"):
            spec.authoritative = False
            spec.metadata["authority_required"] = True
            spec.expectation_reason = "floating-IP ingress was not authoritatively reachable before the lifecycle test, so restoration was not attempted"
            probe = ProbeResult(
                outcome="inconclusive",
                success=False,
                elapsed_ms=0,
                attempts=0,
                destination_ip=state["address"],
                protocol="tcp",
                diagnostics={"cloud_operation_performed": False},
            )
            self._record(spec, probe, state["source"], state["target"])
            return
        if not state.get("detach_requested"):
            spec.authoritative = False
            spec.metadata["authority_required"] = True
            spec.expectation_reason = "The floating-IP detach cloud operation was not issued, so restoration is unverified"
            probe = ProbeResult(
                outcome="inconclusive",
                success=False,
                elapsed_ms=0,
                attempts=0,
                destination_ip=state["address"],
                protocol="tcp",
                diagnostics={"cloud_operation_performed": False},
            )
            self._record(spec, probe, state["source"], state["target"])
            return

        detach_confirmed_before_restore = bool(state.get("detach_confirmed"))
        inject_failure(self.config, "before-fip-return")
        result = self.builder.osc.run(
            "floating",
            "ip",
            "set",
            "--port",
            str(state["port_id"]),
            "--fixed-ip-address",
            str(state["fixed_ip"]),
            state["id"],
            check=False,
            timeout=60,
        )
        if result.returncode != 0:
            raise SuiteError(self._concise(result.stderr or result.stdout))
        association = self.builder.wait_floating_ip_association(
            state["id"],
            expected_port_id=str(state["port_id"]),
            expected_fixed_ip=str(state["fixed_ip"]),
        )
        if not (
            association.get("matched") is True
            and association.get("port_id") == state["port_id"]
            and association.get("fixed_ip_address") == state["fixed_ip"]
            and association.get("floating_ip_address") == state["address"]
        ):
            probe = ProbeResult(
                outcome="error",
                success=False,
                elapsed_ms=0,
                attempts=int(association.get("attempts", 0)),
                stderr="OpenStack did not confirm the restored floating-IP association",
                destination_ip=state["address"],
                protocol="tcp",
                diagnostics={
                    "floating_ip_api_state": association,
                    "detach_confirmed_before_restore": detach_confirmed_before_restore,
                },
            )
        else:
            state["detached"] = False
            state["detach_confirmed"] = False
            state["detach_requested"] = False
            probe = self._wait_fip_state(state, expected=True)
            probe.diagnostics["floating_ip_api_state"] = association
            probe.diagnostics["detach_confirmed_before_restore"] = (
                detach_confirmed_before_restore
            )
        state["target"].metadata["floating_ip_association"] = dict(association)
        spec.authoritative = True
        self._record(spec, probe, state["source"], state["target"])

    def _wait_fip_state(self, state: dict[str, Any], *, expected: bool) -> ProbeResult:
        required = 2 if expected else 3
        wanted = "reachable" if expected else "blocked"
        consecutive = 0
        attempts = 0
        started = time.monotonic()
        deadline = started + self.config.convergence_timeout
        last: ProbeResult | None = None
        observations = []
        finished = started
        while time.monotonic() < deadline:
            attempts += 1
            if state.get("runner"):
                last, authoritative = self.probes.runner_fip.run(
                    state["address"], state.get("target_external_cidr"), protocol="tcp"
                )
                state["authoritative"] = authoritative
            else:
                last = self._verified_fip_probe(
                    "tcp",
                    state["source"],
                    state["source_ip"],
                    state["address"],
                    state["target"],
                    state["fixed_ip"],
                    mode="provider-ingress",
                    expected_source_ips={state["source_ip"]},
                )
            finished = time.monotonic()
            observations.append(
                {
                    "outcome": last.outcome,
                    "success": last.success,
                    "elapsed_ms": last.elapsed_ms,
                    "completed_at_s": finished - started,
                    "stderr": last.stderr[:512],
                }
            )
            # A zero-interval poll must not grow report memory without bound.
            if len(observations) > 128:
                observations.pop(0)
            if last.outcome == wanted and last.success is expected:
                consecutive += 1
            else:
                consecutive = 0
            if consecutive >= required or finished >= deadline:
                break
            time.sleep(
                min(self.config.convergence_interval, max(0.0, deadline - finished))
            )
        if last is None:
            last = ProbeResult(
                outcome="error",
                success=False,
                elapsed_ms=0,
                attempts=0,
                stderr="floating-IP convergence probe produced no result",
                destination_ip=state["address"],
                protocol="tcp",
            )
        return finish_convergence(
            last,
            expected=expected,
            required=required,
            consecutive=consecutive,
            attempts=attempts,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            timeout=self.config.convergence_timeout,
            within_deadline=finished <= deadline,
            observations=observations,
        )
