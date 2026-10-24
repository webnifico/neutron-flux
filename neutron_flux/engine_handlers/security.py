from __future__ import annotations

# mypy: disable-error-code="attr-defined"
from ..errors import SuiteError
from ..models import Endpoint, ProbeResult, TestSpec


class SecurityLifecycleHandlerMixin:
    """Compatibility mixin for this test-operation family."""

    def _security_context(
        self, spec: TestSpec
    ) -> tuple[Endpoint, str, Endpoint, str, int, str, str, str]:
        source, source_ip = self._endpoint_address(
            spec.source_group_id, spec.source_side, spec.source_subnet_id
        )
        destination, destination_ip = self._endpoint_address(
            spec.destination_group_id, spec.destination_side, spec.destination_subnet_id
        )
        family = int(spec.family)
        control_port = int(self.builder.security_control_ports[family])
        source_sg = str(
            source.metadata.get("data_security_group_id")
            or self.builder.test_sg_ids.get(source.side.upper())
            or ""
        )
        destination_sg = str(
            destination.metadata.get("data_security_group_id")
            or self.builder.test_sg_ids.get(destination.side.upper())
            or ""
        )
        if not source_sg or not destination_sg:
            raise SuiteError(
                "Security-group test endpoints lack source/destination security-group identity"
            )
        state_key = f"security:{spec.destination_group_id}:{spec.family}"
        return (
            source,
            source_ip,
            destination,
            destination_ip,
            control_port,
            state_key,
            source_sg,
            destination_sg,
        )

    def _run_security_control(self, spec: TestSpec) -> None:
        # Backward-compatible operation name used by older checkpoints.
        self._run_security_deny(spec)

    def _run_security_deny(self, spec: TestSpec) -> None:
        (
            source,
            source_ip,
            destination,
            destination_ip,
            control_port,
            state_key,
            source_sg,
            destination_sg,
        ) = self._security_context(spec)
        family = int(spec.family)
        if destination.port_security_enabled is False:
            spec.expectation = "not-applicable"
            spec.expectation_reason = "port security is disabled on the destination Neutron port, so security-group enforcement does not apply"
            probe = ProbeResult(
                outcome="blocked",
                success=False,
                elapsed_ms=0,
                attempts=0,
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol="tcp",
                diagnostics={"port_security_enabled": False},
            )
            self.lifecycle[state_key] = {"not_applicable": True}
            self._record(spec, probe, source, destination)
            return

        attached_security_groups = (
            self.builder.port_security_group_ids(destination.test_port_id)
            if hasattr(self.builder, "port_security_group_ids")
            else [destination_sg]
        )
        if destination_sg not in attached_security_groups:
            raise SuiteError(
                f"Destination test port {destination.test_port_id} does not have its "
                f"expected Flux security group {destination_sg}; attached="
                + ",".join(attached_security_groups or ["none"])
            )
        if hasattr(self.builder, "security_groups_allow_port"):
            allowed, matching_rules = self.builder.security_groups_allow_port(
                attached_security_groups,
                family,
                "tcp",
                control_port,
                source_security_group_id=source_sg,
                source_ip=source_ip,
            )
        else:
            allowed, matching_rules = self.builder.security_group_allows_port(
                destination_sg,
                family,
                "tcp",
                control_port,
                source_security_group_id=source_sg,
                source_ip=source_ip,
                conservative_without_source=False,
            )
        path_baseline = self.probes.tcp.endpoint(
            source, source_ip, destination_ip, family
        )
        path_reachable = bool(
            path_baseline.success and path_baseline.outcome == "reachable"
        )
        probe = (
            self.probes.tcp.endpoint_port(
                source, source_ip, destination_ip, family, control_port
            )
            if path_reachable
            else ProbeResult(
                outcome="inconclusive",
                success=False,
                elapsed_ms=path_baseline.elapsed_ms,
                attempts=path_baseline.attempts,
                stdout=path_baseline.stdout,
                stderr=path_baseline.stderr,
                command=path_baseline.command,
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol="tcp",
            )
        )
        authoritative_port = not allowed and path_reachable
        state = {
            "source": source,
            "source_ip": source_ip,
            "destination": destination,
            "destination_ip": destination_ip,
            "control_port": control_port,
            "family": family,
            "source_security_group_id": source_sg,
            "destination_security_group_id": destination_sg,
            "matching_rules": matching_rules,
            "attached_security_group_ids": attached_security_groups,
            "temporary_rule_id": None,
            "baseline_outcome": probe.outcome,
            "path_baseline_outcome": path_baseline.outcome,
            "path_baseline_success": path_reachable,
            "authoritative_port": authoritative_port,
        }
        self.lifecycle[state_key] = state
        if not path_reachable:
            spec.authoritative = False
            spec.metadata["authority_required"] = True
            spec.expectation_reason = (
                "the ordinary Flux TCP path was not reachable before the deny "
                "observation, so a blocked control port cannot be attributed "
                "to security-group enforcement"
            )
            probe = ProbeResult(
                outcome="inconclusive",
                success=False,
                elapsed_ms=path_baseline.elapsed_ms,
                attempts=path_baseline.attempts,
                stdout=probe.stdout,
                stderr=probe.stderr or path_baseline.stderr,
                command=probe.command,
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol="tcp",
                diagnostics={
                    **probe.diagnostics,
                    "control_port": control_port,
                    "listener_confirmed": True,
                    "path_baseline_outcome": path_baseline.outcome,
                    "path_baseline_success": path_baseline.success,
                    "path_baseline_stderr": path_baseline.stderr,
                    "source_security_group_id": source_sg,
                    "destination_security_group_id": destination_sg,
                    "attached_security_group_ids": attached_security_groups,
                },
            )
        elif allowed:
            spec.authoritative = False
            spec.metadata["authority_required"] = True
            spec.expectation_reason = (
                "an existing ingress rule applicable to the actual source "
                "address or source security group already permits the control "
                "TCP port"
            )
            probe = ProbeResult(
                outcome="inconclusive",
                success=False,
                elapsed_ms=probe.elapsed_ms,
                attempts=probe.attempts,
                stdout=probe.stdout,
                stderr=probe.stderr,
                command=probe.command,
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol="tcp",
                diagnostics={
                    **probe.diagnostics,
                    "matching_rules": matching_rules
                    or self.builder.security_control_matching_rules.get(family, []),
                    "control_port": control_port,
                    "listener_confirmed": True,
                    "path_baseline_outcome": path_baseline.outcome,
                    "path_baseline_success": path_baseline.success,
                    "attached_security_group_ids": attached_security_groups,
                },
            )
        else:
            probe.diagnostics.update(
                {
                    "control_port": control_port,
                    "listener_confirmed": True,
                    "source_security_group_id": source_sg,
                    "destination_security_group_id": destination_sg,
                    "attached_security_group_ids": attached_security_groups,
                }
            )
        self._record(spec, probe, source, destination)

    def _run_security_allow(self, spec: TestSpec) -> None:
        (
            source,
            source_ip,
            destination,
            destination_ip,
            control_port,
            state_key,
            source_sg,
            destination_sg,
        ) = self._security_context(spec)
        state = self._require_state(state_key)
        if state.get("not_applicable"):
            spec.expectation = "not-applicable"
            spec.expectation_reason = "port security is disabled on the destination Neutron port, so no allow rule is applied"
            probe = ProbeResult(
                outcome="blocked",
                success=False,
                elapsed_ms=0,
                attempts=0,
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol="tcp",
            )
            self._record(spec, probe, source, destination)
            return
        if not state.get("path_baseline_success", True):
            spec.authoritative = False
            spec.metadata["authority_required"] = True
            spec.expectation_reason = (
                "the ordinary Flux TCP path was not reachable during the deny "
                "baseline, so applying a temporary rule would not produce an "
                "authoritative security-group transition"
            )
            probe = ProbeResult(
                outcome="inconclusive",
                success=False,
                elapsed_ms=0,
                attempts=0,
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol="tcp",
                diagnostics={
                    "control_port": control_port,
                    "listener_confirmed": True,
                    "path_baseline_outcome": state.get("path_baseline_outcome"),
                    "path_baseline_success": False,
                },
            )
            self._record(spec, probe, source, destination)
            return
        if state.get("matching_rules") or not state.get("authoritative_port", False):
            spec.authoritative = False
            spec.metadata["authority_required"] = True
            spec.expectation_reason = "a broad existing ingress rule prevents isolation of the temporary security-group transition"
            probe = ProbeResult(
                outcome="inconclusive",
                success=False,
                elapsed_ms=0,
                attempts=0,
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol="tcp",
                diagnostics={
                    "matching_rules": state.get("matching_rules"),
                    "control_port": control_port,
                    "listener_confirmed": True,
                },
            )
            self._record(spec, probe, source, destination)
            return
        rule_id = self.builder.add_temporary_security_rule(
            destination_security_group_id=destination_sg,
            source_security_group_id=source_sg,
            family=int(spec.family),
            protocol="tcp",
            port=control_port,
        )
        state["temporary_rule_id"] = rule_id
        probe = self._wait_endpoint_state(
            source,
            source_ip,
            destination_ip,
            int(spec.family),
            "tcp-control",
            expected=True,
            destination_port=control_port,
        )
        probe.diagnostics.update(
            {
                "temporary_rule_id": rule_id,
                "control_port": control_port,
                "source_security_group_id": source_sg,
                "destination_security_group_id": destination_sg,
            }
        )
        self._record(spec, probe, source, destination)

    def _run_security_restore(self, spec: TestSpec) -> None:
        (
            source,
            source_ip,
            destination,
            destination_ip,
            control_port,
            state_key,
            source_sg,
            destination_sg,
        ) = self._security_context(spec)
        state = self._require_state(state_key)
        if state.get("not_applicable"):
            spec.expectation = "not-applicable"
            spec.expectation_reason = "port security is disabled on the destination Neutron port, so there is no security-group state to restore"
            probe = ProbeResult(
                outcome="blocked",
                success=False,
                elapsed_ms=0,
                attempts=0,
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol="tcp",
            )
            self._record(spec, probe, source, destination)
            return
        rule_id = state.get("temporary_rule_id")
        if not rule_id:
            spec.authoritative = False
            spec.metadata["authority_required"] = True
            spec.expectation_reason = "no isolated temporary security-group rule was created, so restoration cannot be measured"
            probe = ProbeResult(
                outcome="inconclusive",
                success=False,
                elapsed_ms=0,
                attempts=0,
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol="tcp",
                diagnostics={
                    "control_port": control_port,
                    "listener_confirmed": True,
                },
            )
            self._record(spec, probe, source, destination)
            return
        self.builder.delete_security_rule(str(rule_id), destination_sg)
        state["temporary_rule_id"] = None
        probe = self._wait_endpoint_state(
            source,
            source_ip,
            destination_ip,
            int(spec.family),
            "tcp-control",
            expected=False,
            destination_port=control_port,
        )
        probe.diagnostics.update(
            {
                "removed_rule_id": rule_id,
                "control_port": control_port,
                "source_security_group_id": source_sg,
                "destination_security_group_id": destination_sg,
            }
        )
        self._record(spec, probe, source, destination)
