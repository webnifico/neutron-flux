from __future__ import annotations

# mypy: disable-error-code="attr-defined"
import json
import shlex
import subprocess
import time
from typing import Any

from ..errors import SuiteError
from ..models import Endpoint, ProbeResult, TestSpec
from ..mtu_contract import (
    classify_fragmentation_location,
    classify_mtu_contract_probe,
    confirmed_fragmentation_path_mtu,
    confirmed_no_fragment_path_mtu,
    local_mtu_constraint,
    make_mtu_observation,
    resolve_mtu_contract,
)
from ..mtu_probes import (
    fragment_counter_probe_code,
    fragmentation_probe_code,
    performance_probe_code,
)


class PacketSizeProfileHandlerMixin:
    """Measure routed jumbo/PMTUD/fragmentation behaviour on translated paths."""

    def _endpoint_json(
        self, endpoint: Endpoint, code: str, *, timeout: int = 90
    ) -> dict[str, Any]:
        command = "python3 -c " + shlex.quote(code)
        result = self.builder.ssh_endpoint(endpoint, command, timeout=timeout)
        if result.returncode != 0:
            raise SuiteError(
                "remote packet-size profile failed: "
                + self._concise(result.stderr or result.stdout)
            )
        lines = [line for line in str(result.stdout or "").splitlines() if line.strip()]
        if not lines:
            raise SuiteError("remote packet-size profile returned no JSON")
        try:
            value = json.loads(lines[-1])
        except json.JSONDecodeError as exc:
            raise SuiteError(
                "remote packet-size profile returned invalid JSON"
            ) from exc
        if not isinstance(value, dict):
            raise SuiteError("remote packet-size profile JSON must be an object")
        return value

    def _detach_floating_ip_for_profile(self, state: dict[str, Any]) -> dict[str, Any]:
        cloud_operation = {
            "requested": True,
            "floating_ip_id": str(state.get("id") or ""),
            "address": str(state.get("address") or ""),
            "port_id": str(state.get("port_id") or ""),
            "fixed_ip": str(state.get("fixed_ip") or ""),
            "detach_command_returncode": None,
            "detach_readback": None,
            "detached": False,
            "restore_command_returncode": None,
            "restore_readback": None,
            "restored": False,
        }
        required = ("floating_ip_id", "port_id", "fixed_ip")
        if any(not cloud_operation.get(key) for key in required):
            cloud_operation["error"] = (
                "The floating-IP association did not contain the ID, port, and "
                "fixed-IP fields required for a safe temporary detach"
            )
            return cloud_operation
        command = self.builder.osc.run(
            "floating",
            "ip",
            "unset",
            "--port",
            cloud_operation["floating_ip_id"],
            check=False,
            timeout=60,
        )
        cloud_operation["detach_command_returncode"] = int(command.returncode)
        cloud_operation["detach_command_stderr"] = str(command.stderr or "")
        readback = self.builder.wait_floating_ip_association(
            cloud_operation["floating_ip_id"], expected_port_id=None
        )
        cloud_operation["detach_readback"] = readback
        cloud_operation["detached"] = bool(readback.get("matched"))
        if not cloud_operation["detached"]:
            cloud_operation["error"] = (
                "OpenStack did not confirm the temporary floating-IP detachment"
            )
        return cloud_operation

    def _restore_floating_ip_after_profile(
        self, cloud_operation: dict[str, Any]
    ) -> None:
        if not cloud_operation.get("detached"):
            return
        command = self.builder.osc.run(
            "floating",
            "ip",
            "set",
            "--port",
            str(cloud_operation["port_id"]),
            "--fixed-ip-address",
            str(cloud_operation["fixed_ip"]),
            str(cloud_operation["floating_ip_id"]),
            check=False,
            timeout=60,
        )
        cloud_operation["restore_command_returncode"] = int(command.returncode)
        cloud_operation["restore_command_stderr"] = str(command.stderr or "")
        readback = self.builder.wait_floating_ip_association(
            str(cloud_operation["floating_ip_id"]),
            expected_port_id=str(cloud_operation["port_id"]),
            expected_fixed_ip=str(cloud_operation["fixed_ip"]),
        )
        cloud_operation["restore_readback"] = readback
        cloud_operation["restored"] = bool(readback.get("matched"))
        if not cloud_operation["restored"]:
            cloud_operation["restore_error"] = (
                "OpenStack did not confirm restoration of the floating-IP "
                "association after the router source-NAT profile"
            )

    def _profile_network_mtu_observation(
        self,
        group_id: str | None,
        side: str | None,
    ) -> dict[str, Any]:
        # Preserve small embedded/test engines that intentionally replace the
        # legacy resolver on the instance. Production uses the live,
        # side-specific Neutron observation method.
        if "_network_mtu" in getattr(self, "__dict__", {}):
            mtu = int(self._network_mtu(group_id))
            return make_mtu_observation(
                label=f"{group_id or 'unknown'} network",
                reported_mtu=mtu,
                authority="compatibility MTU resolver",
                authoritative=True,
                resource_type="network",
                resource_id=group_id,
            )
        return self._network_mtu_observation(group_id, side)

    @staticmethod
    def _probe_details(probe: Any) -> dict[str, Any] | None:
        if probe is None:
            return None
        return {
            "outcome": probe.outcome,
            "success": probe.success,
            "command": probe.command,
            "stdout": probe.stdout,
            "stderr": probe.stderr,
            "attempts": probe.attempts,
            "diagnostics": probe.diagnostics,
        }

    def _fip_egress_context(
        self,
        spec: TestSpec,
        *,
        ensure_floating_ip: bool,
    ) -> dict[str, Any]:
        source_group = self._group(spec.source_group_id)
        source, source_ip = self._endpoint_address(
            spec.source_group_id, spec.source_side, spec.source_subnet_id
        )
        provider, provider_ip = self._endpoint_address(
            spec.destination_group_id,
            spec.destination_side,
            spec.destination_subnet_id,
        )
        if not source_group.router_id:
            raise SuiteError("floating-IP outbound testing requires a Neutron router")

        router_state = self.builder.capture_router_state(source_group.router_id)
        gateway = router_state.get("external_gateway_info") or {}
        floating_ip_preexisting = source.label in source_group.fips
        setup_error: str | None = None
        if ensure_floating_ip:
            try:
                if getattr(self, "post_migration_read_only", False):
                    self.builder.ensure_group_fips(source_group, allow_create=False)
                else:
                    self.builder.ensure_group_fips(source_group)
            except SuiteError as exc:
                setup_error = self._concise(str(exc))

        managed_fip = source_group.fips.get(source.label)
        if not isinstance(managed_fip, dict):
            managed_fip = None
        association = {}
        if managed_fip:
            association = self.builder.wait_floating_ip_association(
                managed_fip["id"],
                expected_port_id=source.test_port_id,
                expected_fixed_ip=source_ip,
            )
            source.metadata["floating_ip_association"] = dict(association)
            if not association.get("matched"):
                raise SuiteError(
                    "The floating IP is not associated with the source data port and fixed IP"
                )
        lifecycle_fip = self.lifecycle.get(f"fip:{source_group.plan.id}")
        floating_ip = ""
        if isinstance(lifecycle_fip, dict):
            floating_ip = str(lifecycle_fip.get("address") or "")
        if not floating_ip and managed_fip:
            floating_ip = str(managed_fip.get("address") or "")

        observer_service = dict(provider.metadata.get("probe_service") or {})
        observer_port = int(observer_service.get("tcp_port") or self.config.tcp_port)
        return {
            "source_group": source_group,
            "source": source,
            "source_ip": source_ip,
            "provider": provider,
            "provider_ip": provider_ip,
            "router_state": router_state,
            "gateway": gateway,
            "router_source_nat_enabled": bool(gateway.get("enable_snat", True)),
            "floating_ip": floating_ip,
            "floating_ip_association": association,
            "floating_ip_setup_error": setup_error,
            "floating_ip_association_preexisting": floating_ip_preexisting,
            "floating_ip_created_for_test": bool(
                ensure_floating_ip
                and not floating_ip_preexisting
                and source.label in source_group.fips
            ),
            "observer_service": observer_service,
            "observer_ready": bool(observer_service.get("ready")),
            "observer_port": observer_port,
        }

    def _fip_egress_base_details(
        self,
        spec: TestSpec,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        source = context["source"]
        provider = context["provider"]
        details: dict[str, Any] = {
            "phase": spec.phase,
            "address_path": self._address_evidence(
                spec,
                ProbeResult(
                    "reachable",
                    True,
                    0,
                    0,
                    source_ip=context["source_ip"],
                    destination_ip=context["provider_ip"],
                    diagnostics={
                        "source_floating_ip": {
                            "association": context["floating_ip_association"]
                        }
                    },
                ),
                source,
                provider,
            ),
            "expectation_reason": spec.expectation_reason,
            "dependencies": spec.dependencies,
            **spec.metadata,
            "path_kind": "floating-ip-to-provider-observer",
            "egress_translation_mode": "floating-ip-egress",
            "translation_mode_label": "floating-IP outbound translation",
            "floating_ip": context["floating_ip"] or None,
            "floating_ip_association_preexisting": context[
                "floating_ip_association_preexisting"
            ],
            "floating_ip_created_for_test": context["floating_ip_created_for_test"],
            "router_id": context["source_group"].router_id,
            "router_source_nat_enabled": context["router_source_nat_enabled"],
            "router_state": context["router_state"],
            "provider_observer": {
                "endpoint": provider.label,
                "address": context["provider_ip"],
                "tcp_port": context["observer_port"],
                "service_ready": context["observer_ready"],
                "probe_service": context["observer_service"],
            },
            "source_availability_zone": source.availability_zone,
            "destination_availability_zone": provider.availability_zone,
        }
        details.update(
            {
                "source_compute_host": source.host,
                "destination_compute_host": provider.host,
                "compute_placement": "project-to-provider-translation",
            }
        )
        return details

    def _run_fip_egress_source_address(self, spec: TestSpec) -> None:
        """Verify only the source address observed for one outbound FIP flow."""

        started = time.monotonic()
        context = self._fip_egress_context(spec, ensure_floating_ip=True)
        source = context["source"]
        provider = context["provider"]
        source_ip = str(context["source_ip"])
        provider_ip = str(context["provider_ip"])
        floating_ip = str(context["floating_ip"] or "")
        control_baseline = None
        control_source_ip = ""
        baseline = None
        translated_source_ip = ""

        if (
            not context["floating_ip_setup_error"]
            and floating_ip
            and context["observer_ready"]
        ):
            control_side = "B" if str(spec.destination_side or "A") != "B" else "A"
            try:
                control_endpoint, control_ip = self._endpoint_address(
                    spec.destination_group_id,
                    control_side,
                    spec.destination_subnet_id,
                )
            except (KeyError, SuiteError):
                control_endpoint, control_ip = None, ""
            if (
                control_endpoint is not None
                and control_endpoint.server_id != provider.server_id
                and control_ip
            ):
                control_baseline = self.probes.tcp.endpoint_port(
                    control_endpoint,
                    control_ip,
                    provider_ip,
                    4,
                    int(context["observer_port"]),
                )
                control_source_ip = control_ip
            if control_baseline is None or control_baseline.success:
                baseline = self.probes.tcp.endpoint_peer_identity(
                    source,
                    source_ip,
                    provider_ip,
                    4,
                    port=int(context["observer_port"]),
                )
                translated_source_ip = str(
                    baseline.diagnostics.get("observed_peer_ip") or ""
                )

        expected_translation_ips = [floating_ip] if floating_ip else []
        translation_matches = (
            translated_source_ip == floating_ip
            if translated_source_ip and floating_ip
            else None
        )

        if context["floating_ip_setup_error"]:
            status = "ERROR"
            observed = "floating-ip-association-setup-failed"
            message = (
                "The private endpoint floating-IP association could not be created "
                f"and confirmed: {context['floating_ip_setup_error']}"
            )
        elif not floating_ip:
            status = "ERROR"
            observed = "floating-ip-association-unavailable"
            message = (
                "OpenStack did not provide a confirmed floating-IP association for "
                "the private source endpoint"
            )
        elif not context["observer_ready"]:
            status = "ERROR"
            observed = "provider-observer-service-unavailable"
            message = "The provider observer TCP service was not ready"
        elif control_baseline is not None and not control_baseline.success:
            status = "ERROR" if control_baseline.outcome == "error" else "UNVERIFIED"
            observed = "provider-observer-control-failed"
            message = (
                "The provider-side control endpoint could not reach the observer "
                "service, so the floating-IP path was not attempted"
            )
        elif baseline is None:
            status = "UNVERIFIED"
            observed = "floating-ip-source-address-check-not-run"
            message = "The outbound floating-IP source-address check was not run"
        elif not baseline.success:
            status = (
                "ERROR"
                if baseline.outcome == "error"
                else "UNVERIFIED"
                if baseline.outcome == "inconclusive"
                else "FAIL"
            )
            observed = "floating-ip-outbound-tcp-connection-failed"
            message = (
                "The observer service was ready, but the private endpoint could not "
                "establish the outbound TCP connection through its floating IP"
            )
        elif not translated_source_ip:
            status = "UNVERIFIED"
            observed = "translated-source-address-unavailable"
            message = (
                "The outbound connection reached the observer, but the observer did "
                "not return the source address it saw"
            )
        elif translation_matches is False:
            status = "FAIL"
            observed = "unexpected-translated-source-address"
            message = (
                f"The observer saw source address {translated_source_ip}; the expected "
                f"floating IP was {floating_ip}"
            )
        else:
            status = "PASS"
            observed = "provider-observed-floating-ip-source-address"
            message = (
                f"The provider observer saw {floating_ip}, confirming the private "
                "endpoint used its floating IP as the outbound source address"
            )

        details = self._fip_egress_base_details(spec, context)
        details.update(
            {
                "translated_source_ip_observed_by_provider": (
                    translated_source_ip or None
                ),
                "provider_control_source_ip_observed_by_provider": (
                    control_source_ip or None
                ),
                "expected_translation_ips": expected_translation_ips,
                "translation_matches_expected_identity": translation_matches,
                "provider_observer_control_baseline": self._probe_details(
                    control_baseline
                ),
                "translation_baseline": self._probe_details(baseline),
                "cloud_operation_performed": context["floating_ip_created_for_test"],
            }
        )
        self.reporter.result(
            spec.id,
            spec.category,
            status,
            message,
            family=4,
            source=f"{source.label} ({source_ip})",
            destination=f"{provider.label} ({provider_ip})",
            duration_ms=int((time.monotonic() - started) * 1000),
            details=details,
            expected=spec.expectation,
            observed=observed,
            authoritative=status in {"PASS", "FAIL"},
            display_name=spec.display_name,
            scenario=spec.scenario,
        )

    def _run_fip_egress_mtu(self, spec: TestSpec) -> None:
        """Measure the outbound FIP no-fragment MTU as its own result."""

        started = time.monotonic()
        context = self._fip_egress_context(spec, ensure_floating_ip=False)
        source = context["source"]
        provider = context["provider"]
        source_ip = str(context["source_ip"])
        provider_ip = str(context["provider_ip"])
        source_mtu_evidence = self._profile_network_mtu_observation(
            spec.source_group_id, spec.source_side
        )
        provider_mtu_evidence = self._profile_network_mtu_observation(
            spec.destination_group_id, spec.destination_side
        )
        mtu_contract = resolve_mtu_contract(
            [source_mtu_evidence, provider_mtu_evidence]
        )
        expected_path_mtu = int(mtu_contract["expected_mtu"])
        mtu_profile: dict[str, Any] | None = None
        profile_error: str | None = None
        try:
            mtu_profile = self._endpoint_json(
                source,
                performance_probe_code(source_ip, provider_ip, 4, expected_path_mtu),
            )
            mtu_profile = classify_mtu_contract_probe(
                mtu_profile,
                expected_mtu=expected_path_mtu,
                contract_authoritative=bool(mtu_contract["authoritative"]),
            )
        except (
            SuiteError,
            OSError,
            ValueError,
            TypeError,
            subprocess.SubprocessError,
        ) as exc:
            profile_error = self._concise(str(exc))

        mtu_advisory = False
        if profile_error or mtu_profile is None:
            status = "ERROR"
            observed = "floating-ip-outbound-mtu-check-error"
            message = (
                "The outbound floating-IP source-address prerequisite passed, but "
                f"the path MTU check could not complete: {profile_error or 'no result'}"
            )
        else:
            contract_status = str(
                mtu_profile.get("advertised_mtu_contract_status") or "unverified"
            )
            status = "PASS" if contract_status in {"met", "failed"} else "UNVERIFIED"
            mtu_advisory = contract_status == "failed"
            observed = (
                "path-mtu-below-advertised"
                if mtu_advisory
                else "advertised-mtu-contract-met"
                if status == "PASS"
                else "advertised-mtu-contract-unverified"
            )
            discovered = confirmed_no_fragment_path_mtu(mtu_profile)
            local_constraint, local_class = local_mtu_constraint(mtu_profile)
            if discovered is not None:
                boundary = f"measured no-fragment path MTU {discovered} bytes"
            elif local_constraint is not None:
                boundary = (
                    f"local {str(local_class or 'MTU constraint').replace('-', ' ')} "
                    f"{local_constraint} bytes; path boundary unverified"
                )
            else:
                boundary = "no-fragment path MTU unverified"
            message = (
                f"Floating-IP outbound path: advertised MTU {expected_path_mtu} bytes; "
                f"{boundary}"
            )
            if mtu_advisory:
                message += "; advisory MTU difference; remaining tests may continue"

        details = self._fip_egress_base_details(spec, context)
        details.update(
            {
                "source_network_mtu": int(source_mtu_evidence["effective_mtu"]),
                "external_provider_network_mtu": int(
                    provider_mtu_evidence["effective_mtu"]
                ),
                "provider_observer_interface_mtu": int(
                    provider_mtu_evidence["effective_mtu"]
                ),
                "expected_no_fragment_path_mtu": expected_path_mtu,
                "mtu_contract": mtu_contract,
                "mtu_constraints": mtu_contract["constraints"],
                "limiting_mtu_constraints": mtu_contract["limiting_constraints"],
                "source_network_mtu_evidence": source_mtu_evidence,
                "external_provider_network_mtu_evidence": provider_mtu_evidence,
                "provider_observer_mtu_evidence": provider_mtu_evidence,
                "source_address_test_id": spec.metadata.get("source_address_test_id"),
                "mtu_advisory": mtu_advisory,
                "health": "warning"
                if mtu_advisory
                else "good"
                if status == "PASS"
                else "unverified"
                if status == "UNVERIFIED"
                else "critical",
                "warning_reasons": [message] if mtu_advisory else [],
                "mtu_profile": mtu_profile,
                "profile_error": profile_error,
                "cloud_operation_performed": False,
            }
        )
        self.reporter.result(
            spec.id,
            spec.category,
            status,
            message,
            family=4,
            source=f"{source.label} ({source_ip})",
            destination=f"{provider.label} ({provider_ip})",
            duration_ms=int((time.monotonic() - started) * 1000),
            details=details,
            expected=spec.expectation,
            observed=observed,
            authoritative=status in {"PASS", "FAIL"},
            display_name=spec.display_name,
            scenario=spec.scenario,
        )

    def _run_fip_egress_fragmentation(self, spec: TestSpec) -> None:
        """Classify outbound FIP fragmentation separately from path MTU."""

        started = time.monotonic()
        context = self._fip_egress_context(spec, ensure_floating_ip=False)
        source = context["source"]
        provider = context["provider"]
        source_ip = str(context["source_ip"])
        provider_ip = str(context["provider_ip"])
        mtu_test_id = str(spec.metadata.get("mtu_test_id") or "")
        mtu_result = self.reporter.get_result(mtu_test_id) if mtu_test_id else None
        mtu_profile = (
            mtu_result.details.get("mtu_profile")
            if mtu_result is not None and isinstance(mtu_result.details, dict)
            else None
        )
        if not isinstance(mtu_profile, dict):
            raise SuiteError(
                "floating-IP fragmentation requires the recorded outbound MTU result"
            )

        source_mtu_evidence = self._profile_network_mtu_observation(
            spec.source_group_id, spec.source_side
        )
        provider_mtu_evidence = self._profile_network_mtu_observation(
            spec.destination_group_id, spec.destination_side
        )
        source_mtu = int(source_mtu_evidence["effective_mtu"])
        mtu_contract = resolve_mtu_contract(
            [source_mtu_evidence, provider_mtu_evidence]
        )
        expected_path_mtu = int(mtu_contract["expected_mtu"])
        confirmed_path_mtu = confirmed_fragmentation_path_mtu(
            mtu_profile, expected_path_mtu
        )
        fragmentation_profile: dict[str, Any] | None = None
        profile_error: str | None = None
        try:
            destination_before = self._endpoint_json(
                provider, fragment_counter_probe_code(4)
            )
            raw_profile = self._endpoint_json(
                source,
                fragmentation_probe_code(
                    source_ip,
                    provider_ip,
                    4,
                    source_mtu,
                    confirmed_path_mtu,
                ),
            )
            destination_after = self._endpoint_json(
                provider, fragment_counter_probe_code(4)
            )
            fragmentation_profile = classify_fragmentation_location(
                raw_profile,
                destination_before=destination_before,
                destination_after=destination_after,
                router_ids=[context["source_group"].router_id],
                router_backend_evidence=self._network_router_backend_evidence(),
            )
        except (
            SuiteError,
            OSError,
            ValueError,
            TypeError,
            subprocess.SubprocessError,
        ) as exc:
            profile_error = self._concise(str(exc))

        if profile_error or fragmentation_profile is None:
            status = "ERROR"
            observed = "floating-ip-outbound-fragmentation-check-error"
            message = (
                "The outbound MTU prerequisite passed, but the fragmentation check "
                f"could not complete: {profile_error or 'no result'}"
            )
        else:
            capability = str(fragmentation_profile.get("capability") or "unverified")
            applicable = bool(fragmentation_profile.get("applicable"))
            location = str(
                fragmentation_profile.get("fragmentation_location_label")
                or "Fragmentation location unverified"
            )
            if not applicable and capability == "not-required":
                status = "NOT_APPLICABLE"
                observed = "fragmentation-not-required"
                message = (
                    "Fragmentation was not required because the source-network MTU "
                    "did not exceed the confirmed outbound no-fragment path MTU"
                )
            elif capability in {"supported", "path-supports-source-mtu"}:
                status = "PASS"
                observed = f"fragmentation-{capability}"
                message = f"Floating-IP outbound fragmentation: {location}"
            elif capability == "not-supported":
                status = "FAIL"
                observed = "fragmented-delivery-not-observed"
                message = (
                    "The source-sized IPv4 packet did not cross the floating-IP "
                    "outbound path when fragmentation was permitted"
                )
            else:
                status = "UNVERIFIED"
                observed = "fragmentation-behaviour-unverified"
                message = (
                    "The floating-IP outbound fragmentation behaviour could not be "
                    f"classified; {location.lower()}"
                )

        details = self._fip_egress_base_details(spec, context)
        details.update(
            {
                "source_network_mtu": source_mtu,
                "external_provider_network_mtu": int(
                    provider_mtu_evidence["effective_mtu"]
                ),
                "expected_no_fragment_path_mtu": expected_path_mtu,
                "confirmed_fragmentation_path_mtu": confirmed_path_mtu,
                "mtu_test_id": mtu_test_id,
                "mtu_profile": mtu_profile,
                "fragmentation_profile": fragmentation_profile,
                "profile_error": profile_error,
                "cloud_operation_performed": False,
            }
        )
        self.reporter.result(
            spec.id,
            spec.category,
            status,
            message,
            family=4,
            source=f"{source.label} ({source_ip})",
            destination=f"{provider.label} ({provider_ip})",
            duration_ms=int((time.monotonic() - started) * 1000),
            details=details,
            expected=spec.expectation,
            observed=observed,
            authoritative=status in {"PASS", "FAIL"},
            display_name=spec.display_name,
            scenario=spec.scenario,
        )

    def _run_snat_packet_size_profile(self, spec: TestSpec) -> None:
        started = time.monotonic()
        source_group = self._group(spec.source_group_id)
        source, source_ip = self._endpoint_address(
            spec.source_group_id, spec.source_side, spec.source_subnet_id
        )
        provider, provider_ip = self._endpoint_address(
            spec.destination_group_id,
            spec.destination_side,
            spec.destination_subnet_id,
        )
        if not source_group.router_id:
            raise SuiteError(
                "router source-NAT packet-size profiling requires a Neutron router"
            )

        router_state = self.builder.capture_router_state(source_group.router_id)
        gateway = router_state.get("external_gateway_info") or {}
        source_nat_enabled = bool(gateway.get("enable_snat", True))
        requested_mode = str(
            spec.metadata.get("egress_translation_mode") or "router-source-nat"
        )
        if requested_mode == "floating-ip-egress":
            self.reporter.result(
                spec.id,
                spec.category,
                "SKIP",
                (
                    "The legacy combined floating-IP egress profile is retired and "
                    "will not run. Use the separately listed outbound source-address, "
                    "path MTU, or fragmentation test."
                ),
                family=4,
                source=f"{source.label} ({source_ip})",
                destination=f"{provider.label} ({provider_ip})",
                duration_ms=int((time.monotonic() - started) * 1000),
                details={
                    "expectation_reason": spec.expectation_reason,
                    "dependencies": spec.dependencies,
                    **spec.metadata,
                    "execution_decision": "retired-combined-floating-ip-profile",
                    "cloud_operation_performed": False,
                },
                expected=spec.expectation,
                observed="not-run-retired-combined-profile",
                authoritative=False,
                display_name=spec.display_name,
                scenario=spec.scenario,
            )
            return
        require_floating_ip = bool(spec.metadata.get("require_floating_ip"))
        require_no_floating_ip = bool(spec.metadata.get("require_no_floating_ip"))
        floating_ip_preexisting = source.label in source_group.fips
        floating_ip_setup_error: str | None = None
        if require_floating_ip:
            try:
                # The egress profile is directionally independent from ingress.
                # Exact selection must therefore create and confirm its own safe
                # private-endpoint association instead of relying on a prior
                # inbound floating-IP test to have done so.
                self.builder.ensure_group_fips(source_group)
            except SuiteError as exc:
                floating_ip_setup_error = self._concise(str(exc))
        floating_ip_created_for_profile = bool(
            require_floating_ip
            and not floating_ip_preexisting
            and source.label in source_group.fips
        )
        mode_label = (
            "floating-IP egress"
            if requested_mode == "floating-ip-egress"
            else "router source NAT egress"
        )
        mode_slug = (
            "floating-ip" if requested_mode == "floating-ip-egress" else "source-nat"
        )
        path_kind = (
            "floating-ip-to-provider-observer"
            if requested_mode == "floating-ip-egress"
            else "source-nat-to-provider-observer"
        )
        fip_state = self.lifecycle.get(f"fip:{source_group.plan.id}")
        floating_ip = (
            str(fip_state.get("address") or "") if isinstance(fip_state, dict) else ""
        )
        managed_fip = source_group.fips.get(source.label)
        if not isinstance(managed_fip, dict):
            managed_fip = None
        if not floating_ip and managed_fip:
            floating_ip = str(managed_fip.get("address") or "")
        if not isinstance(fip_state, dict) and managed_fip:
            fip_state = dict(managed_fip)

        precondition_status: str | None = None
        precondition_observed: str | None = None
        precondition_message: str | None = None
        if floating_ip_setup_error:
            precondition_status = "ERROR"
            precondition_observed = "floating-ip-association-setup-failed"
            precondition_message = (
                "The floating-IP egress profile could not create and confirm its "
                f"private-endpoint association: {floating_ip_setup_error}"
            )
        elif require_floating_ip and not floating_ip:
            precondition_status = "ERROR"
            precondition_observed = "floating-ip-association-unavailable"
            precondition_message = (
                "The floating-IP egress profile could not obtain a confirmed "
                "floating-IP association for its private source endpoint"
            )
        elif (
            require_no_floating_ip
            and floating_ip
            and (
                not isinstance(fip_state, dict)
                or any(not fip_state.get(key) for key in ("id", "port_id", "fixed_ip"))
            )
        ):
            precondition_status = "BLOCKED_BY_PREREQUISITE"
            precondition_observed = "floating-ip-detach-state-unavailable"
            precondition_message = (
                "The router source-NAT profile could not safely detach the managed "
                "floating IP because its ID, port, or fixed-IP state was incomplete"
            )
        elif requested_mode == "router-source-nat" and not source_nat_enabled:
            precondition_status = "NOT_APPLICABLE"
            precondition_observed = "source-nat-disabled"
            precondition_message = (
                "The router has source NAT disabled, so the no-floating-IP external "
                "egress packet-size profile was not applicable"
            )

        if precondition_status:
            self.reporter.result(
                spec.id,
                spec.category,
                precondition_status,
                str(precondition_message),
                family=4,
                source=f"{source.label} ({source_ip})",
                destination=f"{provider.label} ({provider_ip})",
                duration_ms=int((time.monotonic() - started) * 1000),
                details={
                    "expectation_reason": spec.expectation_reason,
                    "dependencies": spec.dependencies,
                    **spec.metadata,
                    "path_kind": path_kind,
                    "egress_translation_mode": requested_mode,
                    "router_id": source_group.router_id,
                    "router_source_nat_enabled": source_nat_enabled,
                    "floating_ip": floating_ip or None,
                    "floating_ip_association_preexisting": floating_ip_preexisting,
                    "floating_ip_created_for_profile": floating_ip_created_for_profile,
                    "router_state": router_state,
                    "cloud_operation_performed": floating_ip_created_for_profile,
                },
                expected=spec.expectation,
                observed=str(precondition_observed),
                authoritative=False,
                display_name=spec.display_name,
                scenario=spec.scenario,
            )
            return

        source_mtu_evidence = self._profile_network_mtu_observation(
            spec.source_group_id,
            spec.source_side,
        )
        provider_mtu_evidence = self._profile_network_mtu_observation(
            spec.destination_group_id,
            spec.destination_side,
        )
        source_mtu = int(source_mtu_evidence["effective_mtu"])
        provider_network_mtu = int(provider_mtu_evidence["effective_mtu"])

        observer_service = dict(provider.metadata.get("probe_service") or {})
        observer_ready = bool(observer_service.get("ready"))
        observer_port = int(observer_service.get("tcp_port") or self.config.tcp_port)

        cloud_operation_state: dict[str, Any] = {
            "requested": False,
            "detached": False,
            "restored": False,
        }
        if require_no_floating_ip and floating_ip:
            cloud_operation_state = self._detach_floating_ip_for_profile(
                dict(fip_state or {})
            )

        control_baseline = None
        baseline = None
        translated_source_ip = ""
        control_source_ip = ""
        mtu_profile: dict[str, Any] | None = None
        fragmentation_profile: dict[str, Any] | None = None
        profile_error: str | None = None
        mtu_contract = resolve_mtu_contract(
            [source_mtu_evidence, provider_mtu_evidence]
        )
        expected_path_mtu = int(mtu_contract["expected_mtu"])

        try:
            if cloud_operation_state.get("requested") and not cloud_operation_state.get(
                "detached"
            ):
                profile_error = str(
                    cloud_operation_state.get("error")
                    or "OpenStack did not confirm temporary floating-IP detachment"
                )
            else:
                control_side = "B" if str(spec.destination_side or "A") != "B" else "A"
                try:
                    control_endpoint, control_ip = self._endpoint_address(
                        spec.destination_group_id,
                        control_side,
                        spec.destination_subnet_id,
                    )
                except (KeyError, SuiteError):
                    control_endpoint, control_ip = None, ""

                if (
                    control_endpoint is not None
                    and control_endpoint.server_id != provider.server_id
                    and control_ip
                ):
                    control_baseline = self.probes.tcp.endpoint_port(
                        control_endpoint,
                        control_ip,
                        provider_ip,
                        4,
                        observer_port,
                    )
                    control_source_ip = control_ip

                if observer_ready and (
                    control_baseline is None or control_baseline.success
                ):
                    baseline = self.probes.tcp.endpoint_peer_identity(
                        source,
                        source_ip,
                        provider_ip,
                        4,
                        port=observer_port,
                    )
                    translated_source_ip = str(
                        baseline.diagnostics.get("observed_peer_ip") or ""
                    )
                if baseline is not None and baseline.success:
                    try:
                        mtu_profile = self._endpoint_json(
                            source,
                            performance_probe_code(
                                source_ip, provider_ip, 4, expected_path_mtu
                            ),
                        )
                        mtu_profile = classify_mtu_contract_probe(
                            mtu_profile,
                            expected_mtu=expected_path_mtu,
                            contract_authoritative=bool(mtu_contract["authoritative"]),
                        )
                        confirmed_path_mtu = confirmed_fragmentation_path_mtu(
                            mtu_profile,
                            expected_path_mtu,
                        )
                        destination_before = self._endpoint_json(
                            provider,
                            fragment_counter_probe_code(4),
                        )
                        raw_fragmentation_profile = self._endpoint_json(
                            source,
                            fragmentation_probe_code(
                                source_ip,
                                provider_ip,
                                4,
                                source_mtu,
                                confirmed_path_mtu,
                            ),
                        )
                        destination_after = self._endpoint_json(
                            provider,
                            fragment_counter_probe_code(4),
                        )
                        fragmentation_profile = classify_fragmentation_location(
                            raw_fragmentation_profile,
                            destination_before=destination_before,
                            destination_after=destination_after,
                            router_ids=[source_group.router_id],
                            router_backend_evidence=(
                                self._network_router_backend_evidence()
                            ),
                        )
                    except (
                        SuiteError,
                        OSError,
                        ValueError,
                        TypeError,
                        subprocess.SubprocessError,
                    ) as exc:
                        profile_error = str(exc)
        finally:
            if cloud_operation_state.get("detached"):
                self._restore_floating_ip_after_profile(cloud_operation_state)

        expected_translation_ips = sorted(
            str(item.get("ip_address") or "")
            for item in (gateway.get("external_fixed_ips") or [])
            if isinstance(item, dict) and item.get("ip_address")
        )
        if requested_mode == "floating-ip-egress" and floating_ip:
            expected_translation_ips = [floating_ip]
        translation_matches = (
            translated_source_ip in expected_translation_ips
            if translated_source_ip and expected_translation_ips
            else None
        )

        status = "PASS"
        observed = f"{mode_slug}-path-profiled"
        if cloud_operation_state.get("requested") and not cloud_operation_state.get(
            "detached"
        ):
            status = "ERROR"
            observed = "temporary-floating-ip-detach-unconfirmed"
            message = str(profile_error)
        elif cloud_operation_state.get("detached") and not cloud_operation_state.get(
            "restored"
        ):
            status = "ERROR"
            observed = "floating-ip-restoration-unconfirmed"
            message = str(
                cloud_operation_state.get("restore_error")
                or "The managed floating-IP association was not restored"
            )
        elif not observer_ready:
            status = "ERROR"
            observed = "provider-observer-service-unavailable"
            message = (
                f"The {mode_label} profile could not use the provider endpoint "
                "observer because its transient probe service was not ready"
            )
        elif control_baseline is not None and not control_baseline.success:
            status = "ERROR" if control_baseline.outcome == "error" else "UNVERIFIED"
            observed = "provider-observer-control-failed"
            message = (
                "The alternate provider control endpoint could not reach the exact "
                "provider observer service used by the translated-path test"
            )
        elif baseline is None:
            status = "UNVERIFIED"
            observed = f"{mode_slug}-baseline-not-run"
            message = f"The {mode_label} baseline was not run"
        elif not baseline.success:
            status = (
                "ERROR"
                if baseline.outcome == "error"
                else "UNVERIFIED"
                if baseline.outcome == "inconclusive"
                else "FAIL"
            )
            observed = f"{mode_slug}-provider-observer-failed"
            message = (
                f"The provider observer service was ready, but the project endpoint "
                f"could not establish the translated TCP flow through {mode_label}"
            )
        elif not translated_source_ip:
            status = "UNVERIFIED"
            observed = "translated-source-identity-unavailable"
            message = (
                f"The {mode_label} flow reached the provider observer, but the probe "
                "service did not return the translated source address"
            )
        elif not expected_translation_ips:
            status = "UNVERIFIED"
            observed = "expected-translation-identity-unavailable"
            message = (
                f"The {mode_label} flow reached the provider observer from "
                f"{translated_source_ip}, but OpenStack did not expose an expected "
                "translation address for comparison"
            )
        elif translation_matches is False:
            status = "FAIL"
            observed = "unexpected-source-translation-address"
            message = (
                f"The {mode_label} flow reached the provider observer from "
                f"{translated_source_ip}, but the expected translated source address "
                f"was {', '.join(expected_translation_ips)}"
            )
        elif profile_error or mtu_profile is None:
            status = "UNVERIFIED"
            observed = "packet-size-profile-unverified"
            message = (
                f"{mode_label.capitalize()} connectivity to the provider observer succeeded, "
                "but the packet-size profile could not be verified"
            )
        else:
            contract_status = str(
                mtu_profile.get("advertised_mtu_contract_status") or "unverified"
            )
            if contract_status == "failed":
                observed = "path-mtu-below-advertised"
            elif contract_status != "met":
                status = "UNVERIFIED"
                observed = "advertised-mtu-contract-unverified"
            discovered = confirmed_no_fragment_path_mtu(mtu_profile)
            local_constraint, local_class = local_mtu_constraint(mtu_profile)
            location = str(
                (fragmentation_profile or {}).get("fragmentation_location_label")
                or "fragmentation location unverified"
            )
            pmtud_status = str(mtu_profile.get("pmtud_status") or "unverified").replace(
                "-", " "
            )
            if discovered is not None:
                boundary_text = f"measured no-fragment path MTU {discovered} bytes"
            elif local_constraint is not None:
                boundary_text = (
                    f"local {str(local_class or 'MTU constraint').replace('-', ' ')} "
                    f"{local_constraint} bytes; current path boundary unverified"
                )
            else:
                boundary_text = "no-fragment path MTU unverified"
            message = (
                f"{mode_label.capitalize()} to the provider observer was reachable; "
                f"advertised MTU {expected_path_mtu} bytes; "
                f"{boundary_text}; "
                f"PMTUD evidence {pmtud_status}; {location}"
            )
            if contract_status == "failed":
                message += "; advisory MTU difference; remaining tests may continue"

        def probe_details(probe: Any) -> dict[str, Any] | None:
            if probe is None:
                return None
            return {
                "outcome": probe.outcome,
                "success": probe.success,
                "command": probe.command,
                "stdout": probe.stdout,
                "stderr": probe.stderr,
                "attempts": probe.attempts,
                "diagnostics": probe.diagnostics,
            }

        details = {
            "phase": spec.phase,
            "address_path": self._address_evidence(
                spec,
                ProbeResult(
                    "inconclusive",
                    False,
                    0,
                    0,
                    source_ip=source_ip,
                    destination_ip=provider_ip,
                    diagnostics={"observed_peer_ip": translated_source_ip or None},
                ),
                source,
                provider,
            ),
            "expectation_reason": spec.expectation_reason,
            "dependencies": spec.dependencies,
            **spec.metadata,
            "path_kind": path_kind,
            "egress_translation_mode": requested_mode,
            "translation_mode_label": mode_label,
            "floating_ip": floating_ip or None,
            "floating_ip_association_preexisting": floating_ip_preexisting,
            "floating_ip_created_for_profile": floating_ip_created_for_profile,
            "translated_source_ip_observed_by_provider": translated_source_ip or None,
            "provider_control_source_ip_observed_by_provider": control_source_ip
            or None,
            # Compatibility aliases for legacy report readers.
            "translated_source_ip_observed_by_runner": translated_source_ip or None,
            "provider_control_source_ip_observed_by_runner": control_source_ip or None,
            "expected_translation_ips": expected_translation_ips,
            "translation_matches_expected_identity": translation_matches,
            "source_network_mtu": source_mtu,
            "provider_observer_interface_mtu": provider_network_mtu,
            "runner_interface_mtu": provider_network_mtu,
            "external_provider_network_mtu": provider_network_mtu,
            "expected_no_fragment_path_mtu": expected_path_mtu,
            "mtu_contract": mtu_contract,
            "mtu_constraints": mtu_contract["constraints"],
            "limiting_mtu_constraints": mtu_contract["limiting_constraints"],
            "source_network_mtu_evidence": source_mtu_evidence,
            "external_provider_network_mtu_evidence": provider_mtu_evidence,
            "provider_observer_mtu_evidence": provider_mtu_evidence,
            "runner_interface_mtu_evidence": provider_mtu_evidence,
            "router_id": source_group.router_id,
            "router_source_nat_enabled": source_nat_enabled,
            "router_state": router_state,
            "provider_observer": {
                "endpoint": provider.label,
                "address": provider_ip,
                "tcp_port": observer_port,
                "service_ready": observer_ready,
                "probe_service": observer_service,
            },
            "runner_route": None,
            "runner_control_baseline": probe_details(control_baseline),
            "provider_observer_control_baseline": probe_details(control_baseline),
            "translation_baseline": probe_details(baseline),
            # Compatibility alias for legacy report readers.
            "tcp_baseline": probe_details(baseline),
            "temporary_floating_ip_cloud_operation": cloud_operation_state,
            "cloud_operation_performed": bool(
                cloud_operation_state.get("requested")
                or floating_ip_created_for_profile
            ),
            "mtu_profile": mtu_profile,
            "fragmentation_profile": fragmentation_profile,
            "profile_error": profile_error,
            "source_compute_host": source.host,
            "source_availability_zone": source.availability_zone,
            "destination_compute_host": provider.host,
            "destination_availability_zone": provider.availability_zone,
            "compute_placement": "project-to-provider-translation",
        }
        if status == "PASS" and observed == "path-mtu-below-advertised":
            details.update(
                mtu_advisory=True, health="warning", warning_reasons=[message]
            )
        likely_failure = None
        if status == "FAIL" and baseline is not None:
            likely_failure, diagnostic_details = self.diagnostics.collect(
                spec, baseline, source, provider
            )
            details.update(diagnostic_details)

        self.reporter.result(
            spec.id,
            spec.category,
            status,
            message,
            family=4,
            source=f"{source.label} ({source_ip})",
            destination=f"{provider.label} ({provider_ip})",
            duration_ms=int((time.monotonic() - started) * 1000),
            details=details,
            expected=spec.expectation,
            observed=observed,
            authoritative=status in {"PASS", "FAIL"},
            likely_failure=likely_failure,
            display_name=spec.display_name,
            scenario=spec.scenario,
        )
