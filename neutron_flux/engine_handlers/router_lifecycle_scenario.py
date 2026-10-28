from __future__ import annotations

import time
from typing import Any

from ..errors import RunCancelledError, SuiteError
from ..failure_injection import inject_failure
from ..models import ProbeResult, TestSpec
from ..network_contract import ONE_ROUTER_PROJECT_NETWORKS, group_kind_is


class RouterLifecycleScenarioHandlerMixin:
    """Run baseline, withdraw, and restore as one safely restored scenario."""

    @staticmethod
    def _probe_stage(probe: ProbeResult, status: str, message: str) -> dict[str, Any]:
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
    def _operation_stage(status: str, message: str, **details: Any) -> dict[str, Any]:
        return {"status": status, "message": message, **details}

    def _run_router_lifecycle_scenario(self, spec: TestSpec) -> None:
        source, source_ip = self._endpoint_address(
            spec.source_group_id, spec.source_side, spec.source_subnet_id
        )
        target_group = self._group(spec.destination_group_id)
        target, target_ip = self._endpoint_address(
            spec.destination_group_id,
            spec.destination_side,
            spec.destination_subnet_id,
        )
        if not group_kind_is(
            target_group.plan.kind,
            ONE_ROUTER_PROJECT_NETWORKS,
        ):
            raise SuiteError(
                "Router-interface lifecycle must use the dedicated one-router "
                "project-network topology"
            )
        if not target_group.router_id:
            raise SuiteError("Router-interface lifecycle requires a router")

        family = int(spec.family)
        protocol = str(spec.protocol or "tcp")
        side = str(spec.metadata.get("router_interface_side") or "B")
        subnet_id = (
            (target_group.metadata.get("side_subnet_ids") or {}).get(side)
            or target_group.metadata.get("router_interface_subnet_id")
            or target_group.subnet_ids[0]
        )
        stages: dict[str, Any] = {}
        baseline = self.probes.endpoint(protocol, source, source_ip, target_ip, family)
        if not (baseline.success and baseline.outcome == "reachable"):
            stages["baseline"] = self._probe_stage(
                baseline,
                "FAIL",
                "The routed baseline was not reachable",
            )
            stages["remove_attachment"] = self._operation_stage(
                "NOT_RUN",
                "The router attachment was not removed because the reachable baseline failed",
            )
            stages["withdrawn_connectivity"] = self._operation_stage(
                "NOT_RUN",
                "Connectivity after removal was not measured because no cloud operation occurred",
            )
            stages["restore_attachment"] = self._operation_stage(
                "NOT_RUN",
                "Restoration was not required because no cloud operation occurred",
            )
            stages["restored_connectivity"] = self._operation_stage(
                "NOT_RUN",
                "Restored connectivity was not measured because no cloud operation occurred",
            )
            self.reporter.result(
                spec.id,
                spec.category,
                "BLOCKED_BY_PREREQUISITE",
                "Router-interface lifecycle was not run because its reachable baseline failed",
                family=family,
                source=f"{source.label} ({source_ip})",
                destination=f"{target.label} ({target_ip})",
                duration_ms=baseline.elapsed_ms,
                expected=spec.expectation,
                observed="baseline-unreachable",
                authoritative=False,
                details={
                    "phase": spec.phase,
                    "address_path": self._address_evidence(
                        spec, baseline, source, target
                    ),
                    "expectation_reason": spec.expectation_reason,
                    "dependencies": spec.dependencies,
                    **spec.metadata,
                    "router_id": target_group.router_id,
                    "subnet_id": subnet_id,
                    "cloud_operation_performed": False,
                    "stages": stages,
                    "source_compute_host": source.host,
                    "destination_compute_host": target.host,
                    "source_availability_zone": source.availability_zone,
                    "destination_availability_zone": target.availability_zone,
                },
                display_name=spec.display_name,
                scenario=spec.scenario,
            )
            return

        stages["baseline"] = self._probe_stage(
            baseline, "PASS", "The routed baseline was reachable"
        )
        removed = False
        removal_api_state: dict[str, Any] | None = None
        withdrawn_probe: ProbeResult | None = None
        restore_api_state: dict[str, Any] | None = None
        restored_probe: ProbeResult | None = None
        cloud_operation_error: str | None = None
        restoration_error: str | None = None
        started = time.monotonic()

        cancellation: RunCancelledError | None = None
        command_attempted = False
        try:
            inject_failure(self.config, "before-router-interface-withdraw")
            command_attempted = True
            remove_result = None
            remove_command_error: str | None = None
            try:
                remove_result = self.builder.osc.run(
                    "router",
                    "remove",
                    "subnet",
                    target_group.router_id,
                    str(subnet_id),
                    check=False,
                    timeout=60,
                )
            except RunCancelledError as exc:
                cancellation = exc
                remove_command_error = str(exc)
            except (RuntimeError, OSError, ValueError, KeyError, SuiteError) as exc:
                remove_command_error = str(exc)

            removal_api_state = self.builder.wait_router_interface(
                target_group.router_id, str(subnet_id), present=False
            )
            removed = bool(
                removal_api_state.get("matched")
                and removal_api_state.get("present") is False
            )
            if (
                remove_result is not None
                and remove_result.returncode != 0
                and not removed
            ):
                remove_command_error = self._concise(
                    remove_result.stderr or remove_result.stdout
                )
            if not removed:
                raise SuiteError(
                    remove_command_error
                    or "OpenStack did not confirm that the router interface was removed"
                )
            if cancellation is None:
                withdrawn_probe = self._wait_endpoint_state(
                    source,
                    source_ip,
                    target_ip,
                    family,
                    protocol,
                    expected=False,
                )
        except RunCancelledError as exc:
            cancellation = exc
            cloud_operation_error = str(exc)
        except (RuntimeError, OSError, ValueError, KeyError, SuiteError) as exc:
            cloud_operation_error = str(exc)
            if command_attempted and removal_api_state is None:
                try:
                    removal_api_state = self.builder.wait_router_interface(
                        target_group.router_id, str(subnet_id), present=False
                    )
                    removed = bool(
                        removal_api_state.get("matched")
                        and removal_api_state.get("present") is False
                    )
                    if removed:
                        cloud_operation_error = None
                        if cancellation is None:
                            try:
                                withdrawn_probe = self._wait_endpoint_state(
                                    source,
                                    source_ip,
                                    target_ip,
                                    family,
                                    protocol,
                                    expected=False,
                                )
                            except (
                                RuntimeError,
                                OSError,
                                ValueError,
                                KeyError,
                            ) as probe_exc:
                                cloud_operation_error = str(probe_exc)
                except (RuntimeError, OSError, ValueError, KeyError, SuiteError):
                    pass
        finally:
            # A submitted remove is an uncertain cloud operation until the original
            # attachment has been re-established.  Always issue the idempotent
            # ensure-present operation, even when removal readback was
            # inconclusive or the CLI raised after submitting the request.
            if command_attempted:
                restore_result = None
                restore_command_error: str | None = None
                try:
                    inject_failure(self.config, "before-router-interface-return")
                    try:
                        restore_result = self.builder.osc.run(
                            "router",
                            "add",
                            "subnet",
                            target_group.router_id,
                            str(subnet_id),
                            check=False,
                            timeout=60,
                        )
                    except RunCancelledError as exc:
                        cancellation = cancellation or exc
                        restore_command_error = str(exc)
                    except (
                        RuntimeError,
                        OSError,
                        ValueError,
                        KeyError,
                        SuiteError,
                    ) as exc:
                        restore_command_error = str(exc)

                    restore_api_state = self.builder.wait_router_interface(
                        target_group.router_id, str(subnet_id), present=True
                    )
                    restored = bool(
                        restore_api_state.get("matched")
                        and restore_api_state.get("present") is True
                    )
                    if (
                        restore_result is not None
                        and restore_result.returncode != 0
                        and not restored
                    ):
                        restore_command_error = self._concise(
                            restore_result.stderr or restore_result.stdout
                        )
                    if not restored:
                        raise SuiteError(
                            restore_command_error
                            or "OpenStack did not confirm that the router interface was restored"
                        )
                    if cancellation is None:
                        restored_probe = self._wait_endpoint_state(
                            source,
                            source_ip,
                            target_ip,
                            family,
                            protocol,
                            expected=True,
                        )
                except RunCancelledError as exc:
                    cancellation = cancellation or exc
                    restoration_error = str(exc)
                except (
                    RuntimeError,
                    OSError,
                    ValueError,
                    KeyError,
                    SuiteError,
                ) as exc:
                    restoration_error = str(exc)
                    if restore_api_state is None:
                        try:
                            restore_api_state = self.builder.wait_router_interface(
                                target_group.router_id, str(subnet_id), present=True
                            )
                            restore_confirmed_after_retry = bool(
                                restore_api_state.get("matched")
                                and restore_api_state.get("present") is True
                            )
                            if restore_confirmed_after_retry:
                                restoration_error = None
                                if cancellation is None:
                                    try:
                                        restored_probe = self._wait_endpoint_state(
                                            source,
                                            source_ip,
                                            target_ip,
                                            family,
                                            protocol,
                                            expected=True,
                                        )
                                    except (
                                        RuntimeError,
                                        OSError,
                                        ValueError,
                                        KeyError,
                                    ) as probe_exc:
                                        restoration_error = str(probe_exc)
                        except (
                            RuntimeError,
                            OSError,
                            ValueError,
                            KeyError,
                            SuiteError,
                        ):
                            pass

        if cancellation is not None:
            raise cancellation

        removal_confirmed = bool(
            removal_api_state
            and removal_api_state.get("matched")
            and removal_api_state.get("present") is False
        )
        restore_confirmed = bool(
            restore_api_state
            and restore_api_state.get("matched")
            and restore_api_state.get("present") is True
        )
        stages["remove_attachment"] = self._operation_stage(
            "PASS" if removal_confirmed else "ERROR",
            (
                "OpenStack confirmed the router attachment was removed"
                if removal_confirmed
                else cloud_operation_error
                or "Router attachment removal was not confirmed"
            ),
            api_state=removal_api_state,
        )
        if withdrawn_probe is None:
            stages["withdrawn_connectivity"] = self._operation_stage(
                "NOT_RUN",
                "Connectivity after removal was not measured because removal did not complete",
            )
        else:
            withdrawn_ok = (
                not withdrawn_probe.success and withdrawn_probe.outcome == "blocked"
            )
            stages["withdrawn_connectivity"] = self._probe_stage(
                withdrawn_probe,
                "PASS" if withdrawn_ok else "FAIL",
                (
                    "Traffic became blocked after router-interface removal"
                    if withdrawn_ok
                    else "Traffic did not become blocked after router-interface removal"
                ),
            )
        stages["restore_attachment"] = self._operation_stage(
            (
                "PASS"
                if restore_confirmed
                else "ERROR"
                if command_attempted
                else "NOT_RUN"
            ),
            (
                "OpenStack confirmed the router attachment was restored"
                if restore_confirmed
                else restoration_error
                or (
                    "Restoration was not required"
                    if not command_attempted
                    else "Router attachment restoration was not confirmed"
                )
            ),
            api_state=restore_api_state,
        )
        if restored_probe is None:
            stages["restored_connectivity"] = self._operation_stage(
                "NOT_RUN",
                "Restored connectivity was not measured because restoration did not complete",
            )
        else:
            restored_ok = (
                restored_probe.success and restored_probe.outcome == "reachable"
            )
            stages["restored_connectivity"] = self._probe_stage(
                restored_probe,
                "PASS" if restored_ok else "FAIL",
                (
                    "Traffic returned after router-interface restoration"
                    if restored_ok
                    else "Traffic did not return after router-interface restoration"
                ),
            )

        withdrawn_ok = bool(
            withdrawn_probe
            and not withdrawn_probe.success
            and withdrawn_probe.outcome == "blocked"
        )
        restored_ok = bool(
            restored_probe
            and restored_probe.success
            and restored_probe.outcome == "reachable"
        )
        if restoration_error or (command_attempted and not restore_confirmed):
            status = "ERROR"
            observed = "restoration-failed"
            message = (
                restoration_error or "Router attachment restoration was not confirmed"
            )
        elif cloud_operation_error or not removal_confirmed:
            status = "ERROR"
            observed = "removal-failed"
            message = (
                cloud_operation_error or "Router attachment removal was not confirmed"
            )
        elif not withdrawn_ok:
            status = "FAIL"
            observed = "traffic-not-withdrawn"
            message = (
                "Router attachment was removed, but traffic did not become blocked"
            )
        elif not restored_ok:
            status = "FAIL"
            observed = "traffic-not-restored"
            message = "Router attachment was restored, but original connectivity did not return"
        else:
            status = "PASS"
            observed = "lifecycle-complete"
            message = (
                "Confirmed the complete router-interface lifecycle: reachable baseline, "
                "API-confirmed removal, blocked traffic, API-confirmed restoration, and "
                "recovered traffic"
            )

        self.reporter.result(
            spec.id,
            spec.category,
            status,
            message,
            family=family,
            source=f"{source.label} ({source_ip})",
            destination=f"{target.label} ({target_ip})",
            duration_ms=int((time.monotonic() - started) * 1000) + baseline.elapsed_ms,
            expected=spec.expectation,
            observed=observed,
            authoritative=True,
            details={
                "phase": spec.phase,
                "address_path": self._address_evidence(spec, baseline, source, target),
                "expectation_reason": spec.expectation_reason,
                "dependencies": spec.dependencies,
                **spec.metadata,
                "router_id": target_group.router_id,
                "subnet_id": subnet_id,
                "cloud_operation_submitted": command_attempted,
                "cloud_operation_performed": (
                    True if removal_confirmed else None if command_attempted else False
                ),
                "removal_confirmed": removal_confirmed,
                "restoration_required": command_attempted,
                "restoration_confirmed": restore_confirmed,
                "stages": stages,
                "source_compute_host": source.host,
                "destination_compute_host": target.host,
                "source_availability_zone": source.availability_zone,
                "destination_availability_zone": target.availability_zone,
            },
            display_name=spec.display_name,
            scenario=spec.scenario,
        )
