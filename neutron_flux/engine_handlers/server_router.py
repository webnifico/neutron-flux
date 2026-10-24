from __future__ import annotations

import threading
import time

# mypy: disable-error-code="attr-defined"
from ..convergence import finish_convergence
from ..errors import SuiteError
from ..failure_injection import inject_failure
from ..models import Endpoint, ProbeResult, TestSpec


class ServerRouterLifecycleHandlerMixin:
    """Compatibility mixin for this test-operation family."""

    def _run_router_withdraw(self, spec: TestSpec) -> None:
        source, source_ip = self._endpoint_address(
            spec.source_group_id, spec.source_side, spec.source_subnet_id
        )
        target_group = self._group(spec.destination_group_id)
        target, target_ip = self._endpoint_address(
            spec.destination_group_id, spec.destination_side, spec.destination_subnet_id
        )
        if not target_group.router_id:
            raise SuiteError("Router-interface lifecycle requires a router")
        baseline = self.probes.endpoint(
            str(spec.protocol), source, source_ip, target_ip, int(spec.family)
        )
        state_key = f"router:{target_group.plan.id}"
        if not baseline.success:
            self.lifecycle[state_key] = {
                "source": source,
                "source_ip": source_ip,
                "target": target,
                "target_ip": target_ip,
                "router_id": target_group.router_id,
                "baseline": False,
                "family": spec.family,
                "protocol": spec.protocol,
                "cloud_operation_performed": False,
            }
            spec.authoritative = False
            spec.metadata["authority_required"] = True
            spec.expectation_reason = "the routed baseline was not reachable, so the router interface was not removed"
            probe = ProbeResult(
                outcome="inconclusive",
                success=False,
                elapsed_ms=baseline.elapsed_ms,
                attempts=baseline.attempts,
                source_ip=source_ip,
                destination_ip=target_ip,
                protocol=str(spec.protocol),
                diagnostics={
                    "baseline_outcome": baseline.outcome,
                    "cloud_operation_performed": False,
                },
            )
            self._record(spec, probe, source, target)
            return
        side = str(spec.metadata.get("router_interface_side") or "")
        subnet_id = (
            (
                (target_group.metadata.get("side_subnet_ids") or {}).get(side)
                if side
                else None
            )
            or target_group.metadata.get("router_interface_subnet_id")
            or target_group.subnet_ids[0]
        )
        inject_failure(self.config, "before-router-interface-withdraw")
        result = self.builder.osc.run(
            "router",
            "remove",
            "subnet",
            target_group.router_id,
            str(subnet_id),
            check=False,
            timeout=60,
        )
        if result.returncode != 0:
            raise SuiteError(self._concise(result.stderr or result.stdout))
        state = {
            "source": source,
            "source_ip": source_ip,
            "target": target,
            "target_ip": target_ip,
            "router_id": target_group.router_id,
            "subnet_id": subnet_id,
            "baseline": baseline.success,
            "family": spec.family,
            "protocol": spec.protocol,
            "cloud_operation_performed": True,
            "cloud_operation_confirmed": False,
        }
        self.lifecycle[state_key] = state
        api_state = self.builder.wait_router_interface(
            target_group.router_id, str(subnet_id), present=False
        )
        state["cloud_operation_confirmed"] = bool(api_state.get("matched"))
        probe = self._wait_endpoint_state(
            source,
            source_ip,
            target_ip,
            int(spec.family),
            str(spec.protocol),
            expected=False,
        )
        probe.diagnostics["router_interface_api_state"] = api_state
        if not api_state.get("matched"):
            probe = ProbeResult(
                outcome="error",
                success=False,
                elapsed_ms=probe.elapsed_ms,
                attempts=probe.attempts,
                stderr="OpenStack did not confirm that the router interface was removed",
                source_ip=source_ip,
                destination_ip=target_ip,
                protocol=str(spec.protocol),
                diagnostics={"router_interface_api_state": api_state},
            )
        self._record(spec, probe, source, target)

    def _run_router_return(self, spec: TestSpec) -> None:
        state = self._require_state(f"router:{spec.destination_group_id}")
        if not state.get("cloud_operation_performed"):
            spec.authoritative = False
            spec.metadata["authority_required"] = True
            spec.expectation_reason = "the router interface was not removed because the reachable baseline was unavailable"
            probe = ProbeResult(
                outcome="inconclusive",
                success=False,
                elapsed_ms=0,
                attempts=0,
                source_ip=state.get("source_ip"),
                destination_ip=state.get("target_ip"),
                protocol=str(state.get("protocol") or "tcp"),
                diagnostics={"cloud_operation_performed": False},
            )
            self._record(spec, probe, state.get("source"), state.get("target"))
            return
        inject_failure(self.config, "before-router-interface-return")
        result = self.builder.osc.run(
            "router",
            "add",
            "subnet",
            state["router_id"],
            state["subnet_id"],
            check=False,
            timeout=60,
        )
        if result.returncode != 0:
            raise SuiteError(self._concise(result.stderr or result.stdout))
        api_state = self.builder.wait_router_interface(
            state["router_id"], str(state["subnet_id"]), present=True
        )
        probe = self._wait_endpoint_state(
            state["source"],
            state["source_ip"],
            state["target_ip"],
            int(state["family"]),
            str(state["protocol"]),
            expected=bool(state["baseline"]),
        )
        probe.diagnostics["router_interface_api_state"] = api_state
        if not api_state.get("matched"):
            probe = ProbeResult(
                outcome="error",
                success=False,
                elapsed_ms=probe.elapsed_ms,
                attempts=probe.attempts,
                stderr="OpenStack did not confirm that the logical router attachment was restored",
                source_ip=state["source_ip"],
                destination_ip=state["target_ip"],
                protocol=str(state["protocol"]),
                diagnostics={"router_interface_api_state": api_state},
            )
        self._record(spec, probe, state["source"], state["target"])

    def _run_shared_server_lifecycle(
        self, stops: list[TestSpec], starts: list[TestSpec]
    ) -> None:
        """One stop/start pair, with independently observed address-family checks."""
        observations = {}
        for spec in stops:
            try:
                source, source_ip = self._endpoint_address(
                    spec.source_group_id, spec.source_side, spec.source_subnet_id
                )
                target, target_ip = self._endpoint_address(
                    spec.destination_group_id,
                    spec.destination_side,
                    spec.destination_subnet_id,
                )
                baseline = self.probes.endpoint(
                    str(spec.protocol), source, source_ip, target_ip, int(spec.family)
                )
                observations[spec.family] = (
                    source,
                    source_ip,
                    target,
                    target_ip,
                    baseline,
                )
            except (SuiteError, OSError, ValueError, TypeError, KeyError) as exc:
                from ..errors import RunCancelledError

                if isinstance(exc, RunCancelledError):
                    raise
                observations[spec.family] = None
        primary = next(
            (
                s
                for s in stops
                if observations.get(s.family) and observations[s.family][-1].success
            ),
            stops[0],
        )
        start = next(s for s in starts if s.family == primary.family)
        self._run_one(primary)
        state_key = (
            f"server:{primary.destination_group_id}:{primary.destination_side.upper()}"
        )
        state = self.lifecycle.get(state_key) or {}
        for spec in stops:
            if spec is primary:
                continue
            observation = observations.get(spec.family)
            if (
                not observation
                or not observation[-1].success
                or not state.get("cloud_operation_confirmed")
            ):
                self.reporter.result(
                    spec.id,
                    spec.category,
                    "BLOCKED_BY_PREREQUISITE",
                    "Family baseline or shared server-stop confirmation is unavailable",
                    family=spec.family,
                    expected=spec.expectation,
                    observed="not-run",
                    authoritative=False,
                    details={
                        "shared_operation_test_id": primary.id,
                        "cloud_operation_performed": False,
                    },
                    display_name=spec.display_name,
                    scenario=spec.scenario,
                )
                continue
            source, source_ip, target, target_ip, _ = observation
            try:
                probe = self._wait_endpoint_state(
                    source,
                    source_ip,
                    target_ip,
                    int(spec.family),
                    str(spec.protocol),
                    expected=False,
                )
                probe.diagnostics.update(
                    shared_operation_test_id=primary.id, cloud_operation_performed=False
                )
                self._record(spec, probe, source, target)
            except (SuiteError, OSError, ValueError, TypeError, KeyError) as exc:
                from ..errors import RunCancelledError

                if isinstance(exc, RunCancelledError):
                    raise
                self.reporter.result(
                    spec.id,
                    spec.category,
                    "ERROR",
                    str(exc),
                    family=spec.family,
                    authoritative=False,
                    display_name=spec.display_name,
                    scenario=spec.scenario,
                )
        # Restoration is attempted even if a withdrawal probe failed.
        self._run_one(start)
        for spec in starts:
            if spec is start:
                continue
            observation = observations.get(spec.family)
            if (
                not observation
                or not observation[-1].success
                or not state.get("start_confirmed")
            ):
                self.reporter.result(
                    spec.id,
                    spec.category,
                    "BLOCKED_BY_PREREQUISITE",
                    "Family baseline or shared server-start recovery is unavailable",
                    family=spec.family,
                    expected=spec.expectation,
                    observed="not-run",
                    authoritative=False,
                    details={
                        "shared_operation_test_id": start.id,
                        "cloud_operation_performed": False,
                    },
                    display_name=spec.display_name,
                    scenario=spec.scenario,
                )
                continue
            source, source_ip, target, target_ip, _ = observation
            try:
                probe = self._wait_endpoint_state(
                    source,
                    source_ip,
                    target_ip,
                    int(spec.family),
                    str(spec.protocol),
                    expected=True,
                )
                probe.diagnostics.update(
                    shared_operation_test_id=start.id, cloud_operation_performed=False
                )
                self._record(spec, probe, source, target)
            except (SuiteError, OSError, ValueError, TypeError, KeyError) as exc:
                from ..errors import RunCancelledError

                if isinstance(exc, RunCancelledError):
                    raise
                self.reporter.result(
                    spec.id,
                    spec.category,
                    "ERROR",
                    str(exc),
                    family=spec.family,
                    authoritative=False,
                    display_name=spec.display_name,
                    scenario=spec.scenario,
                )

    def _run_server_stop(self, spec: TestSpec) -> None:
        source, source_ip = self._endpoint_address(
            spec.source_group_id, spec.source_side, spec.source_subnet_id
        )
        group = self._group(spec.destination_group_id)
        target, target_ip = self._endpoint_address(
            spec.destination_group_id, spec.destination_side, spec.destination_subnet_id
        )
        baseline = self.probes.endpoint(
            str(spec.protocol), source, source_ip, target_ip, int(spec.family)
        )
        state_key = f"server:{group.plan.id}:{target.side}"
        if not baseline.success:
            self.lifecycle[state_key] = {
                "source": source,
                "source_ip": source_ip,
                "target": target,
                "target_ip": target_ip,
                "baseline": False,
                "family": spec.family,
                "protocol": spec.protocol,
                "cloud_operation_performed": False,
            }
            spec.authoritative = False
            spec.metadata["authority_required"] = True
            spec.expectation_reason = "the endpoint service was not reachable before the lifecycle test, so the VM was not stopped"
            probe = ProbeResult(
                outcome="inconclusive",
                success=False,
                elapsed_ms=baseline.elapsed_ms,
                attempts=baseline.attempts,
                source_ip=source_ip,
                destination_ip=target_ip,
                protocol=str(spec.protocol),
                diagnostics={
                    "baseline_outcome": baseline.outcome,
                    "cloud_operation_performed": False,
                },
            )
            self._record(spec, probe, source, target)
            return
        inject_failure(self.config, "before-server-stop")
        lifecycle_lock = getattr(self.builder, "lifecycle_lock", None)
        if lifecycle_lock is None:
            lifecycle_lock = threading.RLock()
            self.builder.lifecycle_lock = lifecycle_lock
        with lifecycle_lock:
            result = self.builder.osc.run(
                "server", "stop", target.server_id, check=False, timeout=60
            )
            if result.returncode != 0:
                raise SuiteError(self._concise(result.stderr or result.stdout))
            state = {
                "source": source,
                "source_ip": source_ip,
                "target": target,
                "target_ip": target_ip,
                "baseline": baseline.success,
                "family": spec.family,
                "protocol": spec.protocol,
                "cloud_operation_performed": True,
                "cloud_operation_confirmed": False,
            }
            self.lifecycle[state_key] = state
            self.builder._wait_for_status(
                "server",
                target.server_id,
                {"shutoff"},
                {"error"},
                display_name=target.server_name,
            )
            settle = getattr(self.builder, "_wait_for_server_settlement", None)
            if getattr(
                self.builder, "lifecycle_settlement_enabled", False
            ) and callable(settle):
                settle(
                    target.server_id,
                    [
                        target.management_port_id,
                        target.test_port_id or "",
                    ],
                    expected_statuses={"shutoff"},
                    expected_host=target.host,
                    display_name=target.server_name,
                )
            coordinator = getattr(self.builder, "cloud_operation_coordinator", None)
            if coordinator is not None:
                coordinator.settle(
                    "server-lifecycle",
                    f"allow stopped server {target.server_name} and its VIF state to settle",
                    seconds=10.0,
                )
        state["cloud_operation_confirmed"] = True
        probe = self._wait_endpoint_state(
            source,
            source_ip,
            target_ip,
            int(spec.family),
            str(spec.protocol),
            expected=False,
        )
        self._record(spec, probe, source, target)

    def _run_server_start(self, spec: TestSpec) -> None:
        state = self._require_state(
            f"server:{spec.destination_group_id}:{spec.destination_side.upper()}"
        )
        target: Endpoint = state["target"]
        if not state.get("cloud_operation_performed"):
            spec.authoritative = False
            spec.metadata["authority_required"] = True
            spec.expectation_reason = (
                "the VM was not stopped because the endpoint baseline was unavailable"
            )
            probe = ProbeResult(
                outcome="inconclusive",
                success=False,
                elapsed_ms=0,
                attempts=0,
                source_ip=state.get("source_ip"),
                destination_ip=state.get("target_ip"),
                protocol=str(state.get("protocol") or "tcp"),
                diagnostics={"cloud_operation_performed": False},
            )
            self._record(spec, probe, state.get("source"), target)
            return
        inject_failure(self.config, "before-server-start")
        lifecycle_lock = getattr(self.builder, "lifecycle_lock", None)
        if lifecycle_lock is None:
            lifecycle_lock = threading.RLock()
            self.builder.lifecycle_lock = lifecycle_lock
        with lifecycle_lock:
            result = self.builder.osc.run(
                "server", "start", target.server_id, check=False, timeout=60
            )
            if result.returncode != 0:
                raise SuiteError(self._concise(result.stderr or result.stdout))
            self.builder._wait_for_status(
                "server",
                target.server_id,
                {"active"},
                {"error"},
                display_name=target.server_name,
            )
            settle = getattr(self.builder, "_wait_for_server_settlement", None)
            if getattr(
                self.builder, "lifecycle_settlement_enabled", False
            ) and callable(settle):
                settle(
                    target.server_id,
                    [
                        target.management_port_id,
                        target.test_port_id or "",
                    ],
                    expected_statuses={"active"},
                    expected_host=target.host,
                    display_name=target.server_name,
                )
            if not self.builder._wait_for_ssh(
                target.management_ip,
                proxy=True,
                timeout=self.config.convergence_timeout,
            ):
                raise SuiteError(
                    f"Management SSH did not return after starting {target.server_name}"
                )
            self.builder.reconfigure_endpoint(target)
            coordinator = getattr(self.builder, "cloud_operation_coordinator", None)
            if coordinator is not None:
                coordinator.settle(
                    "server-lifecycle",
                    f"allow started server {target.server_name} and its VIF state to settle",
                    seconds=10.0,
                )
        state["start_confirmed"] = True
        probe = self._wait_endpoint_state(
            state["source"],
            state["source_ip"],
            state["target_ip"],
            int(state["family"]),
            str(state["protocol"]),
            expected=bool(state["baseline"]),
        )
        self._record(spec, probe, state["source"], target)

    def _wait_endpoint_state(
        self,
        source: Endpoint,
        source_ip: str,
        destination_ip: str,
        family: int,
        protocol: str,
        *,
        expected: bool,
        destination_port: int | None = None,
    ) -> ProbeResult:
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
            last = self._execute_endpoint_probe(
                source,
                source_ip,
                destination_ip,
                family,
                protocol,
                destination_port=destination_port,
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
                stderr="convergence probe produced no result",
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol=protocol,
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
