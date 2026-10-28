from __future__ import annotations

# mypy: disable-error-code="attr-defined"
from ..errors import SuiteError
from ..models import ProbeResult, TestSpec
from ..network_contract import static_route_state_key


class StaticRouteLifecycleHandlerMixin:
    """Execute the two-router static-route lifecycle."""

    def _set_static_routes(self, runtime, *, enabled: bool) -> None:
        method = getattr(self.builder, "set_static_routes", None)
        if method is None:
            method = self.builder.set_extra_routes
        method(runtime, enabled=enabled)

    def _set_one_static_route(self, runtime, *, side: str, enabled: bool) -> None:
        method = getattr(self.builder, "set_one_static_route", None)
        if method is None:
            method = self.builder.set_one_extra_route
        method(runtime, side=side, enabled=enabled)

    def _static_route_state(self, group_id: str) -> dict:
        canonical_key = static_route_state_key(group_id)
        state = self.lifecycle.get(canonical_key)
        if state is not None:
            return state
        # In-memory compatibility for callers exercising a legacy approved plan.
        return self._require_state(f"extra-route:{group_id}")

    def _run_static_route_baseline(self, spec: TestSpec) -> None:
        source, source_ip = self._endpoint_address(
            spec.source_group_id, spec.source_side, spec.source_subnet_id
        )
        destination, destination_ip = self._endpoint_address(
            spec.destination_group_id, spec.destination_side, spec.destination_subnet_id
        )
        runtime = self._group(spec.destination_group_id)
        if runtime.metadata.get("routes_installed"):
            self._set_static_routes(runtime, enabled=False)
        probe = self._wait_endpoint_state(
            source,
            source_ip,
            destination_ip,
            int(spec.family),
            str(spec.protocol),
            expected=False,
        )
        state = {
            "family": spec.family,
            "baseline_blocked": probe.outcome == "blocked" and probe.success is False,
            "routes_installed": False,
            "route_setup_error": None,
            "removed_route_side": None,
        }
        self.lifecycle[static_route_state_key(runtime.plan.id)] = state
        self.lifecycle[f"extra-route:{runtime.plan.id}"] = state
        self._record(spec, probe, source, destination)

    def _run_static_route_install(self, spec: TestSpec) -> None:
        runtime = self._group(spec.destination_group_id)
        state = self._static_route_state(runtime.plan.id)
        source, source_ip = self._endpoint_address(
            spec.source_group_id, spec.source_side, spec.source_subnet_id
        )
        destination, destination_ip = self._endpoint_address(
            spec.destination_group_id, spec.destination_side, spec.destination_subnet_id
        )
        if not state.get("baseline_blocked"):
            spec.authoritative = False
            spec.metadata["authority_required"] = True
            spec.expectation_reason = "the no-route baseline was not stably blocked, so the route transition is unverified"
            probe = ProbeResult(
                outcome="inconclusive",
                success=False,
                elapsed_ms=0,
                attempts=0,
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol=str(spec.protocol),
            )
            self._record(spec, probe, source, destination)
            return
        try:
            self._set_static_routes(runtime, enabled=True)
        except SuiteError as exc:
            state["route_setup_error"] = str(exc)
            state["routes_installed"] = True
            try:
                self._set_static_routes(runtime, enabled=False)
                state["routes_installed"] = False
            except SuiteError as rollback_exc:
                state["route_rollback_error"] = str(rollback_exc)
            raise
        state["routes_installed"] = True
        probe = self._wait_endpoint_state(
            source,
            source_ip,
            destination_ip,
            int(spec.family),
            str(spec.protocol),
            expected=True,
        )
        self._record(spec, probe, source, destination)

    def _run_static_route_withdraw(self, spec: TestSpec) -> None:
        runtime = self._group(spec.destination_group_id)
        state = self._static_route_state(runtime.plan.id)
        source, source_ip = self._endpoint_address(
            spec.source_group_id, spec.source_side, spec.source_subnet_id
        )
        destination, destination_ip = self._endpoint_address(
            spec.destination_group_id, spec.destination_side, spec.destination_subnet_id
        )
        if not state.get("routes_installed"):
            spec.authoritative = False
            spec.metadata["authority_required"] = True
            spec.expectation_reason = (
                "the OpenStack router static routes were not installed, so "
                "route withdrawal cannot be measured"
            )
            probe = ProbeResult(
                outcome="inconclusive",
                success=False,
                elapsed_ms=0,
                attempts=0,
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol=str(spec.protocol),
                diagnostics={"route_setup_error": state.get("route_setup_error")},
            )
            self._record(spec, probe, source, destination)
            return
        baseline = self.probes.endpoint(
            str(spec.protocol), source, source_ip, destination_ip, int(spec.family)
        )
        if not baseline.success:
            spec.authoritative = False
            spec.metadata["authority_required"] = True
            spec.expectation_reason = (
                "the selected routed path was not reachable immediately before "
                "router static-route withdrawal"
            )
            probe = ProbeResult(
                outcome="inconclusive",
                success=False,
                elapsed_ms=baseline.elapsed_ms,
                attempts=baseline.attempts,
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol=str(spec.protocol),
                diagnostics={"baseline_outcome": baseline.outcome},
            )
            self._record(spec, probe, source, destination)
            return
        side = str(spec.metadata.get("route_side", "A"))
        # Record enough restoration state immediately before the changing call.
        # If Neutron accepts the request and the subsequent readback fails, the
        # paired restore operation can still return the topology to its original
        # state. Re-adding an existing route is reconciled idempotently by the
        # runtime helper.
        state["removed_route_side"] = side
        state["removed_source"] = source
        state["removed_source_ip"] = source_ip
        state["removed_destination"] = destination
        state["removed_destination_ip"] = destination_ip
        state["removed_protocol"] = spec.protocol
        state["route_removal_confirmed"] = False
        self._set_one_static_route(runtime, side=side, enabled=False)
        state["route_removal_confirmed"] = True
        probe = self._wait_endpoint_state(
            source,
            source_ip,
            destination_ip,
            int(spec.family),
            str(spec.protocol),
            expected=False,
        )
        self._record(spec, probe, source, destination)

    def _run_static_route_restore(self, spec: TestSpec) -> None:
        runtime = self._group(spec.destination_group_id)
        state = self._static_route_state(runtime.plan.id)
        side = state.get("removed_route_side")
        if not side:
            spec.authoritative = False
            spec.metadata["authority_required"] = True
            spec.expectation_reason = (
                "no router static route was withdrawn, so restoration cannot "
                "be measured"
            )
            source, source_ip = self._endpoint_address(
                spec.source_group_id, spec.source_side, spec.source_subnet_id
            )
            destination, destination_ip = self._endpoint_address(
                spec.destination_group_id,
                spec.destination_side,
                spec.destination_subnet_id,
            )
            probe = ProbeResult(
                outcome="inconclusive",
                success=False,
                elapsed_ms=0,
                attempts=0,
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol=str(spec.protocol),
            )
            self._record(spec, probe, source, destination)
            return
        self._set_one_static_route(runtime, side=str(side), enabled=True)
        runtime.metadata["routes_installed"] = True
        state["routes_installed"] = True
        source = state["removed_source"]
        destination = state["removed_destination"]
        probe = self._wait_endpoint_state(
            source,
            state["removed_source_ip"],
            state["removed_destination_ip"],
            int(spec.family),
            str(state.get("removed_protocol") or spec.protocol),
            expected=True,
        )
        self._record(spec, probe, source, destination)

    # Legacy approved-plan and direct integration compatibility.
    _run_extra_route_baseline = _run_static_route_baseline
    _run_extra_route_add = _run_static_route_install
    _run_extra_route_remove = _run_static_route_withdraw
    _run_extra_route_restore = _run_static_route_restore
