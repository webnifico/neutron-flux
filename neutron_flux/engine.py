from __future__ import annotations

import copy
import dataclasses
import time
from collections.abc import Iterable
from typing import Any

from .config import Config
from .diagnostics import DiagnosticCollector
from .engine_handlers.common import EngineCommonMixin
from .engine_handlers.endpoint import EndpointProbeHandlerMixin
from .engine_handlers.floating_ip import FloatingIPLifecycleHandlerMixin
from .engine_handlers.floating_ip_peer import FloatingIPPeerHandlerMixin
from .engine_handlers.mtu_scenario import MTUScenarioHandlerMixin
from .engine_handlers.packet_size import PacketSizeProfileHandlerMixin
from .engine_handlers.registry import bind_operations
from .engine_handlers.router_lifecycle_scenario import (
    RouterLifecycleScenarioHandlerMixin,
)
from .engine_handlers.security import SecurityLifecycleHandlerMixin
from .engine_handlers.server_router import ServerRouterLifecycleHandlerMixin
from .engine_handlers.static_route import StaticRouteLifecycleHandlerMixin
from .engine_state import EngineDependencies, LifecycleStateStore, RouteObservationCache
from .errors import RunCancelledError, SuiteError
from .models import Endpoint, ProbeResult, RuntimeGroup, TestSpec
from .policy import PolicyEvaluator
from .probes import ProbeContext, ProbeRegistry
from .reporting import Reporter
from .resources import ResourceBuilder
from .result_context import recorded_execution_stage
from .scheduling import ACTIVITY, PROBE_WORKERS, admission, bounded_map, timed


class TestEngine(
    EndpointProbeHandlerMixin,
    MTUScenarioHandlerMixin,
    RouterLifecycleScenarioHandlerMixin,
    SecurityLifecycleHandlerMixin,
    FloatingIPLifecycleHandlerMixin,
    FloatingIPPeerHandlerMixin,
    PacketSizeProfileHandlerMixin,
    StaticRouteLifecycleHandlerMixin,
    ServerRouterLifecycleHandlerMixin,
    EngineCommonMixin,
):
    def __init__(
        self,
        config: Config,
        discovery: Any,
        builder: ResourceBuilder,
        reporter: Reporter,
        *,
        diagnostic_builders: dict[str, Any] | None = None,
    ):
        self._runtime_groups = tuple(builder.runtime_groups)
        self.execution_stage_override: str | None = None
        self.dependencies = EngineDependencies(config, discovery, builder, reporter)
        self.config = config
        self.discovery = discovery
        self.builder = builder
        self.reporter = reporter
        self.logger = reporter.logger
        self.policy = PolicyEvaluator()
        self.probes = ProbeRegistry(
            ProbeContext(
                endpoint_executor=builder.ssh_endpoint,
                controller_executor=builder.ssh_controller,
                tcp_port=config.tcp_port,
                udp_port=config.udp_port,
            )
        )
        self.diagnostics = DiagnosticCollector(
            builder, reporter, endpoint_builders=diagnostic_builders
        )
        self.lifecycle: LifecycleStateStore = LifecycleStateStore()
        self._router_backend_evidence_cache: dict[str, Any] | None = None
        self._route_observation_cache: RouteObservationCache | None = None
        self.operations = bind_operations(self)

    @property
    def groups(self) -> dict[str, RuntimeGroup]:
        runtimes = getattr(self, "_runtime_groups", self.builder.runtime_groups)
        return {item.plan.id: item for item in runtimes}

    @staticmethod
    def parallel_probe(spec: TestSpec) -> bool:
        return spec.operation == "probe" and str(spec.protocol) in {
            "icmp",
            "tcp",
            "udp",
        }

    def run_specs(self, specs: Iterable[TestSpec]) -> None:
        pending = [
            dataclasses.replace(
                spec,
                metadata={
                    **spec.metadata,
                    "execution_stage": (
                        "pre-migration"
                        if spec.metadata.get("pre_migration_functional_barrier")
                        else spec.metadata.get("execution_stage")
                        or getattr(self, "execution_stage_override", None)
                        or recorded_execution_stage(spec.metadata)
                        or "initial-testing"
                    ),
                },
            )
            for spec in specs
            if not self.reporter.has_result(spec.id)
        ]
        if not pending:
            return
        with ACTIVITY.scope(
            exclusive=any(not self.parallel_probe(spec) for spec in pending),
            reporter=self.reporter,
            label="functional test batch",
        ):
            wave: list[TestSpec] = []
            shared: dict[str, tuple[list[TestSpec], list[TestSpec]]] = {}
            consumed: set[str] = set()
            for first_index, candidate in enumerate(pending):
                if candidate.operation != "server-stop" or candidate.id in consumed:
                    continue
                group = []
                for item in pending[first_index:]:
                    if item.operation not in {"server-stop", "server-start"} or (
                        item.destination_group_id,
                        item.destination_side,
                    ) != (candidate.destination_group_id, candidate.destination_side):
                        break
                    group.append(item)
                stops = [s for s in group if s.operation == "server-stop"]
                starts = [s for s in group if s.operation == "server-start"]
                if (
                    len(stops) > 1
                    and {s.family for s in stops} == {s.family for s in starts}
                    and len(stops) == len(starts)
                    and not any(s.requires_pass for s in group)
                ):
                    shared[candidate.id] = (stops, starts)
                    consumed.update(s.id for s in group)
            for spec in pending:
                if spec.id in shared:
                    self._run_probe_wave(wave)
                    wave = []
                    self._run_shared_server_lifecycle(*shared[spec.id])
                    continue
                if spec.id in consumed:
                    continue
                if self.parallel_probe(spec):
                    wave.append(spec)
                else:
                    self._run_probe_wave(wave)
                    wave = []
                    self._run_one(spec)
            self._run_probe_wave(wave)

    def _run_probe_wave(self, specs: list[TestSpec]) -> None:
        pending = list(specs)
        while pending:
            ids = {spec.id for spec in pending}
            ready = [
                spec
                for spec in pending
                if not ids.intersection([*spec.requires, *spec.requires_pass])
            ]
            if not ready:
                for spec in pending:
                    self.reporter.result(
                        spec.id,
                        spec.category,
                        "BLOCKED_BY_PREREQUISITE",
                        "Cyclic prerequisites prevent this probe batch from running",
                        family=spec.family,
                        expected=spec.expectation,
                        observed="prerequisite-cycle",
                        authoritative=False,
                        details={
                            "pending_test_ids": sorted(ids),
                            "cloud_operation_performed": False,
                        },
                    )
                return

            # Peer protocols use the same concrete endpoints. A new cache for
            # every ready wave prevents evidence crossing prerequisites,
            # lifecycle changes, performance work or migration safety rounds.
            routes = RouteObservationCache()

            def probe(
                spec: TestSpec, observations: RouteObservationCache = routes
            ) -> None:
                engine = copy.copy(self)
                engine._route_observation_cache = observations
                engine._router_backend_evidence_cache = None
                engine.operations = bind_operations(engine)
                with admission("probe", self.reporter):
                    engine._run_one(spec)

            bounded_map(probe, ready, workers=PROBE_WORKERS)
            completed = {spec.id for spec in ready}
            pending = [spec for spec in pending if spec.id not in completed]

    def _run_one(self, spec: TestSpec) -> None:
        if self.reporter.has_result(spec.id):
            return
        started = time.monotonic()
        with timed(self.reporter, "functional-test", spec.id):
            try:
                self._run_spec(spec)
            except RunCancelledError:
                raise
            except Exception as exc:
                evidence = dict(getattr(exc, "evidence", {}) or {})
                evidence.update(exception_type=type(exc).__name__, message=str(exc))
                source, source_ip = self._failure_endpoint(spec, "source")
                destination, destination_ip = self._failure_endpoint(
                    spec, "destination"
                )
                probe = ProbeResult(
                    outcome="error",
                    success=False,
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                    attempts=1,
                    stderr=str(exc),
                    stdout=str(evidence.get("stdout") or ""),
                    command=str(evidence.get("command") or ""),
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    protocol=spec.protocol,
                    diagnostics={"execution_error": evidence},
                )
                self._record(spec, probe, source, destination)

    def _failure_endpoint(
        self, spec: TestSpec, role: str
    ) -> tuple[Endpoint | None, str | None]:
        """Recover known placement locally; reporting must not rerun setup."""
        if role == "source" and spec.operation == "controller-probe":
            return (
                self.builder.controller,
                self.builder.controller_probe_sources.get(spec.family),
            )
        if role == "destination" and spec.operation == "egress":
            return None, spec.metadata.get("target")
        group = self.groups.get(getattr(spec, f"{role}_group_id"))
        if group is None:
            return None, None
        endpoint = group.endpoint(getattr(spec, f"{role}_side"))
        if endpoint is None:
            return None, None
        if role == "destination" and spec.operation in {
            "fip-peer",
            "fip-baseline",
            "fip-withdraw",
            "fip-return",
        }:
            return endpoint, group.fips.get(endpoint.label, {}).get("address")
        try:
            address = self._address(group, endpoint, getattr(spec, f"{role}_subnet_id"))
        except (SuiteError, IndexError, KeyError):
            address = None
        return endpoint, address

    def _run_spec(self, spec: TestSpec) -> None:
        failed_prerequisites: list[dict[str, str]] = []
        for test_id in spec.requires_pass:
            result = self.reporter.get_result(test_id)
            status = str(result.status) if result is not None else "NOT_RECORDED"
            if status != "PASS":
                failed_prerequisites.append({"test_id": test_id, "status": status})
        if failed_prerequisites:
            self.reporter.result(
                spec.id,
                spec.category,
                "BLOCKED_BY_PREREQUISITE",
                "The test was not run because a required baseline did not pass",
                family=spec.family,
                details={
                    "required_pass_test_ids": list(spec.requires_pass),
                    "failed_prerequisites": failed_prerequisites,
                    "cloud_operation_performed": False,
                },
                expected=spec.expectation,
                observed="prerequisite-not-passed",
                authoritative=False,
                display_name=spec.display_name,
                scenario=spec.scenario,
            )
            return
        function = self.operations.get(spec.operation)
        if not function:
            raise SuiteError(f"Unsupported TestSpec operation: {spec.operation}")
        function(spec)
