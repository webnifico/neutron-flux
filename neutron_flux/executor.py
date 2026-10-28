from __future__ import annotations

import threading
from _thread import RLock as RLockType
from collections import defaultdict
from typing import Any

from .cancellation import raise_if_cancelled
from .check_plan import cross_batch_key
from .check_resume import prepare_check_resume
from .cleanup import CleanupManager
from .concurrent_load import ConcurrentLoadRunner
from .config import Config
from .engine import TestEngine
from .errors import (
    ControllerUnavailableError,
    RunCancelledError,
    SetupFailureError,
    SuiteError,
)
from .execution.placement import PlacementValidationMixin
from .failure_injection import inject_failure
from .logical_results import grades_execution
from .models import Plan, RunCheckpoint, RuntimeGroup, TestSpec
from .network_contract import (
    PRIVATE_TRANSLATION_PROJECT_NETWORK,
    PROJECT_NETWORK,
    PROVIDER_NETWORK,
    ROUTING_UNASSIGNED_PROJECT_NETWORK,
    canonical_group_kind,
)
from .performance import PerformanceRunner, PerformanceSession
from .reporting import Reporter
from .resources import ResourceBuilder
from .scheduling import LIFECYCLE_WORKERS, bounded_map
from .state import StateStore
from .utils import iso_utc


class AdaptiveExecutor(PlacementValidationMixin):
    """Execute one adaptive suite with a three-VM peak.

    The controller remains active. Group-local tests create A and B endpoints,
    then release them. Cross-topology tests use one A endpoint from at most two
    groups. This gives a normal peak of controller + source + destination.
    """

    def __init__(
        self,
        config: Config,
        plan: Plan,
        builder: ResourceBuilder,
        reporter: Reporter,
        cleanup_manager: CleanupManager,
        state_store: StateStore,
        checkpoint: RunCheckpoint,
        performance_lock: RLockType | None = None,
    ):
        self.config = config
        self.plan = plan
        self.builder = builder
        self.reporter = reporter
        self.logger = reporter.logger
        self.cleanup_manager = cleanup_manager
        self.state_store = state_store
        self.checkpoint = checkpoint
        self.groups = {item.id: item for item in plan.groups}
        self.active: dict[str, RuntimeGroup] = {}
        self.failed_groups: set[str] = set()
        self.group_loads = 0
        self.peak_endpoints = 0
        self._placement_check_bindings: dict[str, str] = {}
        self._placement_workflow_id = ""
        self.performance_session = PerformanceSession()
        self.performance_lock = performance_lock or threading.RLock()

    def run(self) -> None:
        raise_if_cancelled()
        prepare_check_resume(self)
        self.logger.section("Executing adaptive three-VM workflow")
        self.logger.log(
            "During the normal adaptive phase, the controller remains active and "
            "at most two endpoint VMs are active at a time"
        )
        if self.config.fabric_scale_enabled and not self.config.selective_run:
            pair_count = max(self.config.fabric_scale_pairs)
            self.logger.log(
                "The optional concurrent VM-pair load phase runs afterward and can "
                "activate "
                f"up to {pair_count} VM pairs ({pair_count * 2} endpoint VMs) "
                "simultaneously",
                "WARNING",
            )
        self._run_phase("intra")
        self._run_cross_phase()
        self._release_all()
        if self.config.fabric_scale_enabled and not self.config.selective_run:
            with self.performance_lock:
                ConcurrentLoadRunner(self).run()
        self._fill_unavailable_results()
        self._validate_plan_consistency()
        executed_network_results = [
            item
            for item in self.reporter.results
            if item.scenario != "Controller readiness"
            and item.status not in {"SKIP", "NOT_APPLICABLE", "BLOCKED_BY_SETUP_ERROR"}
        ]
        if not executed_network_results:
            reasons = list(dict.fromkeys(self.builder.group_failures.values()))
            suffix = f" First recorded cause: {reasons[0]}" if reasons else ""
            raise SetupFailureError(
                "No network connectivity validation executed; every non-controller "
                f"test was skipped during endpoint or topology setup.{suffix}"
            )
        self.logger.section("Adaptive workflow summary")
        self.logger.log(f"Peak active endpoint VMs: {self.peak_endpoints}")
        self.logger.log(f"Endpoint group generations created: {self.group_loads}")
        self.logger.log(
            f"Recorded evidence rows: {sum(1 for item in self.plan.tests if self.reporter.has_result(item.id))}"
        )

    def _run_phase(self, phase: str) -> None:
        grouped: dict[str, list[TestSpec]] = defaultdict(list)
        for spec in self.plan.tests:
            if spec.phase != phase or self.reporter.has_result(spec.id):
                continue
            if len(spec.dependencies) != 1:
                continue
            grouped[spec.dependencies[0]].append(spec)
        ordered = list(grouped.items())
        first_cross = next(
            (
                spec
                for spec in self.plan.tests
                if spec.phase == "cross" and not self.reporter.has_result(spec.id)
            ),
            None,
        )
        warm_id = next(
            (
                group_id
                for group_id in (first_cross.dependencies if first_cross else [])
                if group_id in grouped and self._simple_reusable_group(group_id)
            ),
            None,
        )
        # Reorder complete independent groups only, never the tests within them.
        owners = {spec.id: group_id for group_id, specs in ordered for spec in specs}
        cross_dependencies = any(
            owners.get(required, group_id) != group_id
            for group_id, specs in ordered
            for spec in specs
            for required in spec.requires_pass
        )
        capped_performance = (
            self.config.performance_enabled and self.config.performance_max_paths > 0
        )
        if warm_id and not cross_dependencies and not capped_performance:
            ordered = [item for item in ordered if item[0] != warm_id] + [
                (warm_id, grouped[warm_id])
            ]
        total = len(ordered)
        for index, (group_id, specs) in enumerate(ordered, start=1):
            raise_if_cancelled()
            group = self.groups[group_id]
            self._checkpoint(
                state="RUNNING",
                phase="group-local",
                current_batch=f"{index}/{total}: {group.label}",
                active_group_ids=[],
            )
            self.logger.section(f"Group-local batch {index}/{total}: {group.label}")
            runtime = self._build(group_id, sides=("A", "B"))
            if not runtime:
                self.failed_groups.add(group_id)
                self.builder.stop_group_probes(group_id)
                reason = self.builder.group_failure_reason(group_id) or (
                    f"Could not create endpoint pair for {group.label}; no detailed cause was recorded"
                )
                self._mark_specs_unavailable(specs, reason, setup_error=True)
                self._cleanup_failed_build(group_id)
                continue
            self.active = {group_id: runtime}
            self.builder.runtime_groups = [runtime]
            self._refresh_checkpoint()
            self.peak_endpoints = max(self.peak_endpoints, len(runtime.endpoints))
            engine = TestEngine(
                self.config,
                self.builder.discovery,
                self.builder,
                self.reporter,
            )
            engine.run_specs(specs)
            self._run_performance(specs, engine, stage="group-local")
            self._run_placement_validation_serialized(
                specs,
                engine,
                dependencies=(group_id,),
            )
            retain = (
                index == total
                and group_id == warm_id
                and self._group_clean_for_reuse(specs)
            )
            if retain:
                self.reporter.event(
                    "endpoint-group-retained",
                    "Retained verified endpoints for the next cross-topology batch",
                    group_id=group_id,
                )
            else:
                self._release(group_id)
            self._refresh_checkpoint()

    def _simple_reusable_group(self, group_id: str) -> bool:
        return canonical_group_kind(self.groups[group_id].kind) in {
            PROVIDER_NETWORK,
            PROJECT_NETWORK,
            PRIVATE_TRANSLATION_PROJECT_NETWORK,
            ROUTING_UNASSIGNED_PROJECT_NETWORK,
        }

    def _group_clean_for_reuse(self, specs: list[TestSpec]) -> bool:
        # A failed/unfinished lifecycle or placement check may have left changed
        # guest/router state. Such a generation is always released.
        coordinator = getattr(self.builder, "cloud_operation_coordinator", None)
        server_ids = {
            endpoint.server_id
            for runtime in self.active.values()
            for endpoint in runtime.endpoints
        }
        if any(
            record.get("kind") == "migration"
            and server_ids.intersection(record.get("resource_ids") or [])
            for record in getattr(coordinator, "_latest", {}).values()
        ):
            return False
        for spec in specs:
            if spec.operation == "probe":
                continue
            result = self.reporter.get_result(spec.id)
            if result is None or result.status != "PASS":
                return False
        return not any(runtime.fips for runtime in self.active.values())

    def _run_cross_phase(self) -> None:
        batches: dict[Any, list[TestSpec]] = defaultdict(list)
        for spec in self.plan.tests:
            if spec.phase != "cross" or self.reporter.has_result(spec.id):
                continue
            dependency_key = tuple(dict.fromkeys(spec.dependencies))
            if not dependency_key:
                continue
            if len(dependency_key) > 2:
                raise SuiteError(
                    f"Test {spec.id} requires {len(dependency_key)} endpoint groups; three-VM invariant would be violated"
                )
            batches[cross_batch_key(spec)].append(spec)
        # Stateful batches are barriers. Only independent connectivity and MTU
        # batches between those barriers may move to retain a warm endpoint.
        ordered = self._reuse_ordered_cross_batches(batches)
        self.logger.log(f"Cross-topology batches required: {len(ordered)}")
        for index, key in enumerate(ordered, start=1):
            dependencies, side_signature, _floating = key
            raise_if_cancelled()
            labels = " + ".join(self.groups[item].label for item in dependencies)
            self._checkpoint(
                state="RUNNING",
                phase="cross-topology",
                current_batch=f"{index}/{len(ordered)}: {labels}",
                active_group_ids=list(self.active),
            )
            self.logger.section(
                f"Cross-topology batch {index}/{len(ordered)}: {labels}"
            )
            required_sides = dict(side_signature)
            self._ensure(dependencies, required_sides=required_sides)
            unavailable = [item for item in dependencies if item not in self.active]
            specs = batches[key]
            if unavailable:
                reasons = []
                for group_id in unavailable:
                    reasons.append(
                        self.builder.group_failure_reason(group_id)
                        or f"Could not create endpoint group {self.groups[group_id].label}"
                    )
                self._mark_specs_unavailable(
                    specs,
                    "Required endpoint group unavailable: " + " | ".join(reasons),
                    setup_error=False,
                    blocked=True,
                )
                continue
            self.builder.runtime_groups = list(self.active.values())
            self.peak_endpoints = max(
                self.peak_endpoints,
                sum(len(item.endpoints) for item in self.active.values()),
            )
            engine = TestEngine(
                self.config,
                self.builder.discovery,
                self.builder,
                self.reporter,
            )
            engine.run_specs(specs)
            self._run_performance(specs, engine, stage="cross-topology")
            self._run_placement_validation_serialized(
                specs,
                engine,
                dependencies=dependencies,
            )
            self._refresh_checkpoint()

    def _reuse_ordered_cross_batches(
        self, batches: dict[Any, list[TestSpec]]
    ) -> list[Any]:
        config = getattr(self, "config", None)
        if (
            getattr(config, "performance_enabled", False)
            and getattr(config, "performance_max_paths", 0) > 0
        ):
            # The existing path cap selects the first eligible paths per stage.
            # Retain that order rather than silently changing measured coverage.
            return list(batches)
        ordered: list[Any] = []
        pending: list[Any] = []
        current = self._active_reuse_keys()

        def flush() -> None:
            nonlocal current
            while pending:
                owners = {spec.id: key for key in pending for spec in batches[key]}
                ready = [
                    key
                    for key in pending
                    if all(
                        owners.get(required, key) == key
                        for spec in batches[key]
                        for required in [*spec.requires, *spec.requires_pass]
                    )
                ]
                # A cyclic/invalid dependency keeps its original order so the
                # engine reports it as blocked; it must never be assumed passed.
                candidates = ready or pending[:1]
                selected = max(
                    candidates,
                    key=lambda key: len(
                        current.intersection(self._batch_reuse_keys(key))
                    ),
                )
                ordered.append(selected)
                pending.remove(selected)
                current = self._batch_reuse_keys(selected)

        for key, specs in batches.items():
            # Packet-size checks reset only the guest's route PMTU cache and
            # then measure it. They do not mutate cloud topology, so they can
            # move with their independent connectivity batch. Never reorder
            # tests within a batch or across a lifecycle/mutation barrier.
            if all(
                TestEngine.parallel_probe(spec) or spec.operation == "mtu-scenario"
                for spec in specs
            ):
                pending.append(key)
            else:
                flush()
                ordered.append(key)
                current = self._batch_reuse_keys(key)
        flush()
        return ordered

    def _active_reuse_keys(self) -> set[tuple[str, ...]]:
        return {
            (group_id, endpoint.side.upper())
            for group_id, runtime in self.active.items()
            for endpoint in runtime.endpoints
        }

    def _batch_reuse_keys(self, key: Any) -> set[tuple[str, ...]]:
        return {
            (group_id, side.upper()) for group_id, sides in key[1] for side in sides
        }

    def _run_performance(
        self, specs: list[TestSpec], engine: TestEngine, *, stage: str
    ) -> None:
        if not self.config.performance_enabled:
            return
        if getattr(
            getattr(self, "config", None),
            "derived_tests_suppressed",
            getattr(getattr(self, "config", None), "selective_run", False),
        ):
            return
        runner = PerformanceRunner(
            self.config,
            self.builder,
            self.reporter,
            engine,
            session=self.performance_session,
        )
        performance_specs = runner.plan_specs(specs, stage=stage)
        if not performance_specs:
            return
        self._append_runtime_specs(performance_specs)
        with self.performance_lock:
            runner.run_specs(performance_specs)
        self._refresh_checkpoint()

    def _run_placement_validation_serialized(
        self,
        specs: list[TestSpec],
        engine: TestEngine,
        *,
        dependencies: tuple[str, ...],
    ) -> None:
        """Prevent migration traffic from contaminating Flux measurements.

        The lock is re-entrant because successful live migration can trigger a
        post-migration performance pass from inside placement validation.
        Multi-AZ lanes receive the same lock instance.
        """
        if getattr(
            getattr(self, "config", None),
            "derived_tests_suppressed",
            getattr(getattr(self, "config", None), "selective_run", False),
        ):
            return
        if getattr(getattr(self, "config", None), "target_host_pairs", None):
            if not getattr(self, "_exact_pair_migration_notice_logged", False):
                self.logger.log(
                    "Scheduler-selected placement migrations are omitted because "
                    "the exact --target-host-pairs scope owns pair-local "
                    "migration coverage"
                )
                self._exact_pair_migration_notice_logged = True
            return
        with self.performance_lock:
            builder = getattr(self, "builder", None)
            if builder is None:
                self._run_compute_placement_validation(
                    specs,
                    engine,
                    dependencies=dependencies,
                )
                return
            coordinator = getattr(builder, "cloud_operation_coordinator", None)
            endpoints = self._placement_endpoints(dependencies, specs)
            if coordinator is None or endpoints is None:
                self._run_compute_placement_validation(
                    specs,
                    engine,
                    dependencies=dependencies,
                )
                return
            source, destination = endpoints
            # B is the only migrating endpoint. The transaction starts before
            # baseline capture and remains held through every post-migration
            # ICMP/TCP/UDP/MTU and performance readback.
            with coordinator.transaction(
                "migration",
                (
                    "compute placement migration and final functional "
                    f"validation for {destination.label}"
                ),
                resource_ids=[destination.server_id],
                source_host=destination.host,
                availability_zone=destination.availability_zone,
                max_attempts=self.config.migration_submission_budget,
                conflicts=("all-cloud-operations",),
                final_cooldown=5.0,
            ):
                self._run_compute_placement_validation(
                    specs,
                    engine,
                    dependencies=dependencies,
                )

    def _append_runtime_specs(self, specs: list[TestSpec]) -> None:
        existing = {item.id for item in self.plan.tests}
        changed = False
        for spec in specs:
            if spec.id in existing:
                continue
            self.plan.tests.append(spec)
            existing.add(spec.id)
            changed = True
        if changed:
            self.reporter.save_plan()
            self._refresh_checkpoint()

    def _ensure(
        self,
        required: tuple[str, ...],
        *,
        required_sides: dict[str, tuple[str, ...]] | None = None,
    ) -> None:
        required_sides = required_sides or {group_id: ("A",) for group_id in required}
        required_sides = {
            group_id: tuple(
                side.upper() for side in required_sides.get(group_id, ("A",))
            )
            for group_id in required
        }
        if any(
            not sides or len(set(sides)) != len(sides) or set(sides) - {"A", "B"}
            for sides in required_sides.values()
        ):
            raise SuiteError("Endpoint batches require unique A/B roles")
        requested_count = sum(
            len(set(required_sides.get(group_id, ("A",))))
            for group_id in dict.fromkeys(required)
        )
        if requested_count > self.config.max_active_endpoints:
            raise SuiteError(
                f"Requested endpoint batch exceeds maximum active endpoints: {requested_count} > {self.config.max_active_endpoints}"
            )
        required_set = set(required)
        for group_id in list(self.active):
            if group_id not in required_set:
                self._release(group_id)
        for group_id in list(self.active):
            actual = {
                endpoint.side.upper() for endpoint in self.active[group_id].endpoints
            }
            expected = {item.upper() for item in required_sides.get(group_id, ("A",))}
            if actual != expected:
                runtime = self.active[group_id]
                if (
                    expected < actual
                    and self._simple_reusable_group(group_id)
                    and not runtime.fips
                ):
                    for side in sorted(actual - expected):
                        self.builder.stop_endpoint_probe(runtime.endpoint(side))
                        if not self.cleanup_manager.cleanup_group_side(group_id, side):
                            self._record_unresolved_group(group_id)
                            raise SuiteError(
                                f"Could not release surplus endpoint {group_id}:{side}"
                            )
                        runtime.endpoints = [
                            endpoint
                            for endpoint in runtime.endpoints
                            if endpoint.side.upper() != side
                        ]
                    self.reporter.event(
                        "endpoint-reused",
                        "Retained compatible endpoint and topology after releasing surplus sides",
                        group_id=group_id,
                        sides=sorted(expected),
                    )
                elif (
                    actual < expected
                    and group_id in getattr(self, "provider_handoff_group_ids", set())
                    and canonical_group_kind(self.groups[group_id].kind)
                    == PROVIDER_NETWORK
                    and not runtime.fips
                ):
                    missing = sorted(expected - actual)
                    active_count = sum(
                        len(item.endpoints) for item in self.active.values()
                    )
                    if active_count + len(missing) > self.config.max_active_endpoints:
                        raise SuiteError(
                            "Retained provider endpoint would exceed the endpoint limit"
                        )
                    for side in missing:
                        self.builder.build_group_side(
                            runtime, self.groups[group_id], side
                        )
                    self.reporter.event(
                        "endpoint-reused",
                        "Retained verified provider endpoint while preparing its next peer",
                        group_id=group_id,
                        sides=sorted(expected),
                    )
                else:
                    self._release(group_id)
        pending = [
            group_id
            for group_id in required
            if group_id not in self.active and group_id not in self.failed_groups
        ]
        prepared = (
            len(pending) > 1
            and getattr(self.builder, "cloud_operation_coordinator", None) is not None
            and callable(getattr(self.builder, "complete_group_endpoints", None))
            and callable(getattr(self.builder, "finalize_group_endpoints", None))
        )
        if prepared:
            self._build_endpoint_batch(pending, required_sides)
        for group_id in () if prepared else pending:
            if group_id in self.active or group_id in self.failed_groups:
                continue
            runtime = self._build(
                group_id,
                sides=tuple(required_sides.get(group_id, ("A",))),
            )
            if not runtime:
                self.failed_groups.add(group_id)
                self.builder.stop_group_probes(group_id)
                self._cleanup_failed_build(group_id)
                continue
            self.active[group_id] = runtime
            self.builder.runtime_groups = list(self.active.values())
            self._refresh_checkpoint()
        self.builder.runtime_groups = list(self.active.values())
        endpoint_count = sum(len(item.endpoints) for item in self.active.values())
        if endpoint_count > self.config.max_active_endpoints:
            raise SuiteError(
                f"Adaptive scheduler exceeded maximum active endpoints: {endpoint_count} > {self.config.max_active_endpoints}"
            )

    def _build_endpoint_batch(
        self, pending: list[str], sides: dict[str, tuple[str, ...]]
    ) -> None:
        """Prepare graphs serially, then populate the bounded endpoint batch.

        Network changes must finish before endpoint workers hold shared lifecycle
        windows. Runtime ownership is committed before workers start, so even a
        cancellation leaves every partially created resource reachable by cleanup.
        """
        for group_id in pending:
            raise_if_cancelled()
            self.group_loads += 1
            self._inject_failure(f"before-group:{group_id}")
            runtime = self.builder.build_group(
                self.groups[group_id],
                sides=tuple(sides.get(group_id, ("A",))),
                defer_endpoints=True,
            )
            if runtime is None:
                self.failed_groups.add(group_id)
                self.builder.stop_group_probes(group_id)
                self._cleanup_failed_build(group_id)
                continue
            self.active[group_id] = runtime
            self.builder.runtime_groups = list(self.active.values())
            self._refresh_checkpoint()
        ready = [group_id for group_id in pending if group_id in self.active]

        def populate(group_id: str) -> tuple[RuntimeGroup | None, Exception | None]:
            try:
                runtime = self.builder.complete_group_endpoints(
                    self.active[group_id], sides=tuple(sides.get(group_id, ("A",)))
                )
                self._inject_failure(f"after-group:{group_id}")
                return runtime, None
            except (SuiteError, OSError) as exc:
                # Harvest all workers before performing cleanup or propagation.
                return None, exc

        try:
            outcomes = bounded_map(populate, ready, workers=LIFECYCLE_WORKERS)
        finally:
            # bounded_map joins its pool before raising, including cancellation.
            self.builder.runtime_groups = list(self.active.values())
            self._refresh_checkpoint()
        cancellation = next(
            (
                error
                for _runtime, error in outcomes
                if isinstance(error, RunCancelledError)
            ),
            None,
        )
        if cancellation is not None:
            # A terminated child can raise without setting process-wide state.
            # Preserve all ownership for outer cancellation cleanup before any
            # peer is finalized or a failed build is removed.
            raise cancellation
        controller_error = next(
            (
                error
                for _runtime, error in outcomes
                if isinstance(error, ControllerUnavailableError)
            ),
            None,
        )
        if controller_error is not None:
            # Every peer needs the same controller. Preserve this shared cause
            # before an ordinary failure or its cleanup can obscure it.
            raise controller_error
        first_error: Exception | None = None
        for group_id, (runtime, error) in zip(ready, outcomes, strict=True):
            if runtime is not None and error is None:
                try:
                    self.builder.finalize_group_endpoints(runtime)
                    verify = getattr(self, "_verify_runtime", None)
                    if callable(verify):
                        verify(runtime)
                except RunCancelledError:
                    raise
                except ControllerUnavailableError as exc:
                    error = exc
                    runtime = None
                except SuiteError as exc:
                    self.builder.group_failures[group_id] = str(exc)
                    runtime = None
            if runtime is None or error is not None:
                self.failed_groups.add(group_id)
                if error is not None and first_error is None:
                    first_error = error
                self.builder.stop_group_probes(group_id)
                if not isinstance(error, RunCancelledError):
                    self._cleanup_failed_build(group_id)
                    self.active.pop(group_id, None)
                continue
            self.active[group_id] = runtime
        self.builder.runtime_groups = list(self.active.values())
        self._refresh_checkpoint()
        if first_error is not None:
            raise first_error

    def _build(self, group_id: str, *, sides: tuple[str, ...]) -> RuntimeGroup | None:
        raise_if_cancelled()
        self.group_loads += 1
        self.builder.runtime_groups = list(self.active.values())
        self._inject_failure(f"before-group:{group_id}")
        runtime = self.builder.build_group(
            self.groups[group_id],
            sides=sides,
        )
        self._inject_failure(f"after-group:{group_id}")
        return runtime

    def _release(self, group_id: str) -> None:
        runtime = self.active.get(group_id)
        self.builder.stop_group_probes(group_id)
        complete = self.cleanup_manager.cleanup_group(group_id)
        if not complete:
            self.logger.log(
                f"Endpoint group {group_id} could not be fully released; "
                "stopping adaptive execution so unresolved resources remain "
                "checkpointed for final cleanup",
                "ERROR",
            )
            self._record_unresolved_group(group_id)
            raise SuiteError(
                f"Endpoint group {group_id} could not be fully released; "
                "later endpoint batches were not started"
            )
        self.active.pop(group_id, None)
        if runtime in self.builder.runtime_groups:
            self.builder.runtime_groups.remove(runtime)
        self.builder.runtime_groups = list(self.active.values())
        self._refresh_checkpoint()

    def _release_all(self) -> None:
        failures: list[str] = []
        for group_id in list(self.active):
            try:
                self._release(group_id)
            except RunCancelledError:
                raise
            except SuiteError as exc:
                failures.append(str(exc))
        self._refresh_checkpoint()
        if failures:
            raise SuiteError(
                "One or more endpoint groups could not be fully released: "
                + " | ".join(failures)
            )

    def _cleanup_failed_build(self, group_id: str) -> None:
        if self.cleanup_manager.cleanup_group(group_id):
            return
        self._record_unresolved_group(group_id)
        raise SuiteError(
            f"Partial endpoint group {group_id} could not be fully cleaned; "
            "later endpoint batches were not started"
        )

    def _record_unresolved_group(self, group_id: str) -> None:
        unresolved = self.checkpoint.metadata.setdefault("unresolved_group_ids", [])
        if group_id not in unresolved:
            unresolved.append(group_id)
        self.builder.runtime_groups = list(self.active.values())
        self._refresh_checkpoint()

    def _mark_specs_unavailable(
        self,
        specs: list[TestSpec],
        reason: str,
        *,
        setup_error: bool = False,
        blocked: bool = False,
    ) -> None:
        pending = [spec for spec in specs if not self.reporter.has_result(spec.id)]
        if not pending:
            return
        for index, spec in enumerate(pending):
            if setup_error and index == 0:
                status = "ERROR"
                observed = "setup-error"
                message = (
                    "Two-router topology construction failed: " + reason
                    if any(
                        self.builder.group_failure_type(group_id)
                        == "two-router-topology-construction"
                        for group_id in spec.dependencies
                    )
                    else "Endpoint or topology setup failed: " + reason
                )
            elif setup_error or blocked:
                status = "BLOCKED_BY_SETUP_ERROR"
                observed = "not-run"
                message = reason
            else:
                status = "SKIP"
                observed = "not-run"
                message = reason
            self.reporter.result(
                spec.id,
                spec.category,
                status,
                message,
                family=spec.family,
                expected=spec.expectation,
                observed=observed,
                authoritative=(
                    spec.authoritative
                    if status not in {"ERROR", "BLOCKED_BY_SETUP_ERROR"}
                    else False
                ),
                details={
                    "dependencies": spec.dependencies,
                    "expectation_reason": spec.expectation_reason,
                    "blocked_by_setup_error": status == "BLOCKED_BY_SETUP_ERROR",
                    "root_setup_error": setup_error and index == 0,
                },
                display_name=spec.display_name,
                scenario=spec.scenario,
            )

    def _fill_unavailable_results(self) -> None:
        for spec in self.plan.tests:
            if self.reporter.has_result(spec.id):
                continue
            dependency_reasons = [
                reason
                for group_id in spec.dependencies
                if (reason := self.builder.group_failure_reason(group_id)) is not None
            ]
            reason = (
                "Required resource unavailable: " + " | ".join(dependency_reasons)
                if dependency_reasons
                else "required resource or capability was unavailable"
            )
            status = "BLOCKED_BY_SETUP_ERROR" if dependency_reasons else "SKIP"
            self.reporter.result(
                spec.id,
                spec.category,
                status,
                reason,
                family=spec.family,
                expected=spec.expectation,
                observed="not-run",
                authoritative=False if dependency_reasons else spec.authoritative,
                details={
                    "dependencies": spec.dependencies,
                    "blocked_by_setup_error": bool(dependency_reasons),
                },
                display_name=spec.display_name,
                scenario=spec.scenario,
            )

    def _validate_plan_consistency(self) -> None:
        planned = {item.id for item in self.plan.tests}
        recorded = {item.test_id for item in self.reporter.results}
        missing = sorted(planned - recorded)
        extra = sorted(recorded - planned)
        if missing:
            raise SuiteError(
                f"Plan/result consistency failure: {len(missing)} planned tests lack results"
            )
        if extra:
            raise SuiteError(
                f"Plan/result consistency failure: {len(extra)} unplanned results were recorded"
            )
        if len(recorded) != len(self.reporter.results):
            raise SuiteError("Result IDs are not unique")

    def _refresh_checkpoint(self) -> None:
        completed = [
            item.id for item in self.plan.tests if self.reporter.has_result(item.id)
        ]
        failed = [
            item.test_id
            for item in self.reporter.results
            if grades_execution(item) and item.status in {"FAIL", "ERROR"}
        ]
        completed_ids = set(completed)
        pending = [item.id for item in self.plan.tests if item.id not in completed_ids]
        self.checkpoint.completed_test_ids = completed
        self.checkpoint.failed_test_ids = failed
        self.checkpoint.pending_test_ids = pending
        self.checkpoint.active_group_ids = list(self.active)
        self.checkpoint.metadata["group_failures"] = dict(self.builder.group_failures)
        self.checkpoint.metadata["active_probe_processes"] = (
            self.builder.probe_service.active_count
        )
        self.checkpoint.updated_at = iso_utc()
        self.checkpoint.last_activity = self.checkpoint.updated_at
        self.state_store.save(self.checkpoint)

    def _checkpoint(
        self,
        *,
        state: str,
        phase: str,
        current_batch: str | None,
        active_group_ids: list[str],
    ) -> None:
        self.checkpoint.state = state
        self.checkpoint.phase = phase
        self.checkpoint.current_batch = current_batch
        self.checkpoint.active_group_ids = active_group_ids
        self._refresh_checkpoint()

    def _inject_failure(self, point: str) -> None:
        inject_failure(self.config, point)
