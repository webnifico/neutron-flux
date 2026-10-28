from __future__ import annotations

import dataclasses
import shutil
import threading
from _thread import RLock as RLockType
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, cast

from .cancellation import hard_abort_reason, hard_abort_requested
from .check_plan import copy_bindings
from .cleanup import CleanupManager
from .cloud_operation import CloudOperationCoordinator
from .config import Config
from .engine import TestEngine
from .errors import RunCancelledError, SetupFailureError, SuiteError
from .executor import AdaptiveExecutor
from .log import Logger
from .logical_results import grades_execution
from .models import (
    Plan,
    PlannedGroup,
    RunCheckpoint,
    RuntimeGroup,
    TestSpec,
    ZoneExecutionPlan,
)
from .openstack import OpenStack
from .performance import PerformanceRunner, PerformanceSession
from .planner_components.estimates import performance_estimate
from .reporting import Reporter, ResourceTracker, ScopedReporter
from .resources import LaunchSelection, ResourceBuilder, SecurityGroupBundle
from .state import StateStore
from .utils import iso_utc, unique_safe_name


def zone_scope(zone: str) -> str:
    return unique_safe_name(f"az-{zone}", 32)


def zone_group_id(group_id: str, zone: str) -> str:
    return f"{group_id}@{unique_safe_name(zone, 24)}"


def clone_group_for_zone(group: PlannedGroup, zone: str) -> PlannedGroup:
    return dataclasses.replace(
        group,
        id=zone_group_id(group.id, zone),
        label=f"{group.label} [{zone}]",
        metadata={
            **group.metadata,
            "base_group_id": group.id,
            "availability_zone": zone,
        },
    )


def clone_plan_for_zone(plan: Plan, zone: str) -> Plan:
    mapping = {group.id: zone_group_id(group.id, zone) for group in plan.groups}
    groups = [clone_group_for_zone(group, zone) for group in plan.groups]
    tests: list[TestSpec] = []
    for spec in plan.tests:
        tests.append(
            dataclasses.replace(
                spec,
                dependencies=[mapping.get(item, item) for item in spec.dependencies],
                source_group_id=(
                    mapping.get(spec.source_group_id, spec.source_group_id)
                    if spec.source_group_id
                    else None
                ),
                destination_group_id=(
                    mapping.get(spec.destination_group_id, spec.destination_group_id)
                    if spec.destination_group_id
                    else None
                ),
                metadata={
                    **spec.metadata,
                    "availability_zone": zone,
                    "base_test_id": spec.id,
                },
                requires=list(spec.requires),
                requires_pass=list(spec.requires_pass),
            )
        )
    provider_count = len(plan.provider_groups)
    return Plan(
        provider_groups=groups[:provider_count],
        tenant_groups=groups[provider_count:],
        estimated=dict(plan.estimated),
        skipped=list(plan.skipped),
        tests=tests,
        warnings=list(plan.warnings),
        host_qualification=plan.host_qualification,
    )


def _cross_zone_base_batches(plan: Plan) -> dict[tuple[str, ...], list[TestSpec]]:
    batches: dict[tuple[str, ...], list[TestSpec]] = defaultdict(list)
    groups = {group.id: group for group in plan.groups}
    # Same selected provider network across AZs. Ordered AZ pairs provide both
    # directions, so retain only the A->B base protocol entries.
    for spec in plan.tests:
        if (
            spec.operation == "probe"
            and spec.phase == "intra"
            and len(spec.dependencies) == 1
            and spec.category == "same-subnet"
            and spec.source_side == "A"
            and spec.destination_side == "B"
            and spec.protocol in {"icmp", "tcp", "udp"}
            and groups.get(spec.dependencies[0])
            and groups[spec.dependencies[0]].kind == "provider"
        ):
            batches[(spec.dependencies[0],)].append(spec)
    # Existing planner-approved connectivity between different network
    # topologies, now executed with source and destination in different AZs.
    for spec in plan.tests:
        if (
            spec.operation == "probe"
            and spec.phase == "cross"
            and len(tuple(dict.fromkeys(spec.dependencies))) == 2
        ):
            batches[tuple(dict.fromkeys(spec.dependencies))].append(spec)
    return batches


def _cross_zone_test_id(source_zone: str, destination_zone: str, base_id: str) -> str:
    return (
        f"CROSS-ZONE-{unique_safe_name(source_zone, 18).upper()}-TO-"
        f"{unique_safe_name(destination_zone, 18).upper()}-{base_id}"
    )


def cross_zone_specs(plan: Plan, zones: list[str]) -> list[TestSpec]:
    output: list[TestSpec] = []
    for dependencies, specs in _cross_zone_base_batches(plan).items():
        for source_zone in zones:
            for destination_zone in zones:
                if source_zone == destination_zone:
                    continue
                for base in specs:
                    source_base = base.source_group_id or dependencies[0]
                    destination_base = base.destination_group_id or dependencies[-1]
                    source_group = zone_group_id(source_base, source_zone)
                    destination_group = zone_group_id(
                        destination_base, destination_zone
                    )
                    output.append(
                        dataclasses.replace(
                            base,
                            id=_cross_zone_test_id(
                                source_zone, destination_zone, base.id
                            ),
                            category="cross-zone-connectivity",
                            dependencies=[source_group, destination_group],
                            source_group_id=source_group,
                            destination_group_id=destination_group,
                            source_side="A",
                            destination_side="A",
                            phase="cross-zone",
                            metadata={
                                **base.metadata,
                                "source_availability_zone": source_zone,
                                "destination_availability_zone": destination_zone,
                                "base_test_id": base.id,
                                "base_category": base.category,
                            },
                            display_name=(
                                f"{base.display_name or base.id} — "
                                f"{source_zone} to {destination_zone}"
                            ),
                            scenario="Connectivity between availability zones",
                            requires=[],
                            requires_pass=[],
                        )
                    )
    unique: dict[str, TestSpec] = {}
    for item in output:
        if item.id in unique:
            raise SuiteError(
                f"Cross-zone test ID collision for {item.id}; "
                "availability-zone identities are ambiguous"
            )
        unique[item.id] = item
    return list(unique.values())


def aggregate_plan(
    plan: Plan, zone_plan: ZoneExecutionPlan, config: Config | None = None
) -> Plan:
    all_groups: list[PlannedGroup] = []
    tests: list[TestSpec] = []
    provider_groups: list[PlannedGroup] = []
    tenant_groups: list[PlannedGroup] = []
    for zone in zone_plan.zones:
        lane = clone_plan_for_zone(plan, zone)
        all_groups.extend(lane.groups)
        provider_groups.extend(lane.provider_groups)
        tenant_groups.extend(lane.tenant_groups)
        if zone_plan.includes_per_zone:
            prefix = zone_scope(zone).upper()
            for spec in lane.tests:
                tests.append(
                    dataclasses.replace(
                        spec,
                        id=f"{prefix}-{spec.id}",
                        requires=[f"{prefix}-{item}" for item in spec.requires],
                        requires_pass=[
                            f"{prefix}-{item}" for item in spec.requires_pass
                        ],
                    )
                )
        else:
            # Cross-zone-only mode still prepares and validates one controller
            # in every AZ; include only bootstrap tests from the lane plan.
            prefix = zone_scope(zone).upper()
            for spec in lane.tests:
                if spec.scenario == "Controller readiness":
                    tests.append(
                        dataclasses.replace(
                            spec,
                            id=f"{prefix}-{spec.id}",
                            requires=[f"{prefix}-{item}" for item in spec.requires],
                            requires_pass=[
                                f"{prefix}-{item}" for item in spec.requires_pass
                            ],
                        )
                    )
    if zone_plan.includes_cross_zone:
        tests.extend(cross_zone_specs(plan, zone_plan.zones))
    estimated = dict(plan.estimated)
    multiplier = len(zone_plan.zones)
    for key in list(estimated):
        if key.startswith("peak_") or key in {
            "endpoint_groups",
            "provider_groups",
            "project_network_groups",
            "group_loads",
            "endpoint_vm_boots",
            "provider_group_generations",
            "project_network_topology_generations",
            "networks_created",
            "subnets_created",
            "routers_created",
            "floating_ips_created",
        }:
            estimated[key] = int(estimated[key]) * multiplier
    estimated["security_groups_created"] = int(
        plan.estimated.get("security_groups_created", 4)
    )
    estimated["security_group_rules_peak"] = int(
        plan.estimated.get("security_group_rules_peak", 24)
    ) + (multiplier if zone_plan.includes_per_zone else 0)
    estimated["selected_availability_zones"] = multiplier
    estimated["cross_zone_tests"] = len(cross_zone_specs(plan, zone_plan.zones))
    performance = (
        performance_estimate(config, tests)
        if config is not None
        and config.performance_enabled
        and not config.derived_tests_suppressed
        else {
            "performance_path_candidates": 0,
            "performance_paths_selected": 0,
            "performance_paths_omitted": 0,
            "floating_ip_performance_paths": 0,
            "performance_result_rows": 0,
            "performance_estimated_seconds": 0,
            "performance_estimated_seconds_minimum": 0,
            "performance_estimated_seconds_maximum": 0,
            "performance_topology_classes": 0,
            "performance_execution_stages": 0,
        }
    )
    estimated.update(performance)
    estimated["functional_test_results"] = len(tests)
    estimated["test_results"] = len(tests)
    estimated["estimated_result_rows"] = len(tests) + int(
        performance["performance_result_rows"]
    )
    return Plan(
        provider_groups=provider_groups,
        tenant_groups=tenant_groups,
        estimated=estimated,
        skipped=list(plan.skipped),
        tests=tests,
        warnings=[
            *plan.warnings,
            *zone_plan.warnings,
            f"Availability-zone mode: {zone_plan.mode}; zones: {', '.join(zone_plan.zones)}",
        ],
        host_qualification=plan.host_qualification,
        selection_mode=plan.selection_mode,
        requested_test_ids=list(plan.requested_test_ids),
        automatically_included_test_ids=list(plan.automatically_included_test_ids),
    )


@dataclasses.dataclass
class ZoneLane:
    zone: str
    scope: str
    config: Config
    plan: Plan
    reporter: ScopedReporter
    osc: OpenStack
    tracker: ResourceTracker
    cleanup_manager: CleanupManager
    state_store: StateStore
    checkpoint: RunCheckpoint
    builder: ResourceBuilder
    prepared: bool = False
    setup_error: str | None = None
    execution_error: str | None = None


class _CrossZonePerformanceControl:
    """Dispatch guest commands through the controller that owns each endpoint."""

    def __init__(self, builders_by_server: dict[str, ResourceBuilder]):
        self.builders_by_server = builders_by_server

    def ssh_endpoint(
        self, endpoint: Any, remote_command: str, *, timeout: int | None = None
    ):
        builder = self.builders_by_server.get(str(endpoint.server_id))
        if builder is None:
            raise SuiteError(
                f"No availability-zone controller owns endpoint {endpoint.label}"
            )
        return builder.ssh_endpoint(endpoint, remote_command, timeout=timeout)


class CrossZoneExecutor:
    def __init__(
        self,
        config: Config,
        base_plan: Plan,
        lanes: dict[str, ZoneLane],
        reporter: Reporter,
        workers: int,
        performance_lock: RLockType | None = None,
        selected_test_ids: set[str] | None = None,
    ):
        self.config = config
        self.base_plan = base_plan
        self.lanes = lanes
        self.reporter = ScopedReporter(reporter, "cross-zone", availability_zone=None)
        self.logger = self.reporter.logger
        self.workers = max(1, workers)
        self.performance_session = PerformanceSession()
        # Performance runs are intentionally serialized across synchronized AZ
        # lanes. This avoids one measurement contaminating another while the
        # functional connectivity work remains parallel.
        self.performance_lock = performance_lock or threading.RLock()
        self.selected_test_ids = (
            set(selected_test_ids) if selected_test_ids is not None else None
        )
        self.reporter.plan = Plan([], [], {}, [], tests=[])

    def run(self) -> None:
        batches = _cross_zone_base_batches(self.base_plan)
        selected_test_ids = getattr(self, "selected_test_ids", None)
        if selected_test_ids is not None:
            selected_batches: dict[tuple[str, ...], list[TestSpec]] = {}
            for dependencies, specs in batches.items():
                selected_specs = [
                    spec
                    for spec in specs
                    if any(
                        _cross_zone_test_id(source_zone, destination_zone, spec.id)
                        in selected_test_ids
                        for source_zone in self.lanes
                        for destination_zone in self.lanes
                        if source_zone != destination_zone
                    )
                ]
                if selected_specs:
                    selected_batches[dependencies] = selected_specs
            batches = selected_batches
        self.logger.section("Executing synchronized cross-zone connectivity suite")
        self.logger.log(
            f"Cross-zone topology batches: {len(batches)}; zones active together: "
            + ", ".join(self.lanes)
        )
        for index, (dependencies, base_specs) in enumerate(batches.items(), start=1):
            labels = " + ".join(
                self.base_plan.group(item).label for item in dependencies
            )
            self.logger.section(f"Cross-zone batch {index}/{len(batches)}: {labels}")
            active: dict[str, dict[str, RuntimeGroup]] = {}
            cleanup_errors: list[str] = []
            try:
                active = self._build_batch(dependencies)
                if not active:
                    self._record_unavailable_batch(dependencies, base_specs)
                else:
                    with ThreadPoolExecutor(
                        max_workers=min(self.workers, len(self.lanes))
                    ) as pool:
                        futures = [
                            pool.submit(
                                self._run_from_source_zone,
                                source_zone,
                                dependencies,
                                base_specs,
                                active,
                            )
                            for source_zone in self.lanes
                        ]
                        for future in as_completed(futures):
                            future.result()
            finally:
                # Cleanup must cover partial builds as well as successful batches.
                # Resource IDs are journaled by each lane as soon as creation
                # succeeds, so group cleanup remains authoritative even when
                # _build_batch raises before returning its active mapping.
                cleanup_errors = self._cleanup_batch(dependencies)
            if cleanup_errors:
                raise SuiteError(
                    "Cross-zone endpoint cleanup was incomplete; later batches "
                    "were not started: " + " | ".join(cleanup_errors)
                )

    def _build_batch(
        self, dependencies: tuple[str, ...]
    ) -> dict[str, dict[str, RuntimeGroup]]:
        active: dict[str, dict[str, RuntimeGroup]] = {zone: {} for zone in self.lanes}
        tasks = []
        with ThreadPoolExecutor(
            max_workers=min(
                self.workers * max(1, len(dependencies)),
                len(self.lanes) * max(1, len(dependencies)),
            )
        ) as pool:
            for zone, lane in self.lanes.items():
                for base_group_id in dependencies:
                    group = lane.plan.group(zone_group_id(base_group_id, zone))
                    future = pool.submit(
                        lane.builder.build_group,
                        group,
                        sides=("A",),
                    )
                    tasks.append((zone, base_group_id, future))
            build_errors: list[str] = []
            for zone, base_group_id, future in tasks:
                try:
                    runtime = future.result()
                except RunCancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001 - convert lane setup into a recorded batch failure
                    build_errors.append(
                        f"{zone}:{base_group_id} ({type(exc).__name__}: {exc})"
                    )
                    continue
                if runtime is not None:
                    active[zone][base_group_id] = runtime
                    lane = self.lanes[zone]
                    lane.builder.runtime_groups = list(active[zone].values())
                    self._refresh_lane_checkpoint(lane, phase="cross-zone-build")
        expected = len(dependencies)
        failures = [
            f"{zone}:{base_group_id}"
            for zone in active
            for base_group_id in dependencies
            if base_group_id not in active[zone]
        ]
        if build_errors:
            self.logger.log(
                "Cross-zone endpoint preparation raised an execution error for "
                + ", ".join(build_errors),
                "ERROR",
            )
            raise SetupFailureError(
                "Cross-zone endpoint preparation failed: " + " | ".join(build_errors)
            )
        if failures:
            self.logger.log(
                "Cross-zone endpoint preparation failed for " + ", ".join(failures),
                "ERROR",
            )
            return {}
        for zone, lane in self.lanes.items():
            lane.builder.runtime_groups = list(active[zone].values())
            if len(active[zone]) != expected:
                return {}
        return active

    def _run_from_source_zone(
        self,
        source_zone: str,
        dependencies: tuple[str, ...],
        base_specs: list[TestSpec],
        active: dict[str, dict[str, RuntimeGroup]],
    ) -> None:
        source_lane = self.lanes[source_zone]
        diagnostic_builders = {
            endpoint.server_id: self.lanes[zone].builder
            for zone, groups in active.items()
            for runtime in groups.values()
            for endpoint in runtime.endpoints
        }
        selected_test_ids = getattr(self, "selected_test_ids", None)
        for destination_zone in self.lanes:
            if destination_zone == source_zone:
                continue
            executed_specs: list[TestSpec] = []
            engine: TestEngine | None = None
            for base in base_specs:
                source_base = base.source_group_id or dependencies[0]
                destination_base = base.destination_group_id or dependencies[-1]
                source_runtime = active[source_zone][source_base]
                destination_runtime = active[destination_zone][destination_base]
                source_lane.builder.runtime_groups = [
                    source_runtime,
                    destination_runtime,
                ]
                spec = dataclasses.replace(
                    base,
                    id=_cross_zone_test_id(source_zone, destination_zone, base.id),
                    category="cross-zone-connectivity",
                    dependencies=[
                        source_runtime.plan.id,
                        destination_runtime.plan.id,
                    ],
                    source_group_id=source_runtime.plan.id,
                    destination_group_id=destination_runtime.plan.id,
                    source_side="A",
                    destination_side="A",
                    phase="cross-zone",
                    metadata={
                        **base.metadata,
                        "source_availability_zone": source_zone,
                        "destination_availability_zone": destination_zone,
                        "base_test_id": base.id,
                        "base_category": base.category,
                    },
                    display_name=(
                        f"{base.display_name or base.id} — "
                        f"{source_zone} to {destination_zone}"
                    ),
                    scenario="Connectivity between availability zones",
                )
                if selected_test_ids is not None and spec.id not in selected_test_ids:
                    continue
                approved = (
                    next(
                        (
                            item
                            for item in self.reporter.plan.tests
                            if item.id == spec.id
                        ),
                        None,
                    )
                    if self.reporter.plan
                    else None
                )
                if approved is not None:
                    copy_bindings(spec, approved)
                executed_specs.append(spec)
            if executed_specs:
                self_ids = {base.id for base in base_specs}
                for spec in executed_specs:
                    for field in ("requires", "requires_pass"):
                        setattr(
                            spec,
                            field,
                            [
                                _cross_zone_test_id(
                                    source_zone, destination_zone, required
                                )
                                if required in self_ids
                                else required
                                for required in getattr(spec, field)
                            ],
                        )
                source_lane.builder.runtime_groups = list(
                    {
                        runtime.plan.id: runtime
                        for zone in (source_zone, destination_zone)
                        for runtime in active[zone].values()
                    }.values()
                )
                engine = TestEngine(
                    source_lane.config,
                    source_lane.builder.discovery,
                    source_lane.builder,
                    cast(Reporter, self.reporter),
                    diagnostic_builders=diagnostic_builders,
                )
                engine.run_specs(executed_specs)
                self._run_performance(source_lane, engine, executed_specs, active)

    def _run_performance(
        self,
        source_lane: ZoneLane,
        engine: TestEngine,
        source_specs: list[TestSpec],
        active: dict[str, dict[str, RuntimeGroup]],
    ) -> None:
        if not self.config.performance_enabled or self.config.derived_tests_suppressed:
            return
        builders_by_server = {
            endpoint.server_id: self.lanes[zone].builder
            for zone, groups in active.items()
            for runtime in groups.values()
            for endpoint in runtime.endpoints
        }
        control = _CrossZonePerformanceControl(builders_by_server)
        # Serialize measurements so cross-zone lanes do not distort each
        # other's throughput, latency, or loss observations.
        with self.performance_lock:
            runner = PerformanceRunner(
                source_lane.config,
                control,
                cast(Reporter, self.reporter),
                engine,
                session=self.performance_session,
            )
            specs = runner.plan_specs(source_specs, stage="cross-zone")
            if not specs:
                return
            if self.reporter.plan is None:
                raise SuiteError(
                    "Cross-zone performance planning requires an initialized run plan"
                )
            existing = {item.id for item in self.reporter.plan.tests}
            self.reporter.plan.tests.extend(
                item for item in specs if item.id not in existing
            )
            self.reporter.save_plan()
            runner.run_specs(specs)

    def _record_unavailable_batch(
        self, dependencies: tuple[str, ...], base_specs: list[TestSpec]
    ) -> None:
        recorded = 0
        selected_test_ids = getattr(self, "selected_test_ids", None)
        for spec in cross_zone_specs(self.base_plan, list(self.lanes)):
            base_id = str(spec.metadata.get("base_test_id") or "")
            if base_id not in {item.id for item in base_specs}:
                continue
            if selected_test_ids is not None and spec.id not in selected_test_ids:
                continue
            if self.reporter.has_result(spec.id):
                continue
            self.reporter.result(
                spec.id,
                spec.category,
                "BLOCKED_BY_SETUP_ERROR",
                "One or more synchronized AZ endpoint groups could not be created",
                family=spec.family,
                expected=spec.expectation,
                observed="not-run",
                authoritative=False,
                details=spec.metadata,
                display_name=spec.display_name,
                scenario=spec.scenario,
                emit_console=False,
            )
            recorded += 1
        if recorded:
            self.logger.log(
                f"Cross-zone batch coverage: {recorded} planned "
                f"{'validation was' if recorded == 1 else 'validations were'} "
                "recorded as not run because synchronized endpoint groups could "
                "not be created.",
                "ERROR",
            )

    def _cleanup_batch(self, dependencies: tuple[str, ...]) -> list[str]:
        def cleanup_lane(lane: ZoneLane) -> list[str]:
            failures: list[str] = []
            # A one-worker executor lets us inspect each operation's exception
            # without one failure aborting the rest of this lane's cleanup.
            with ThreadPoolExecutor(max_workers=1) as serial:
                for base_group_id in dependencies:
                    group_id = zone_group_id(base_group_id, lane.zone)
                    stop_future = serial.submit(
                        lane.builder.stop_group_probes, group_id
                    )
                    stop_error = stop_future.exception()
                    cleanup_future = serial.submit(
                        lane.cleanup_manager.cleanup_group, group_id
                    )
                    cleanup_error = cleanup_future.exception()
                    complete = (
                        bool(cleanup_future.result())
                        if cleanup_error is None
                        else False
                    )
                    errors = [
                        str(item)
                        for item in (stop_error, cleanup_error)
                        if item is not None
                    ]
                    if errors:
                        failures.append(f"{lane.zone}:{group_id} ({'; '.join(errors)})")
                    elif not complete:
                        failures.append(f"{lane.zone}:{group_id} (cleanup incomplete)")
                    if complete:
                        lane.builder.runtime_groups = [
                            item
                            for item in lane.builder.runtime_groups
                            if item.plan.id != group_id
                        ]
            lane.builder.runtime_groups = self._lane_owned_runtimes(lane)
            self._refresh_lane_checkpoint(lane, phase="cross-zone-cleanup")
            return failures

        failures: list[str] = []
        with ThreadPoolExecutor(max_workers=min(self.workers, len(self.lanes))) as pool:
            futures = [pool.submit(cleanup_lane, lane) for lane in self.lanes.values()]
            for future in as_completed(futures):
                failures.extend(future.result())
        for failure in failures:
            self.logger.log(f"Cross-zone cleanup issue: {failure}", "ERROR")
        return failures

    @staticmethod
    def _lane_owned_runtimes(lane: ZoneLane) -> list[RuntimeGroup]:
        return [
            runtime
            for runtime in lane.builder.runtime_groups
            if runtime.plan.metadata.get("availability_zone") == lane.zone
        ]

    @staticmethod
    def _refresh_lane_checkpoint(lane: ZoneLane, *, phase: str) -> None:
        lane_results = list(lane.reporter.results)
        completed = list(dict.fromkeys(item.test_id for item in lane_results))
        lane.checkpoint.completed_test_ids = completed
        lane.checkpoint.failed_test_ids = [
            item.test_id
            for item in lane_results
            if grades_execution(item) and item.status in {"FAIL", "ERROR"}
        ]
        lane.checkpoint.pending_test_ids = [
            item.id for item in lane.plan.tests if item.id not in completed
        ]
        lane.checkpoint.active_group_ids = [
            runtime.plan.id for runtime in CrossZoneExecutor._lane_owned_runtimes(lane)
        ]
        lane.checkpoint.state = "RUNNING"
        lane.checkpoint.phase = phase
        lane.checkpoint.updated_at = iso_utc()
        lane.checkpoint.last_activity = lane.checkpoint.updated_at
        lane.state_store.save(lane.checkpoint)


class MultiZoneOrchestrator:
    def __init__(
        self,
        config: Config,
        discovery,
        base_plan: Plan,
        zone_plan: ZoneExecutionPlan,
        reporter: Reporter,
        launch_selection: LaunchSelection,
        *,
        execution_plan: Plan | None = None,
    ):
        self.config = config
        self.discovery = discovery
        self.base_plan = base_plan
        self.zone_plan = zone_plan
        self.reporter = reporter
        self.logger = reporter.logger
        self.launch_selection = launch_selection
        self.execution_plan = execution_plan or aggregate_plan(
            base_plan, zone_plan, config
        )
        self.selected_test_ids = (
            {item.id for item in self.execution_plan.tests}
            if config.selective_run
            else None
        )
        self.lanes: dict[str, ZoneLane] = {}
        self.shared_security_reporter: ScopedReporter | None = None
        self.shared_security_builder: ResourceBuilder | None = None
        self.shared_security_cleanup: CleanupManager | None = None
        self.prepared = False
        self.performance_lock = threading.RLock()
        self.cloud_operation_coordinator = CloudOperationCoordinator(reporter)
        self.lifecycle_lock = self.cloud_operation_coordinator.lock

    def _planned_cross_zone_specs(self) -> list[TestSpec]:
        return [
            item
            for item in self.execution_plan.tests
            if item.phase == "cross-zone" or item.id.startswith("CROSS-ZONE-")
        ]

    def _filter_lane_plan(self, lane_plan: Plan, zone: str) -> Plan:
        if self.selected_test_ids is None:
            return lane_plan
        prefix = zone_scope(zone).upper() + "-"
        local_ids = {
            test_id[len(prefix) :]
            for test_id in self.selected_test_ids
            if test_id.startswith(prefix)
        }
        tests = [item for item in lane_plan.tests if item.id in local_ids]
        return dataclasses.replace(
            lane_plan,
            tests=tests,
            selection_mode="exact",
            requested_test_ids=list(self.execution_plan.requested_test_ids),
            automatically_included_test_ids=[
                test_id[len(prefix) :]
                for test_id in self.execution_plan.automatically_included_test_ids
                if test_id.startswith(prefix)
            ],
        )

    @staticmethod
    def _failure_text(exc: BaseException) -> str:
        text = str(exc).strip()
        return f"{type(exc).__name__}: {text}" if text else type(exc).__name__

    @property
    def active_lanes(self) -> dict[str, ZoneLane]:
        """Return AZ lanes that remain safe and eligible to execute."""

        return {
            zone: lane
            for zone, lane in self.lanes.items()
            if lane.prepared
            and lane.setup_error is None
            and lane.execution_error is None
        }

    def _expected_lane_specs(self, lane: ZoneLane) -> list[TestSpec]:
        if self.zone_plan.includes_per_zone:
            return list(lane.plan.tests)
        return [
            spec
            for spec in lane.plan.tests
            if spec.scenario == "Controller readiness"
            or spec.id in {"CONTROL-OBSERVATION-PORTS", "CONTROL-SSH"}
        ]

    def _root_lane_spec(self, lane: ZoneLane, *, phase: str) -> TestSpec | None:
        if phase != "controller-bootstrap":
            return None
        missing = [
            spec
            for spec in self._expected_lane_specs(lane)
            if not lane.reporter.has_result(spec.id)
        ]
        for preferred in ("CONTROL-SSH", "CONTROL-OBSERVATION-PORTS"):
            match = next((spec for spec in missing if spec.id == preferred), None)
            if match is not None:
                return match
        return None

    def _record_lane_failure(
        self,
        lane: ZoneLane,
        exc: BaseException,
        *,
        phase: str,
    ) -> None:
        """Isolate one failed lane and materialize only its blocked work."""

        failure = self._failure_text(exc)
        setup_failure = phase == "controller-bootstrap"
        if setup_failure:
            lane.prepared = False
            lane.setup_error = failure
            lane.checkpoint.state = "FAILED"
        else:
            lane.execution_error = failure
            lane.checkpoint.state = "FAILED"
        lane.checkpoint.phase = phase

        root_spec = self._root_lane_spec(lane, phase=phase)
        root_result_id: str | None = None
        existing_root = next(
            (
                result
                for result in reversed(lane.reporter.results)
                if result.status == "ERROR"
                and bool((result.details or {}).get("root_lane_error"))
                and str((result.details or {}).get("failure_phase") or "") == phase
            ),
            None,
        )
        if existing_root is not None:
            root_result_id = lane.reporter.scoped_test_id(existing_root.test_id)
        else:
            root_local_id = (
                root_spec.id
                if root_spec is not None
                else (
                    "CONTROLLER-SETUP-ERROR"
                    if setup_failure
                    else "LANE-EXECUTION-ERROR"
                )
            )
            root_category = (
                "controller-bootstrap"
                if setup_failure
                else root_spec.category
                if root_spec is not None
                else "execution-control"
            )
            root_expected = (
                "controller-bootstrap-complete"
                if setup_failure
                else root_spec.expectation
                if root_spec is not None
                else "execution-complete"
            )
            root_observed = (
                "controller-bootstrap-error" if setup_failure else "execution-error"
            )
            root_display_name = (
                "Prepare the availability-zone probe controller"
                if setup_failure
                else root_spec.display_name
                if root_spec is not None
                else "Complete the availability-zone execution lane"
            )
            root_scenario = (
                "Controller readiness"
                if setup_failure
                else root_spec.scenario
                if root_spec is not None
                else "Availability-zone execution"
            )
            diagnostic_binding = {}
            if root_spec is None:
                context_spec = next(iter(self._expected_lane_specs(lane)), None)
                if context_spec is not None and context_spec.metadata.get(
                    "planned_check_id"
                ):
                    diagnostic_binding = {
                        "planned_check_id": context_spec.metadata["planned_check_id"],
                        "check_sample": True,
                    }
            lane.reporter.result(
                root_local_id,
                root_category,
                "ERROR",
                (
                    f"Neutron Flux controller setup failed in {lane.zone}; no "
                    f"cloud networking verdict was produced: {failure}"
                    if setup_failure
                    else f"Neutron Flux stopped the {lane.zone} execution lane: {failure}"
                ),
                family=(
                    None
                    if setup_failure
                    else root_spec.family
                    if root_spec is not None
                    else None
                ),
                expected=root_expected,
                observed=root_observed,
                authoritative=False,
                likely_failure="neutron-flux tool failure",
                details={
                    **(root_spec.metadata if root_spec is not None else {}),
                    "dependencies": (
                        list(root_spec.dependencies) if root_spec is not None else []
                    ),
                    **diagnostic_binding,
                    "root_lane_error": True,
                    "root_setup_error": setup_failure,
                    "tool_failure": True,
                    "failure_phase": phase,
                    "exception_type": type(exc).__name__,
                    "exception_message": str(exc),
                    "operation": (
                        "tool-controller-bootstrap"
                        if setup_failure
                        else "tool-lane-execution"
                    ),
                    "controller_bootstrap_diagnostics": list(
                        getattr(lane.builder, "controller_bootstrap_diagnostics", [])
                        or []
                    ),
                },
                display_name=root_display_name,
                scenario=root_scenario,
            )
            root_result_id = lane.reporter.scoped_test_id(root_local_id)

        blocked = 0
        for spec in self._expected_lane_specs(lane):
            if lane.reporter.has_result(spec.id):
                continue
            lane.reporter.result(
                spec.id,
                spec.category,
                "BLOCKED_BY_SETUP_ERROR",
                (
                    f"Not run because Neutron Flux controller setup failed in {lane.zone}"
                    if setup_failure
                    else f"Not run because the Neutron Flux {lane.zone} execution lane stopped"
                ),
                family=spec.family,
                expected=spec.expectation,
                observed="not-run",
                authoritative=False,
                details={
                    **spec.metadata,
                    "dependencies": list(spec.dependencies),
                    "coverage_outcome": "NEVER_RAN",
                    "blocked_by_setup_error": True,
                    "tool_failure": True,
                    "failure_phase": phase,
                    "root_setup_result_id": root_result_id,
                    "reason_authority": (
                        "neutron-flux availability-zone execution ledger"
                    ),
                },
                display_name=spec.display_name,
                scenario=spec.scenario,
                emit_console=False,
            )
            blocked += 1

        lane.reporter.record_setup_failure(
            (
                f"Controller setup failed in availability zone {lane.zone}: {failure}"
                if setup_failure
                else f"Execution failed in availability zone {lane.zone}: {failure}"
            ),
            failure_phase=phase,
            tool_failure=True,
            root_setup_result_id=root_result_id,
            blocked_descendant_count=blocked,
            emit_console=False,
        )
        lane_results = list(lane.reporter.results)
        lane.checkpoint.completed_test_ids = list(
            dict.fromkeys(result.test_id for result in lane_results)
        )
        lane.checkpoint.failed_test_ids = [
            result.test_id
            for result in lane_results
            if grades_execution(result) and result.status in {"FAIL", "ERROR"}
        ]
        lane.checkpoint.pending_test_ids = []
        lane.checkpoint.updated_at = iso_utc()
        lane.checkpoint.last_activity = lane.checkpoint.updated_at
        lane.checkpoint.metadata.update(
            {
                "failure_phase": phase,
                "root_error": failure,
                "blocked_descendant_count": blocked,
            }
        )
        lane.state_store.save(lane.checkpoint)
        self.logger.log(
            (
                f"Availability-zone lane {lane.zone} failed during "
                f"{phase.replace('-', ' ')}: {failure}. "
                f"{blocked} downstream "
                f"{'validation was' if blocked == 1 else 'validations were'} "
                "recorded as not run. This lane was isolated; remaining lanes "
                "are evaluated independently."
            ),
            "ERROR",
        )

    def _record_unavailable_cross_zone_specs(
        self,
        unavailable_zones: set[str],
        *,
        reason: str,
    ) -> int:
        if not self.zone_plan.includes_cross_zone:
            return 0
        recorded = 0
        for spec in self._planned_cross_zone_specs():
            source_zone = str(spec.metadata.get("source_availability_zone") or "")
            destination_zone = str(
                spec.metadata.get("destination_availability_zone") or ""
            )
            if unavailable_zones and not (
                {source_zone, destination_zone} & unavailable_zones
            ):
                continue
            if self.reporter.has_result(spec.id):
                continue
            self.reporter.result(
                spec.id,
                spec.category,
                "BLOCKED_BY_SETUP_ERROR",
                reason,
                family=spec.family,
                expected=spec.expectation,
                observed="not-run",
                authoritative=False,
                details={
                    **spec.metadata,
                    "dependencies": list(spec.dependencies),
                    "execution_scope": "cross-zone",
                    "coverage_outcome": "NEVER_RAN",
                    "blocked_by_setup_error": True,
                    "tool_failure": True,
                    "unavailable_availability_zones": sorted(unavailable_zones),
                    "reason_authority": (
                        "neutron-flux availability-zone execution ledger"
                    ),
                },
                display_name=spec.display_name,
                scenario=spec.scenario,
                emit_console=False,
            )
            recorded += 1
        if recorded:
            affected = (
                ", ".join(sorted(unavailable_zones))
                if unavailable_zones
                else "all required availability-zone lanes"
            )
            self.logger.log(
                f"Cross-zone coverage: {recorded} planned "
                f"{'validation was' if recorded == 1 else 'validations were'} "
                f"recorded as not run; unavailable scope: {affected}.",
                "ERROR",
            )
        return recorded

    def _prepare_shared_security_groups(self) -> SecurityGroupBundle:
        self.logger.section("Preparing one run-wide security-group bundle")
        reporter = ScopedReporter(
            self.reporter, "shared-security", availability_zone=None
        )
        osc = OpenStack(
            cast(Logger, reporter.logger),
            cloud_operation_coordinator=self.cloud_operation_coordinator,
        )
        tracker = ResourceTracker(cast(Reporter, reporter))
        cleanup = CleanupManager(
            osc,
            cast(Reporter, reporter),
            tracker,
            self.config,
            lifecycle_lock=self.lifecycle_lock,
            cloud_operation_coordinator=self.cloud_operation_coordinator,
        )
        builder = ResourceBuilder(
            self.config,
            self.discovery,
            self.base_plan,
            osc,
            cast(Reporter, reporter),
            tracker,
            launch_selection=self.launch_selection,
            lifecycle_lock=self.lifecycle_lock,
            cloud_operation_coordinator=self.cloud_operation_coordinator,
        )
        builder.management_cidr = builder._choose_management_cidr()
        self.shared_security_reporter = reporter
        self.shared_security_builder = builder
        self.shared_security_cleanup = cleanup
        builder._create_security_groups(select_control_ports=False)
        self.cloud_operation_coordinator.settle(
            "security-group",
            "allow the shared security-group rule bundle to converge before AZ lane preparation",
            seconds=15.0,
        )
        bundle = builder.export_security_group_bundle()
        self.logger.log(
            "Run-wide security groups ready: 4 groups and one deterministic rule set "
            f"shared by {len(self.zone_plan.zones)} availability-zone lanes"
        )
        return bundle

    def prepare(self) -> None:
        shared_bundle = self._prepare_shared_security_groups()
        self.logger.section(
            "Preparing availability-zone lanes with paced dataplane cloud operations"
        )
        self.logger.log(
            "Automatic scheduling across AZs: journaled and paced submissions, bounded independent lifecycle/readiness work, exclusive measurement and migration windows, and quarantine for ambiguous cloud operations"
        )
        for lane_index, zone in enumerate(self.zone_plan.zones):
            scope = zone_scope(zone)
            lane_config = dataclasses.replace(
                self.config,
                availability_zones=[zone],
                availability_zones_all=False,
                zone_mode="per-zone",
                mgmt_cidr=shared_bundle.management_cidr,
            )
            lane_reporter = ScopedReporter(self.reporter, scope, availability_zone=zone)
            lane_plan = self._filter_lane_plan(
                clone_plan_for_zone(self.base_plan, zone), zone
            )
            approved_specs = {item.id: item for item in self.execution_plan.tests}
            for spec in lane_plan.tests:
                approved = approved_specs.get(lane_reporter.scoped_test_id(spec.id))
                if approved is not None:
                    copy_bindings(spec, approved)
            lane_reporter.plan = lane_plan
            osc = OpenStack(
                cast(Logger, lane_reporter.logger),
                cloud_operation_coordinator=self.cloud_operation_coordinator,
            )
            tracker = ResourceTracker(cast(Reporter, lane_reporter))
            cleanup = CleanupManager(
                osc,
                cast(Reporter, lane_reporter),
                tracker,
                lane_config,
                lifecycle_lock=self.lifecycle_lock,
                cloud_operation_coordinator=self.cloud_operation_coordinator,
            )
            state_root = self.reporter.run_dir / "zones" / scope / "state"
            state_store = StateStore(state_root)
            now = iso_utc()
            checkpoint = RunCheckpoint(
                run_id=f"{self.reporter.run_id}-{scope}",
                state="INITIALIZING",
                action="run",
                phase="initializing",
                current_batch=None,
                started_at=now,
                updated_at=now,
                last_activity=now,
                completed_test_ids=[],
                failed_test_ids=[],
                pending_test_ids=[item.id for item in lane_plan.tests],
                active_group_ids=[],
                manifest_path=str(lane_reporter.manifest_path),
                report_dir=str(lane_reporter.run_dir),
                cleanup_state="NOT_STARTED",
                metadata={"availability_zone": zone, "execution_scope": scope},
            )
            builder = ResourceBuilder(
                lane_config,
                self.discovery,
                lane_plan,
                osc,
                cast(Reporter, lane_reporter),
                tracker,
                launch_selection=self.launch_selection,
                lifecycle_lock=self.lifecycle_lock,
                cloud_operation_coordinator=self.cloud_operation_coordinator,
            )
            builder.shared_security_group_bundle = shared_bundle
            # Each lane uses a distinct temporary TCP control port while sharing
            # the same A/B security groups. This keeps concurrent security-group
            # lifecycle tests independent without consuming per-AZ SG quota.
            # Reserve a disjoint 128-port search window for each lane. The
            # chooser scans at most 128 candidates, so 256-port spacing cannot
            # converge on another lane's temporary rule port.
            builder.security_control_port_seed = (
                self.config.tcp_port + 2 + (lane_index * 256)
            )
            self.lanes[zone] = ZoneLane(
                zone=zone,
                scope=scope,
                config=lane_config,
                plan=lane_plan,
                reporter=lane_reporter,
                osc=osc,
                tracker=tracker,
                cleanup_manager=cleanup,
                state_store=state_store,
                checkpoint=checkpoint,
                builder=builder,
            )

        failures: dict[str, BaseException] = {}
        with ThreadPoolExecutor(max_workers=self.zone_plan.parallel_workers) as pool:
            futures = {
                pool.submit(self._prepare_lane, lane): zone
                for zone, lane in self.lanes.items()
            }
            for future in as_completed(futures):
                zone = futures[future]
                try:
                    future.result()
                    lane = self.lanes[zone]
                    lane.prepared = True
                    lane.setup_error = None
                except RunCancelledError:
                    raise
                except Exception as exc:
                    failures[zone] = exc
                    self._record_lane_failure(
                        self.lanes[zone], exc, phase="controller-bootstrap"
                    )
        if failures:
            unavailable = set(failures)
            self._record_unavailable_cross_zone_specs(
                unavailable,
                reason=(
                    "Cross-zone validation did not run because one or more required "
                    "availability-zone controllers failed setup: "
                    + " | ".join(
                        f"{zone}: {self._failure_text(exc)}"
                        for zone, exc in sorted(failures.items())
                    )
                ),
            )
        active = self.active_lanes
        if not active:
            raise SetupFailureError(
                "No availability-zone lane completed controller setup: "
                + " | ".join(
                    f"{zone}: {self._failure_text(exc)}"
                    for zone, exc in sorted(failures.items())
                )
            )
        self.prepared = True
        self.logger.log(
            "Availability-zone controllers ready for execution: "
            + ", ".join(active)
            + (
                "; unavailable lanes: " + ", ".join(sorted(failures))
                if failures
                else ""
            )
        )

    def _prepare_lane(self, lane: ZoneLane) -> None:
        lane.state_store.save(lane.checkpoint)
        lane.builder.prepare()
        required = {"CONTROL-OBSERVATION-PORTS", "CONTROL-SSH"}
        missing = [item for item in required if not lane.reporter.has_result(item)]
        if missing:
            raise SuiteError(
                f"Controller bootstrap in {lane.zone} did not record required results: "
                + ", ".join(missing)
            )
        lane.builder.update_cloud_heartbeat("active")
        lane.prepared = True
        lane.setup_error = None

    def run(self) -> None:
        if not self.prepared:
            self.prepare()
        if self.zone_plan.includes_per_zone:
            self.logger.section(
                "Running complete suites with serialized lifecycle changes"
            )
            failures: dict[str, BaseException] = {}
            active_before_run = self.active_lanes
            with ThreadPoolExecutor(
                max_workers=self.zone_plan.parallel_workers
            ) as pool:
                futures = {
                    pool.submit(self._run_lane, lane): zone
                    for zone, lane in active_before_run.items()
                }
                for future in as_completed(futures):
                    zone = futures[future]
                    try:
                        future.result()
                    except RunCancelledError:
                        raise
                    except Exception as exc:
                        failures[zone] = exc
                        self._record_lane_failure(
                            self.lanes[zone], exc, phase="per-zone-execution"
                        )
            if failures:
                self._record_unavailable_cross_zone_specs(
                    set(failures),
                    reason=(
                        "Cross-zone validation did not run because one or more "
                        "required availability-zone lanes failed during per-zone "
                        "execution: "
                        + " | ".join(
                            f"{zone}: {self._failure_text(exc)}"
                            for zone, exc in sorted(failures.items())
                        )
                    ),
                )
        if self.zone_plan.includes_cross_zone and self._planned_cross_zone_specs():
            active = self.active_lanes
            unavailable = set(self.lanes) - set(active)
            if unavailable:
                self._record_unavailable_cross_zone_specs(
                    unavailable,
                    reason=(
                        "Cross-zone validation did not run for paths involving an "
                        "availability-zone lane whose controller or execution phase "
                        "was unavailable"
                    ),
                )
            if len(active) >= 2:
                try:
                    CrossZoneExecutor(
                        self.config,
                        self.base_plan,
                        active,
                        self.reporter,
                        self.zone_plan.parallel_workers,
                        self.performance_lock,
                        selected_test_ids=self.selected_test_ids,
                    ).run()
                except RunCancelledError:
                    raise
                except (SuiteError, OSError, ValueError, TypeError) as exc:
                    reason = f"Cross-zone execution failed: {self._failure_text(exc)}"
                    self.reporter.record_setup_failure(
                        reason,
                        execution_scope="cross-zone",
                        failure_phase="cross-zone-execution",
                        tool_failure=True,
                    )
                    self._record_unavailable_cross_zone_specs(
                        set(),
                        reason=reason,
                    )
                    self.logger.log(reason, "ERROR")
            elif not unavailable:
                reason = (
                    "Cross-zone validation requires at least two prepared "
                    "availability-zone lanes"
                )
                self.reporter.record_setup_failure(
                    reason,
                    execution_scope="cross-zone",
                    failure_phase="cross-zone-execution",
                    tool_failure=True,
                )
                self._record_unavailable_cross_zone_specs(set(), reason=reason)

    def _run_lane(self, lane: ZoneLane) -> None:
        AdaptiveExecutor(
            lane.config,
            lane.plan,
            lane.builder,
            cast(Reporter, lane.reporter),
            lane.cleanup_manager,
            lane.state_store,
            lane.checkpoint,
            self.performance_lock,
        ).run()

    def sync_checkpoints(
        self, state: str, phase: str, cleanup_state: str, error: str | None = None
    ) -> None:
        """Publish each lane's final evidence without losing its own failure."""
        parent_cleanup = self.reporter.cleanup_summary
        verified_clean = (
            parent_cleanup.get("complete") is True
            and not parent_cleanup.get("errors")
            and not parent_cleanup.get("leftovers")
            and not parent_cleanup.get("unresolved_operations")
            and not parent_cleanup.get("unverified_resource_count")
            and not parent_cleanup.get("interrupted")
            and all(
                item.delete_status in {"deleted", "already-absent"}
                for item in self.reporter.resources
            )
        )
        for lane in self.lanes.values():
            checkpoint = lane.checkpoint
            prefix = lane.scope.upper() + "-"
            results = [
                dataclasses.replace(item, test_id=item.test_id[len(prefix) :])
                for item in self.reporter.results
                if item.test_id.startswith(prefix)
            ]
            completed = list(dict.fromkeys(item.test_id for item in results))
            checkpoint.completed_test_ids = completed
            terminal = [item for item in results if grades_execution(item)]
            checkpoint.failed_test_ids = [
                item.test_id for item in terminal if item.status in {"FAIL", "ERROR"}
            ]
            checkpoint.pending_test_ids = [
                item.id
                for item in self._expected_lane_specs(lane)
                if item.id not in set(completed)
            ]
            previous_execution = checkpoint.metadata.get("execution_state")
            failure = (
                lane.setup_error
                or lane.execution_error
                or (
                    checkpoint.error
                    if previous_execution == "FAILED" or checkpoint.state == "FAILED"
                    else None
                )
            )
            cancelled = previous_execution == "CANCELLED" or any(
                item.status == "NOT_RUN_CANCELLED" for item in terminal
            )
            invalid = any(
                item.status not in {"PASS", "NOT_APPLICABLE"} for item in terminal
            )
            if failure or checkpoint.failed_test_ids or (invalid and not cancelled):
                lane_state = "FAILED"
            elif cancelled:
                lane_state = "CANCELLED"
            elif state in {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"}:
                lane_state = (
                    "COMPLETED"
                    if not checkpoint.pending_test_ids
                    else state
                    if state != "COMPLETED"
                    else "INTERRUPTED"
                )
            else:
                lane_state = state
            if lane_state in {"COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"}:
                checkpoint.metadata["execution_state"] = lane_state
            if cleanup_state == "COMPLETE" and not verified_clean:
                checkpoint.cleanup_state = "INCOMPLETE"
            else:
                checkpoint.cleanup_state = cleanup_state
            if checkpoint.cleanup_state == "INCOMPLETE":
                lane_state = "CLEANUP_INCOMPLETE"
            checkpoint.state = lane_state
            checkpoint.phase = phase
            checkpoint.current_batch = None
            if checkpoint.cleanup_state == "COMPLETE":
                checkpoint.active_group_ids = []
            checkpoint.error = failure or (
                checkpoint.error or error
                if checkpoint.metadata.get("execution_state")
                in {"FAILED", "CANCELLED", "INTERRUPTED"}
                else None
            )
            checkpoint.updated_at = iso_utc()
            checkpoint.last_activity = checkpoint.updated_at
            lane.state_store.save(checkpoint)

    def stop_all_probes(self) -> None:
        for lane in self.lanes.values():
            lane.builder.stop_all_probes()

    def update_cloud_heartbeat(self, state: str) -> None:
        for lane in self.active_lanes.values():
            lane.builder.update_cloud_heartbeat(state)

    def cleanup_all(self) -> bool:
        lane_errors: list[str] = []
        zone_summaries: dict[str, dict] = {}

        def interrupted_result() -> bool:
            confirmed_deleted = len(
                {
                    (resource.resource_type, resource.id)
                    for resource in self.reporter.resources
                    if resource.delete_status in {"deleted", "already-absent"}
                }
            )
            explicit_deleted = len(
                {
                    (resource.resource_type, resource.id)
                    for resource in self.reporter.resources
                    if resource.delete_status == "deleted"
                }
            )
            unverified = sum(
                resource.delete_status not in {"deleted", "already-absent"}
                for resource in self.reporter.resources
            )
            known_leftovers = [
                item
                for summary in [
                    self.reporter.cleanup_summary,
                    *zone_summaries.values(),
                ]
                for item in summary.get("leftovers", [])
                if ":QUARANTINED:" in str(item)
            ]
            errors = [
                item
                for item in dict.fromkeys(
                    [
                        *lane_errors,
                        *self.reporter.cleanup_summary.get("errors", []),
                    ]
                )
                if "received signal" not in str(item).lower()
            ]
            self.reporter.cleanup_summary.update(
                {
                    "attempted": True,
                    "complete": None,
                    "interrupted": True,
                    "interruption_reason": hard_abort_reason(),
                    "scope_verification": (
                        "multi-zone-cleanup-interrupted-before-final-verification"
                    ),
                    "deleted": explicit_deleted,
                    "confirmed_deleted_count": confirmed_deleted,
                    "unverified_resource_count": unverified,
                    "errors": errors,
                    "leftovers": list(dict.fromkeys(known_leftovers)),
                    "zones": zone_summaries,
                    "ownership_model": (
                        "tracked lane cleanup interrupted before the parent "
                        "exact-run adoption sweep"
                    ),
                }
            )
            self.reporter.event(
                "multi-zone-cleanup-interrupted",
                "Multi-zone cleanup stopped before parent verification",
                confirmed_deleted=confirmed_deleted,
                unverified_resources=unverified,
                reason=hard_abort_reason(),
            )
            self.logger.log(
                "Multi-zone cleanup stopped before final verification; "
                f"{confirmed_deleted} deletion(s) are confirmed and "
                f"{unverified} tracked resource(s) require resumed cleanup",
                "WARNING",
            )
            if self.shared_security_builder is not None:
                shutil.rmtree(self.shared_security_builder.work_dir, ignore_errors=True)
            return False

        if self.lanes:
            with ThreadPoolExecutor(
                max_workers=self.zone_plan.parallel_workers
            ) as pool:
                futures = {
                    pool.submit(
                        lane.cleanup_manager.cleanup,
                        adopt_discovered=False,
                        clear_recovery_artifacts=False,
                        completion_message=None,
                    ): zone
                    for zone, lane in self.lanes.items()
                }
                for future in as_completed(futures):
                    zone = futures[future]
                    lane = self.lanes[zone]
                    try:
                        lane_complete = bool(future.result())
                    except Exception as exc:
                        lane_complete = False
                        lane.reporter.cleanup_summary["errors"].append(str(exc))
                    if not lane_complete:
                        lane.reporter.cleanup_summary.setdefault(
                            "scope_verification",
                            "incomplete-before-final-run-sweep",
                        )
                    lane_errors.extend(
                        f"{zone}: {item}"
                        for item in lane.reporter.cleanup_summary.get("errors", [])
                    )
                    zone_summaries[zone] = dict(lane.reporter.cleanup_summary)

        if hard_abort_requested() or any(
            summary.get("interrupted") for summary in zone_summaries.values()
        ):
            return interrupted_result()

        # Shared security groups must be deleted only after every AZ lane has
        # removed its ports. Otherwise Neutron correctly rejects SG deletion as
        # still in use.
        if self.shared_security_cleanup is not None:
            shared_complete = False
            try:
                shared_complete = bool(
                    self.shared_security_cleanup.cleanup(
                        adopt_discovered=False,
                        clear_recovery_artifacts=False,
                        completion_message=None,
                    )
                )
            except Exception as exc:
                if self.shared_security_reporter is not None:
                    self.shared_security_reporter.cleanup_summary["errors"].append(
                        str(exc)
                    )
            if self.shared_security_reporter is not None:
                summary = self.shared_security_reporter.cleanup_summary
                if not shared_complete:
                    summary.setdefault(
                        "scope_verification",
                        "incomplete-before-final-run-sweep",
                    )
                lane_errors.extend(
                    f"shared-security: {item}" for item in summary.get("errors", [])
                )
                zone_summaries["shared-security"] = dict(summary)
        if self.shared_security_builder is not None:
            shutil.rmtree(self.shared_security_builder.work_dir, ignore_errors=True)

        if hard_abort_requested() or any(
            summary.get("interrupted") for summary in zone_summaries.values()
        ):
            return interrupted_result()

        # One parent-scoped exact-run sweep owns orphan adoption. Lane cleanup
        # is deliberately limited to resources already tracked in that lane so
        # one AZ can never adopt or delete another AZ's resources or the shared
        # security-group bundle.
        final_osc = OpenStack(
            self.logger,
            cloud_operation_coordinator=self.cloud_operation_coordinator,
        )
        final_tracker = ResourceTracker(self.reporter)
        final_cleanup = CleanupManager(
            final_osc,
            self.reporter,
            final_tracker,
            self.config,
            lifecycle_lock=self.lifecycle_lock,
            cloud_operation_coordinator=self.cloud_operation_coordinator,
        )
        try:
            complete = bool(
                final_cleanup.cleanup(
                    run_tag=self.reporter.run_tag,
                    name_prefix=self.reporter.name_prefix,
                    adopt_discovered=True,
                    clear_recovery_artifacts=True,
                    completion_message=(
                        "Cleanup complete; one parent-scoped exact-run sweep "
                        "verified that no managed resources remain"
                    ),
                )
            )
        except (SuiteError, OSError, ValueError, TypeError) as exc:
            complete = False
            self.reporter.cleanup_summary.setdefault("errors", []).append(str(exc))

        if hard_abort_requested() or self.reporter.cleanup_summary.get("interrupted"):
            return interrupted_result()

        final_errors = list(self.reporter.cleanup_summary.get("errors") or [])
        final_leftovers = list(self.reporter.cleanup_summary.get("leftovers") or [])
        if complete:
            managers = [
                (zone, lane.cleanup_manager, lane.reporter)
                for zone, lane in self.lanes.items()
            ]
            if self.shared_security_cleanup is not None:
                managers.append(
                    (
                        "shared-security",
                        self.shared_security_cleanup,
                        self.shared_security_reporter,
                    )
                )
            for zone, manager, scoped in managers:
                manager._clear_recovery_artifacts()
                summary = scoped.cleanup_summary
                summary.update(
                    {
                        "complete": True,
                        "leftovers": [],
                        "unresolved_operations": [],
                        "recovered_errors": list(summary.get("errors") or []),
                        "errors": [],
                        "scope_verification": "verified-by-final-parent-sweep",
                    }
                )
                zone_summaries[zone] = dict(summary)
        combined_errors = list(dict.fromkeys([*lane_errors, *final_errors]))
        deleted = len(
            {
                (resource.resource_type, resource.id)
                for resource in self.reporter.resources
                if resource.delete_status == "deleted"
            }
        )
        self.reporter.cleanup_summary.update(
            {
                "attempted": True,
                "complete": complete,
                "deleted": deleted,
                "errors": [] if complete else combined_errors,
                "recovered_errors": combined_errors if complete else [],
                "leftovers": final_leftovers,
                "zones": zone_summaries,
                "ownership_model": (
                    "tracked lane cleanup followed by one parent exact-run "
                    "adoption sweep"
                ),
            }
        )
        return complete
