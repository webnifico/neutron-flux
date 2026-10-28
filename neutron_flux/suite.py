from __future__ import annotations

import pathlib
import shutil
import time
from collections import Counter

from .cancellation import raise_if_cancelled
from .capability_preflight import CapabilityPreflight
from .check_ledger import finalize_checks
from .check_plan import build_check_plan, describe_check_plan
from .cleanup import CleanupManager
from .cloud_operation import CloudOperationCoordinator
from .config import Config
from .diagrams import PlanDiagramRenderer
from .discovery import Discoverer
from .errors import SetupFailureError, SuiteError
from .executor import AdaptiveExecutor
from .failure_injection import inject_failure
from .host_qualification import HostQualificationPlanner
from .logical_results import grades_execution
from .models import Discovery, Plan, RunCheckpoint, ZoneExecutionPlan
from .multi_zone import MultiZoneOrchestrator, aggregate_plan
from .openstack import OpenStack
from .operation_recovery import recover_operations
from .pair_suite import (
    estimate_pair_suite,
    expand_pair_suite,
    is_pair_suite,
    run_pair_suite,
    validate_pair_execution_plan,
)
from .plan_contract import (
    create_plan_contract,
    drift_diff,
    format_drift,
    inventory_snapshot,
    load_plan_contract,
    verify_plan_contract,
)
from .planning import Planner
from .progress import reporter_progress
from .reporting import Reporter, ResourceTracker
from .resources import (
    LaunchSelection,
    ResourceBuilder,
    resolve_launch_selection,
    validate_launch_selection_quota,
)
from .state import StateStore
from .test_selection import select_plan_tests
from .utils import iso_utc
from .zones import ZonePreflight


class Suite:
    def __init__(
        self,
        config: Config,
        reporter: Reporter,
        state_store: StateStore,
        checkpoint: RunCheckpoint,
    ):
        self.config = config
        self.reporter = reporter
        self.logger = reporter.logger
        self.state_store = state_store
        self.checkpoint = checkpoint
        self.cloud_operation_coordinator = CloudOperationCoordinator(reporter)
        self.osc = OpenStack(
            self.logger,
            cloud_operation_coordinator=self.cloud_operation_coordinator,
        )
        self.tracker = ResourceTracker(reporter)
        self.lifecycle_lock = self.cloud_operation_coordinator.lock
        self.discovery: Discovery | None = None
        self.plan: Plan | None = None
        self.builder: ResourceBuilder | None = None
        self.launch_selection: LaunchSelection | None = None
        self.zone_plan: ZoneExecutionPlan | None = None
        self.zone_orchestrator: MultiZoneOrchestrator | None = None
        self.base_plan: Plan | None = None
        self.capabilities: dict[str, object] | None = None
        self.cleanup_manager = CleanupManager(
            self.osc,
            reporter,
            self.tracker,
            config,
            lifecycle_lock=self.lifecycle_lock,
            cloud_operation_coordinator=self.cloud_operation_coordinator,
        )
        self.resources_started = False
        self._last_heartbeat = 0.0
        self._last_cloud_heartbeat = 0.0
        self.reporter.logger.heartbeat = self._heartbeat

    def _heartbeat(self) -> None:
        now = time.monotonic()
        if now - self._last_heartbeat < 5:
            return
        self._last_heartbeat = now
        self.checkpoint.last_activity = iso_utc()
        self.checkpoint.updated_at = self.checkpoint.last_activity
        self.checkpoint.metadata["test_progress"] = reporter_progress(self.reporter)
        try:
            self.state_store.save(self.checkpoint)
        except (OSError, SuiteError):
            # Logging must never fail the network test because a status
            # heartbeat could not be persisted momentarily.
            pass
        if not self._last_cloud_heartbeat or now - self._last_cloud_heartbeat >= 300:
            self._last_cloud_heartbeat = now
            if self.zone_orchestrator is not None:
                self.zone_orchestrator.update_cloud_heartbeat("active")
            elif self.builder is not None:
                self.builder.update_cloud_heartbeat("active")

    def sync_zone_checkpoints(self) -> None:
        if self.zone_orchestrator is not None:
            self.zone_orchestrator.sync_checkpoints(
                self.checkpoint.state,
                self.checkpoint.phase,
                self.checkpoint.cleanup_state,
                self.checkpoint.error,
            )

    def mark_terminal_state(self, state: str, message: str | None = None) -> None:
        """Stop heartbeats and publish an explicit cloud-visible terminal state."""
        normalized = state.strip().upper()
        self.reporter.logger.heartbeat = None
        self.checkpoint.state = normalized
        self.checkpoint.phase = normalized.lower().replace("_", "-")
        self.checkpoint.error = message
        self.checkpoint.updated_at = iso_utc()
        self.checkpoint.last_activity = self.checkpoint.updated_at
        try:
            self.sync_zone_checkpoints()
            self.state_store.save(self.checkpoint)
        except (OSError, SuiteError):
            pass
        cloud_state = normalized.lower()
        try:
            if self.zone_orchestrator is not None:
                self.zone_orchestrator.update_cloud_heartbeat(cloud_state)
            elif self.builder is not None:
                self.builder.update_cloud_heartbeat(cloud_state)
        except SuiteError as exc:
            self.logger.log(
                f"Could not publish terminal cloud run state {cloud_state}: {exc}",
                "WARNING",
            )

    def _render_plan_output(self) -> None:
        """Render one operator-facing plan view, never two competing views."""

        if self.discovery is None or self.plan is None:
            raise SuiteError("Plan output requested before discovery and planning")
        PlanDiagramRenderer(
            self.config, self.discovery, self.plan, self.logger
        ).render()

    def execute(self) -> int:
        raise_if_cancelled()
        self._preflight_commands()
        if self.config.action == "cleanup":
            return self.cleanup_existing()

        if self.config.action == "run":
            recover_operations(self.osc, self.cloud_operation_coordinator, self.logger)
        inject_failure(self.config, "before-discovery")
        self.discovery = Discoverer(self.osc, self.logger, self.config).discover()
        inject_failure(self.config, "after-discovery")
        if self.config.resume_run_id:
            self._prepare_resume_resources()
            # Discard inventory taken while the old generation consumed quota
            # and held addresses. Planning must use verified post-cleanup facts.
            self.discovery = Discoverer(self.osc, self.logger, self.config).discover()
        self.reporter.discovery = self.discovery
        self.logger.section("Validating requested VM launch inputs")
        self.launch_selection = resolve_launch_selection(
            self.config, self.osc, self.logger
        )
        planner = Planner(self.config, self.discovery, self.logger)
        self.base_plan = planner.build()
        host_qualification = HostQualificationPlanner(
            self.config,
            self.discovery,
            self.base_plan,
            self.osc,
            self.logger,
        ).build()
        if host_qualification is not None:
            self.base_plan.host_qualification = host_qualification
            self.base_plan = expand_pair_suite(self.base_plan, coordinated=True)
            estimate_pair_suite(planner, self.base_plan)
            if not self.config.selective_run:
                self.logger.section("Exact host-pair execution plan")
                planner._print_summary(self.base_plan)
        if not self.config.selective_run:
            validate_launch_selection_quota(
                self.config, self.discovery, self.base_plan, self.launch_selection
            )
        explicit_zones = bool(
            self.config.availability_zones or self.config.availability_zones_all
        )
        if explicit_zones:
            self.zone_plan = ZonePreflight(
                self.config,
                self.discovery,
                self.base_plan,
                self.osc,
                self.reporter,
                self.launch_selection,
            ).build()
            self.plan = aggregate_plan(self.base_plan, self.zone_plan, self.config)
            if not self.config.selective_run:
                self.logger.section("Aggregate availability-zone execution plan")
                planner._print_summary(self.plan)
        else:
            # Preserve the automatic single-AZ execution path, IDs, resource
            # peak, and report structure when the operator did not request
            # explicit zone coverage.
            self.zone_plan = None
            self.plan = self.base_plan
        if self.config.selective_run:
            self.plan = select_plan_tests(
                self.plan,
                self.config.test_ids,
                include_derived=self.config.include_derived_tests,
            )
            if self.zone_plan is not None:
                selected_base_ids = list(
                    dict.fromkeys(
                        str((spec.metadata or {}).get("base_test_id") or spec.id)
                        for spec in self.plan.tests
                        if spec.scenario != "Controller readiness"
                    )
                )
                if selected_base_ids:
                    self.base_plan = select_plan_tests(
                        self.base_plan, selected_base_ids
                    )
                    planner.recalculate(self.base_plan, quota_preflight=False)
            else:
                self.base_plan = self.plan
            if is_pair_suite(self.plan):
                estimate_pair_suite(planner, self.plan)
            else:
                planner.recalculate(self.plan, quota_preflight=True)
            self.logger.section("Exact test execution plan")
            planner._print_summary(self.plan)
            validate_launch_selection_quota(
                self.config, self.discovery, self.plan, self.launch_selection
            )
        self.capabilities = CapabilityPreflight(
            self.config,
            self.discovery,
            self.plan,
            self.osc,
            self.logger,
        ).run()
        self.reporter.capabilities = self.capabilities
        build_check_plan(self.plan, self.config)
        self.plan.estimated["suite_passes"] = self.config.repeat_count
        self.plan.estimated["total_result_rows_all_passes"] = (
            len(self.plan.tests) * self.config.repeat_count
        )
        if self.config.repeat_count > 1:
            self.logger.log(
                f"Requested {self.config.repeat_count} complete suite passes; separate reports and cleanup for each pass"
            )
        current_contract = create_plan_contract(
            self.config,
            self.discovery,
            self.plan,
            self.capabilities,
        )
        approved_path = (
            pathlib.Path(self.checkpoint.plan_path)
            if self.config.resume_run_id and self.checkpoint.plan_path
            else None
        )
        if approved_path is not None:
            approved_contract, approved_plan = load_plan_contract(
                approved_path,
                prefer_runtime_plan=bool(self.config.resume_run_id),
            )
            diff = verify_plan_contract(approved_contract, current_contract)
            if diff:
                self.reporter.plan_contract = approved_contract
                self.reporter.plan_approval = {
                    "verified": False,
                    "source": str(approved_path),
                    "fingerprint": approved_contract.get("fingerprint"),
                    "mode": "resume",
                }
                self.reporter.plan = approved_plan
                self.reporter.save_plan_drift(diff)
                self.reporter.event(
                    "plan-drift-rejected",
                    "Approved plan no longer matches current cloud inventory",
                    changes=len(diff),
                    drift_path=str(self.reporter.plan_drift_path),
                )
                raise SuiteError(
                    "Approved plan drift detected before resource creation "
                    f"({len(diff)} change(s)); exact diff: "
                    f"{self.reporter.plan_drift_path}\n{format_drift(diff)}"
                )
            self.plan = approved_plan
            self.reporter.plan_contract = approved_contract
            self.reporter.plan_approval = {
                "verified": True,
                "source": str(approved_path),
                "fingerprint": approved_contract.get("fingerprint"),
                "mode": "resume",
            }
            self.reporter.event(
                "approved-plan-verified",
                "Approved plan fingerprint and current inventory match",
                fingerprint=approved_contract.get("fingerprint"),
                source=str(approved_path),
                resume=bool(self.config.resume_run_id),
            )
        else:
            self.reporter.plan_contract = current_contract
            self.reporter.plan_approval = {
                "verified": True,
                "source": "generated-this-run",
                "fingerprint": current_contract.get("fingerprint"),
                "mode": "generated",
            }
        inject_failure(self.config, "after-planning")
        self.reporter.plan = self.plan
        self.reporter.save_plan()
        describe_check_plan(self.plan, self.logger)
        self.checkpoint.plan_path = str(self.reporter.plan_path)
        self.checkpoint.pending_test_ids = [
            item.id for item in self.plan.tests if not self.reporter.has_result(item.id)
        ]
        self._save_checkpoint("PLANNED", "planning", None)

        blockers = list((self.capabilities or {}).get("blockers") or [])
        if blockers and self.config.action == "run":
            message = "Capability preflight blocked resource creation: " + ", ".join(
                map(str, blockers)
            )
            self.reporter.record_setup_failure(
                message,
                blockers=blockers,
                capabilities=self.capabilities,
            )
            raise SetupFailureError(message)

        if self.config.action == "plan":
            self._render_plan_output()
            self.reporter.cleanup_summary.update({"attempted": False, "complete": True})
            self._save_checkpoint("COMPLETED", "plan-complete", None)
            return 0

        validate_pair_execution_plan(self.plan)
        self.resources_started = True
        raise_if_cancelled()
        if self.zone_plan is None:
            self.logger.log(
                "Automatic scheduling: journaled and paced cloud operation submissions; "
                "bounded independent lifecycles and probes; exclusive measurement "
                "and disruptive-test windows; elapsed convergence credits settlement"
            )
            self.builder = ResourceBuilder(
                self.config,
                self.discovery,
                self.plan,
                self.osc,
                self.reporter,
                self.tracker,
                launch_selection=self.launch_selection,
                lifecycle_lock=self.lifecycle_lock,
                cloud_operation_coordinator=self.cloud_operation_coordinator,
            )
            self._save_checkpoint("RUNNING", "controller-bootstrap", None)
            self.builder.prepare()
            self.builder.update_cloud_heartbeat("active")
            self._validate_bootstrap_results()
            if is_pair_suite(self.plan):
                run_pair_suite(
                    self.config,
                    self.plan,
                    self.builder,
                    self.reporter,
                    self.cleanup_manager,
                    self.state_store,
                    self.checkpoint,
                )
            else:
                AdaptiveExecutor(
                    self.config,
                    self.plan,
                    self.builder,
                    self.reporter,
                    self.cleanup_manager,
                    self.state_store,
                    self.checkpoint,
                ).run()

        else:
            if not self.base_plan:
                raise SuiteError("Availability-zone base plan was not initialized")
            self.zone_orchestrator = MultiZoneOrchestrator(
                self.config,
                self.discovery,
                self.base_plan,
                self.zone_plan,
                self.reporter,
                self.launch_selection,
                execution_plan=self.plan,
            )
            self._save_checkpoint("RUNNING", "availability-zone-bootstrap", None)
            self.zone_orchestrator.prepare()
            self.zone_orchestrator.update_cloud_heartbeat("active")
            self.zone_orchestrator.run()
        finalize_checks(self.reporter)
        self._save_checkpoint("TESTS_COMPLETE", "tests-complete", None)
        return 0

    def record_cancelled_results(self, reason: str) -> int:
        """Record every unstarted planned check as operator-cancelled.

        Workers may have already recorded genuine PASS/FAIL results or
        dependency-blocked checks before the signal.  Only missing plan rows are
        filled here, preserving those authoritative earlier outcomes.
        """
        if self.plan is None:
            return 0
        recorded = 0
        cancelled_scopes: Counter[str] = Counter()
        for spec in self.plan.tests:
            if self.reporter.has_result(spec.id):
                continue
            metadata = dict(spec.metadata or {})
            source_zone = str(metadata.get("source_availability_zone") or "").strip()
            destination_zone = str(
                metadata.get("destination_availability_zone") or ""
            ).strip()
            scope = str(metadata.get("availability_zone") or "").strip()
            if not scope and (source_zone or destination_zone):
                scope = "cross-zone"
            scope = scope or "run scope"
            self.reporter.result(
                spec.id,
                spec.category,
                "NOT_RUN_CANCELLED",
                f"Run cancelled by operator before this check executed: {reason}",
                family=spec.family,
                expected=spec.expectation,
                observed="not-run",
                authoritative=False,
                details={
                    **metadata,
                    "dependencies": spec.dependencies,
                    "cancelled_by_operator": True,
                    "cancellation_reason": reason,
                    "coverage_outcome": "NEVER_RAN",
                },
                display_name=spec.display_name,
                scenario=spec.scenario,
                emit_console=False,
            )
            recorded += 1
            cancelled_scopes[scope] += 1
        self.checkpoint.completed_test_ids = [
            item.test_id for item in self.reporter.results
        ]
        self.checkpoint.pending_test_ids = []
        self.checkpoint.failed_test_ids = [
            item.test_id
            for item in self.reporter.results
            if grades_execution(item) and item.status in {"FAIL", "ERROR"}
        ]
        self.checkpoint.metadata["cancelled_test_count"] = recorded
        self.checkpoint.metadata["cancelled_test_scopes"] = dict(cancelled_scopes)
        if recorded:
            scope_summary = ", ".join(
                f"{scope}: {count}" for scope, count in sorted(cancelled_scopes.items())
            )
            self.reporter.logger.log(
                f"Cancellation summary: {recorded} planned "
                f"{'validation did' if recorded == 1 else 'validations did'} not "
                "start. Completed results were preserved, and full per-test "
                "cancellation records are retained in the reports. "
                f"Not-run scope: {scope_summary}.",
                "WARNING",
            )
        else:
            self.reporter.logger.log(
                "Cancellation summary: no additional planned validations remained "
                "unstarted; completed results were preserved.",
                "WARNING",
            )
        return recorded

    def cleanup_existing(self) -> int:
        if self.config.cleanup_orphans:
            complete = self.cleanup_manager.cleanup_orphans()
            self.checkpoint.cleanup_state = "COMPLETE" if complete else "INCOMPLETE"
            self._save_checkpoint(
                "COMPLETED" if complete else "CLEANUP_INCOMPLETE",
                "orphan-cleanup",
                None,
            )
            return 0 if complete else 3
        complete = self.cleanup_manager.cleanup(
            run_tag=self.reporter.run_tag,
            name_prefix=self.reporter.name_prefix,
        )
        self.checkpoint.cleanup_state = "COMPLETE" if complete else "INCOMPLETE"
        self._save_checkpoint(
            "COMPLETED" if complete else "CLEANUP_INCOMPLETE",
            "cleanup",
            None,
        )
        return 0 if complete else 3

    def cleanup_if_required(self, successful_execution: bool) -> bool | None:
        # Probe processes are always transient, even when OpenStack resources are
        # intentionally retained for debugging. Close every SSH-held process
        # before deciding whether the cloud resources themselves should remain.
        if self.zone_orchestrator is not None:
            self.zone_orchestrator.stop_all_probes()
        elif self.builder is not None:
            self.builder.stop_all_probes()
        if not self.resources_started:
            return None
        should_cleanup = not self.config.keep_resources and (
            successful_execution or self.config.auto_cleanup_on_failure
        )
        if not should_cleanup:
            self.reporter.cleanup_summary.update(
                {
                    "attempted": False,
                    "complete": None,
                    "leftovers": [
                        f"{item.resource_type}:{item.id}:{item.name}"
                        for item in self.reporter.resources
                        if item.delete_status not in {"deleted", "already-absent"}
                    ],
                }
            )
            self.checkpoint.cleanup_state = "RETAINED"
            self._save_checkpoint("COMPLETED", "resources-retained", None)
            return None
        self.checkpoint.cleanup_state = "RUNNING"
        self._save_checkpoint("CLEANING", "cleanup", None)
        complete = (
            self.zone_orchestrator.cleanup_all()
            if self.zone_orchestrator is not None
            else self.cleanup_manager.cleanup()
        )
        self.checkpoint.cleanup_state = "COMPLETE" if complete else "INCOMPLETE"
        self._save_checkpoint(
            "COMPLETED" if complete else "CLEANUP_INCOMPLETE",
            "cleanup-complete" if complete else "cleanup-incomplete",
            None,
        )
        return complete

    def _validate_bootstrap_results(self) -> None:
        required = ("CONTROL-OBSERVATION-PORTS", "CONTROL-SSH")
        missing = [item for item in required if not self.reporter.has_result(item)]
        if missing:
            raise SuiteError(
                "Controller bootstrap did not record required results: "
                + ", ".join(missing)
            )

    def _prepare_resume_resources(self) -> None:
        """Verify saved identity and current scope before retiring the old run."""
        if not self.checkpoint.plan_path or self.discovery is None:
            raise SetupFailureError(
                "Resume requires a saved plan and current project inventory"
            )
        contract, plan = load_plan_contract(pathlib.Path(self.checkpoint.plan_path))
        approved = contract.get("inventory") or {}
        current = inventory_snapshot(self.discovery, plan)
        if not approved.get("project_id") or not current.get("project_id"):
            raise SetupFailureError("Resume cleanup requires verified project identity")
        fields = ("cloud", "project_id", "network_extensions", "networks")
        changes = drift_diff(
            {key: approved.get(key) for key in fields},
            {key: current.get(key) for key in fields},
            path="inventory",
        )
        if changes:
            raise SetupFailureError(
                "Resume inventory changed before resource reconciliation:\n"
                + format_drift(changes)
            )
        self._cleanup_stale_resume_resources()

    def _cleanup_stale_resume_resources(self) -> None:
        remaining = [
            item
            for item in self.reporter.resources
            if item.delete_status not in {"deleted", "already-absent"}
        ]
        self.logger.section("Reconciling resources left by the interrupted run")
        self.checkpoint.cleanup_state = "RUNNING"
        complete = self.cleanup_manager.cleanup(
            adopt_discovered=True,
            clear_recovery_artifacts=False,
            completion_message=(
                "Resume preflight cleanup complete; rebuilding only resources "
                "needed by unfinished tests"
            ),
        )
        if not complete:
            self.checkpoint.cleanup_state = "INCOMPLETE"
            raise SetupFailureError(
                "Resume is blocked because resources from the interrupted "
                "execution could not be safely reconciled"
            )
        history = dict(self.reporter.cleanup_summary)
        self.reporter.cleanup_summary = {
            "attempted": False,
            "complete": None,
            "deleted": 0,
            "adopted_orphans": 0,
            "leftovers": [],
            "errors": [],
            "resume_preflight": history,
        }
        self.checkpoint.cleanup_state = "NOT_STARTED"
        self.reporter.event(
            "resume-resource-reconciliation",
            "Stale managed resources were deleted before resume",
            resources=len(remaining),
        )

    def _preflight_commands(self) -> None:
        required = ["openstack"]
        if self.config.action == "run":
            required.extend(["ssh", "ssh-keygen"])
        missing = [command for command in required if not shutil.which(command)]
        if missing:
            raise SuiteError(f"Required commands not found: {', '.join(missing)}")
        self.osc.run("token", "issue")

    def _save_checkpoint(
        self, state: str, phase: str, current_batch: str | None
    ) -> None:
        self.checkpoint.state = state
        self.checkpoint.phase = phase
        self.checkpoint.current_batch = current_batch
        self.checkpoint.completed_test_ids = [
            item.test_id for item in self.reporter.results
        ]
        self.checkpoint.failed_test_ids = [
            item.test_id
            for item in self.reporter.results
            if grades_execution(item) and item.status in {"FAIL", "ERROR"}
        ]
        if self.plan:
            completed = set(self.checkpoint.completed_test_ids)
            self.checkpoint.pending_test_ids = [
                item.id for item in self.plan.tests if item.id not in completed
            ]
        self.checkpoint.manifest_path = str(self.reporter.manifest_path)
        self.checkpoint.metadata["test_progress"] = reporter_progress(self.reporter)
        self.checkpoint.report_dir = str(self.reporter.run_dir)
        self.checkpoint.updated_at = iso_utc()
        self.checkpoint.last_activity = self.checkpoint.updated_at
        self.sync_zone_checkpoints()
        self.state_store.save(self.checkpoint)
        if self.builder is not None or self.zone_orchestrator is not None:
            cloud_state = (
                "active"
                if state in {"RUNNING", "PLANNED", "TESTS_COMPLETE", "CLEANING"}
                else state.lower()
            )
            if self.zone_orchestrator is not None:
                self.zone_orchestrator.update_cloud_heartbeat(cloud_state)
            elif self.builder is not None:
                self.builder.update_cloud_heartbeat(cloud_state)
