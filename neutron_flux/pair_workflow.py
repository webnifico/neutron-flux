"""Execute each topology through the requested placements before releasing it."""

from __future__ import annotations

import dataclasses
import hashlib
from collections import defaultdict
from contextlib import nullcontext
from typing import Any

from .cancellation import raise_if_cancelled
from .check_plan import batch_key, migration_baseline_specs, migration_probe_spec
from .engine import TestEngine
from .errors import ControllerUnavailableError, RunCancelledError, SuiteError
from .migration_completion import migration_completion
from .models import Plan, PlannedGroup, TestSpec
from .network_contract import PROVIDER_NETWORK, canonical_group_kind
from .pair_executor import PairScopeExecutor, _remap
from .pair_placement import PairPlacementMixin
from .performance import PerformanceSession


def coordinate_pair_plan(plan: Plan) -> Plan:
    """Share topology identities and reserve exactly one opposite-relation transition."""
    if not plan.host_qualification or any(
        s.metadata.get("coordinated_pair") for s in plan.tests
    ):
        return plan
    if any(
        spec.metadata.get("pair_scope_id")
        and (
            spec.metadata.get("pair_placement_policy") != "initial-opposite-v1"
            or spec.metadata.get("pair_placement") not in {"initial", "opposite"}
        )
        for spec in plan.tests
    ):
        raise SuiteError(
            "Legacy placement expansion requires a fresh two-placement plan"
        )
    group_map = {}
    for group in plan.groups:
        meta = group.metadata
        identity = f"{meta['host_qualification_pair_id']}:{meta['host_qualification_cycle']}:{meta['base_group_id']}"
        group_map[group.id] = (
            f"{meta['base_group_id']}@workflow-{hashlib.sha256(identity.encode()).hexdigest()[:16]}"
        )
    providers: dict[str, PlannedGroup] = {}
    tenants: dict[str, PlannedGroup] = {}
    for group in plan.groups:
        target = providers if group in plan.provider_groups else tenants
        target.setdefault(
            group_map[group.id],
            dataclasses.replace(
                group,
                id=group_map[group.id],
                metadata=_remap(group.metadata, group_map),
            ),
        )
    batches: dict[tuple[Any, ...], dict[str, list[TestSpec]]] = defaultdict(
        lambda: defaultdict(list)
    )
    controls = []
    for spec in plan.tests:
        if not spec.metadata.get("pair_scope_id"):
            controls.append(spec)
            continue
        clone = dataclasses.replace(
            spec,
            # Egress uses one endpoint of the existing local topology. Keeping
            # it in a separate cross batch would create a one-VM "host pair".
            phase="intra"
            if spec.operation == "egress" and len(spec.dependencies) == 1
            else spec.phase,
            dependencies=_remap(spec.dependencies, group_map),
            source_group_id=group_map.get(spec.source_group_id, spec.source_group_id)
            if spec.source_group_id is not None
            else None,
            destination_group_id=group_map.get(
                spec.destination_group_id, spec.destination_group_id
            )
            if spec.destination_group_id is not None
            else None,
            metadata={**_remap(spec.metadata, group_map), "coordinated_pair": True},
        )
        # Join initial/opposite slots before adding their placement scope, while
        # retaining topology state such as a source without a floating IP.
        key = batch_key(
            dataclasses.replace(
                clone,
                metadata={**clone.metadata, "coordinated_pair": False},
            )
        )
        batches[key][clone.metadata["pair_placement"]].append(clone)
    tests = list(controls)
    for key, placements in batches.items():
        token = hashlib.sha256(repr(key).encode()).hexdigest()[:16]
        previous = None
        previous_specs: list[TestSpec] = []
        for placement in ("initial", "opposite"):
            specs = placements.get(placement, [])
            if not specs:
                continue
            for spec in specs:
                spec.metadata["workflow_batch"] = token
                spec.metadata["placement_origin"] = (
                    "initial-boot" if previous is None else "after-transition"
                )
            if previous is not None:
                tests.append(
                    TestSpec(
                        id=f"PAIR-TRANSITION-{token}-{placement}",
                        category="compute-placement",
                        operation="pair-transition",
                        family=None,
                        expectation="requested-placement-verified",
                        expectation_reason="The next placement must be verified before its checks run",
                        authoritative=True,
                        dependencies=list(specs[0].dependencies),
                        phase="placement",
                        requires=[
                            s.id for s in migration_baseline_specs(previous_specs)
                        ],
                        display_name="Move one endpoint and verify the opposite compute placement",
                        scenario="Host-pair placement transition",
                        metadata={
                            **{
                                k: v
                                for k, v in specs[0].metadata.items()
                                if k != "base_test_id"
                            },
                            "transition_from": previous,
                            "workflow_phase": specs[0].phase,
                            "workflow_sides": dict(key[2]) if key[0] != "intra" else {},
                        },
                    )
                )
            tests.extend(specs)
            previous = placement
            previous_specs = specs
    return dataclasses.replace(
        plan,
        provider_groups=list(providers.values()),
        tenant_groups=list(tenants.values()),
        tests=tests,
        warnings=[
            text
            for text in plan.warnings
            if not text.startswith("Host selectors constrain")
        ]
        + [
            "Each topology tests its verified initial placement, then moves one endpoint "
            "to the opposite relation and tests again: intra → inter or inter → intra. "
            "No third placement or return trip is planned. Host selectors still constrain "
            "initial provisioning. Transitions use the configured migration strategy "
            "when eligible; otherwise one endpoint is recreated, never claimed as a "
            "migration. Checks and conditional performance work are reserved up front."
        ],
    )


def workflow_plans(plan: Plan) -> list[Plan]:
    batches: dict[str, list[TestSpec]] = defaultdict(list)
    for spec in plan.tests:
        if spec.metadata.get("workflow_batch"):
            batches[spec.metadata["workflow_batch"]].append(spec)
    providers = {group.id: group for group in plan.provider_groups}
    tenants = {group.id: group for group in plan.tenant_groups}
    provider_order = {
        group.id: index for index, group in enumerate(plan.provider_groups)
    }
    tenant_order = {group.id: index for index, group in enumerate(plan.tenant_groups)}
    output = []
    for specs in batches.values():
        dependencies = {group_id for spec in specs for group_id in spec.dependencies}
        output.append(
            dataclasses.replace(
                plan,
                tests=specs,
                provider_groups=[
                    providers[group_id]
                    for group_id in sorted(
                        dependencies & providers.keys(), key=provider_order.__getitem__
                    )
                ],
                tenant_groups=[
                    tenants[group_id]
                    for group_id in sorted(
                        dependencies & tenants.keys(), key=tenant_order.__getitem__
                    )
                ],
            )
        )
    return output


class CoordinatedPairExecutor(PairPlacementMixin, PairScopeExecutor):
    """One topology lifetime, with a verified boundary between placements."""

    def _retain_provider_endpoint(self) -> bool:
        group_id = getattr(self, "handoff_group_id", None)
        if (
            not group_id
            or group_id not in self.active
            or getattr(self, "_post_transition_read_only", False)
        ):
            return False
        runtime = self.active[group_id]
        endpoint = runtime.endpoint("A")
        coordinator = getattr(self.builder, "cloud_operation_coordinator", None)
        if (
            canonical_group_kind(runtime.plan.kind) != PROVIDER_NETWORK
            or runtime.router_id
            or runtime.fips
            or runtime.metadata.get("pending_floating_ips")
            or endpoint is None
            or coordinator is None
            or not callable(getattr(coordinator, "cloud_operation_summary", None))
        ):
            return False
        if any(
            result is None or result.status != "PASS"
            for result in (
                self.reporter.get_result(spec.id) for spec in self.plan.tests
            )
        ):
            return False
        summary = coordinator.cloud_operation_summary()
        if (
            summary.get("unresolved_count")
            or summary.get("quarantined_resources")
            or summary.get("quarantined_hosts")
        ):
            return False
        service = getattr(self.builder, "probe_service", None)
        readback = getattr(self.builder, "_stable_existing_probe_service", None)
        if (
            service is None
            or not service.is_running(endpoint)
            or not callable(readback)
        ):
            return False
        readback_stage = "placement"
        try:
            self._verify_runtime(runtime)
            readback_stage = "probe-service"
            ready, _evidence = readback(endpoint)
        except (RunCancelledError, ControllerUnavailableError):
            raise
        except SuiteError as exc:
            self.reporter.event(
                "provider-endpoint-reuse-declined",
                "Provider endpoint reuse was declined because its final readback "
                "could not be verified; releasing this topology before the next lifetime",
                group_id=group_id,
                readback_stage=readback_stage,
                reason=str(exc),
            )
            return False
        if not ready:
            return False
        # Delete the previous peer before another lifetime can provision its peer.
        # Terminal successful migrations remain valid: the next initial stage uses
        # fresh actual placement rather than returning this endpoint to a hint.
        for other_id in list(self.active):
            if other_id != group_id:
                self._release(other_id)
        for other in list(runtime.endpoints):
            if other is endpoint:
                continue
            self.builder.stop_endpoint_probe(other)
            if not self.cleanup_manager.cleanup_group_side(group_id, other.side):
                self._record_unresolved_group(group_id)
                raise SuiteError(
                    f"Could not release provider handoff peer {group_id}:{other.side}"
                )
            runtime.endpoints.remove(other)
        self.builder.runtime_groups = [runtime]
        self._refresh_checkpoint()
        self.reporter.event(
            "provider-endpoint-retained",
            "Retained one verified provider endpoint for the next independent topology lifetime",
            group_id=group_id,
            server_id=endpoint.server_id,
            observed_host=endpoint.host,
        )
        return True

    def prepare_resume(self) -> None:
        if not self.config.resume_run_id:
            return
        originals = [
            s
            for s in self.plan.tests
            if not s.metadata.get("supplemental")
            and not s.metadata.get("resume_recheck")
        ]
        if not any(self.reporter.has_result(s.id) for s in originals):
            return
        attempt = 1
        known = {s.id for s in self.reporter.plan.tests}
        while any(f"{s.id}-RESUME-{attempt}" in known for s in originals):
            attempt += 1
        mapping = {
            s.id: f"{s.id}-RESUME-{attempt}" if self.reporter.has_result(s.id) else s.id
            for s in originals
        }
        replay = [
            dataclasses.replace(
                s,
                id=mapping[s.id],
                requires=[mapping.get(i, i) for i in s.requires],
                requires_pass=[mapping.get(i, i) for i in s.requires_pass],
                metadata={**s.metadata, "resume_recheck": True, "source_spec_id": s.id},
            )
            for s in originals
        ]
        stale = [
            s
            for s in self.plan.tests
            if (s.metadata.get("supplemental") or s.metadata.get("resume_recheck"))
            and not self.reporter.has_result(s.id)
        ]
        for spec in stale:
            spec.metadata["check_sample"] = True
        self.reporter.save_plan()
        self._mark_specs_unavailable(
            stale,
            "Interrupted observation belongs to the previous VM generation; the same planned checks are reassessed on fresh resources",
            blocked=True,
        )
        self._append_runtime_specs([s for s in replay if s.id not in known])
        self.plan.tests = replay
        self._refresh_checkpoint()

    def _placement_control_spec(self, *args: Any, **kwargs: Any) -> TestSpec:
        spec = super()._placement_control_spec(*args, **kwargs)
        spec.metadata.update(
            planned_check_id=self.transition.metadata.get(
                "planned_check_id", self.transition.id
            ),
            check_sample=True,
        )
        return spec

    def _compute_migration_attempts(
        self,
        source: Any,
        destination: Any,
        *,
        desired_relation: str,
        maximum_attempts: int | None = None,
    ) -> tuple[list[Any], str]:
        targets, reason = self._select_migration_targets(
            destination, source, desired_relation=desired_relation
        )
        exact = [
            (destination, source, target)
            for target in targets
            if target.host == self.target_host
        ]
        return (
            exact,
            reason
            if exact
            else f"Requested target {self.target_host} is not an eligible migration destination",
        )

    def _rotate(self, group_id: str, endpoint: Any) -> None:
        runtime = self.active[group_id]
        self.builder.stop_endpoint_probe(endpoint)
        if not self.cleanup_manager.cleanup_group_side(group_id, endpoint.side):
            self._record_unresolved_group(group_id)
            raise SuiteError(f"Could not release endpoint {group_id}:{endpoint.side}")
        runtime.fips.pop(endpoint.label, None)
        runtime.metadata.get("pending_floating_ips", {}).pop(endpoint.label, None)
        runtime.endpoints.remove(endpoint)
        self.builder.build_group_side(
            runtime,
            self.groups[group_id],
            endpoint.side,
        )
        self._refresh_checkpoint()

    def _transition(
        self, spec: TestSpec, previous: list[TestSpec], engine: TestEngine
    ) -> bool:
        self.transition = spec
        self._placement_workflow_id = spec.id
        self._post_transition_read_only = False
        dependencies = tuple(spec.dependencies)
        before = [(g, e, e.host) for g, r in self.active.items() for e in r.endpoints]
        changes = [
            (g, e)
            for g, e, host in before
            if host != self.groups[g].metadata["target_hosts"].get(e.side)
        ]
        if len(before) != 2 or len(changes) != 1:
            raise SuiteError(
                "The opposite-placement transition must move exactly one of two endpoint VMs"
            )
        desired_hosts = [
            self.groups[g].metadata["target_hosts"][e.side] for g, e, _ in before
        ]
        if (before[0][2] == before[1][2]) == (desired_hosts[0] == desired_hosts[1]):
            raise SuiteError("Transition does not change intra/inter compute relation")
        evidence: dict[str, Any] = {
            "planned_endpoint_transitions": 1,
            "initial_hosts": [host for _, _, host in before],
            "requested_final_hosts": desired_hosts,
            "from": spec.metadata["transition_from"],
            "to": spec.metadata["pair_placement"],
            "transitions": [],
        }
        eligible = (
            self.config.compute_host_connectivity_enabled
            and self.scope["qualification_strategy"] != "stable"
            and self.scope["qualification_profile"] != "connectivity"
        )
        migration_protocols = {s.protocol for s in migration_baseline_specs(previous)}
        if not {"icmp", "tcp", "udp"} <= migration_protocols:
            eligible = False
            evidence["migration_not_applicable"] = (
                "This topology has no complete authoritative reachable ICMP/TCP/UDP baseline; placement coverage uses endpoint recreation"
            )
        status = "PASS"
        for group_id, moving, source_host in before:
            group = self.groups[group_id]
            target_host = group.metadata["target_hosts"][moving.side]
            if source_host == target_host:
                continue
            peer = next((e for _, e, _ in before if e is not moving), None)
            same_zone = (
                moving.availability_zone
                == group.metadata["target_availability_zones"][moving.side]
            )
            if not eligible or not same_zone or peer is None:
                self._rotate(group_id, moving)
                evidence["transitions"].append(
                    {
                        "method": "endpoint-recreation",
                        "source_host": source_host,
                        "destination_host": target_host,
                    }
                )
                continue
            self.target_host = target_host
            self._placement_check_bindings = {
                "MIGRATION-FUNCTIONAL-BASELINE": spec.metadata.get(
                    "planned_check_id", spec.id
                )
            }
            relation = "same" if peer.host == target_host else "different"
            coordinator = getattr(self.builder, "cloud_operation_coordinator", None)
            transaction = (
                coordinator.transaction(
                    "migration",
                    spec.display_name,
                    resource_ids=[moving.server_id, peer.server_id],
                    source_host=source_host,
                    destination_host=target_host,
                    availability_zone=moving.availability_zone,
                    max_attempts=self.config.migration_submission_budget,
                    conflicts=("all-cloud-operations",),
                    final_cooldown=5.0,
                )
                if coordinator
                else nullcontext()
            )
            with self.performance_lock, transaction:
                result = self._attempt_configured_migration(
                    dependencies=dependencies,
                    source=peer,
                    destination=moving,
                    current_relation="intra-compute"
                    if peer.host == moving.host
                    else "inter-compute",
                    desired_relation=relation,
                    desired_label=spec.metadata["pair_placement"],
                    pre_submission_barrier=lambda number, kind, endpoint, stationary, target: (
                        self._pre_migration_functional_barrier(
                            previous,
                            engine,
                            dependencies=dependencies,
                            source=stationary,
                            destination=endpoint,
                            current_relation="intra-compute"
                            if stationary.host == endpoint.host
                            else "inter-compute",
                            submission_number=number,
                            migration_kind=kind,
                        )
                    ),
                )
            migration = result[1] if result else None
            if migration is None:
                evidence["transitions"].append(
                    {
                        "source_host": source_host,
                        "destination_host": target_host,
                        "attempts": result[3] if result else [],
                        "error": result[7]
                        if result
                        else "Requested migration is unavailable",
                    }
                )
                status = "ERROR" if result and result[7] else "UNVERIFIED"
                if result and not self.reporter.has_result(result[0].id):
                    lifecycle = result[0]
                    self.reporter.result(
                        lifecycle.id,
                        lifecycle.category,
                        status,
                        str(result[7] or "Migration was not completed"),
                        expected=lifecycle.expectation,
                        observed="placement-unavailable",
                        authoritative=False,
                        display_name=lifecycle.display_name,
                        scenario=lifecycle.scenario,
                    )
                break
            observed = dataclasses.asdict(migration)
            evidence["transitions"].append(observed)
            observed["completion_assessment"] = migration_completion(observed)
            status = observed["completion_assessment"]["status"]
            if (
                migration.details.get("migration_mode") == "live"
                and self.config.live_migration_continuity
            ):
                continuity_status, _, continuity_message, details = (
                    self._live_continuity_verdict(
                        migration.details.get("continuity") or {}
                    )
                )
                observed["continuity_assessment"] = details
                observed["continuity_message"] = continuity_message
                if continuity_status == "FAIL" or (
                    continuity_status == "UNVERIFIED" and status == "PASS"
                ):
                    status = continuity_status
            if result:
                lifecycle = result[0]
                self.reporter.result(
                    lifecycle.id,
                    lifecycle.category,
                    status,
                    observed.get("continuity_message")
                    or "Migration identity, readiness and placement evidence belongs to the planned transition",
                    expected=lifecycle.expectation,
                    observed="migration-assessed",
                    authoritative=True,
                    details={
                        "transition_check_id": spec.metadata.get(
                            "planned_check_id", spec.id
                        ),
                        **(
                            {"continuity": observed["continuity_assessment"]}
                            if observed.get("continuity_assessment") is not None
                            else {}
                        ),
                    },
                    display_name=lifecycle.display_name,
                    scenario=lifecycle.scenario,
                )
            if result and result[5]:
                evidence["cold_fallback_used"] = True
                # A successful cold fallback does not qualify live migration.
                if status == "PASS":
                    status = "UNVERIFIED"
        achieved = all(
            e.host == self.groups[g].metadata["target_hosts"][e.side]
            for g, r in self.active.items()
            for e in r.endpoints
        )
        if achieved:
            for runtime in self.active.values():
                self._verify_runtime(runtime)
        self.reporter.result(
            spec.id,
            spec.category,
            status if achieved else ("ERROR" if status == "PASS" else status),
            f"{spec.display_name}: {'placement verified' if achieved else 'requested placement not achieved'}"
            + "".join(
                f"; {item.get('continuity_message') or item.get('error')}"
                for item in evidence["transitions"]
                if item.get("continuity_message") or item.get("error")
            ),
            expected=spec.expectation,
            observed="requested-placement-verified"
            if achieved
            else "placement-unavailable",
            authoritative=True,
            details=evidence,
            display_name=spec.display_name,
            scenario=spec.scenario,
        )
        if achieved:
            moves = evidence["transitions"]
            recreation = bool(moves) and all(
                item.get("method") == "endpoint-recreation" for item in moves
            )
            modes = {
                str((item.get("details") or {}).get("migration_mode") or "")
                for item in moves
                if item.get("method") != "endpoint-recreation"
            }
            self._completed_execution_stage = (
                "post-endpoint-recreation"
                if recreation
                else f"post-{next(iter(modes))}-migration"
                if len(modes) == 1 and modes <= {"live", "cold"}
                else "post-migration"
            )
        # Guest probe recovery does not replace independent packet outcomes.
        # A proved terminal move with unchanged identity/ownership permits
        # readback only; uncertainty in those prerequisites still blocks work.
        safe = all(
            item.get("method") == "endpoint-recreation"
            or migration_completion({**item, "endpoint_ready": True})["verified"]
            is True
            for item in evidence["transitions"]
        )
        self._post_transition_read_only = safe and any(
            item.get("endpoint_ready") is not True
            for item in evidence["transitions"]
            if item.get("method") != "endpoint-recreation"
        )
        return achieved and safe and status != "ERROR"

    def run(self) -> None:
        self.prepare_resume()
        completed = False
        placements: dict[str, list[TestSpec]] = defaultdict(list)
        transitions = []
        for spec in list(self.plan.tests):
            if spec.metadata.get("supplemental"):
                continue
            if spec.operation == "pair-transition":
                transitions.append(spec)
            else:
                placements[spec.metadata["pair_placement"]].append(spec)
        if set(placements) - {"initial", "opposite"} or len(transitions) > 1:
            raise SuiteError(
                "Unsupported placement plan; start a fresh two-placement run"
            )
        transition = transitions[0] if transitions else None
        initial = placements.get("initial", [])
        opposite = placements.get("opposite", [])
        anchor = next(iter(initial or opposite or transitions), None)
        if anchor is None:
            return
        dependencies = tuple(anchor.dependencies)
        phase = anchor.metadata.get("workflow_phase", anchor.phase)
        sides = (
            {g: ("A", "B") for g in dependencies}
            if phase == "intra"
            else anchor.metadata.get("workflow_sides") or dict(batch_key(anchor)[2])
        )
        try:
            raise_if_cancelled()
            if not self.scope["pair_scope_eligible"]:
                self._mark_specs_unavailable(
                    self.plan.tests,
                    " | ".join(self.scope["pair_scope_blockers"]),
                    blocked=True,
                )
                return
            # Initial creation respects host hints. Accept a verified in-scope
            # topology where it is, without normalizing it through a migration.
            self.scope.update(pair_placement="initial")
            self._ensure(dependencies, required_sides=sides)
            if any(g not in self.active for g in dependencies):
                self._mark_specs_unavailable(
                    initial or opposite,
                    " | ".join(
                        self.builder.group_failure_reason(g) or "Topology unavailable"
                        for g in dependencies
                        if g not in self.active
                    ),
                    setup_error=True,
                )
                self._mark_specs_unavailable(
                    ([transition] if transition else [])
                    + (opposite if initial else []),
                    "Initial topology was unavailable; no placement transition was submitted",
                    blocked=True,
                )
                return
            try:
                members = self._ordered_pair_endpoints(dependencies, sides)
            except SuiteError as exc:
                self._mark_specs_unavailable(
                    initial or opposite, str(exc), setup_error=True
                )
                self._mark_specs_unavailable(
                    ([transition] if transition else [])
                    + (opposite if initial else []),
                    "Initial placement could not be verified",
                    blocked=True,
                )
                return
            self._bind_pair_stage(initial or opposite, members)
            if not initial:
                # Historical selective execution of a single slot is read-only.
                # It supplies no evidence of a transition or the other relation.
                self._run_pair_stage(opposite, phase)
                if transition:
                    self._mark_specs_unavailable(
                        [transition], "No initial baseline was selected", blocked=True
                    )
                return
            engine = self._run_pair_stage(initial, phase)
            self._refresh_checkpoint()
            if not opposite and transition is None:
                return  # Explicit single-host scope: only intra is possible.
            if transition is None:
                self._mark_specs_unavailable(
                    opposite,
                    "Opposite placement requires its planned transition",
                    blocked=True,
                )
                return
            raise_if_cancelled()
            self._prepare_opposite_placement(opposite, transition, members)
            try:
                ready = self._transition(transition, initial, engine)
            except RunCancelledError:
                raise
            except SuiteError as exc:
                ready = False
                if not self.reporter.has_result(transition.id):
                    self.reporter.result(
                        transition.id,
                        transition.category,
                        "ERROR",
                        str(exc),
                        expected=transition.expectation,
                        observed="transition-execution-error",
                        authoritative=False,
                        details={
                            "tool_failure": True,
                            "failure_phase": "placement-transition",
                        },
                        display_name=transition.display_name,
                        scenario=transition.scenario,
                    )
            if not ready:
                self._mark_specs_unavailable(
                    opposite,
                    "The single transition did not achieve safe, verified opposite placement",
                    blocked=True,
                )
                return  # Never bootstrap a third stage after a failed move.
            self._bind_pair_stage(
                opposite, self._ordered_pair_endpoints(dependencies, sides)
            )
            self._run_pair_stage(
                opposite,
                phase,
                read_only=getattr(self, "_post_transition_read_only", False),
            )
            self._refresh_checkpoint()
            completed = True
        finally:
            retained = False
            try:
                if completed:
                    retained = self._retain_provider_endpoint()
            finally:
                if not retained:
                    self._release_all()
            # The outer cancellation machinery owns interrupted outcomes.
        self._fill_unavailable_results()

    def _run_pair_stage(
        self, specs: list[TestSpec], phase: str, *, read_only: bool = False
    ) -> TestEngine:
        sessions = getattr(self, "performance_sessions", {})
        self.performance_session = sessions.setdefault(
            self.scope["pair_scope_id"], PerformanceSession()
        )
        self.performance_sessions = sessions
        self.logger.section(
            f"{self.scope['requested_source_host']} ↔ {self.scope['requested_destination_host']} · "
            f"{self.scope['pair_placement']} · {self.scope.get('pair_observed_placement', 'unverified')} · "
            f"cycle {self.scope['host_qualification_cycle']}"
        )
        self.builder.runtime_groups = list(self.active.values())
        engine = TestEngine(
            self.config, self.builder.discovery, self.builder, self.reporter
        )
        if self.scope["pair_placement"] == "opposite":
            engine.execution_stage_override = getattr(
                self, "_completed_execution_stage", "initial-testing"
            )
        elif any(spec.operation == "pair-transition" for spec in self.plan.tests):
            complete_protocols = {s.protocol for s in migration_baseline_specs(specs)}
            recreation = (
                not self.config.compute_host_connectivity_enabled
                or self.scope["qualification_strategy"] == "stable"
                or self.scope["qualification_profile"] == "connectivity"
                or self.scope.get("same_availability_zone") is False
                or not {"icmp", "tcp", "udp"} <= complete_protocols
            )
            engine.execution_stage_override = (
                "pre-endpoint-recreation" if recreation else "pre-migration"
            )
        else:
            engine.execution_stage_override = "initial-testing"
        engine.post_migration_read_only = read_only
        if read_only:
            readback = [
                migration_probe_spec(spec)
                for spec in specs
                if spec.operation
                in {
                    "probe",
                    "mtu-scenario",
                    "egress",
                    "fip-peer",
                    "fip-baseline",
                    "fip-egress-source-address",
                    "fip-egress-mtu",
                    "fip-egress-fragmentation",
                    "static-route-install",
                }
                and not spec.metadata.get("server_start_recovery")
            ]
            selected_ids = {spec.id for spec in readback}
            for spec in specs:
                if spec.id in selected_ids or self.reporter.has_result(spec.id):
                    continue
                self.reporter.result(
                    spec.id,
                    spec.category,
                    "BLOCKED_BY_PREREQUISITE",
                    "The migration's guest probe recovery failed; independent packet readback is attempted, but lifecycle writes and load work require a healthy endpoint",
                    family=spec.family,
                    expected=spec.expectation,
                    observed="migration-recovery-prerequisite-failed",
                    authoritative=False,
                    display_name=spec.display_name,
                    scenario=spec.scenario,
                    details={
                        "cloud_operation_performed": False,
                        "post_migration_read_only": True,
                    },
                )
            engine.run_specs(readback)
            return engine
        baseline = [
            s
            for s in specs
            if s.operation in {"probe", "mtu-scenario"}
            and not s.requires
            and not s.requires_pass
        ]
        stage = "group-local" if phase == "intra" else "cross-topology"
        engine.run_specs(baseline)
        self._run_performance(baseline, engine, stage=stage)
        engine.run_specs([s for s in specs if s not in baseline])
        self._run_performance(specs, engine, stage=stage)
        return engine


def estimate_coordinated_pair_suite(planner: Any, plan: Plan) -> None:
    """Budget the materialized topology lifetimes, including conditional transitions."""
    estimates = []
    migrations = rotations = 0
    for lane in workflow_plans(plan):
        specs = [s for s in lane.tests if s.operation != "pair-transition"]
        first_scope = specs[0].metadata["pair_scope_id"]
        first = [s for s in specs if s.metadata["pair_scope_id"] == first_scope]
        lane_planner = type(planner)(
            dataclasses.replace(
                planner.config,
                fabric_scale_enabled=False,
                performance_enabled=planner.config.performance_enabled
                and specs[0].metadata["qualification_profile"] != "connectivity",
            ),
            planner.discovery,
            planner.logger,
        )
        estimate = lane_planner._estimate_plan(
            lane.provider_groups, lane.tenant_groups, first
        )
        full = lane_planner._estimate_plan(
            lane.provider_groups, lane.tenant_groups, specs
        )
        performance = {
            key: value
            for key, value in full.items()
            if key.startswith("performance_") or key == "floating_ip_performance_paths"
        }
        estimate.update(performance)
        estimate["functional_test_results"] = len(lane.tests)
        estimate["test_results"] = len(lane.tests)
        estimate["estimated_result_rows"] = (
            len(lane.tests) + performance["performance_result_rows"]
        )
        transitions = [s for s in lane.tests if s.operation == "pair-transition"]
        metadata = specs[0].metadata
        migrate = (
            planner.config.compute_host_connectivity_enabled
            and metadata["qualification_profile"] != "connectivity"
            and metadata["qualification_strategy"] != "stable"
            and {"icmp", "tcp", "udp"}
            <= {s.protocol for s in migration_baseline_specs(first)}
        )
        pair_zones = (
            {g.host: g.availability_zone for g in plan.host_qualification.hosts}
            if plan.host_qualification
            else {}
        )
        same_zone = pair_zones.get(metadata["requested_source_host"]) == pair_zones.get(
            metadata["requested_destination_host"]
        )
        if migrate and same_zone:
            migrations += len(transitions)
        else:
            rotations += len(transitions)
            estimate["endpoint_vm_boots"] += len(transitions)
        # Floating-IP lifecycle is assessed in every placement on the retained topology.
        estimate["floating_ips_created"] = 1 + (
            estimate["floating_ips_created"] - 1
        ) * len({s.metadata["pair_scope_id"] for s in specs})
        estimates.append(estimate)
    if not estimates:
        planner.recalculate(plan)
        return
    fixed = {
        "security_groups_created",
        "security_group_rules_peak",
        "concurrent_load_pairs",
        "performance_topology_classes",
    }
    plan.estimated = {
        key: (
            max if key.startswith(("peak_", "normal_peak_")) or key in fixed else sum
        )(row.get(key, 0) for row in estimates)
        for key in estimates[0]
    }
    for key in ("networks_created", "subnets_created", "floating_ips_created"):
        plan.estimated[key] -= len(estimates) - 1
    controls = sum(s.scenario == "Controller readiness" for s in plan.tests)
    for key in ("functional_test_results", "test_results", "estimated_result_rows"):
        plan.estimated[key] += controls
    plan.estimated.update(
        topology_lifetimes=len(estimates),
        targeted_migrations_maximum=migrations,
        endpoint_recreations=rotations,
        host_pair_placement_suites=len(
            {
                s.metadata.get("pair_scope_id")
                for s in plan.tests
                if s.metadata.get("pair_scope_id")
            }
        ),
        # Failed migration recovery can require fresh setup; this is a bound, not extra checks.
        endpoint_vm_boots_maximum=plan.estimated["endpoint_vm_boots"] + migrations * 2,
    )
    all_specs = [
        s
        for s in plan.tests
        if s.metadata.get("qualification_profile") != "connectivity"
    ]
    all_performance = planner._performance_estimate(
        [] if planner.config.derived_tests_suppressed else all_specs
    )
    plan.estimated.update(
        {
            key: value
            for key, value in all_performance.items()
            if key.startswith("performance_") or key == "floating_ip_performance_paths"
        }
    )
    plan.estimated["estimated_result_rows"] = (
        len(plan.tests) + plan.estimated["performance_result_rows"]
    )
    if planner.config.fabric_scale_enabled and not planner.config.selective_run:
        # Each topology lifetime was budgeted above. Only the optional load
        # phase's peak reservation remains; do not simulate an unrelated global
        # adaptive workflow over every expanded host-pair specification.
        load_estimate = planner._estimate_plan(
            plan.provider_groups, plan.tenant_groups, []
        )
        load_scopes = len(
            {
                s.metadata["pair_scope_id"]
                for s in all_specs
                if s.metadata.get("pair_scope_id")
            }
        )
        pairs = max(planner.config.fabric_scale_pairs)
        extra = pairs * 2 * load_scopes
        plan.estimated["endpoint_vm_boots"] += extra
        plan.estimated["endpoint_vm_boots_maximum"] += extra
        plan.estimated["concurrent_load_endpoint_boots"] = extra
        for key in ("networks_created", "subnets_created", "routers_created"):
            plan.estimated[key] += pairs * load_scopes
        for key, value in load_estimate.items():
            if key.startswith("peak_"):
                plan.estimated[key] = max(plan.estimated[key], value)
    if plan.host_qualification:
        plan.host_qualification.estimates.update(plan.estimated)
    if not planner.config.selective_run or plan.selection_mode == "exact":
        planner._quota_preflight(plan)
