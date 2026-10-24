from __future__ import annotations

import dataclasses
import hashlib

# mypy: disable-error-code="attr-defined"
from ..check_ledger import check_ledger, finish_checks, resolve_checks
from ..check_plan import (
    migration_batch_eligible,
    migration_probe_spec,
    migration_readback_specs,
)
from ..engine import TestEngine
from ..migration_completion import migration_completion
from ..models import ComputeHostInfo, Endpoint, TestSpec
from ..utils import safe_name
from .placement_migration import PlacementMigrationMixin


class PlacementValidationMixin(PlacementMigrationMixin):
    """Compute-placement and migration validation workflow."""

    @staticmethod
    def _placement_relation(source: Endpoint, destination: Endpoint) -> str | None:
        if not source.host or not destination.host:
            return None
        return "intra-compute" if source.host == destination.host else "inter-compute"

    def _placement_endpoints(
        self,
        dependencies: tuple[str, ...],
        specs: list[TestSpec] | None = None,
    ) -> tuple[Endpoint, Endpoint] | None:
        if len(dependencies) == 1:
            runtime = self.active.get(dependencies[0])
            if not runtime:
                return None
            # Side A is the stationary anchor for every ordinary placement
            # scenario. Side B is the sole migration subject.
            source = runtime.endpoint("A")
            destination = runtime.endpoint("B")
            return (source, destination) if source and destination else None
        if len(dependencies) == 2:
            first = self.active.get(dependencies[0])
            second = self.active.get(dependencies[1])
            if not first or not second:
                return None
            # Cross-group/cross-AZ batches are read-only placement coverage.
            source = first.endpoint("A")
            destination = second.endpoint("A")
            return (source, destination) if source and destination else None
        return None

    def _placement_probe_specs(
        self,
        specs: list[TestSpec],
        *,
        relation: str,
        source: Endpoint,
        destination: Endpoint,
        execution_stage: str = "post-migration",
    ) -> list[TestSpec]:
        suffix = "INTRA" if relation == "intra-compute" else "INTER"
        scenario = (
            "Intra-compute connectivity"
            if relation == "intra-compute"
            else "Inter-compute connectivity"
        )
        dependency_ids = sorted(
            {dependency for spec in specs for dependency in spec.dependencies}
        )
        runtime_token = self._placement_identity_token(
            *dependency_ids,
            source.server_id,
            destination.server_id,
            getattr(self, "_placement_workflow_id", ""),
        )
        output: list[TestSpec] = []
        for spec in migration_readback_specs(specs):
            probe_spec = migration_probe_spec(spec)
            active = getattr(self, "active", {})
            source_group = active.get(spec.source_group_id)
            destination_group = active.get(spec.destination_group_id)
            probe_source = (
                source_group.endpoint(spec.source_side) if source_group else None
            ) or source
            probe_destination = (
                destination_group.endpoint(spec.destination_side)
                if destination_group
                else None
            ) or destination
            hosts = (
                f"[{probe_source.host or 'unknown'}]"
                if spec.operation == "egress"
                else f"[{probe_source.host or 'unknown'} -> {probe_destination.host or 'unknown'}]"
            )
            clone = dataclasses.replace(
                probe_spec,
                id=f"{spec.id}-PLACEMENT-{suffix}-{runtime_token}",
                phase="placement",
                display_name=(
                    f"{probe_spec.display_name or spec.id} — {relation} {hosts}"
                ),
                scenario=scenario,
                metadata={
                    **spec.metadata,
                    "supplemental": True,
                    **(
                        {
                            "planned_check_id": spec.metadata["check_bindings"][
                                "post-migration"
                            ]
                        }
                        if spec.metadata.get("check_bindings", {}).get("post-migration")
                        else {}
                    ),
                    "source_spec_id": spec.id,
                    "execution_stage": execution_stage,
                    "compute_placement": relation,
                    "source_compute_host": probe_source.host,
                    "source_availability_zone": probe_source.availability_zone,
                    **(
                        {
                            "destination_compute_host": probe_destination.host,
                            "destination_availability_zone": probe_destination.availability_zone,
                        }
                        if spec.operation != "egress"
                        else {}
                    ),
                },
            )
            if spec.operation == "egress":
                for key in (
                    "destination_compute_host",
                    "destination_availability_zone",
                    "destination_server_id",
                    "destination_management_ip",
                ):
                    clone.metadata.pop(key, None)
            output.append(clone)
        # Dependencies on another replayed measurement belong to this placement,
        # particularly fragmentation's measured outbound MTU. Historical IDs
        # would silently substitute the pre-migration measurement.
        replacements = {spec.metadata["source_spec_id"]: spec.id for spec in output}
        for spec in output:
            spec.requires = [
                replacements.get(identity, identity) for identity in spec.requires
            ]
            spec.requires_pass = [
                replacements.get(identity, identity) for identity in spec.requires_pass
            ]
            for key in ("mtu_test_id", "source_address_test_id"):
                identity = spec.metadata.get(key)
                if identity in replacements:
                    spec.metadata[key] = replacements[identity]
        return output

    @staticmethod
    def _placement_identity_token(*values: str) -> str:
        """Build a readable collision-resistant token for runtime results.

        Planned group IDs can share long prefixes, and the same planned group
        can be instantiated more than once.  Include the complete logical
        identity, workflow scope and concrete server IDs in the digest so
        separate workflows sharing endpoint VMs retain separate evidence.
        """
        normalized = [str(value) for value in values if str(value)]
        raw = "\x1f".join(normalized)
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
        readable = "-".join(safe_name(value, 12) for value in normalized[:3])
        return f"{safe_name(readable, 40)}-{digest}"

    def _placement_control_spec(
        self,
        dependencies: tuple[str, ...],
        *,
        source: Endpoint,
        destination: Endpoint,
        kind: str,
        display_name: str,
        scenario: str,
        expectation: str,
    ) -> TestSpec:
        token = self._placement_identity_token(
            *dependencies,
            source.server_id,
            destination.server_id,
            getattr(self, "_placement_workflow_id", ""),
        )
        controls = getattr(self, "_placement_check_bindings", {})
        key = next(
            (
                name
                for name in sorted(controls, key=len, reverse=True)
                if kind == name or kind.startswith(name + "-")
            ),
            None,
        )
        binding = {"planned_check_id": controls[key]} if key else {}
        if key == "MIGRATION-FUNCTIONAL-BASELINE":
            binding["check_sample"] = True
        return TestSpec(
            id=f"PLACEMENT-{kind}-{token}",
            category="compute-placement",
            operation="compute-placement",
            family=None,
            expectation=expectation,
            expectation_reason="compute placement and migration state must match the requested topology",
            authoritative=True,
            dependencies=list(dependencies),
            phase="placement",
            display_name=display_name,
            scenario=scenario,
            metadata={"supplemental": True, **binding},
        )

    def _select_migration_targets(
        self,
        endpoint: Endpoint,
        peer: Endpoint,
        *,
        desired_relation: str,
    ) -> tuple[list[ComputeHostInfo], str]:
        """Use the full target API, with compatibility for older builders."""
        selector = getattr(self.builder, "select_compute_migration_targets", None)
        if selector is not None:
            targets, reason = selector(
                endpoint,
                peer,
                desired_relation=desired_relation,
            )
            return list(targets), reason
        target, reason = self.builder.select_compute_migration_target(
            endpoint,
            peer,
            desired_relation=desired_relation,
        )
        return ([target] if target is not None else []), reason

    def _compute_migration_attempts(
        self,
        source: Endpoint,
        destination: Endpoint,
        *,
        desired_relation: str,
        maximum_attempts: int | None = None,
    ) -> tuple[list[tuple[Endpoint, Endpoint, ComputeHostInfo]], str]:
        """Resolve eligible destinations within the requested submission budget.

        Ordinary placement validation keeps side A stationary and moves side B.
        Exact ``--target-host-pairs`` qualification may also use the safe reverse
        direction when creating same-host placement. That keeps every submission
        inside the declared pair while allowing a cold fallback to avoid a Nova
        destination that was authoritatively rejected as unsuitable.
        """
        maximum = max(
            1,
            int(
                maximum_attempts
                if maximum_attempts is not None
                else self.config.migration_submission_budget
            ),
        )
        targets, reason = self._select_migration_targets(
            destination,
            source,
            desired_relation=desired_relation,
        )
        base = [(destination, source, target) for target in targets]

        configured_pairs = {
            frozenset((str(first), str(second)))
            for first, second in (getattr(self.config, "target_host_pairs", None) or [])
            if str(first) and str(second)
        }
        requested_pair = frozenset(
            (
                str(source.metadata.get("requested_host") or source.host or ""),
                str(
                    destination.metadata.get("requested_host") or destination.host or ""
                ),
            )
        )
        exact_pair = (
            desired_relation == "same"
            and len(requested_pair) == 2
            and requested_pair in configured_pairs
        )
        if exact_pair:
            reverse_targets, reverse_reason = self._select_migration_targets(
                source,
                destination,
                desired_relation=desired_relation,
            )
            base.extend((source, destination, target) for target in reverse_targets)
            if not targets and reverse_targets:
                reason = reverse_reason

        unique: list[tuple[Endpoint, Endpoint, ComputeHostInfo]] = []
        seen: set[tuple[str, str]] = set()
        for moving, stationary, target in base:
            target_host = str(getattr(target, "host", "") or "")
            key = (moving.server_id, target_host)
            if not target_host or key in seen:
                continue
            seen.add(key)
            unique.append((moving, stationary, target))
        if not unique:
            return (
                [],
                reason
                if reason and reason != "eligible"
                else "No eligible migration target was discovered",
            )
        return unique[:maximum], "eligible"

    def _record_hidden_placement(
        self,
        dependencies: tuple[str, ...],
        source: Endpoint,
        destination: Endpoint,
    ) -> None:
        coverage = self._placement_control_spec(
            dependencies,
            source=source,
            destination=destination,
            kind="HOST-DISCOVERY",
            display_name="Discover endpoint compute placement",
            scenario="Compute-host placement coverage",
            expectation="placement-known",
        )
        self._append_runtime_specs([coverage])
        self.reporter.result(
            coverage.id,
            coverage.category,
            "UNVERIFIED",
            "Nova did not expose compute-host placement for both endpoints",
            expected=coverage.expectation,
            observed="placement-hidden",
            authoritative=True,
            details={"dependencies": list(dependencies)},
            display_name=coverage.display_name,
            scenario=coverage.scenario,
        )

    def _placement_batch_is_read_only(
        self, dependencies: tuple[str, ...], specs: list[TestSpec] | None = None
    ) -> bool:
        if len(dependencies) == 1 or migration_batch_eligible(specs or []):
            return False
        self.logger.log(
            "Cross-group compute placement is read-only; no cross-AZ or "
            "cross-group migration was scheduled"
        )
        return True

    def _run_compute_placement_validation(
        self,
        specs: list[TestSpec],
        engine: TestEngine,
        *,
        dependencies: tuple[str, ...],
    ) -> None:
        # SNAT and floating-IP batches can share the same dependencies and VMs.
        # Scope every derived result to its complete logical test batch, even
        # when a legacy plan has no explicit check bindings.
        self._placement_workflow_id = self._placement_identity_token(
            *sorted(spec.id for spec in specs)
        )
        controls: dict[str, str] = next(
            (
                spec.metadata.get("check_bindings", {}).get("placement", {})
                for spec in specs
                if spec.metadata.get("check_bindings", {}).get("placement")
            ),
            {},
        )
        self._placement_check_bindings = controls
        endpoints = self._placement_endpoints(dependencies, specs) if controls else None
        if endpoints and all(endpoint.host for endpoint in endpoints):
            resolve_checks(
                self.reporter,
                {
                    controls["HOST-DISCOVERY"]: (
                        "PASSED",
                        f"Observed hosts: {endpoints[0].host} / {endpoints[1].host}",
                    )
                },
            )
        self._run_compute_placement_work(specs, engine, dependencies=dependencies)
        if not controls:
            return
        # Initial reachability is existing evidence; it is not rerun for a new ID.
        baseline = controls.get("MIGRATION-BASELINE")
        if baseline:
            _, results = self._functional_baseline_results(specs)
            passed = [
                row for row in results if row is not None and row.status == "PASS"
            ]
            if passed:
                resolve_checks(
                    self.reporter,
                    {
                        baseline: (
                            "PASSED",
                            "Functional baseline is available; "
                            f"{len(passed)} successful observations",
                        )
                    },
                )
        barrier = controls.get("MIGRATION-FUNCTIONAL-BASELINE")
        if barrier:
            # A retry starts a fresh complete functional barrier. Its final assessment
            # owns all rounds and submissions, including unsuccessful samples.
            rows = [
                row
                for row in self.reporter.results
                if (row.details or {}).get("planned_check_id") == barrier
                and row.category == "compute-placement"
            ]
            if rows:
                final = rows[-1]
                outcome = "PASSED" if final.status == "PASS" else "BLOCKED"
                resolve_checks(
                    self.reporter,
                    {barrier: (outcome, final.message)},
                    replace_existing=True,
                )
        identities = set(controls.values())
        for spec in specs:
            bindings = spec.metadata.get("check_bindings", {})
            if bindings.get("post-migration"):
                identities.add(bindings["post-migration"])
            identities.update(
                bindings.get("performance", {}).get("post-live-migration", {}).values()
            )
        ledger = {row["id"]: row for row in check_ledger(self.reporter)}
        reason = next(
            (
                row["reason"]
                for name in ("MIGRATION", "HOST-DISCOVERY", "MIGRATION-BASELINE")
                if (row := ledger.get(controls.get(name), {})).get("outcome")
                not in {None, "PASSED", "PENDING"}
            ),
            "Migration prerequisite or requested migration mode did not enable this check",
        )
        # Live-only follow-up checks are inapplicable after a successful cold fallback.
        lifecycle_results = [
            row
            for row in self.reporter.results
            if (row.details or {}).get("planned_check_id") == controls.get("MIGRATION")
        ]
        cold = any(
            (row.details or {}).get("migration_mode") == "cold"
            or (row.details or {}).get("details", {}).get("migration_mode") == "cold"
            for row in lifecycle_results
            if row.status == "PASS"
        )
        if cold:
            live_ids = {
                identity
                for spec in specs
                for identity in spec.metadata.get("check_bindings", {})
                .get("performance", {})
                .get("post-live-migration", {})
                .values()
            }
            if controls.get("LIVE-CONTINUITY"):
                live_ids.add(controls["LIVE-CONTINUITY"])
            finish_checks(
                self.reporter,
                live_ids,
                outcome="INAPPLICABLE",
                reason="A cold migration completed; this check requires a completed live migration",
            )
        finish_checks(self.reporter, identities, reason=str(reason))

    def _run_compute_placement_work(
        self,
        specs: list[TestSpec],
        engine: TestEngine,
        *,
        dependencies: tuple[str, ...],
    ) -> None:
        if not self.config.compute_host_connectivity_enabled:
            return
        if not any(
            spec.operation in {"probe", "fip-baseline", "fip-peer"} for spec in specs
        ):
            return
        endpoints = self._placement_endpoints(dependencies, specs)
        if endpoints is None:
            return
        source, destination = endpoints
        current_relation = self._placement_relation(source, destination)
        if current_relation is None:
            self._record_hidden_placement(dependencies, source, destination)
            return

        reachable_specs, reachable_results = self._functional_baseline_results(specs)
        if not reachable_specs:
            # Observation-only and isolation checks establish no reachable
            # baseline for migration. Host discovery remains available.
            return
        observed_results = [
            result for result in reachable_results if result is not None
        ]
        if (
            reachable_specs
            and len(observed_results) == len(reachable_specs)
            and not any(result.status == "PASS" for result in observed_results)
        ):
            self._record_unavailable_migration_baseline(
                dependencies,
                source,
                destination,
                current_relation,
                reachable_specs,
                reachable_results,
            )
            return

        # The ordinary functional specs have already executed against the
        # current concrete endpoint placement. Treat that as the authoritative
        # coverage for the current relation instead of cloning and rerunning the
        # same probes under PLACEMENT-INTRA/INTER result IDs.
        validated_relations: set[str] = {current_relation}
        self.logger.log(
            f"Compute placement {current_relation} is already covered by the "
            "ordinary functional results; duplicate supplemental probes were omitted"
        )

        def validate_relation(relation: str) -> None:
            if relation in validated_relations:
                return
            relation_specs = self._placement_probe_specs(
                specs,
                relation=relation,
                source=source,
                destination=destination,
                execution_stage="initial-testing",
            )
            self._append_runtime_specs(relation_specs)
            if relation_specs:
                self.logger.section(
                    f"Compute placement validation: {relation} "
                    f"({source.host} -> {destination.host})"
                )
                engine.run_specs(relation_specs)
            validated_relations.add(relation)

        # Cross-group and cross-AZ batches retain ordinary read-only coverage.
        if self._placement_batch_is_read_only(dependencies, specs):
            return

        coordinator = getattr(self.builder, "cloud_operation_coordinator", None)

        def pre_submission_barrier(
            submission_number: int,
            migration_kind: str,
            moving: Endpoint,
            stationary: Endpoint,
            target: ComputeHostInfo,
        ) -> bool:
            if coordinator is None:
                return True
            return self._pre_migration_functional_barrier(
                specs,
                engine,
                dependencies=dependencies,
                source=source,
                destination=destination,
                current_relation=current_relation,
                submission_number=submission_number,
                migration_kind=migration_kind,
            )

        desired_relation = (
            "different" if current_relation == "intra-compute" else "same"
        )
        desired_label = (
            "inter-compute" if desired_relation == "different" else "intra-compute"
        )
        migration_execution = self._attempt_configured_migration(
            dependencies=dependencies,
            source=source,
            destination=destination,
            current_relation=current_relation,
            desired_relation=desired_relation,
            desired_label=desired_label,
            pre_submission_barrier=pre_submission_barrier,
        )
        if migration_execution is None:
            return
        (
            lifecycle,
            result,
            migrated_endpoint,
            attempt_details,
            attempts,
            fallback_used,
            migration_mode,
            terminal_error,
            all_unavailable,
        ) = migration_execution

        if result is None or migrated_endpoint is None:
            current_after = self._placement_relation(source, destination)
            if terminal_error is None and current_after is not None:
                # Normally this relation was validated before migration. This
                # guard covers any safe recovery path that returned a relation
                # not yet exercised without ever duplicating completed checks.
                validate_relation(current_after)
            ambiguous = any(
                item.get("cloud_operation_outcome") == "AMBIGUOUS"
                for item in attempt_details
            )
            safety_barrier = any(
                item.get("status") == "unverified-safety-barrier"
                for item in attempt_details
            )
            if ambiguous:
                status = "UNVERIFIED"
                observed = "command-outcome-ambiguous"
            elif safety_barrier or (all_unavailable and terminal_error is None):
                status = "UNVERIFIED"
                observed = (
                    "fresh-functional-baseline-unavailable"
                    if safety_barrier
                    else "placement-unavailable"
                )
            else:
                status = "FAIL"
                observed = "migration-attempts-failed"
            attempted_hosts = ", ".join(
                str(item.get("target_host") or "unknown") for item in attempt_details
            )
            retained_relation = (
                current_after
                if current_after is not None and current_after in validated_relations
                else current_relation
            )
            not_submitted = bool(attempt_details) and all(
                item.get("cloud_operation_outcome") == "NOT_SUBMITTED"
                for item in attempt_details
            )
            message = (
                f"Migration to {desired_label} placement was not submitted: "
                + str(
                    attempt_details[-1].get("message")
                    or "Migration safety checks did not pass"
                )
                + f". Existing {retained_relation} results were retained."
                if not_submitted
                else f"Could not create {desired_label} placement after "
                f"{len(attempt_details)} attempt(s) ({attempted_hosts}). "
                f"The previously completed {retained_relation} placement tests "
                "were retained and were not rerun unnecessarily."
            )
            if terminal_error:
                message += f" Retries stopped because the instance state was not safely retryable: {terminal_error}"
            self.reporter.result(
                lifecycle.id,
                lifecycle.category,
                status,
                message,
                source=destination.host,
                destination=source.host if desired_relation == "same" else None,
                expected=lifecycle.expectation,
                observed=observed,
                authoritative=True,
                details={
                    "current_relation": current_relation,
                    "desired_relation": desired_label,
                    "attempts": attempt_details,
                    **(
                        {"lifecycle_cloud_operation_performed": False}
                        if not_submitted
                        else {}
                    ),
                    "cloud_operation_outcome": (
                        "AMBIGUOUS"
                        if ambiguous
                        else (
                            attempt_details[-1].get("cloud_operation_outcome")
                            if attempt_details
                            else "NOT_SUBMITTED"
                        )
                    ),
                    "retry_permitted": bool(
                        attempt_details and attempt_details[-1].get("retry_permitted")
                    ),
                    "host_quarantined": ambiguous,
                    "effective_submission_budget": self.config.migration_submission_budget,
                    "validated_relations": sorted(validated_relations),
                    "current_relation_after_attempts": current_after,
                },
                display_name=lifecycle.display_name,
                scenario=lifecycle.scenario,
            )
            return

        binding = self._placement_control_spec(
            dependencies,
            source=source,
            destination=destination,
            kind=f"PORT-BINDING-{desired_label.upper()}",
            display_name=(
                f"Verify Neutron port rebinding after {desired_label} migration — "
                f"{migrated_endpoint.label}"
            ),
            scenario="Post-migration Neutron port binding",
            expectation="bound-to-destination",
        )
        readiness = self._placement_control_spec(
            dependencies,
            source=source,
            destination=destination,
            kind=f"ENDPOINT-READY-{desired_label.upper()}",
            display_name=(
                f"Restore endpoint networking after {desired_label} migration — "
                f"{migrated_endpoint.label}"
            ),
            scenario="Post-migration endpoint readiness",
            expectation="endpoint-ready",
        )
        self._append_runtime_specs([binding, readiness])

        achieved_relation = self._placement_relation(source, destination)
        expected_relation = desired_label
        result.details = {
            **result.details,
            "migration_attempts": attempt_details,
            "successful_attempt": len(attempt_details),
            "configured_migration_mode": migration_mode,
            "cold_fallback_used": fallback_used,
            "effective_submission_budget": self.config.migration_submission_budget,
            "completion_assessment": migration_completion(dataclasses.asdict(result)),
        }
        if achieved_relation != expected_relation:
            self.reporter.result(
                lifecycle.id,
                lifecycle.category,
                "FAIL",
                f"Migration completed but produced {achieved_relation or 'unknown'} placement instead of {expected_relation}",
                source=result.source_host,
                destination=result.destination_host,
                expected=lifecycle.expectation,
                observed="wrong-placement",
                authoritative=True,
                details=dataclasses.asdict(result),
                display_name=lifecycle.display_name,
                scenario=lifecycle.scenario,
            )
            self.reporter.result(
                binding.id,
                binding.category,
                "UNVERIFIED",
                "Requested compute relation was not achieved",
                expected=binding.expectation,
                observed="not-run",
                authoritative=True,
                details={"blocked_by": lifecycle.id},
                display_name=binding.display_name,
                scenario=binding.scenario,
            )
            self.reporter.result(
                readiness.id,
                readiness.category,
                "UNVERIFIED",
                "Requested compute relation was not achieved",
                expected=readiness.expectation,
                observed="not-run",
                authoritative=True,
                details={"blocked_by": lifecycle.id},
                display_name=readiness.display_name,
                scenario=readiness.scenario,
            )
            return

        completed_mode = str(result.details.get("migration_mode") or "cold")
        if completed_mode == "live":
            confirmation_text = (
                "Nova completed the live migration without a resize-confirmation phase"
            )
        else:
            confirmation_text = (
                "Nova automatically confirmed the migration before the explicit confirmation completed"
                if result.automatically_confirmed
                else "the suite explicitly confirmed the migration immediately at VERIFY_RESIZE"
            )
        retry_text = (
            ""
            if len(attempt_details) == 1
            else f" after {len(attempt_details) - 1} safely recovered failed attempt(s)"
        )
        if result.migration_record_verified is False:
            lifecycle_status = "FAIL"
            lifecycle_observed = "migration-record-invalid"
            lifecycle_suffix = f"; {result.migration_record_error}"
        elif result.task_state_cleared is False:
            lifecycle_status = "FAIL"
            lifecycle_observed = "task-state-not-cleared"
            lifecycle_suffix = "; Nova still exposed a non-empty task state after migration confirmation"
        elif result.volume_attachment_verified is False:
            lifecycle_status = "FAIL"
            lifecycle_observed = "volume-attachment-changed"
            lifecycle_suffix = f"; {result.volume_validation_error}"
        elif result.guest_marker_verified is False:
            lifecycle_status = "FAIL"
            lifecycle_observed = "guest-disk-marker-changed"
            lifecycle_suffix = f"; {result.guest_marker_error}"
        elif result.migration_record_verified is None and "terminal state" in (
            result.migration_record_error or ""
        ):
            lifecycle_status = "UNVERIFIED"
            lifecycle_observed = "migration-record-unverified"
            lifecycle_suffix = f"; {result.migration_record_error or 'Nova migration completion record is unavailable'}"
        elif result.guest_marker_verified is None:
            lifecycle_status = "UNVERIFIED"
            lifecycle_observed = "guest-disk-evidence-unavailable"
            lifecycle_suffix = (
                "; the persistent guest-disk marker could not be independently verified"
            )
        elif (
            self.config.storage == "volume"
            and result.volume_attachment_verified is None
        ):
            lifecycle_status = "UNVERIFIED"
            lifecycle_observed = "volume-attachment-evidence-unavailable"
            lifecycle_suffix = (
                "; final placement and guest state were verified, but the root-volume attachment "
                "could not be independently confirmed"
            )
        else:
            lifecycle_status = "PASS"
            lifecycle_observed = "migrated-and-confirmed"
            required_evidence = (
                "observed source-to-destination host transition, migration confirmation, final ACTIVE state, "
                "unchanged availability zone, and preserved persistent guest-disk marker"
            )
            if self.config.storage == "volume":
                required_evidence += ", with the same root-volume attachment preserved"
            lifecycle_suffix = f"; authoritative verification used {required_evidence}"
        full_completion = migration_completion(dataclasses.asdict(result))
        nova_completion = migration_completion(
            {
                **dataclasses.asdict(result),
                # These two separately reported layers do not change Nova's own
                # lifecycle outcome. Their actual evidence remains in the full
                # assessment and the dedicated binding/readiness results.
                "port_binding_verified": True,
                "endpoint_ready": True,
            }
        )
        if nova_completion["verified"] is not True:
            lifecycle_status = nova_completion["status"]
            if lifecycle_observed == "migrated-and-confirmed":
                lifecycle_observed = "nova-lifecycle-evidence-incomplete"
                lifecycle_suffix = (
                    "; required Nova lifecycle evidence was not verified: "
                    + ", ".join(
                        nova_completion["failed_checks"]
                        + nova_completion["missing_checks"]
                    )
                )
        result.details.update(
            completion_assessment=full_completion,
            nova_lifecycle_assessment=nova_completion,
        )
        if full_completion["verified"] is not True:
            lifecycle_suffix += f"; full migration completion={full_completion['status']} (binding and readiness are assessed separately)"
        self.reporter.result(
            lifecycle.id,
            lifecycle.category,
            lifecycle_status,
            (
                f"Nova lifecycle: moved {migrated_endpoint.label} to {result.destination_host} "
                f"using {completed_mode} migration on attempt {len(attempt_details)}"
                f"{retry_text}; "
                f"{confirmation_text}, returned it to ACTIVE, and preserved "
                f"availability zone {result.destination_availability_zone}{lifecycle_suffix}"
            ),
            source=result.source_host,
            destination=result.destination_host,
            expected=lifecycle.expectation,
            observed=lifecycle_observed,
            authoritative=True,
            details=dataclasses.asdict(result),
            display_name=lifecycle.display_name,
            scenario=lifecycle.scenario,
        )
        if result.port_binding_verified is True:
            binding_status = "PASS"
            binding_message = (
                f"All endpoint ports retained identity and became ACTIVE with "
                f"binding:host_id={result.destination_host}"
            )
            binding_observed = "bound-to-destination"
        elif result.port_binding_verified is False:
            binding_status = "FAIL"
            binding_message = result.port_validation_error or (
                "Neutron port state did not converge on the destination compute host"
            )
            binding_observed = "binding-invalid"
        else:
            binding_status = "UNVERIFIED"
            binding_message = (
                "Port identity, addressing, security groups, and ACTIVE state were preserved, "
                "but Neutron policy did not expose binding:host_id"
            )
            binding_observed = "binding-host-hidden"
        self.reporter.result(
            binding.id,
            binding.category,
            binding_status,
            binding_message,
            source=result.source_host,
            destination=result.destination_host,
            expected=binding.expectation,
            observed=binding_observed,
            authoritative=True,
            details=result.details,
            display_name=binding.display_name,
            scenario=binding.scenario,
        )

        readiness_status = "PASS" if result.endpoint_ready else "FAIL"
        readiness_observed = (
            "endpoint-ready" if result.endpoint_ready else "endpoint-unavailable"
        )
        readiness_message = (
            "SSH, the persistent guest-disk marker, OpenStack-provided guest networking, and the transient endpoint probe were restored"
            if result.endpoint_ready
            else (
                result.endpoint_recovery_error
                or "The migrated endpoint did not regain a usable guest network and probe service"
            )
        )
        self.reporter.result(
            readiness.id,
            readiness.category,
            readiness_status,
            readiness_message,
            source=result.source_host,
            destination=result.destination_host,
            expected=readiness.expectation,
            observed=readiness_observed,
            authoritative=True,
            details=result.details,
            display_name=readiness.display_name,
            scenario=readiness.scenario,
        )

        if completed_mode == "live" and self.config.live_migration_continuity:
            continuity_spec = self._placement_control_spec(
                dependencies,
                source=source,
                destination=destination,
                kind=f"LIVE-CONTINUITY-{desired_label.upper()}",
                display_name=(
                    f"Measure endpoint traffic continuity during live migration — "
                    f"{migrated_endpoint.label}"
                ),
                scenario="Live migration network continuity",
                expectation="traffic-continuity-measured",
            )
            self._append_runtime_specs([continuity_spec])
            continuity = result.details.get("continuity") or {}
            (
                continuity_status,
                continuity_observed,
                continuity_message,
                continuity_details,
            ) = self._live_continuity_verdict(continuity)
            self.reporter.result(
                continuity_spec.id,
                continuity_spec.category,
                continuity_status,
                continuity_message,
                source=result.source_host,
                destination=result.destination_host,
                expected=continuity_spec.expectation,
                observed=continuity_observed,
                authoritative=True,
                details=continuity_details,
                display_name=continuity_spec.display_name,
                scenario=continuity_spec.scenario,
            )

        migrated_specs = self._placement_probe_specs(
            specs,
            relation=expected_relation,
            source=source,
            destination=destination,
            execution_stage=f"post-{completed_mode}-migration",
        )
        self._append_runtime_specs(migrated_specs)
        if migrated_specs:
            self.logger.section(
                f"Post-migration connectivity validation: {expected_relation} "
                f"({source.host} -> {destination.host})"
            )
            if not result.endpoint_ready:
                self.logger.log(
                    "Post-migration endpoint readiness did not fully recover; "
                    "running every planned data-plane check independently so "
                    "each protocol and MTU path records its own authoritative outcome",
                    "WARNING",
                )
            engine.run_specs(migrated_specs)
            validated_relations.add(expected_relation)
            if completed_mode == "live" and any(
                spec.operation in {"probe", "fip-baseline"}
                and spec.protocol == "tcp"
                and spec.expectation == "reachable"
                for spec in migrated_specs
            ):
                self.logger.section(
                    "Post-live-migration project-network performance validation"
                )
                self._run_performance(
                    migrated_specs,
                    engine,
                    stage="post-live-migration",
                )
