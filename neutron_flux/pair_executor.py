"""Placement enforcement and runtime helpers for exact host pairs."""

from __future__ import annotations

import copy
import dataclasses
from contextlib import nullcontext
from typing import Any

from .check_plan import migration_batch_eligible
from .check_resume import conditional_pending
from .engine import TestEngine
from .errors import ControllerUnavailableError, RunCancelledError, SuiteError
from .executor import AdaptiveExecutor
from .models import Endpoint, Plan, RuntimeGroup, TestSpec
from .scheduling import READ_WORKERS, bounded_map


def _remap(value: Any, mapping: dict[str, str]) -> Any:
    if isinstance(value, str):
        return mapping.get(value, value)
    if isinstance(value, list):
        return [_remap(item, mapping) for item in value]
    if isinstance(value, tuple):
        return tuple(_remap(item, mapping) for item in value)
    if isinstance(value, dict):
        return {key: _remap(item, mapping) for key, item in value.items()}
    return copy.deepcopy(value)


class PairScopeExecutor(AdaptiveExecutor):
    """Reuse the ordinary suite, enforcing exact placement at every batch."""

    plan: Plan

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        metadata = next(
            spec.metadata
            for spec in self.plan.tests
            if spec.metadata.get("pair_scope_id")
        )
        self.scope = {
            key: value
            for key, value in metadata.items()
            if key.startswith(
                ("pair_", "host_qualification", "qualification_", "requested_", "same_")
            )
            or key == "inventory_fingerprint"
        }

    def prepare_resume(self) -> None:
        """Recheck a partial placement on freshly created resources.

        Completed evidence is retained. Interrupted runtime observations belonged
        to the deleted VM generation and remain explicitly incomplete. New
        baseline checks produce fresh performance/migration evidence; their IDs
        and prerequisites are journaled before another resource is created.
        """
        if not self.config.resume_run_id or not any(
            self.reporter.has_result(spec.id) for spec in self.plan.tests
        ):
            return
        base = [
            spec
            for spec in self.plan.tests
            if spec.phase in {"intra", "cross"}
            and not spec.metadata.get("supplemental")
            and not spec.metadata.get("resume_recheck")
        ]
        if (
            getattr(self.reporter.plan, "checks", None)
            and all(self.reporter.has_result(spec.id) for spec in base)
            and not conditional_pending(self.reporter, base, include_load=False)
        ):
            return
        generation = 1 + int(
            self.checkpoint.metadata.setdefault("pair_resume_attempts", {}).get(
                self.scope["pair_scope_id"], 0
            )
        )
        self.checkpoint.metadata["pair_resume_attempts"][
            self.scope["pair_scope_id"]
        ] = generation
        mapping = {
            spec.id: f"{spec.id}-RECHECK-{generation}"
            if self.reporter.has_result(spec.id)
            else spec.id
            for spec in base
        }
        replay = [
            dataclasses.replace(
                spec,
                id=mapping[spec.id],
                requires=[mapping.get(item, item) for item in spec.requires],
                requires_pass=[mapping.get(item, item) for item in spec.requires_pass],
                metadata={
                    **spec.metadata,
                    "resume_recheck": True,
                    "source_spec_id": spec.id,
                },
            )
            for spec in base
        ]
        base_ids = {spec.id for spec in base}
        stale = [
            spec
            for spec in self.plan.tests
            if spec.id not in base_ids and not self.reporter.has_result(spec.id)
        ]
        for spec in stale:
            if spec.metadata.get("planned_check_id"):
                spec.metadata["check_sample"] = True
        self.reporter.save_plan()
        self._mark_specs_unavailable(
            stale,
            "The interrupted runtime observation belonged to the previous VM generation, which was reconciled before resume. Fresh baseline and derived checks are recorded separately; this historical observation cannot be reconstructed.",
            blocked=True,
        )
        self._append_runtime_specs([spec for spec in replay if spec.id not in base_ids])
        replay_ids = {spec.id for spec in replay}
        self.plan.tests = replay + [
            spec for spec in self.plan.tests if spec.id not in replay_ids
        ]
        self.reporter.event(
            "host-pair-resume-recheck",
            "Rechecking a partial host placement on fresh resources; completed evidence is retained",
            scope=self.scope["pair_scope_id"],
            attempt=generation,
            recheck_ids=sorted(replay_ids),
            interrupted_runtime_ids=[spec.id for spec in stale],
        )
        self._refresh_checkpoint()

    def _hosts_for(
        self, sides: tuple[str, ...], index: int | None = None
    ) -> dict[str, str]:
        hosts = self.scope["pair_scope_hosts"]
        return {
            side: hosts[
                index if index is not None else (0 if side.upper() == "A" else 1)
            ]
            for side in sides
        }

    def _active_reuse_keys(self) -> set[tuple[str, ...]]:
        return {
            (group_id, endpoint.side.upper(), endpoint.host or "")
            for group_id, runtime in self.active.items()
            for endpoint in runtime.endpoints
        }

    def _batch_reuse_keys(self, key: Any) -> set[tuple[str, ...]]:
        dependencies, requirements = key[:2]
        keys: set[tuple[str, ...]] = set()
        for group_id, sides in requirements:
            index = dependencies.index(group_id) if len(dependencies) == 2 else None
            hosts = self._hosts_for(sides, index)
            keys.update((group_id, side.upper(), hosts[side]) for side in sides)
        return keys

    def _set_hosts(self, group_id: str, hosts: dict[str, str]) -> None:
        zones = self.scope.get("pair_selected_host_zones") or dict(
            zip(
                self.scope["pair_scope_hosts"],
                self.scope["pair_scope_zones"],
                strict=True,
            )
        )
        group = self.groups[group_id]
        self.groups[group_id] = dataclasses.replace(
            group,
            metadata={
                **group.metadata,
                "target_hosts": hosts,
                "target_availability_zones": {
                    side: zones[host] for side, host in hosts.items()
                },
            },
        )

    def _verify_runtime(self, runtime: RuntimeGroup) -> None:
        group = self.groups.get(runtime.plan.id, runtime.plan)
        expected = group.metadata["target_hosts"]
        zones = group.metadata["target_availability_zones"]
        checks: list[tuple[Endpoint, str, str | None]] = []
        roles: set[str] = set()
        servers: set[str] = set()
        for endpoint in runtime.endpoints:
            if (
                endpoint.side not in {"A", "B"}
                or endpoint.side in roles
                or not endpoint.server_id
                or endpoint.server_id in servers
            ):
                raise SuiteError(f"Invalid endpoint roles for {group.id}")
            roles.add(endpoint.side)
            servers.add(endpoint.server_id)
            host = expected.get(endpoint.side)
            if not host or endpoint.host != host:
                raise SuiteError(
                    f"Exact placement mismatch for {endpoint.label}: expected {host}, observed {endpoint.host}"
                )
            zone = zones.get(endpoint.side)
            if zone and endpoint.availability_zone != zone:
                raise SuiteError(
                    f"Exact availability-zone mismatch for {endpoint.label}: "
                    f"expected {zone}, observed {endpoint.availability_zone}"
                )
            checks.append((endpoint, host, zone))

        def verify(check: tuple[Endpoint, str, str | None]) -> None:
            endpoint, host, zone = check
            self.builder.verify_server_placement(
                endpoint.server_id,
                [endpoint.management_port_id, endpoint.test_port_id or ""],
                expected_statuses={"active"},
                expected_host=host,
                expected_availability_zone=zone,
                display_name=endpoint.server_name,
                stable_observations=2,
                reuse_fresh=True,
            )

        # OpenStack admits each read itself. Holding a read/lifecycle slot here
        # would obstruct the independent Neutron reads inside each verifier.
        bounded_map(verify, checks, workers=READ_WORKERS)

    def _build(self, group_id: str, *, sides: tuple[str, ...]) -> RuntimeGroup | None:
        runtime = super()._build(group_id, sides=sides)
        if runtime is not None:
            try:
                self._verify_runtime(runtime)
            except (RunCancelledError, ControllerUnavailableError):
                raise
            except SuiteError as exc:
                self.builder.group_failures[group_id] = str(exc)
                self.builder.stop_group_probes(group_id)
                self._cleanup_failed_build(group_id)
                self.builder.runtime_groups = [
                    item
                    for item in self.builder.runtime_groups
                    if item.plan.id != group_id
                ]
                return None
        return runtime

    def _ensure(
        self,
        required: tuple[str, ...],
        *,
        required_sides: dict[str, tuple[str, ...]] | None = None,
    ) -> None:
        retained: dict[str, RuntimeGroup] = dict(self.active)
        sides = required_sides or {group_id: ("A",) for group_id in required}
        for index, group_id in enumerate(required):
            hosts = self._hosts_for(
                sides[group_id], index if len(required) == 2 else None
            )
            runtime = self.active.get(group_id)
            if runtime and any(
                endpoint.side in hosts and endpoint.host != hosts[endpoint.side]
                for endpoint in runtime.endpoints
            ):
                self._release(group_id)
            self._set_hosts(group_id, hosts)
        super()._ensure(required, required_sides=sides)
        for group_id in list(required):
            runtime = self.active.get(group_id)
            # _build already verifies every new endpoint against Nova and
            # Neutron. Recheck retained generations before reuse, without
            # immediately repeating that full check on newly built groups.
            if runtime is retained.get(group_id) and runtime is not None:
                try:
                    self._verify_runtime(runtime)
                except (RunCancelledError, ControllerUnavailableError):
                    raise
                except SuiteError as exc:
                    self.builder.group_failures[group_id] = str(exc)
                    self.failed_groups.add(group_id)
                    self._release(group_id)

    def _append_runtime_specs(self, specs: list[TestSpec]) -> None:
        for spec in specs:
            spec.metadata = {**self.scope, **spec.metadata}
        global_plan = self.reporter.plan
        if global_plan is not self.plan:
            existing = {spec.id for spec in global_plan.tests}
            global_plan.tests.extend(spec for spec in specs if spec.id not in existing)
        super()._append_runtime_specs(specs)

    def _refresh_checkpoint(self) -> None:
        lane = self.plan
        try:
            self.plan = self.reporter.plan
            super()._refresh_checkpoint()
        finally:
            self.plan = lane

    def _validate_plan_consistency(self) -> None:
        missing = [
            spec.id for spec in self.plan.tests if not self.reporter.has_result(spec.id)
        ]
        if missing:
            raise SuiteError(
                f"Host-pair suite has {len(missing)} planned tests without terminal results"
            )

    def _run_placement_validation_serialized(
        self,
        specs: list[TestSpec],
        engine: TestEngine,
        *,
        dependencies: tuple[str, ...],
    ) -> None:
        if (
            self.config.derived_tests_suppressed
            or self.scope.get("pair_placement_policy") == "initial-opposite-v1"
            or self.scope["pair_placement"] != "inter"
            or not self.scope["same_availability_zone"]
            or self.scope["qualification_strategy"] == "stable"
            or self.scope["qualification_profile"] == "connectivity"
            or not self.config.compute_host_connectivity_enabled
            or not migration_batch_eligible(specs)
        ):
            return
        endpoints = self._placement_endpoints(dependencies, specs)
        if endpoints is None:
            return
        source, destination = endpoints
        coordinator = getattr(self.builder, "cloud_operation_coordinator", None)
        transaction = (
            coordinator.transaction(
                "migration",
                "Exact host-pair migration and recovery checks",
                resource_ids=[source.server_id, destination.server_id],
                source_host=destination.host,
                destination_host=source.host,
                availability_zone=destination.availability_zone,
                max_attempts=self.config.migration_submission_budget,
                conflicts=("all-cloud-operations",),
                final_cooldown=5.0,
            )
            if coordinator
            else nullcontext()
        )
        with self.performance_lock, transaction:
            self._run_compute_placement_validation(
                specs, engine, dependencies=dependencies
            )
