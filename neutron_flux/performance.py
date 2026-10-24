from __future__ import annotations

import contextlib
import dataclasses
import ipaddress
import json
import math
import select
import shlex
import statistics
import subprocess
import time
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .cancellation import raise_if_cancelled, register_process, unregister_process
from .check_ledger import finish_checks, resolve_checks
from .check_plan import MEASUREMENTS
from .config import Config
from .errors import (
    MeasurementExecutionError,
    RunCancelledError,
    SuiteError,
)
from .measurement_programs import tcp_client_code, udp_client_code
from .models import Endpoint, TestSpec
from .mtu_contract import (
    classify_fragmentation_location,
    make_mtu_observation,
    resolve_mtu_contract,
)
from .mtu_probes import (
    fragment_counter_probe_code,
    fragmentation_probe_code,
    performance_probe_code,
)
from .performance_analysis import PerformanceAnalysisMixin
from .performance_measurements import PerformanceMeasurementMixin
from .performance_metrics import (
    _coefficient_of_variation,
    _confidence_interval_95,
    _last_line,
    _parse_ping,
    _tukey_outliers,
    udp_statistics_error,
)
from .performance_results import PerformanceResultMixin, performance_spec_metadata
from .performance_udp_matrix import UDPMatrixMixin
from .pmtu_cache import route_cache_reset_code
from .probe_service import ProbeServiceManager
from .reporting import Reporter
from .result_context import recorded_execution_stage
from .result_contract import performance_expectation
from .scheduling import ACTIVITY, timed
from .utils import unique_safe_name


@dataclasses.dataclass(frozen=True)
class PerformancePath:
    path_id: str
    source_spec_id: str
    category: str
    family: int
    source_group_id: str | None
    destination_group_id: str
    source_side: str
    destination_side: str
    source_subnet_id: str | None
    destination_subnet_id: str | None
    stage: str
    execution_scope: str | None = None
    path_kind: str = "endpoint"
    lifecycle_key: str | None = None
    directions: tuple[str, ...] = ("forward", "reverse")


@dataclasses.dataclass
class PerformanceSession:
    seen: set[tuple[Any, ...]] = dataclasses.field(default_factory=set)
    eligible_by_stage: dict[str, int] = dataclasses.field(default_factory=dict)
    selected_by_stage: dict[str, int] = dataclasses.field(default_factory=dict)
    omitted_by_stage: dict[str, int] = dataclasses.field(default_factory=dict)
    completed_by_stage: dict[str, int] = dataclasses.field(default_factory=dict)
    selected_by_category: dict[str, int] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True)
class ResolvedPerformancePath:
    plan: PerformancePath
    source: Endpoint
    destination: Endpoint
    source_ip: str
    destination_ip: str
    source_mtu: int
    destination_mtu: int
    placement: str
    availability_scope: str
    destination_bind_ip: str | None = None
    reverse_expected_peer_ip: str | None = None
    source_mtu_evidence: dict[str, Any] = dataclasses.field(default_factory=dict)
    destination_mtu_evidence: dict[str, Any] = dataclasses.field(default_factory=dict)
    additional_mtu_evidence: tuple[dict[str, Any], ...] = ()
    router_ids: tuple[str, ...] = ()
    router_backend_evidence: dict[str, Any] = dataclasses.field(default_factory=dict)

    @property
    def expected_mtu(self) -> int:
        value = self.mtu_contract.get("expected_mtu")
        return (
            int(value)
            if value is not None
            else min(self.source_mtu, self.destination_mtu)
        )

    @property
    def mtu_contract(self) -> dict[str, Any]:
        observations = [
            item
            for item in (
                self.source_mtu_evidence,
                self.destination_mtu_evidence,
                *self.additional_mtu_evidence,
            )
            if item
        ]
        if not observations:
            observations = [
                make_mtu_observation(
                    label="source network",
                    reported_mtu=self.source_mtu,
                    authority="compatibility MTU resolver",
                    authoritative=True,
                    resource_type="network",
                ),
                make_mtu_observation(
                    label="destination network",
                    reported_mtu=self.destination_mtu,
                    authority="compatibility MTU resolver",
                    authoritative=True,
                    resource_type="network",
                ),
            ]
        return resolve_mtu_contract(observations)

    @property
    def forward_source_ip(self) -> str:
        return self.source_ip

    @property
    def forward_destination_ip(self) -> str:
        return self.destination_ip

    @property
    def reverse_source_ip(self) -> str:
        return self.destination_bind_ip or self.destination_ip

    @property
    def reverse_destination_ip(self) -> str:
        return self.source_ip

    @property
    def label(self) -> str:
        return (
            f"{self.source.label} ({self.source_ip}) → "
            f"{self.destination.label} ({self.destination_ip})"
        )


class PerformanceRunner(
    UDPMatrixMixin,
    PerformanceResultMixin,
    PerformanceMeasurementMixin,
    PerformanceAnalysisMixin,
):
    """Run exhaustive network-path measurements unless explicitly capped."""

    MEASUREMENTS = MEASUREMENTS
    CATEGORY_PRIORITY = {
        "project-network-routing": 0,
        "tenant-router": 0,
        "routed-provider": 1,
        "project-provider-connectivity": 2,
        "tenant-provider-connectivity": 2,
        "same-subnet": 3,
        "provider-network-connectivity": 4,
        "router-extra-route": 5,
        "router-static-routing": 5,
    }

    def __init__(
        self,
        config: Config,
        builder: Any,
        reporter: Reporter,
        engine: Any,
        *,
        session: PerformanceSession | None = None,
    ):
        self.config = config
        self.builder = builder
        self.reporter = reporter
        self.engine = engine
        self.session = session or PerformanceSession()
        self._planned: dict[str, PerformancePath] = {}
        self._performance_executions: list[dict[str, Any]] = []

    def plan_specs(
        self, source_specs: Iterable[TestSpec], *, stage: str
    ) -> list[TestSpec]:
        if not self.config.performance_enabled:
            return []
        source_specs = list(source_specs)
        source_metadata = {}
        for spec in source_specs:
            observed = self.reporter.get_result(spec.id)
            details = getattr(observed, "details", None)
            source_metadata[spec.id] = {
                **spec.metadata,
                "execution_stage": (
                    details.get("execution_stage")
                    if isinstance(details, dict)
                    else None
                )
                or getattr(self.engine, "execution_stage_override", None)
                or recorded_execution_stage(spec.metadata)
                or "initial-testing",
            }
        self._check_source_specs = source_specs
        self._check_stage = stage
        self._check_exclusions: dict[str, tuple[str, str]] = {}
        paths = self._select_paths(source_specs, stage=stage)
        result: list[TestSpec] = []
        for path in paths:
            applicable_measurements = (
                self.MEASUREMENTS
                if "reverse" in path.directions
                else tuple(item for item in self.MEASUREMENTS if item[0] != "asymmetry")
            )
            for measurement, display in applicable_measurements:
                test_id = f"PERF-{path.path_id}-{measurement.upper()}"
                spec = TestSpec(
                    id=test_id,
                    category="network-performance",
                    operation=f"performance-{measurement}",
                    family=path.family,
                    expectation=performance_expectation(measurement),
                    expectation_reason=(
                        "every measured direction passed authoritative functional "
                        "reachability and is eligible for network-path performance "
                        "measurement"
                    ),
                    authoritative=True,
                    dependencies=list(
                        dict.fromkeys(
                            item
                            for item in [
                                path.source_group_id,
                                path.destination_group_id,
                            ]
                            if item
                        )
                    ),
                    source_group_id=path.source_group_id,
                    destination_group_id=path.destination_group_id,
                    source_side=path.source_side,
                    destination_side=path.destination_side,
                    source_subnet_id=path.source_subnet_id,
                    destination_subnet_id=path.destination_subnet_id,
                    protocol="performance",
                    phase=stage,
                    metadata=performance_spec_metadata(
                        source_metadata, path, measurement, stage
                    ),
                    display_name=display,
                    scenario="Network path performance",
                )
                self._planned[test_id] = path
                result.append(spec)
        if not result:
            self._finish_planned_checks()
        return result

    def _exclude_planned_path(
        self, spec: TestSpec, reason: str, *, inapplicable: bool = False
    ) -> None:
        outcome = "INAPPLICABLE" if inapplicable else "BLOCKED"
        for identity in (
            spec.metadata.get("check_bindings", {})
            .get("performance", {})
            .get(getattr(self, "_check_stage", ""), {})
            .values()
        ):
            self._check_exclusions[identity] = (outcome, reason)

    def _finish_planned_checks(self) -> None:
        resolve_checks(self.reporter, getattr(self, "_check_exclusions", {}))
        identities = {
            identity
            for spec in getattr(self, "_check_source_specs", [])
            for identity in spec.metadata.get("check_bindings", {})
            .get("performance", {})
            .get(getattr(self, "_check_stage", ""), {})
            .values()
        }
        finish_checks(
            self.reporter,
            identities,
            reason="Required TCP connectivity did not pass in this measurement window",
        )

    def run_specs(self, specs: Iterable[TestSpec]) -> None:
        with (
            ACTIVITY.scope(
                exclusive=True, reporter=self.reporter, label="baseline performance"
            ),
            timed(self.reporter, "performance", "baseline performance"),
        ):
            self._run_specs_isolated(specs)
            self._finish_planned_checks()

    def _select_paths(
        self, source_specs: Iterable[TestSpec], *, stage: str
    ) -> list[PerformancePath]:
        source_specs = list(source_specs)
        candidates = [
            spec
            for spec in source_specs
            if spec.operation in {"probe", "fip-baseline"}
            and spec.expectation == "reachable"
            and spec.authoritative
            and self.reporter.get_result(spec.id) is not None
            and self.reporter.get_result(spec.id).status == "PASS"
            and spec.family in {4, 6}
            and spec.destination_group_id
            and spec.protocol == "tcp"
            and (spec.operation == "fip-baseline" or spec.source_group_id)
        ]
        candidates.sort(
            key=lambda item: (
                self.CATEGORY_PRIORITY.get(item.category, 99),
                item.id,
            )
        )

        def qualification_scope(spec: TestSpec) -> tuple[Any, ...]:
            pair_id = spec.metadata.get("host_qualification_pair_id")
            if not pair_id:
                return ()
            # Rolling reuses group/side IDs across hosts, and stable reuses
            # them across cycles. Each requested pair/cycle needs measurement.
            return (
                "host-qualification",
                str(pair_id),
                int(spec.metadata.get("host_qualification_cycle") or 1),
                str(spec.metadata.get("pair_scope_id") or ""),
            )

        def endpoint_key(spec: TestSpec) -> tuple[Any, ...]:
            return (
                spec.source_group_id,
                spec.source_side,
                spec.source_subnet_id,
                spec.destination_group_id,
                spec.destination_side,
                spec.destination_subnet_id,
                spec.family,
                stage,
                *qualification_scope(spec),
            )

        passed_endpoint_directions = {
            endpoint_key(spec): spec for spec in candidates if spec.operation == "probe"
        }
        eligible: list[tuple[TestSpec, tuple[Any, ...], PerformancePath]] = []
        local_signatures: set[tuple[Any, ...]] = set()
        missing_reverse_paths: set[frozenset[tuple[Any, ...]]] = set()
        for spec in candidates:
            execution_scope = str(getattr(self.reporter, "scope", "") or "")
            if spec.operation == "fip-baseline":
                lifecycle_key = f"fip:{spec.destination_group_id}"
                state = self.engine.lifecycle.get(lifecycle_key)
                if not isinstance(state, dict):
                    self._exclude_planned_path(
                        spec, "Floating-IP lifecycle state is unavailable"
                    )
                    continue
                if not state.get("authoritative") or not state.get("baseline"):
                    self._exclude_planned_path(
                        spec, "Floating-IP baseline is not authoritative"
                    )
                    continue
                signature = (
                    "floating-ip",
                    str(state.get("id") or state.get("address") or spec.id),
                    str(state.get("source_mode") or "unknown"),
                    stage,
                )
                reverse = signature
                path_kind = "floating-ip"
                # A runner-to-floating-IP baseline proves ingress only.  A new
                # VM-to-runner connection is a different path and must not be
                # invented as the reverse direction.
                directions = ("forward",)
            else:
                signature = (
                    spec.source_group_id,
                    spec.source_side,
                    spec.source_subnet_id,
                    spec.destination_group_id,
                    spec.destination_side,
                    spec.destination_subnet_id,
                    spec.family,
                    stage,
                    *qualification_scope(spec),
                )
                reverse = (
                    spec.destination_group_id,
                    spec.destination_side,
                    spec.destination_subnet_id,
                    spec.source_group_id,
                    spec.source_side,
                    spec.source_subnet_id,
                    spec.family,
                    stage,
                    *qualification_scope(spec),
                )
                lifecycle_key = None
                path_kind = "endpoint"
                if reverse not in passed_endpoint_directions:
                    missing_reverse_paths.add(frozenset((signature, reverse)))
                    self._exclude_planned_path(
                        spec,
                        "Reverse TCP connectivity did not pass in the same measurement window",
                    )
                    continue
                directions = ("forward", "reverse")
            if signature in self.session.seen or reverse in self.session.seen:
                self._exclude_planned_path(
                    spec,
                    "This path has already been measured in this stage",
                    inapplicable=True,
                )
                continue
            if signature in local_signatures or reverse in local_signatures:
                continue
            path_token = unique_safe_name(
                f"{execution_scope}-{stage}-{spec.category}-IPv{spec.family}-{spec.id}",
                80,
            ).upper()
            path = PerformancePath(
                path_id=path_token,
                source_spec_id=spec.id,
                category=spec.category,
                family=int(spec.family),
                source_group_id=(
                    str(spec.source_group_id) if spec.source_group_id else None
                ),
                destination_group_id=str(spec.destination_group_id),
                source_side=spec.source_side,
                destination_side=spec.destination_side,
                source_subnet_id=spec.source_subnet_id,
                destination_subnet_id=spec.destination_subnet_id,
                stage=stage,
                execution_scope=execution_scope or None,
                path_kind=path_kind,
                lifecycle_key=lifecycle_key,
                directions=directions,
            )
            try:
                source, destination, *_ = self._resolve_endpoints(path)
            except SuiteError as exc:
                self._exclude_planned_path(
                    spec, f"Performance endpoints unavailable: {exc}"
                )
                continue
            if path_kind == "endpoint" and source.server_id == destination.server_id:
                self._exclude_planned_path(
                    spec,
                    "Source and destination resolve to the same VM",
                    inapplicable=True,
                )
                continue
            local_signatures.add(signature)
            eligible.append((spec, signature, path))

        configured_limit = int(self.config.performance_max_paths)
        already_selected = self.session.selected_by_stage.get(stage, 0)
        remaining = (
            max(0, configured_limit - already_selected)
            if configured_limit > 0
            else len(eligible)
        )
        chosen = eligible[:remaining]
        for omitted_spec, _, _ in eligible[remaining:]:
            self._exclude_planned_path(
                omitted_spec,
                f"Configured limit of {configured_limit} performance paths reached for {stage}",
                inapplicable=True,
            )
        omitted = max(0, len(eligible) - len(chosen))
        self.session.eligible_by_stage[stage] = self.session.eligible_by_stage.get(
            stage, 0
        ) + len(eligible)
        self.session.omitted_by_stage[stage] = (
            self.session.omitted_by_stage.get(stage, 0) + omitted
        )
        eligible_by_category: dict[str, int] = {}
        for spec, _, _ in eligible:
            eligible_by_category[spec.category] = (
                eligible_by_category.get(spec.category, 0) + 1
            )
        selected: list[PerformancePath] = []
        by_category: dict[str, int] = {}
        for spec, signature, path in chosen:
            self.session.seen.add(signature)
            selected.append(path)
            by_category[spec.category] = by_category.get(spec.category, 0) + 1
            self.session.selected_by_category[spec.category] = (
                self.session.selected_by_category.get(spec.category, 0) + 1
            )
        if selected:
            self.session.selected_by_stage[stage] = already_selected + len(selected)
        self.reporter.event(
            "performance-coverage",
            f"Selected {len(selected)} of {len(eligible)} eligible performance paths for {stage}",
            stage=stage,
            eligible_paths=len(eligible),
            selected_paths=len(selected),
            omitted_paths=omitted,
            configured_max_paths=configured_limit,
            unlimited=configured_limit == 0,
            eligible_by_topology=eligible_by_category,
            selected_by_topology=by_category,
            omitted_by_topology={
                category: max(0, count - int(by_category.get(category, 0)))
                for category, count in eligible_by_category.items()
            },
            paths_rejected_without_reverse_functional_pass=len(missing_reverse_paths),
            selected_forward_only_paths=sum(
                1 for item in selected if item.directions == ("forward",)
            ),
        )
        if eligible or missing_reverse_paths:
            limit_text = "unlimited" if configured_limit == 0 else str(configured_limit)
            self.reporter.logger.log(
                f"Performance coverage for {stage}: eligible={len(eligible)}, "
                f"selected={len(selected)}, omitted={omitted}, configured_limit={limit_text}, "
                f"rejected_without_reverse_pass={len(missing_reverse_paths)}"
            )
        return selected

    def _mtu_observation(
        self,
        group_id: str,
        side: str | None,
        observations: dict[str, dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        identity = getattr(self.engine, "_network_identity", None)
        network_id = str(identity(group_id, side)[0]) if callable(identity) else None
        if observations is not None and network_id in observations:
            return dict(observations[network_id])
        resolver = getattr(self.engine, "_network_mtu_observation", None)
        if callable(resolver):
            observation = resolver(group_id, side)
            if isinstance(observation, dict) and observation.get("effective_mtu"):
                if observations is not None and network_id:
                    observations[network_id] = dict(observation)
                return observation
            raise SuiteError(
                f"MTU observation for runtime group {group_id} was incomplete"
            )
        # Compatibility for embedded engines and older unit harnesses. The canonical
        # engine always supplies the provenance-aware resolver above.
        mtu = int(self.engine._network_mtu(group_id))
        return make_mtu_observation(
            label=f"{group_id} network",
            reported_mtu=mtu,
            authority="compatibility MTU resolver",
            authoritative=True,
            resource_type="network",
            resource_id=group_id,
        )

    def _router_ids_for_path(self, path: PerformancePath) -> tuple[str, ...]:
        router_ids: list[str] = []
        for group_id in dict.fromkeys(
            item for item in (path.source_group_id, path.destination_group_id) if item
        ):
            runtime = None
            group_resolver = getattr(self.engine, "_group", None)
            if callable(group_resolver):
                try:
                    runtime = group_resolver(group_id)
                except SuiteError:
                    runtime = None
            if runtime is None:
                runtime = (getattr(self.engine, "groups", {}) or {}).get(group_id)
            if runtime is None:
                continue
            if getattr(runtime, "router_id", None):
                router_ids.append(str(runtime.router_id))
            for router_id in (
                (getattr(runtime, "metadata", {}) or {}).get("routers", {}).values()
            ):
                if router_id:
                    router_ids.append(str(router_id))
        return tuple(dict.fromkeys(router_ids))

    def _additional_path_mtu_evidence(
        self,
        path: PerformancePath,
        *observed: dict[str, Any],
    ) -> tuple[dict[str, Any], ...]:
        group_resolver = getattr(self.engine, "_group", None)
        resolver = getattr(self.engine, "_neutron_network_mtu_observation", None)
        if not callable(group_resolver) or not callable(resolver):
            return ()
        seen = {
            str(item.get("resource_id")) for item in observed if item.get("resource_id")
        }
        evidence: list[dict[str, Any]] = []
        for group_id in dict.fromkeys(
            item for item in (path.source_group_id, path.destination_group_id) if item
        ):
            try:
                runtime = group_resolver(group_id)
            except (KeyError, StopIteration, SuiteError):
                continue
            metadata = getattr(runtime, "metadata", {}) or {}
            network_ids = metadata.get("network_ids") or {}
            network_names = metadata.get("network_names") or {}
            for side, raw_network_id in network_ids.items():
                network_id = str(raw_network_id or "")
                if not network_id or network_id in seen:
                    continue
                network_name = str(network_names.get(side) or network_id)
                evidence.append(resolver(network_id, network_name))
                seen.add(network_id)
            if path.path_kind == "floating-ip":
                plan = getattr(runtime, "plan", None)
                external_network_id = str(
                    getattr(plan, "external_network_id", None) or ""
                )
                if external_network_id and external_network_id not in seen:
                    external_network_name = str(
                        getattr(plan, "external_network_name", None)
                        or external_network_id
                    )
                    evidence.append(
                        resolver(external_network_id, external_network_name)
                    )
                    seen.add(external_network_id)
        return tuple(evidence)

    def _router_backend_evidence(
        self,
        path: PerformancePath,
    ) -> dict[str, Any]:
        if not self._router_ids_for_path(path):
            return {}
        resolver = getattr(self.engine, "_network_router_backend_evidence", None)
        if not callable(resolver):
            return {
                "backend": "unknown",
                "confirmed": False,
                "reason": "router backend evidence was unavailable",
            }
        evidence = resolver()
        return (
            dict(evidence)
            if isinstance(evidence, dict)
            else {
                "backend": "unknown",
                "confirmed": False,
                "reason": "router backend evidence was malformed",
            }
        )

    def _resolve_endpoints(
        self, path: PerformancePath
    ) -> tuple[Endpoint, Endpoint, str, str, str | None]:
        """Resolve eligibility from existing endpoint state, without API reads."""
        if path.path_kind == "floating-ip":
            state = self.engine.lifecycle.get(str(path.lifecycle_key or ""))
            if not isinstance(state, dict):
                raise SuiteError("Floating-IP lifecycle state is unavailable")
            destination = state.get("target")
            destination_ip = str(state.get("address") or "")
            destination_bind_ip = str(state.get("fixed_ip") or "")
            if isinstance(destination, Endpoint) and not destination_bind_ip:
                destination_bind_ip = str(
                    destination.fixed_ips.get(str(path.destination_subnet_id or ""))
                    or next(
                        (
                            value
                            for value in destination.fixed_ips.values()
                            if ":" not in str(value)
                        ),
                        "",
                    )
                )
            source_ip = str(state.get("source_ip") or "")
            if (
                not isinstance(destination, Endpoint)
                or not destination_ip
                or not destination_bind_ip
                or not source_ip
            ):
                raise SuiteError("Floating-IP performance endpoints are incomplete")
            source = state.get("source")
            if not isinstance(source, Endpoint):
                source = Endpoint(
                    label="Flux runner",
                    server_id="runner-local",
                    server_name="runner-local",
                    management_port_id="runner-local",
                    management_ip=source_ip,
                    test_port_id=None,
                    test_mac=None,
                    fixed_ips={"runner": source_ip},
                    host="runner",
                    availability_zone=None,
                    volume_id=None,
                    side="R",
                    metadata={"performance_local": True, "source_mode": "runner"},
                )
            return source, destination, source_ip, destination_ip, destination_bind_ip
        source, source_ip = self.engine._endpoint_address(
            str(path.source_group_id), path.source_side, path.source_subnet_id
        )
        destination, destination_ip = self.engine._endpoint_address(
            path.destination_group_id, path.destination_side, path.destination_subnet_id
        )
        return source, destination, source_ip, destination_ip, None

    def _resolve(self, path: PerformancePath) -> ResolvedPerformancePath:
        source, destination, source_ip, destination_ip, bind_ip = (
            self._resolve_endpoints(path)
        )
        # This snapshot lives for one path resolution only. The next path,
        # lifecycle stage or migration always obtains fresh Neutron evidence.
        observations: dict[str, dict[str, Any]] = {}
        destination_mtu_evidence = self._mtu_observation(
            path.destination_group_id, path.destination_side, observations
        )
        destination_mtu = int(destination_mtu_evidence["effective_mtu"])
        local_source = path.path_kind == "floating-ip" and bool(
            source.metadata.get("performance_local")
        )
        if local_source:
            if "_local_path_mtu" in getattr(self, "__dict__", {}):
                source_mtu = self._local_path_mtu(
                    source_ip, destination_ip, fallback=destination_mtu
                )
                source_mtu_evidence = make_mtu_observation(
                    label="Flux runner route/interface",
                    reported_mtu=source_mtu,
                    authority="compatibility local MTU resolver",
                    authoritative=True,
                    resource_type="interface",
                    resource_id="runner-local",
                )
            else:
                source_mtu_evidence = self._local_path_mtu_observation(
                    source_ip, destination_ip, fallback=destination_mtu
                )
        else:
            source_mtu_evidence = self._mtu_observation(
                str(path.source_group_id), path.source_side, observations
            )
        source_mtu = int(source_mtu_evidence["effective_mtu"])
        placement = (
            "runner-to-cloud"
            if local_source
            else "same-compute"
            if source.host and source.host == destination.host
            else "cross-compute"
            if source.host and destination.host
            else "placement-unavailable"
        )
        availability_scope = (
            "runner-to-az"
            if local_source
            else "same-az"
            if source.availability_zone
            and source.availability_zone == destination.availability_zone
            else "cross-az"
            if source.availability_zone and destination.availability_zone
            else "az-unavailable"
        )
        return ResolvedPerformancePath(
            plan=path,
            source=source,
            destination=destination,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_mtu=source_mtu,
            destination_mtu=destination_mtu,
            placement=placement,
            availability_scope=availability_scope,
            destination_bind_ip=bind_ip,
            reverse_expected_peer_ip=destination_ip
            if path.path_kind == "floating-ip"
            else None,
            source_mtu_evidence=source_mtu_evidence,
            destination_mtu_evidence=destination_mtu_evidence,
            additional_mtu_evidence=self._additional_path_mtu_evidence(
                path, source_mtu_evidence, destination_mtu_evidence
            ),
            router_ids=self._router_ids_for_path(path),
            router_backend_evidence=self._router_backend_evidence(path),
        )

    @staticmethod
    def _local_path_mtu_observation(
        source_ip: str,
        destination_ip: str,
        *,
        fallback: int,
    ) -> dict[str, Any]:
        reported_mtu = None
        device = ""
        try:
            route = subprocess.run(
                ["ip", "-j", "route", "get", destination_ip, "from", source_ip],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
            rows = json.loads(route.stdout or "[]") if route.returncode == 0 else []
            device = str(rows[0].get("dev") or "") if rows else ""
            if device:
                link = subprocess.run(
                    ["ip", "-j", "link", "show", "dev", device],
                    text=True,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                links = json.loads(link.stdout or "[]") if link.returncode == 0 else []
                mtu = int(links[0].get("mtu") or 0) if links else 0
                if mtu > 0:
                    reported_mtu = mtu
        except (
            OSError,
            ValueError,
            IndexError,
            json.JSONDecodeError,
            subprocess.TimeoutExpired,
        ):
            pass
        return make_mtu_observation(
            label=f"Flux runner interface {device or 'unresolved'}",
            reported_mtu=reported_mtu,
            authority="Flux runner kernel route/interface inspection",
            authoritative=reported_mtu is not None,
            resource_type="interface",
            resource_id=device or "runner-local",
            fallback_mtu=fallback,
            source="ip route get and ip link show",
        )

    @staticmethod
    def _local_path_mtu(source_ip: str, destination_ip: str, *, fallback: int) -> int:
        observation = PerformanceRunner._local_path_mtu_observation(
            source_ip,
            destination_ip,
            fallback=fallback,
        )
        return int(observation["effective_mtu"])

    @contextlib.contextmanager
    def _local_probe_server(self, path: ResolvedPerformancePath):
        if (
            not path.source.metadata.get("performance_local")
            or "reverse" not in path.plan.directions
        ):
            yield
            return
        manager = ProbeServiceManager(
            self.config.tcp_port,
            self.config.udp_port,
            startup_timeout=20,
            stop_timeout=5,
        )
        code = manager._server_code(path.source)
        process = subprocess.Popen(
            ["python3", "-u", "-c", code, "neutron-flux-local-performance-probe"],
            text=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        register_process(process)
        try:
            if process.stdout is None:
                raise SuiteError("Local performance probe stdout pipe was not created")
            deadline = time.monotonic() + 20
            ready = False
            captured: list[str] = []
            while time.monotonic() < deadline and process.poll() is None:
                raise_if_cancelled()
                readable, _, _ = select.select(
                    [process.stdout], [], [], max(0.0, deadline - time.monotonic())
                )
                if not readable:
                    continue
                line = process.stdout.readline().strip()
                if line:
                    captured.append(line)
                if line.startswith(manager.READY_PREFIX):
                    ready = True
                    break
                if line.startswith(manager.ERROR_PREFIX):
                    break
            if not ready:
                stderr = ""
                if process.stderr is not None and process.poll() is not None:
                    stderr = process.stderr.read().strip()
                raise SuiteError(
                    "Could not start the temporary runner performance listener: "
                    + _last_line(
                        stderr or " | ".join(captured) or "no readiness output"
                    )
                )
            self.reporter.logger.log(
                f"Temporary runner performance listener ready on {path.source_ip}: "
                f"TCP/{self.config.tcp_port}, UDP/{self.config.udp_port}"
            )
            yield
        finally:
            try:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
            finally:
                unregister_process(process)
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()

    def _tcp_direction(
        self,
        source: Endpoint,
        source_ip: str,
        destination_ip: str,
        family: int,
        *,
        expected_peer_ip: str | None = None,
    ) -> dict[str, Any]:
        peer_kwargs = {"expected_peer_ip": expected_peer_ip} if expected_peer_ip else {}
        warmup = self._tcp_upload(
            source,
            source_ip,
            destination_ip,
            family,
            streams=1,
            **peer_kwargs,
        )
        repeats = [
            self._tcp_upload(
                source,
                source_ip,
                destination_ip,
                family,
                streams=1,
                **peer_kwargs,
            )
            for _ in range(self.config.performance_repeats)
        ]
        stream_results: dict[str, dict[str, Any]] = {"1": self._summarize_tcp(repeats)}
        stream_results["1"]["warmup_sample"] = warmup
        stream_results["1"]["warmup_samples"] = 1
        for streams in self.config.performance_tcp_streams:
            if streams == 1:
                continue
            stream_results[str(streams)] = self._summarize_tcp(
                [
                    self._tcp_upload(
                        source,
                        source_ip,
                        destination_ip,
                        family,
                        streams=streams,
                        **peer_kwargs,
                    )
                ]
            )
        return {
            "warmup": warmup,
            "repeats": repeats,
            "streams": stream_results,
        }

    def _tcp_upload(
        self,
        source: Endpoint,
        source_ip: str,
        destination_ip: str,
        family: int,
        *,
        streams: int,
        duration_seconds: int | None = None,
        expected_peer_ip: str | None = None,
    ) -> dict[str, Any]:
        duration = duration_seconds or self.config.performance_duration_seconds
        code = self._tcp_client_code(
            source_ip,
            destination_ip,
            family,
            self.config.tcp_port,
            duration,
            streams,
        )
        result = self._run_json_with_transient_retry(
            source,
            code,
            timeout=duration + 45,
        )
        self._require_expected_peer(result, expected_peer_ip, protocol="TCP")
        return result

    @staticmethod
    def _require_expected_peer(
        result: dict[str, Any],
        expected_peer_ip: str | None,
        *,
        protocol: str,
    ) -> None:
        if not expected_peer_ip:
            return
        raw_peers = result.get("peer_ips")
        if isinstance(raw_peers, list):
            observed_peers = [
                str(item).strip() for item in raw_peers if str(item).strip()
            ]
        else:
            observed = str(result.get("peer_ip") or "").strip()
            observed_peers = [observed] if observed else []
        try:
            expected = ipaddress.ip_address(expected_peer_ip)
            matches = bool(observed_peers) and all(
                ipaddress.ip_address(item) == expected for item in observed_peers
            )
        except ValueError:
            matches = False
        if not matches:
            rendered = ", ".join(observed_peers) or "an unknown address"
            raise SuiteError(
                f"Reverse floating-IP {protocol} flow was observed from "
                f"{rendered}; expected SNAT source {expected_peer_ip}"
            )
        result["expected_peer_ip"] = expected_peer_ip
        result["peer_verified"] = True

    _tcp_client_code = staticmethod(tcp_client_code)

    @staticmethod
    def _summarize_tcp(runs: list[dict[str, Any]]) -> dict[str, Any]:
        values = [float(item["mbps"]) for item in runs]
        retransmissions = [
            int(item["retransmissions"])
            for item in runs
            if item.get("retransmissions") is not None
        ]
        interval_values = [
            float(value) for item in runs for value in item.get("intervals_mbps", [])
        ]
        total_bytes = sum(int(item.get("bytes") or 0) for item in runs)
        total_elapsed_s = sum(float(item.get("elapsed_s") or 0.0) for item in runs)
        total_retransmissions = sum(retransmissions)
        return {
            "runs": runs,
            "median_mbps": statistics.median(values),
            "minimum_mbps": min(values),
            "maximum_mbps": max(values),
            "mean_mbps": statistics.fmean(values),
            "stdev_mbps": statistics.stdev(values) if len(values) > 1 else 0.0,
            "variation_pct": _coefficient_of_variation(values),
            "confidence_95_mbps": _confidence_interval_95(values),
            "outliers_mbps": _tukey_outliers(values),
            "minimum_interval_mbps": min(interval_values) if interval_values else None,
            "maximum_interval_mbps": max(interval_values) if interval_values else None,
            "total_retransmissions": total_retransmissions,
            "maximum_retransmissions": max(retransmissions, default=None),
            "retransmission_samples": len(retransmissions),
            "total_bytes": total_bytes,
            "total_elapsed_s": total_elapsed_s,
            "retransmissions_per_gib": (
                total_retransmissions * (1024.0**3) / total_bytes
                if retransmissions and total_bytes > 0
                else None
            ),
            "retransmissions_per_second": (
                total_retransmissions / total_elapsed_s
                if retransmissions and total_elapsed_s > 0.0
                else None
            ),
            "client_mss": min(int(item.get("client_mss") or 0) for item in runs),
            "server_mss": min(int(item.get("server_mss") or 0) for item in runs),
        }

    def _bidirectional_tcp(self, path: ResolvedPerformancePath) -> dict[str, Any]:
        reverse_peer_kwargs = (
            {"expected_peer_ip": path.reverse_expected_peer_ip}
            if path.reverse_expected_peer_ip
            else {}
        )
        with ThreadPoolExecutor(max_workers=2) as pool:
            forward = pool.submit(
                self._tcp_upload,
                path.source,
                path.forward_source_ip,
                path.forward_destination_ip,
                path.plan.family,
                streams=1,
            )
            reverse = pool.submit(
                self._tcp_upload,
                path.destination,
                path.reverse_source_ip,
                path.reverse_destination_ip,
                path.plan.family,
                streams=1,
                **reverse_peer_kwargs,
            )
            forward_result = forward.result()
            reverse_result = reverse.result()
        return {
            "forward_mbps": float(forward_result["mbps"]),
            "reverse_mbps": float(reverse_result["mbps"]),
            "aggregate_mbps": float(forward_result["mbps"])
            + float(reverse_result["mbps"]),
            "forward_sample": forward_result,
            "reverse_sample": reverse_result,
        }

    def _ping(
        self,
        source: Endpoint,
        source_ip: str,
        destination_ip: str,
        family: int,
    ) -> dict[str, Any]:
        flag = "-6" if family == 6 else "-4"
        measured_command = (
            f"LC_ALL=C LANG=C ping {flag} -n -c {self.config.performance_ping_count} "
            f"-i 0.2 -W 2 -I {shlex.quote(source_ip)} "
            f"{shlex.quote(destination_ip)}"
        )
        warmup_count = int(self.config.performance_ping_warmup_count)
        warmup_command = (
            f"LC_ALL=C LANG=C ping {flag} -n -c {warmup_count} "
            f"-i 0.2 -W 2 -I {shlex.quote(source_ip)} "
            f"{shlex.quote(destination_ip)}"
            if warmup_count > 0
            else ""
        )
        command = (
            f"{warmup_command} >/dev/null 2>&1 || true; {measured_command}"
            if warmup_command
            else measured_command
        )
        timeout = max(
            30,
            (
                self.config.performance_ping_count
                + self.config.performance_ping_warmup_count
            )
            // 5
            + 20,
        )
        result = self._execute_performance_command(
            source, command, timeout=timeout, local_command=["bash", "-lc", command]
        )
        parsed = _parse_ping(
            result.returncode, result.stdout or "", result.stderr or ""
        )
        if not parsed["transmitted"]:
            raise MeasurementExecutionError(
                "Latency command returned no packet transmission statistics",
                evidence={
                    "command": command,
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                },
            )
        parsed["warmup_count"] = warmup_count
        parsed["measured_count_requested"] = int(self.config.performance_ping_count)
        parsed["execution_evidence"] = next(
            (
                dict(item)
                for item in reversed(self._performance_executions)
                if item["command"] == command and item["server_id"] == source.server_id
            ),
            {
                "command": command,
                "endpoint": source.label,
                "server_id": source.server_id,
            },
        )
        return parsed

    def _loaded_latency(
        self,
        source: Endpoint,
        source_ip: str,
        destination_ip: str,
        family: int,
        *,
        expected_peer_ip: str | None = None,
    ) -> dict[str, Any]:
        load_duration = max(
            self.config.performance_duration_seconds,
            math.ceil(
                (
                    self.config.performance_ping_count
                    + self.config.performance_ping_warmup_count
                )
                * 0.2
            )
            + 2,
        )
        peer_kwargs = {"expected_peer_ip": expected_peer_ip} if expected_peer_ip else {}
        with ThreadPoolExecutor(max_workers=2) as pool:
            load = pool.submit(
                self._tcp_upload,
                source,
                source_ip,
                destination_ip,
                family,
                streams=max(self.config.performance_tcp_streams),
                duration_seconds=load_duration,
                **peer_kwargs,
            )
            time.sleep(0.25)
            latency = self._ping(source, source_ip, destination_ip, family)
            load_result = load.result()
        latency["load_mbps"] = float(load_result["mbps"])
        latency["load_streams"] = int(load_result["streams"])
        latency["load_sample"] = load_result
        return latency

    def _adaptive_udp_samples(
        self,
        endpoint: Endpoint,
        source_ip: str,
        destination_ip: str,
        family: int,
        configured_rate: int,
        packet_size: int,
        *,
        expected_peer_ip: str | None = None,
        sustainable_rate_hint: int | None = None,
    ) -> list[dict[str, Any]]:
        adaptive = bool(
            getattr(self.config, "performance_udp_adaptive_calibration", True)
        )
        minimum_rate = max(
            1,
            int(getattr(self.config, "performance_udp_calibration_min_rate_mbps", 1)),
        )
        maximum_attempts = max(
            1,
            int(getattr(self.config, "performance_udp_calibration_max_attempts", 4)),
        )
        backoff = float(
            getattr(self.config, "performance_udp_calibration_backoff_factor", 0.5)
        )
        attempts: list[dict[str, Any]] = []
        self._udp_active_profile = {
            "endpoint": endpoint.label,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "packet_size": packet_size,
            "configured_rate_mbps": configured_rate,
            "completed_attempts": attempts,
        }
        rate = int(configured_rate)
        seen_rates: set[int] = set()

        for attempt in range(1, maximum_attempts + 1):
            if rate in seen_rates:
                break
            seen_rates.add(rate)
            peer_kwargs = (
                {"expected_peer_ip": expected_peer_ip} if expected_peer_ip else {}
            )
            measurement = self._udp_measurement(
                endpoint,
                source_ip,
                destination_ip,
                family,
                rate,
                packet_size,
                **peer_kwargs,
            )
            self._annotate_udp_sample(
                measurement,
                configured_rate=configured_rate,
                attempted_rate=rate,
                packet_size=packet_size,
                attempt=attempt,
            )
            attempts.append(measurement)
            if measurement.get("packet_size_supported") is False:
                measurement["calibration_status"] = "packet-size-rejected"
                # Lowering offered load cannot repair a local packet-size
                # rejection. Keep this boundary attempt, then test any derived
                # payload as a separate profile in the matrix.
                break
            if not measurement["sender_telemetry_available"]:
                measurement["calibration_selected"] = True
                measurement["calibration_status"] = "telemetry-unavailable"
                break
            if not adaptive or not measurement["endpoint_limited"]:
                measurement["calibration_selected"] = True
                measurement["calibration_status"] = (
                    "sustainable" if adaptive else "disabled"
                )
                break
            if rate <= minimum_rate:
                break
            next_rate = max(minimum_rate, int(rate * backoff))
            if next_rate >= rate:
                next_rate = rate - 1
            # Spend the existing final retry on a previously sustainable lower
            # rate when ordinary backoff would stop above it. Always try the
            # requested load first, and verify the hint again in this profile.
            if (
                attempt == maximum_attempts - 1
                and sustainable_rate_hint is not None
                and minimum_rate <= sustainable_rate_hint < next_rate
                and sustainable_rate_hint not in seen_rates
            ):
                next_rate = sustainable_rate_hint
            rate = max(minimum_rate, next_rate)

        selected = next(
            (
                item
                for item in reversed(attempts)
                if not item["endpoint_limited"]
                and item.get("packet_size_supported") is not False
            ),
            None,
        )
        if (
            selected is None
            and attempts
            and attempts[-1].get("packet_size_supported") is not False
        ):
            attempts[-1]["calibration_selected"] = True
            attempts[-1]["calibration_status"] = "endpoint-limited"
        selected_rate = (
            int(selected.get("requested_mbps") or 0) if selected is not None else None
        )
        for item in attempts:
            item["calibration_attempts"] = len(attempts)
            item["calibration_selected_rate_mbps"] = selected_rate
            item["calibration_origin_rate_mbps"] = int(configured_rate)
            if item.get("endpoint_limited") and not item.get("calibration_status"):
                item["calibration_status"] = "endpoint-limited-sample"
        return attempts

    def _annotate_udp_sample(
        self,
        measurement: dict[str, Any],
        *,
        configured_rate: int,
        attempted_rate: int,
        packet_size: int,
        attempt: int,
    ) -> None:
        receiver_goodput = measurement.get("mbps")
        sender_mbps = measurement.get("sender_mbps")
        measurement["offered_mbps"] = attempted_rate
        measurement["requested_mbps"] = attempted_rate
        measurement["configured_rate_mbps"] = configured_rate
        measurement["receiver_goodput_mbps"] = receiver_goodput
        # Compatibility alias retained for old report consumers.
        measurement["achieved_mbps"] = receiver_goodput
        if measurement.get("packet_size_supported") is False:
            measurement.update(
                offered_achievement_pct=None,
                sender_achievement_pct=None,
                delivery_pct=None,
                load_valid=False,
                sender_telemetry_available=sender_mbps is not None,
                endpoint_limited=False,
                endpoint_limit_reason=None,
                assessment_scope="packet-size-boundary",
                load_validity="packet-size-rejected",
                packet_size=packet_size,
                calibration_attempt=attempt,
                calibration_selected=False,
            )
            return
        measurement["offered_achievement_pct"] = (
            (float(receiver_goodput) / float(attempted_rate)) * 100.0
            if receiver_goodput is not None and attempted_rate
            else None
        )
        measurement["sender_achievement_pct"] = (
            (float(sender_mbps) / float(attempted_rate)) * 100.0
            if sender_mbps is not None and attempted_rate
            else None
        )
        measurement["delivery_pct"] = (
            (float(receiver_goodput) / float(sender_mbps)) * 100.0
            if receiver_goodput is not None
            and sender_mbps is not None
            and float(sender_mbps) > 0.0
            else None
        )
        sender_threshold = float(
            getattr(
                self.config,
                "performance_udp_sender_achievement_threshold_pct",
                90.0,
            )
        )
        sender_achievement = measurement.get("sender_achievement_pct")
        sender_valid = bool(
            sender_achievement is not None
            and float(sender_achievement) >= sender_threshold
        )
        drop_attribution = str(measurement.get("receiver_drop_attribution") or "")
        receiver_limited = bool(
            drop_attribution
            in {
                "receiver-drop-counters-increased",
                "receiver-kernel-or-socket-loss-observed",
            }
            or int(measurement.get("receiver_socket_rxq_overflow") or 0) > 0
        )
        endpoint_limited = not sender_valid or receiver_limited
        measurement["load_valid"] = sender_valid and not receiver_limited
        measurement["sender_telemetry_available"] = sender_mbps is not None
        measurement["sender_achievement_threshold_pct"] = sender_threshold
        measurement["endpoint_limited"] = endpoint_limited
        measurement["endpoint_limit_reason"] = (
            "receiver-overload"
            if receiver_limited
            else "sender-load-not-achieved"
            if not sender_valid
            else None
        )
        measurement["assessment_scope"] = (
            "endpoint-capacity" if endpoint_limited else "network-path"
        )
        measurement["load_validity"] = (
            "endpoint-limited" if endpoint_limited else "achieved"
        )
        measurement["packet_size"] = packet_size
        measurement["calibration_attempt"] = attempt
        measurement["calibration_selected"] = False

    def _udp_measurement(
        self,
        source: Endpoint,
        source_ip: str,
        destination_ip: str,
        family: int,
        rate_mbps: int,
        packet_size: int,
        *,
        duration_seconds: int | None = None,
        expected_peer_ip: str | None = None,
    ) -> dict[str, Any]:
        code = self._udp_client_code(
            source_ip,
            destination_ip,
            family,
            self.config.udp_port,
            duration_seconds or self.config.performance_duration_seconds,
            rate_mbps,
            packet_size,
        )
        result = self._run_json_with_transient_retry(
            source,
            code,
            timeout=(duration_seconds or self.config.performance_duration_seconds) + 35,
        )
        if (
            result.get("packet_size_supported") is not False
            or result.get("control_statistics_available") is not False
        ):
            statistics_error = udp_statistics_error(result, require_complete=True)
            if statistics_error:
                raise MeasurementExecutionError(statistics_error)
        if (
            result.get("packet_size_supported") is not False
            or result.get("control_statistics_available") is not False
        ):
            self._require_expected_peer(result, expected_peer_ip, protocol="UDP")
        elif expected_peer_ip:
            result.update(expected_peer_ip=expected_peer_ip, peer_verified=False)
        return result

    _udp_client_code = staticmethod(udp_client_code)

    def _fragmentation_probe(
        self,
        source: Endpoint,
        source_ip: str,
        destination_ip: str,
        family: int,
        source_mtu: int,
        path_mtu: int | None,
        *,
        destination: Endpoint | None = None,
        router_ids: Iterable[str] = (),
        router_backend_evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        destination_before = self._fragment_counter_snapshot(destination, family)
        code = self._fragmentation_client_code(
            source_ip,
            destination_ip,
            family,
            source_mtu,
            path_mtu,
        )
        profile = self._run_json(source, code, timeout=90)
        destination_after = self._fragment_counter_snapshot(destination, family)
        return classify_fragmentation_location(
            profile,
            destination_before=destination_before,
            destination_after=destination_after,
            router_ids=router_ids,
            router_backend_evidence=router_backend_evidence,
        )

    def _fragment_counter_snapshot(
        self,
        endpoint: Endpoint | None,
        family: int,
    ) -> dict[str, Any]:
        if endpoint is None:
            return {
                "family": family,
                "available": False,
                "counters": {},
                "error": "destination endpoint was unavailable",
            }
        try:
            return self._run_json(
                endpoint,
                fragment_counter_probe_code(family),
                timeout=15,
            )
        except (
            OSError,
            ValueError,
            TypeError,
            SuiteError,
            subprocess.SubprocessError,
        ) as exc:
            return {
                "family": family,
                "available": False,
                "counters": {},
                "error": str(exc),
            }

    @staticmethod
    def _fragmentation_client_code(
        source_ip: str,
        destination_ip: str,
        family: int,
        source_mtu: int,
        path_mtu: int | None,
    ) -> str:
        return fragmentation_probe_code(
            source_ip,
            destination_ip,
            family,
            source_mtu,
            path_mtu,
        )

    def _fresh_mtu_probe(
        self,
        source: Endpoint,
        source_ip: str,
        destination_ip: str,
        family: int,
        expected_mtu: int,
    ) -> dict[str, Any]:
        reset = self._reset_route_pmtu_cache(
            source, source_ip, destination_ip, family, expected_mtu
        )
        probe = self._mtu_probe(source, source_ip, destination_ip, family, expected_mtu)
        probe["route_pmtu_cache_reset"] = reset
        probe["route_pmtu_cache_reset_verified"] = bool(reset.get("verified"))
        return probe

    def _reset_route_pmtu_cache(
        self,
        source: Endpoint,
        source_ip: str,
        destination_ip: str,
        family: int,
        expected_mtu: int,
    ) -> dict[str, Any]:
        if not source.metadata.get("performance_local") and not callable(
            getattr(getattr(self, "builder", None), "ssh_endpoint", None)
        ):
            # Offline unit doubles can replace the probe without providing an
            # SSH-capable builder. This is never used by a real cloud endpoint.
            return {
                "attempted": False,
                "verified": True,
                "status": "not-applicable-offline-test-double",
                "family": family,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
            }
        code = self._route_cache_reset_code(
            source_ip, destination_ip, family, expected_mtu
        )
        try:
            return self._run_json(source, code, timeout=30)
        except RunCancelledError:
            raise
        except (SuiteError, OSError, subprocess.SubprocessError) as exc:
            return {
                "attempted": True,
                "verified": False,
                "error": f"{type(exc).__name__}: {exc}",
                "family": family,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
            }

    _route_cache_reset_code = staticmethod(route_cache_reset_code)

    def _mtu_probe(
        self,
        source: Endpoint,
        source_ip: str,
        destination_ip: str,
        family: int,
        expected_mtu: int,
    ) -> dict[str, Any]:
        code = self._mtu_client_code(source_ip, destination_ip, family, expected_mtu)
        return self._run_json(source, code, timeout=90)

    @staticmethod
    def _mtu_client_code(
        source_ip: str, destination_ip: str, family: int, expected_mtu: int
    ) -> str:
        return performance_probe_code(source_ip, destination_ip, family, expected_mtu)


__all__ = [
    "PerformancePath",
    "PerformanceRunner",
    "PerformanceSession",
    "ResolvedPerformancePath",
]
