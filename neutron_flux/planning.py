from __future__ import annotations

import hashlib

from .config import Config
from .errors import SuiteError, UnsupportedTopologyError
from .log import Logger
from .models import Discovery, Plan, PlannedGroup, TestSpec
from .network_contract import ROUTING_UNASSIGNED_PROJECT_NETWORK
from .planner_components.estimates import EstimatePlannerMixin
from .planner_components.groups import GroupPlannerMixin
from .planner_components.tests import TestSpecPlannerMixin
from .translation_safety import (
    floating_ip_target_sides,
    validate_plan_translation_safety,
)
from .utils import safe_name


class Planner(GroupPlannerMixin, TestSpecPlannerMixin, EstimatePlannerMixin):
    _reserved_synthetic_networks = None

    def __init__(self, config: Config, discovery: Discovery, logger: Logger):
        self.config = config
        self.discovery = discovery
        self.logger = logger

    @staticmethod
    def _id_token(value: str, limit: int = 30) -> str:
        """Return a readable, deterministic, collision-resistant identifier token."""
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
        stem_limit = max(1, limit - len(digest) - 1)
        return f"{safe_name(value, stem_limit)}-{digest}"

    def build(self) -> Plan:
        self.logger.section("Building adaptive topology-aware coverage plan")
        self._reserved_synthetic_networks = None
        skipped: list[dict[str, str]] = []
        warnings: list[str] = []
        providers = self._provider_groups(skipped)
        tenants = self._tenant_groups(providers, skipped)
        translations = self._private_translation_groups(skipped)
        # The owned private IPv4 translation topology already covers the same
        # unassigned fixed subnet and default-SNAT path as a generated control.
        covered_gateways = {group.external_subnet_id for group in translations}
        tenants = [
            group
            for group in tenants
            if not (
                group.kind == ROUTING_UNASSIGNED_PROJECT_NETWORK
                and group.families == [4]
                and not group.pool_id
                and group.external_subnet_id in covered_gateways
                and not self.config.no_routing_group_ipv4_cidr
            )
        ]
        tenants.extend(translations)
        # Internal routing does not require an external gateway of that family.
        # Both families use a usable pool or disjoint generated private subnets.
        # External/FIP tests are still gated by the selected provider subnets.
        routing_scenarios = self._routing_scenario_groups(skipped, {4, 6})
        tenants.extend(routing_scenarios)
        if not providers:
            raise UnsupportedTopologyError(
                "No usable external provider subnet was discovered"
            )
        if not any(4 in item.families for item in providers):
            raise UnsupportedTopologyError(
                "No usable external IPv4 subnet was discovered. Neutron Flux uses an IPv4 runner control path."
            )
        tests = self._test_specs(providers, tenants, warnings, skipped)
        for group in tenants:
            reason = group.metadata.get("external_checks_omitted_reason")
            if reason:
                skipped.append(
                    {
                        "resource": f"{group.label}: undeclared external paths",
                        "reason": str(reason),
                    }
                )
        ids = [item.id for item in tests]
        if len(ids) != len(set(ids)):
            duplicates = sorted({item for item in ids if ids.count(item) > 1})
            raise SuiteError(
                f"Planner generated duplicate test IDs: {', '.join(duplicates[:5])}"
            )

        estimated = self._estimate_plan(providers, tenants, tests)
        plan = Plan(
            providers, tenants, estimated, skipped, tests=tests, warnings=warnings
        )
        validate_plan_translation_safety(plan)
        if not self.config.selective_run:
            self._quota_preflight(plan)
        explicit_zone_scope = bool(
            self.config.availability_zones or self.config.availability_zones_all
        )
        if not (
            self.config.selective_run
            or explicit_zone_scope
            or self.config.host_qualification_enabled
        ):
            self._print_summary(plan)
        return plan

    def _estimate_plan(
        self,
        providers: list[PlannedGroup],
        tenants: list[PlannedGroup],
        tests: list[TestSpec],
    ) -> dict[str, int]:
        groups = [*providers, *tenants]
        attachments = sum(
            len(item.subnet_ids) if item.kind == "provider" else 1 for item in groups
        )
        controller_probe_ports = 1
        tenant_fips = len(
            {group_id for item in tests for group_id in floating_ip_target_sides(item)}
        )
        execution = self._execution_estimate(tests, groups)
        performance = (
            {
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
            if self.config.derived_tests_suppressed
            else self._performance_estimate(tests)
        )
        concurrent_load_pairs = (
            max(self.config.fabric_scale_pairs)
            if self.config.fabric_scale_enabled and not self.config.selective_run
            else 0
        )
        concurrent_load_peak_instances = (
            2 + (concurrent_load_pairs * 2) if concurrent_load_pairs else 0
        )
        concurrent_load_peak_ports = (
            4 + (concurrent_load_pairs * 6) if concurrent_load_pairs else 0
        )
        return {
            "endpoint_groups": len(groups),
            "provider_groups": len(providers),
            "project_network_groups": len(tenants),
            "attachments": attachments,
            "functional_test_results": len(tests),
            "test_results": len(tests),
            "estimated_result_rows": len(tests)
            + int(performance["performance_result_rows"]),
            "normal_peak_instances": 3,
            "peak_instances": max(4, concurrent_load_peak_instances),
            "peak_endpoint_instances": max(
                2,
                execution["peak_endpoint_instances"],
                concurrent_load_pairs * 2,
            ),
            "normal_peak_ports": (1 + controller_probe_ports + 4),
            "peak_ports": max(
                1 + controller_probe_ports + 2 + 4,
                concurrent_load_peak_ports,
            ),
            "normal_peak_volumes": 0 if self.config.storage == "host" else 3,
            "peak_volumes": (
                0
                if self.config.storage == "host"
                else max(4, concurrent_load_peak_instances)
            ),
            "peak_created_networks": max(
                1 + execution["peak_group_networks"], 1 + concurrent_load_pairs
            ),
            "peak_created_subnets": max(
                1 + execution["peak_group_subnets"], 1 + concurrent_load_pairs
            ),
            "peak_created_routers": max(
                execution["peak_group_routers"], concurrent_load_pairs
            ),
            "concurrent_load_pairs": concurrent_load_pairs,
            "concurrent_load_endpoint_boots": concurrent_load_pairs * 2,
            "peak_floating_ips": (
                2
                if any(s.operation == "fip-peer" for s in tests)
                else 1
                if tenant_fips
                else 0
            )
            + 1,
            "group_loads": execution["group_loads"],
            "endpoint_vm_boots": (
                execution["endpoint_vm_boots"] + (concurrent_load_pairs * 2)
            ),
            "provider_group_generations": execution["provider_group_generations"],
            "project_network_topology_generations": execution[
                "tenant_group_generations"
            ],
            "networks_created": (
                1 + execution["networks_created"] + concurrent_load_pairs
            ),
            "subnets_created": (
                1 + execution["subnets_created"] + concurrent_load_pairs
            ),
            "routers_created": (execution["routers_created"] + concurrent_load_pairs),
            "floating_ips_created": execution["fip_group_generations"] + 1,
            "security_groups_created": 4,
            "security_group_rules_peak": 24,
            **performance,
        }

    def recalculate(self, plan: Plan, *, quota_preflight: bool = True) -> Plan:
        plan.estimated = self._estimate_plan(
            plan.provider_groups, plan.tenant_groups, plan.tests
        )
        if quota_preflight:
            self._quota_preflight(plan)
        return plan

    def _print_summary(self, plan: Plan) -> None:
        if plan.selection_mode == "exact":
            self.logger.log(
                "Coverage mode: exact test selection; "
                f"{len(plan.requested_test_ids)} requested and "
                f"{len(plan.automatically_included_test_ids)} automatic control/prerequisite"
            )
        else:
            self.logger.log("Coverage mode: one adaptive topology-aware suite")
        self.logger.log(
            "IPv6 mode: explicit Neutron fixed addresses supplied by OpenStack; "
            "guest networking is verified read-only"
        )
        self.logger.log(
            "Control/data path: runner-to-controller access uses provider IPv4"
            + "; IPv6 tests originate between OpenStack endpoints, so native "
            "runner IPv6 is not required"
        )
        self.logger.log(
            "Availability-zone policy: "
            + (
                "run-wide selection restricted to: "
                + ", ".join(self.config.availability_zones)
                if self.config.availability_zones
                else "automatic run-wide non-internal AZ selection; nova is fallback only"
            )
        )
        labels = {
            "normal_peak_instances": "normal maximum concurrently existing instances",
            "peak_instances": "maximum concurrently existing instances",
            "peak_endpoint_instances": "maximum concurrently existing endpoint instances",
            "normal_peak_ports": "normal maximum concurrently existing ports",
            "peak_ports": "maximum concurrently existing ports",
            "normal_peak_volumes": "normal maximum concurrently existing volumes",
            "peak_volumes": "maximum concurrently existing volumes",
            "peak_created_networks": "maximum concurrently existing Flux-created networks",
            "peak_created_subnets": "maximum concurrently existing Flux-created subnets",
            "peak_created_routers": "maximum concurrently existing Flux-created routers",
            "peak_floating_ips": "maximum concurrently existing floating IPs",
            "group_loads": "total endpoint-group load operations over the run",
            "endpoint_vm_boots": "total endpoint VM boot operations over the run",
            "provider_group_generations": "total provider-group generations over the run",
            "project_network_topology_generations": (
                "total project-network topology generations over the run"
            ),
            "networks_created": "total network create operations over the run",
            "subnets_created": "total subnet create operations over the run",
            "routers_created": "total router create operations over the run",
            "floating_ips_created": "total floating-IP create operations over the run",
            "performance_path_candidates": "unique performance-capable logical paths before runtime reachability",
            "performance_paths_selected": "performance paths selected under the configured path limit",
            "performance_paths_omitted": "performance paths omitted by the explicit path limit",
            "floating_ip_performance_paths": "floating-IP performance paths",
            "performance_result_rows": "performance result rows if every selected path is reachable",
            "performance_estimated_seconds": "conservative performance execution seconds",
            "performance_estimated_seconds_minimum": "minimum performance execution seconds without UDP calibration backoff",
            "performance_estimated_seconds_maximum": "maximum performance execution seconds with configured UDP calibration backoff",
            "performance_topology_classes": "performance topology classes represented",
            "performance_execution_stages": "independently limited performance execution stages",
            "functional_test_results": "planned functional result rows",
            "estimated_result_rows": "total runtime result rows including selected performance measurements",
        }
        for key, value in plan.estimated.items():
            label = labels.get(key, key.replace(chr(95), chr(32)))
            self.logger.log(f"Estimated {label}: {value}")
        for warning in plan.warnings:
            self.logger.log(warning, "WARNING")
