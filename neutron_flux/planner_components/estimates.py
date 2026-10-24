from __future__ import annotations

from collections import defaultdict
from typing import Any

# mypy: disable-error-code="attr-defined"
from ..check_plan import cross_batch_key
from ..constants import MIN_TEST_RAM_MB
from ..errors import UnsupportedTopologyError
from ..models import Plan, PlannedGroup, TestSpec
from ..network_contract import (
    ONE_ROUTER_PROJECT_NETWORKS,
    PRIVATE_TRANSLATION_PROJECT_NETWORK,
    PROJECT_NETWORK,
    ROUTING_UNASSIGNED_PROJECT_NETWORK,
    TWO_ROUTER_STATIC_ROUTING,
    canonical_group_kind,
)
from ..translation_safety import floating_ip_target_sides
from ..utils import safe_name

_PERFORMANCE_CATEGORY_PRIORITY = {
    "project-network-routing": 0,
    "tenant-router": 0,
    "routed-provider": 1,
    "project-provider-connectivity": 2,
    "tenant-provider-connectivity": 2,
    "same-subnet": 3,
    "provider-network-connectivity": 4,
    "router-extra-route": 5,
    "router-static-routing": 5,
    "cross-zone-connectivity": 6,
}


def _performance_execution_scope(spec: TestSpec) -> tuple[str, str]:
    metadata = spec.metadata or {}
    if spec.phase == "cross-zone":
        return "cross-zone", "cross-zone"
    zone = str(metadata.get("availability_zone") or "").strip()
    scope = f"zone:{zone}" if zone else "single-scope"
    if metadata.get("coordinated_pair"):
        scope += ":" + str(metadata["pair_scope_id"])
    stage = (
        "group-local"
        if spec.phase == "intra"
        else "cross-topology"
        if spec.phase == "cross"
        else str(spec.phase or "runtime")
    )
    return scope, stage


def performance_estimate(config: object, tests: list[TestSpec]) -> dict[str, int]:
    """Estimate runtime performance rows using the executor's real selection rules.

    The path limit is applied independently to each execution-session/stage pair,
    matching one PerformanceSession per AZ lane and one shared cross-AZ session.
    Endpoint paths require passed specifications in both directions; floating-IP
    ingress paths remain forward-only. Disabled performance has no candidate
    paths, result rows, or execution time, even when functional probes exist.
    """

    if not getattr(config, "performance_enabled", True):
        tests = []

    candidates = [
        spec
        for spec in tests
        if spec.operation in {"probe", "fip-baseline"}
        and spec.expectation == "reachable"
        and spec.authoritative
        and spec.protocol == "tcp"
        and spec.family in {4, 6}
        and spec.destination_group_id
        and (spec.operation == "fip-baseline" or spec.source_group_id)
    ]
    by_scope_stage: defaultdict[tuple[str, str], list[TestSpec]] = defaultdict(list)
    for spec in candidates:
        by_scope_stage[_performance_execution_scope(spec)].append(spec)

    configured_limit = int(getattr(config, "performance_max_paths", 0) or 0)
    selected_records: list[tuple[TestSpec, bool]] = []
    eligible_records: list[tuple[TestSpec, bool]] = []
    topology_classes: set[str] = set()
    independently_limited_stages = 0

    for (_scope, _stage), scoped_specs in sorted(by_scope_stage.items()):
        scoped_specs.sort(
            key=lambda item: (
                _PERFORMANCE_CATEGORY_PRIORITY.get(item.category, 99),
                item.id,
            )
        )
        endpoint_keys = {
            (
                spec.source_group_id,
                spec.source_side,
                spec.source_subnet_id,
                spec.destination_group_id,
                spec.destination_side,
                spec.destination_subnet_id,
                spec.family,
            )
            for spec in scoped_specs
            if spec.operation == "probe"
        }
        seen: set[tuple[object, ...]] = set()
        records: list[tuple[TestSpec, bool]] = []
        for spec in scoped_specs:
            if spec.operation == "fip-baseline":
                signature = (
                    "floating-ip",
                    spec.destination_group_id,
                    spec.metadata.get("floating_ip_subnet_id"),
                    spec.family,
                )
                reverse = signature
                floating = True
            else:
                signature = (
                    spec.source_group_id,
                    spec.source_side,
                    spec.source_subnet_id,
                    spec.destination_group_id,
                    spec.destination_side,
                    spec.destination_subnet_id,
                    spec.family,
                )
                reverse = (
                    spec.destination_group_id,
                    spec.destination_side,
                    spec.destination_subnet_id,
                    spec.source_group_id,
                    spec.source_side,
                    spec.source_subnet_id,
                    spec.family,
                )
                if reverse not in endpoint_keys:
                    continue
                floating = False
            if signature in seen or reverse in seen:
                continue
            seen.add(signature)
            records.append((spec, floating))
            topology_classes.add(spec.category)
        if records:
            independently_limited_stages += 1
        eligible_records.extend(records)
        chosen = records[:configured_limit] if configured_limit > 0 else records
        selected_records.extend(chosen)

    selected = len(selected_records)
    eligible = len(eligible_records)
    selected_floating = sum(1 for _, floating in selected_records if floating)
    floating_total = sum(1 for _, floating in eligible_records if floating)

    duration = int(getattr(config, "performance_duration_seconds", 0) or 0)
    repeats = int(getattr(config, "performance_repeats", 0) or 0)
    tcp_streams = list(getattr(config, "performance_tcp_streams", []) or [])
    tcp_runs_per_direction = (
        1 + repeats + sum(1 for item in tcp_streams if int(item) != 1)
    )
    ping_count = int(getattr(config, "performance_ping_count", 0) or 0)
    ping_warmup = int(getattr(config, "performance_ping_warmup_count", 0) or 0)
    ping_seconds = max(1, (ping_count + ping_warmup + 4) // 5)
    loaded_seconds = max(duration, ((ping_count + ping_warmup + 4) // 5) + 2)
    udp_rates = len(list(getattr(config, "performance_udp_rates_mbps", []) or []))
    # Runtime adds one near-MTU datagram size unless it already exists. The
    # estimate intentionally budgets it because the expected MTU is discovered
    # only when concrete endpoints are available.
    udp_sizes = len(set(getattr(config, "performance_udp_packet_sizes", []) or [])) + 1
    adaptive = bool(getattr(config, "performance_udp_adaptive_calibration", True))
    max_udp_attempts = (
        int(getattr(config, "performance_udp_calibration_max_attempts", 1) or 1)
        if adaptive
        else 1
    )

    minimum_seconds = 0
    maximum_seconds = 0
    for _spec, floating in selected_records:
        directions = 1 if floating else 2
        tcp_seconds = directions * tcp_runs_per_direction * duration
        if directions == 2:
            tcp_seconds += duration  # simultaneous bidirectional sample
        latency_seconds = directions * (ping_seconds + loaded_seconds)
        udp_base = directions * udp_rates * udp_sizes * duration
        # MTU/fragmentation probes are bounded commands rather than fixed-duration
        # loads. Twenty seconds per direction is a conservative planning allowance.
        mtu_seconds = directions * 20
        orchestration_seconds = 10
        minimum_seconds += (
            tcp_seconds
            + latency_seconds
            + udp_base
            + mtu_seconds
            + orchestration_seconds
        )
        maximum_seconds += (
            tcp_seconds
            + latency_seconds
            + (udp_base * max(1, max_udp_attempts) * (2 if directions == 2 else 1))
            + mtu_seconds
            + orchestration_seconds
        )

    return {
        "performance_path_candidates": eligible,
        "performance_paths_selected": selected,
        "performance_paths_omitted": eligible - selected,
        "floating_ip_performance_paths": floating_total,
        "performance_result_rows": selected * 7 - selected_floating,
        "performance_estimated_seconds": maximum_seconds,
        "performance_estimated_seconds_minimum": minimum_seconds,
        "performance_estimated_seconds_maximum": maximum_seconds,
        "performance_topology_classes": len(topology_classes),
        "performance_execution_stages": independently_limited_stages,
    }


class EstimatePlannerMixin:
    """Compatibility mixin for this planning concern."""

    def _execution_estimate(
        self,
        tests: list[TestSpec],
        groups: list[PlannedGroup],
    ) -> dict[str, int]:
        """Simulate the adaptive scheduler to estimate actual group generations."""
        group_by_id = {item.id: item for item in groups}
        loads: defaultdict[str, int] = defaultdict(int)
        endpoint_vm_boots = 0

        intra_group_ids: list[str] = []
        seen_intra: set[str] = set()
        for spec in tests:
            if spec.phase == "intra" and len(spec.dependencies) == 1:
                group_id = spec.dependencies[0]
                if group_id not in seen_intra:
                    seen_intra.add(group_id)
                    intra_group_ids.append(group_id)
        for group_id in intra_group_ids:
            loads[group_id] += 1
            endpoint_vm_boots += 2

        batches: list[tuple[Any, ...]] = []
        seen_batches: set[tuple[Any, ...]] = set()
        for spec in tests:
            if spec.phase != "cross" or not spec.dependencies:
                continue
            key = cross_batch_key(spec)
            if key not in seen_batches:
                seen_batches.add(key)
                batches.append(key)
        remaining = list(batches)
        active: dict[str, tuple[str, ...]] = {}
        active_hosts: dict[str, str | None] = {}
        ordered: list[tuple[Any, ...]] = []
        peak_endpoint_instances = 2 if intra_group_ids else 0
        max_concurrent_tenant_groups = (
            1
            if any(
                group_by_id[group_id].kind != "provider" for group_id in intra_group_ids
            )
            else 0
        )
        while remaining:
            remaining.sort(
                key=lambda item: (
                    -len(set(active).intersection(item[0])),
                    len(item[0]),
                    tuple(
                        safe_name(group_by_id[group_id].label) for group_id in item[0]
                    ),
                )
            )
            selected = remaining.pop(0)
            ordered.append(selected)
            dependencies, side_signature, _floating = selected
            requested_sides = dict(side_signature)
            required_hosts = {
                group_id: (
                    group_by_id[group_id].metadata.get("pair_scope_hosts")
                    or [None, None]
                )[index if len(dependencies) == 2 else 0]
                for index, group_id in enumerate(dependencies)
            }
            for group_id in dependencies:
                sides = requested_sides[group_id]
                if (
                    active.get(group_id) != sides
                    or active_hosts.get(group_id) != required_hosts[group_id]
                ):
                    loads[group_id] += 1
                    endpoint_vm_boots += len(sides)
            active = {group_id: requested_sides[group_id] for group_id in dependencies}
            active_hosts = required_hosts
            peak_endpoint_instances = max(
                peak_endpoint_instances,
                sum(len(sides) for sides in active.values()),
            )
            max_concurrent_tenant_groups = max(
                max_concurrent_tenant_groups,
                sum(
                    1
                    for group_id in dependencies
                    if group_by_id[group_id].kind != "provider"
                ),
            )

        fip_sides: defaultdict[str, set[str]] = defaultdict(set)
        for spec in tests:
            for group_id, sides in floating_ip_target_sides(spec).items():
                fip_sides[group_id].update(sides)
        provider_generations = sum(
            count
            for group_id, count in loads.items()
            if group_by_id[group_id].kind == "provider"
        )
        tenant_generations = sum(
            count
            for group_id, count in loads.items()
            if group_by_id[group_id].kind != "provider"
        )
        resource_weights = {
            "provider": (0, 0, 0),
            PROJECT_NETWORK: (1, 1, 1),
            ROUTING_UNASSIGNED_PROJECT_NETWORK: (1, 1, 1),
            ONE_ROUTER_PROJECT_NETWORKS: (2, 2, 1),
            TWO_ROUTER_STATIC_ROUTING: (3, 3, 2),
            PRIVATE_TRANSLATION_PROJECT_NETWORK: (1, 1, 1),
        }
        networks_created = 0
        subnets_created = 0
        routers_created = 0
        peak_group_networks = 0
        peak_group_subnets = 0
        peak_group_routers = 0
        for group_id, count in loads.items():
            weights = resource_weights.get(
                canonical_group_kind(group_by_id[group_id].kind),
                (1, 1, 1),
            )
            networks_created += weights[0] * count
            subnets_created += weights[1] * count
            routers_created += weights[2] * count
            peak_group_networks = max(peak_group_networks, weights[0])
            peak_group_subnets = max(peak_group_subnets, weights[1])
            peak_group_routers = max(peak_group_routers, weights[2])
        for dependencies, _sides, _floating in ordered:
            weights = [
                resource_weights.get(
                    canonical_group_kind(group_by_id[group_id].kind), (1, 1, 1)
                )
                for group_id in dependencies
            ]
            peak_group_networks = max(peak_group_networks, sum(w[0] for w in weights))
            peak_group_subnets = max(peak_group_subnets, sum(w[1] for w in weights))
            peak_group_routers = max(peak_group_routers, sum(w[2] for w in weights))
        return {
            "group_loads": sum(loads.values()),
            "endpoint_vm_boots": endpoint_vm_boots,
            "provider_group_generations": provider_generations,
            "tenant_group_generations": tenant_generations,
            "fip_group_generations": sum(
                loads[group_id] * len(sides) for group_id, sides in fip_sides.items()
            ),
            "cross_batches": len(ordered),
            "max_concurrent_tenant_groups": max_concurrent_tenant_groups,
            "networks_created": networks_created,
            "subnets_created": subnets_created,
            "routers_created": routers_created,
            "peak_group_networks": peak_group_networks,
            "peak_group_subnets": peak_group_subnets,
            "peak_group_routers": peak_group_routers,
            "peak_endpoint_instances": peak_endpoint_instances,
        }

    def _performance_estimate(self, tests: list[TestSpec]) -> dict[str, int]:
        return performance_estimate(self.config, tests)

    def _quota_preflight(self, plan: Plan) -> None:
        needs = {
            "instances": plan.estimated["peak_instances"],
            "cores": plan.estimated["peak_instances"],
            "ram": plan.estimated["peak_instances"] * MIN_TEST_RAM_MB,
            "ports": plan.estimated["peak_ports"],
            "networks": plan.estimated["peak_created_networks"],
            "subnets": plan.estimated["peak_created_subnets"],
            "routers": plan.estimated["peak_created_routers"],
            "floating_ips": plan.estimated["peak_floating_ips"],
            "security_groups": plan.estimated["security_groups_created"],
            "security_group_rules": plan.estimated["security_group_rules_peak"],
            "key_pairs": 1,
        }
        if self.config.storage == "volume":
            needs["volumes"] = plan.estimated["peak_volumes"]
            needs["gigabytes"] = (
                plan.estimated["peak_volumes"] * self.config.volume_size
            )
        shortages: list[str] = []
        for resource, required in needs.items():
            quota = self.discovery.quota_info.get(resource)
            if quota and quota.available is not None and quota.available < required:
                shortages.append(
                    f"{resource}: need {required}, available {quota.available}"
                )
        if shortages:
            raise UnsupportedTopologyError(
                "Quota preflight failed before resource creation: "
                + "; ".join(shortages)
            )
