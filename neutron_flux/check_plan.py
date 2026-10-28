"""Immutable logical checks, independent of runtime resources and sample IDs.

``tests`` remains the executor/evidence schedule. ``checks`` is the full approved
operator workload: every possible conditional assessment is reserved before boot.
Retries and sampling rounds bind to those checks and never enlarge this inventory.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import replace
from typing import Any

from .models import Plan, TestSpec

MEASUREMENTS = (
    ("tcp-throughput", "TCP throughput"),
    ("latency", "Idle and loaded latency"),
    ("udp", "UDP application-delivery loss, jitter, and packet rate"),
    ("mtu-mss", "Path MTU, PMTUD, and TCP MSS"),
    ("asymmetry", "Directional asymmetry"),
    ("concurrency", "Concurrent-flow scaling"),
    ("repeatability", "Path repeatability"),
)
BINDING_KEYS = ("planned_check_id", "check_bindings", "check_sample")


def migration_probe_spec(spec: TestSpec) -> TestSpec:
    """Read back a route-install connectivity assertion without changing routes."""
    if spec.operation != "static-route-install":
        return spec
    return replace(
        spec,
        operation="probe",
        display_name=(
            f"Two-router static-route connectivity — IPv{spec.family} "
            f"{spec.source_side} to {spec.destination_side} {str(spec.protocol).upper()}"
        ),
    )


def migration_baseline_specs(specs: list[TestSpec]) -> list[TestSpec]:
    """Connectivity is required for migration; packet-size observations are not."""
    return [
        spec
        for spec in specs
        if spec.authoritative
        and spec.operation
        in {"probe", "fip-baseline", "fip-peer", "static-route-install"}
        and spec.expectation == "reachable"
        and spec.protocol in {"icmp", "tcp", "udp"}
    ]


def migration_barrier_specs(specs: list[TestSpec]) -> list[TestSpec]:
    """Refresh peer connectivity and each selected external path before migration.

    External targets cannot replace the peer ICMP/TCP/UDP matrix that makes a
    migration eligible. A lifecycle recovery sample repeats the same external
    path, so refresh its ordinary assertion only once at the safety barrier.
    """
    return [
        *migration_baseline_specs(specs),
        *[
            spec
            for spec in specs
            if spec.operation == "egress"
            and spec.authoritative
            and spec.expectation == "reachable"
            and not spec.metadata.get("server_start_recovery")
        ],
    ]


def migration_batch_eligible(specs: list[TestSpec]) -> bool:
    """Migrate owned paths with declared connectivity across endpoint groups."""
    return (
        bool(specs)
        and specs[0].phase != "cross-zone"
        and (
            len(specs[0].dependencies) == 1
            or any(
                spec.operation in {"fip-baseline", "fip-peer"}
                or spec.metadata.get("require_no_floating_ip")
                or spec.category in {"provider-network-connectivity", "routed-provider"}
                or (
                    spec.category == "project-provider-connectivity"
                    and spec.authoritative
                    and spec.expectation == "reachable"
                )
                for spec in specs
            )
        )
    )


def migration_readback_specs(specs: list[TestSpec]) -> list[TestSpec]:
    """Replay measurements, never withdraw or restore a mapping during readback."""
    return [
        spec
        for spec in specs
        if spec.operation
        in {
            "probe",
            "fip-baseline",
            "fip-peer",
            "mtu-scenario",
            "snat-packet-size-profile",
            "static-route-install",
            "egress",
        }
        or spec.metadata.get("require_floating_ip")
        if not spec.metadata.get("server_start_recovery")
    ]


def cross_batch_key(spec: TestSpec) -> tuple[Any, ...]:
    # A router-SNAT profile requires no FIP. FIP mappings must survive placement
    # transitions, so these states cannot share a batch, even with the same VMs.
    floating = spec.operation.startswith("fip-") or bool(
        spec.metadata.get("require_floating_ip")
    )
    state = (
        ("source-without-fip", spec.source_group_id, spec.source_side)
        if spec.metadata.get("source_without_floating_ip")
        else floating
    )
    # Traffic direction belongs to the assertion, not to the physical topology.
    # Both directions must use the same endpoint generation and placement move.
    return (tuple(sorted(set(spec.dependencies))), endpoint_sides(spec), state)


def check_id(kind: str, identity: Any) -> str:
    raw = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return f"CHECK-{kind.upper()}-{hashlib.sha256(raw.encode()).hexdigest()[:24]}"


def batch_key(spec: TestSpec) -> tuple[Any, ...]:
    dependencies = tuple(sorted(set(spec.dependencies)))
    scope = (
        (spec.metadata["pair_scope_id"],)
        if spec.metadata.get("coordinated_pair")
        else ()
    )
    if spec.phase == "intra":
        return (spec.phase, dependencies, *scope)
    return (spec.phase, *cross_batch_key(spec), *scope)


def endpoint_sides(spec: TestSpec) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Use the same bounded endpoint requirements for planning and execution."""
    dependencies = tuple(sorted(set(spec.dependencies)))
    sides: dict[str, set[str]] = defaultdict(set)
    for group, side in (
        (spec.source_group_id, spec.source_side),
        (spec.destination_group_id, spec.destination_side),
    ):
        if group in dependencies:
            sides[str(group)].add(str(side or "A").upper())
    if (
        spec.operation == "fip-peer"
        and len(dependencies) == 1
        and spec.source_group_id == spec.destination_group_id
    ):
        # Own-FIP checks share the existing two-VM same-router batch. This also
        # preserves both endpoints while a host-pair workflow moves them.
        sides[str(spec.source_group_id)].update({"A", "B"})
    return tuple(
        (group, tuple(sorted(sides.get(group) or {"A"}))) for group in dependencies
    )


def _path_key(spec: TestSpec) -> tuple[Any, ...]:
    return (
        spec.source_group_id,
        spec.source_side,
        spec.source_subnet_id,
        spec.destination_group_id,
        spec.destination_side,
        spec.destination_subnet_id,
        spec.family,
    )


def copy_bindings(spec: TestSpec, approved: TestSpec) -> None:
    spec.metadata = {
        **spec.metadata,
        **{
            key: approved.metadata[key]
            for key in BINDING_KEYS
            if key in approved.metadata
        },
    }


def build_check_plan(plan: Plan, config: Any) -> None:
    """Expand once, after topology/zone/host selection, before approval."""
    if plan.checks:
        return
    checks: dict[str, dict[str, Any]] = {}
    groups = {group.id: group.label for group in plan.groups}

    context: dict[str, Any] = {}

    def add(
        identity: str,
        title: str,
        kind: str,
        stage: str,
        prerequisites: list[str],
        condition: str,
        **details: Any,
    ) -> str:
        if identity in checks:
            raise ValueError(f"Duplicate planned check: {identity}")
        checks[identity] = dict(
            id=identity,
            title=title,
            kind=kind,
            stage=stage,
            prerequisites=prerequisites,
            condition=condition,
            **{
                key: context[key]
                for key in (
                    "pair_scope_id",
                    "pair_placement",
                    "requested_source_host",
                    "requested_destination_host",
                    "host_qualification_cycle",
                )
                if key in context
            },
            **details,
        )
        return identity

    batches: dict[tuple[Any, ...], list[TestSpec]] = defaultdict(list)
    for spec in plan.tests:
        context = spec.metadata
        spec.metadata = {
            **spec.metadata,
            "planned_check_id": spec.id,
            "check_bindings": {},
        }
        add(
            spec.id,
            spec.display_name or spec.id,
            "migration" if spec.operation == "pair-transition" else "network",
            spec.phase,
            list(dict.fromkeys([*spec.requires, *spec.requires_pass])),
            "Required topology and prerequisites are available",
            category=spec.category,
            family=spec.family,
            host_pair_id=spec.metadata.get("host_qualification_pair_id"),
            cycle=spec.metadata.get("host_qualification_cycle"),
        )
        if spec.dependencies and spec.phase in {"intra", "cross", "cross-zone"}:
            batches[batch_key(spec)].append(spec)

    derived = not getattr(config, "derived_tests_suppressed", False)
    for key, specs in batches.items():
        metadata = specs[0].metadata
        context = metadata
        label = " + ".join(groups.get(item, item) for item in specs[0].dependencies)
        pair_label = metadata.get("pair_scope_id")
        if pair_label:
            label += f" / {pair_label}"
        bindings: dict[str, Any] = {}
        performance = (
            derived
            and config.performance_enabled
            and metadata.get("qualification_profile") != "connectivity"
        )
        placement = (
            derived
            and config.compute_host_connectivity_enabled
            and specs[0].phase != "cross-zone"
            and any(s.operation in {"probe", "fip-baseline", "fip-peer"} for s in specs)
        )
        if metadata.get("pair_scope_id"):
            placement = bool(
                placement
                and metadata.get("pair_placement") == "inter"
                and metadata.get("same_availability_zone")
                and metadata.get("qualification_strategy") != "stable"
                and metadata.get("qualification_profile") != "connectivity"
                and migration_batch_eligible(specs)
            )
        elif getattr(config, "target_host_pairs", None):
            placement = False
        if metadata.get("coordinated_pair"):
            placement = False
        baseline_ids = [spec.id for spec in migration_baseline_specs(specs)]
        has_reachable_baseline = bool(baseline_ids)
        migration = (
            placement and has_reachable_baseline and migration_batch_eligible(specs)
        )
        controls: dict[str, str] = {}
        base_ids = [spec.id for spec in specs]
        if placement:
            controls["HOST-DISCOVERY"] = add(
                check_id("placement", [key, "hosts"]),
                f"Discover endpoint compute placement — {label}",
                "migration",
                "placement",
                base_ids,
                "Endpoint pair is available",
            )
        if placement and not migration and has_reachable_baseline:
            controls["MIGRATION-BASELINE"] = add(
                check_id("placement", [key, "baseline"]),
                f"Verify functional connectivity baseline — {label}",
                "migration",
                "placement",
                baseline_ids,
                "Functional connectivity has been tested; cross-group placement is read-only",
            )
        if migration:
            live = getattr(config, "migration_mode", "live-preferred") != "cold-only"
            definitions = [
                (
                    "MIGRATION-BASELINE",
                    "Verify initial functional baseline",
                    "Functional connectivity has been tested",
                ),
                (
                    "MIGRATION-FUNCTIONAL-BASELINE",
                    "Verify fresh migration safety baseline",
                    "One fresh complete probe matrix; live recovery retries require verified rollback and source ownership",
                ),
                (
                    "MIGRATION",
                    "Migrate endpoint and verify requested placement",
                    "Eligible destination and successful safety baseline",
                ),
                (
                    "PORT-BINDING",
                    "Verify Neutron port binding after migration",
                    "Migration achieved the requested placement",
                ),
                (
                    "ENDPOINT-READY",
                    "Verify guest networking and readiness after migration",
                    "Migration achieved the requested placement",
                ),
            ]
            if live:
                definitions.append(
                    (
                        "LIVE-MIGRATION",
                        "Verify live migration capability",
                        "Eligible live migration destination and safety baseline",
                    )
                )
                if getattr(config, "live_migration_continuity", False):
                    definitions.append(
                        (
                            "LIVE-CONTINUITY",
                            "Measure live migration traffic continuity",
                            "Live migration completed",
                        )
                    )
            for name, title, condition in definitions:
                controls[name] = add(
                    check_id("migration", [key, name]),
                    f"{title} — {label}",
                    "migration",
                    "migration",
                    [spec.id for spec in migration_barrier_specs(specs)]
                    if name == "MIGRATION-FUNCTIONAL-BASELINE"
                    else baseline_ids,
                    condition,
                )
            for spec in specs:
                if spec in migration_readback_specs(specs):
                    identity = add(
                        check_id("post-migration", spec.id),
                        f"After migration: {migration_probe_spec(spec).display_name or spec.id}",
                        "migration",
                        "post-migration",
                        [controls["MIGRATION"]],
                        "Migration achieved the requested placement",
                        family=spec.family,
                    )
                    spec.metadata["check_bindings"]["post-migration"] = identity
        if controls:
            bindings["placement"] = controls
            for spec in specs:
                spec.metadata["check_bindings"].update(bindings)
        if not performance:
            continue
        stage = {
            "intra": "group-local",
            "cross": "cross-topology",
            "cross-zone": "cross-zone",
        }[specs[0].phase]
        stages = [stage]
        if (
            migration
            and getattr(config, "migration_mode", "live-preferred") != "cold-only"
        ):
            stages.append("post-live-migration")
        candidates = [
            spec
            for spec in specs
            if spec.operation in {"probe", "fip-baseline"}
            and spec.expectation == "reachable"
            and spec.authoritative
            and spec.family in {4, 6}
            and spec.protocol == "tcp"
            and spec.destination_group_id
            and (spec.operation == "fip-baseline" or spec.source_group_id)
        ]
        endpoint_keys = {
            _path_key(spec) for spec in candidates if spec.operation == "probe"
        }
        candidates = [
            spec
            for spec in candidates
            if spec.operation == "fip-baseline"
            or (*_path_key(spec)[3:6], *_path_key(spec)[:3], spec.family)
            in endpoint_keys
        ]
        paths: dict[str, list[TestSpec]] = defaultdict(list)
        for spec in candidates:
            path_tuple = _path_key(spec)
            path_identity = (
                ["fip", spec.destination_group_id, spec.family]
                if spec.operation == "fip-baseline"
                else sorted(
                    [
                        list(path_tuple),
                        list((*path_tuple[3:6], *path_tuple[:3], path_tuple[6])),
                    ],
                    key=str,
                )
            )
            paths[json.dumps(path_identity)].append(spec)
        for path_token, sources in paths.items():
            floating = sources[0].operation == "fip-baseline"
            # One logical path holds both directions and all of its measurements.
            source_ids = [spec.id for spec in sources]
            for perf_stage in stages:
                prerequisites = (
                    source_ids
                    if perf_stage != "post-live-migration"
                    else [
                        spec.metadata["check_bindings"]["post-migration"]
                        for spec in sources
                    ]
                )
                mapping = {}
                for measurement, title in MEASUREMENTS:
                    if floating and measurement == "asymmetry":
                        continue
                    identity = check_id(
                        "performance", [key, path_token, perf_stage, measurement]
                    )
                    mapping[measurement] = add(
                        identity,
                        f"{title} — {label} — IPv{sources[0].family}",
                        "performance",
                        perf_stage,
                        prerequisites,
                        (
                            "Authoritative floating-IP ingress passed"
                            if floating
                            else "Both TCP directions passed in the same measurement window"
                        )
                        + (
                            f"; selected within the {config.performance_max_paths}-path stage limit"
                            if config.performance_max_paths > 0
                            else ""
                        )
                        + (
                            "; live migration completed"
                            if perf_stage == "post-live-migration"
                            else ""
                        ),
                        measurement=measurement,
                        family=sources[0].family,
                    )
                for spec in sources:
                    spec.metadata["check_bindings"].setdefault("performance", {})[
                        perf_stage
                    ] = mapping

    if derived and config.fabric_scale_enabled and not config.selective_run:
        scopes: dict[str, TestSpec] = {}
        for spec in plan.tests:
            if spec.scenario == "Controller readiness" or spec.phase == "cross-zone":
                continue
            if spec.metadata.get("qualification_profile") == "connectivity":
                continue
            zone = spec.metadata.get("availability_zone", "")
            pair = spec.metadata.get("pair_scope_id", "")
            scope = json.dumps([zone, pair])
            scopes.setdefault(scope, spec)
        for scope in scopes:
            context = scopes[scope].metadata
            identity = add(
                check_id("load", scope),
                "Concurrent VM-pair load",
                "load",
                "concurrent-path-load",
                [],
                "Requested VM pairs can be created; configured load levels are samples",
            )
            for spec in plan.tests:
                if (
                    json.dumps(
                        [
                            spec.metadata.get("availability_zone", ""),
                            spec.metadata.get("pair_scope_id", ""),
                        ]
                    )
                    == scope
                ):
                    spec.metadata["check_bindings"]["load"] = identity
    plan.checks = list(checks.values())
    plan.estimated["planned_checks"] = len(plan.checks)
    plan.estimated["conditional_checks"] = sum(
        row["kind"] != "network" for row in plan.checks
    )


def describe_check_plan(plan: Plan, logger: Any) -> None:
    if not plan.checks:
        return
    counts = Counter(row["kind"] for row in plan.checks)
    logger.log(
        f"Planned: {len(plan.checks)} checks (fixed after discovery and selection)"
    )
    for kind, title in (
        ("network", "network and controller checks"),
        ("performance", "performance checks"),
        ("migration", "placement, migration and recovery checks"),
        ("load", "concurrent VM-pair load checks"),
    ):
        if counts[kind]:
            logger.log(f"  {counts[kind]} {title}")
    if counts["performance"]:
        logger.log(
            "  Performance: TCP throughput, idle/loaded latency, UDP delivery, "
            "MTU/MSS, asymmetry, concurrent flows and repeatability; requires proven connectivity."
        )
    if counts["migration"]:
        logger.log(
            "  Migration: host placement, functional safety baseline, migration, "
            "port binding, guest readiness, configured live continuity and post-migration checks; "
            "requires an eligible destination and a safe instance state."
        )
    logger.log(
        "Conditional checks are included above. Unmet conditions finish as blocked or "
        "not applicable, with a reason. Retries and samples stay within these checks."
    )
