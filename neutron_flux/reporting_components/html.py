from __future__ import annotations

import dataclasses
import datetime as dt
import html as html_lib
import json
import math
import pathlib
from collections import Counter, defaultdict
from typing import Any

from ..check_ledger import check_ledger
from ..constants import (
    DISPLAY_VERSION,
    RELEASE_IDENTIFIER,
    RELEASE_REVISION,
)
from ..errors import SuiteError
from ..junit_report import build_junit
from ..mtu_contract import confirmed_no_fragment_path_mtu
from ..operator_explanations import (
    explain_result,
    lifecycle_explanations,
    operator_overview,
)
from ..performance_metrics import udp_sample_assessable
from ..plan_contract import plan_dict
from ..progress import reporter_progress
from ..replay_plan import build_replay_plan, render_replay_plan_text
from ..report_exports import (
    render_host_qualification_csv,
    render_incident_summary,
)
from ..result_contract import typed_verdict
from ..results_io import atomic_write_text
from ..scheduling import timing_summary
from .dashboard_model import build_dashboard_model
from .evidence_pool import pool_evidence
from .html_template import HTML_TEMPLATE
from .operator_context import contextual_results
from .report_payload import (
    DASHBOARD_MODEL_VERSION,
    REPORT_MODEL_VERSION,
    build_report_payload,
)
from .tcp_summary import tcp_retransmission_summary


def _atomic_write(path: pathlib.Path, content: str) -> None:
    atomic_write_text(path, content)


def _json_value(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return {
            field.name: _json_value(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return [_json_value(item) for item in sorted(value, key=repr)]
    if isinstance(value, pathlib.Path):
        return str(value)
    if isinstance(value, (dt.datetime, dt.date)):
        return value.isoformat()
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    return repr(value)


def _performance_summary(performance: list[dict[str, Any]]) -> dict[str, Any]:
    throughput: list[float] = []
    concurrency: list[float] = []
    idle_p95: list[float] = []
    loaded_ratios: list[float] = []
    udp_loss: list[float] = []
    udp_endpoint_loss: list[float] = []
    udp_excluded_samples = 0
    udp_jitter: list[float] = []
    udp_mbps: list[float] = []
    udp_pps: list[float] = []
    fairness: list[float] = []
    asymmetry: list[float] = []
    repeatability: list[float] = []
    mtu_mismatches = 0
    load_pair_levels: list[int] = []
    load_aggregate: list[float] = []
    load_fairness: list[float] = []
    load_icmp_loss: list[float] = []
    load_udp_application_loss: list[float] = []
    load_pair_throughput: list[float] = []
    load_degradation: list[float] = []
    load_loaded_ratios: list[float] = []
    load_udp_jitter: list[float] = []
    load_loaded_aggregate: list[float] = []
    load_clean_retransmissions: list[float] = []
    load_loaded_retransmissions: list[float] = []
    path_ids: set[str] = set()

    def number(value: Any) -> float | None:
        if isinstance(value, bool):
            return None
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            return None
        return parsed if math.isfinite(parsed) else None

    for item in performance:
        details = item.get("details") or {}
        metrics = details.get("metrics") or {}
        path = details.get("path") or {}
        path_id = path.get("path_id")
        if path_id:
            path_ids.add(str(path_id))
        measurement = details.get("measurement")
        if measurement == "tcp-throughput":
            for direction in ("forward", "reverse"):
                value = number(
                    (
                        ((metrics.get(direction) or {}).get("streams") or {}).get("1")
                        or {}
                    ).get("median_mbps")
                )
                if value is not None:
                    throughput.append(value)
        elif measurement == "concurrency":
            for direction in ("forward", "reverse"):
                direction_metrics = metrics.get(direction) or {}
                value = number(direction_metrics.get("best_aggregate_mbps"))
                if value is not None:
                    concurrency.append(value)
                for stream_count, sample in (
                    direction_metrics.get("fairness") or {}
                ).items():
                    if str(stream_count) == "1":
                        continue
                    parsed = number(sample)
                    if parsed is not None:
                        fairness.append(parsed)
        elif measurement == "latency":
            for direction in ("forward", "reverse"):
                value = number(
                    ((metrics.get("idle") or {}).get(direction) or {}).get("p95_ms")
                )
                if value is not None:
                    idle_p95.append(value)
                ratio = number((metrics.get("loaded_p95_ratio") or {}).get(direction))
                if ratio is not None:
                    loaded_ratios.append(ratio)
        elif measurement == "udp":
            for direction in ("forward", "reverse"):
                for sample in metrics.get(direction) or []:
                    if not udp_sample_assessable(sample):
                        udp_excluded_samples += 1
                        if sample.get("packet_size_supported") is not False and (
                            sample.get("endpoint_limited") is True
                            or sample.get("load_valid") is False
                        ):
                            endpoint_loss = number(sample.get("loss_pct"))
                            if endpoint_loss is not None:
                                udp_endpoint_loss.append(endpoint_loss)
                        continue
                    loss = number(sample.get("loss_pct"))
                    jitter = number(sample.get("jitter_ms"))
                    if loss is not None:
                        udp_loss.append(loss)
                    if jitter is not None:
                        udp_jitter.append(jitter)
                    achieved = number(
                        sample.get("receiver_goodput_mbps", sample.get("mbps"))
                    )
                    packet_rate = number(sample.get("pps"))
                    if achieved is not None:
                        udp_mbps.append(achieved)
                    if packet_rate is not None:
                        udp_pps.append(packet_rate)
        elif measurement == "mtu-mss":
            expected = number(metrics.get("expected_mtu"))
            discovered_values = [
                number(confirmed_no_fragment_path_mtu(metrics.get(direction) or {}))
                for direction in ("forward", "reverse")
            ]
            if expected is not None and any(
                value is not None and value < expected for value in discovered_values
            ):
                mtu_mismatches += 1
        elif measurement == "asymmetry":
            for key in ("throughput_difference_pct", "latency_difference_pct"):
                value = number(metrics.get(key))
                if value is not None:
                    asymmetry.append(value)
        elif measurement == "repeatability":
            value = number(metrics.get("worst_variation_pct"))
            if value is not None:
                repeatability.append(value)
        elif measurement in {"concurrent-path-load", "fabric-scale"}:
            for level in metrics.get("levels") or []:
                pair_count = number(level.get("pairs"))
                aggregate_value = number(level.get("median_aggregate_mbps"))
                fairness_value = number(level.get("minimum_fairness"))
                icmp_loss_value = number(level.get("maximum_loaded_icmp_loss_pct"))
                udp_loss_value = number(
                    level.get("maximum_loaded_udp_application_loss_pct")
                )
                if udp_loss_value is None:
                    udp_loss_value = number(level.get("maximum_loaded_udp_loss_pct"))
                # Old manifests exposed one combined value. Treat it as the
                # historical UDP display fallback only; never infer ICMP loss
                # from it in a new report.
                if udp_loss_value is None:
                    udp_loss_value = number(level.get("maximum_loaded_loss_pct"))
                pair_value = number(level.get("median_pair_mbps"))
                degradation_value = number(level.get("per_pair_degradation_pct"))
                loaded_ratio_value = number(level.get("median_loaded_latency_ratio"))
                udp_jitter_value = number(level.get("maximum_loaded_udp_jitter_ms"))
                loaded_aggregate_value = number(
                    level.get("median_loaded_tcp_aggregate_mbps")
                )
                clean_retransmissions_value = number(level.get("total_retransmissions"))
                loaded_retransmissions_value = number(
                    level.get("total_loaded_retransmissions")
                )
                if pair_count is not None:
                    load_pair_levels.append(int(pair_count))
                if aggregate_value is not None:
                    load_aggregate.append(aggregate_value)
                if fairness_value is not None:
                    load_fairness.append(fairness_value)
                if icmp_loss_value is not None:
                    load_icmp_loss.append(icmp_loss_value)
                if udp_loss_value is not None:
                    load_udp_application_loss.append(udp_loss_value)
                if pair_value is not None:
                    load_pair_throughput.append(pair_value)
                if degradation_value is not None:
                    load_degradation.append(degradation_value)
                if loaded_ratio_value is not None:
                    load_loaded_ratios.append(loaded_ratio_value)
                if udp_jitter_value is not None:
                    load_udp_jitter.append(udp_jitter_value)
                if loaded_aggregate_value is not None:
                    load_loaded_aggregate.append(loaded_aggregate_value)
                if clean_retransmissions_value is not None:
                    load_clean_retransmissions.append(clean_retransmissions_value)
                if loaded_retransmissions_value is not None:
                    load_loaded_retransmissions.append(loaded_retransmissions_value)

    return {
        "paths": len(path_ids),
        "warning_results": sum(
            1
            for item in performance
            if item.get("status") == "PASS"
            and (item.get("details") or {}).get("health") == "warning"
        ),
        "lowest_single_stream_mbps": min(throughput) if throughput else None,
        "highest_single_stream_mbps": max(throughput) if throughput else None,
        **tcp_retransmission_summary(performance),
        "best_concurrent_mbps": max(concurrency) if concurrency else None,
        "highest_idle_p95_ms": max(idle_p95) if idle_p95 else None,
        "worst_loaded_latency_ratio": max(loaded_ratios) if loaded_ratios else None,
        "worst_udp_loss_pct": max(udp_loss) if udp_loss else None,
        "worst_endpoint_limited_udp_loss_pct": max(udp_endpoint_loss)
        if udp_endpoint_loss
        else None,
        "excluded_udp_samples": udp_excluded_samples,
        "worst_udp_jitter_ms": max(udp_jitter) if udp_jitter else None,
        "best_udp_mbps": max(udp_mbps) if udp_mbps else None,
        "best_udp_pps": max(udp_pps) if udp_pps else None,
        "lowest_concurrent_fairness": min(fairness) if fairness else None,
        "worst_directional_asymmetry_pct": max(asymmetry) if asymmetry else None,
        "worst_repeatability_variation_pct": max(repeatability)
        if repeatability
        else None,
        "mtu_mismatch_paths": mtu_mismatches,
        "concurrent_load_max_pairs": max(load_pair_levels)
        if load_pair_levels
        else None,
        "concurrent_load_highest_observed_aggregate_mbps": max(load_aggregate)
        if load_aggregate
        else None,
        "concurrent_load_lowest_fairness": min(load_fairness)
        if load_fairness
        else None,
        "concurrent_load_worst_loaded_icmp_loss_pct": max(load_icmp_loss)
        if load_icmp_loss
        else None,
        "concurrent_load_worst_loaded_udp_application_loss_pct": max(
            load_udp_application_loss
        )
        if load_udp_application_loss
        else None,
        # Compatibility alias for existing consumers. New manifests and UI
        # label this specifically as UDP application-delivery loss.
        "concurrent_load_worst_loaded_loss_pct": max(load_udp_application_loss)
        if load_udp_application_loss
        else None,
        "concurrent_load_lowest_pair_mbps": min(load_pair_throughput)
        if load_pair_throughput
        else None,
        "concurrent_load_worst_degradation_pct": max(load_degradation)
        if load_degradation
        else None,
        "concurrent_load_worst_loaded_latency_ratio": max(load_loaded_ratios)
        if load_loaded_ratios
        else None,
        "concurrent_load_worst_udp_jitter_ms": max(load_udp_jitter)
        if load_udp_jitter
        else None,
        "concurrent_load_highest_observed_loaded_tcp_aggregate_mbps": (
            max(load_loaded_aggregate) if load_loaded_aggregate else None
        ),
        "concurrent_load_worst_clean_retransmissions": (
            max(load_clean_retransmissions) if load_clean_retransmissions else None
        ),
        "concurrent_load_worst_loaded_retransmissions": (
            max(load_loaded_retransmissions) if load_loaded_retransmissions else None
        ),
    }


def _performance_coverage(
    events: list[dict[str, Any]],
    performance: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    stages: dict[str, dict[str, Any]] = {}
    topologies: dict[str, dict[str, int]] = {}
    total_eligible = 0
    total_selected = 0
    total_omitted = 0
    configured_limits: set[int] = set()
    for event in events:
        if str(event.get("type") or "") != "performance-coverage":
            continue
        details = event.get("details") or {}
        if not isinstance(details, dict):
            details = event
        stage = str(details.get("stage") or "unknown")
        eligible = int(details.get("eligible_paths") or 0)
        selected = int(details.get("selected_paths") or 0)
        omitted = int(details.get("omitted_paths") or 0)
        limit = int(details.get("configured_max_paths") or 0)
        configured_limits.add(limit)
        row = stages.setdefault(
            stage,
            {
                "eligible": 0,
                "selected": 0,
                "omitted": 0,
                "configured_max_paths": limit,
                "unlimited": bool(details.get("unlimited", limit == 0)),
            },
        )
        row["eligible"] += eligible
        row["selected"] += selected
        row["omitted"] += omitted
        total_eligible += eligible
        total_selected += selected
        total_omitted += omitted
        for field, key in (
            ("eligible_by_topology", "eligible"),
            ("selected_by_topology", "selected"),
            ("omitted_by_topology", "omitted"),
        ):
            values = details.get(field) or {}
            if not isinstance(values, dict):
                continue
            for topology, value in values.items():
                target = topologies.setdefault(
                    str(topology),
                    {
                        "eligible": 0,
                        "selected": 0,
                        "omitted": 0,
                        "completed": 0,
                        "failed": 0,
                        "errors": 0,
                        "unverified": 0,
                        "incomplete": 0,
                    },
                )
                target[key] += int(value or 0)

    by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for result in performance or []:
        details = result.get("details") or {}
        if not isinstance(details, dict):
            continue
        path = details.get("path") or {}
        if not isinstance(path, dict):
            continue
        path_id = str(path.get("path_id") or "").strip()
        if path_id:
            by_path[path_id].append(result)

    actual = {
        "completed": 0,
        "failed": 0,
        "errors": 0,
        "unverified": 0,
        "incomplete": 0,
    }
    for rows in by_path.values():
        path = (rows[0].get("details") or {}).get("path") or {}
        directions = path.get("directions")
        expected_measurements = (
            6
            if isinstance(directions, (list, tuple))
            and directions
            and "reverse"
            not in {str(direction).strip().lower() for direction in directions}
            else 7
        )
        topology = str(path.get("source_category") or "uncategorized")
        target = topologies.setdefault(
            topology,
            {
                "eligible": 0,
                "selected": 0,
                "omitted": 0,
                "completed": 0,
                "failed": 0,
                "errors": 0,
                "unverified": 0,
                "incomplete": 0,
            },
        )
        statuses = {str(row.get("status") or "UNKNOWN").upper() for row in rows}
        measurements = {
            str((row.get("details") or {}).get("measurement") or "")
            for row in rows
            if (row.get("details") or {}).get("measurement")
        }
        if "ERROR" in statuses:
            bucket = "errors"
        elif "FAIL" in statuses:
            bucket = "failed"
        elif statuses & {
            "UNVERIFIED",
            "SKIP",
            "NOT_APPLICABLE",
            "BLOCKED_BY_SETUP_ERROR",
            "BLOCKED_BY_PREREQUISITE",
            "NOT_RUN_CANCELLED",
        }:
            bucket = "unverified"
        elif statuses == {"PASS"} and len(measurements) >= expected_measurements:
            bucket = "completed"
        else:
            bucket = "incomplete"
        target[bucket] += 1
        actual[bucket] += 1

    return {
        "eligible": total_eligible,
        "selected": total_selected,
        "omitted": total_omitted,
        "measured_paths": len(by_path),
        **actual,
        "unlimited": configured_limits in ({0}, set()),
        "configured_limits": sorted(configured_limits),
        "stages": stages,
        "topologies": topologies,
    }


def _performance_index(performance: list[dict[str, Any]]) -> dict[str, Any]:
    """Reference canonical result rows without duplicating raw measurements."""

    measurements = Counter(
        str((item.get("details") or {}).get("measurement") or "unknown")
        for item in performance
    )
    path_ids = sorted(
        {
            str(((item.get("details") or {}).get("path") or {}).get("path_id"))
            for item in performance
            if ((item.get("details") or {}).get("path") or {}).get("path_id")
        }
    )
    return {
        "schema_version": 2,
        "storage": "canonical-results",
        "result_ids": [str(item.get("test_id") or "") for item in performance],
        "path_ids": path_ids,
        "result_count": len(performance),
        "measurement_counts": dict(measurements),
    }


def build_run_payload(
    reporter: Any,
    *,
    final_status: str,
    finished: dt.datetime,
    counts: Counter[str],
    include_dashboard: bool = True,
) -> dict[str, Any]:
    results = [_json_value(item) for item in reporter.results]
    performance = [
        item for item in results if bool((item.get("details") or {}).get("performance"))
    ]
    categories: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    contract_types: Counter[str] = Counter()
    contract_verdicts: Counter[str] = Counter()
    authority_classes: Counter[str] = Counter()
    path_signature_keys: set[str] = set()
    for item in results:
        categories[str(item.get("category") or "uncategorized")][
            str(item.get("status") or "UNKNOWN")
        ] += 1
        contract = item.get("contract") or {}
        signature = item.get("path_signature") or {}
        contract_types[str(contract.get("type") or "untyped")] += 1
        contract_verdicts[typed_verdict(item)] += 1
        authority_classes[
            str((contract.get("authority") or {}).get("classification") or "unknown")
        ] += 1
        if signature.get("key"):
            path_signature_keys.add(str(signature["key"]))
    discovery = None
    if reporter.discovery is not None:
        discovery = {
            "project_id": reporter.discovery.project_id,
            "project_name": reporter.discovery.project_name,
            "cloud": reporter.discovery.cloud,
            "region_name": reporter.discovery.region_name,
            "network_count": len(reporter.discovery.networks),
            "subnet_count": len(reporter.discovery.subnets),
            "subnet_pool_count": len(reporter.discovery.pools),
            "segment_count": len(reporter.discovery.segments),
            "network_extensions": list(reporter.discovery.network_extensions),
            "networks": [_json_value(item) for item in reporter.discovery.networks],
            "subnets": [_json_value(item) for item in reporter.discovery.subnets],
        }
    config = reporter.config
    events = _json_value(reporter.events)
    performance_coverage = _performance_coverage(
        events if isinstance(events, list) else [],
        performance,
    )
    coordinator = getattr(reporter, "cloud_operation_coordinator", None)
    cloud_operation_summary = (
        _json_value(coordinator.cloud_operation_summary())
        if coordinator is not None
        else {
            "operations": [],
            "unresolved_operation_ids": [],
            "unresolved_count": 0,
            "quarantined_resources": {},
            "quarantined_hosts": [],
            "external_unresolved_operations": [],
            "hosts": {},
        }
    )
    payload = {
        "schema_version": 1,
        "tool": "neutron-flux",
        "tool_version": DISPLAY_VERSION,
        "release": {
            "identifier": RELEASE_IDENTIFIER,
            "revision": RELEASE_REVISION,
        },
        "run": {
            "run_id": reporter.run_id,
            "action": reporter.action,
            "started_at": reporter.started.isoformat(),
            "finished_at": finished.isoformat(),
            "final_status": final_status,
            "run_tag": reporter.run_tag,
            "name_prefix": reporter.name_prefix,
            "release_revision": RELEASE_REVISION,
        },
        "configuration": {
            "repeat": {
                "total": config.repeat_count,
                "pass": config.repeat_index,
                "root_run_id": config.repeat_root_id,
            },
            "quiet_period_scale": config.quiet_period_scale,
            "operation_gap_scale": config.operation_gap_scale,
            "test_selection": {
                "include_derived_tests": config.include_derived_tests,
                "mode": (
                    reporter.plan.selection_mode
                    if reporter.plan is not None
                    else "exact"
                    if config.test_ids
                    else "all"
                ),
                "requested_test_ids": (
                    list(reporter.plan.requested_test_ids)
                    if reporter.plan is not None
                    else list(config.test_ids)
                ),
                "automatically_included_test_ids": (
                    list(reporter.plan.automatically_included_test_ids)
                    if reporter.plan is not None
                    else []
                ),
            },
            "image": config.image,
            "flavor": config.flavor,
            "storage": config.storage,
            "volume_size": config.volume_size,
            "volume_type": config.volume_type,
            "availability_zones": list(config.availability_zones),
            "availability_zones_all": config.availability_zones_all,
            "zone_mode": config.zone_mode,
            "allow_cross_az_volumes": config.allow_cross_az_volumes,
            "volume_az_policy": "prefer-compute-then-default",
            "allow_cross_az_networking": config.allow_cross_az_networking,
            "network_az": config.network_az,
            "router_az": config.router_az,
            "host_qualification": {
                "enabled": config.host_qualification_enabled,
                "target_hosts": list(config.target_hosts),
                "target_aggregates": list(config.target_aggregates),
                "target_host_pairs": [
                    [source, destination]
                    for source, destination in config.target_host_pairs
                ],
                "include_same_host": config.include_same_host,
                "strategy": config.qualification_strategy,
                "profile": config.qualification_profile,
                "cycles": config.qualification_cycles,
            },
            "external_networks": list(config.external_networks),
            "performance_enabled": config.performance_enabled,
            "performance_duration_seconds": config.performance_duration_seconds,
            "performance_repeats": config.performance_repeats,
            "performance_max_paths": config.performance_max_paths,
            "performance_tcp_streams": list(config.performance_tcp_streams),
            "performance_udp_rates_mbps": list(config.performance_udp_rates_mbps),
            "performance_udp_packet_sizes": list(config.performance_udp_packet_sizes),
            "performance_udp_calibration": {
                "enabled": getattr(
                    config, "performance_udp_adaptive_calibration", True
                ),
                "min_rate_mbps": getattr(
                    config, "performance_udp_calibration_min_rate_mbps", 1
                ),
                "max_attempts": getattr(
                    config, "performance_udp_calibration_max_attempts", 4
                ),
                "backoff_factor": getattr(
                    config, "performance_udp_calibration_backoff_factor", 0.5
                ),
            },
            "routing_contracts": list(getattr(config, "routing_contracts", []) or []),
            "input_sources": dict(getattr(config, "input_sources", {}) or {}),
            "performance_profile": config.performance_profile,
            "performance_thresholds_enforced": config.performance_enforce_thresholds,
            "concurrent_vm_pair_load": {
                "enabled": config.fabric_scale_enabled,
                "pairs": list(config.fabric_scale_pairs),
                "runs": config.fabric_scale_runs,
                "duration_seconds": config.fabric_scale_duration_seconds,
            },
            "migration": {
                "enabled": config.compute_host_connectivity_enabled,
                "require_shared_aggregate": config.require_shared_compute_aggregate,
                "mode": config.migration_mode,
                "storage": config.migration_storage,
                "effective_storage": (
                    "not used"
                    if config.migration_mode == "cold-only"
                    else config.effective_migration_storage
                ),
                "transport": (
                    "not used"
                    if config.migration_mode == "cold-only"
                    else "block live migration"
                    if config.effective_migration_storage == "host"
                    else "shared/volume-backed live migration"
                ),
                "live_attempts": config.live_migration_attempts,
                "effective_submission_budget": config.migration_submission_budget,
                "cold_fallback": config.cold_migration_fallback,
                "continuity": config.live_migration_continuity,
            },
            "network_paths": {
                "runner_control_family": "IPv4",
                "ipv6_test_origin": "OpenStack endpoint VMs",
                "runner_ipv6_required": False,
            },
            "junit_enabled": config.junit_report_enabled,
            "evidence_enabled": config.evidence_enabled,
            "performance_thresholds": {
                "udp_loss_pct": config.performance_udp_loss_threshold_pct,
                "udp_sender_achievement_pct": (
                    config.performance_udp_sender_achievement_threshold_pct
                ),
                "udp_reordering_pct": config.performance_udp_reordering_threshold_pct,
                "loaded_latency_ratio": config.performance_loaded_latency_ratio_threshold,
                "directional_asymmetry_pct": config.performance_asymmetry_threshold_pct,
                "repeatability_variation_pct": config.performance_variation_threshold_pct,
            },
        },
        "summary": {
            "test_progress": reporter_progress(reporter),
            "counts": dict(counts),
            "total_results": len(results),
            "performance_results": len(performance),
            "performance": _performance_summary(performance),
            "performance_coverage": performance_coverage,
            "categories": {key: dict(value) for key, value in categories.items()},
            "contracts": {
                "schema_version": 1,
                "types": dict(contract_types),
                "verdicts": dict(contract_verdicts),
                "authority": dict(authority_classes),
                "semantic_paths": len(path_signature_keys),
            },
            "setup_failed": reporter.setup_failed,
            "interrupted": reporter.interrupted,
            "cleanup_complete": reporter.cleanup_summary.get("complete"),
            "unresolved_cloud_operations": cloud_operation_summary.get(
                "unresolved_count", 0
            ),
            "quarantined_hosts": len(
                cloud_operation_summary.get("quarantined_hosts") or []
            ),
        },
        "discovery": discovery,
        "plan": (
            _json_value(plan_dict(reporter.plan)) if reporter.plan is not None else None
        ),
        "plan_approval": _json_value(getattr(reporter, "plan_approval", {})),
        "plan_drift": _json_value(getattr(reporter, "plan_drift", [])),
        "capabilities": _json_value(getattr(reporter, "capabilities", None)),
        "planned_check_ledger": _json_value(check_ledger(reporter)),
        "coverage_ledger": _json_value(getattr(reporter, "coverage_ledger", [])),
        "results": results,
        "performance": _performance_index(performance),
        "resources": [_json_value(item) for item in reporter.resources],
        "cleanup": _json_value(reporter.cleanup_summary),
        "cloud_operations": cloud_operation_summary,
        "events": events,
        "timing": timing_summary(events),
        "setup_failures": _json_value(reporter.setup_failures),
        "error": reporter.error,
        "cancellation_reason": getattr(reporter, "cancellation_reason", None),
        "traceback": reporter.traceback,
    }
    presentation = {**payload, "results": contextual_results(payload)}
    payload["operator_report"] = {
        "overview": operator_overview(presentation),
        "lifecycle_issues": lifecycle_explanations(payload),
        "results": {
            row["test_id"]: explain_result(row) for row in presentation["results"]
        },
    }
    payload["replay_plan"] = build_replay_plan(payload)
    if include_dashboard:
        payload["dashboard"] = build_dashboard_model(payload)
    return payload


def write_structured_reports(
    reporter: Any,
    *,
    final_status: str,
    finished: dt.datetime,
    counts: Counter[str],
) -> tuple[pathlib.Path, pathlib.Path | None]:
    payload = build_run_payload(
        reporter, final_status=final_status, finished=finished, counts=counts
    )
    results_path = reporter.run_dir / "results.json"
    results_text = (
        json.dumps(payload, separators=(",", ":"), sort_keys=True, allow_nan=False)
        + "\n"
    )
    junit_path = reporter.run_dir / "report.junit.xml"
    html_path = reporter.run_dir / "report.html"
    qualification_csv_path = reporter.run_dir / "host-qualification.csv"
    incident_path = reporter.run_dir / "incident-summary.md"
    replay_json_path = reporter.run_dir / "replay-plan.json"
    replay_text_path = reporter.run_dir / "replay-plan.txt"
    # Render every enabled artifact before replacing any existing output. A
    # serialization/rendering error must not leave a new results.json beside an
    # old optional artifact from a different finalization attempt.
    junit_text = (
        build_junit(payload, include_evidence=reporter.config.evidence_enabled)
        if reporter.config.junit_report_enabled
        else None
    )
    html_text = render_html(payload) if reporter.config.html_report_enabled else None
    qualification_csv_text = render_host_qualification_csv(payload)
    incident_text = render_incident_summary(payload)
    replay_plan = payload.get("replay_plan") or build_replay_plan(payload)
    replay_json_text = (
        json.dumps(
            replay_plan,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    )
    replay_text = render_replay_plan_text(replay_plan)

    _atomic_write(results_path, results_text)
    _atomic_write(qualification_csv_path, qualification_csv_text)
    _atomic_write(incident_path, incident_text)
    _atomic_write(replay_json_path, replay_json_text)
    _atomic_write(replay_text_path, replay_text)
    if reporter.config.junit_report_enabled:
        if junit_text is None:
            raise SuiteError("JUnit output was enabled but was not rendered")
        _atomic_write(junit_path, junit_text)
    else:
        junit_path.unlink(missing_ok=True)
    if not reporter.config.html_report_enabled:
        html_path.unlink(missing_ok=True)
        return results_path, None
    if html_text is None:
        raise SuiteError("HTML output was enabled but was not rendered")
    _atomic_write(html_path, html_text)
    return results_path, html_path


def render_html(payload: dict[str, Any]) -> str:
    from .manual_programs import manual_helper_source

    dashboard = payload.get("dashboard") or {}
    if dashboard.get("model_version") != DASHBOARD_MODEL_VERSION or (
        payload.get("results")
        and dashboard.get("report_shape_version") != REPORT_MODEL_VERSION
    ):
        payload = dict(payload)
        payload["dashboard"] = build_dashboard_model(payload)
    report_payload = build_report_payload(payload)
    report_payload["manual_helper_source"] = manual_helper_source()
    report_payload["report_renderer_version"] = DISPLAY_VERSION
    data = json.dumps(
        pool_evidence(report_payload),
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).replace("</", "<\\/")
    title = html_lib.escape(f"Neutron Flux — {payload['run']['run_id']}")
    return HTML_TEMPLATE.replace("__TITLE__", title).replace("__DATA__", data)


__all__ = [
    "build_run_payload",
    "render_html",
    "write_structured_reports",
    "_atomic_write",
]
