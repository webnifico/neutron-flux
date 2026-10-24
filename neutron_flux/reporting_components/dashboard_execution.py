from __future__ import annotations

import datetime as dt
import re
from collections import Counter, defaultdict
from typing import Any

from ..operator_explanations import is_execution_lane_failure

_NOT_EXECUTED_OUTCOMES = {"BLOCKED", "NEVER_RAN", "CANCELLED", "PENDING"}


def _parse_time(value: Any) -> dt.datetime | None:
    try:
        return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _result_dimensions(result: dict[str, Any]) -> dict[str, set[str]]:
    details = result.get("details") or {}
    path = details.get("path") or {}

    def values(*items: Any) -> set[str]:
        return {str(item) for item in items if item is not None and item != ""}

    hosts = values(
        path.get("source_compute_host"),
        path.get("destination_compute_host"),
        details.get("requested_source_host"),
        details.get("requested_destination_host"),
        details.get("observed_source_host"),
        details.get("observed_destination_host"),
    )
    for endpoint in details.get("endpoints") or []:
        if isinstance(endpoint, dict):
            hosts.update(
                values(
                    endpoint.get("observed_host"),
                    endpoint.get("requested_host"),
                )
            )
    return {
        "host": hosts,
        "availability_zone": values(
            path.get("source_availability_zone"),
            path.get("destination_availability_zone"),
            details.get("source_availability_zone"),
            details.get("destination_availability_zone"),
            details.get("availability_zone"),
        ),
        "network": values(
            path.get("source_network"),
            path.get("destination_network"),
            details.get("network_id"),
            details.get("network_name"),
            details.get("external_network_id"),
            details.get("external_network_name"),
        ),
        "router": values(
            details.get("router_id"),
            details.get("source_router_id"),
            details.get("destination_router_id"),
        ),
        "subnet": values(
            path.get("source_subnet_id"),
            path.get("destination_subnet_id"),
            details.get("subnet_id"),
            details.get("source_subnet_id"),
            details.get("destination_subnet_id"),
        ),
        "direction": values(
            path.get("direction"),
            details.get("direction"),
            f"{result.get('source')} -> {result.get('destination')}"
            if result.get("source") or result.get("destination")
            else None,
        ),
        "mtu": values(
            path.get("expected_mtu"),
            details.get("expected_mtu"),
            (details.get("metrics") or {}).get("expected_mtu"),
        ),
        "cycle": values(details.get("host_qualification_cycle")),
    }


def _correlated_fault_domains(
    results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], set[str]] = defaultdict(set)
    status_by_id: dict[str, str] = {}
    for result in results:
        if result.get("severity") in {"good", "neutral", "blocked"}:
            continue
        result_id = str(result.get("result_id") or result.get("test_id") or "")
        status_by_id[result_id] = str(result.get("status") or "UNKNOWN")
        for dimension, dimension_values in _result_dimensions(result).items():
            for value in dimension_values:
                grouped[(dimension, value)].add(result_id)
    rows = []
    for (dimension, value), result_ids in grouped.items():
        if len(result_ids) < 2:
            continue
        ids = sorted(result_ids)
        rows.append(
            {
                "dimension": dimension,
                "value": value,
                "result_ids": ids,
                "result_count": len(ids),
                "status_counts": dict(
                    Counter(status_by_id[result_id] for result_id in ids)
                ),
                "note": (
                    "These results share a recorded dimension. No root cause is "
                    "assigned by the report."
                ),
            }
        )
    return sorted(
        rows,
        key=lambda item: (-int(item["result_count"]), item["dimension"], item["value"]),
    )[:100]


def _coverage_model(payload: dict[str, Any]) -> dict[str, Any]:
    ledger = list(
        payload.get("planned_check_ledger")
        or [
            row
            for row in (payload.get("coverage_ledger") or [])
            if row.get("kind") in (None, "test")
        ]
    )
    outcomes = Counter(str(item.get("outcome") or "UNKNOWN") for item in ledger)
    categories: dict[str, Counter[str]] = defaultdict(Counter)
    phases: dict[str, Counter[str]] = defaultdict(Counter)
    for item in ledger:
        outcome = str(item.get("outcome") or "UNKNOWN")
        categories[str(item.get("category") or "uncategorized")][outcome] += 1
        phases[str(item.get("phase") or "unspecified")][outcome] += 1

    def rows(values: dict[str, Counter[str]]) -> list[dict[str, Any]]:
        return [
            {
                "name": name,
                "outcomes": dict(counts),
                "total": sum(counts.values()),
            }
            for name, counts in sorted(values.items())
        ]

    return {
        "outcomes": dict(outcomes),
        "total": len(ledger),
        "complete": not any(outcomes.get(key, 0) for key in _NOT_EXECUTED_OUTCOMES),
        "by_category": rows(categories),
        "by_phase": rows(phases),
        "cells": ledger,
    }


def _standardize_evidence(result: dict[str, Any]) -> dict[str, Any]:
    details = result.get("details") or {}
    path = details.get("path") or {}
    commands: list[Any] = []
    for key in (
        "command",
        "commands",
        "probe_command",
        "openstack_command",
        "guest_command",
    ):
        value = details.get(key)
        if value:
            commands.extend(value if isinstance(value, list) else [value])
    diagnostics = details.get("diagnostics") or {}
    if isinstance(diagnostics, dict) and diagnostics.get("command"):
        commands.append(diagnostics["command"])
    return {
        "expected": result.get("expected"),
        "observed": result.get("observed"),
        "authority": {
            "authoritative": result.get("authoritative"),
            "source": details.get("authority")
            or details.get("reason_authority")
            or "Neutron Flux test contract",
        },
        "reason": result.get("message"),
        "placement": {
            "classification": result.get("placement"),
            "source_host": path.get("source_compute_host")
            or details.get("observed_source_host"),
            "destination_host": path.get("destination_compute_host")
            or details.get("observed_destination_host"),
            "source_availability_zone": path.get("source_availability_zone")
            or details.get("source_availability_zone"),
            "destination_availability_zone": path.get("destination_availability_zone")
            or details.get("destination_availability_zone"),
            "method": details.get("placement_method"),
        },
        "commands": commands,
        "parsed_evidence": details.get("parsed_evidence")
        or details.get("metrics")
        or details.get("diagnostics")
        or {},
        "raw_evidence": {
            "available": bool(details),
            "source": "result.details",
            "fields": sorted(map(str, details)),
        },
    }


def _setup_incidents(
    payload: dict[str, Any],
    results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    explicit_zones = {
        str((result.get("details") or {}).get("availability_zone") or "").strip()
        for result in results
        if (result.get("details") or {}).get("root_setup_error")
    }
    explicit_zones.discard("")
    incidents: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for failure in payload.get("setup_failures") or []:
        if isinstance(failure, dict):
            message = str(failure.get("message") or "").strip()
            details = failure.get("details") or {}
        else:
            message = str(failure or "").strip()
            details = {}
        zone = str(details.get("availability_zone") or "").strip()
        if not zone:
            scope = str(details.get("execution_scope") or "").strip()
            if scope.startswith("az-"):
                zone = scope[3:]
        if not zone:
            match = re.search(r"\b([a-z]{2,}-[a-z0-9-]*\d)\b", message, re.I)
            zone = match.group(1).lower() if match else ""
        if zone in explicit_zones:
            continue
        execution_failure = is_execution_lane_failure(details)
        title = (
            "Neutron Flux test execution stopped"
            if execution_failure
            else "Neutron Flux controller setup did not complete"
        ) + (f" in {zone}" if zone else "")
        summary = message or "A tool failure blocked planned validation coverage."
        key = (title, summary)
        if key in seen:
            continue
        seen.add(key)
        incidents.append(
            {
                "severity": "error",
                "title": title,
                "summary": summary,
                "result_count": 1,
                "setup_failure": not execution_failure,
                "execution_failure": execution_failure,
            }
        )
    return incidents


def _command_centre(
    payload: dict[str, Any],
    results: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    run = payload.get("run") or {}
    start = _parse_time(run.get("started_at"))
    finish = _parse_time(run.get("finished_at"))
    duration = (
        max(0.0, (finish - start).total_seconds())
        if start is not None and finish is not None
        else None
    )
    required_evidence = 0
    complete_evidence = 0
    for result in results:
        required_evidence += 1
        if result.get("severity") == "blocked":
            continue
        if (
            result.get("expected") is not None
            and result.get("observed") is not None
            and result.get("authoritative") is not None
            and bool(result.get("message"))
        ):
            complete_evidence += 1
    approval = payload.get("plan_approval") or {}
    discovery = payload.get("discovery") or {}
    coverage = payload.get("planned_check_ledger") or [
        row
        for row in (payload.get("coverage_ledger") or [])
        if row.get("kind") in (None, "test")
    ]
    never_ran = sum(
        1 for item in coverage if item.get("outcome") in _NOT_EXECUTED_OUTCOMES
    )
    top_incidents = [*_setup_incidents(payload, results), *findings]
    return {
        "overall_health": run.get("final_status"),
        "cleanup_state": (payload.get("cleanup") or {}).get("complete"),
        "evidence": {
            "complete": complete_evidence,
            "required": required_evidence,
            "percentage": (
                100.0 * complete_evidence / required_evidence
                if required_evidence
                else 100.0
            ),
        },
        "plan_fingerprint": approval.get("fingerprint"),
        "plan_verified": approval.get("verified"),
        "plan_source": approval.get("source"),
        "cloud_identity": {
            "cloud": discovery.get("cloud"),
            "project_id": discovery.get("project_id"),
            "project_name": discovery.get("project_name"),
        },
        "duration_seconds": duration,
        "coverage": {
            "total": len(coverage),
            "never_ran": never_ran,
            "blocked": sum(item.get("outcome") == "BLOCKED" for item in coverage),
            "complete": never_ran == 0,
        },
        "capability_blockers": list(
            (payload.get("capabilities") or {}).get("blockers") or []
        ),
        "top_incidents": top_incidents[:5],
    }


def _topology_workspace(
    paths: list[dict[str, Any]],
    host_qualification: dict[str, Any],
) -> dict[str, Any]:
    zones: dict[str, list[str]] = defaultdict(list)
    aggregates: dict[str, list[str]] = defaultdict(list)
    for host in host_qualification.get("hosts") or []:
        name = str(host.get("host") or "")
        zones[str(host.get("availability_zone") or "Unknown AZ")].append(name)
        for aggregate in host.get("aggregate_names") or []:
            aggregates[str(aggregate)].append(name)
    overlays = []
    for path in paths:
        overlays.append(
            {
                "path_id": path.get("path_id"),
                "source": path.get("source"),
                "destination": path.get("destination"),
                "family": path.get("family"),
                "health": path.get("health"),
                "direction": "source-to-destination",
                "placement": path.get("placement"),
                "link_confidence": (
                    "recorded-test-pair" if path.get("result_ids") else "not-recorded"
                ),
            }
        )
    return {
        "availability_zone_boundaries": [
            {"name": name, "hosts": sorted(hosts)}
            for name, hosts in sorted(zones.items())
        ],
        "aggregate_boundaries": [
            {"name": name, "hosts": sorted(hosts)}
            for name, hosts in sorted(aggregates.items())
        ],
        "directional_path_overlays": overlays,
    }


def _lifecycle_timeline(
    payload: dict[str, Any],
    results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows = []
    for index, event in enumerate(payload.get("events") or []):
        rows.append(
            {
                "id": f"event-{index + 1}",
                "timestamp": event.get("timestamp"),
                "kind": event.get("type") or "event",
                "message": event.get("message"),
                "details": event.get("details") or {},
            }
        )
    for result in results:
        rows.append(
            {
                "id": f"result-{result.get('result_id')}",
                "timestamp": result.get("started_at"),
                "kind": "test-result",
                "message": result.get("title") or result.get("test_id"),
                "status": result.get("status"),
                "result_id": result.get("result_id"),
            }
        )
    for resource in payload.get("resources") or []:
        if resource.get("created_at"):
            rows.append(
                {
                    "id": f"create-{resource.get('sequence')}",
                    "timestamp": resource.get("created_at"),
                    "kind": f"{resource.get('resource_type')}-created",
                    "message": resource.get("name"),
                }
            )
        if resource.get("deleted_at"):
            rows.append(
                {
                    "id": f"delete-{resource.get('sequence')}",
                    "timestamp": resource.get("deleted_at"),
                    "kind": f"{resource.get('resource_type')}-deleted",
                    "message": resource.get("name"),
                }
            )
    return sorted(rows, key=lambda row: str(row.get("timestamp") or ""))


def enrich_dashboard_model(
    payload: dict[str, Any],
    results: list[dict[str, Any]],
    paths: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    host_qualification: dict[str, Any],
) -> dict[str, Any]:
    for result in results:
        result["evidence"] = _standardize_evidence(result)
    for pair in host_qualification.get("pairs") or []:
        pair_results = [
            result
            for result in results
            if (result.get("reporting_context") or result.get("details") or {}).get(
                "host_qualification_pair_id"
            )
            == pair.get("pair_id")
        ]
        pair["networks"] = sorted(
            {
                value
                for result in pair_results
                for value in _result_dimensions(result)["network"]
            }
        )
        pair["test_types"] = sorted(
            {
                str(
                    (result.get("details") or {}).get("measurement")
                    or result.get("category")
                    or "validation"
                )
                for result in pair_results
            }
        )
        pair["topologies"] = sorted(
            {
                str(
                    ((result.get("details") or {}).get("path") or {}).get(
                        "source_category"
                    )
                    or (result.get("details") or {}).get("base_group_id")
                    or "provider"
                )
                for result in pair_results
            }
        )
    return {
        "command_centre": _command_centre(payload, results, findings),
        "coverage_matrix": _coverage_model(payload),
        "correlated_fault_domains": _correlated_fault_domains(results),
        "topology_workspace": _topology_workspace(paths, host_qualification),
        "lifecycle_timeline": _lifecycle_timeline(payload, results),
        "baseline_comparison": {
            "supported": True,
            "input": "results.json",
            "runs_entirely_in_browser": True,
        },
        "virtualization": {
            "result_window": 200,
            "matrix_window": 250,
        },
    }


__all__ = ["enrich_dashboard_model"]
