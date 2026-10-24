from __future__ import annotations

import dataclasses
import hashlib
import json
import pathlib
from typing import Any

from .config import Config
from .configuration.snapshots import execution_settings
from .constants import DISPLAY_VERSION
from .errors import SuiteError
from .models import (
    Discovery,
    HostQualificationHost,
    HostQualificationPair,
    HostQualificationPlan,
    Plan,
    PlannedGroup,
    TestSpec,
)
from .network_contract import (
    LEGACY_CATEGORY_ALIASES,
    LEGACY_GROUP_KIND_ALIASES,
    LEGACY_OPERATION_ALIASES,
)
from .operation_compat import canonical_operation_fields
from .translation_safety import validate_plan_translation_safety
from .utils import iso_utc

PLAN_CONTRACT_SCHEMA = 1
MAX_PLAN_BYTES = 16 * 1024 * 1024


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def plan_dict(
    plan: Plan,
    *,
    immutable_identity: bool = False,
) -> dict[str, Any]:
    value = dataclasses.asdict(plan)
    value["project_network_groups"] = value.pop("tenant_groups", [])
    value["estimated"] = _canonical_contract_value(value.get("estimated") or {})
    qualification = value.get("host_qualification")
    if immutable_identity and isinstance(qualification, dict):
        # Wall-clock generation time is evidence, not plan identity.
        qualification["generated_at"] = None
    return value


def configuration_snapshot(config: Config) -> dict[str, Any]:
    return {
        "execution_settings": execution_settings(config),
        "pacing": {
            "quiet_period_scale": config.quiet_period_scale,
            "operation_gap_scale": config.operation_gap_scale,
        },
        "image": config.image,
        "flavor": config.flavor,
        "storage": config.storage,
        "volume_size": config.volume_size,
        "volume_type": config.volume_type,
        "networks": list(config.external_networks),
        "availability_zones": list(config.availability_zones),
        "availability_zones_all": config.availability_zones_all,
        "zone_mode": config.zone_mode,
        "az_placement": {
            "allow_cross_az_volumes": config.allow_cross_az_volumes,
            "allow_cross_az_networking": config.allow_cross_az_networking,
            "network_az": config.network_az,
            "router_az": config.router_az,
        },
        "execution": {
            "selection_mode": "exact" if config.test_ids else "all",
            "test_ids": list(config.test_ids),
        },
        "qualification": {
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
        "performance": {
            "profile": config.performance_profile,
            "enabled": config.performance_enabled,
            "duration_seconds": config.performance_duration_seconds,
            "repeats": config.performance_repeats,
            "max_paths": config.performance_max_paths,
            "tcp_streams": list(config.performance_tcp_streams),
            "udp_rates_mbps": list(config.performance_udp_rates_mbps),
            "udp_packet_sizes": list(config.performance_udp_packet_sizes),
            "ping_count": config.performance_ping_count,
        },
        "concurrent_load": {
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
            "live_attempts": config.live_migration_attempts,
            "cold_fallback": config.cold_migration_fallback,
            "continuity": config.live_migration_continuity,
        },
    }


def _network_snapshot(discovery: Discovery) -> list[dict[str, Any]]:
    subnets_by_network: dict[str, list[dict[str, Any]]] = {}
    for subnet in discovery.subnets:
        subnets_by_network.setdefault(subnet.network_id, []).append(
            {
                "id": subnet.id,
                "name": subnet.name,
                "cidr": subnet.cidr,
                "ip_version": subnet.ip_version,
                "gateway_ip": subnet.gateway_ip,
                "dhcp_enabled": subnet.dhcp_enabled,
                "subnetpool_id": subnet.subnetpool_id,
                "segment_id": subnet.segment_id,
                "address_scope_id": subnet.address_scope_id,
                "service_types": sorted(subnet.service_types),
            }
        )
    rows = []
    for network in discovery.networks:
        rows.append(
            {
                "id": network.id,
                "name": network.name,
                "external": network.external,
                "shared": network.shared,
                "network_type": network.network_type,
                "physical_network": network.physical_network,
                "segmentation_id": network.segmentation_id,
                "mtu": network.mtu,
                "port_security_enabled": network.port_security_enabled,
                "segment_ids": sorted(network.segment_ids),
                "subnets": sorted(
                    subnets_by_network.get(network.id, []),
                    key=lambda item: (item["id"], item["cidr"]),
                ),
            }
        )
    return sorted(rows, key=lambda item: (item["id"], item["name"]))


def inventory_snapshot(
    discovery: Discovery,
    plan: Plan,
    capabilities: dict[str, Any] | None = None,
) -> dict[str, Any]:
    qualification = plan.host_qualification
    hosts = []
    pairs = []
    aggregates: list[dict[str, Any]] = []
    if qualification is not None:
        hosts = [
            {
                "host": host.host,
                "availability_zone": host.availability_zone,
                "enabled": host.enabled,
                "up": host.up,
                "service_ids": sorted(host.service_ids),
                "aggregate_ids": sorted(host.aggregate_ids),
                "aggregate_names": sorted(host.aggregate_names),
                "blockers": list(host.blockers),
            }
            for host in qualification.hosts
        ]
        pairs = [
            {
                "pair_id": pair.pair_id,
                "source_host": pair.source_host,
                "destination_host": pair.destination_host,
                "source_availability_zone": pair.source_availability_zone,
                "destination_availability_zone": pair.destination_availability_zone,
                "status": pair.status,
                "blockers": list(pair.blockers),
            }
            for pair in qualification.pairs
        ]
        aggregates = [
            {"id": aggregate_id, "name": aggregate_name}
            for aggregate_id, aggregate_name in zip(
                qualification.resolved_aggregate_ids,
                qualification.resolved_aggregate_names,
                strict=False,
            )
        ]
    quota_rows = [
        {
            "resource": name,
            "limit": quota.limit,
            "used": quota.used,
            "reserved": quota.reserved,
            "available": quota.available,
        }
        for name, quota in sorted(discovery.quota_info.items())
    ]
    stable_capabilities = []
    for check in (capabilities or {}).get("checks") or []:
        if not isinstance(check, dict):
            continue
        if check.get("drift_relevant", True) is False:
            continue
        stable_capabilities.append(
            {
                "id": check.get("id"),
                "status": check.get("status"),
                "required": bool(check.get("required")),
                "evidence": check.get("evidence") or {},
            }
        )
    return {
        "cloud": discovery.cloud,
        "project_id": discovery.project_id,
        "project_name": discovery.project_name,
        "network_extensions": sorted(discovery.network_extensions),
        "networks": _network_snapshot(discovery),
        "quotas": quota_rows,
        "hosts": sorted(hosts, key=lambda item: item["host"]),
        "host_pairs": sorted(pairs, key=lambda item: item["pair_id"]),
        "aggregates": sorted(aggregates, key=lambda item: (item["id"], item["name"])),
        **(
            {"aggregate_policy": qualification.aggregate_policy}
            if qualification is not None
            and qualification.aggregate_policy.get("requested") == "auto"
            else {}
        ),
        "capabilities": sorted(
            stable_capabilities, key=lambda item: str(item.get("id") or "")
        ),
    }


def create_plan_contract(
    config: Config,
    discovery: Discovery,
    plan: Plan,
    capabilities: dict[str, Any] | None = None,
) -> dict[str, Any]:
    configuration = configuration_snapshot(config)
    inventory = inventory_snapshot(discovery, plan, capabilities)
    immutable_plan = plan_dict(plan, immutable_identity=True)
    signed = {
        "configuration": configuration,
        "inventory": inventory,
        "plan": immutable_plan,
    }
    return {
        "schema_version": PLAN_CONTRACT_SCHEMA,
        "kind": "neutron-flux-approved-plan",
        "tool_version": DISPLAY_VERSION,
        "generated_at": iso_utc(),
        "fingerprint": _sha256(signed),
        "configuration_fingerprint": _sha256(configuration),
        "inventory_fingerprint": _sha256(inventory),
        "plan_fingerprint": _sha256(immutable_plan),
        "configuration": configuration,
        "inventory": inventory,
        "plan": immutable_plan,
    }


def attach_runtime_plan(contract: dict[str, Any], plan: Plan) -> dict[str, Any]:
    runtime_plan = plan_dict(plan)
    return {
        **contract,
        "runtime_plan": runtime_plan,
        "runtime_plan_fingerprint": _sha256(runtime_plan),
    }


def _host_qualification_from_dict(
    value: dict[str, Any] | None,
) -> HostQualificationPlan | None:
    if not value:
        return None
    raw = dict(value)
    raw["hosts"] = [HostQualificationHost(**item) for item in raw.get("hosts") or []]
    raw["pairs"] = [HostQualificationPair(**item) for item in raw.get("pairs") or []]
    return HostQualificationPlan(**raw)


def plan_from_dict(value: dict[str, Any]) -> Plan:
    if "project_network_groups" in value and "tenant_groups" in value:
        raise SuiteError(
            "Approved plan contains both project_network_groups and the legacy "
            "tenant_groups alias; mixed aliases are ambiguous"
        )
    try:
        plan = Plan(
            provider_groups=[
                PlannedGroup(**item) for item in value.get("provider_groups") or []
            ],
            tenant_groups=[
                PlannedGroup(**item)
                for item in (
                    value.get("project_network_groups")
                    or value.get("tenant_groups")
                    or []
                )
            ],
            estimated=dict(_canonical_contract_value(value.get("estimated") or {})),
            skipped=list(value.get("skipped") or []),
            tests=[TestSpec(**item) for item in value.get("tests") or []],
            checks=list(value.get("checks") or []),
            warnings=list(value.get("warnings") or []),
            host_qualification=_host_qualification_from_dict(
                value.get("host_qualification")
            ),
            selection_mode=str(value.get("selection_mode") or "all"),
            requested_test_ids=list(value.get("requested_test_ids") or []),
            automatically_included_test_ids=list(
                value.get("automatically_included_test_ids") or []
            ),
        )
        validate_plan_translation_safety(plan)
        return plan
    except (TypeError, ValueError) as exc:
        raise SuiteError(
            f"Approved plan contains an invalid plan payload: {exc}"
        ) from exc


def load_plan_contract(
    path: pathlib.Path,
    *,
    prefer_runtime_plan: bool = False,
) -> tuple[dict[str, Any], Plan]:
    resolved = path.expanduser()
    if resolved.is_symlink():
        raise SuiteError(f"Approved plan must not be a symbolic link: {resolved}")
    if not resolved.is_file():
        raise SuiteError(f"Approved plan does not exist: {resolved}")
    try:
        size = resolved.stat().st_size
        if size > MAX_PLAN_BYTES:
            raise SuiteError(
                f"Approved plan exceeds {MAX_PLAN_BYTES} bytes: {resolved}"
            )
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SuiteError(f"Could not read approved plan {resolved}: {exc}") from exc
    if not isinstance(value, dict):
        raise SuiteError("Approved plan root must be a JSON object")
    if value.get("schema_version") != PLAN_CONTRACT_SCHEMA:
        raise SuiteError(
            "Approved plan schema is unsupported: "
            f"{value.get('schema_version')!r}; expected {PLAN_CONTRACT_SCHEMA}"
        )
    if value.get("kind") != "neutron-flux-approved-plan":
        raise SuiteError("Input is not a Neutron Flux approved plan")
    for field in ("configuration", "inventory", "plan", "fingerprint"):
        if field not in value:
            raise SuiteError(f"Approved plan is missing {field}")
    signed = {
        "configuration": value["configuration"],
        "inventory": value["inventory"],
        "plan": value["plan"],
    }
    actual = _sha256(signed)
    if actual != value["fingerprint"]:
        raise SuiteError(
            "Approved plan fingerprint mismatch; the plan was modified after generation"
        )
    if not isinstance(value["plan"], dict):
        raise SuiteError("Approved plan payload must be an object")
    selected = value["plan"]
    if prefer_runtime_plan and "runtime_plan" in value:
        runtime_plan = value["runtime_plan"]
        if not isinstance(runtime_plan, dict):
            raise SuiteError("Saved runtime plan payload must be an object")
        if _sha256(runtime_plan) != value.get("runtime_plan_fingerprint"):
            raise SuiteError(
                "Saved runtime plan fingerprint mismatch; resume state was modified"
            )
        selected = runtime_plan
    return value, plan_from_dict(selected)


def drift_diff(
    approved: Any,
    current: Any,
    *,
    path: str = "",
) -> list[dict[str, Any]]:
    if isinstance(approved, dict) and isinstance(current, dict):
        rows: list[dict[str, Any]] = []
        for key in sorted(set(approved).union(current)):
            child = f"{path}.{key}" if path else str(key)
            if key not in approved:
                rows.append(
                    {
                        "path": child,
                        "change": "added",
                        "approved": None,
                        "current": current[key],
                    }
                )
            elif key not in current:
                rows.append(
                    {
                        "path": child,
                        "change": "removed",
                        "approved": approved[key],
                        "current": None,
                    }
                )
            else:
                rows.extend(drift_diff(approved[key], current[key], path=child))
        return rows
    if isinstance(approved, list) and isinstance(current, list):
        if approved == current:
            return []
        # Inventory lists are canonical and sorted, so an exact row-level value
        # is clearer than an index-by-index cascade after one insertion.
        return [
            {
                "path": path,
                "change": "changed",
                "approved": approved,
                "current": current,
            }
        ]
    if approved != current:
        return [
            {
                "path": path,
                "change": "changed",
                "approved": approved,
                "current": current,
            }
        ]
    return []


def verify_plan_contract(
    approved: dict[str, Any],
    current: dict[str, Any],
) -> list[dict[str, Any]]:
    approved_configuration = _semantic_configuration(approved.get("configuration"))
    current_configuration = _semantic_configuration(current.get("configuration"))
    approved_plan = _semantic_plan(approved.get("plan"))
    current_plan = _semantic_plan(current.get("plan"))
    return [
        *drift_diff(
            approved_configuration,
            current_configuration,
            path="configuration",
        ),
        *drift_diff(
            _semantic_inventory(approved.get("inventory")),
            _semantic_inventory(current.get("inventory")),
            path="inventory",
        ),
        *drift_diff(
            approved_plan,
            current_plan,
            path="plan",
        ),
    ]


def _semantic_inventory(value: Any) -> Any:
    """Quota consumption is live headroom, not an immutable workload identity.

    Limits and resource visibility still participate in drift checks. The full
    original snapshot remains fingerprinted, and fresh quota preflight remains
    mandatory before provisioning.
    """
    if not isinstance(value, dict):
        return value
    inventory = dict(value)
    if isinstance(inventory.get("quotas"), list):
        inventory["quotas"] = [
            {
                key: item
                for key, item in row.items()
                if key not in {"used", "reserved", "available"}
            }
            if isinstance(row, dict)
            else row
            for row in inventory["quotas"]
        ]
    if isinstance(inventory.get("capabilities"), list):
        capabilities = []
        for check in inventory["capabilities"]:
            if (
                isinstance(check, dict)
                and check.get("id") == "quota-headroom"
                and isinstance(check.get("evidence"), dict)
            ):
                # Headroom is also recorded as capability evidence. Preserve
                # requirements and PASS/FAIL while ignoring transient usage.
                check = {
                    **check,
                    "evidence": {
                        name: {
                            key: item for key, item in row.items() if key != "available"
                        }
                        if isinstance(row, dict)
                        else row
                        for name, row in check["evidence"].items()
                    },
                }
            capabilities.append(check)
        inventory["capabilities"] = capabilities
    return inventory


def _semantic_configuration(value: Any) -> Any:
    """Normalize renamed configuration keys without weakening drift checks.

    Legacy contracts used ``fabric`` for the optional concurrent VM-pair
    measurement.  Current contracts emit the accurate ``concurrent_load`` name.  The
    original serialized value is still fingerprinted and validated before this
    compatibility normalization is used.
    """

    if not isinstance(value, dict):
        return value
    output = canonical_operation_fields(value)
    execution = output.get("execution_settings")
    if isinstance(execution, dict):
        execution = dict(execution)
        for key in ("keep_resources", "auto_cleanup_on_failure"):
            execution.pop(key, None)
        output["execution_settings"] = execution
    if "fabric" in output and "concurrent_load" in output:
        raise SuiteError(
            "Plan configuration contains both concurrent_load and the legacy "
            "fabric alias; mixed aliases are ambiguous"
        )
    legacy = output.pop("fabric", None)
    if "concurrent_load" not in output and legacy is not None:
        output["concurrent_load"] = legacy
    return _canonical_contract_value(output)


def _canonical_contract_string(value: str) -> str:
    output = value
    replacements = {
        **LEGACY_GROUP_KIND_ALIASES,
        **LEGACY_CATEGORY_ALIASES,
        **LEGACY_OPERATION_ALIASES,
    }
    for legacy, canonical in sorted(
        replacements.items(), key=lambda item: len(item[0]), reverse=True
    ):
        output = output.replace(legacy, canonical)
    return output


def _canonical_contract_value(value: Any) -> Any:
    if isinstance(value, str):
        return _canonical_contract_string(value)
    if isinstance(value, list):
        return [_canonical_contract_value(item) for item in value]
    if isinstance(value, dict):
        key_aliases = {
            "fabric_scale_pairs": "concurrent_load_pairs",
            "fabric_scale_endpoint_boots": "concurrent_load_endpoint_boots",
            "tenant_groups": "project_network_groups",
            "tenant_topology_generations": ("project_network_topology_generations"),
        }
        for legacy, canonical in key_aliases.items():
            if legacy in value and canonical in value:
                raise SuiteError(
                    "Plan payload contains both "
                    f"{canonical} and the legacy {legacy} alias; "
                    "mixed aliases are ambiguous"
                )
        return {
            key_aliases.get(key, key): _canonical_contract_value(item)
            for key, item in value.items()
        }
    return value


_PRESENTATION_METADATA_KEYS = frozenset(
    {
        "coverage_scope",
        "routing_relationship_label",
        "scenario",
        "scenario_label",
    }
)


def _semantic_group(value: dict[str, Any]) -> dict[str, Any]:
    output = {
        key: item
        for key, item in value.items()
        if key not in {"label", "network_name", "pool_name", "external_network_name"}
    }
    metadata = output.get("metadata")
    if isinstance(metadata, dict):
        output["metadata"] = {
            key: item
            for key, item in metadata.items()
            if key not in _PRESENTATION_METADATA_KEYS
        }
    return _canonical_contract_value(output)


def _semantic_test(value: dict[str, Any]) -> dict[str, Any]:
    # IDs and prose are deliberately excluded: normalization replaces misleading legacy
    # terms in those presentation fields.  Every executable field remains in
    # the comparison, so a changed path, operation, dependency, expectation,
    # authority decision, protocol, or lifecycle cloud operation still rejects the
    # approved plan.
    output = {
        key: item
        for key, item in value.items()
        if key
        not in {
            "id",
            "display_name",
            "scenario",
            "expectation_reason",
        }
    }
    metadata = output.get("metadata")
    if isinstance(metadata, dict):
        output["metadata"] = {
            key: item
            for key, item in metadata.items()
            if key not in _PRESENTATION_METADATA_KEYS
        }
    return _canonical_contract_value(output)


def _semantic_plan(value: Any) -> Any:
    """Return the executable identity of a plan across vocabulary revisions."""

    if not isinstance(value, dict):
        return value
    if "project_network_groups" in value and "tenant_groups" in value:
        raise SuiteError(
            "Plan payload contains both project_network_groups and the legacy "
            "tenant_groups alias; mixed aliases are ambiguous"
        )
    output: dict[str, Any] = {}
    for key, item in value.items():
        canonical_key = "project_network_groups" if key == "tenant_groups" else key
        if key in {"warnings", "skipped"}:
            # These are re-created from current inventory and validated by the
            # inventory snapshot. Their prose may legitimately improve.
            continue
        if canonical_key in {
            "provider_groups",
            "project_network_groups",
        } and isinstance(item, list):
            rows = [_semantic_group(row) for row in item if isinstance(row, dict)]
            output[canonical_key] = sorted(rows, key=_canonical_json)
            continue
        if key == "tests" and isinstance(item, list):
            rows = [_semantic_test(row) for row in item if isinstance(row, dict)]
            output[canonical_key] = sorted(rows, key=_canonical_json)
            continue
        output[canonical_key] = _canonical_contract_value(item)
    return output


def format_drift(diff: list[dict[str, Any]], *, limit: int = 50) -> str:
    rows = []
    for item in diff[:limit]:
        rows.append(
            f"- {item['path']}: {item['change']}; "
            f"approved={item.get('approved')!r}; current={item.get('current')!r}"
        )
    if len(diff) > limit:
        rows.append(f"- ... {len(diff) - limit} additional changes")
    return "\n".join(rows)


__all__ = [
    "PLAN_CONTRACT_SCHEMA",
    "attach_runtime_plan",
    "configuration_snapshot",
    "create_plan_contract",
    "drift_diff",
    "format_drift",
    "inventory_snapshot",
    "load_plan_contract",
    "plan_dict",
    "plan_from_dict",
    "verify_plan_contract",
]
