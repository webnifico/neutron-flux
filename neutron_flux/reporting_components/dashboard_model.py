from __future__ import annotations

import datetime as dt
import math
import re
import statistics
from collections import Counter, defaultdict
from collections.abc import Iterable
from typing import Any

from ..logical_results import logical_results
from ..operation_compat import canonical_operation_event_type
from ..operator_explanations import (
    explain_result,
    is_execution_lane_failure,
    needs_attention,
)
from ..result_context import result_context
from ..result_contract import normalize_result_record, typed_verdict
from ..terminology import (
    friendly_operator_text as _central_friendly_operator_text,
)
from ..terminology import friendly_scenario as _central_friendly_scenario
from ..test_names import execution_name, test_name
from .dashboard_environment import build_environment_summary, build_network_inventory
from .dashboard_execution import enrich_dashboard_model
from .dashboard_findings import finding_measurements, finding_summary
from .dashboard_glossary import GLOSSARY as _GLOSSARY
from .dashboard_mtu_model import mtu_boundary_values
from .dashboard_topology import (
    _allocation_model,
    _attach_path_allocation_context,
)
from .dashboard_udp_model import udp_measurement_values
from .dashboard_vocabulary import (
    LEGACY_DIRECT_COMPONENT_LOCATIONS as _LEGACY_DIRECT_COMPONENT_LOCATIONS,
)
from .dashboard_vocabulary import MEASUREMENT_TITLES as _MEASUREMENT_TITLES
from .dashboard_vocabulary import RESULT_VIEW_KEYS
from .dashboard_vocabulary import STATUS_WEIGHT as _STATUS_WEIGHT
from .operator_context import (
    PERFORMANCE_FINDINGS,
    connection_story,
    contextual_results,
    endpoint_zones,
)


def friendly_operator_text(value: Any) -> str:
    """Translate legacy internal topology wording for operator-facing text."""
    return _central_friendly_operator_text(value)


def friendly_scenario(value: Any) -> str:
    return _central_friendly_scenario(value)


def _canonical_measurement(value: Any) -> str:
    measurement = str(value or "")
    return "concurrent-path-load" if measurement == "fabric-scale" else measurement


def _safe_fragmentation_view(fragmentation: dict[str, Any]) -> dict[str, Any]:
    """Keep component attribution only when component-local evidence exists."""

    safe = dict(fragmentation)
    location = str(safe.get("fragmentation_location") or "")
    label = str(safe.get("fragmentation_location_label") or "")
    component = dict(safe.pop("component_inference", None) or {})
    component_evidence = component.get("component_local_evidence")
    directly_observed = bool(
        isinstance(component_evidence, dict)
        and component_evidence.get("directly_observed") is True
        and str(component_evidence.get("observer") or "").strip()
        and str(component_evidence.get("observed_at") or "").strip()
        and str(component_evidence.get("method") or "").strip()
        and component_evidence.get("result") is not None
        and component.get("directly_observed") is True
        and safe.get("component_attribution_directly_observed") is True
    )
    legacy_component_claim = location in _LEGACY_DIRECT_COMPONENT_LOCATIONS or (
        "router fragmented" in label.lower()
    )
    if directly_observed:
        component["directly_observed"] = True
        safe["component_observation"] = component
        return safe

    safe["component_attribution_directly_observed"] = False
    safe["router_fragmentation_observed"] = None
    safe["ovn_router_fragmentation_observed"] = None
    if legacy_component_claim:
        safe["fragmentation_location"] = None
        safe["fragmentation_location_label"] = None
        safe["attribution_reason"] = (
            "No component-local fragmentation observation was recorded."
        )
    return safe


def _num(value: Any) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed == parsed else None


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    try:
        return dt.datetime.fromisoformat(text.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return text


def friendly_host(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return "—"
    first = text.split(".", 1)[0]
    match = re.search(
        r"(?:^|[-_])(compute|controller|network|storage|infra|utility|spine|leaf)(?:[-_]?)(\d+)",
        first,
        re.I,
    )
    if match:
        return f"{match.group(1).lower()}{match.group(2)}"
    for prefix in ("openstack-", "nova-", "host-"):
        if first.lower().startswith(prefix):
            first = first[len(prefix) :]
            break
    return first or text


def _strip_zone(text: str) -> str:
    return re.sub(r"\s*\[[^\]]+\]", "", text).strip()


def friendly_endpoint(value: Any) -> dict[str, Any]:
    raw = str(value or "").strip()
    if not raw:
        return {
            "raw": "",
            "label": "—",
            "ip": None,
            "side": None,
            "zone": None,
            "network": None,
            "description": "Endpoint identity was not recorded.",
        }
    zone = None
    body = raw
    possible_zone, separator, endpoint_body = body.partition("/")
    # Legacy endpoints use ``zone/label``. Descriptions use ``label / detail``.
    if (
        separator
        and possible_zone
        and endpoint_body
        and not possible_zone[-1].isspace()
        and not endpoint_body[0].isspace()
    ):
        zone = possible_zone
        body = endpoint_body
    ip_match = re.search(r"\s+\(([^()]+)\)\s*$", body)
    ip = ip_match.group(1).strip() if ip_match else None
    if ip_match:
        body = body[: ip_match.start()].strip()
    body = _strip_zone(body)
    side_match = re.search(r":([AB])$", body)
    side = side_match.group(1) if side_match else None
    if side_match:
        body = body[: side_match.start()].strip()

    # A raw IP endpoint is common for external targets and the Flux runner.
    if ip is None and re.fullmatch(r"[0-9a-fA-F:.]+", body):
        ip = body

    label = body
    network = None
    description = "Network endpoint"
    patterns = (
        (r"^Provider\s+(.+)$", r"\1", "Provider network endpoint"),
        (
            r"^IPv4 tenant connectivity through\s+(.+)$",
            r"Project endpoint behind router",
            r"Project endpoint behind a Neutron router; the external gateway network is \1.",
        ),
        (
            r"^IPv6 tenant connectivity through\s+(.+)$",
            r"Project endpoint behind router",
            r"Project endpoint behind a Neutron router; the external gateway network is \1.",
        ),
        (
            r"^IPv4 tenant networks from (.+) on one Neutron router$",
            r"Project subnet",
            r"Project subnet reached through one Neutron router; subnet pool \1.",
        ),
        (
            r"^IPv6 tenant networks from (.+) on one Neutron router$",
            r"Project subnet",
            r"Project subnet reached through one Neutron router; subnet pool \1.",
        ),
        (
            r"^IPv4 two-router extra-route topology from (.+)$",
            r"Project subnet behind router",
            "Endpoint in a two-router static-routing topology",
        ),
        (
            r"^IPv6 two-router extra-route topology from (.+)$",
            r"Project subnet behind router",
            "Endpoint in a two-router static-routing topology",
        ),
    )
    for pattern, replacement, meaning in patterns:
        match = re.match(pattern, label)
        if match:
            network = match.group(1) if match.groups() else None
            label = re.sub(pattern, replacement, label)
            description = match.expand(meaning)
            break
    if label == "Flux runner":
        description = "Host running Neutron Flux"
    elif ip and label == ip:
        description = "External or controller address"
    if side:
        label = f"{label} {side}"
    return {
        "raw": raw,
        "label": label,
        "ip": ip,
        "side": side,
        "zone": zone,
        "network": network,
        "description": description,
    }


def _endpoint_availability_zone(
    details: dict[str, Any],
    path: dict[str, Any],
    role: str,
    endpoint: dict[str, Any],
) -> str | None:
    """Prefer recorded endpoint placement over legacy display-label prefixes."""
    zone = (
        path.get(f"{role}_availability_zone")
        or details.get(f"{role}_availability_zone")
        or (details.get("availability_zone") if role == "source" else None)
        or endpoint.get("zone")
    )
    return str(zone).strip() or None if zone is not None else None


def friendly_title(result: dict[str, Any]) -> str:
    return test_name(result)


def _phase(result: dict[str, Any]) -> str:
    return result_context(result)["timing"]


def _placement(result: dict[str, Any]) -> str:
    return result_context(result)["placement"]


def _family(result: dict[str, Any]) -> int | None:
    details = result.get("details") or {}
    path = details.get("path") or {}
    value = path.get("family", result.get("family"))
    try:
        return int(value)
    except (TypeError, ValueError):
        display = str(result.get("display_name") or "")
        if "IPv6" in display:
            return 6
        if "IPv4" in display:
            return 4
        return None


def _severity(result: dict[str, Any]) -> str:
    status = str(result.get("status") or "UNKNOWN")
    if status == "ERROR":
        return "error"
    if status == "FAIL":
        return "critical"
    if status in {
        "BLOCKED_BY_SETUP_ERROR",
        "BLOCKED_BY_PREREQUISITE",
        "NOT_RUN_CANCELLED",
    }:
        return "blocked"
    if status == "UNVERIFIED":
        return "unverified"
    if status in {"SKIP", "NOT_APPLICABLE"}:
        return "neutral"
    if status == "PASS" and needs_attention(result):
        return "warning"
    return "good"


def _result_status_weight(result: dict[str, Any]) -> int:
    weight = _STATUS_WEIGHT.get(str(result.get("status") or ""), 15)
    if result.get("status") == "PASS" and needs_attention(result):
        weight = max(weight, 15)
    return weight


def _result_identity(index: int, result: dict[str, Any]) -> str:
    test_id = str(result.get("test_id") or "").strip()
    return test_id or f"result-{index + 1:04d}"


def _external_destination(result: dict[str, Any]) -> bool:
    return (
        result.get("category") == "egress"
        or (result.get("details") or {}).get("operation") == "egress"
    )


def _path_seed(result: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    details = result.get("details") or {}
    path = details.get("path") or {}
    src = friendly_endpoint(result.get("source") or path.get("source_label"))
    dst = friendly_endpoint(result.get("destination") or path.get("destination_label"))
    if not src.get("ip"):
        src["ip"] = path.get("source_ip")
    if not dst.get("ip"):
        dst["ip"] = path.get("destination_ip")
    if (src["label"] == "—" or src.get("label") == src.get("ip")) and path.get(
        "source_label"
    ):
        original_ip = src.get("ip")
        src = friendly_endpoint(path.get("source_label"))
        src["ip"] = src.get("ip") or original_ip or path.get("source_ip")
    if (dst["label"] == "—" or dst.get("label") == dst.get("ip")) and path.get(
        "destination_label"
    ):
        original_ip = dst.get("ip")
        dst = friendly_endpoint(path.get("destination_label"))
        dst["ip"] = dst.get("ip") or original_ip or path.get("destination_ip")
    if not src.get("ip") and not dst.get("ip") and not path.get("path_id"):
        return None
    family = _family(result)
    phase = _phase(result)
    canonical = str(path.get("path_id") or "")
    if not canonical:
        canonical = "|".join(
            [
                str(src.get("ip") or src.get("label") or "source"),
                str(dst.get("ip") or dst.get("label") or "destination"),
                str(family or 0),
                phase,
                str(
                    path.get("source_group_id") or details.get("source_group_id") or ""
                ),
                str(
                    path.get("destination_group_id")
                    or details.get("destination_group_id")
                    or ""
                ),
                str(
                    path.get("source_subnet_id")
                    or details.get("source_subnet_id")
                    or ""
                ),
                str(
                    path.get("destination_subnet_id")
                    or details.get("destination_subnet_id")
                    or ""
                ),
                str(
                    path.get("source_endpoint_side")
                    or details.get("source_endpoint_side")
                    or ""
                ),
                str(
                    path.get("destination_endpoint_side")
                    or details.get("destination_endpoint_side")
                    or ""
                ),
                str(details.get("host_qualification_pair_id") or ""),
                str(details.get("host_qualification_cycle") or ""),
            ]
        )
    source_host = path.get("source_compute_host") or details.get("source_compute_host")
    destination_host = path.get("destination_compute_host") or details.get(
        "destination_compute_host"
    )
    external_destination = _external_destination(result)
    if external_destination:
        destination_host = None
        dst["label"] = "External destination"
    zone = src["zone"] = _endpoint_availability_zone(details, path, "source", src)
    destination_zone = dst["zone"] = _endpoint_availability_zone(
        details, path, "destination", dst
    )
    if external_destination:
        destination_zone = dst["zone"] = None
    placement = _placement(result)
    return canonical, {
        "canonical_id": canonical,
        "source": src,
        "destination": dst,
        "source_ip": src.get("ip"),
        "destination_ip": dst.get("ip"),
        "family": family,
        "family_label": f"IPv{family}" if family else "IP family unavailable",
        "phase": phase,
        "measurement_stage": path.get("stage"),
        "placement": placement,
        "source_host": source_host,
        "destination_host": destination_host,
        "source_group_id": path.get("source_group_id"),
        "destination_group_id": path.get("destination_group_id"),
        "source_endpoint_side": path.get("source_endpoint_side") or src.get("side"),
        "destination_endpoint_side": path.get("destination_endpoint_side")
        or dst.get("side"),
        "source_host_alias": friendly_host(source_host),
        "destination_host_alias": None
        if external_destination
        else friendly_host(destination_host),
        "availability_zone": zone,
        "source_availability_zone": zone,
        "destination_availability_zone": None
        if external_destination
        else destination_zone or zone,
        "expected_mtu": path.get("expected_mtu"),
    }


def _measurement_summary(result: dict[str, Any]) -> dict[str, Any] | None:
    details = result.get("details") or {}
    name = _canonical_measurement(details.get("measurement"))
    metrics = details.get("metrics") or {}
    translated_path_kinds = {
        "source-nat-to-runner",
        "floating-ip-to-runner",
        "source-nat-to-provider-observer",
        "floating-ip-to-provider-observer",
    }
    if not name and details.get("path_kind") in translated_path_kinds:
        name = "mtu-mss"
        forward = dict(details.get("mtu_profile") or {})
        forward["fragmentation"] = details.get("fragmentation_profile") or {}
        metrics = {
            "expected_mtu": details.get("expected_no_fragment_path_mtu"),
            "source_mtu": details.get("source_network_mtu"),
            "destination_mtu": details.get(
                "provider_observer_interface_mtu", details.get("runner_interface_mtu")
            ),
            "external_provider_mtu": details.get("external_provider_network_mtu"),
            "contract_authoritative": (details.get("mtu_contract") or {}).get(
                "authoritative"
            ),
            "contract_authority_summary": (details.get("mtu_contract") or {}).get(
                "authority_summary"
            ),
            "mtu_constraints": details.get("mtu_constraints") or [],
            "limiting_mtu_constraints": details.get("limiting_mtu_constraints") or [],
            "mtu_contract_formula": (details.get("mtu_contract") or {}).get("formula"),
            "mtu_contract_fallback_used": (details.get("mtu_contract") or {}).get(
                "fallback_used"
            ),
            "directions": ["forward"],
            "forward": forward,
            "egress_translation_mode": details.get("egress_translation_mode"),
            "translated_source_ip": details.get(
                "translated_source_ip_observed_by_provider",
                details.get("translated_source_ip_observed_by_runner"),
            ),
            "translation_observer": details.get("provider_observer") or {},
            "expected_translation_ips": details.get("expected_translation_ips") or [],
            "translation_matches": details.get("translation_matches_expected_identity"),
            "floating_ip": details.get("floating_ip"),
        }
    if not name:
        return None
    summary: dict[str, Any] = {
        "kind": name,
        "title": _MEASUREMENT_TITLES.get(str(name), friendly_title(result)),
        "status": result.get("status"),
        "health": details.get("health")
        or ("critical" if result.get("status") == "FAIL" else "good"),
        "message": result.get("message"),
        "warning_reasons": list(details.get("warning_reasons") or []),
        "values": {},
    }
    values = summary["values"]
    if name == "tcp-throughput":
        for direction in ("forward", "reverse"):
            streams = (metrics.get(direction) or {}).get("streams") or {}
            sample = streams.get("1") or streams.get(1) or {}
            values[f"{direction}_mbps"] = _num(sample.get("median_mbps"))
            values[f"{direction}_retransmissions"] = _num(
                sample.get("total_retransmissions")
            )
        bidir = metrics.get("bidirectional") or {}
        values["bidirectional_mbps"] = _num(bidir.get("aggregate_mbps"))
    elif name == "latency":
        for direction in ("forward", "reverse"):
            values[f"idle_{direction}_p95_ms"] = _num(
                ((metrics.get("idle") or {}).get(direction) or {}).get("p95_ms")
            )
            values[f"loaded_{direction}_p95_ms"] = _num(
                ((metrics.get("loaded") or {}).get(direction) or {}).get("p95_ms")
            )
            values[f"loaded_{direction}_ratio"] = _num(
                (metrics.get("loaded_p95_ratio") or {}).get(direction)
            )
    elif name == "udp":
        values.update(udp_measurement_values(metrics))
    elif name == "mtu-mss":
        values["expected_mtu"] = _num(metrics.get("expected_mtu"))
        values["source_mtu"] = _num(metrics.get("source_mtu"))
        values["destination_mtu"] = _num(metrics.get("destination_mtu"))
        values["external_provider_mtu"] = _num(metrics.get("external_provider_mtu"))
        values["egress_translation_mode"] = metrics.get("egress_translation_mode")
        values["translated_source_ip"] = metrics.get("translated_source_ip")
        values["expected_translation_ips"] = (
            metrics.get("expected_translation_ips") or []
        )
        values["translation_matches"] = metrics.get("translation_matches")
        values["floating_ip"] = metrics.get("floating_ip")
        values["contract_authoritative"] = metrics.get("contract_authoritative")
        values["contract_authority_summary"] = metrics.get("contract_authority_summary")
        values["mtu_constraints"] = metrics.get("mtu_constraints") or []
        values["limiting_mtu_constraints"] = (
            metrics.get("limiting_mtu_constraints") or []
        )
        values["mtu_contract_formula"] = metrics.get("mtu_contract_formula")
        values["mtu_contract_fallback_used"] = metrics.get("mtu_contract_fallback_used")
        for direction in ("forward", "reverse"):
            sample = metrics.get(direction) or {}
            values.update(mtu_boundary_values(sample, direction))
            values[f"{direction}_client_mss"] = _num(sample.get("client_mss"))
            values[f"{direction}_server_mss"] = _num(sample.get("server_mss"))
            values[f"{direction}_confidence"] = sample.get("discovery_confidence")
            values[f"{direction}_contract_status"] = sample.get(
                "advertised_mtu_contract_status"
            )
            values[f"{direction}_pmtud_status"] = sample.get("pmtud_status")
            values[f"{direction}_pmtud_explanation"] = sample.get("pmtud_explanation")
            persistence = sample.get("post_migration_persistence") or {}
            values[f"{direction}_persistence"] = persistence.get("classification")
            values[f"{direction}_persistence_reason"] = persistence.get("reason")
            values[f"{direction}_persistence_samples"] = (
                persistence.get("samples") or []
            )
            fragmentation = _safe_fragmentation_view(sample.get("fragmentation") or {})
            values[f"{direction}_fragmentation_capability"] = fragmentation.get(
                "capability"
            )
            values[f"{direction}_fragmentation_model"] = fragmentation.get(
                "fragmentation_model"
            )
            values[f"{direction}_fragmentation_packet_size"] = _num(
                fragmentation.get("tested_packet_size")
            )
            values[f"{direction}_fragmentation_reason"] = fragmentation.get("reason")
            values[f"{direction}_fragmentation_location"] = fragmentation.get(
                "fragmentation_location"
            )
            values[f"{direction}_fragmentation_location_label"] = fragmentation.get(
                "fragmentation_location_label"
            )
            values[f"{direction}_fragmentation_attribution_confidence"] = (
                fragmentation.get("attribution_confidence")
            )
            values[f"{direction}_fragmentation_attribution_reason"] = fragmentation.get(
                "attribution_reason"
            )
            values[f"{direction}_fragmentation_endpoint_observations"] = (
                fragmentation.get("endpoint_observations") or {}
            )
            values[f"{direction}_fragmentation_component_observation"] = (
                fragmentation.get("component_observation") or {}
            )
            values[f"{direction}_fragmentation_component_directly_observed"] = (
                fragmentation.get("component_attribution_directly_observed") is True
                and (fragmentation.get("component_observation") or {}).get(
                    "directly_observed"
                )
                is True
            )
            values[f"{direction}_router_ids"] = fragmentation.get("router_ids") or []
            values[f"{direction}_router_backend_evidence"] = (
                fragmentation.get("router_backend_evidence") or {}
            )
            values[f"{direction}_source_fragment_counter_delta"] = (
                fragmentation.get("source_fragment_counter_delta") or {}
            )
            values[f"{direction}_destination_reassembly_counter_delta"] = (
                fragmentation.get("destination_reassembly_counter_delta") or {}
            )
    elif name == "concurrency":
        for direction in ("forward", "reverse"):
            sample = metrics.get(direction) or {}
            values[f"{direction}_best_aggregate_mbps"] = _num(
                sample.get("best_aggregate_mbps")
            )
            fairness = [
                _num(value)
                for key, value in (sample.get("fairness") or {}).items()
                if str(key) != "1"
            ]
            values[f"{direction}_minimum_fairness"] = min(
                (value for value in fairness if value is not None), default=None
            )
    elif name == "asymmetry":
        values["throughput_difference_pct"] = _num(
            metrics.get("throughput_difference_pct")
        )
        values["latency_difference_pct"] = _num(metrics.get("latency_difference_pct"))
        values["udp_loss_difference_pct"] = _num(
            metrics.get(
                "udp_loss_difference_pct_points", metrics.get("udp_loss_difference_pct")
            )
        )
        for component in ("tcp", "latency", "udp"):
            values[component + "_health"] = metrics.get(component + "_health")
        values["udp_compared_profiles"] = metrics.get("udp_compared_profiles")
        values["udp_unmatched_profiles"] = metrics.get("udp_unmatched_profiles")
    elif name == "repeatability":
        values["worst_variation_pct"] = _num(metrics.get("worst_variation_pct"))
    elif name == "concurrent-path-load":
        values["levels"] = list(metrics.get("levels") or [])
    return summary


def _connectivity_summary(results: Iterable[dict[str, Any]]) -> dict[str, Any]:
    protocols: dict[str, dict[str, Any]] = {}
    relevant = []
    for result in results:
        if (result.get("details") or {}).get("performance"):
            continue
        details = result.get("details") or {}
        protocol: str | None = str(details.get("protocol") or "").upper()
        if protocol not in {"ICMP", "TCP", "UDP"}:
            display = (
                f"{result.get('display_name', '')} {result.get('test_id', '')}".upper()
            )
            protocol = next(
                (
                    name
                    for name, pattern in (
                        ("ICMP", r"\b(?:ICMP|PING)\b"),
                        ("TCP", r"\b(?:TCP|SSH)\b"),
                        ("UDP", r"\bUDP\b"),
                    )
                    if re.search(pattern, display)
                ),
                None,
            )
        if protocol:
            previous = protocols.get(protocol)
            if previous is None or _result_status_weight(result) > previous["weight"]:
                protocols[protocol] = {
                    "status": result.get("status"),
                    "observed": result.get("observed"),
                    "expected": result.get("expected"),
                    "result_id": result.get("result_id"),
                    "weight": _result_status_weight(result),
                }
            relevant.append(result)
    worst = max(relevant, key=_result_status_weight, default=None)
    for sample in protocols.values():
        sample.pop("weight")
    return {
        "status": worst.get("status") if worst else "PASS",
        "protocols": protocols,
        "tested": len(relevant),
    }


def _path_health(path: dict[str, Any]) -> str:
    severities = {result.get("severity") for result in path.get("results", [])}
    if "error" in severities:
        return "error"
    if "critical" in severities:
        return "critical"
    if "warning" in severities:
        return "warning"
    if severities & {"blocked", "unverified"}:
        return "unverified"
    if severities == {"neutral"}:
        return "neutral"
    return "good"


def _root_key(result: dict[str, Any]) -> tuple[str, str]:
    details = result.get("details") or {}
    category = str(result.get("category") or "validation")
    measurement = str(details.get("measurement") or "")
    status = str(result.get("status") or "").upper()
    if details.get("tool_failure") or details.get("root_lane_error"):
        phase = str(details.get("failure_phase") or "").lower()
        setup_failure = not is_execution_lane_failure(details) and (
            details.get("root_setup_error") or "controller" in phase or "setup" in phase
        )
        return (
            (
                "neutron-flux-controller-setup",
                "Neutron Flux controller setup did not complete",
            )
            if setup_failure
            else (
                "neutron-flux-execution",
                "Neutron Flux could not complete an execution lane",
            )
        )
    if status in {
        "BLOCKED_BY_SETUP_ERROR",
        "BLOCKED_BY_PREREQUISITE",
        "NOT_RUN_CANCELLED",
    }:
        return (
            "coverage-not-run",
            "Validations were not run because an earlier stage did not complete",
        )
    if status == "ERROR":
        return "execution", "Flux could not complete a validation operation"
    story = connection_story(result)
    if story:
        return "translated-tcp-connect", story["title"]
    if measurement == "asymmetry":
        return (
            "direction",
            "Forward/reverse comparison is incomplete"
            if status == "UNVERIFIED"
            else "Directional measurements require review",
        )
    if measurement in PERFORMANCE_FINDINGS:
        return PERFORMANCE_FINDINGS[measurement]
    if category == "compute-placement":
        explanation = explain_result(result)
        if explanation["kind"] == "migration-port-validation-failed":
            return "migration-port-validation", explanation["headline"]
        if explanation["kind"] == "interruption-tolerance-exceeded":
            return "migration-interruption", explanation["headline"]
        return "migration", "Placement or migration validation requires review"
    text = " ".join(
        str(value or "")
        for value in (
            result.get("display_name"),
            result.get("message"),
            category,
            measurement,
        )
    ).lower()
    if "mtu" in text or "pmtud" in text or "mss" in text:
        return "mtu", "Packet-size validation requires review"
    if "udp" in text and ("loss" in text or "reorder" in text or "jitter" in text):
        return "udp", "UDP packet quality requires review"
    if "latency" in text:
        return "latency", "Latency measurements require review"
    if "asymmetry" in text or "directional" in text:
        return "direction", "Directional measurements require review"
    if "repeatability" in text or "variation" in text:
        return "repeatability", "Repeated performance measurements require review"
    if "router" in text and "lifecycle" in text:
        return "router-lifecycle", "Router-interface lifecycle did not complete cleanly"
    if "migration" in text:
        return "migration", "Migration lifecycle requires review"
    if "connect" in text or "reachable" in text or "blocked" in text:
        return "connectivity", "Connectivity validation requires review"
    if status == "ERROR":
        return "execution", "Flux could not complete a validation operation"
    return category, f"{friendly_title(result)} requires review"


def _incident_group_key(result: dict[str, Any]) -> tuple[str, str, str]:
    """Return a stable incident identity, root family, and display title."""

    details = result.get("details") or {}
    root, title = _root_key(result)
    explicit = str(
        details.get("dependent_on_incident_id") or details.get("root_incident_id") or ""
    ).strip()
    if explicit:
        return f"incident:{explicit}", root, title
    blocked_by = str(details.get("blocked_by") or "").strip()
    if blocked_by:
        return f"blocked-by:{blocked_by}", root, title
    # Older and non-cascaded results do not carry an explicit incident ID.
    # Preserve their established root-family grouping instead of inventing one
    # incident per path.
    return root, root, title


def _incident_source(result: dict[str, Any]) -> bool:
    """Exclude advisory PASS and non-authoritative observation-only rows."""

    status = str(result.get("status") or "").upper()
    details = result.get("details") or {}
    if details.get("check_sample") and not details.get("tool_failure"):
        return False
    if details.get("dependent_on_incident_id"):
        return True
    if status in {"FAIL", "ERROR"}:
        return True
    if status != "UNVERIFIED":
        return False
    authority = str(result.get("authority_classification") or "").lower()
    expectation = str(result.get("expected") or "").lower()
    observation_only = (
        "observation" in expectation
        or authority in {"observation", "non-authoritative", "informational"}
        or details.get("observation_only") is True
    )
    return not observation_only


def _finding_group(result: dict[str, Any]) -> str:
    severity = result.get("severity")
    if severity == "critical":
        return "confirmed"
    if severity == "error":
        return "errors"
    if severity == "warning":
        return "advisories"
    if severity == "blocked":
        return "blocked"
    return "observations"


def _series_summary(values: Iterable[Any]) -> dict[str, float | int | None]:
    numbers = [
        float(value)
        for value in values
        if isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    ]
    if not numbers:
        return {
            "samples": 0,
            "median": None,
            "minimum": None,
            "maximum": None,
            "variation_pct": None,
            "coefficient_of_variation_pct": None,
        }
    median = statistics.median(numbers)
    mean = statistics.fmean(numbers)
    deviation = statistics.pstdev(numbers) if len(numbers) > 1 else 0.0
    return {
        "samples": len(numbers),
        "median": median,
        "minimum": min(numbers),
        "maximum": max(numbers),
        "variation_pct": (
            100.0 * (max(numbers) - min(numbers)) / abs(median) if median else 0.0
        ),
        "coefficient_of_variation_pct": (
            100.0 * deviation / abs(mean) if mean else 0.0
        ),
    }


def _host_qualification_model(
    payload: dict[str, Any],
    results: list[dict[str, Any]],
    paths: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    qualification = (
        ((payload.get("plan") or {}).get("host_qualification") or {})
        if isinstance(payload.get("plan"), dict)
        else {}
    )
    if not qualification or not qualification.get("enabled"):
        return {
            "enabled": False,
            "hosts": [],
            "pairs": [],
            "availability_zones": [],
            "inventory_fingerprint": None,
        }

    results_by_pair: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for result in results:
        pair_id = str(
            (result.get("reporting_context") or result.get("details") or {}).get(
                "host_qualification_pair_id"
            )
            or ""
        )
        if pair_id:
            results_by_pair[pair_id].append(result)
    result_path_ids = {
        str(result.get("result_id")): str(result.get("path_id"))
        for result in results
        if result.get("path_id")
    }

    pair_rows: list[dict[str, Any]] = []
    for pair in qualification.get("pairs") or []:
        pair_id = str(pair.get("pair_id") or "")
        pair_results = results_by_pair.get(pair_id, [])
        statuses = Counter(
            str(result.get("status") or "UNKNOWN") for result in pair_results
        )
        worst = max(
            pair_results,
            key=_result_status_weight,
            default=None,
        )
        measurement_rows = [
            summary
            for summary in (_measurement_summary(result) for result in pair_results)
            if summary
        ]

        def measurement_values(
            kind: str,
            *keys: str,
            _rows: list[dict[str, Any]] = measurement_rows,
        ) -> list[float]:
            values: list[float] = []
            for row in _rows:
                if row.get("kind") != kind:
                    continue
                candidates = [_num((row.get("values") or {}).get(key)) for key in keys]
                finite = [value for value in candidates if value is not None]
                if finite:
                    values.append(
                        min(finite)
                        if kind in {"tcp-throughput", "mtu-mss"}
                        else max(finite)
                    )
            return values

        result_ids = {str(result.get("result_id")) for result in pair_results}
        pair_findings = [
            finding["finding_id"]
            for finding in findings
            if result_ids.intersection(finding.get("result_ids") or [])
        ]
        cycles = sorted(
            {
                int(value)
                for value in (
                    (
                        result.get("reporting_context") or result.get("details") or {}
                    ).get("host_qualification_cycle")
                    for result in pair_results
                )
                if isinstance(value, int)
            }
        )
        relationship = (
            "Same host"
            if pair.get("same_host")
            else "Same AZ"
            if pair.get("same_availability_zone")
            else "Cross AZ"
        )
        pair_rows.append(
            {
                **pair,
                "relationship": relationship,
                "severity": (
                    worst.get("severity")
                    if worst
                    else "blocked"
                    if pair.get("status") == "BLOCKED_BY_PREREQUISITE"
                    else "neutral"
                ),
                "status_counts": dict(statuses),
                "result_ids": sorted(result_ids),
                "path_ids": sorted(
                    {
                        result_path_ids[result_id]
                        for result_id in result_ids
                        if result_id in result_path_ids
                    }
                ),
                "finding_ids": pair_findings,
                "finding_count": len(pair_findings),
                "completed_cycles": cycles,
                "families": sorted(
                    {
                        int(result["family_value"])
                        for result in pair_results
                        if result.get("family_value") in {4, 6}
                    }
                ),
                "profiles": sorted(
                    {
                        str((result.get("details") or {}).get("qualification_profile"))
                        for result in pair_results
                        if (result.get("details") or {}).get("qualification_profile")
                    }
                )
                or [str(qualification.get("profile") or "full")],
                "tcp_mbps": _series_summary(
                    measurement_values(
                        "tcp-throughput",
                        "forward_mbps",
                        "reverse_mbps",
                    )
                ),
                "p95_latency_ms": _series_summary(
                    measurement_values(
                        "latency",
                        "idle_forward_p95_ms",
                        "idle_reverse_p95_ms",
                    )
                ),
                "udp_loss_pct": _series_summary(
                    measurement_values(
                        "udp",
                        "forward_loss_pct",
                        "reverse_loss_pct",
                    )
                ),
                "mtu_bytes": _series_summary(
                    measurement_values(
                        "mtu-mss",
                        "forward_discovered_mtu",
                        "reverse_discovered_mtu",
                    )
                ),
                "rerun_fragment": (
                    "--target-host-pairs "
                    f"{pair.get('source_host')}:{pair.get('destination_host')}"
                ),
            }
        )

    pair_ids_by_host: dict[str, list[str]] = defaultdict(list)
    endpoint_rows_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for pair in pair_rows:
        for host in {
            str(pair.get("source_host") or ""),
            str(pair.get("destination_host") or ""),
        }:
            if host:
                pair_ids_by_host[host].append(str(pair.get("pair_id")))
        for result in results_by_pair.get(str(pair.get("pair_id")), []):
            for endpoint in (result.get("details") or {}).get("endpoints") or []:
                host = str(
                    endpoint.get("observed_host")
                    or endpoint.get("requested_host")
                    or ""
                )
                if host and endpoint not in endpoint_rows_by_host[host]:
                    endpoint_rows_by_host[host].append(endpoint)

    hosts = []
    for host in qualification.get("hosts") or []:
        name = str(host.get("host") or "")
        ids = list(dict.fromkeys(pair_ids_by_host.get(name, [])))
        associated_findings = sorted(
            {
                finding_id
                for pair in pair_rows
                if pair.get("pair_id") in ids
                for finding_id in pair.get("finding_ids") or []
            }
        )
        hosts.append(
            {
                **host,
                "pair_ids": ids,
                "endpoints": endpoint_rows_by_host.get(name, []),
                "finding_ids": associated_findings,
                "finding_count": len(associated_findings),
            }
        )

    zones: dict[str, list[str]] = defaultdict(list)
    for host in hosts:
        zone = str(host.get("availability_zone") or "Unknown AZ")
        zones[zone].append(str(host.get("host")))
    return {
        "enabled": True,
        "strategy": qualification.get("strategy"),
        "profile": qualification.get("profile"),
        "cycles": qualification.get("cycles"),
        "include_same_host": qualification.get("include_same_host"),
        "inventory_fingerprint": qualification.get("inventory_fingerprint"),
        "generated_at": qualification.get("generated_at"),
        "requested_hosts": qualification.get("requested_hosts") or [],
        "requested_aggregates": qualification.get("requested_aggregates") or [],
        "requested_pairs": qualification.get("requested_pairs") or [],
        "resolved_aggregate_ids": qualification.get("resolved_aggregate_ids") or [],
        "resolved_aggregate_names": qualification.get("resolved_aggregate_names") or [],
        "estimates": qualification.get("estimates") or {},
        "warnings": qualification.get("warnings") or [],
        "hosts": hosts,
        "pairs": pair_rows,
        "availability_zones": [
            {"name": zone, "hosts": sorted(names)}
            for zone, names in sorted(zones.items())
        ],
    }


def _availability_inventory_from_events(
    payload: dict[str, Any],
) -> tuple[set[str], set[str]]:
    """Extract only the AZ capability schema emitted by ZonePreflight."""
    zones: set[str] = set()
    hosts: set[str] = set()
    events = payload.get("events")
    if not isinstance(events, list):
        return zones, hosts
    for event in events:
        if (
            not isinstance(event, dict)
            or event.get("type") != "availability-zone-scope-validated"
        ):
            continue
        details = event.get("details")
        capabilities = (
            details.get("capabilities") if isinstance(details, dict) else None
        )
        if not isinstance(capabilities, dict):
            continue
        for zone, data in capabilities.items():
            if not isinstance(data, dict):
                continue
            zone_name = str(zone).strip()
            if zone_name:
                zones.add(zone_name)
            enabled_hosts = data.get("enabled_hosts")
            if not isinstance(enabled_hosts, list):
                continue
            hosts.update(
                host_name for host in enabled_hosts if (host_name := str(host).strip())
            )
    return zones, hosts


def _dashboard_result_projection(
    index: int,
    raw: dict[str, Any],
) -> tuple[dict[str, Any], set[str], set[str], set[str]]:
    """Normalize one result and collect its display-level environment identity."""
    result = normalize_result_record(raw, share_evidence=True)
    result_id = _result_identity(index, result)
    source = friendly_endpoint(result.get("source"))
    destination = friendly_endpoint(result.get("destination"))
    details = result.get("details") or {}
    path_details = details.get("path") or {}
    source["zone"] = _endpoint_availability_zone(
        details, path_details, "source", source
    )
    destination["zone"] = _endpoint_availability_zone(
        details, path_details, "destination", destination
    )
    external_destination = _external_destination(result)
    if external_destination:
        destination["label"] = "External destination"
        destination["zone"] = None
    contract = result.get("contract") or {}
    expectation = contract.get("expectation") or {}
    observation = contract.get("observation") or {}
    authority = contract.get("authority") or {}
    signature = result.get("path_signature") or {}
    result_hosts = {
        str(host)
        for host in (
            path_details.get("source_compute_host"),
            None
            if external_destination
            else path_details.get("destination_compute_host"),
            details.get("source_compute_host"),
            None if external_destination else details.get("destination_compute_host"),
            details.get("requested_source_host"),
            None if external_destination else details.get("requested_destination_host"),
            details.get("observed_source_host"),
            None if external_destination else details.get("observed_destination_host"),
        )
        if host
    }
    result_zones = {
        str(endpoint["zone"])
        for endpoint in (source, destination)
        if endpoint.get("zone")
    }
    result_networks: set[str] = set()
    for endpoint in (source, destination):
        label = str(endpoint.get("label") or "")
        if label and label not in {"—", "Flux runner"}:
            result_networks.add(re.sub(r"\s+[AB]$", "", label))

    family = _family(result)
    context = result_context(result)
    row = {
        **result,
        "result_id": result_id,
        "title": friendly_title(result),
        "test_name": test_name(result),
        "execution_name": execution_name(result),
        "human_context": context,
        "context_lines": context["lines"],
        "timing": context["timing"],
        "action": context["action"],
        "scenario_label": friendly_scenario(result.get("scenario")),
        "operator_message": friendly_operator_text(result.get("message")),
        "contract_type": contract.get("type"),
        "contract_description": contract.get("description"),
        "contract_verdict": typed_verdict(result),
        "contract_outcome": (contract.get("verdict") or {}).get("outcome"),
        "expectation_code": expectation.get("code"),
        "expectation_description": expectation.get("description"),
        "expectation_source": (expectation.get("source") or {}).get("classification"),
        "expectation_source_description": (expectation.get("source") or {}).get(
            "description"
        ),
        "permitted_uncertainty": expectation.get("permitted_uncertainty"),
        "observation_code": observation.get("code"),
        "observation_description": observation.get("description"),
        "supporting_result_ids": observation.get("supporting_result_ids") or [],
        "authority_classification": authority.get("classification"),
        "authority_authoritative": authority.get("authoritative"),
        "authority_limitation": authority.get("limitation"),
        "semantic_path_key": signature.get("key"),
        "semantic_path_display": signature.get("display"),
        "packet_size_accounting": contract.get("packet_size"),
        "lifecycle_contract": contract.get("lifecycle"),
        "source_display": source,
        "destination_display": destination,
        "source_ip": source.get("ip"),
        "destination_ip": destination.get("ip"),
        "family_value": family,
        "family_label": f"IPv{family}" if family else "IP family unavailable",
        "phase": _phase(result),
        "placement": _placement(result),
        "severity": _severity(result),
        "canonical_name": result.get("display_name"),
        "search_text": " ".join(
            str(value or "")
            for value in (
                result_id,
                result.get("display_name"),
                result.get("scenario"),
                friendly_scenario(result.get("scenario")),
                result.get("category"),
                result.get("source"),
                result.get("destination"),
                result.get("message"),
                friendly_operator_text(result.get("message")),
                contract.get("type"),
                expectation.get("code"),
                expectation.get("description"),
                observation.get("code"),
                observation.get("description"),
                authority.get("classification"),
                signature.get("key"),
            )
        ).lower(),
    }
    row.pop("likely_failure", None)
    return row, result_hosts, result_networks, result_zones


def _dashboard_result_view(result: dict[str, Any]) -> dict[str, Any]:
    """Return a compact index into the canonical top-level result records."""
    return {key: result.get(key) for key in RESULT_VIEW_KEYS}


def _empty_results_note(run: dict[str, Any], cleanup: dict[str, Any]) -> str:
    if run.get("action") == "cleanup":
        return (
            "This action cleaned eligible test resources; no network tests ran."
            if cleanup.get("complete") is True
            else "This cleanup action ran no network tests."
        )
    return "No network test results were recorded by this action."


def build_dashboard_model(payload: dict[str, Any]) -> dict[str, Any]:
    raw_results = contextual_results(payload)
    result_rows: list[dict[str, Any]] = []
    hosts: set[str] = set()
    networks: set[str] = set()
    zones: set[str] = set(
        payload.get("configuration", {}).get("availability_zones") or []
    )
    raw_qualification = (
        ((payload.get("plan") or {}).get("host_qualification") or {})
        if isinstance(payload.get("plan"), dict)
        else {}
    )
    for host in raw_qualification.get("hosts") or []:
        if host.get("host"):
            hosts.add(str(host["host"]))
        if host.get("availability_zone"):
            zones.add(str(host["availability_zone"]))

    for index, raw in enumerate(raw_results):
        row, row_hosts, row_networks, row_zones = _dashboard_result_projection(
            index, raw
        )
        result_rows.append(row)
        hosts.update(row_hosts)
        networks.update(row_networks)
        zones.update(row_zones)

    # Availability inventory can name hosts even when a run has no path results.
    # Other events also use a ``capabilities`` key, so schema-filter them first.
    event_zones, event_hosts = _availability_inventory_from_events(payload)
    zones.update(event_zones)
    hosts.update(event_hosts)

    # Build paths with performance paths first so functional results can attach to them.
    path_builders: dict[str, dict[str, Any]] = {}
    result_path_key: dict[str, str] = {}
    endpoint_lookup: dict[tuple[Any, ...], list[str]] = defaultdict(list)
    for result in sorted(
        result_rows,
        key=lambda item: 0 if (item.get("details") or {}).get("performance") else 1,
    ):
        seeded = _path_seed(result)
        if seeded is None:
            continue
        key, base = seeded
        lookup_key = (
            base["source"].get("ip"),
            base["destination"].get("ip"),
            base.get("family"),
            base.get("phase"),
            (result.get("reporting_context") or result.get("details") or {}).get(
                "host_qualification_pair_id"
            ),
            (result.get("reporting_context") or result.get("details") or {}).get(
                "host_qualification_cycle"
            ),
            base.get("source_group_id"),
            base.get("destination_group_id"),
        )
        if (
            not (result.get("details") or {}).get("performance")
            and key not in path_builders
        ):
            candidates = endpoint_lookup.get(lookup_key) or []
            if candidates:
                key = candidates[0]
        if key not in path_builders:
            path_builders[key] = {
                **base,
                "results": [],
                "measurements": {},
                "timeline": [],
            }
            endpoint_lookup[lookup_key].append(key)
        path = path_builders[key]
        path["results"].append(result)
        result_path_key[result["result_id"]] = key
        measurement = _measurement_summary(result)
        if measurement:
            measurement["result_id"] = result["result_id"]
            path["measurements"][str(measurement["kind"])] = measurement
        path["timeline"].append(
            {
                "timestamp": _iso(result.get("started_at")),
                "title": result["title"],
                "status": result.get("status"),
                "severity": result["severity"],
                "message": result.get("operator_message") or result.get("message"),
                "result_id": result["result_id"],
            }
        )

    def path_sort(item: tuple[str, dict[str, Any]]) -> tuple[Any, ...]:
        key, path = item
        return (
            0 if path.get("measurements") else 1,
            str(path.get("availability_zone") or ""),
            str(path.get("phase") or ""),
            str(path.get("source", {}).get("label") or ""),
            str(path.get("destination", {}).get("label") or ""),
            int(path.get("family") or 0),
            key,
        )

    paths: list[dict[str, Any]] = []
    for index, (key, path) in enumerate(
        sorted(path_builders.items(), key=path_sort), start=1
    ):
        alias = f"P{index:02d}"
        path["path_id"] = alias
        path["path_number"] = index
        path["path_reference"] = f"Path {index:02d}"
        path["canonical_id"] = key
        path["title"] = f"{path['source']['label']} → {path['destination']['label']}"
        path["endpoint_pair"] = (
            f"{path.get('source_ip') or 'source IP unavailable'} → {path.get('destination_ip') or 'destination IP unavailable'}"
        )
        path["connectivity"] = _connectivity_summary(path["results"])
        path["health"] = _path_health(path)
        path["measurement_count"] = len(path.get("measurements") or {})
        path["is_measurement_path"] = bool(path["measurement_count"])
        path["finding_ids"] = []
        path["result_ids"] = [result["result_id"] for result in path["results"]]
        path["timeline"].sort(key=lambda row: str(row.get("timestamp") or ""))
        path["results"] = [
            {
                "result_id": result["result_id"],
                "title": result["title"],
                "status": result.get("status"),
                "severity": result["severity"],
                "message": result.get("operator_message") or result.get("message"),
                "expected": result.get("expected"),
                "observed": result.get("observed"),
            }
            for result in path["results"]
        ]
        paths.append(path)
    path_alias_by_key = {path["canonical_id"]: path["path_id"] for path in paths}
    for result in result_rows:
        canonical = result_path_key.get(result["result_id"])
        result["path_id"] = path_alias_by_key.get(canonical)

    # Link post-migration measurements to their matching baseline path and
    # precompute the small set of deltas the dashboard needs.
    def comparison_signature(path: dict[str, Any]) -> tuple[Any, ...]:
        return (
            path.get("source", {}).get("ip") or path.get("source", {}).get("label"),
            path.get("destination", {}).get("ip")
            or path.get("destination", {}).get("label"),
            path.get("family"),
            next(
                (
                    (
                        result.get("reporting_context") or result.get("details") or {}
                    ).get("host_qualification_pair_id")
                    for result in result_rows
                    if result.get("path_id") == path.get("path_id")
                ),
                None,
            ),
            next(
                (
                    (
                        result.get("reporting_context") or result.get("details") or {}
                    ).get("host_qualification_cycle")
                    for result in result_rows
                    if result.get("path_id") == path.get("path_id")
                ),
                None,
            ),
        )

    baseline_by_signature = {
        comparison_signature(path): path
        for path in paths
        if path.get("is_measurement_path")
        and (
            path.get("phase") == "Before migration"
            or (
                path.get("phase") == "Migration timing not recorded"
                and path.get("measurement_stage") in {"group-local", "cross-topology"}
            )
        )
    }

    def measurement_value(path: dict[str, Any], kind: str, key: str) -> float | None:
        return _num(
            (
                ((path.get("measurements") or {}).get(kind) or {}).get("values") or {}
            ).get(key)
        )

    for path in paths:
        if path.get("phase") != "After migration" or not path.get(
            "is_measurement_path"
        ):
            continue
        baseline = baseline_by_signature.get(comparison_signature(path))
        if baseline is None:
            continue
        definitions = (
            ("TCP forward", "tcp-throughput", "forward_mbps", "mbps"),
            ("TCP reverse", "tcp-throughput", "reverse_mbps", "mbps"),
            (
                "95th-percentile idle latency: source to destination",
                "latency",
                "idle_forward_p95_ms",
                "ms",
            ),
            (
                "95th-percentile idle latency: destination to source",
                "latency",
                "idle_reverse_p95_ms",
                "ms",
            ),
            (
                "Loaded-to-idle latency ratio: source to destination",
                "latency",
                "loaded_forward_ratio",
                "ratio",
            ),
            (
                "Loaded-to-idle latency ratio: destination to source",
                "latency",
                "loaded_reverse_ratio",
                "ratio",
            ),
            (
                "UDP application-delivery loss forward",
                "udp",
                "forward_loss_pct",
                "percent",
            ),
            (
                "UDP application-delivery loss reverse",
                "udp",
                "reverse_loss_pct",
                "percent",
            ),
            (
                "Confirmed no-fragment path MTU: source to destination",
                "mtu-mss",
                "forward_discovered_mtu",
                "bytes",
            ),
            (
                "Confirmed no-fragment path MTU: destination to source",
                "mtu-mss",
                "reverse_discovered_mtu",
                "bytes",
            ),
        )
        rows = []
        for label, kind, key, unit in definitions:
            before = measurement_value(baseline, kind, key)
            after = measurement_value(path, kind, key)
            if before is None and after is None:
                continue
            delta = after - before if before is not None and after is not None else None
            delta_pct = (
                (100.0 * delta / abs(before))
                if delta is not None and before not in (0, None)
                else None
            )
            rows.append(
                {
                    "label": label,
                    "unit": unit,
                    "before": before,
                    "after": after,
                    "delta": delta,
                    "delta_pct": delta_pct,
                }
            )
        path["comparison"] = {
            "baseline_path_id": baseline["path_id"],
            "rows": rows,
        }
        baseline.setdefault("post_migration_path_ids", []).append(path["path_id"])

    # Group actionable results into compact findings.
    finding_sources = [
        result
        for result in logical_results({**payload, "results": result_rows})
        if _incident_source(result)
    ]
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    incident_metadata: dict[str, tuple[str, str]] = {}
    for result in finding_sources:
        incident_key, root, title = _incident_group_key(result)
        grouped[incident_key].append(result)
        incident_metadata.setdefault(incident_key, (root, title))
    findings: list[dict[str, Any]] = []
    for index, (incident_key, items) in enumerate(
        sorted(
            grouped.items(),
            key=lambda entry: (
                -max(_result_status_weight(item) for item in entry[1]),
                entry[0],
            ),
        ),
        start=1,
    ):
        path_ids = tuple(
            sorted({str(item.get("path_id")) for item in items if item.get("path_id")})
        )
        root, title = incident_metadata[incident_key]
        Counter(_finding_group(item) for item in items)
        severity = max(items, key=_result_status_weight)["severity"]
        finding_id = f"F{index:02d}"
        finding_reference = f"Finding {index}"
        measurements = finding_measurements(items)
        status_counts = Counter(str(item.get("status")) for item in items)
        affected_zones = sorted(
            {
                str(zone)
                for item in items
                for zone in (
                    (item.get("source_display") or {}).get("zone"),
                    (item.get("destination_display") or {}).get("zone"),
                    (item.get("details") or {}).get("availability_zone"),
                    *endpoint_zones(item.get("details") or {}),
                )
                if zone
            }
        )
        summary = finding_summary(
            root,
            items,
            path_count=len(path_ids),
            measurements=measurements,
            status_counts=status_counts,
        )
        finding = {
            "finding_id": finding_id,
            "finding_number": index,
            "finding_reference": finding_reference,
            "root_key": root,
            "incident_key": incident_key,
            "title": title,
            "severity": severity,
            "group": _finding_group(max(items, key=_result_status_weight)),
            "summary": summary,
            "path_ids": list(path_ids),
            "result_ids": [item["result_id"] for item in items],
            "result_count": len(items),
            "measurements": measurements,
            "status_counts": dict(status_counts),
            "affected_zones": affected_zones,
            "affected_categories": sorted(
                {str(item.get("category")) for item in items if item.get("category")}
            ),
        }
        findings.append(finding)
        for path in paths:
            if path["path_id"] in path_ids:
                path["finding_ids"].append(finding_id)

    # Environment inventory.
    host_aliases = [
        {"alias": friendly_host(host), "full_name": host}
        for host in sorted(hosts, key=lambda value: (friendly_host(value), value))
    ]
    resources = list(payload.get("resources") or [])
    discovery = payload.get("discovery") or {}
    allocation = _allocation_model(payload, resources)
    network_inventory, network_names = build_network_inventory(
        discovery, resources, allocation, raw_results
    )
    _attach_path_allocation_context(paths, allocation, network_names)
    environment = build_environment_summary(
        discovery=discovery,
        zones=zones,
        host_aliases=host_aliases,
        resources=resources,
        allocation=allocation,
        network_inventory=network_inventory,
        paths=paths,
    )
    cleanup = payload.get("cleanup") or {}
    cleanup_present = sum(
        1
        for resource in resources
        if str(resource.get("cleanup_state") or "").upper() not in {"DELETED", "ABSENT"}
    )
    counts = Counter(
        str(result.get("status") or "UNKNOWN")
        for result in logical_results({**payload, "results": result_rows})
    )
    health_counts = Counter(path["health"] for path in paths)
    attention_count = len(findings)
    run = payload.get("run") or {}
    narrative = []
    setup_failure_count = len(payload.get("setup_failures") or [])
    blocked_count = sum(
        counts.get(status, 0)
        for status in ("BLOCKED_BY_SETUP_ERROR", "BLOCKED_BY_PREREQUISITE")
    )
    if findings:
        narrative.append(
            f"The run completed with {len(findings)} grouped condition{'s' if len(findings) != 1 else ''} requiring review."
        )
        for finding in findings[:2]:
            affected = len(finding["path_ids"])
            suffix = (
                f" across {affected} endpoint pair{'s' if affected != 1 else ''}"
                if affected
                else ""
            )
            narrative.append(f"{finding['title']}{suffix}.")
    elif not (setup_failure_count or blocked_count):
        narrative.append(
            "All executed validations matched their expected behaviour."
            if counts
            else _empty_results_note(run, cleanup)
        )
    if setup_failure_count or blocked_count:
        narrative.append(
            "Tool/setup failures did not create additional cloud-network findings; "
            f"{blocked_count} planned validation(s) were blocked."
        )
    if cleanup.get("complete") is True and cleanup_present == 0:
        narrative.append(
            "Cleanup completed for the eligible scope; all tracked resource records "
            "are marked absent or deleted."
        )
    elif cleanup.get("complete") is False or cleanup_present:
        narrative.append(
            "Cleanup requires review because resources or operations remain unresolved."
        )
    # A compact event stream for the Evidence workspace.
    events = []
    for index, event in enumerate(payload.get("events") or []):
        details = event.get("details") or {}
        event_type = canonical_operation_event_type(str(event.get("type") or "event"))
        if event_type not in {
            "live-migration-complete",
            "migration-functional-safety-observation",
            "migration-safety-observation",
            "cloud-operation-transaction-start",
            "cloud-operation-transaction-finish",
            "dataplane-settlement",
            "server-ready",
            "group-ready",
        }:
            continue
        events.append(
            {
                "event_id": f"E{index + 1:04d}",
                "event_reference": f"Event {index + 1}",
                "timestamp": _iso(event.get("timestamp")),
                "type": event_type,
                "title": event_type.replace("-", " ").title(),
                "message": friendly_operator_text(event.get("message")),
                "operation_id": details.get("operation_id"),
                "transaction_id": details.get("transaction_id"),
                "source_host": friendly_host(details.get("source_host")),
                "destination_host": friendly_host(details.get("destination_host")),
                "details": details,
            }
        )
    events.sort(key=lambda event: str(event.get("timestamp") or ""))
    host_qualification = _host_qualification_model(
        payload,
        result_rows,
        paths,
        findings,
    )

    model = {
        # Typed network contracts and semantic paths carry their own evidence.
        "model_version": 15,
        "report_shape_version": 13,
        "glossary": list(_GLOSSARY),
        "environment": environment,
        "aliases": {"hosts": host_aliases},
        "results": result_rows,
        "paths": paths,
        "findings": findings,
        "events": events,
        "host_qualification": host_qualification,
        "contracts": {
            "types": dict(
                Counter(
                    str(item.get("contract_type") or "untyped") for item in result_rows
                )
            ),
            "verdicts": dict(
                Counter(
                    str(item.get("contract_verdict") or "ERROR") for item in result_rows
                )
            ),
            "authority": dict(
                Counter(
                    (
                        "not-assessed"
                        if item.get("severity") == "blocked"
                        else str(item.get("authority_classification") or "unknown")
                    )
                    for item in result_rows
                )
            ),
            "semantic_paths": len(
                {
                    str(item.get("semantic_path_key"))
                    for item in result_rows
                    if item.get("semantic_path_key")
                }
            ),
        },
        "summary": {
            "result_counts": dict(counts),
            "path_health_counts": dict(health_counts),
            "finding_count": attention_count,
            "executed_count": sum(
                counts.get(status, 0)
                for status in ("PASS", "FAIL", "ERROR", "UNVERIFIED")
            ),
            "narrative": narrative,
            # Keep the legacy field; failed or pending records are not proof of presence.
            "cleanup_present": cleanup_present,
            "cleanup_unresolved_resources": cleanup_present,
            "cleanup_verification_issues": sum(
                "verification-error" in str(issue)
                for issue in cleanup.get("leftovers") or []
            ),
            "cleanup_complete": cleanup.get("complete"),
            "final_status": run.get("final_status"),
        },
    }
    model.update(
        enrich_dashboard_model(
            payload,
            result_rows,
            paths,
            findings,
            host_qualification,
        )
    )
    model.pop("topology_workspace", None)
    model["contracts"].pop("authority", None)
    model["results"] = [_dashboard_result_view(result) for result in result_rows]
    return model


__all__ = [
    "build_dashboard_model",
    "friendly_endpoint",
    "friendly_host",
    "friendly_title",
]
