from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from typing import Any

from .mtu_contract import confirmed_no_fragment_path_mtu, local_mtu_constraint
from .network_contract import canonical_category
from .operation_compat import canonical_operation_fields
from .packet_size_components import component_contracts as _component_contracts
from .result_contract_compatibility import (
    canonicalize_supplied_contract as _canonicalize_supplied_contract,
)
from .result_contract_compatibility import (
    canonicalize_supplied_path_signature as _canonicalize_supplied_path_signature,
)
from .result_contract_compatibility import (
    openstack_objects as _openstack_objects,
)
from .result_contract_integrity import (
    PATH_SIGNATURE_RESERVED_FIELDS as _PATH_SIGNATURE_RESERVED_FIELDS,
)
from .result_contract_integrity import (
    validate_overlay_consistency as _validate_overlay_consistency,
)
from .result_contract_integrity import (
    validate_supplied_contract as _validate_supplied_contract,
)

CONTRACT_SCHEMA_VERSION = 1
PATH_SIGNATURE_SCHEMA_VERSION = 1

AUTHORITY_CLASSES = {"openstack", "protocol", "operator", "inferred", "fallback"}
TYPED_VERDICTS = {
    "PASS",
    "FAIL",
    "UNVERIFIED",
    "BLOCKED",
    "INAPPLICABLE",
    "NOT_RUN",
    "ERROR",
}

_STATUS_TO_VERDICT = {
    "PASS": "PASS",
    "FAIL": "FAIL",
    "UNVERIFIED": "UNVERIFIED",
    "ERROR": "ERROR",
    "BLOCKED_BY_SETUP_ERROR": "BLOCKED",
    "BLOCKED_BY_PREREQUISITE": "BLOCKED",
    "SKIP": "INAPPLICABLE",
    "NOT_APPLICABLE": "INAPPLICABLE",
    "NOT_RUN_CANCELLED": "NOT_RUN",
}

_VERDICT_TO_OUTCOME = {
    "PASS": "met",
    "FAIL": "violated",
    "UNVERIFIED": "unverified",
    "BLOCKED": "blocked",
    "INAPPLICABLE": "inapplicable",
    "NOT_RUN": "not-run",
    "ERROR": "not-evaluated",
}

_VERDICT_TO_EXECUTION = {
    "PASS": "completed",
    "FAIL": "completed",
    "UNVERIFIED": "completed-with-insufficient-evidence",
    "BLOCKED": "not-completed",
    "INAPPLICABLE": "not-applicable",
    "NOT_RUN": "not-started",
    "ERROR": "execution-error",
}

_PERFORMANCE_CONTRACTS: dict[str, dict[str, str]] = {
    "tcp-throughput": {
        "type": "throughput",
        "expectation": "tcp-throughput-profile-recorded",
        "expectation_description": (
            "Record usable TCP throughput in every eligible direction, including "
            "single-stream, multi-stream, retransmission, and bidirectional evidence."
        ),
        "pass_observation": "tcp-throughput-profile-measured",
        "unverified_observation": "tcp-throughput-evidence-incomplete",
        "fail_observation": "tcp-throughput-contract-violated",
        "error_observation": "tcp-throughput-measurement-error",
    },
    "latency": {
        "type": "latency",
        "expectation": "idle-and-loaded-latency-profile-recorded",
        "expectation_description": (
            "Record idle and loaded latency, packet loss, and the loaded-to-idle "
            "latency ratio in every eligible direction."
        ),
        "pass_observation": "idle-and-loaded-latency-measured",
        "unverified_observation": "latency-evidence-incomplete",
        "fail_observation": "latency-contract-violated",
        "error_observation": "latency-measurement-error",
    },
    "udp": {
        "type": "udp-quality",
        "expectation": "udp-quality-profile-recorded",
        "expectation_description": (
            "Record requested and generated UDP rate, application receive rate, "
            "application-delivery loss, jitter, duplicates, reordering, and receiver "
            "drop telemetry for every requested packet size and direction."
        ),
        "pass_observation": "udp-quality-profile-measured",
        "unverified_observation": "udp-quality-evidence-incomplete",
        "fail_observation": "udp-quality-contract-violated",
        "error_observation": "udp-quality-measurement-error",
    },
    "mtu-mss": {
        "type": "packet-size-path",
        "expectation": "packet-size-contract-assessed",
        "expectation_description": (
            "Assess the advertised path MTU, the confirmed no-fragment boundary, "
            "PMTUD behavior, fragmentation behavior, and TCP MSS in every eligible "
            "direction."
        ),
        "pass_observation": "packet-size-contract-assessed",
        "unverified_observation": "packet-size-evidence-incomplete",
        "fail_observation": "packet-size-contract-violated",
        "error_observation": "packet-size-measurement-error",
    },
    "asymmetry": {
        "type": "directional-balance",
        "expectation": "directional-balance-assessed",
        "expectation_description": (
            "Compare forward and reverse throughput, latency, and UDP "
            "application-delivery loss without assuming that directional differences "
            "identify an infrastructure cause."
        ),
        "pass_observation": "directional-balance-measured",
        "unverified_observation": "directional-balance-evidence-incomplete",
        "fail_observation": "directional-balance-policy-violated",
        "error_observation": "directional-balance-measurement-error",
    },
    "concurrency": {
        "type": "concurrency",
        "expectation": "concurrent-flow-scaling-assessed",
        "expectation_description": (
            "Measure concurrent-flow aggregate throughput, per-flow throughput, and "
            "fairness in every eligible direction."
        ),
        "pass_observation": "concurrent-flow-scaling-measured",
        "unverified_observation": "concurrent-flow-evidence-incomplete",
        "fail_observation": "concurrent-flow-contract-violated",
        "error_observation": "concurrent-flow-measurement-error",
    },
    "repeatability": {
        "type": "repeatability",
        "expectation": "throughput-repeatability-assessed",
        "expectation_description": (
            "Measure repeated single-stream TCP samples and report variation in every "
            "eligible direction."
        ),
        "pass_observation": "throughput-repeatability-measured",
        "unverified_observation": "repeatability-evidence-incomplete",
        "fail_observation": "repeatability-policy-violated",
        "error_observation": "repeatability-measurement-error",
    },
    "concurrent-path-load": {
        "type": "concurrency",
        "expectation": "concurrent-vm-pair-load-assessed",
        "expectation_description": (
            "Run the requested simultaneous VM-pair levels and record aggregate and "
            "per-pair throughput, fairness, loaded latency, and UDP quality."
        ),
        "pass_observation": "concurrent-vm-pair-load-measured",
        "unverified_observation": "concurrent-vm-pair-evidence-incomplete",
        "fail_observation": "concurrent-vm-pair-contract-violated",
        "error_observation": "concurrent-vm-pair-measurement-error",
    },
}

_EXPECTATION_DESCRIPTIONS = {
    "reachable": "The selected network path must be reachable.",
    "blocked": "The selected traffic must remain blocked by the requested policy.",
    "withdrawn": "The path must withdraw after the requested lifecycle operation.",
    "restored": "The path must return after the requested restoration operation.",
    "unreachable": "The selected path must not carry the tested traffic.",
    "address-assigned": "OpenStack must assign the requested address to the endpoint.",
    "concurrent-paths-usable": (
        "Every requested simultaneous VM pair must retain a usable project-network path."
    ),
}

_OBSERVATION_DESCRIPTIONS = {
    "reachable": "The path was reachable.",
    "blocked": "The traffic was blocked.",
    "withdrawn": "The path withdrew after the cloud operation.",
    "restored": "The path returned after restoration.",
    "not-run": "The validation did not start.",
    "dependency-unavailable": "Required supporting evidence was unavailable.",
    "execution-error": "The validation could not execute to a terminal observation.",
    "measurement-error": "The measurement could not execute to a terminal observation.",
    "functional-path-unusable": "At least one requested path returned no usable traffic.",
    "operator-threshold-exceeded": "An enforced operator threshold was exceeded.",
    "threshold-exceeded": "An enforced operator threshold was exceeded.",
    "measurement-unverified": "The measurement completed without enough evidence for an authoritative verdict.",
}

_UUID_RE = re.compile(
    r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b"
)
_IP_SUFFIX_RE = re.compile(r"\s*\((?:[0-9a-fA-F:.]+)\)\s*$")
_BRACKET_RE = re.compile(r"\s*\[[^\]]+\]")
_PLACEMENT_SCOPE_PREFIX_RE = re.compile(r"^PLACEMENT-(?:INTRA|INTER)-", re.I)


def typed_verdict_for_status(status: Any) -> str:
    return _STATUS_TO_VERDICT.get(str(status or "").strip().upper(), "ERROR")


def execution_state_for_status(status: Any) -> str:
    return _VERDICT_TO_EXECUTION[typed_verdict_for_status(status)]


def typed_verdict(item: Mapping[str, Any] | Any) -> str:
    if isinstance(item, Mapping):
        contract = item.get("contract")
        status = item.get("status")
    else:
        contract = getattr(item, "contract", None)
        status = getattr(item, "status", None)
    if isinstance(contract, Mapping):
        verdict = contract.get("verdict")
        if isinstance(verdict, Mapping):
            state = str(verdict.get("state") or "").strip().upper()
            if state in TYPED_VERDICTS:
                return state
    return typed_verdict_for_status(status)


def performance_expectation(measurement: Any) -> str:
    definition = _PERFORMANCE_CONTRACTS.get(_canonical_measurement(measurement))
    return (
        definition["expectation"]
        if definition is not None
        else "network-measurement-assessed"
    )


def performance_observation(
    measurement: Any,
    *,
    status: Any,
    health: Any = None,
    verdict_basis: Any = None,
) -> str:
    canonical = _canonical_measurement(measurement)
    definition = _PERFORMANCE_CONTRACTS.get(canonical)
    if definition is None:
        return "network-measurement-recorded"
    normalized_status = str(status or "").strip().upper()
    basis = str(verdict_basis or "").strip().lower()
    if normalized_status == "PASS":
        return definition["pass_observation"]
    if normalized_status == "UNVERIFIED":
        return definition["unverified_observation"]
    if normalized_status == "ERROR":
        return definition["error_observation"]
    if normalized_status == "FAIL":
        if "threshold" in basis or (
            str(health or "").lower() == "warning" and canonical != "mtu-mss"
        ):
            if canonical in {"asymmetry", "repeatability"}:
                return definition["fail_observation"]
            return f"{definition['type']}-operator-threshold-violated"
        return definition["fail_observation"]
    if normalized_status in {"BLOCKED_BY_SETUP_ERROR", "BLOCKED_BY_PREREQUISITE"}:
        return f"{definition['type']}-not-run-prerequisite"
    if normalized_status in {"SKIP", "NOT_APPLICABLE"}:
        return f"{definition['type']}-not-applicable"
    return f"{definition['type']}-not-run"


def expectation_description(code: Any, *, contract_type: Any = None) -> str:
    text = str(code or "").strip()
    canonical_type = str(contract_type or "").strip()
    for definition in _PERFORMANCE_CONTRACTS.values():
        if text == definition["expectation"]:
            return definition["expectation_description"]
    if text == "mtu-behavior-assessed":
        return "Measure packet-size behavior and record differences from the advertised MTU as advisory observations."
    if text == "measurement-complete":
        if canonical_type:
            return f"Complete the {canonical_type.replace('-', ' ')} assessment with usable evidence."
        return "Complete the requested network measurement with usable evidence."
    return _EXPECTATION_DESCRIPTIONS.get(
        text, _human_code(text) or "No explicit expectation was recorded."
    )


def observation_description(code: Any, *, message: Any = None) -> str:
    text = str(code or "").strip()
    if text == "measured":
        return str(
            message or "The requested network measurement produced usable evidence."
        )
    if text in _OBSERVATION_DESCRIPTIONS:
        return _OBSERVATION_DESCRIPTIONS[text]
    for definition in _PERFORMANCE_CONTRACTS.values():
        if text == definition["pass_observation"]:
            return str(message or _human_code(text))
        if text == definition["unverified_observation"]:
            return str(
                message or "The measurement evidence was incomplete or ambiguous."
            )
        if text == definition["fail_observation"] or text.endswith(
            "operator-threshold-violated"
        ):
            return str(message or "The measured result violated the enforced contract.")
        if text == definition["error_observation"]:
            return str(message or "The measurement could not complete.")
    return str(message or _human_code(text) or "No parsed observation was recorded.")


def build_result_contract(
    *,
    test_id: str,
    category: str,
    status: str,
    family: int | None,
    source: str | None,
    destination: str | None,
    expected: str | None,
    observed: str | None,
    authoritative: bool | None,
    message: str,
    details: Mapping[str, Any] | None,
    scenario: str | None = None,
    supplied: Mapping[str, Any] | None = None,
    _legacy_blocked_isolation: bool = False,
) -> dict[str, Any]:
    evidence = dict(details or {})
    measurement = _canonical_measurement(evidence.get("measurement"))
    contract_type = _contract_type(
        category=category,
        expected=expected,
        test_id=test_id,
        details=evidence,
        measurement=measurement,
        legacy_blocked_isolation=_legacy_blocked_isolation,
    )
    canonical_expected = _canonical_expectation(expected, measurement)
    canonical_observed = _canonical_observation(
        observed,
        measurement=measurement,
        status=status,
        details=evidence,
    )
    verdict_state = typed_verdict_for_status(status)
    outcome = _VERDICT_TO_OUTCOME[verdict_state]
    authority = _authority(
        authoritative=authoritative,
        details=evidence,
        measurement=measurement,
        status=status,
    )
    expectation_source = _expectation_source(authority, evidence, measurement)
    path_signature = build_path_signature(
        test_id=test_id,
        category=category,
        family=family,
        source=source,
        destination=destination,
        details=evidence,
        scenario=scenario,
        contract_type=contract_type,
    )
    contract: dict[str, Any] = {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "type": contract_type,
        "description": _contract_description(
            contract_type, category=category, scenario=scenario, measurement=measurement
        ),
        "source": _endpoint_contract(source, role="source"),
        "destination": _endpoint_contract(destination, role="destination"),
        "family": family,
        "expectation": {
            "code": canonical_expected,
            "description": expectation_description(
                canonical_expected, contract_type=contract_type
            ),
            "source": expectation_source,
            "openstack_objects": _openstack_objects(evidence),
            "permitted_uncertainty": _permitted_uncertainty(
                contract_type=contract_type,
                authoritative=authoritative,
                details=evidence,
            ),
        },
        "observation": {
            "code": canonical_observed,
            "description": observation_description(
                canonical_observed,
                message=message,
            ),
            "supporting_evidence": _supporting_evidence(evidence),
            "supporting_result_ids": _supporting_result_ids(evidence, test_id),
        },
        "verdict": {
            "state": verdict_state,
            "outcome": outcome,
            "basis": _verdict_basis(status, evidence, authoritative),
        },
        "authority": authority,
        "execution": {
            "state": _VERDICT_TO_EXECUTION[verdict_state],
            "complete": verdict_state in {"PASS", "FAIL", "UNVERIFIED"},
        },
        "path_health": _path_health(status, evidence),
        "mechanism": _mechanism(evidence),
        "attribution": _attribution(evidence, authoritative),
        "path_signature_key": path_signature["key"],
    }
    lifecycle = _lifecycle_contract(
        contract_type=contract_type,
        status=status,
        expected=canonical_expected,
        observed=canonical_observed,
        details=evidence,
    )
    if lifecycle:
        contract["lifecycle"] = lifecycle
    packet_size = packet_size_accounting(evidence, family=family)
    if packet_size:
        contract["packet_size"] = packet_size
    components = _component_contracts(
        contract_type=contract_type,
        status=status,
        details=evidence,
        family=family,
    )
    if components:
        contract["components"] = components
    if supplied is not None:
        legacy = None
        if (
            expected == "blocked"
            and supplied.get("type") == "security-group-isolation"
            and contract_type != "security-group-isolation"
        ):
            legacy = build_result_contract(
                test_id=test_id,
                category=category,
                status=status,
                family=family,
                source=source,
                destination=destination,
                expected=expected,
                observed=observed,
                authoritative=authoritative,
                message=message,
                details=details,
                scenario=scenario,
                _legacy_blocked_isolation=True,
            )
        supplied = _canonicalize_supplied_contract(
            supplied,
            generated=contract,
            details=evidence,
            family=family,
            contract_type=contract_type,
            status=status,
            legacy_generated=legacy,
        )
        _validate_supplied_contract(
            supplied,
            generated=contract,
            expected_verdict=verdict_state,
        )
        contract = _merge_supplied_contract(contract, supplied)
    if contract.get("path_signature_key") != path_signature["key"]:
        raise ValueError(
            "Result contract path signature key contradicts the canonical semantic "
            "path identity"
        )
    validate_result_contract(
        contract,
        status=status,
        expected=canonical_expected,
        observed=canonical_observed,
        authoritative=authoritative,
    )
    return contract


def build_path_signature(
    *,
    test_id: str,
    category: str,
    family: int | None,
    source: str | None,
    destination: str | None,
    details: Mapping[str, Any] | None,
    scenario: str | None,
    contract_type: str,
) -> dict[str, Any]:
    evidence = dict(details or {})
    path = evidence.get("path") if isinstance(evidence.get("path"), Mapping) else {}
    measurement = _canonical_measurement(evidence.get("measurement"))
    source_label = path.get("source_label") or source
    destination_label = path.get("destination_label") or destination
    source_zone = path.get("source_availability_zone") or evidence.get(
        "source_availability_zone"
    )
    destination_zone = path.get("destination_availability_zone") or evidence.get(
        "destination_availability_zone"
    )
    execution_scope = (
        path.get("execution_scope")
        or evidence.get("execution_scope")
        or evidence.get("availability_zone")
    )
    identity = {
        "contract_type": contract_type,
        "category": canonical_category(category),
        "measurement": measurement or None,
        "semantic_test": _semantic_test_id(test_id, evidence),
        "source": _semantic_endpoint(source_label),
        "destination": _semantic_endpoint(destination_label),
        "family": family or path.get("family"),
        "phase": evidence.get("phase") or path.get("stage") or evidence.get("stage"),
        "placement": _canonical_placement(
            path.get("placement")
            or evidence.get("compute_placement")
            or evidence.get("placement")
        ),
        "availability_scope": _canonical_availability_scope(
            path.get("availability_scope")
            or evidence.get("availability_zone_placement")
        ),
        "execution_scope": _semantic_text(execution_scope),
        "source_availability_zone": _semantic_text(source_zone),
        "destination_availability_zone": _semantic_text(destination_zone),
        "direction": _direction_identity(path, evidence),
        "operation": _semantic_text(
            path.get("operation")
            or evidence.get("operation")
            or evidence.get("probe_operation")
        ),
        "protocol": _semantic_text(
            path.get("protocol")
            or evidence.get("protocol")
            or evidence.get("probe_protocol")
        ),
        "destination_port": _optional_int(
            path.get("destination_port")
            or evidence.get("destination_port")
            or evidence.get("port")
        ),
        "lifecycle_key": _semantic_text(
            path.get("lifecycle_key") or evidence.get("lifecycle_key")
        ),
        "host_pair": _semantic_text(
            evidence.get("host_qualification_pair_id")
            or evidence.get("target_host_pair_id")
        ),
        "source_group": _semantic_group(
            path.get("source_group_id") or evidence.get("source_group_id"),
            source_label,
        ),
        "destination_group": _semantic_group(
            path.get("destination_group_id") or evidence.get("destination_group_id"),
            destination_label,
        ),
    }
    identity = {
        key: value for key, value in identity.items() if value not in (None, "", [], {})
    }
    encoded = json.dumps(
        identity, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    placement = {
        "class": identity.get("placement"),
        "availability_scope": identity.get("availability_scope"),
        "source_host": path.get("source_compute_host")
        or evidence.get("source_compute_host")
        or evidence.get("observed_source_host"),
        "destination_host": path.get("destination_compute_host")
        or evidence.get("destination_compute_host")
        or evidence.get("observed_destination_host"),
        "requested_source_host": evidence.get("requested_source_host"),
        "requested_destination_host": evidence.get("requested_destination_host"),
        "source_availability_zone": source_zone,
        "destination_availability_zone": destination_zone,
        "execution_scope": execution_scope,
    }
    context = {
        "source": _endpoint_contract(source_label, role="source"),
        "destination": _endpoint_contract(destination_label, role="destination"),
        "family": identity.get("family"),
        "network_objects": _network_context(evidence, path),
        "translation": _translation_context(evidence, path),
        "placement": {
            key: value
            for key, value in placement.items()
            if value not in (None, "", [], {})
        },
        "packet_size": _packet_size_context(evidence, family=family),
        "lifecycle": _lifecycle_context(evidence, path),
        "supporting_result_ids": _supporting_result_ids(evidence, test_id),
    }
    context = {
        key: value for key, value in context.items() if value not in (None, "", [], {})
    }
    display_parts = [
        str(source_label or "source"),
        "→",
        str(destination_label or "destination"),
    ]
    if identity.get("family"):
        display_parts.append(f"IPv{identity['family']}")
    if identity.get("placement"):
        display_parts.append(str(identity["placement"]))
    return {
        "schema_version": PATH_SIGNATURE_SCHEMA_VERSION,
        "key": f"sha256:{digest}",
        "identity": identity,
        "context": context,
        "display": " · ".join(display_parts),
    }


def packet_size_accounting(
    details: Mapping[str, Any] | None,
    *,
    family: int | None,
) -> dict[str, Any]:
    evidence = dict(details or {})
    measurement = _canonical_measurement(evidence.get("measurement"))
    metrics = (
        evidence.get("metrics") if isinstance(evidence.get("metrics"), Mapping) else {}
    )
    ip_header = 40 if family == 6 else 20
    output: dict[str, Any] = {
        "units": "bytes",
        "layer_boundary": (
            "IP packet sizes exclude Ethernet framing; UDP packet_size values are "
            "application datagram bytes before UDP and IP headers."
        ),
    }
    if measurement == "mtu-mss" or any(
        isinstance(metrics.get(direction), Mapping)
        and metrics.get(direction, {}).get("discovered_mtu") is not None
        for direction in ("forward", "reverse")
    ):
        output["advertised_path_mtu_bytes"] = metrics.get("expected_mtu")
        directions: dict[str, Any] = {}
        for direction in ("forward", "reverse"):
            item = metrics.get(direction)
            if not isinstance(item, Mapping):
                continue
            item_dict = dict(item)
            discovered = _positive_int(confirmed_no_fragment_path_mtu(item_dict))
            local_constraint, local_class = local_mtu_constraint(item_dict)
            icmp_header = _positive_int(item.get("header_bytes")) or ip_header + 8
            fragmentation = (
                item.get("fragmentation")
                if isinstance(item.get("fragmentation"), Mapping)
                else {}
            )
            tested = _positive_int(fragmentation.get("tested_packet_size"))
            frag_header = (
                _positive_int(fragmentation.get("header_bytes")) or icmp_header
            )
            expected_mss = _positive_int(item.get("expected_max_mss"))
            directions[direction] = {
                "confirmed_no_fragment_ip_packet_bytes": discovered,
                "local_constraint_ip_packet_bytes": _positive_int(local_constraint),
                "local_constraint_class": local_class,
                "icmp_combined_header_bytes": icmp_header,
                "confirmed_no_fragment_icmp_payload_bytes": (
                    max(0, discovered - icmp_header) if discovered is not None else None
                ),
                "df_accounting": (
                    "IP packet bytes = ICMP payload bytes + IPv4/IPv6 header + "
                    "8-byte ICMP header"
                ),
                "fragmentation_test": {
                    "ip_packet_bytes": tested,
                    "combined_header_bytes": frag_header,
                    "icmp_payload_bytes": (
                        max(0, tested - frag_header) if tested is not None else None
                    ),
                    "capability": fragmentation.get("capability"),
                    "location": fragmentation.get("fragmentation_location"),
                    "reassembly_observed": _reassembly_observed(fragmentation),
                },
                "tcp_mss": {
                    "expected_max_tcp_payload_bytes": expected_mss,
                    "observed_client_tcp_payload_bytes": _positive_int(
                        item.get("client_mss")
                    ),
                    "observed_server_tcp_payload_bytes": _positive_int(
                        item.get("server_mss")
                    ),
                    "combined_tcp_ip_header_bytes": 60 if family == 6 else 40,
                    "accounting": (
                        "IP packet bytes = TCP payload (MSS) + minimum TCP and "
                        "IPv4/IPv6 headers"
                    ),
                },
                "pmtud_state": item.get("pmtud_status"),
            }
        output["directions"] = directions
        output["formula"] = metrics.get("mtu_contract_formula")
        output["contract_authoritative"] = metrics.get("contract_authoritative")
        return output
    if measurement == "udp":
        directions: dict[str, list[dict[str, Any]]] = {}
        for direction in ("forward", "reverse"):
            rows = metrics.get(direction)
            if not isinstance(rows, list):
                continue
            normalized: list[dict[str, Any]] = []
            for row in rows:
                if not isinstance(row, Mapping):
                    continue
                payload_bytes = _positive_int(row.get("packet_size"))
                achieved_mbps = row.get("achieved_mbps")
                if achieved_mbps is None:
                    achieved_mbps = row.get("mbps")
                normalized.append(
                    {
                        "udp_application_datagram_bytes": payload_bytes,
                        "udp_header_bytes": 8,
                        "ip_header_bytes": ip_header,
                        "ip_packet_bytes": (
                            payload_bytes + 8 + ip_header
                            if payload_bytes is not None
                            else None
                        ),
                        "offered_mbps": row.get("offered_mbps"),
                        "achieved_mbps": achieved_mbps,
                    }
                )
            directions[direction] = normalized
        output["directions"] = directions
        output["formula"] = (
            "IP packet bytes = UDP application datagram bytes + 8-byte UDP header + "
            "IPv4/IPv6 header"
        )
        return output
    direct_packet = _positive_int(evidence.get("packet_size"))
    if direct_packet is not None:
        header = _positive_int(evidence.get("header_bytes")) or ip_header + 8
        output.update(
            {
                "ip_packet_bytes": direct_packet,
                "combined_header_bytes": header,
                "payload_bytes": max(0, direct_packet - header),
                "formula": "IP packet bytes = payload bytes + recorded combined headers",
            }
        )
        return output
    return {}


def validate_result_contract(
    contract: Mapping[str, Any],
    *,
    status: Any,
    expected: Any = None,
    observed: Any = None,
    authoritative: bool | None = None,
) -> None:
    if not isinstance(contract, Mapping):
        raise ValueError("Result contract must be an object")
    if contract.get("schema_version") != CONTRACT_SCHEMA_VERSION:
        raise ValueError(
            f"Unsupported result contract schema {contract.get('schema_version')!r}"
        )
    contract_type = str(contract.get("type") or "").strip()
    if not contract_type:
        raise ValueError("Result contract.type must be a non-empty string")
    expectation = contract.get("expectation")
    observation = contract.get("observation")
    verdict = contract.get("verdict")
    authority = contract.get("authority")
    execution = contract.get("execution")
    source = contract.get("source")
    destination = contract.get("destination")
    for name, value in (
        ("expectation", expectation),
        ("observation", observation),
        ("verdict", verdict),
        ("authority", authority),
        ("execution", execution),
        ("source", source),
        ("destination", destination),
    ):
        if not isinstance(value, Mapping):
            raise ValueError(f"Result contract.{name} must be an object")
    family = contract.get("family")
    if family is not None and (
        isinstance(family, bool) or not isinstance(family, int) or family not in {4, 6}
    ):
        raise ValueError("Result contract.family must be IPv4, IPv6, or null")
    path_signature_key = str(contract.get("path_signature_key") or "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", path_signature_key):
        raise ValueError(
            "Result contract.path_signature_key must be a SHA-256 identity"
        )
    for role, endpoint in (("source", source), ("destination", destination)):
        if endpoint.get("role") != role:
            raise ValueError(f"Result contract.{role}.role must be {role!r}")
        for field in ("display", "semantic"):
            value = endpoint.get(field)
            if value is not None and not isinstance(value, str):
                raise ValueError(
                    f"Result contract.{role}.{field} must be a string or null"
                )
    state = str(verdict.get("state") or "").strip().upper()
    expected_state = typed_verdict_for_status(status)
    if state != expected_state:
        raise ValueError(
            "Result status contradicts typed contract verdict: "
            f"status={status!r}, verdict={state!r}, expected={expected_state!r}"
        )
    outcome = str(verdict.get("outcome") or "").strip().lower()
    expected_outcome = _VERDICT_TO_OUTCOME[state]
    if outcome != expected_outcome:
        raise ValueError(
            "Typed contract verdict outcome contradicts its state: "
            f"state={state!r}, outcome={outcome!r}, expected={expected_outcome!r}"
        )
    execution_state = str(execution.get("state") or "").strip().lower()
    expected_execution_state = _VERDICT_TO_EXECUTION[state]
    if execution_state != expected_execution_state:
        raise ValueError(
            "Typed contract execution state contradicts its verdict: "
            f"state={state!r}, execution={execution_state!r}, "
            f"expected={expected_execution_state!r}"
        )
    execution_complete = execution.get("complete")
    if not isinstance(execution_complete, bool):
        raise ValueError("Result contract.execution.complete must be boolean")
    expected_execution_complete = state in {"PASS", "FAIL", "UNVERIFIED"}
    if execution_complete != expected_execution_complete:
        raise ValueError(
            "Typed contract execution completion contradicts its verdict: "
            f"state={state!r}, complete={execution_complete!r}, "
            f"expected={expected_execution_complete!r}"
        )
    classification = str(authority.get("classification") or "").strip().lower()
    if classification not in AUTHORITY_CLASSES:
        raise ValueError(
            "Result contract.authority.classification must be one of "
            + ", ".join(sorted(AUTHORITY_CLASSES))
        )
    authority_flag = authority.get("authoritative")
    if not isinstance(authority_flag, bool):
        raise ValueError("Result contract.authority.authoritative must be boolean")
    if authoritative is not None and authority_flag != bool(authoritative):
        raise ValueError(
            "Result authoritative flag contradicts the typed contract authority"
        )
    expectation_source = expectation.get("source")
    if not isinstance(expectation_source, Mapping):
        raise ValueError("Result contract.expectation.source must be an object")
    expectation_classification = (
        str(expectation_source.get("classification") or "").strip().lower()
    )
    if expectation_classification not in AUTHORITY_CLASSES:
        raise ValueError(
            "Result contract.expectation.source.classification must be one of "
            + ", ".join(sorted(AUTHORITY_CLASSES))
        )
    if expectation_classification != classification:
        raise ValueError(
            "Typed contract expectation source contradicts its authority classification"
        )
    if expected is not None and expectation.get("code") != expected:
        raise ValueError(
            "Result expected value contradicts typed contract expectation: "
            f"expected={expected!r}, contract={expectation.get('code')!r}"
        )
    if observed is not None and observation.get("code") != observed:
        raise ValueError(
            "Result observed value contradicts typed contract observation: "
            f"observed={observed!r}, contract={observation.get('code')!r}"
        )


def validate_path_signature(signature: Mapping[str, Any]) -> None:
    if not isinstance(signature, Mapping):
        raise ValueError("Result path_signature must be an object")
    if signature.get("schema_version") != PATH_SIGNATURE_SCHEMA_VERSION:
        raise ValueError(
            f"Unsupported path signature schema {signature.get('schema_version')!r}"
        )
    key = str(signature.get("key") or "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", key):
        raise ValueError("Result path_signature.key must be a SHA-256 identity")
    identity = signature.get("identity")
    if not isinstance(identity, Mapping) or not identity:
        raise ValueError("Result path_signature.identity must be a non-empty object")
    context = signature.get("context")
    if context is not None and not isinstance(context, Mapping):
        raise ValueError("Result path_signature.context must be an object")
    display = signature.get("display")
    if display is not None and not isinstance(display, str):
        raise ValueError("Result path_signature.display must be a string or null")
    encoded = json.dumps(
        identity, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    expected = "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    if key != expected:
        raise ValueError("Result path_signature.key does not match its identity")


def normalize_result_record(
    item: Mapping[str, Any], *, share_evidence: bool = False
) -> dict[str, Any]:
    """Normalize a record, optionally borrowing evidence for read-only views.

    Mutable consumers retain isolated evidence by default. Report renderers can
    borrow unchanged trees during synchronous projection; root fields and typed
    contracts remain independent and legacy field translations still copy the
    affected branches.
    """
    normalized = dict(
        canonical_operation_fields(dict(item), share_unchanged=True)
        if share_evidence
        else canonical_operation_fields(copy.deepcopy(dict(item)))
    )
    details = normalized.get("details")
    if not isinstance(details, dict):
        details = {}
        normalized["details"] = details
    measurement = _canonical_measurement(details.get("measurement"))
    expected = normalized.get("expected")
    observed = normalized.get("observed")
    canonical_expected = _canonical_expectation(expected, measurement)
    canonical_observed = _canonical_observation(
        observed,
        measurement=measurement,
        status=str(normalized.get("status") or "ERROR"),
        details=details,
    )
    supplied_contract = normalized.get("contract")
    if supplied_contract not in (None, {}) and not isinstance(
        supplied_contract, Mapping
    ):
        raise ValueError("Result contract must be an object")
    raw_authoritative = normalized.get("authoritative")
    if raw_authoritative is not None and not isinstance(raw_authoritative, bool):
        raise ValueError("Result authoritative must be boolean or null")
    raw_family = normalized.get("family")
    family = _optional_int(raw_family)
    if raw_family is not None and (
        isinstance(raw_family, bool) or family not in {4, 6}
    ):
        raise ValueError("Result family must be IPv4, IPv6, or null")
    contract = build_result_contract(
        test_id=str(normalized.get("test_id") or "unknown-result"),
        category=str(normalized.get("category") or "uncategorized"),
        status=str(normalized.get("status") or "ERROR"),
        family=family,
        source=_optional_string(normalized.get("source")),
        destination=_optional_string(normalized.get("destination")),
        expected=_optional_string(canonical_expected),
        observed=_optional_string(canonical_observed),
        authoritative=raw_authoritative,
        message=str(normalized.get("message") or ""),
        details=details,
        scenario=_optional_string(normalized.get("scenario")),
        supplied=(
            supplied_contract
            if isinstance(supplied_contract, Mapping) and supplied_contract
            else None
        ),
    )
    signature = normalized.get("path_signature")
    if signature not in (None, {}) and not isinstance(signature, Mapping):
        raise ValueError("Result path_signature must be an object")
    generated_signature = build_path_signature(
        test_id=str(normalized.get("test_id") or "unknown-result"),
        category=str(normalized.get("category") or "uncategorized"),
        family=family,
        source=_optional_string(normalized.get("source")),
        destination=_optional_string(normalized.get("destination")),
        details=details,
        scenario=_optional_string(normalized.get("scenario")),
        contract_type=str(contract.get("type")),
    )
    if isinstance(signature, Mapping) and signature:
        signature = _canonicalize_supplied_path_signature(
            signature,
            generated=generated_signature,
            details=details,
            family=family,
            legacy_blocked_isolation=bool(
                canonical_expected == "blocked"
                and isinstance(supplied_contract, Mapping)
                and supplied_contract.get("type") == "security-group-isolation"
            ),
        )
        validate_path_signature(signature)
        if signature.get("key") != generated_signature.get("key"):
            raise ValueError(
                "Result path_signature contradicts the canonical semantic path identity"
            )
        _validate_overlay_consistency(
            signature,
            generated_signature,
            label="Supplied result path_signature",
            reserved_root_fields=_PATH_SIGNATURE_RESERVED_FIELDS,
        )
        generated_signature = _merge_mapping(generated_signature, signature)
    if "family" in normalized:
        normalized["family"] = family
    if "authoritative" in normalized:
        normalized["authoritative"] = raw_authoritative
    normalized["expected"] = canonical_expected
    normalized["observed"] = canonical_observed
    normalized["contract"] = contract
    normalized["path_signature"] = generated_signature
    return normalized


def semantic_result_key(item: Mapping[str, Any]) -> tuple[Any, ...]:
    """Return the stable comparison identity for one logical validation.

    The typed contract is intentionally excluded. A changed expectation or
    contract type must still match the same validation path so comparison can
    classify it as ``contract changed`` rather than as unrelated removal and
    addition. Human-facing descriptions are also excluded; they are compared
    separately as mention drift.
    """

    normalized = normalize_result_record(item)
    signature = normalized["path_signature"]
    identity = dict(signature.get("identity") or {})
    identity.pop("contract_type", None)
    encoded = json.dumps(
        identity,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return ("semantic-result", encoded)


def contract_shape(item: Mapping[str, Any]) -> dict[str, Any]:
    normalized = normalize_result_record(item)
    contract = normalized["contract"]
    expectation = contract.get("expectation") or {}
    return {
        "type": contract.get("type"),
        "expected": expectation.get("code"),
        "expectation_source": (expectation.get("source") or {}).get("classification"),
        "permitted_uncertainty": expectation.get("permitted_uncertainty"),
        "family": contract.get("family"),
    }


def observation_shape(item: Mapping[str, Any]) -> dict[str, Any]:
    normalized = normalize_result_record(item)
    contract = normalized["contract"]
    observation = contract.get("observation") or {}
    details = normalized.get("details") or {}
    return {
        "code": observation.get("code"),
        "health": details.get("health"),
        "metrics": details.get("metrics"),
        "lifecycle": contract.get("lifecycle"),
        "packet_size": contract.get("packet_size"),
    }


def _contract_type(
    *,
    category: str,
    expected: Any,
    test_id: str,
    details: Mapping[str, Any],
    measurement: str,
    legacy_blocked_isolation: bool = False,
) -> str:
    if bool(details.get("tool_failure")):
        return "tool-execution"
    if measurement in _PERFORMANCE_CONTRACTS:
        return _PERFORMANCE_CONTRACTS[measurement]["type"]
    text = " ".join(
        str(value or "").lower()
        for value in (
            category,
            expected,
            test_id,
            details.get("operation"),
            details.get("scenario"),
        )
    )
    if "address" in text and ("assign" in text or "allocation" in text):
        return "address-assignment"
    if "security" in text or (
        legacy_blocked_isolation and str(expected or "").lower() == "blocked"
    ):
        return "security-group-isolation"
    if "static-route" in text or "extra-route" in text:
        return "static-routing"
    if "floating" in text or "dnat" in text:
        return "floating-ip-translation"
    if "snat" in text or "source-nat" in text or "source translation" in text:
        return "source-translation"
    if "packet-size" in text or "mtu" in text or "pmtud" in text or "mss" in text:
        return "packet-size-path"
    if "migration" in text:
        return "migration-continuity"
    if "lifecycle" in text or str(expected or "").lower() in {"withdrawn", "restored"}:
        return "lifecycle-continuity"
    if "placement" in text or "host-qualification" in text:
        return "placement-resilience"
    if "cleanup" in text:
        return "cleanup"
    if str(expected or "").lower() in {"reachable", "unreachable", "blocked"}:
        return "connectivity"
    return "network-observation"


def _contract_description(
    contract_type: str,
    *,
    category: str,
    scenario: str | None,
    measurement: str,
) -> str:
    descriptions = {
        "address-assignment": "OpenStack address assignment and endpoint usability.",
        "connectivity": "Project-visible network reachability between the selected endpoints.",
        "security-group-isolation": "Project-visible traffic isolation enforced by security-group policy.",
        "static-routing": "Project-visible reachability through Neutron router static routes.",
        "source-translation": "Project egress through Neutron source address translation.",
        "floating-ip-translation": "Floating-IP destination and source translation behavior.",
        "packet-size-path": "Path MTU, PMTUD, fragmentation, reassembly, and TCP MSS behavior.",
        "lifecycle-continuity": "Network behavior before, during, and after a controlled lifecycle cloud operation.",
        "placement-resilience": "Network behavior for the requested intra-compute or inter-compute placement.",
        "migration-continuity": "Project-network behavior and recovery across an AZ-safe server migration.",
        "throughput": "TCP throughput observed from project endpoints.",
        "latency": "Idle and loaded round-trip latency observed from project endpoints.",
        "udp-quality": "UDP delivery quality observed from project endpoints.",
        "directional-balance": "Forward and reverse path behavior compared without component attribution.",
        "concurrency": "Project-network behavior under simultaneous flows or VM-pair load.",
        "repeatability": "Variation across repeated project-network measurements.",
        "cleanup": "Cleanup completion and absence verification for Flux-managed resources.",
        "network-observation": "A project-visible OpenStack network behavior observation.",
    }
    description = descriptions.get(contract_type, descriptions["network-observation"])
    qualifier = scenario or category or measurement
    return (
        f"{description} Validation context: {qualifier}." if qualifier else description
    )


def _authority(
    *,
    authoritative: bool | None,
    details: Mapping[str, Any],
    measurement: str,
    status: str,
) -> dict[str, Any]:
    explicit = (
        str(
            details.get("authority_classification")
            or details.get("expectation_authority")
            or ""
        )
        .strip()
        .lower()
    )
    fallback = bool(
        details.get("fallback_used")
        or details.get("mtu_contract_fallback_used")
        or (
            (details.get("metrics") or {}).get("mtu_contract_fallback_used")
            if isinstance(details.get("metrics"), Mapping)
            else False
        )
    )
    reason_authority = str(details.get("reason_authority") or "").lower()
    verdict_basis = str(details.get("verdict_basis") or "").lower()
    if explicit in AUTHORITY_CLASSES:
        classification = explicit
    elif fallback:
        classification = "fallback"
    elif "threshold" in verdict_basis:
        classification = "operator"
    elif measurement:
        if measurement == "mtu-mss" and _mtu_contract_authoritative(details):
            classification = "openstack"
        else:
            classification = "protocol"
    elif any(
        token in reason_authority
        for token in ("openstack", "neutron", "nova", "cinder", "octavia")
    ):
        classification = "openstack"
    elif any(
        token in reason_authority
        for token in ("protocol", "icmp", "tcp", "udp", "probe")
    ):
        classification = "protocol"
    elif authoritative is True:
        classification = "operator"
    elif authoritative is False:
        classification = "inferred"
    else:
        classification = "fallback"
    sources = _authority_sources(details, classification)
    return {
        "classification": classification,
        "authoritative": bool(authoritative),
        "sources": sources,
        "limitation": (
            None
            if authoritative is True
            else "The evidence is supporting, inferred, or fallback evidence and does not establish an authoritative contract verdict."
        ),
    }


def _expectation_source(
    authority: Mapping[str, Any],
    details: Mapping[str, Any],
    measurement: str,
) -> dict[str, Any]:
    classification = str(authority.get("classification") or "fallback")
    descriptions = {
        "openstack": "Live OpenStack resource metadata and the approved Flux plan.",
        "protocol": "Protocol behavior observed by disposable OpenStack virtual machines.",
        "operator": "Operator-selected Flux policy, topology selection, or enforced threshold.",
        "inferred": "A supporting expectation inferred from related project-visible evidence.",
        "fallback": "A compatibility fallback used because authoritative metadata was unavailable.",
    }
    if measurement and classification == "protocol":
        description = (
            "The approved performance plan and protocol measurements from disposable "
            "OpenStack virtual machines."
        )
    else:
        description = descriptions[classification]
    declared = details.get("expectation_source") or details.get("reason_authority")
    if declared:
        description = f"{description} Recorded source: {declared}."
    return {
        "classification": classification,
        "description": description,
    }


def _authority_sources(
    details: Mapping[str, Any], classification: str
) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    for key in (
        "reason_authority",
        "expectation_source",
        "authority",
        "mtu_contract_authority_summary",
    ):
        value = details.get(key)
        if value:
            values.append({"kind": classification, "description": str(value)})
    metrics = details.get("metrics")
    if isinstance(metrics, Mapping) and metrics.get("contract_authority_summary"):
        values.append(
            {
                "kind": "openstack",
                "description": str(metrics.get("contract_authority_summary")),
            }
        )
    if not values:
        values.append(
            {
                "kind": classification,
                "description": _expectation_source(
                    {"classification": classification}, {}, ""
                )["description"],
            }
        )
    return values


def _permitted_uncertainty(
    *,
    contract_type: str,
    authoritative: bool | None,
    details: Mapping[str, Any],
) -> str:
    if details.get("performance") and not details.get("thresholds_enforced"):
        return (
            "Measurement variation and advisory threshold deviations may remain PASS; "
            "missing or ambiguous evidence must be UNVERIFIED, not PASS."
        )
    if authoritative is not True:
        return (
            "Supporting evidence may describe the observation, but it cannot establish "
            "PASS or FAIL for an authoritative network contract."
        )
    if contract_type in {"lifecycle-continuity", "migration-continuity"}:
        return (
            "Bounded convergence is permitted only when the recorded settlement window "
            "reaches a stable terminal state; ambiguous recovery remains UNVERIFIED."
        )
    return (
        "No hidden success state is permitted: incomplete, contradictory, or ambiguous "
        "evidence must be UNVERIFIED, BLOCKED, NOT_RUN, or ERROR."
    )


def _verdict_basis(
    status: str,
    details: Mapping[str, Any],
    authoritative: bool | None,
) -> str:
    explicit = details.get("verdict_basis") or details.get("contract_verdict")
    if explicit:
        return str(explicit)
    verdict = typed_verdict_for_status(status)
    if verdict == "ERROR":
        return "execution-error"
    if verdict == "BLOCKED":
        return "prerequisite-or-setup-block"
    if verdict == "NOT_RUN":
        return "run-ended-before-execution"
    if verdict == "INAPPLICABLE":
        return "topology-or-capability-not-applicable"
    if verdict == "UNVERIFIED":
        return "insufficient-or-ambiguous-evidence"
    if authoritative is not True:
        return "supporting-observation"
    return "authoritative-contract-evidence"


def _path_health(status: str, details: Mapping[str, Any]) -> dict[str, Any]:
    supplied = details.get("path_health")
    if isinstance(supplied, Mapping):
        return dict(supplied)
    health = str(details.get("health") or "").lower()
    verdict = typed_verdict_for_status(status)
    if verdict == "PASS":
        state = (
            "advisory-warning" if health in {"warning", "critical"} else "contract-met"
        )
    elif verdict == "FAIL":
        state = "contract-violated"
    elif verdict == "ERROR":
        state = "not-assessed-execution-error"
    elif verdict == "INAPPLICABLE":
        state = "not-applicable"
    else:
        state = "not-authoritatively-assessed"
    return {"state": state, "measurement_health": health or None}


def _mechanism(details: Mapping[str, Any]) -> dict[str, Any]:
    supplied = details.get("mechanism_assessment")
    if isinstance(supplied, Mapping):
        return dict(supplied)
    mtu = details.get("mtu_contract")
    if isinstance(mtu, Mapping):
        return {
            "name": "packet-size-path-protection",
            "state": mtu.get("mechanism_status")
            or mtu.get("pmtud_status")
            or "not-separately-assessed",
        }
    return {"state": "not-separately-assessed"}


def _attribution(
    details: Mapping[str, Any], authoritative: bool | None
) -> dict[str, Any]:
    supplied = details.get("attribution")
    if isinstance(supplied, Mapping):
        result = dict(supplied)
    else:
        result = {
            "scope": details.get("placement_scope") or "project-visible-path",
            "confidence": "authoritative-observation"
            if authoritative is True
            else "limited",
        }
    result.setdefault("causal_claim", False)
    result.setdefault(
        "limitation",
        "Project-visible evidence does not by itself identify a hidden physical or virtual network component.",
    )
    return result


def _lifecycle_contract(
    *,
    contract_type: str,
    status: str,
    expected: Any,
    observed: Any,
    details: Mapping[str, Any],
) -> dict[str, Any]:
    if contract_type not in {
        "lifecycle-continuity",
        "migration-continuity",
    } and not any(
        key in details
        for key in (
            "pre_state",
            "post_state",
            "restoration",
            "convergence",
            "migration_attempts",
            "post_migration_persistence",
        )
    ):
        return {}
    convergence = _convergence_evidence(details)
    return {
        "transition": details.get("operation")
        or details.get("lifecycle_key")
        or expected,
        "before": details.get("pre_state")
        or details.get("baseline")
        or details.get("baseline_outcome"),
        "requested_change": details.get("cloud_operation")
        or details.get("requested_change")
        or details.get("cloud_operation_outcome"),
        "after": details.get("post_state") or observed,
        "restoration": details.get("restoration") or details.get("restoration_state"),
        "convergence": convergence,
        "terminal_state": execution_state_for_status(status),
    }


def _network_context(
    details: Mapping[str, Any], path: Mapping[str, Any]
) -> dict[str, Any]:
    combined = {**dict(details), **dict(path)}
    return {
        "networks": _collect_values(
            combined,
            (
                "network_id",
                "network_ids",
                "network_name",
                "network_names",
                "external_network_id",
                "external_network_name",
            ),
        ),
        "subnets": _collect_values(
            combined,
            (
                "subnet_id",
                "subnet_ids",
                "source_subnet_id",
                "destination_subnet_id",
                "external_subnet_id",
                "floating_subnet_id",
                "cidr",
                "source_cidr",
                "destination_cidr",
            ),
        ),
        "routers": _collect_values(
            combined,
            ("router_id", "router_ids", "source_router_id", "destination_router_id"),
        ),
        "static_routes": _collect_values(
            combined,
            ("routes", "static_routes", "extra_routes", "destination_cidr", "nexthop"),
        ),
    }


def _translation_context(
    details: Mapping[str, Any], path: Mapping[str, Any]
) -> dict[str, Any]:
    combined = {**dict(details), **dict(path)}
    values = {
        "source_nat_enabled": combined.get("source_nat_enabled"),
        "translation_mode": combined.get("translation_mode")
        or combined.get("egress_translation_mode"),
        "floating_ip": combined.get("floating_ip")
        or combined.get("floating_ip_address"),
        "floating_ip_id": combined.get("floating_ip_id"),
        "translated_source_ip": combined.get("translated_source_ip"),
        "expected_translation_ips": combined.get("expected_translation_ips"),
        "translation_matches": combined.get("translation_matches"),
    }
    return {
        key: value for key, value in values.items() if value not in (None, "", [], {})
    }


def _packet_size_context(
    details: Mapping[str, Any], *, family: int | None
) -> dict[str, Any]:
    accounting = packet_size_accounting(details, family=family)
    if not accounting:
        return {}
    metrics = (
        details.get("metrics") if isinstance(details.get("metrics"), Mapping) else {}
    )
    return {
        "advertised_mtu": metrics.get("expected_mtu"),
        "guest_interface_mtu": {
            "source": metrics.get("source_mtu"),
            "destination": metrics.get("destination_mtu"),
        },
        "accounting": accounting,
    }


def _lifecycle_context(
    details: Mapping[str, Any], path: Mapping[str, Any]
) -> dict[str, Any]:
    convergence = _convergence_evidence(details)
    values = {
        "lifecycle_key": path.get("lifecycle_key") or details.get("lifecycle_key"),
        "stage": path.get("stage") or details.get("stage") or details.get("phase"),
        "pre_migration": details.get("pre_migration") or details.get("pre_state"),
        "post_migration": details.get("post_migration") or details.get("post_state"),
        "migration_attempts": details.get("migration_attempts"),
        "convergence": convergence,
    }
    return {
        key: value for key, value in values.items() if value not in (None, "", [], {})
    }


def _convergence_evidence(details: Mapping[str, Any]) -> dict[str, Any]:
    supplied = details.get("convergence")
    if isinstance(supplied, Mapping):
        return dict(supplied)
    metrics = details.get("metrics")
    samples: list[Any] = []
    classifications: list[str] = []
    elapsed: list[float] = []
    if isinstance(metrics, Mapping):
        for direction in ("forward", "reverse"):
            item = metrics.get(direction)
            if not isinstance(item, Mapping):
                continue
            persistence = item.get("post_migration_persistence")
            if not isinstance(persistence, Mapping):
                continue
            classifications.append(str(persistence.get("classification") or ""))
            if persistence.get("elapsed_seconds") is not None:
                try:
                    elapsed.append(float(persistence["elapsed_seconds"]))
                except (TypeError, ValueError):
                    pass
            if isinstance(persistence.get("samples"), list):
                samples.extend(persistence["samples"])
    if not classifications and not samples and not elapsed:
        return {}
    return {
        "classifications": [item for item in classifications if item],
        "elapsed_seconds": max(elapsed) if elapsed else None,
        "samples": samples,
        "settled": all(item != "unstable" for item in classifications)
        if classifications
        else None,
    }


def _supporting_evidence(details: Mapping[str, Any]) -> list[dict[str, Any]]:
    fields = (
        "probe",
        "metrics",
        "diagnostics",
        "mtu_contract",
        "migration_attempts",
        "continuity",
        "path_health",
        "mechanism_assessment",
        "attribution",
        "cloud_operation_outcome",
        "execution",
    )
    output: list[dict[str, Any]] = []
    for field in fields:
        value = details.get(field)
        if value not in (None, "", [], {}):
            output.append(
                {
                    "path": f"details.{field}",
                    "kind": "structured-evidence",
                }
            )
    return output


def _supporting_result_ids(details: Mapping[str, Any], test_id: str) -> list[str]:
    values: list[str] = []
    for key in (
        "supporting_result_ids",
        "result_ids",
        "dependencies",
        "source_spec_id",
        "base_test_id",
        "functional_result_ids",
    ):
        raw = details.get(key)
        if isinstance(raw, str):
            values.append(raw)
        elif isinstance(raw, Iterable) and not isinstance(raw, (str, bytes, Mapping)):
            values.extend(str(item) for item in raw if item)
    return sorted({value for value in values if value and value != test_id})


def _endpoint_contract(value: Any, *, role: str) -> dict[str, Any]:
    raw = str(value or "").strip()
    return {
        "role": role,
        "display": raw or None,
        "semantic": _semantic_endpoint(raw),
    }


def _canonical_expectation(expected: Any, measurement: str) -> str | None:
    text = _optional_string(expected)
    if measurement and (text in {None, "measurement-complete"}):
        return performance_expectation(measurement)
    if measurement == "concurrent-path-load" and text == "concurrent-paths-usable":
        return performance_expectation(measurement)
    return text


def _canonical_observation(
    observed: Any,
    *,
    measurement: str,
    status: str,
    details: Mapping[str, Any],
) -> str | None:
    text = _optional_string(observed)
    if measurement and text in {
        None,
        "measured",
        "measurement-complete",
        "measurement-unverified",
        "threshold-exceeded",
        "operator-threshold-exceeded",
        "functional-path-unusable",
        "measurement-error",
        "execution-error",
        "dependency-unavailable",
    }:
        return performance_observation(
            measurement,
            status=status,
            health=details.get("health"),
            verdict_basis=details.get("verdict_basis"),
        )
    return text


def _canonical_measurement(value: Any) -> str:
    text = str(value or "").strip().lower()
    return "concurrent-path-load" if text == "fabric-scale" else text


def _canonical_placement(value: Any) -> str | None:
    text = str(value or "").strip().lower().replace("_", "-")
    if not text:
        return None
    if any(
        token in text
        for token in (
            "same-compute",
            "same compute",
            "intra-compute",
            "same-host",
            "same host",
        )
    ):
        return "intra-compute"
    if any(
        token in text
        for token in (
            "cross-compute",
            "different compute",
            "inter-compute",
            "different-host",
            "different host",
        )
    ):
        return "inter-compute"
    if "unavailable" in text or "unknown" in text:
        return "placement-unavailable"
    return _semantic_text(text)


def _canonical_availability_scope(value: Any) -> str | None:
    text = str(value or "").strip().lower().replace("_", "-")
    if not text:
        return None
    if any(token in text for token in ("same-az", "same availability", "per-zone")):
        return "intra-availability-zone"
    if any(
        token in text
        for token in ("cross-az", "cross availability", "different availability")
    ):
        return "inter-availability-zone"
    if "unavailable" in text or "unknown" in text:
        return "availability-zone-unavailable"
    return _semantic_text(text)


def _direction_identity(
    path: Mapping[str, Any], details: Mapping[str, Any]
) -> str | None:
    directions = path.get("directions") or details.get("directions")
    if isinstance(directions, list):
        normalized = sorted(str(item).lower() for item in directions if item)
        return "+".join(normalized) if normalized else None
    value = details.get("direction")
    return _semantic_text(value)


def _semantic_endpoint(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    if "/" in text:
        prefix, remainder = text.split("/", 1)
        if prefix and not re.search(r"\s", prefix):
            text = remainder
    text = _IP_SUFFIX_RE.sub("", text)
    text = _BRACKET_RE.sub("", text)
    text = re.sub(r":([AB])$", r" side-\1", text, flags=re.I)
    text = _UUID_RE.sub("<openstack-object>", text)
    return _semantic_text(text)


def _semantic_group(group_id: Any, label: Any) -> str | None:
    semantic_label = _semantic_endpoint(label)
    if semantic_label:
        return semantic_label
    text = str(group_id or "").strip()
    if not text:
        return None
    return _semantic_text(_UUID_RE.sub("<openstack-object>", text))


def _semantic_test_id(
    value: Any,
    details: Mapping[str, Any] | None = None,
) -> str:
    text = str(value or "unknown-result").strip()
    evidence = dict(details or {})
    path = evidence.get("path") if isinstance(evidence.get("path"), Mapping) else {}
    prefixes: set[str] = set()
    for raw in (
        path.get("execution_scope"),
        evidence.get("execution_scope"),
        path.get("availability_zone"),
        evidence.get("availability_zone"),
    ):
        scope = str(raw or "").strip()
        if not scope:
            continue
        prefixes.add(scope)
        if not scope.lower().startswith("az-"):
            prefixes.add(f"az-{scope}")
    for prefix in sorted(prefixes, key=len, reverse=True):
        token = f"{prefix}-"
        if text.casefold().startswith(token.casefold()):
            text = text[len(token) :]
            break
    text = _PLACEMENT_SCOPE_PREFIX_RE.sub("", text)
    text = _UUID_RE.sub("<openstack-object>", text)
    return _semantic_text(text) or "unknown-result"


def _semantic_text(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if not text:
        return None
    text = re.sub(r"\s+", " ", text)
    return text


def _collect_values(mapping: Mapping[str, Any], keys: tuple[str, ...]) -> list[Any]:
    output: list[Any] = []
    for key in keys:
        value = mapping.get(key)
        if value in (None, "", [], {}):
            continue
        if isinstance(value, list):
            output.extend(value)
        elif isinstance(value, tuple):
            output.extend(value)
        else:
            output.append(value)
    # JSON-compatible stable de-duplication without assuming hashability.
    unique: dict[str, Any] = {}
    for value in output:
        try:
            marker = json.dumps(
                value, sort_keys=True, separators=(",", ":"), allow_nan=False
            )
        except (TypeError, ValueError):
            marker = str(value)
            value = str(value)
        unique[marker] = value
    return [unique[key] for key in sorted(unique)]


def _reassembly_observed(fragmentation: Mapping[str, Any]) -> bool | None:
    endpoint = fragmentation.get("endpoint_observations")
    if isinstance(endpoint, Mapping):
        reassembly = endpoint.get("destination_reassembly")
        if isinstance(reassembly, Mapping):
            value = reassembly.get("directly_observed")
            if isinstance(value, bool):
                return value
    value = fragmentation.get("in_path_fragmentation_observed")
    return value if isinstance(value, bool) else None


def _positive_int(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _human_code(value: Any) -> str:
    text = str(value or "").strip().replace("_", " ").replace("-", " ")
    return text[:1].upper() + text[1:] if text else ""


def _mtu_contract_authoritative(details: Mapping[str, Any]) -> bool:
    metrics = details.get("metrics")
    if isinstance(metrics, Mapping):
        return bool(metrics.get("contract_authoritative"))
    mtu = details.get("mtu_contract")
    return bool(mtu.get("authoritative")) if isinstance(mtu, Mapping) else False


def _merge_supplied_contract(
    generated: Mapping[str, Any], supplied: Mapping[str, Any]
) -> dict[str, Any]:
    return _merge_mapping(dict(generated), supplied)


def _merge_mapping(
    base: Mapping[str, Any], overlay: Mapping[str, Any]
) -> dict[str, Any]:
    output = copy.deepcopy(dict(base))
    for key, value in overlay.items():
        if isinstance(value, Mapping) and isinstance(output.get(key), Mapping):
            output[key] = _merge_mapping(output[key], value)
        else:
            output[key] = copy.deepcopy(value)
    return output


__all__ = [
    "AUTHORITY_CLASSES",
    "CONTRACT_SCHEMA_VERSION",
    "PATH_SIGNATURE_SCHEMA_VERSION",
    "TYPED_VERDICTS",
    "build_path_signature",
    "build_result_contract",
    "contract_shape",
    "execution_state_for_status",
    "expectation_description",
    "normalize_result_record",
    "observation_description",
    "observation_shape",
    "packet_size_accounting",
    "performance_expectation",
    "performance_observation",
    "semantic_result_key",
    "typed_verdict",
    "typed_verdict_for_status",
    "validate_path_signature",
    "validate_result_contract",
]
