from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Mapping
from typing import Any

from .operation_compat import canonical_operation_descriptions

_LEGACY_EXPECTATION_DESCRIPTIONS: dict[str, frozenset[str]] = {
    "withdrawn": frozenset(
        {"The path must withdraw after the requested routing attachment is removed."}
    ),
    "restored": frozenset(
        {"The path must return after the requested routing attachment is restored."}
    ),
    "udp-quality-profile-recorded": frozenset(
        {
            "Record offered and achieved UDP rate, packet rate, loss, jitter, "
            "duplicates, and reordering for every requested packet size and direction.",
        }
    ),
    "directional-balance-assessed": frozenset(
        {
            "Compare forward and reverse throughput, latency, and UDP loss without "
            "assuming that directional differences identify an infrastructure cause.",
        }
    ),
}

_NON_SEMANTIC_ID_KEYS = {
    "operation_id",
    "transaction_id",
    "run_id",
    "result_id",
    "path_id",
    "pair_id",
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


def _typed_verdict(status: Any) -> str:
    return _STATUS_TO_VERDICT.get(str(status or "").strip().upper(), "ERROR")


def openstack_object_candidates(
    details: Mapping[str, Any],
) -> dict[tuple[str, str, str], set[str]]:
    output: dict[tuple[str, str, str], set[str]] = {}

    def visit(
        value: Any, *, key: str = "", path: str = "details", depth: int = 0
    ) -> None:
        if depth > 5:
            return
        if isinstance(value, Mapping):
            for child_key, child in value.items():
                child_name = str(child_key)
                visit(
                    child, key=child_name, path=f"{path}.{child_name}", depth=depth + 1
                )
            return
        if isinstance(value, list):
            for child in value[:64]:
                visit(child, key=key, path=path, depth=depth + 1)
            return
        normalized_key = key.lower()
        if normalized_key in _NON_SEMANTIC_ID_KEYS:
            return
        if not (normalized_key.endswith("_id") or normalized_key.endswith("_ids")):
            return
        if value is None:
            return
        identifier = str(value).strip()
        if not identifier or len(identifier) > 256:
            return
        object_type = normalized_key.removesuffix("_ids").removesuffix("_id")
        object_type = object_type.replace("source_", "").replace("destination_", "")
        if object_type in {"group", "spec", "base_test", "host_qualification_pair"}:
            return
        role = (
            "source"
            if normalized_key.startswith("source_")
            else "destination"
            if normalized_key.startswith("destination_")
            else "related"
        )
        output.setdefault((object_type, identifier, role), set()).add(path)

    visit(details)
    return output


def openstack_objects(details: Mapping[str, Any]) -> list[dict[str, str]]:
    candidates = openstack_object_candidates(details)
    return [
        {
            "type": object_type,
            "id": identifier,
            "role": role,
            "evidence_path": min(candidates[(object_type, identifier, role)]),
        }
        for object_type, identifier, role in sorted(candidates)
    ]


def canonicalize_supplied_contract(
    supplied: Mapping[str, Any],
    *,
    generated: Mapping[str, Any],
    details: Mapping[str, Any],
    family: int | None,
    contract_type: str,
    status: str,
    legacy_generated: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Normalize only provably generated legacy fields before strict validation."""

    normalized = canonical_operation_descriptions(
        copy.deepcopy(dict(supplied)), generated
    )
    if legacy_generated is not None:
        # Only exact historical generated values may be upgraded. All other
        # fields, including verdicts and endpoint identity, remain strictly checked.
        for key, legacy_value in legacy_generated.items():
            if (
                legacy_value != generated.get(key)
                and key in normalized
                and normalized[key] == legacy_value
            ):
                if key in generated:
                    normalized[key] = copy.deepcopy(generated[key])
                else:
                    del normalized[key]
    _canonicalize_openstack_object_paths(
        normalized,
        generated=generated,
        details=details,
    )
    _canonicalize_legacy_expectation_description(
        normalized,
        generated=generated,
    )
    _replace_exact_legacy_field(
        normalized,
        generated=generated,
        field="components",
        legacy=_legacy_component_contracts(
            contract_type=contract_type,
            status=status,
            details=details,
            family=family,
        ),
    )
    _replace_exact_legacy_field(
        normalized,
        generated=generated,
        field="components",
        legacy=_legacy_component_contracts(
            contract_type=contract_type,
            status=status,
            details=details,
            family=family,
            local_boundary_descriptions=True,
        ),
    )
    _replace_exact_legacy_field(
        normalized,
        generated=generated,
        field="packet_size",
        legacy=_legacy_packet_size_accounting(details, family=family),
    )
    return normalized


def _canonicalize_legacy_expectation_description(
    supplied: dict[str, Any],
    *,
    generated: Mapping[str, Any],
) -> None:
    expectation = supplied.get("expectation")
    generated_expectation = generated.get("expectation")
    if not isinstance(expectation, Mapping) or not isinstance(
        generated_expectation, Mapping
    ):
        return
    code = str(expectation.get("code") or "")
    if code != str(generated_expectation.get("code") or ""):
        return
    supplied_description = expectation.get("description")
    generated_description = generated_expectation.get("description")
    if supplied_description == generated_description:
        return
    if supplied_description not in _LEGACY_EXPECTATION_DESCRIPTIONS.get(
        code, frozenset()
    ):
        return
    normalized_expectation = dict(expectation)
    normalized_expectation["description"] = copy.deepcopy(generated_description)
    supplied["expectation"] = normalized_expectation


def canonicalize_supplied_path_signature(
    supplied: Mapping[str, Any],
    *,
    generated: Mapping[str, Any],
    details: Mapping[str, Any],
    family: int | None,
    legacy_blocked_isolation: bool = False,
) -> dict[str, Any]:
    """Upgrade exact legacy classification/context without accepting overrides."""

    normalized = copy.deepcopy(dict(supplied))
    if legacy_blocked_isolation:
        identity = copy.deepcopy(dict(generated.get("identity") or {}))
        identity["contract_type"] = "security-group-isolation"
        encoded = json.dumps(
            identity, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        legacy_key = "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        if (
            normalized.get("identity") == identity
            and normalized.get("key") == legacy_key
        ):
            normalized["identity"] = copy.deepcopy(generated["identity"])
            normalized["key"] = generated["key"]
    context = normalized.get("context")
    generated_context = generated.get("context")
    if not isinstance(context, Mapping) or not isinstance(generated_context, Mapping):
        return normalized
    legacy_packet_size = _legacy_packet_size_context(details, family=family)
    if (
        "packet_size" in context
        and context.get("packet_size") != generated_context.get("packet_size")
        and context.get("packet_size") == legacy_packet_size
    ):
        replacement = dict(context)
        replacement["packet_size"] = copy.deepcopy(generated_context.get("packet_size"))
        normalized["context"] = replacement
    return normalized


def _canonicalize_openstack_object_paths(
    supplied: dict[str, Any],
    *,
    generated: Mapping[str, Any],
    details: Mapping[str, Any],
) -> None:
    expectation = supplied.get("expectation")
    if not isinstance(expectation, Mapping) or "openstack_objects" not in expectation:
        return
    supplied_objects = expectation.get("openstack_objects")
    generated_expectation = generated.get("expectation")
    generated_objects = (
        generated_expectation.get("openstack_objects")
        if isinstance(generated_expectation, Mapping)
        else None
    )
    label = "Supplied result contract expectation.openstack_objects"
    if not isinstance(supplied_objects, list) or not isinstance(
        generated_objects, list
    ):
        raise ValueError(f"{label} contradicts the canonical value")
    if len(supplied_objects) != len(generated_objects):
        raise ValueError(f"{label} contradicts the canonical value")
    if supplied_objects == generated_objects:
        # Canonical evidence already has the exact generated string fields and
        # paths. Only legacy path alternatives need another evidence-tree scan.
        return
    candidates = openstack_object_candidates(details)
    required_fields = {"type", "id", "role", "evidence_path"}
    for supplied_object, generated_object in zip(
        supplied_objects, generated_objects, strict=True
    ):
        if not isinstance(supplied_object, Mapping) or not isinstance(
            generated_object, Mapping
        ):
            raise ValueError(f"{label} contradicts the canonical value")
        if set(supplied_object) != required_fields:
            raise ValueError(f"{label} contradicts the canonical value")
        identity = tuple(
            str(supplied_object.get(field) or "") for field in ("type", "id", "role")
        )
        generated_identity = tuple(
            str(generated_object.get(field) or "") for field in ("type", "id", "role")
        )
        if identity != generated_identity:
            raise ValueError(f"{label} contradicts the canonical value")
        evidence_path = str(supplied_object.get("evidence_path") or "")
        if evidence_path not in candidates.get(identity, set()):
            raise ValueError(f"{label} contradicts the canonical value")
    normalized_expectation = dict(expectation)
    normalized_expectation["openstack_objects"] = copy.deepcopy(generated_objects)
    supplied["expectation"] = normalized_expectation


def _replace_exact_legacy_field(
    supplied: dict[str, Any],
    *,
    generated: Mapping[str, Any],
    field: str,
    legacy: Any,
) -> None:
    if field not in supplied or supplied.get(field) == generated.get(field):
        return
    if supplied.get(field) == legacy:
        supplied[field] = copy.deepcopy(generated.get(field))


def _legacy_component_contracts(
    *,
    contract_type: str,
    status: str,
    details: Mapping[str, Any],
    family: int | None,
    local_boundary_descriptions: bool = False,
) -> list[dict[str, Any]]:
    if contract_type != "packet-size-path":
        return []
    metrics = details.get("metrics")
    if not isinstance(metrics, Mapping):
        return []
    direction_rows = [
        item
        for direction in ("forward", "reverse")
        if isinstance((item := metrics.get(direction)), Mapping)
    ]
    mtu_states = [
        str(item.get("advertised_mtu_contract_status") or "unverified")
        for item in direction_rows
    ]
    pmtud_states = [
        str(item.get("pmtud_status") or "unverified") for item in direction_rows
    ]
    fragmentation_states = [
        str((item.get("fragmentation") or {}).get("capability") or "unverified")
        for item in direction_rows
    ]
    mss_complete = bool(direction_rows) and all(
        item.get("client_mss") is not None and item.get("server_mss") is not None
        for item in direction_rows
    )
    verdict = _typed_verdict(status)
    return [
        {
            "type": "mtu",
            "description": (
                "Advertised MTU and measured or local boundary evidence"
                if local_boundary_descriptions
                else "Advertised and confirmed no-fragment MTU boundary"
            ),
            "observed": mtu_states,
            "verdict": verdict,
        },
        {
            "type": "pmtud",
            "description": "Path MTU discovery behavior",
            "observed": pmtud_states,
            "verdict": verdict,
        },
        {
            "type": "ipv4-fragmentation" if family == 4 else "ipv6-packet-too-big",
            "description": (
                "IPv4 fragmentation and reassembly behavior"
                if family == 4
                else "IPv6 Packet Too Big and source-fragmentation behavior"
            ),
            "observed": fragmentation_states,
            "verdict": verdict,
        },
        {
            "type": "tcp-mss",
            "description": (
                "TCP MSS remains within the available path or route constraint."
                if local_boundary_descriptions
                else "TCP MSS remains within the confirmed path boundary."
            ),
            "observed": "complete" if mss_complete else "incomplete",
            "verdict": "PASS" if mss_complete and status == "PASS" else verdict,
        },
    ]


def _legacy_packet_size_context(
    details: Mapping[str, Any], *, family: int | None
) -> dict[str, Any]:
    accounting = _legacy_packet_size_accounting(details, family=family)
    if not accounting:
        return {}
    metrics = details.get("metrics")
    metrics = metrics if isinstance(metrics, Mapping) else {}
    return {
        "advertised_mtu": metrics.get("expected_mtu"),
        "guest_interface_mtu": {
            "source": metrics.get("source_mtu"),
            "destination": metrics.get("destination_mtu"),
        },
        "accounting": accounting,
    }


def _legacy_packet_size_accounting(
    details: Mapping[str, Any], *, family: int | None
) -> dict[str, Any]:
    measurement = str(details.get("measurement") or "").strip().lower()
    measurement = (
        "concurrent-path-load" if measurement == "fabric-scale" else measurement
    )
    metrics = details.get("metrics")
    metrics = metrics if isinstance(metrics, Mapping) else {}
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
            discovered = _positive_int(item.get("discovered_mtu"))
            icmp_header = _positive_int(item.get("header_bytes")) or ip_header + 8
            fragmentation = item.get("fragmentation")
            fragmentation = fragmentation if isinstance(fragmentation, Mapping) else {}
            tested = _positive_int(fragmentation.get("tested_packet_size"))
            frag_header = (
                _positive_int(fragmentation.get("header_bytes")) or icmp_header
            )
            expected_mss = _positive_int(item.get("expected_max_mss"))
            directions[direction] = {
                "confirmed_no_fragment_ip_packet_bytes": discovered,
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
    direct_packet = _positive_int(details.get("packet_size"))
    if direct_packet is not None:
        header = _positive_int(details.get("header_bytes")) or ip_header + 8
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


__all__ = [
    "canonicalize_supplied_contract",
    "canonicalize_supplied_path_signature",
    "openstack_objects",
]
