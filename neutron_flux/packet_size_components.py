"""Packet-size component outcomes derived from their own recorded evidence."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def _verdict(
    states: list[str], *, passed: set[str], inapplicable: set[str] | None = None
) -> str:
    inapplicable = inapplicable or set()
    if any(
        state in {"failed", "not-supported", "above-constraint"} for state in states
    ):
        return "FAIL"
    if not states or any(state not in passed | inapplicable for state in states):
        return "UNVERIFIED"
    return "INAPPLICABLE" if all(state in inapplicable for state in states) else "PASS"


def _mss_state(item: Mapping[str, Any]) -> str:
    values: list[int] = []
    for key in ("client_mss", "server_mss", "expected_max_mss"):
        value = item.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            return "incomplete"
        values.append(value)
    client, server, maximum = values
    return "above-constraint" if max(client, server) > maximum else "within-constraint"


def _fragmentation_state(item: Mapping[str, Any]) -> str:
    fragmentation = item.get("fragmentation")
    if not isinstance(fragmentation, Mapping):
        return "unverified"
    capability = str(fragmentation.get("capability") or "unverified")
    if capability in {"not-required", "path-supports-source-mtu"}:
        return capability
    packet_size = fragmentation.get("tested_packet_size")
    if (
        isinstance(packet_size, bool)
        or not isinstance(packet_size, int)
        or packet_size <= 0
    ):
        return "unverified"
    permitted = fragmentation.get("fragmentation_permitted")
    classification = (
        permitted.get("classification") if isinstance(permitted, Mapping) else None
    )
    if capability == "supported" and classification == "success":
        return capability
    if capability == "not-supported" and classification == "no-reply":
        return capability
    return "unverified"


def component_contracts(
    *,
    contract_type: str,
    status: str,
    details: Mapping[str, Any],
    family: int | None,
) -> list[dict[str, Any]]:
    """Keep advisory test status separate from each component's observation.

    A completed MTU observation can retain its overall advisory PASS while an
    advertised-size contract failed. Conversely, an unrelated component failure
    cannot turn observed PMTUD feedback into a PMTUD failure.
    """
    if contract_type != "packet-size-path":
        return []
    metrics = details.get("metrics")
    if not isinstance(metrics, Mapping):
        return []
    recorded_directions = metrics.get("directions")
    directions = (
        [
            direction
            for direction in recorded_directions
            if direction in {"forward", "reverse"}
        ]
        if isinstance(recorded_directions, (list, tuple))
        else [direction for direction in ("forward", "reverse") if direction in metrics]
    )
    rows = [
        item if isinstance((item := metrics.get(direction)), Mapping) else {}
        for direction in directions
    ]
    mtu_states = [
        str(item.get("advertised_mtu_contract_status") or "unverified")
        if item.get("advertised_mtu_contract_authoritative") is not False
        else "unverified"
        for item in rows
    ]
    pmtud_states = [str(item.get("pmtud_status") or "unverified") for item in rows]
    fragmentation_states = [_fragmentation_state(item) for item in rows]
    mss_states = [_mss_state(item) for item in rows]
    specifications = [
        (
            "mtu",
            "Advertised MTU and measured or local boundary evidence",
            mtu_states,
            {"met"},
            set(),
        ),
        (
            "pmtud",
            "Path MTU discovery behavior",
            pmtud_states,
            {"packet-too-big-received"},
            {"expected-size-confirmed"},
        ),
        (
            "ipv4-fragmentation" if family == 4 else "ipv6-packet-too-big",
            "IPv4 fragmentation and reassembly behavior"
            if family == 4
            else "IPv6 Packet Too Big and source-fragmentation behavior",
            fragmentation_states,
            {"supported"},
            {"not-required", "path-supports-source-mtu"},
        ),
    ]
    components: list[dict[str, Any]] = [
        {
            "type": component_type,
            "description": description,
            "observed": states,
            "verdict": _verdict(states, passed=passed, inapplicable=inapplicable),
        }
        for component_type, description, states, passed, inapplicable in specifications
    ]
    components[2]["scope"] = "Recorded packet sizes and probe window only"
    components[2]["tested_packet_sizes"] = [
        fragmentation.get("tested_packet_size")
        if isinstance((fragmentation := item.get("fragmentation")), Mapping)
        and isinstance(fragmentation.get("fragmentation_permitted"), Mapping)
        else None
        for item in rows
    ]
    mss_verdict = _verdict(mss_states, passed={"within-constraint"})
    components.append(
        {
            "type": "tcp-mss",
            "description": "TCP MSS remains within the available path or route constraint.",
            "observed": "within-constraint"
            if mss_verdict == "PASS"
            else "above-constraint"
            if mss_verdict == "FAIL"
            else "incomplete",
            "verdict": mss_verdict,
        }
    )
    return components
