"""Fail-closed evidence that a guest probe used its declared data interface."""

from __future__ import annotations

import ipaddress
from typing import Any

from .models import Endpoint


def _canonical_address(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(value))
    except (TypeError, ValueError):
        return None


def data_route_evidence(
    endpoint: Endpoint, source_ip: str, destination_ip: str, route: Any
) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "verified": None,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "expected_port_id": endpoint.test_port_id,
        "expected_mac": endpoint.test_mac,
        "management_port_id": endpoint.management_port_id,
    }
    canonical_source = _canonical_address(source_ip)
    fixed_addresses = {
        _canonical_address(value) for value in endpoint.fixed_ips.values()
    }
    if (
        canonical_source is None
        or canonical_source not in fixed_addresses
        or (
            endpoint.test_port_id
            and endpoint.test_port_id == endpoint.management_port_id
        )
    ):
        return {
            **evidence,
            "verified": False,
            "reason": "probe source is not a distinct declared data port/address",
        }
    if not isinstance(route, dict) or not endpoint.test_mac:
        return {**evidence, "reason": "data interface/route evidence is unavailable"}
    links = route.get("interfaces")
    if not isinstance(links, list):
        return {**evidence, "reason": "guest interface inventory is unavailable"}
    data_links = [
        link
        for link in links
        if isinstance(link, dict)
        and str(link.get("address") or "").lower() == endpoint.test_mac.lower()
    ]
    if len(data_links) != 1:
        return {
            **evidence,
            "verified": False,
            "reason": "declared data-port MAC was not uniquely present in the guest",
        }
    data = data_links[0]
    addresses = {
        _canonical_address(row.get("local"))
        for row in data.get("addr_info", [])
        if isinstance(row, dict)
    }
    evidence.update(
        expected_device=data.get("ifname"), observed_device=route.get("device")
    )
    if canonical_source not in addresses:
        return {
            **evidence,
            "verified": False,
            "reason": "bound source IP was not assigned to the declared data interface",
        }
    if (
        route.get("source") is not None
        and _canonical_address(route["source"]) != canonical_source
    ):
        return {
            **evidence,
            "verified": False,
            "reason": "route selected a different source address",
        }
    if route.get("device") and route["device"] != data.get("ifname"):
        return {
            **evidence,
            "verified": False,
            "reason": "route selected another interface instead of the declared data interface",
        }
    if route.get("returncode") == 0 and route.get("device") == data.get("ifname"):
        return {
            **evidence,
            "verified": True,
            "reason": "bound data source and egress device match the declared Neutron port",
        }
    # A real missing route is a valid negative observation. A failed inspector,
    # permission error, or missing command is not evidence of isolation.
    text = str(route.get("stderr") or "").lower()
    if route.get("returncode") not in (None, 0) and any(
        value in text
        for value in (
            "network is unreachable",
            "no route to host",
            "host is unreachable",
        )
    ):
        return {
            **evidence,
            "verified": True,
            "reason": "data source verified; kernel reports no route",
        }
    return {**evidence, "reason": "kernel route could not be verified"}
