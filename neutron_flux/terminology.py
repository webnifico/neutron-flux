from __future__ import annotations

import re
from typing import Any

from .operation_compat import operation_display_text

CATEGORY_LABELS = {
    "compute-placement": "Compute placement and migration",
    "controller-bootstrap": "Controller setup",
    "cross-zone-connectivity": "Cross-zone network connectivity",
    "egress": "External egress",
    "floating-ip": "Floating-IP connectivity",
    "floating-ip-lifecycle": "Floating-IP lifecycle",
    "floating-ip-peer": "Floating-IP peer and hairpin connectivity",
    "floating-ip-packet-size": "Floating-IP packet size",
    "floating-ip-egress-source-address": "Floating-IP outbound source address",
    "floating-ip-egress-mtu": "Floating-IP outbound path MTU",
    "floating-ip-egress-fragmentation": "Floating-IP outbound fragmentation",
    "mtu": "MTU validation",
    "network-performance": "Network path performance",
    "provider-network-connectivity": "Provider network connectivity",
    "routed-provider": "Routed provider network connectivity",
    "tenant-provider-connectivity": "Project/provider fixed-IP connectivity",
    "project-provider-connectivity": "Project/provider fixed-IP connectivity",
    "router-extra-route": "Router static-route connectivity",
    "router-static-routing": "Router static-route connectivity",
    "router-interface-lifecycle": "Router interface lifecycle",
    "same-subnet": "Same-network connectivity",
    "security-group": "Security-group enforcement",
    "server-lifecycle": "Server stop/start lifecycle",
    "source-nat-setting": "Router SNAT setting lifecycle",
    "source-nat-connectivity": "Router source-NAT connectivity",
    "source-nat-packet-size": "Router source-NAT packet size",
    "tenant-router": "Routing between project networks",
    "project-network-routing": "Routing between project networks",
}

SCENARIO_LABELS = {
    "Tenant-visible network performance": "Network path performance",
    "Tenant same-network connectivity": "Project-network same-subnet connectivity",
    "Direct tenant-to-provider routing": (
        "Project/provider connectivity with matching address scopes"
    ),
    "Tenant/provider fixed-IP connectivity": "Project/provider fixed-IP connectivity",
    "Tenant-to-tenant routing through one Neutron router": (
        "Routing between project networks through one Neutron router"
    ),
    "Routing between two Neutron routers using extra routes": (
        "Router-to-router static routing"
    ),
    "Router-interface lifecycle for every usable tenant pool": (
        "Router-interface lifecycle for a project subnet pool"
    ),
    "Floating IPv4 ingress": "Inbound connectivity through a floating IPv4 address",
    "Floating IPv4 lifecycle": "Floating IPv4 address lifecycle",
    "Representative MTU validation": "Sampled MTU validation",
    "Representative security-group enforcement": ("Sampled security-group enforcement"),
    "Representative external egress": "Sampled external egress",
    "Representative VM stop/start recovery": "Sampled VM stop/start recovery",
    "Representative IPv4 source-NAT setting lifecycle": (
        "Sampled IPv4 router SNAT setting lifecycle"
    ),
}

_REPLACEMENTS = (
    (r"\btenant-to-tenant\b", "project-to-project"),
    (r"\btenant/provider\b", "project/provider"),
    (r"\btenant networks\b", "project networks"),
    (r"\btenant network\b", "project network"),
    (r"\btenant subnets\b", "project subnets"),
    (r"\btenant subnet\b", "project subnet"),
    (r"\btenant topology\b", "router-connected project topology"),
    (r"\btenant endpoint\b", "project endpoint"),
    (r"\btenant traffic\b", "project-network traffic"),
    (r"\btenant router\b", "Neutron router"),
    (r"\btenant pools\b", "project subnet pools"),
    (r"\btenant pool\b", "project subnet pool"),
    (r"\btenant fixed IP\b", "project fixed IP"),
    (r"\btenant\b", "project"),
    (r"\bextra routes\b", "router static routes"),
    (r"\bextra route\b", "router static route"),
    (r"\bextra-route\b", "static-route"),
    (r"\bsource-NAT path\b", "router SNAT egress path"),
    (r"\bsource-NAT setting\b", "router SNAT setting"),
    (r"\bsource-NAT\b", "router SNAT"),
    (r"\brepresentative\b", "sampled"),
)


def friendly_operator_text(value: Any) -> str:
    """Translate stable internal vocabulary only at human-facing boundaries."""
    text = operation_display_text(str(value or ""))
    for pattern, replacement in _REPLACEMENTS:
        text = re.sub(pattern, replacement, text, flags=re.I)
    return text


def friendly_scenario(value: Any) -> str:
    raw = str(value or "").strip()
    return SCENARIO_LABELS.get(raw, friendly_operator_text(raw))


def friendly_title(value: Any) -> str:
    return friendly_operator_text(value)


def category_label(category: str) -> str:
    return CATEGORY_LABELS.get(category, friendly_operator_text(category).title())


__all__ = [
    "CATEGORY_LABELS",
    "SCENARIO_LABELS",
    "category_label",
    "friendly_operator_text",
    "friendly_scenario",
    "friendly_title",
]
