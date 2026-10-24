from __future__ import annotations

from typing import Any

# Canonical topology identities.  Older plans and checkpoints remain
# executable through the legacy aliases below, but new plans never emit the
# former tenant/extra-route vocabulary.
PROVIDER_NETWORK = "provider"
PROJECT_NETWORK = "project-network"
ROUTING_UNASSIGNED_PROJECT_NETWORK = "routing-unassigned-project-network"
ONE_ROUTER_PROJECT_NETWORKS = "one-router-project-networks"
TWO_ROUTER_STATIC_ROUTING = "two-router-static-routing"
NESTED_PUBLIC_PROJECT_NETWORK = "nested-public-project-network"
PRIVATE_TRANSLATION_PROJECT_NETWORK = "private-translation-project-network"

LEGACY_GROUP_KIND_ALIASES = {
    "tenant-pool": PROJECT_NETWORK,
    "tenant-no-routing-group": ROUTING_UNASSIGNED_PROJECT_NETWORK,
    "tenant-router-pair": ONE_ROUTER_PROJECT_NETWORKS,
    "extra-route-pair": TWO_ROUTER_STATIC_ROUTING,
}

GROUP_KIND_RESOURCE_SLUGS = {
    PROVIDER_NETWORK: "provider-network",
    PROJECT_NETWORK: "project-network",
    ROUTING_UNASSIGNED_PROJECT_NETWORK: "routing-unassigned",
    ONE_ROUTER_PROJECT_NETWORKS: "one-router",
    TWO_ROUTER_STATIC_ROUTING: "two-router-static",
    NESTED_PUBLIC_PROJECT_NETWORK: "nested-public",
    PRIVATE_TRANSLATION_PROJECT_NETWORK: "private-translation",
}

PROJECT_NETWORK_KINDS = frozenset(
    {
        PROJECT_NETWORK,
        ROUTING_UNASSIGNED_PROJECT_NETWORK,
        "tenant-pool",
        "tenant-no-routing-group",
    }
)
ONE_ROUTER_KINDS = frozenset({ONE_ROUTER_PROJECT_NETWORKS, "tenant-router-pair"})
STATIC_ROUTING_KINDS = frozenset({TWO_ROUTER_STATIC_ROUTING, "extra-route-pair"})
NESTED_PUBLIC_KINDS = frozenset({NESTED_PUBLIC_PROJECT_NETWORK})

# Floating addresses may only target a fixed address on a topology that Flux
# created expressly for translation.  The value is serialized in plans so the
# planner, approved-plan loader, and runtime can enforce the same contract.
FLOATING_IP_TARGET_CONTRACT = "disposable-private-fixed-ip"

PROJECT_PROVIDER_CONNECTIVITY = "project-provider-connectivity"
PROJECT_NETWORK_ROUTING = "project-network-routing"
ROUTER_STATIC_ROUTING = "router-static-routing"

LEGACY_CATEGORY_ALIASES = {
    "tenant-provider-connectivity": PROJECT_PROVIDER_CONNECTIVITY,
    "tenant-router": PROJECT_NETWORK_ROUTING,
    "router-extra-route": ROUTER_STATIC_ROUTING,
}

STATIC_ROUTE_BASELINE = "static-route-baseline"
STATIC_ROUTE_INSTALL = "static-route-install"
STATIC_ROUTE_WITHDRAW = "static-route-withdraw"
STATIC_ROUTE_RESTORE = "static-route-restore"

LEGACY_OPERATION_ALIASES = {
    "extra-route-baseline": STATIC_ROUTE_BASELINE,
    "extra-route-add": STATIC_ROUTE_INSTALL,
    "extra-route-remove": STATIC_ROUTE_WITHDRAW,
    "extra-route-restore": STATIC_ROUTE_RESTORE,
}

STATIC_ROUTING_OPERATIONS = frozenset(
    {
        STATIC_ROUTE_BASELINE,
        STATIC_ROUTE_INSTALL,
        STATIC_ROUTE_WITHDRAW,
        STATIC_ROUTE_RESTORE,
        *LEGACY_OPERATION_ALIASES,
    }
)


def canonical_group_kind(value: Any) -> str:
    raw = str(value or "").strip()
    return LEGACY_GROUP_KIND_ALIASES.get(raw, raw)


def canonical_category(value: Any) -> str:
    raw = str(value or "").strip()
    return LEGACY_CATEGORY_ALIASES.get(raw, raw)


def group_kind_is(value: Any, canonical: str) -> bool:
    return canonical_group_kind(value) == canonical


def group_resource_slug(value: Any) -> str:
    canonical = canonical_group_kind(value)
    return GROUP_KIND_RESOURCE_SLUGS.get(
        canonical,
        canonical.replace("_", "-") or "network-path",
    )


def static_route_state_key(group_id: Any) -> str:
    return f"static-route:{str(group_id or '').strip()}"


__all__ = [
    "GROUP_KIND_RESOURCE_SLUGS",
    "LEGACY_CATEGORY_ALIASES",
    "LEGACY_GROUP_KIND_ALIASES",
    "LEGACY_OPERATION_ALIASES",
    "ONE_ROUTER_KINDS",
    "ONE_ROUTER_PROJECT_NETWORKS",
    "NESTED_PUBLIC_KINDS",
    "NESTED_PUBLIC_PROJECT_NETWORK",
    "FLOATING_IP_TARGET_CONTRACT",
    "PRIVATE_TRANSLATION_PROJECT_NETWORK",
    "PROJECT_NETWORK",
    "PROJECT_NETWORK_KINDS",
    "PROJECT_NETWORK_ROUTING",
    "PROJECT_PROVIDER_CONNECTIVITY",
    "PROVIDER_NETWORK",
    "ROUTER_STATIC_ROUTING",
    "ROUTING_UNASSIGNED_PROJECT_NETWORK",
    "STATIC_ROUTE_BASELINE",
    "STATIC_ROUTE_INSTALL",
    "STATIC_ROUTE_RESTORE",
    "STATIC_ROUTE_WITHDRAW",
    "STATIC_ROUTING_KINDS",
    "STATIC_ROUTING_OPERATIONS",
    "TWO_ROUTER_STATIC_ROUTING",
    "canonical_category",
    "canonical_group_kind",
    "group_kind_is",
    "group_resource_slug",
    "static_route_state_key",
]
