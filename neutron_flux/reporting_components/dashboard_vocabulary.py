from __future__ import annotations

STATUS_WEIGHT = {
    "ERROR": 60,
    "FAIL": 50,
    "BLOCKED_BY_SETUP_ERROR": 40,
    "BLOCKED_BY_PREREQUISITE": 35,
    "UNVERIFIED": 30,
    "NOT_RUN_CANCELLED": 25,
    "SKIP": 20,
    "NOT_APPLICABLE": 10,
    "PASS": 0,
}

TITLE_REPLACEMENTS = {
    "Provider subnet connectivity": "Provider connectivity",
    "Tenant same-network connectivity": "Project-network same-subnet connectivity",
    "Tenant-to-tenant routing through one router": "Routing between project networks",
    "Two-router extra-route connectivity": "Router-to-router static routing",
    "Tenant/provider fixed-IP connectivity": "Project/provider connectivity",
    "Representative provider MTU boundary": "Provider MTU boundary",
    "Representative guest oversized-packet rejection": "Oversized-packet rejection",
    "Path MTU, PMTUD, and TCP MSS": "Path packet-size and TCP segment limits",
    "Idle and loaded latency": "Idle and loaded latency",
    "UDP application-delivery loss, jitter, and packet rate": "UDP quality",
    "Concurrent-flow scaling": "Concurrent-flow scaling",
    "Path repeatability": "Path repeatability",
    "Directional asymmetry": "Directional balance",
    "Measure tenant traffic continuity during live migration": (
        "Live-migration traffic continuity"
    ),
    "Verify fresh functional baseline before live migration submission 1/2": (
        "Pre-migration functional baseline"
    ),
    "Verify fresh functional baseline before live migration submission 2/2": (
        "Pre-migration functional baseline"
    ),
    "Live-migrate an endpoint into intra-compute placement": (
        "Move endpoint to intra-compute placement"
    ),
    "Live-migrate an endpoint into inter-compute placement": (
        "Move endpoint to inter-compute placement"
    ),
    "Create intra-compute placement using the configured migration strategy": (
        "Create intra-compute placement"
    ),
    "Create inter-compute placement using the configured migration strategy": (
        "Create inter-compute placement"
    ),
    "Verify Neutron port rebinding after intra-compute migration": (
        "Verify port rebinding after migration"
    ),
    "Verify Neutron port rebinding after inter-compute migration": (
        "Verify port rebinding after migration"
    ),
    "Restore endpoint networking after intra-compute migration": (
        "Restore endpoint networking"
    ),
    "Restore endpoint networking after inter-compute migration": (
        "Restore endpoint networking"
    ),
    "Representative stop test VM and verify service loss": (
        "Stop/start service lifecycle"
    ),
    "Representative start test VM and verify service recovery": (
        "Stop/start service lifecycle"
    ),
    "Representative security-group deny test": "Security-group deny",
    "Representative security-group allow test": "Security-group allow",
    "Representative security-group restore test": "Security-group restore",
    "Representative remove tenant router attachment": "Router-interface lifecycle",
    "Representative restore tenant router attachment": "Router-interface lifecycle",
    "Remove tenant B router attachment": "Router-interface lifecycle",
    "Restore tenant B router attachment": "Router-interface lifecycle",
    "Two-router baseline without extra routes": "Baseline before static routes",
    "Add routes between two Neutron routers": "Add router static routes",
    "Remove one extra route": "Withdraw one router static route",
    "Restore removed extra route": "Restore router static route",
    "Configure the OpenStack probe controller": "Configure probe controller",
    "Reach the probe controller over SSH": "Reach probe controller",
}

TOPOLOGY_LABELS = {
    "same-subnet": (
        "Same subnet",
        "Endpoints share the same Neutron network and IP subnet.",
    ),
    "tenant-router": (
        "Routing between project networks",
        "Two project-owned networks communicate through one Neutron router.",
    ),
    "router-extra-route": (
        "Router-to-router static routing",
        "Two Neutron routers exchange traffic through explicit static routes "
        "across a transit network.",
    ),
    "project-network-routing": (
        "Routing between project networks",
        "Two project-owned networks communicate through one Neutron router.",
    ),
    "router-static-routing": (
        "Router-to-router static routing",
        "Two Neutron routers exchange traffic through explicit static routes "
        "across a transit network.",
    ),
    "project-provider-connectivity": (
        "Project-to-provider fixed-IP routing",
        "A fixed IP on a project-owned network communicates with an endpoint "
        "on a provider network.",
    ),
    "tenant-provider-connectivity": (
        "Project-to-provider fixed-IP routing",
        "A fixed IP on a project-owned network communicates with an endpoint "
        "on a provider network.",
    ),
    "floating-ip": (
        "Floating IP ingress",
        "Traffic enters through a Neutron floating IP and destination network "
        "address translation.",
    ),
    "source-nat": (
        "Project-network external egress",
        "A project endpoint initiates traffic through a Neutron router using "
        "source network address translation.",
    ),
    "source-nat-packet-size": (
        "Router source-NAT packet-size behaviour",
        "A project endpoint without a floating IP initiates traffic to the Flux "
        "runner through the router external gateway so Flux can measure "
        "translated identity, routed MTU, PMTUD, and fragmentation capability.",
    ),
    "floating-ip-packet-size": (
        "Floating-IP egress packet-size behaviour",
        "A project endpoint with a floating IP initiates traffic to the Flux "
        "runner so Flux can verify the translated source identity, routed MTU, "
        "PMTUD, and fragmentation capability.",
    ),
    "floating-ip-egress-source-address": (
        "Floating-IP outbound source address",
        "A private endpoint initiates one TCP connection to a provider observer, "
        "which reports the translated source address it saw.",
    ),
    "floating-ip-egress-mtu": (
        "Floating-IP outbound path MTU",
        "DF/PMTUD probes measure the no-fragment packet-size boundary only after "
        "the outbound source-address prerequisite passes.",
    ),
    "floating-ip-egress-fragmentation": (
        "Floating-IP outbound fragmentation",
        "A separate probe checks whether a source-sized IPv4 packet crosses when "
        "fragmentation is permitted.",
    ),
    "provider": (
        "Provider network",
        "Endpoints communicate directly on an operator-provided Neutron network.",
    ),
}

MEASUREMENT_TITLES = {
    "tcp-throughput": "TCP throughput",
    "latency": "Latency under idle and loaded traffic",
    "udp": "UDP packet quality",
    "mtu-mss": "Packet-size limits",
    "concurrency": "Concurrent TCP flow scaling",
    "asymmetry": "Forward and reverse balance",
    "repeatability": "Measurement repeatability",
    "fabric-scale": "Concurrent VM-pair load",
    "concurrent-path-load": "Concurrent VM-pair load",
}

LEGACY_DIRECT_COMPONENT_LOCATIONS = {
    "ovn-router",
    "neutron-router",
    "ovn-router-path",
    "neutron-router-path",
    "in-path-router",
}

__all__ = [
    "LEGACY_DIRECT_COMPONENT_LOCATIONS",
    "MEASUREMENT_TITLES",
    "STATUS_WEIGHT",
    "TITLE_REPLACEMENTS",
    "TOPOLOGY_LABELS",
]


RESULT_VIEW_KEYS = (
    "result_id",
    "title",
    "test_name",
    "status",
    "severity",
    "scenario_label",
    "operator_message",
    "phase",
    "family_label",
    "path_id",
    "source_display",
    "destination_display",
    "expected",
    "observed",
    "contract_type",
    "contract_verdict",
    "semantic_path_key",
    "host_scope",
)
