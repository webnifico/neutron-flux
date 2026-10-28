"""Concise human test titles independent from execution context."""

from __future__ import annotations

import re
from typing import Any

from .terminology import friendly_operator_text

TITLES = {
    "Configure probe controller": "Configure the probe VM",
    "Reach probe controller": "Connect to the probe VM",
    "TCP throughput": "Measure TCP throughput",
    "Latency under idle and loaded traffic": "Measure latency with and without traffic load",
    "UDP packet quality": "Measure UDP packet loss, jitter and packet rate",
    "Packet-size limits": "Measure path MTU and TCP MSS",
    "Forward and reverse balance": "Compare TCP, latency and UDP in both directions",
    "Concurrent TCP flow scaling": "Measure throughput with concurrent TCP connections",
    "Measurement repeatability": "Check whether repeated throughput measurements agree",
    "Project-network router-interface lifecycle": "Check connectivity when a router interface changes",
    "Sampled provider MTU boundary": "Test the provider-network MTU boundary",
    "Pre-migration functional baseline": "Verify connectivity before migration",
    "Move endpoint to intra-compute placement": "Migrate a VM onto the same host as its peer",
    "Create intra-compute placement": "Verify both test VMs are on the same host",
    "Verify port rebinding after migration": "Verify network ports bind to the destination host",
    "Restore endpoint networking": "Verify VM networking recovers after migration",
    "Measure endpoint traffic continuity during live migration": "Measure traffic interruption during live migration",
    "Router SNAT packet-size and fragmentation profile": "Test outbound MTU and fragmentation through router SNAT",
}


def title_for(row):
    title = row["title"]
    if title in TITLES:
        return TITLES[title]
    if title.startswith("Prove exact placement:"):
        return "Verify test VMs are on the requested hosts"
    protocol = title.rsplit(" · ", 1)[-1]
    operation = {
        "ICMP": "Ping",
        "TCP": "Test TCP connectivity",
        "UDP": "Test UDP connectivity",
    }.get(protocol)
    if operation and title.startswith("Provider connectivity · "):
        return operation + " between VMs on the same provider subnet"
    if operation and title.startswith("Project-network same-subnet connectivity · "):
        return operation + " between VMs on the same project subnet"
    if operation and title.startswith(
        "Routing between project networks through one router · "
    ):
        return operation + " between project networks through one router"
    if operation and title.startswith("Project/provider fixed-IP observation · "):
        return operation + " between project and provider fixed IPs"
    if operation and title.startswith("Separate provider network connectivity · "):
        return operation + " between separate provider networks"
    if operation and title.startswith("Floating IPv4 ingress for "):
        return {
            "ICMP": "Ping a VM through its floating IP",
            "TCP": "Test inbound TCP through a floating IP",
            "UDP": "Test inbound UDP through a floating IP",
        }[protocol]
    prefixes = {
        "Floating-IP outbound source-address verification through ": "Verify outbound traffic uses the floating IP",
        "Floating-IP outbound no-fragment path MTU through ": "Test outbound MTU through a floating IP",
        "Floating-IP outbound IPv4 fragmentation through ": "Test outbound IPv4 fragmentation through a floating IP",
        "Detach floating IPv4 address for ": "Check TCP access after detaching a floating IP",
        "Reassociate floating IPv4 address for ": "Check TCP access after reattaching a floating IP",
        "Sampled security-group deny test": "Verify the security group blocks TCP",
        "Sampled security-group allow test": "Verify the security group permits TCP",
        "Sampled security-group restore test": "Verify TCP after restoring the security group",
        "Sampled stop test VM and verify service loss": "Verify TCP service stops when the VM stops",
        "Sampled start test VM and verify service recovery": "Verify TCP service returns when the VM starts",
        "Two-router baseline without static routes": "Check connectivity before adding static routes (ICMP)",
        "Add router static routes": "Check connectivity after adding static routes (ICMP)",
        "Withdraw one router static route": "Check TCP connectivity after removing a static route",
        "Restore removed router static route": "Check TCP connectivity after restoring a static route",
    }
    for prefix, replacement in prefixes.items():
        if title.startswith(prefix):
            return replacement
    if operation and title.startswith("Two-router static-route connectivity · "):
        return operation + " through two routers with static routes"
    if title.startswith("Sampled external IPv4 reachability to "):
        target = title.split(" to ", 1)[1].split(" · ", 1)[0]
        return "Ping external IPv4 address " + target
    return title


TITLE_REPLACEMENTS = {
    "Provider subnet connectivity": "Provider connectivity",
    "Tenant same-network connectivity": "Project-network same-subnet connectivity",
    "Tenant-to-tenant routing through one router": "Routing between project networks",
    "Two-router extra-route connectivity": "Router-to-router static-route connectivity",
    "Tenant/provider fixed-IP connectivity": "Project/provider connectivity",
    "Representative provider MTU boundary": "Provider MTU boundary",
    "Representative guest oversized-packet rejection": "Oversized-packet rejection",
    "Path MTU, PMTUD, and TCP MSS": "Path packet-size and TCP segment limits",
    "Idle and loaded latency": "Idle and loaded latency",
    "UDP application-delivery loss, jitter, and packet rate": "UDP quality",
    "Concurrent-flow scaling": "Concurrent-flow scaling",
    "Path repeatability": "Path repeatability",
    "Directional asymmetry": "Directional balance",
    "Measure tenant traffic continuity during live migration": "Live-migration traffic continuity",
    "Verify fresh functional baseline before live migration submission 1/2": "Pre-migration functional baseline",
    "Verify fresh functional baseline before live migration submission 2/2": "Pre-migration functional baseline",
    "Live-migrate an endpoint into intra-compute placement": "Move endpoint to intra-compute placement",
    "Live-migrate an endpoint into inter-compute placement": "Move endpoint to inter-compute placement",
    "Create intra-compute placement using the configured migration strategy": "Create intra-compute placement",
    "Create inter-compute placement using the configured migration strategy": "Create inter-compute placement",
    "Verify Neutron port rebinding after intra-compute migration": "Verify port rebinding after migration",
    "Verify Neutron port rebinding after inter-compute migration": "Verify port rebinding after migration",
    "Restore endpoint networking after intra-compute migration": "Restore endpoint networking",
    "Restore endpoint networking after inter-compute migration": "Restore endpoint networking",
    "Representative stop test VM and verify service loss": "Stop/start service lifecycle",
    "Representative start test VM and verify service recovery": "Stop/start service lifecycle",
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


def test_name(result: dict[str, Any]) -> str:
    details = {
        **(result.get("reporting_context") or {}),
        **(result.get("details") or result.get("metadata") or {}),
    }
    operation = details.get("operation") or result.get("operation")
    transitions = details.get("transitions") or details.get("related_transitions") or []
    if (
        result.get("category") == "compute-placement"
        and transitions
        and all(
            isinstance(transition, dict)
            and transition.get("method") == "endpoint-recreation"
            for transition in transitions
        )
    ):
        return "Recreate one endpoint and verify its compute placement"
    operations = {
        "security-deny": "Verify TCP is blocked by the security group",
        "security-allow": "Verify TCP access after adding an allow rule",
        "security-restore": "Verify TCP is blocked after removing the allow rule",
        "server-stop": "Verify TCP service stops when the destination VM stops",
        "server-start": "Verify TCP service returns when the destination VM restarts",
        "static-route-baseline": "Verify ping is blocked before adding static routes",
        "static-route-install": "Verify connectivity after adding static routes",
        "static-route-withdraw": "Verify TCP is blocked after removing a static route",
        "static-route-restore": "Verify TCP returns after restoring the static route",
        "fip-withdraw": "Verify TCP is blocked after removing the floating IP",
        "fip-return": "Verify TCP returns after reattaching the floating IP",
        "controller-observation": "Configure the probe VM's network access",
        "controller-ssh": "Connect to the probe VM over SSH",
        "pair-transition": "Migrate one VM and verify its new host",
    }
    if operation in operations:
        return operations[operation]
    measurement = str(
        details.get("measurement") or details.get("performance_measurement") or ""
    )
    measurement = (
        "concurrent-path-load" if measurement == "fabric-scale" else measurement
    )
    if measurement in MEASUREMENT_TITLES:
        return title_for({"title": MEASUREMENT_TITLES[measurement]})
    display = str(result.get("display_name") or "Validation result")
    base = re.split(r"\s+—\s+", display, maxsplit=1)[0].strip()
    base = re.sub(r"\s+\[[^\]]+\]\s*$", "", base).strip()
    if base.startswith("Verify fresh functional baseline before"):
        return "Verify connectivity immediately before migration"
    if base.startswith("Move one endpoint and verify"):
        return "Migrate one VM and verify its new host"
    if base.startswith("Own floating-IP hairpin"):
        return "Test a VM's access to its own floating IP"
    if base.startswith("VM with floating IP to peer floating IP"):
        return "Test access from a VM with a floating IP to a peer's floating IP"
    if base.startswith("Private fixed IP without floating IP to floating IP"):
        return "Test access from a VM without a floating IP to a peer's floating IP"
    translated = friendly_operator_text(base)
    translated = translated[:1].upper() + translated[1:]
    direct = title_for({"title": translated})
    if direct != translated:
        return direct
    for old, new in TITLE_REPLACEMENTS.items():
        if base.startswith(old):
            base = new
            break
    protocol = str(details.get("protocol") or result.get("protocol") or "").upper()
    if protocol not in {"ICMP", "TCP", "UDP"}:
        match = re.search(r"\b(ICMP|TCP|UDP)\b", display, re.I)
        protocol = match.group(1).upper() if match else ""
    if protocol and not re.search(rf"\b{protocol}\b", base, re.I):
        base += " · " + protocol
    return title_for({"title": friendly_operator_text(base)})
