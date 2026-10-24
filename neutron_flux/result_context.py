"""Evidence-backed context shared by the console and generated reports.

The planner's ``phase`` is a grouping key, not an execution time or a compute
placement.  This module deliberately keeps those three concepts separate.
It only reads records; it never changes a verdict or signed path identity.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

ACTION_LABELS = {
    "security-deny": "Without a TCP allow rule",
    "security-allow": "After adding a temporary TCP allow rule",
    "security-restore": "After removing the temporary TCP allow rule",
    "server-stop": "After stopping the destination VM",
    "server-start": "After restarting the destination VM",
    "static-route-baseline": "Before adding static routes",
    "static-route-install": "After adding static routes between the routers",
    "static-route-withdraw": "After removing one router's static route",
    "static-route-restore": "After restoring the removed static route",
    "fip-withdraw": "After removing the destination VM's floating IP",
    "fip-return": "After reattaching the destination VM's floating IP",
    "router-interface-remove": "After removing the destination router interface",
    "router-interface-restore": "After restoring the destination router interface",
}

PURPOSES = {
    "security-deny": "Check that TCP is blocked while the security group has no matching allow rule.",
    "security-allow": "Check that adding a TCP allow rule makes the same service reachable.",
    "security-restore": "Check that removing the temporary allow rule blocks TCP again.",
    "server-stop": "Check that the destination service becomes unreachable when its VM is stopped.",
    "server-start": "Check that the destination service becomes reachable when its VM restarts.",
    "static-route-baseline": "Check that ping receives no reply before the routers have the required static routes.",
    "static-route-install": "Check that adding static routes makes the private networks communicate through both routers.",
    "static-route-withdraw": "Check that removing a required static route interrupts the connection.",
    "static-route-restore": "Check that restoring the removed static route restores the connection.",
    "fip-withdraw": "Check that removing a floating IP prevents access through that address.",
    "fip-return": "Check that reattaching the floating IP restores access to the same VM.",
    "controller-observation": "Check that the probe VM has usable networking before any network tests start.",
    "controller-ssh": "Check that the runner can connect to the probe VM over SSH.",
}

MEASUREMENT_PURPOSES = {
    "tcp-throughput": "Measure how much TCP data the path carries per second.",
    "latency": "Measure round-trip delay while the path is idle and while it carries traffic.",
    "udp": "Measure how many UDP packets arrive, their jitter and packet rate.",
    "mtu-mss": "Measure the largest packets the path carries and the TCP segment sizes negotiated by the VMs.",
    "concurrency": "Measure how throughput changes when several TCP connections share the path.",
    "repeatability": "Check whether repeated throughput measurements on the same path agree.",
    "asymmetry": "Compare throughput, latency and UDP delivery in both directions.",
    "concurrent-path-load": "Measure several VM-to-VM paths while they carry traffic together.",
    "fabric-scale": "Measure several VM-to-VM paths while they carry traffic together.",
}


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> str:
    return str(value or "").strip()


def recorded_execution_stage(metadata: dict[str, Any]) -> str | None:
    """Read execution order from structured workflow facts, never host names."""
    if metadata.get("pre_migration_functional_barrier"):
        return "pre-migration"
    stage = _text(metadata.get("execution_stage"))
    if stage:
        return stage
    if metadata.get("pair_placement_policy") == "initial-opposite-v1":
        placement = metadata.get("pair_placement")
        if placement == "self":
            placement = _mapping(metadata.get("topology_placement_context")).get(
                "pair_placement"
            )
        if placement == "initial":
            return "pre-migration"
        if placement == "opposite" and (
            metadata.get("placement_origin") == "after-transition"
            or metadata.get("confirmed_pair_transition") is True
        ):
            method = metadata.get("placement_transition_method")
            return (
                "post-endpoint-recreation"
                if method == "endpoint-recreation"
                else "post-migration"
                if method == "migration"
                else "post-placement-transition"
            )
    if _mapping(_mapping(metadata.get("check_bindings")).get("placement")).get(
        "MIGRATION"
    ):
        return "pre-migration"
    return None


def normalize_topology_label(value: Any) -> str:
    """Clarify a historical synthetic IPv6 label without changing its identity."""
    return _text(value).replace(
        "IPv6 project-network connectivity with routing metadata unassigned through ",
        "Private IPv6 same-subnet connectivity; external routing not tested "
        "— selected external network ",
    )


def _ip(value: Any) -> str | None:
    text = _text(value)
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return None
    return text


def _parts(result: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    details = dict(_mapping(result.get("reporting_context")))
    details.update(_mapping(result.get("details") or result.get("metadata")))
    if not details.get("transitions") and details.get("related_transitions"):
        details["transitions"] = details["related_transitions"]
    if (
        result.get("category") == "compute-placement"
        and not details.get("transitions")
        and details.get("source_host")
        and details.get("destination_host")
        and details.get("server_id")
    ):
        details["transitions"] = [
            {
                key: details[key]
                for key in ("server_id", "source_host", "destination_host", "confirmed")
                if key in details
            }
        ]
    topology = _mapping(details.get("topology_placement_context"))
    if details.get("pair_placement") == "self" and topology.get("pair_placement"):
        details["pair_placement"] = topology["pair_placement"]
    return details, _mapping(details.get("path"))


def _label(raw: Any, side: Any, role: str) -> tuple[str, str | None, str | None]:
    text = normalize_topology_label(raw)
    address_match = re.search(r"\s*\(([^()]+)\)\s*$", text)
    address = _ip(address_match.group(1)) if address_match else _ip(text)
    if address_match:
        text = text[: address_match.start()].strip()
    text = re.sub(r"\s*\[[^\]]+\]", "", text)
    side_match = re.search(r":([AB])$", text)
    side = _text(side or (side_match.group(1) if side_match else ""))
    if side_match:
        text = text[: side_match.start()]
    suffix = f" {side}" if side in {"A", "B"} else ""
    if text.startswith("Provider "):
        network = text.removeprefix("Provider ").strip()
        return f"{network or 'Provider'} VM{suffix}", network or None, address
    if re.search(r"(?:private|tenant|project|router)", text, re.I):
        network_match = re.search(r"(?:through|from)\s+(.+)$", text, re.I)
        private_network = network_match.group(1) if network_match else None
        label = f"Private VM{suffix}"
        if "second router" in text:
            label += " behind the second router"
        if "source without floating IP" in text:
            label += " without a floating IP"
        return label, private_network, address
    if text in {"Flux runner", "runner"}:
        return "Flux runner", None, address
    if address:
        return f"{role.title()} endpoint", None, address
    # Cloud object UUIDs and planner codes belong in technical evidence.
    if not text or re.fullmatch(r"[A-Z0-9_-]{10,}|[0-9a-f-]{32,}", text):
        return f"{role.title()} VM{suffix}", None, address
    return text, None, address


def _endpoint(
    result: dict[str, Any], details: dict[str, Any], path: dict[str, Any], role: str
) -> dict[str, Any]:
    address = _mapping(_mapping(details.get("address_path")).get(role))
    raw = path.get(f"{role}_label") or result.get(role)
    label, network, displayed_ip = _label(
        raw,
        path.get(f"{role}_endpoint_side") or details.get(f"{role}_side"),
        role,
    )
    probe = address.get("probe_address") or path.get(f"{role}_ip") or displayed_ip
    fixed = address.get("fixed_ip")
    floating = address.get("floating_ip")
    # A displayed fixed address is usable evidence for a plain fixed-IP path.
    # A displayed floating address must never be relabelled as a fixed address.
    floating_path = path.get("path_kind") == "floating-ip" or result.get(
        "category"
    ) in {"floating-ip", "floating-ip-lifecycle", "floating-ip-peer"}
    if not fixed and not floating_path:
        fixed = displayed_ip or path.get(f"{role}_ip")
    host = path.get(f"{role}_compute_host") or details.get(f"{role}_compute_host")
    zone = path.get(f"{role}_availability_zone") or details.get(
        f"{role}_availability_zone"
    )
    external = role == "destination" and (
        details.get("operation") == "egress" or result.get("category") == "egress"
    )
    if external:
        # Older placement readbacks copied their peer VM's metadata into an
        # Internet destination. Keep the observed target, discard that context.
        label, network, fixed, floating, host, zone = (
            "External destination",
            None,
            None,
            None,
            None,
            None,
        )
    actual_network = address.get("network_name") or details.get(f"{role}_network_name")
    external_network = (
        network.split(" / ", 1)[0]
        if network and label.startswith("Private VM") and "through " in _text(raw)
        else None
    )
    if label.startswith("Private VM") and actual_network == external_network:
        actual_network = None
    return {
        "label": label,
        "network": None
        if external
        else actual_network
        or (network if _text(raw).startswith("Provider ") else None),
        "external_network": external_network,
        "fixed_ip": fixed,
        "floating_ip": floating,
        "floating_ip_status": None if external else address.get("floating_ip_status"),
        "probe_address": probe,
        "compute_host": host,
        "availability_zone": zone,
    }


def _execution_state(result: dict[str, Any]) -> str:
    details, _ = _parts(result)
    if details.get("cloud_operation_outcome") == "NOT_SUBMITTED":
        return "Migration not submitted"
    status = _text(result.get("status"))
    state = _text(
        _mapping(_mapping(result.get("contract")).get("execution")).get("state")
    )
    if status.startswith(("BLOCKED", "NOT_RUN")) or state in {
        "blocked",
        "not-run",
        "cancelled",
    }:
        return "Did not run"
    if status in {"SKIP", "NOT_APPLICABLE"}:
        return "Not applicable" if status == "NOT_APPLICABLE" else "Skipped"
    if not status:
        return "Planned"
    return "Executed"


def _timing(
    result: dict[str, Any], details: dict[str, Any], path: dict[str, Any]
) -> str:
    if result.get("category") == "controller-bootstrap":
        return "Controller setup"
    if details.get("cloud_operation_outcome") == "NOT_SUBMITTED":
        return "Before migration"
    execution_stage = _text(details.get("execution_stage"))
    stage_labels = {
        "initial-testing": "Initial testing",
        "pre-migration": "Before migration",
        "post-migration": "After migration",
        "post-live-migration": "After migration",
        "post-cold-migration": "After migration",
        "post-placement-transition": "After placement transition",
        "pre-endpoint-recreation": "Before endpoint recreation",
        "post-endpoint-recreation": "After endpoint recreation",
        "during-endpoint-recreation": "During endpoint recreation",
        "during-migration": "During migration",
        "placement-discovery": "Initial placement discovery",
    }
    if execution_stage in stage_labels:
        return stage_labels[execution_stage]
    if _recreated_placement(details):
        if result.get("category") == "compute-placement":
            return "During endpoint recreation"
        if details.get("pair_placement") == "initial":
            return "Before endpoint recreation"
        if details.get("pair_placement") == "opposite":
            return "After endpoint recreation"
    stage = _text(path.get("stage") or details.get("stage"))
    display = _text(result.get("display_name")).lower()
    if stage in {"pre-migration", "pre-live-migration"} or re.search(
        r"before (?:live |cold )?migration|pre-migration", display
    ):
        return "Before migration"
    if stage in {"post-migration", "post-live-migration", "post-cold-migration"}:
        return "After migration"
    if details.get("continuity") or details.get("continuity_assessment"):
        return "During migration"
    if result.get("category") == "compute-placement" and (
        details.get("transitions")
        or (details.get("source_host") and details.get("destination_host"))
        or _mapping(details.get("details")).get("continuity")
        or "migrat" in display
        or "move one endpoint" in display
    ):
        return "During migration"
    if _execution_state(result) != "Executed":
        if details.get("pair_placement") == "initial":
            return "Planned before migration"
        if details.get("pair_placement") == "opposite":
            return "Planned after migration"
    if details.get("pair_placement_policy") == "initial-opposite-v1":
        if details.get("pair_placement") == "initial":
            return "Before migration"
        if details.get("pair_placement") == "opposite" and (
            details.get("placement_origin") == "after-transition"
            or details.get("confirmed_pair_transition") is True
        ):
            return (
                "After migration"
                if details.get("placement_transition_method") == "migration"
                else "After placement transition"
            )
    return "Migration timing not recorded"


def _recreated_placement(details: dict[str, Any]) -> bool:
    if details.get("placement_transition_method") == "endpoint-recreation":
        return True
    transitions = details.get("transitions") or []
    return bool(transitions) and all(
        isinstance(transition, dict)
        and transition.get("method") == "endpoint-recreation"
        for transition in transitions
    )


def _action(result: dict[str, Any], details: dict[str, Any]) -> str | None:
    operation = _text(details.get("operation") or result.get("operation"))
    if operation in {"static-route-withdraw", "static-route-restore"} and details.get(
        "route_side"
    ):
        side = details["route_side"]
        role = (
            "source"
            if side == details.get("source_side")
            else "destination"
            if side == details.get("destination_side")
            else None
        )
        if role:
            action = "removing" if operation == "static-route-withdraw" else "restoring"
            return f"After {action} the static route on the {role} network's router"
    if operation in ACTION_LABELS:
        return ACTION_LABELS[operation]
    if result.get("category") == "router-interface-lifecycle":
        return "Remove and restore the destination router interface"
    if result.get("category") == "compute-placement" and details.get("transitions"):
        moves = [
            transition
            for transition in details["transitions"]
            if isinstance(transition, dict)
            and transition.get("source_host")
            and transition.get("destination_host")
        ]
        if len(moves) == 1:
            label = _moving_label(details, moves[0])
            if _recreated_placement(details):
                return f"Recreate one endpoint from placement on {moves[0]['source_host']} on {moves[0]['destination_host']}"
            return f"Move {label} from {moves[0]['source_host']} to {moves[0]['destination_host']}"
        return "Move one VM and verify its new compute host"
    return None


def _moving_label(details: dict[str, Any], transition: dict[str, Any]) -> str:
    for endpoint in details.get("moving_endpoints") or []:
        if endpoint.get("server_id") == transition.get("server_id"):
            return _label(endpoint.get("label"), endpoint.get("side"), "moving")[0]
    return "one VM"


def _path(
    result: dict[str, Any],
    details: dict[str, Any],
    path: dict[str, Any],
    source: dict[str, Any],
    destination: dict[str, Any],
) -> str:
    category = _text(path.get("source_category") or result.get("category"))
    kind = _text(path.get("path_kind") or details.get("path_kind"))
    nat = _text(details.get("nat_path"))
    if result.get("category") == "controller-bootstrap":
        return (
            "Flux runner → probe VM over SSH"
            if result.get("destination")
            else "Probe VM network setup"
        )
    if result.get("category") == "compute-placement":
        if _recreated_placement(details):
            return "Endpoint recreation for opposite compute placement"
        return (
            "Compute host migration"
            if details.get("transitions")
            else "VM networking around migration"
        )
    if category == "egress":
        destination["label"] = "External target"
        destination["fixed_ip"] = None
        return "VM → external IP address"
    if nat == "self-hairpin" or details.get("packet_path_placement") == "self":
        return "Private VM → its own floating IP → the same VM"
    if nat == "snat-to-floating-ip":
        return "Private VM without a floating IP → router source NAT → another VM's floating IP"
    if nat in {"same-router", "different-routers"}:
        router = "one router" if nat == "same-router" else "two different routers"
        return f"Private VM with a floating IP → peer VM's floating IP through {router}"
    if (
        category == "source-nat-connectivity"
        or "source-nat" in kind
        or details.get("egress_translation_mode") == "router-source-nat"
    ):
        return "Private fixed IP → router source NAT → public VM's fixed IP"
    if (
        kind == "floating-ip-to-provider-observer"
        or details.get("egress_translation_mode") == "floating-ip-egress"
    ):
        return (
            "Private fixed IP → outbound floating-IP translation → public VM's fixed IP"
        )
    if kind == "floating-ip" or category in {"floating-ip", "floating-ip-lifecycle"}:
        return "Public VM's fixed IP → floating IP → private VM's fixed IP"
    if category in {"router-static-routing", "router-extra-route"}:
        return "Private fixed IP → first router → second router → private fixed IP"
    if category in {
        "project-network-routing",
        "tenant-routing",
        "router-interface-lifecycle",
    }:
        return "Private fixed IP → one router → another private subnet's fixed IP"
    if category == "same-subnet":
        return "Fixed IP → fixed IP on the same subnet"
    if source.get("probe_address") or destination.get("probe_address"):
        return f"{source['label']} → {destination['label']}"
    return "Network path was not recorded"


def _placement(
    result: dict[str, Any],
    details: dict[str, Any],
    source: dict[str, Any],
    destination: dict[str, Any],
) -> str:
    if result.get("category") == "controller-bootstrap":
        return "Probe VM; compute placement is not part of this setup check"
    self_path = (
        details.get("packet_path_placement") == "self"
        or details.get("nat_path") == "self-hairpin"
    )
    src, dst = source.get("compute_host"), destination.get("compute_host")
    if self_path:
        return (
            f"One VM on {src or dst}"
            if src or dst
            else "One VM; compute host was not recorded"
        )
    if result.get("category") == "egress":
        return (
            f"Source VM on {src}; external destination has no Flux compute host"
            if src
            else "Source compute host was not recorded; destination is external"
        )
    if src and dst:
        if src == dst:
            return f"Both VMs on {src} (same compute host)"
        return f"Source VM on {src}; destination VM on {dst} (different compute hosts)"
    if src or dst:
        role, host = ("Source", src) if src else ("Destination", dst)
        return f"{role} VM on {host}; the other compute host was not recorded"
    return "Compute hosts were not recorded"


def _supporting_placement(details: dict[str, Any]) -> str | None:
    hosts: set[str] = set()
    relations: set[str] = set()
    external_targets = False
    rows = details.get("supporting_paths") or []
    if not rows:
        return None
    for row in rows:
        evidence, path = _parts(row)
        source = _endpoint(row, evidence, path, "source")["compute_host"]
        destination = _endpoint(row, evidence, path, "destination")["compute_host"]
        if row.get("category") == "egress" and source:
            hosts.add(str(source))
            external_targets = True
            continue
        if not source or not destination:
            return None
        hosts.update((str(source), str(destination)))
        relations.add("same" if source == destination else "different")
    if not relations:
        return f"Checked source VMs on {' and '.join(sorted(hosts))}; external destinations have no Flux compute host"
    relation = (
        "same compute host"
        if relations == {"same"}
        else "different compute hosts"
        if relations == {"different"}
        else "same-host and different-host paths"
    )
    return f"Checked VMs on {' and '.join(sorted(hosts))} ({relation})" + (
        "; external destinations have no Flux compute host" if external_targets else ""
    )


def _endpoint_line(role: str, endpoint: dict[str, Any], state: str) -> str:
    parts = [endpoint["label"]]
    fixed, floating, probe = (
        endpoint.get(key) for key in ("fixed_ip", "floating_ip", "probe_address")
    )
    if fixed:
        label = (
            "previous fixed-IP mapping"
            if "detached" in _text(endpoint.get("floating_ip_status"))
            else "fixed IP"
        )
        parts.append(f"{label} {fixed}")
    if floating:
        attached = endpoint.get("floating_ip_status")
        parts.append(f"floating IP {floating}" + (f" ({attached})" if attached else ""))
    if probe:
        word = "planned test address" if state != "Executed" else "address used in test"
        parts.append(f"{word} {probe}")
    if endpoint.get("network"):
        parts.append(f"network {endpoint['network']}")
    if endpoint.get("external_network"):
        parts.append(f"router's external network {endpoint['external_network']}")
    if endpoint.get("availability_zone"):
        parts.append(f"availability zone {endpoint['availability_zone']}")
    return f"{role}: " + "; ".join(parts)


def result_context(result: dict[str, Any]) -> dict[str, Any]:
    """Describe one check using recorded endpoints, actions and execution context."""
    from .test_titles import test_name

    details, path = _parts(result)
    source = _endpoint(result, details, path, "source")
    destination = _endpoint(result, details, path, "destination")
    monitored = _mapping(details.get("monitored_path"))
    monitor_details, monitor_path = _parts(monitored)
    if monitored:
        source = _endpoint(monitored, monitor_details, monitor_path, "source")
        destination = _endpoint(monitored, monitor_details, monitor_path, "destination")
    addresses = _mapping(
        (monitor_details if monitored else details).get("address_path")
    )
    source_id = _mapping(addresses.get("source")).get("server_id")
    destination_id = _mapping(addresses.get("destination")).get("server_id")
    if (
        source["label"] == destination["label"]
        and source_id
        and destination_id
        and source_id != destination_id
    ):
        source["label"] = "Source " + source["label"].lower()
        destination["label"] = "Destination " + destination["label"].lower()
    if result.get("category") == "controller-bootstrap":
        source["label"] = "Flux runner" if result.get("destination") else "Probe VM"
        destination["label"] = (
            "Probe VM" if result.get("destination") else "Not applicable"
        )
    state = _execution_state(result)
    timing = _timing(result, details, path)
    action = _action(result, details)
    operation = _text(details.get("operation") or result.get("operation"))
    measurement = _text(
        details.get("measurement") or details.get("performance_measurement")
    )
    purpose = PURPOSES.get(operation) or MEASUREMENT_PURPOSES.get(measurement)
    if not purpose:
        if result.get("category") == "router-interface-lifecycle":
            purpose = "Check that routed TCP is reachable, becomes blocked when the router interface is removed, and returns after the interface is restored."
        elif result.get("category") == "compute-placement":
            purpose = (
                "Verify the recreated endpoint reaches the required compute host before network checks continue."
                if _recreated_placement(details)
                else "Recheck the selected VM-to-VM protocols and applicable external egress paths immediately before submitting the VM migration."
                if timing == "Before migration"
                else "Check migration completion, the VM's actual compute host and network recovery."
            )
        elif result.get("category") == "source-nat-packet-size":
            purpose = "Measure the outbound path's packet-size limit and delivery with IPv4 fragmentation through router source NAT."
        elif result.get("category") == "floating-ip-egress-source-address":
            purpose = "Check that the public destination sees the private VM's floating IP as the source of an outbound TCP connection."
        elif result.get("category") == "floating-ip-egress-mtu":
            purpose = "Measure the largest outbound IPv4 packet delivered through floating-IP translation without fragmentation."
        elif result.get("category") == "floating-ip-egress-fragmentation":
            purpose = "Check whether an oversized outbound IPv4 packet arrives when fragmentation is permitted through floating-IP translation."
        elif result.get("category") == "mtu":
            purpose = "Check delivery at the advertised packet size and record how oversized packets are handled."
        else:
            expected = _text(result.get("expected") or result.get("expectation"))
            purpose = (
                "Check that the selected network path blocks traffic as configured."
                if expected in {"blocked", "withdrawn", "isolated", "rejected"}
                else "Check that traffic reaches the selected destination through this network path."
            )
    network_path = _path(result, details, path, source, destination)
    if monitored:
        network_path = _path(
            monitored, monitor_details, monitor_path, source, destination
        )
    placement = _placement(result, details, source, destination)
    protocol = _text(details.get("protocol") or result.get("protocol")).upper()
    if protocol not in {"ICMP", "TCP", "UDP", "SSH"}:
        protocol = ""
    if not protocol:
        protocol = {
            "tcp-throughput": "TCP",
            "udp": "UDP",
            "concurrency": "TCP",
            "repeatability": "TCP",
            "latency": "ICMP and TCP",
            "mtu-mss": "ICMP and TCP",
            "asymmetry": "ICMP, TCP and UDP",
        }.get(measurement, "")
    if result.get("category") in {"mtu", "source-nat-packet-size"} and not protocol:
        protocol = "ICMP" if result.get("category") == "mtu" else "ICMP and TCP"
    if not protocol:
        protocol = {
            "router-interface-lifecycle": "TCP",
            "floating-ip-egress-source-address": "TCP",
            "floating-ip-egress-mtu": "ICMP",
            "floating-ip-egress-fragmentation": "ICMP",
        }.get(_text(result.get("category")), "")
    if result.get("category") == "controller-bootstrap" and result.get("destination"):
        protocol = "SSH"
    if monitored:
        protocol = "ICMP, TCP and UDP"
    if not protocol and details.get("protocols"):
        protocols = [
            str(value).upper()
            for value in details["protocols"]
            if str(value).upper() in {"ICMP", "TCP", "UDP"}
        ]
        if protocols:
            protocol = (
                ", ".join(protocols[:-1]) + " and " + protocols[-1]
                if len(protocols) > 1
                else protocols[0]
            )
    family = (
        path.get("family")
        or result.get("family")
        or details.get("family")
        or monitored.get("family")
    )
    family_label = (
        f"IPv{family}" if family in {4, 6, "4", "6"} else "IP family was not recorded"
    )
    support_families = sorted(
        {
            int(row["family"])
            for row in details.get("supporting_paths") or []
            if isinstance(row, dict) and row.get("family") in {4, 6}
        }
    )
    if family_label == "IP family was not recorded" and support_families:
        family_label = " and ".join(f"IPv{value}" for value in support_families)
    lines = [f"Purpose: {purpose}", f"Path: {network_path}"]
    moves = []
    after_placement = None
    if result.get("category") == "compute-placement":
        transitions = details.get("transitions") or []
        for transition in transitions:
            if (
                isinstance(transition, dict)
                and transition.get("source_host")
                and transition.get("destination_host")
            ):
                confirmation = (
                    "confirmed"
                    if transition.get("confirmed") is True
                    else "completion confirmation not recorded"
                )
                label = _moving_label(details, transition)
                if transition.get("method") == "endpoint-recreation":
                    lines.append(
                        f"Endpoint recreation: placement on {transition['source_host']} → placement on {transition['destination_host']}; an existing VM was not migrated."
                    )
                else:
                    lines.append(
                        f"VM move: {label}, {transition['source_host']} → {transition['destination_host']} ({confirmation})"
                    )
                moves.append(
                    {
                        "label": label,
                        "source_host": transition["source_host"],
                        "destination_host": transition["destination_host"],
                        "confirmed": transition.get("confirmed") is True,
                    }
                )
        if (
            not transitions
            and timing in {"During migration", "Before migration"}
            and result.get("source")
            and result.get("destination")
        ):
            lines.append(
                f"Intended VM move: {result['source']} → {result['destination']}; request not submitted"
                if state == "Migration not submitted"
                else f"VM move: {result['source']} → {result['destination']}"
            )
        supporting_lines = []
        for supporting in details.get("supporting_paths") or []:
            if not isinstance(supporting, dict):
                continue
            support_details, support_path = _parts(supporting)
            src = _endpoint(supporting, support_details, support_path, "source")
            dst = _endpoint(supporting, support_details, support_path, "destination")
            text = f"{src['label']} {src.get('probe_address') or 'address not recorded'} on {src.get('compute_host') or 'host not recorded'} → {dst['label']} {dst.get('probe_address') or 'address not recorded'} on {dst.get('compute_host') or 'host not recorded'}"
            if text not in supporting_lines:
                supporting_lines.append(text)
        lines.extend(f"Checked path: {line}" for line in supporting_lines)
        if not monitored and supporting_lines:
            supported_placement = _supporting_placement(details)
            if supported_placement:
                placement = supported_placement
                lines.append(f"VM placement before the move: {placement}")
        if monitored:
            lines.extend(
                [
                    _endpoint_line("Traffic source", source, state),
                    _endpoint_line("Traffic destination", destination, state),
                ]
            )
            observer_id = (
                _mapping(monitor_details.get("address_path"))
                .get("source", {})
                .get("server_id")
            )
            moving_ids = {
                transition.get("server_id")
                for transition in transitions
                if isinstance(transition, dict) and transition.get("server_id")
            }
            target_id = _mapping(
                _mapping(monitor_details.get("address_path")).get("destination")
            ).get("server_id")
            role = (
                "traffic source"
                if observer_id and observer_id in moving_ids
                else "traffic destination"
                if target_id and target_id in moving_ids
                else None
            )
            lines.append(
                f"Moving VM's role in this traffic test: {role or 'not recorded'}"
            )
            lines.append(f"VM placement before the move: {placement}")
            confirmed = [
                transition
                for transition in transitions
                if isinstance(transition, dict) and transition.get("confirmed") is True
            ]
            if len(confirmed) == 1 and role:
                after_source, after_destination = dict(source), dict(destination)
                if role == "traffic source":
                    after_source["compute_host"] = confirmed[0].get("destination_host")
                else:
                    after_destination["compute_host"] = confirmed[0].get(
                        "destination_host"
                    )
                after_placement = _placement(
                    monitored, monitor_details, after_source, after_destination
                )
                lines.append(f"VM placement after the move: {after_placement}")
                stationary = destination if role == "traffic source" else source
                if stationary.get("compute_host"):
                    lines.append(
                        f"Stationary peer's recorded compute host: {stationary['label']} on {stationary['compute_host']}"
                    )
            placement = "Before move: " + placement
            if after_placement:
                placement += "; after move: " + after_placement
    elif result.get("category") == "controller-bootstrap":
        if result.get("destination"):
            lines.append(
                f"Runner access: SSH to probe VM address {result['destination']}"
            )
        else:
            for port in details.get("ports") or []:
                if isinstance(port, dict):
                    configured_ips = ", ".join(
                        str(value) for value in (port.get("fixed_ips") or {}).values()
                    )
                    if configured_ips:
                        lines.append(
                            f"Probe VM: fixed IP {configured_ips}; provider network {port.get('network_name') or 'not recorded'}"
                        )
    else:
        lines.extend(
            [
                _endpoint_line("Source", source, state),
                _endpoint_line("Destination", destination, state),
            ]
        )
        self_transition = _mapping(details.get("topology_endpoint_transition"))
        if self_transition and self_transition.get("confirmed") is True:
            role = self_transition.get("role")
            origin, target = (
                self_transition.get("source_host"),
                self_transition.get("destination_host"),
            )
            if origin and target and role in {"moving", "stationary"}:
                owner = (
                    "self-hairpin VM"
                    if details.get("nat_path") == "self-hairpin"
                    or details.get("packet_path_placement") == "self"
                    else "source VM"
                )
                peer = (
                    _label(self_transition.get("moving_label"), None, "moving")[0]
                    if self_transition.get("moving_label")
                    else "peer VM"
                )
                if role == "stationary":
                    scope = (
                        f"{peer} moved from {origin} to {target}; this {owner} stayed on {source.get('compute_host') or destination.get('compute_host') or 'its recorded host'}."
                        if timing == "After migration"
                        else f"The topology's migration moves {peer} from {origin} to {target}; this {owner} is stationary."
                    )
                else:
                    scope = (
                        f"This {owner} moved from {origin} to {target}."
                        if timing == "After migration"
                        else f"The topology's migration moves this {owner} from {origin} to {target}."
                    )
                lines.append(f"Migration scope: {scope}")
    port = _mapping(_mapping(details.get("probe")).get("diagnostics")).get(
        "destination_port"
    )
    if protocol:
        traffic = "ICMP (ping)" if protocol == "ICMP" else protocol
        if port and protocol in {"TCP", "UDP"}:
            traffic += f" port {port}"
        lines.append(f"Traffic: {traffic} over {family_label}")
    elif family in {4, 6, "4", "6"}:
        lines.append(f"Address family: {family_label}")
    when = timing if state == "Executed" else f"{timing}; {state.lower()}"
    lines.append(f"When: {when}")
    if action:
        lines.append(
            f"Condition: {action}"
            if state == "Executed"
            else f"Planned condition: {action}"
        )
    if result.get("category") != "compute-placement":
        lines.append(f"VM placement: {placement}")
    observed_source = _mapping(details.get("address_path")).get(
        "observed_source_ip"
    ) or details.get("translated_source_ip_observed_by_provider")
    if observed_source and state == "Executed":
        lines.append(f"Source address seen by the destination: {observed_source}")
    return {
        "test": test_name(result),
        "purpose": purpose,
        "path": network_path,
        "source": source,
        "destination": destination,
        "protocol": protocol,
        "family": family_label,
        "placement": placement,
        "after_placement": after_placement,
        "timing": timing,
        "action": action,
        "execution_state": state,
        "lines": lines,
        "moves": moves,
    }


def context_lines(result: dict[str, Any]) -> list[str]:
    """Return the same readable context for console, text and HTML renderers."""
    return result_context(result)["lines"]
