"""Ordered manual recipes, distinct from immutable historical command evidence.

The recipes operate on operator-supplied, current disposable resources. They do
not infer a topology, substitute addresses into saved programs, or execute APIs.
"""

from __future__ import annotations

import ipaddress
import re
from types import SimpleNamespace
from typing import Any

from .manual_recipe_operations import (
    _lifecycle_recipe,
    _performance_recipe,
    _placement_recipe,
    _static_route_recipe,
    _traffic_recipe,
)


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _address(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.rsplit("(", 1)[-1].removesuffix(")").strip()
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def _probe(details: dict[str, Any]) -> dict[str, Any]:
    for key in ("probe", "translation_baseline"):
        value = _mapping(details.get(key))
        if value:
            return value
    stages = _mapping(details.get("stages"))
    for key in ("baseline", "valid_boundary", "restored_connectivity"):
        value = _mapping(stages.get(key))
        if value:
            return _mapping(value.get("probe")) or value
    return {}


def _endpoint(
    result: dict[str, Any], details: dict[str, Any], side: str
) -> dict[str, Any]:
    addressing = _mapping(_mapping(details.get("address_path")).get(side))
    diagnostic = _mapping(_probe(details).get("diagnostics"))
    fip = _mapping(diagnostic.get(f"{side}_floating_ip"))
    path = _mapping(details.get("path"))
    fixed = (
        addressing.get("fixed_ip") or fip.get("fixed_ip") or path.get(f"{side}_bind_ip")
    )
    target = (
        addressing.get("probe_address")
        or path.get(f"{side}_ip")
        or details.get(f"{side}_ip")
        or _address(result.get(side))
    )
    if side == "source":
        fixed = fixed or _mapping(diagnostic.get("data_path_verification")).get(
            "source_ip"
        )
    if side == "destination":
        fixed = fixed or diagnostic.get("expected_destination_fixed_ip")
    return {
        "label": result.get(side) or path.get(f"{side}_label"),
        "ip": target,
        "fixed_ip": fixed or target,
        "floating_ip": addressing.get("floating_ip") or fip.get("address"),
        "floating_ip_id": addressing.get("floating_ip_id") or fip.get("id"),
        "server_id": addressing.get("server_id")
        or details.get(f"{side}_server_id")
        or path.get(f"{side}_server_id")
        or fip.get("server_id"),
        "port_id": addressing.get("port_id") or fip.get("port_id"),
        "host": details.get(f"{side}_compute_host") or path.get(f"{side}_compute_host"),
        "zone": details.get(f"{side}_availability_zone")
        or path.get(f"{side}_availability_zone"),
        "data_mac": path.get(f"{side}_test_mac") or path.get(f"{side}_data_mac"),
    }


def _recipe_family(
    result: dict[str, Any],
    details: dict[str, Any],
    continuity: dict[str, Any],
    source: dict[str, Any],
    destination: dict[str, Any],
) -> tuple[int | None, str | None]:
    """Use agreeing recorded families and recovered addresses, never a default."""
    families: set[int] = set()
    declarations = (
        result.get("family"),
        details.get("family"),
        _mapping(details.get("path")).get("family"),
        continuity.get("family"),
    )
    for value in declarations:
        if value in (None, ""):
            continue
        if isinstance(value, bool) or str(value) not in {"4", "6"}:
            return (
                None,
                "The recorded IP family is invalid. Confirm the intended family and endpoint addresses before reproducing this check.",
            )
        families.add(int(value))
    for endpoint in (source, destination):
        for key in ("ip", "fixed_ip"):
            value = endpoint.get(key)
            if not value:
                continue
            try:
                families.add(ipaddress.ip_address(value).version)
            except ValueError:
                return (
                    None,
                    "A recorded endpoint address is invalid. Confirm the intended family and endpoint addresses before reproducing this check.",
                )
    if len(families) > 1:
        return (
            None,
            "The recorded IP family and endpoint addresses disagree. Confirm one consistent address family before reproducing this check.",
        )
    if not families:
        return (
            None,
            "No IP family or usable endpoint addresses were recorded. Confirm the intended family and endpoint addresses before reproducing traffic.",
        )
    return next(iter(families)), None


def build_recipe(
    result: dict[str, Any], context: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Return current-input commands and explicit roles; never a historical replay."""
    details = _mapping(result.get("details"))
    context = context or {}
    configuration = _mapping(context.get("configuration"))
    category = str(details.get("base_category") or result.get("category") or "")
    operation = str(details.get("operation") or "")
    source = _endpoint(result, details, "source")
    destination = _endpoint(result, details, "destination")
    continuity: dict[str, Any] = {}
    if category == "compute-placement":
        continuity = _mapping(details.get("continuity")) or _mapping(
            _mapping(details.get("details")).get("continuity")
        )
        if not continuity and details.get("stationary_server_id"):
            continuity = details
        source["fixed_ip"] = continuity.get("source_ip") or source.get("fixed_ip")
        source["ip"] = source["fixed_ip"]
        source["server_id"] = continuity.get("stationary_server_id") or source.get(
            "server_id"
        )
        destination["fixed_ip"] = continuity.get("target_fixed_ip") or destination.get(
            "fixed_ip"
        )
        destination["ip"] = continuity.get("destination_ip") or destination.get(
            "fixed_ip"
        )
        destination["server_id"] = continuity.get(
            "moving_server_id"
        ) or destination.get("server_id")
        references = [
            str(identity)
            for round_row in details.get("rounds") or []
            if isinstance(round_row, dict)
            for identity in round_row.get("test_ids") or []
        ]
        for identity in references:
            support = next(
                (
                    row
                    for row in context.get("results") or []
                    if isinstance(row, dict)
                    and str(row.get("test_id") or "").endswith(identity)
                ),
                None,
            )
            if support:
                for side, endpoint in (
                    ("source", source),
                    ("destination", destination),
                ):
                    candidate = _endpoint(
                        support, _mapping(support.get("details")), side
                    )
                    for key in ("ip", "fixed_ip", "server_id", "port_id"):
                        endpoint[key] = endpoint.get(key) or candidate.get(key)
                break
    family, family_gap = _recipe_family(
        result, details, continuity, source, destination
    )
    # Resolve only explicit address/identity matches. Reused labels or addresses
    # with contradictory identities remain operator inputs rather than guesses.
    for endpoint in (source, destination):
        if endpoint.get("server_id") or not endpoint.get("fixed_ip"):
            continue
        candidates: dict[str, dict[str, Any]] = {}
        for row in context.get("results") or []:
            if not isinstance(row, dict):
                continue
            row_details = _mapping(row.get("details"))
            for row_side in ("source", "destination"):
                candidate = _endpoint(row, row_details, row_side)
                if candidate.get("fixed_ip") == endpoint["fixed_ip"] and candidate.get(
                    "server_id"
                ):
                    candidates[str(candidate["server_id"])] = candidate
        if len(candidates) == 1:
            candidate = next(iter(candidates.values()))
            for key in ("server_id", "port_id", "floating_ip", "floating_ip_id"):
                endpoint[key] = endpoint.get(key) or candidate.get(key)
    resources = [row for row in context.get("resources") or [] if isinstance(row, dict)]
    names = {str(row.get("id")): row.get("name") for row in resources}
    for endpoint in (source, destination):
        endpoint["server_name"] = _mapping(details.get("path")).get(
            f"{'source' if endpoint is source else 'destination'}_server_name"
        ) or names.get(str(endpoint.get("server_id")))
    protocol = str(
        details.get("protocol")
        or ("tcp" if category == "floating-ip-egress-source-address" else "")
    ).lower()
    probe = _probe(details)
    diagnostic = _mapping(probe.get("diagnostics"))
    path = _mapping(details.get("path"))
    params: dict[str, dict[str, Any]] = {}
    steps: list[dict[str, Any]] = []
    gaps: list[str] = [family_gap] if family_gap else []
    notes: list[str] = []

    def recorded_port(transport: str) -> Any:
        ports: set[int] = set()
        for row in context.get("results") or []:
            if not isinstance(row, dict):
                continue
            other = _mapping(row.get("details"))
            if other.get("protocol") != transport:
                continue
            endpoint = _endpoint(row, other, "destination")
            if endpoint.get("server_id") != destination.get("server_id"):
                continue
            port_value = _mapping(_probe(other).get("diagnostics")).get(
                "destination_port"
            )
            if isinstance(port_value, int) and other.get("operation") not in {
                "security-allow",
                "security-deny",
                "security-restore",
            }:
                ports.add(port_value)
        return (
            next(iter(ports))
            if len(ports) == 1
            else configuration.get(f"{transport}_port")
        )

    def parameter(
        name: str, label: str, recorded: Any = None, kind: str = "text"
    ) -> None:
        params[name] = {
            "name": name,
            "label": label,
            "recorded": str(recorded) if recorded is not None else "",
            "kind": kind,
            "required": True,
        }

    def step(
        title: str, role: str, command: str, expected: str, *, phase: str = "run"
    ) -> None:
        used = re.findall(r"\$\{?([A-Z][A-Z_0-9]*)", command)
        used.extend(re.findall(r"os\.environ\[['\"]([A-Z][A-Z_0-9]*)['\"]\]", command))
        steps.append(
            {
                "title": title,
                "role": role,
                "command": command,
                "expected": expected,
                "phase": phase,
                "parameters": list(
                    dict.fromkeys(value for value in used if value in params)
                ),
            }
        )

    parameter("SOURCE_IP", "Source VM data address", source.get("fixed_ip"), "ip")
    parameter(
        "DESTINATION_IP",
        "Probe target address (floating IP when testing ingress/hairpin)",
        destination.get("ip"),
        "ip",
    )
    parameter(
        "DESTINATION_FIXED_IP",
        "Destination VM local data address (never its floating IP)",
        destination.get("fixed_ip"),
        "ip",
    )
    parameter(
        "DESTINATION_SERVER_ID",
        "Destination VM UUID / responder identity",
        destination.get("server_id"),
    )
    parameter(
        "HELPER",
        "Path to downloaded neutron-flux-manual.py on both guests",
        "./neutron-flux-manual.py",
        "path",
    )
    parameter(
        "TOKEN", "Fresh shared probe token (32 hexadecimal characters)", "", "token"
    )

    nat_path = str(details.get("nat_path") or diagnostic.get("nat_path") or "")
    if nat_path == "self-hairpin":
        notes.append(
            "Use one test VM and its own floating-IP association. Start the responder/observer and client in separate terminals on the same VM. SOURCE_IP and DESTINATION_FIXED_IP must be that VM's local fixed IP; DESTINATION_IP is its floating IP."
        )
    elif nat_path:
        notes.append(
            f"NAT path: {nat_path}. Preserve the recorded router relationship: same-router endpoints share one router; different-router endpoints use separate routers with the same external subnet."
        )
    if details.get("require_no_floating_ip") or details.get(
        "source_without_floating_ip"
    ):
        notes.append(
            "SNAT prerequisite: the source data port has no floating IP; its project router has source NAT enabled. Verify both API states before probing. The provider responder must report the router gateway address as the observed peer."
        )
        parameter("SOURCE_PORT_ID", "Source data-port UUID", source.get("port_id"))
        parameter("ROUTER_ID", "Source project router UUID", details.get("router_id"))
        step(
            "Verify the SNAT starting state",
            "Runner with OpenStack credentials",
            'openstack router show "$ROUTER_ID" -f json\nopenstack floating ip list --port "$SOURCE_PORT_ID" --long -f json',
            "external_gateway_info.enable_snat is true; the floating-IP list for the source port is empty.",
            phase="prepare",
        )
    translated = details.get("expected_translation_ips") or diagnostic.get(
        "expected_translated_sources"
    )
    if not translated and details.get("require_floating_ip"):
        translated = [source.get("floating_ip") or details.get("floating_ip")]
    if isinstance(translated, list) and len(translated) == 1 and translated[0]:
        parameter(
            "EXPECTED_PEER_IP",
            "Source address the destination must observe after NAT",
            translated[0],
            "ip",
        )

    expected = str(
        result.get("expected")
        or details.get("expectation_reason")
        or "Compare with the recorded assertion"
    )
    expected_probe = "A validated response from the intended destination; inspect peer_ip for any required source translation."
    if expected in {"blocked", "withdrawn"}:
        expected_probe = "A stable timeout or network rejection while the destination listener is independently confirmed ready. An unrelated route, identity or listener error does not prove isolation."

    port = diagnostic.get("destination_port")
    if protocol in {"tcp", "udp"} or category in {
        "server-lifecycle",
        "security-group",
        "floating-ip-lifecycle",
    }:
        protocol = protocol or "tcp"
        parameter(
            "PROBE_PORT", f"Recorded {protocol.upper()} destination port", port, "port"
        )
        notes.append(
            "Download the self-contained Python helper once, copy the identical file to both guests, and use Python 3. No Flux installation, nc or iperf service is assumed. Keep independent management access. Allow the selected responder ports only through the disposable test security groups."
        )
        step(
            "Start the matching responder first",
            "Destination VM; foreground terminal",
            'python3 "$HELPER" probe-server --bind "$DESTINATION_FIXED_IP" --probe-id "$DESTINATION_SERVER_ID" --tcp-port "$PROBE_PORT" --udp-port "$PROBE_PORT" --lifetime 3600',
            "Wait for NEUTRON_FLUX_READY; retain this terminal and its received-peer evidence. TCP and UDP can share the same numeric port; this recipe uses only the selected test protocol.",
            phase="prepare",
        )

    if family is not None and (source.get("ip") or destination.get("ip")):
        step(
            "Confirm the data route",
            "Source VM",
            f'ip -{family} route get "$DESTINATION_IP" from "$SOURCE_IP"',
            "The selected device/source belongs to the intended Neutron data port, not its management port.",
            phase="prepare",
        )

    identity = (
        ' --expected-probe-id "$DESTINATION_SERVER_ID"'
        if category.startswith("floating-ip")
        or protocol == "udp"
        or "EXPECTED_PEER_IP" in params
        else ""
    )
    peer = (
        ' --expected-peer-ip "$EXPECTED_PEER_IP"'
        if "EXPECTED_PEER_IP" in params
        else ""
    )
    if protocol in {"tcp", "udp"}:
        probe_command = (
            'python3 "$HELPER" probe-client --source "$SOURCE_IP" --destination "$DESTINATION_IP" --protocol '
            + protocol
            + ' --port "$PROBE_PORT" --token "$TOKEN"'
            + identity
            + peer
        )
    else:
        protocol = "icmp"
        probe_command = (
            f'ping -{family} -n -c 3 -W 2 -I "$SOURCE_IP" "$DESTINATION_IP"'
            if family is not None
            else ""
        )
        attestation = _mapping(diagnostic.get("icmp_destination_attestation"))
        if attestation and family is not None:
            parameter(
                "DESTINATION_DATA_MAC",
                "Destination data-port MAC for ICMP attestation",
                destination.get("data_mac"),
                "mac",
            )
            probe_command = f'ping -{family} -n -c 3 -W 2 -p "$TOKEN" -I "$SOURCE_IP" "$DESTINATION_IP"'
            step(
                "Start destination ICMP attestation",
                "Destination VM, root/sudo; separate terminal",
                'sudo python3 "$HELPER" icmp-observer --local-ip "$DESTINATION_FIXED_IP" --data-mac "$DESTINATION_DATA_MAC" --probe-id "$DESTINATION_SERVER_ID" --token "$TOKEN" --timeout 30'
                + (
                    ' --expected-peer-ip "$EXPECTED_PEER_IP"'
                    if "EXPECTED_PEER_IP" in params
                    else ""
                ),
                "Wait for NF_ICMP_READY, then run the source ping before the 30-second deadline. Verify destination identity and the observed source, not ping success alone.",
                phase="prepare",
            )

    changes_state = False
    responder_command = 'python3 "$HELPER" probe-server --bind "$DESTINATION_FIXED_IP" --probe-id "$DESTINATION_SERVER_ID" --tcp-port "$PROBE_PORT" --udp-port "$PROBE_PORT" --lifetime 3600'
    state = SimpleNamespace(
        category=category,
        details=details,
        operation=operation,
        family=family,
        source=source,
        destination=destination,
        protocol=protocol,
        params=params,
        steps=steps,
        gaps=gaps,
        notes=notes,
        parameter=parameter,
        step=step,
        path=path,
        configuration=configuration,
        probe_command=probe_command,
        expected=expected,
        expected_probe=expected_probe,
        peer=peer,
        responder_command=responder_command,
        diagnostic=diagnostic,
        reporting_context=_mapping(result.get("reporting_context")),
        planned_check=next(
            (
                check
                for check in context.get("planned_check_ledger") or []
                if isinstance(check, dict)
                and check.get("id") == details.get("planned_check_id")
            ),
            {},
        ),
        recorded_port=recorded_port,
    )
    if category == "compute-placement":
        changes_state, protocol = _placement_recipe(state)
    elif family is None:
        # Keep the conflicting evidence visible, but do not emit a guessed
        # probe or a family-specific policy/lifecycle change.
        steps.clear()
    elif category in {
        "server-lifecycle",
        "floating-ip-lifecycle",
        "router-interface-lifecycle",
        "security-group",
    }:
        changes_state, protocol = _lifecycle_recipe(state)
    elif category == "router-static-routing":
        changes_state, protocol = _static_route_recipe(state)
    elif category == "network-performance":
        changes_state, protocol = _performance_recipe(state)
    else:
        changes_state, protocol = _traffic_recipe(state)
    used = {name for item in steps for name in item["parameters"]}
    parameters = [value for key, value in params.items() if key in used]
    if (
        not all((source.get("ip"), destination.get("ip")))
        and category != "compute-placement"
    ):
        gaps.append(
            "One or both endpoint addresses are missing from this record. Identify the actual probe source and target before running the recipe."
        )
    return {
        "parameters": parameters,
        "steps": steps,
        "notes": notes,
        "incomplete": list(dict.fromkeys(gaps)),
        "changes_state": changes_state,
        "source": source,
        "destination": destination,
        "assertion": expected,
        "protocol": protocol.upper(),
        "helper_required": any('"$HELPER"' in row["command"] for row in steps),
    }
