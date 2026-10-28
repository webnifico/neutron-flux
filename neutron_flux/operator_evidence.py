"""Bounded, recorded diagnostic facts; no inferred fault attribution."""

from __future__ import annotations

from typing import Any


def mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def text(value: Any, limit: int = 1600) -> str:
    value = str(value if value is not None else "").strip()
    return value if len(value) <= limit else value[:limit].rstrip() + " … [truncated]"


def diagnostic_snapshot(payload: dict[str, Any]) -> dict[str, Any]:
    """Keep useful guest output and selected cloud fields, not whole API objects."""
    guests = {}
    for role in ("source", "destination"):
        guest = mapping(mapping(payload.get("guests")).get(role))
        if guest:
            guests[role] = {
                key: text(guest[key], 16000 if key == "output" else 1600)
                if isinstance(guest[key], str)
                else guest[key]
                for key in ("label", "server_id", "status", "usable", "error", "output")
                if key in guest
            }
    resources = []
    for identity, raw in mapping(payload.get("openstack")).items():
        data = mapping(raw)
        fields = {
            key: data[key]
            for key in (
                "id",
                "name",
                "status",
                "admin_state_up",
                "fixed_ips",
                "binding_host_id",
                "binding:host_id",
                "binding_vif_type",
                "binding:vif_type",
                "OS-EXT-SRV-ATTR:host",
                "security_group_ids",
                "security_groups",
                "device_id",
                "error",
            )
            if key in data
        }
        resources.append({"reference": identity, **fields})
    return {
        "test_id": payload.get("test"),
        "guests": guests,
        "resources": resources,
        **(
            {"control_paths": payload["control_paths"]}
            if payload.get("control_paths")
            else {}
        ),
        "timing_note": "Diagnostics were collected after the probe; they are a later snapshot, not a packet trace of the failed flow.",
    }


def evidence_facts(result: dict[str, Any]) -> list[dict[str, str]]:
    details = mapping(result.get("details"))
    probe = mapping(details.get("tcp_baseline")) or mapping(details.get("probe"))
    diagnostics = mapping(probe.get("diagnostics"))
    protocol = str(
        details.get("protocol")
        or probe.get("protocol")
        or ("tcp" if details.get("tcp_baseline") else "")
    ).lower()
    connected_label = {
        "tcp": "TCP connection established",
        "udp": "UDP socket peer selected",
    }.get(protocol, "Socket peer selected")
    snapshot = mapping(result.get("operator_diagnostics")) or mapping(
        details.get("diagnostic_snapshot")
    )
    facts: list[dict[str, str]] = []

    def add(label: str, value: Any) -> None:
        if value is not None and value != "" and value != [] and value != {}:
            facts.append({"label": label, "value": text(value)})

    for key, label in (
        ("failure_phase", "Failed probe step"),
        ("error_type", "Probe error type"),
        ("error", "Probe error"),
        ("destination_port", "Destination port"),
        ("connected", connected_label),
        ("request_sent", "Request sent"),
        ("token_sent", "Echo token sent"),
        ("response_received", "Response received"),
        ("echo_received", "Echo received"),
        ("response_validated", "Response validated"),
        ("echo_validated", "Echo validated"),
    ):
        value = diagnostics.get(key)
        add(label, ("Yes" if value else "No") if isinstance(value, bool) else value)
    add("Probe attempts", probe.get("attempts"))
    add("Probe error output", probe.get("stderr"))
    execution_error = mapping(details.get("execution_error"))
    add("SSH target", execution_error.get("endpoint_address"))
    add("SSH jump host", execution_error.get("controller_address"))
    stage = execution_error.get("last_observed_stage")
    add(
        "Last observed SSH stage",
        {
            "ssh-command-launched": "SSH launched; remote command start not observed",
            "remote-command-started": "Remote command started; completion not observed",
            "remote-command-completed": "Remote command completed; SSH did not finish",
        }.get(stage, stage),
    )
    add("Remote command exit status", execution_error.get("remote_returncode"))
    add("Partial SSH error output", execution_error.get("stderr"))
    execution = mapping(details.get("execution_diagnostics"))
    health = mapping(execution.get("compute_service_health"))
    add("Diagnostic snapshot time", execution.get("captured_at"))
    add("Compute service evidence", health.get("status"))
    add("Compute service evidence limit", health.get("reason"))
    add("Observed compute service records", health.get("data"))
    add("Router ID", details.get("router_id"))
    if "router_source_nat_enabled" in details:
        add(
            "Router source NAT enabled",
            "Yes" if details["router_source_nat_enabled"] else "No",
        )
    router = mapping(details.get("router_state"))
    if "admin_state_up" in router:
        add(
            "Router administratively enabled",
            "Yes" if router["admin_state_up"] else "No",
        )
    if result.get("status") in {"FAIL", "ERROR", "UNVERIFIED"}:
        for key, label in (
            (
                "expected_no_fragment_path_mtu",
                "Expected no-fragment MTU (not a measured result)",
            ),
            ("cloud_operation_outcome", "Cloud operation outcome"),
            ("nova_migration_record_error", "Migration evidence error"),
            ("migration_attempts", "Recorded migration attempts"),
            ("port_host_mismatches", "Port binding mismatches"),
            ("prerequisite_error", "Prerequisite error"),
        ):
            add(label, details.get(key))
    route = mapping(diagnostics.get("endpoint_route"))
    add("Guest route lookup", route.get("stdout") or route.get("stderr"))
    add("Recorded protocol", details.get("protocol") or probe.get("protocol"))
    observer = mapping(details.get("provider_observer"))
    if "service_ready" in observer:
        add(
            "Provider observer ready before probe",
            "Yes" if observer["service_ready"] else "No",
        )
    add(
        "Expected translated source",
        ", ".join(map(str, details.get("expected_translation_ips") or [])),
    )
    add(
        "Observed translated source",
        details.get("translated_source_ip_observed_by_provider"),
    )
    for role, guest in mapping(snapshot.get("guests")).items():
        guest = mapping(guest)
        add(f"{role.title()} VM ID", guest.get("server_id"))
        if guest.get("usable") is False:
            add(
                f"{role.title()} diagnostics unavailable",
                guest.get("error") or guest.get("status"),
            )
        output = str(guest.get("output") or "")
        sections: dict[str, list[str]] = {}
        section = ""
        for line in output.splitlines():
            if line.startswith("### "):
                section = line[4:].strip()
                sections.setdefault(section, [])
            elif section:
                sections[section].append(line)
        for section, label in (
            ("ip route show table all", "route table defaults"),
            ("ip -6 route show table all", "IPv6 routes"),
        ):
            routes = [
                line
                for line in sections.get(section, [])
                if line.startswith("default ")
            ]
            add(f"{role.title()} {label}", "\n".join(routes))
        port = diagnostics.get("destination_port") or observer.get("tcp_port")
        sockets = [
            line for line in sections.get("sockets", []) if port and f":{port} " in line
        ]
        if sockets:
            add(f"{role.title()} socket snapshot", "\n".join(sockets))
    for resource in snapshot.get("resources") or []:
        resource = mapping(resource)
        identity = str(resource.get("reference") or "resource")
        if "-port-" not in identity:
            continue
        values = []
        if resource.get("status"):
            values.append(str(resource["status"]))
        if "admin_state_up" in resource:
            values.append(
                "administratively enabled"
                if resource["admin_state_up"]
                else "administratively disabled"
            )
        addresses = [
            mapping(row).get("ip_address")
            for row in resource.get("fixed_ips") or []
            if isinstance(row, dict)
        ]
        if addresses:
            values.append(
                "addresses " + ", ".join(str(value) for value in addresses if value)
            )
        host = resource.get("binding_host_id") or resource.get("binding:host_id")
        if host:
            values.append(f"bound to {host}")
        for key, label in (
            ("binding_vif_type", "interface type"),
            ("binding:vif_type", "interface type"),
            ("security_group_ids", "security group IDs"),
            ("error", "collection error"),
        ):
            if key in resource:
                value = resource[key]
                values.append(
                    f"{label}: "
                    + (
                        ", ".join(map(str, value))
                        if isinstance(value, list)
                        else str(value)
                    )
                )
        role, _, port_id = identity.partition("-port-")
        add(f"{role.title()} Neutron port {port_id}", "; ".join(values))
    if snapshot.get("guests") or snapshot.get("resources"):
        add("Snapshot timing", snapshot.get("timing_note"))
    return facts
