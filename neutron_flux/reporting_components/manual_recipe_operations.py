"""Operation-specific, ordered manual steps using current parameter inputs."""

from __future__ import annotations

from typing import Any

from .manual_recipe_support import (
    _mapping,
    _wait_fip,
    _wait_router_interface,
    _wait_server,
)


def _placement_recipe(state: Any) -> tuple[bool, str]:
    protocol = state.protocol
    details = state.details
    source = state.source
    destination = state.destination
    gaps = state.gaps
    notes = state.notes
    parameter = state.parameter
    step = state.step
    expected = state.expected
    changes_state = False
    # Placement discovery, baseline, port readback and readiness are evidence
    # checks, not invitations to submit another migration.
    is_move = expected in {
        "live-migration-complete",
        "cold-migration-complete",
        "placement-achieved",
        "traffic-continuity-measured",
    }
    moving = (
        details.get("server_id")
        or details.get("moving_server_id")
        or destination.get("server_id")
    )
    if details.get("resolution_only") is True and not moving:
        stage = state.reporting_context.get("execution_stage")
        supporting = state.planned_check.get("prerequisites") or []
        if stage == "pre-migration":
            notes.append(
                "This ledger row summarizes a functional baseline before migration. Reproduce its supporting ICMP, TCP and UDP rows in both directions for every applicable family, plus any listed external-egress checks. Match the original placement and verify all required probes before submitting a migration; this summary itself performs no migration."
            )
        else:
            notes.append(
                "This is a read-only placement prerequisite recorded by the execution ledger. Inspect both current endpoint VMs' actual compute hosts, availability zones and data-port bindings using the supporting workflow; do not submit a migration for this summary."
            )
        if supporting:
            notes.append(
                "Supporting planned checks: " + ", ".join(map(str, supporting))
            )
        gaps.append(
            "No endpoint VM UUIDs or standalone command were recorded on this summary row. Open its supporting workflow/probe results, identify the two current disposable VMs and use those guides. An empty moving-VM identifier or a single ping cannot reproduce this prerequisite."
        )
        return changes_state, protocol
    parameter("MOVING_SERVER_ID", "VM UUID whose placement is being inspected", moving)
    parameter(
        "TARGET_HOST",
        "Requested destination compute in the same AZ",
        details.get("destination_host")
        or _mapping(details.get("migration_completion_evidence")).get(
            "destination_host"
        ),
    )
    if not is_move:
        if expected == "fresh-functional-matrix":
            parameter(
                "SOURCE_SERVER_ID", "Baseline source VM UUID", source.get("server_id")
            )
            parameter(
                "DESTINATION_SERVER_ID",
                "Baseline destination VM UUID",
                destination.get("server_id"),
            )
            inspect = 'openstack server show "$SOURCE_SERVER_ID" -f json\nopenstack server show "$DESTINATION_SERVER_ID" -f json'
        else:
            inspect = 'openstack server show "$MOVING_SERVER_ID" -f json\nopenstack port list --device-id "$MOVING_SERVER_ID" --long -f json'
        step(
            "Inspect the saved placement assertion",
            "Runner with admin OpenStack credentials",
            inspect,
            "Compare actual compute host, AZ, stable power/task state and data-port binding with this result's assertion. This step performs no migration.",
        )
        if expected == "fresh-functional-matrix":
            notes.append(
                "This row summarizes related baseline probes. Repeat its supporting ICMP, TCP and UDP rows in both directions before any new migration; this read-only summary is not a migration procedure."
            )
    else:
        changes_state = True
        mode = str(
            details.get("migration_mode")
            or _mapping(details.get("details")).get("migration_mode")
            or "live"
        )
        storage = str(
            details.get("migration_storage")
            or _mapping(details.get("details")).get("migration_storage")
            or ""
        )
        if mode == "live" and storage not in {"shared", "host"}:
            parameter(
                "STORAGE_FLAG",
                "Verified live migration storage flag (--shared-migration or --block-migration)",
            )
            storage_flag = ' "$STORAGE_FLAG"'
        else:
            storage_flag = (
                " --block-migration" if storage == "host" else " --shared-migration"
            )
        step(
            "Save placement and migration inventory",
            "Runner with admin OpenStack credentials",
            'openstack server show "$MOVING_SERVER_ID" -f json\nopenstack --os-compute-api-version 2.56 server migration list --server "$MOVING_SERVER_ID" -f json',
            "Save the initial host/AZ, attached volumes and task state. Verify the target is healthy, compatible and in the same availability zone before continuing.",
            phase="prepare",
        )
        if expected == "traffic-continuity-measured":
            gaps.append(
                "This continuity assertion needs the full phase-marked ICMP/TCP/UDP monitor used by Flux. The simple probe recipe cannot reproduce TCP-session survival or interruption brackets. Use the matching Flux workflow for that assertion; the commands below reproduce the migration and endpoint recovery only."
            )
        gaps.append(
            "Before submitting migration, use this workflow's supporting ICMP/TCP/UDP reproduction rows in both directions on the original placement. A single ping cannot replace that functional matrix, destination readiness, guest/volume identity and port-binding checks."
        )
        migrate = "openstack --os-compute-api-version 2.56 server migrate"
        if mode == "live":
            migrate += (
                ' --live-migration --host "$TARGET_HOST"'
                + storage_flag
                + ' --wait "$MOVING_SERVER_ID"\n'
                + _wait_server("ACTIVE", host=True)
            )
        else:
            migrate += (
                ' --host "$TARGET_HOST" "$MOVING_SERVER_ID"\n'
                + _wait_server("VERIFY_RESIZE", host=True)
                + '\nopenstack --os-compute-api-version 2.56 server migrate confirm "$MOVING_SERVER_ID"\n'
                + _wait_server("ACTIVE", host=True)
            )
        step(
            "Submit one " + mode + " migration and verify its terminal state",
            "Runner with admin OpenStack credentials",
            migrate,
            "Require a new completed migration record, target host/AZ, cleared task state, valid port binding and unchanged attached volumes. A successful CLI return alone is insufficient.",
        )
        step(
            "Inspect destination placement and ports after recovery",
            "Runner",
            'openstack server show "$MOVING_SERVER_ID" -f json\nopenstack port list --device-id "$MOVING_SERVER_ID" --long -f json',
            "Require the target compute/AZ and valid bindings; restart disposable responders if needed, then repeat the same supporting ICMP/TCP/UDP rows in both directions on the opposite placement relation. Stop after this one transition.",
        )
        notes.append(
            "Do not automatically migrate back: save the approved final placement. Any return migration is a separate operator-approved action, not part of this coverage check."
        )
    return changes_state, protocol


def _lifecycle_recipe(state: Any) -> tuple[bool, str]:
    diagnostic = state.diagnostic
    category = state.category
    details = state.details
    operation = state.operation
    family = state.family
    destination = state.destination
    protocol = state.protocol
    steps = state.steps
    gaps = state.gaps
    notes = state.notes
    parameter = state.parameter
    step = state.step
    probe_command = state.probe_command
    expected_probe = state.expected_probe
    responder_command = state.responder_command
    changes_state = False
    if category == "server-lifecycle":
        changes_state = True
        parameter(
            "MOVING_SERVER_ID",
            "Disposable destination VM UUID for lifecycle operation",
            destination.get("server_id"),
        )
        action = operation.removeprefix("server-")
        if action == "start":
            steps[:] = [
                item
                for item in steps
                if item["title"] != "Start the matching responder first"
            ]
            step(
                "Verify the stopped starting state",
                "Runner",
                _wait_server("SHUTOFF"),
                "The destination is already SHUTOFF from the preceding verified stop stage.",
                phase="prepare",
            )
            step(
                "Verify the service is withdrawn before start",
                "Source VM",
                probe_command,
                "Fresh connections are blocked while the destination is stopped.",
            )
        else:
            step(
                "Check the service before changing server state",
                "Source VM",
                probe_command,
                "A valid baseline response from the ready destination service.",
            )
        if action in {"stop", "start", "reboot"}:
            if action == "start":
                notes.append(
                    "Starting-state prerequisite: this result follows a verified stop of this disposable VM. If reproducing the full lifecycle, first perform the server-stop guide and confirm the service is withdrawn."
                )
            command = (
                f"openstack server {action}"
                + (" --soft" if action == "reboot" else "")
                + ' "$MOVING_SERVER_ID"\n'
                + _wait_server("SHUTOFF" if action == "stop" else "ACTIVE")
            )
            step(
                "Perform the recorded " + action + " operation",
                "Runner",
                command,
                "The requested server state is confirmed by fresh API readback; retain independent access to the source VM.",
            )
            if action in {"start", "reboot"}:
                step(
                    "Restart the temporary responder after guest recovery",
                    "Destination VM; foreground terminal",
                    responder_command,
                    "Reconnect independently after guest initialization; wait for NEUTRON_FLUX_READY before probing.",
                )
            step(
                "Check service state after the operation",
                "Source VM",
                probe_command,
                expected_probe,
            )
            if action == "stop":
                step(
                    "Restore the running destination",
                    "Runner",
                    'openstack server start "$MOVING_SERVER_ID"\n'
                    + _wait_server("ACTIVE"),
                    "Wait for guest initialization, restart the responder, and require the original baseline response.",
                    phase="restore",
                )
                step(
                    "Restart the restored service",
                    "Destination VM; foreground terminal",
                    responder_command,
                    "Wait for NEUTRON_FLUX_READY.",
                    phase="restore",
                )
                step(
                    "Verify the original running baseline",
                    "Source VM",
                    probe_command,
                    "The intended service returns a valid response.",
                    phase="restore",
                )
        else:
            gaps.append(
                "The recorded server lifecycle operation is missing or unsupported; no state-changing command has been invented."
            )
    elif category == "floating-ip-lifecycle":
        changes_state = True
        parameter(
            "FLOATING_IP_ID",
            "Disposable floating-IP UUID",
            destination.get("floating_ip_id")
            or _mapping(diagnostic.get("floating_ip_api_state")).get("floating_ip_id"),
        )
        parameter(
            "DESTINATION_PORT_ID",
            "Destination fixed-IP data-port UUID",
            destination.get("port_id"),
        )
        step(
            "Save and verify the original floating-IP association",
            "Runner",
            'openstack floating ip show "$FLOATING_IP_ID" -f json\n'
            + _wait_fip(attached=True),
            "Require the intended destination fixed IP and port; source observer resides on the recorded provider subnet.",
            phase="prepare",
        )
        step(
            "Verify associated ingress",
            "Source provider observer VM",
            probe_command,
            "A response from the intended private destination, not from another holder of the address.",
        )
        step(
            "Detach only this test association",
            "Runner",
            'openstack floating ip unset --port "$FLOATING_IP_ID"\n'
            + _wait_fip(attached=False),
            "API port_id is null/empty. Do not delete the floating-IP allocation.",
        )
        step(
            "Verify ingress withdrawal",
            "Source provider observer VM",
            probe_command,
            "New ingress connections are stably blocked while the destination listener remains ready via independent management access.",
        )
        step(
            "Restore the exact fixed-IP association",
            "Runner",
            'openstack floating ip set --port "$DESTINATION_PORT_ID" --fixed-ip-address "$DESTINATION_FIXED_IP" "$FLOATING_IP_ID"\n'
            + _wait_fip(attached=True),
            "Original port/fixed-IP association is confirmed by the API.",
            phase="restore",
        )
        step(
            "Verify restored ingress",
            "Source provider observer VM",
            probe_command,
            "The original identity-validated ingress response returns.",
            phase="restore",
        )
    elif category == "router-interface-lifecycle":
        changes_state = True
        parameter("ROUTER_ID", "Disposable router UUID", details.get("router_id"))
        parameter(
            "SUBNET_ID",
            "Destination subnet UUID to detach/restore",
            details.get("subnet_id"),
        )
        step(
            "Save router interface configuration",
            "Runner",
            'openstack router show "$ROUTER_ID" -f json\nopenstack port list --device-id "$ROUTER_ID" --long -f json',
            "Save the destination subnet gateway interface/IP. Re-add by subnet only when the interface uses the subnet gateway; a custom interface address needs exact port-based restoration.",
            phase="prepare",
        )
        step(
            "Verify routing baseline",
            "Source VM",
            probe_command,
            "Destination reachable through the intended router, with independent management access to both VMs.",
        )
        step(
            "Detach the recorded destination subnet",
            "Runner",
            'openstack router remove subnet "$ROUTER_ID" "$SUBNET_ID"\n'
            + _wait_router_interface(attached=False),
            "No router interface port still refers to this subnet.",
        )
        step(
            "Verify routing withdrawal",
            "Source VM",
            probe_command,
            "Stable withdrawal of the routed path; preserve the output and router API state.",
        )
        step(
            "Restore the subnet gateway interface",
            "Runner",
            'openstack router add subnet "$ROUTER_ID" "$SUBNET_ID"\n'
            + _wait_router_interface(attached=True),
            "The same subnet/gateway attachment is present.",
            phase="restore",
        )
        step(
            "Verify recovered routing",
            "Source VM",
            probe_command,
            "The original valid response returns.",
            phase="restore",
        )
    elif category == "security-group":
        changes_state = operation not in {"security-deny", "security-control"}
        parameter(
            "SOURCE_SECURITY_GROUP_ID",
            "Disposable source data-port security-group UUID",
            diagnostic.get("source_security_group_id"),
        )
        parameter(
            "DESTINATION_SECURITY_GROUP_ID",
            "Disposable destination data-port security-group UUID",
            diagnostic.get("destination_security_group_id"),
        )
        parameter("RULE_ID", "UUID of only the temporary rule created below", "")
        notes.append(
            "Confirm port security is enabled and the source/destination groups are actually attached. The control-port listener must be reachable locally on the destination; an allowed service port must pass first. Inspect all attached destination groups to ensure none already permits this control flow. Do not replace existing port groups."
        )
        step(
            "Inspect the exact existing policy",
            "Runner",
            'openstack security group rule list "$DESTINATION_SECURITY_GROUP_ID" --long -f json',
            "The selected control TCP port is initially denied to the source security group.",
            phase="prepare",
        )
        step(
            "Verify the control port is initially denied",
            "Source VM",
            probe_command,
            "Control TCP flow is blocked while the regular allowed service baseline passes.",
        )
        if changes_state:
            notes.append(
                "This guide shows the complete temporary allow/restore lifecycle; the selected result corresponds to "
                + operation
                + ". Retain the one newly created rule ID across these stages."
            )
            step(
                "Add one temporary ingress rule",
                "Runner",
                f'openstack security group rule create --ingress --ethertype IPv{family} --protocol tcp --dst-port "$PROBE_PORT" --remote-group "$SOURCE_SECURITY_GROUP_ID" "$DESTINATION_SECURITY_GROUP_ID" -f json',
                "Save the returned id into RULE_ID. Do not reuse a historical rule UUID.",
            )
            step(
                "Verify the temporary allow rule",
                "Source VM",
                probe_command,
                "Repeat fresh connections until a valid echo is received; allow up to the recorded convergence timeout.",
            )
            step(
                "Remove only the newly created rule",
                "Runner",
                'openstack security group rule delete "$RULE_ID"\nopenstack security group rule list "$DESTINATION_SECURITY_GROUP_ID" --long -f json',
                "The exact temporary rule UUID is absent and original groups/rules remain unchanged.",
                phase="restore",
            )
            step(
                "Verify original deny policy returns",
                "Source VM",
                probe_command,
                "Fresh control-port connections are again blocked; the allowed baseline still passes.",
                phase="restore",
            )
    return changes_state, protocol


def _static_route_recipe(state: Any) -> tuple[bool, str]:
    protocol = state.protocol
    details = state.details
    operation = state.operation
    gaps = state.gaps
    notes = state.notes
    parameter = state.parameter
    step = state.step
    probe_command = state.probe_command
    expected_probe = state.expected_probe
    changes_state = False
    changes_state = operation in {
        "static-route-install",
        "static-route-withdraw",
        "static-route-restore",
    }
    for side in ("A", "B"):
        parameter(f"ROUTER_{side}_ID", f"Disposable router {side} UUID")
        parameter(
            f"ROUTE_{side}_DESTINATION",
            f"Remote project subnet CIDR routed by router {side}",
            kind="cidr",
        )
        parameter(
            f"ROUTE_{side}_GATEWAY",
            f"Peer router's transit IP used by router {side}",
            kind="ip",
        )
    notes.append(
        "Two routers share one transit subnet; each VM is on its router's separate endpoint subnet. Supply the peer router transit IP as next hop, not the remote VM address. Save both route lists before modifying only the two test routes."
    )
    step(
        "Save both route lists",
        "Runner",
        'openstack router show "$ROUTER_A_ID" -f json\nopenstack router show "$ROUTER_B_ID" -f json',
        "Match the recorded phase: no remote routes for baseline; both routes present for connected tests.",
        phase="prepare",
    )
    if changes_state:
        action = "remove" if operation == "static-route-withdraw" else "add"
        sides = (
            [str(details.get("route_side") or "A")]
            if operation in {"static-route-withdraw", "static-route-restore"}
            else ["A", "B"]
        )
        for side in sides:
            if side not in {"A", "B"}:
                gaps.append(
                    "Recorded route side is invalid; verify which router owns the changing route."
                )
                continue
            step(
                f"{action.capitalize()} only router {side}'s test route",
                "Runner",
                f'openstack router {action} route --route "destination=$ROUTE_{side}_DESTINATION,gateway=$ROUTE_{side}_GATEWAY" "$ROUTER_{side}_ID"\nopenstack router show "$ROUTER_{side}_ID" -f json',
                "Verify the exact destination/nexthop pair is "
                + ("absent" if action == "remove" else "present")
                + " before probing.",
            )
    step(
        "Probe the recorded static-route phase",
        "Source VM",
        probe_command,
        expected_probe,
    )
    if changes_state:
        gaps.append(
            "Restore both routers to the saved route lists after testing: remove only newly added test routes, or re-add the exact withdrawn test route. The original full route lists are not embedded in this result; do not replace unrelated routes."
        )
    return changes_state, protocol


def _performance_recipe(state: Any) -> tuple[bool, str]:
    details = state.details
    source = state.source
    protocol = state.protocol
    gaps = state.gaps
    notes = state.notes
    parameter = state.parameter
    step = state.step
    path = state.path
    configuration = state.configuration
    peer = state.peer
    recorded_port = state.recorded_port
    changes_state = False
    notes.append(
        "Use the helper's matching NF-PERF responder. Measurements must preserve the saved duration, repetitions, streams, rates, packet sizes, both directions and idle/loaded phases. Derived summaries alone are not new measurements."
    )
    parameter("TCP_PORT", "NF-PERF responder TCP port", recorded_port("tcp"), "port")
    parameter("UDP_PORT", "NF-PERF responder UDP port", recorded_port("udp"), "port")
    parameter(
        "DURATION",
        "Measurement duration in seconds",
        configuration.get("performance_duration_seconds"),
        "number",
    )
    parameter(
        "REPEATS",
        "Recorded measurement repetitions",
        configuration.get("performance_repeats"),
        "number",
    )
    stream_counts = configuration.get("performance_tcp_streams") or []
    rates = configuration.get("performance_udp_rates_mbps") or []
    packet_sizes = configuration.get("performance_udp_packet_sizes") or []
    parameter(
        "STREAMS",
        "TCP parallel stream count for this sample",
        stream_counts[0] if stream_counts else None,
        "number",
    )
    parameter(
        "RATE_MBPS",
        "UDP offered rate in Mbit/s for this sample",
        rates[0] if rates else None,
        "number",
    )
    parameter(
        "PACKET_SIZE",
        "UDP payload bytes for this sample",
        packet_sizes[0] if packet_sizes else None,
        "number",
    )
    if stream_counts or rates or packet_sizes:
        notes.append(
            f"Saved run profile: TCP streams {stream_counts}; UDP rates {rates} Mbit/s; UDP payloads {packet_sizes} bytes. The sample command uses the first entry; repeat all recorded combinations and any calibrated lower rates shown in the saved measurements."
        )
    step(
        "Start NF-PERF destination responder",
        "Destination VM; foreground terminal",
        'python3 "$HELPER" probe-server --bind "$DESTINATION_FIXED_IP" --probe-id "$DESTINATION_SERVER_ID" --tcp-port "$TCP_PORT" --udp-port "$UDP_PORT" --lifetime 3600',
        "Wait for NEUTRON_FLUX_READY. For reverse direction start the same responder on the original source using that VM's local data IP and UUID.",
        phase="prepare",
    )
    measurement = str(details.get("measurement") or "")
    protocol = (
        "udp"
        if measurement == "udp"
        else "tcp"
        if measurement
        in {"tcp-throughput", "concurrency", "repeatability", "asymmetry"}
        else "icmp"
        if measurement == "mtu-mss"
        else "mixed"
    )
    if measurement in {"tcp-throughput", "concurrency", "repeatability", "asymmetry"}:
        step(
            "Repeat the recorded TCP sample",
            "Source VM",
            'python3 "$HELPER" perf-client --source "$SOURCE_IP" --destination "$DESTINATION_IP" --protocol tcp --port "$TCP_PORT" --duration "$DURATION" --streams "$STREAMS" --repeats "$REPEATS" --expected-probe-id "$DESTINATION_SERVER_ID"'
            + peer,
            "Retain per-stream throughput, receiver delivery and retransmissions; repeat each stream/repetition combination and reverse direction from the saved samples.",
        )
    elif measurement == "udp":
        step(
            "Repeat the recorded UDP sample",
            "Source VM",
            'python3 "$HELPER" perf-client --source "$SOURCE_IP" --destination "$DESTINATION_IP" --protocol udp --port "$UDP_PORT" --duration "$DURATION" --repeats "$REPEATS" --rate-mbps "$RATE_MBPS" --packet-size "$PACKET_SIZE" --expected-probe-id "$DESTINATION_SERVER_ID"'
            + peer,
            "Compare receiver loss, jitter/reordering and actual sender achievement at every recorded rate/size. Reproduce calibration before classifying loss.",
        )
    elif measurement == "mtu-mss":
        gaps.append(
            "The MTU helper reproduces packet-size boundary observations only; it does not reproduce the TCP client/server MSS observation. Use the matching Flux measurement workflow to collect TCP MSS before claiming this combined MTU/MSS measurement has been reproduced."
        )
        parameter(
            "MTU",
            "Advertised effective network MTU",
            path.get("expected_mtu"),
            "number",
        )
        step(
            "Repeat packet-size boundary observations",
            "Source VM",
            'python3 "$HELPER" mtu-client --source "$SOURCE_IP" --destination "$DESTINATION_IP" --mtu "$MTU"',
            "Record valid/oversized DF outcomes and PMTUD feedback in each direction. Do not classify a locally rejected packet as an end-to-end delivered packet.",
        )
    else:
        gaps.append(
            "This loaded/idle or multi-path measurement requires the coordinated Flux workload schedule. Standalone throughput commands cannot recreate concurrent load or timing; use its Flux workflow and saved execution evidence rather than claim an equivalent measurement."
        )
    if not details.get("command_evidence"):
        gaps.append(
            "This older result did not save performance command options. Enter the duration, repetitions, stream counts, rate/size matrix and listener ports from its run configuration and saved samples before copying a measurement command."
        )
    notes.append(
        "For reverse measurements, explicitly swap source/destination fixed addresses, VM identities and any NAT mapping; do not send to a private address from an external observer unless that reverse path is part of the recorded contract."
    )
    if measurement in {
        "tcp-throughput",
        "concurrency",
        "repeatability",
        "asymmetry",
        "udp",
    }:
        parameter(
            "SOURCE_SERVER_ID",
            "Original source VM UUID / reverse responder identity",
            source.get("server_id"),
        )
        parameter(
            "REVERSE_TARGET_IP",
            "Original source address reachable from the original destination (its FIP if required)",
            path.get("reverse_destination_ip")
            or source.get("floating_ip")
            or source.get("fixed_ip"),
            "ip",
        )
        step(
            "Start reverse-direction responder",
            "Original source VM; separate foreground terminal",
            'python3 "$HELPER" probe-server --bind "$SOURCE_IP" --probe-id "$SOURCE_SERVER_ID" --tcp-port "$TCP_PORT" --udp-port "$UDP_PORT" --lifetime 3600',
            "Wait for NEUTRON_FLUX_READY. Original forward responder can remain running.",
        )
        reverse_protocol = "udp" if measurement == "udp" else "tcp"
        reverse_port = "UDP_PORT" if reverse_protocol == "udp" else "TCP_PORT"
        reverse_extra = (
            ' --rate-mbps "$RATE_MBPS" --packet-size "$PACKET_SIZE"'
            if reverse_protocol == "udp"
            else ' --streams "$STREAMS"'
        )
        if path.get("reverse_expected_peer_ip"):
            parameter(
                "REVERSE_EXPECTED_PEER_IP",
                "Translated source observed during the reverse direction",
                path["reverse_expected_peer_ip"],
                "ip",
            )
            reverse_extra += ' --expected-peer-ip "$REVERSE_EXPECTED_PEER_IP"'
        step(
            "Run the reverse-direction sample",
            "Original destination VM",
            'python3 "$HELPER" perf-client --source "$DESTINATION_FIXED_IP" --destination "$REVERSE_TARGET_IP" --protocol '
            + reverse_protocol
            + ' --port "$'
            + reverse_port
            + '" --duration "$DURATION" --repeats "$REPEATS" --expected-probe-id "$SOURCE_SERVER_ID"'
            + reverse_extra,
            "Use the matching opposite-direction saved samples/thresholds. Retain receiver-confirmed delivery, not only sender throughput.",
        )
    return changes_state, protocol


def _traffic_recipe(state: Any) -> tuple[bool, str]:
    protocol = state.protocol
    category = state.category
    details = state.details
    gaps = state.gaps
    parameter = state.parameter
    step = state.step
    path = state.path
    probe_command = state.probe_command
    expected_probe = state.expected_probe
    changes_state = False
    if category in {"controller-bootstrap", "execution-control"}:
        gaps.append(
            "This is a control/setup result, not a VM traffic procedure. Inspect its exact API/SSH operations and run settings; no fictitious endpoint probe is supplied."
        )
    elif any(word in category for word in ("mtu", "packet-size", "fragmentation")):
        parameter(
            "MTU",
            "Advertised effective network/path MTU",
            details.get("network_mtu")
            or path.get("expected_mtu")
            or _mapping(details.get("mtu_contract")).get("expected_mtu"),
            "number",
        )
        step(
            "Repeat the MTU boundary check",
            "Source VM",
            'python3 "$HELPER" mtu-client --source "$SOURCE_IP" --destination "$DESTINATION_IP" --mtu "$MTU"',
            "Preserve IP family and DF behavior; distinguish payload length, full IP packet size, local rejection and destination-confirmed delivery.",
        )
        if category in {"floating-ip-egress-fragmentation", "source-nat-packet-size"}:
            gaps.append(
                "This assertion includes observer-confirmed translation/fragment delivery. The MTU boundary helper alone does not reproduce that observer assertion; use the saved stage commands and the matching provider observer workflow. Do not infer fragment delivery from a local send return code."
            )
    else:
        step(
            "Run the selected traffic probe", "Source VM", probe_command, expected_probe
        )

    return changes_state, protocol
