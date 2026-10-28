"""Manual procedures and exact recorded commands, without inventing run inputs.

These are report instructions only. The report never executes these operations.
Missing resource IDs, policy, listeners or ordered changes stay explicit gaps.
"""

from __future__ import annotations

import shlex
from typing import Any

from .manual_recipes import build_recipe

_SETUP = {
    "same-subnet": "Attach both test VMs to the recorded subnet. Keep management access separate from the interface being tested.",
    "cross-zone-connectivity": "Place the source and destination VMs in their recorded availability zones and attach each to its recorded network and subnet.",
    "project-network-routing": "Create the two recorded project subnets and attach both to one test router. Put one VM on each subnet; verify the router interfaces and guest gateways.",
    "router-static-routing": "Recreate the two routers, endpoint subnets and transit network. Save each router's route list and match the recorded phase before testing with or without the static routes.",
    "project-provider-connectivity": "Place one VM on the project network and the other on the provider network. Match the recorded router, gateway and routing policy; an address range does not establish whether communication should be allowed.",
    "provider-network-connectivity": "Use the two recorded provider networks. Keep their existing routing and isolation policy; compare against this test's expected result.",
    "egress": "Use the source VM's recorded network and gateway, and the recorded external destination. Verify the source interface and IP family before testing.",
    "controller-bootstrap": "Prepare the controller's management network, credentials, guest initialization and probe services using the run settings. Check runner-to-controller access first.",
    "execution-control": "Identify the operation and first error in the saved evidence. Check that operation's inputs, access and required resources before retrying it.",
}

_CHANGES = {
    "security-group": (
        "Save the original security-group rules and port associations. Confirm the destination listener and a passing baseline before changing rules.",
        "Apply the rule change named by this test to the disposable test port. Repeat the same probe with the recorded protocol and port; compare the expected allowed or denied behavior.",
        "Restore the saved rules and port associations, then repeat the baseline probe.",
    ),
    "server-lifecycle": (
        "Identify the test VM and save its initial power state. Confirm a passing baseline and management access before the lifecycle action.",
        "Perform the stop, start or reboot operation named by this test. Wait for the corresponding server state, then repeat the recorded connectivity probe.",
        "Restore the original server state, wait for guest initialization and repeat the baseline probe.",
    ),
    "router-interface-lifecycle": (
        "Save the test router's interface ports, subnet IDs and addresses. Confirm baseline connectivity and independent access to both VMs.",
        "Detach or reattach the interface identified by the test phase. Wait for the change, then repeat the same probe and record both the router state and result.",
        "Restore the saved router interface and address configuration, then repeat the baseline probe.",
    ),
    "floating-ip-lifecycle": (
        "Save the floating IP's port and fixed-IP association. Verify the observer can reach the floating IP before the change.",
        "Apply the detach, reassociation or restoration named by the test phase. Probe from the same observer and confirm the association at each step.",
        "Restore the saved floating-IP association and repeat the baseline ingress probe.",
    ),
    "compute-placement": (
        "Record the source and destination compute hosts, VM storage and migration mode. Confirm the functional baseline and save the initial placement.",
        "Perform only the migration stage named by this result using the recorded mode. Wait for the migration and VM to settle, confirm the actual compute host and repeat the same functional or performance checks.",
        "Confirm the final VM state and placement. Restore the agreed test placement if required, then repeat the baseline checks.",
    ),
    "source-nat-setting": (
        "Save the project router and external gateway configuration. Use the cloud's project-member default for source NAT.",
        "Inspect the recorded source-NAT setting and test external reachability from the project VM. Do not assume that an observed setting alone proves translation.",
        "Remove only the disposable router and networks created for this reproduction.",
    ),
}


def _commands(details: dict[str, Any]) -> tuple[list[dict[str, str]], list[str]]:
    commands: list[dict[str, str]] = []
    missing: list[str] = []
    seen: set[str] = set()

    def visit(value: Any, location: str) -> None:
        if isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{location}[{index}]")
        elif isinstance(value, dict):
            command = value.get("command")
            if isinstance(command, list) and all(isinstance(v, str) for v in command):
                command = shlex.join(command)
            if isinstance(command, str) and command.strip() and command not in seen:
                seen.add(command)
                if len(command) > 32_000:
                    missing.append(
                        "A long command is available only in results.json; it has not been shortened into a copyable command."
                    )
                elif len(commands) < 24:
                    context = "Recorded operation; confirm the execution location in the evidence"
                    if "icmp_destination_attestation" in location:
                        context = (
                            "Destination VM data-port observer: run FIRST in a separate terminal; "
                            "wait for NF_ICMP_READY, then run the recorded tokenized ping on the SOURCE VM"
                        )
                    elif command.lstrip().startswith("openstack "):
                        context = "Runner with the same project and region credentials"
                    elif any(
                        key in location
                        for key in ("probe", "tcp_baseline", "endpoint_route")
                    ):
                        context = "Recorded probe endpoint; use the source VM or observer shown in the test"
                    commands.append(
                        {"command": command, "location": location, "context": context}
                    )
                else:
                    missing.append(
                        "Further commands are in results.json. This report lists the first 24 distinct commands for this result."
                    )
            for key, child in value.items():
                if key not in {"command", "stdout", "stderr", "raw"}:
                    visit(child, f"{location}.{key}")

    visit(details, "details")
    commands.sort(
        key=lambda item: "icmp_destination_attestation" not in item["location"]
    )
    return commands, list(dict.fromkeys(missing))


def manual_reproduction(
    result: dict[str, Any], *, context: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Build guidance for every outcome, including an unexecuted planned check."""
    details = result.get("details") or {}
    category = str(details.get("base_category") or result.get("category") or "")
    self_hairpin = details.get("nat_path") == "self-hairpin"
    commands, missing = _commands(details)
    setup = [
        _SETUP.get(
            category,
            "Recreate the source and destination networks, subnets, router connections and host placement recorded for this test. Keep an independent management connection.",
        )
    ]
    actions = [
        "Run the recorded probe from its recorded execution location. Keep its protocol, source binding, destination port, packet size, timeout and repeat count."
    ]
    restore = [
        "Remove only the disposable resources created for this reproduction; retain existing provider networks and shared infrastructure."
    ]
    change = _CHANGES.get(category)
    changed = bool(change or category == "router-static-routing")
    if change:
        setup.append(change[0])
        actions = [change[1]]
        restore.insert(0, change[2])
    if category == "router-static-routing":
        actions = [
            "Match the baseline or configured-route phase named by the test. Apply the saved destination/next-hop routes to the test routers only when that phase requires them; repeat the endpoint probe in both directions."
        ]
        restore.insert(
            0, "Restore both routers' saved route lists and repeat the baseline check."
        )
    if category.startswith("floating-ip"):
        if self_hairpin:
            setup = [
                "Use one test VM with the recorded fixed-IP port and its own floating-IP association on the recorded external network. Run the probe inside that VM against its own floating IP; retain independent management access."
            ]
        else:
            setup.append(
                "Use the recorded external network, floating-IP associations and fixed-IP ports. Match the probe source, destination and direction shown in the evidence; use a separate observer only when the recorded check requires one."
            )
    if any("icmp_destination_attestation" in item["location"] for item in commands):
        setup.append(
            "The ICMP destination observer needs root or passwordless sudo with CAP_NET_RAW. "
            "It is read-only and stops automatically; "
            + (
                "run the observer and source ping in separate terminals on the same VM for this self-hairpin check."
                if self_hairpin
                else "run its recorded command on the destination, not the source."
            )
        )
        actions.insert(
            0,
            "Start the destination observer and wait for NF_ICMP_READY. Before its 15-second capture deadline, "
            "run the recorded source ping with the identical -p token. Compare destination requests and translated source; "
            "a successful ping alone does not reproduce the identity assertion.",
        )
    if category in {"source-nat-packet-size", "floating-ip-egress-source-address"}:
        setup.append(
            "Use an external observer that records the received source address. Match the recorded floating-IP or source-NAT arrangement; local guest output alone cannot confirm the translated address."
        )
    if category == "network-performance":
        setup.append(
            "Start the destination service required by the recorded measurement. Match the protocol, listener port, direction, stream count, rate, duration and repeat count from the saved samples."
        )
        actions = [
            "Repeat the recorded measurement in each recorded direction. Retain sender and receiver output and use the recorded thresholds; one ping does not reproduce a performance measurement."
        ]
        restore.insert(
            0,
            "Stop the temporary measurement listeners and restore any test firewall changes.",
        )
    if any(word in category for word in ("mtu", "packet-size", "fragmentation")):
        setup.append(
            "Record interface and network MTUs at both ends. Preserve the packet-size sequence, IP family, fragmentation flags and external observer requirements shown in the evidence."
        )
        actions = [
            "Repeat the saved packet-size probes in order, including the boundary checks. Record delivery, ICMP errors and observer evidence; distinguish the IP packet size from ping's payload size."
        ]
    protocol = str(details.get("protocol") or "").upper()
    if protocol in {"TCP", "UDP"}:
        setup.append(
            f"Start the matching {protocol} destination listener or echo service and verify its port and response behavior before running the client command."
        )
    failure = {
        key: details[key]
        for key in (
            "exception_type",
            "exception_message",
            "failure_phase",
            "operation",
            "root_setup_result_id",
            "root_setup_error",
            "root_lane_error",
        )
        if isinstance(details.get(key), (str, int, float, bool))
    }
    if not commands:
        missing.append(
            "No exact shell command was saved for this result. Use its supporting attempts and the ordered procedure below; do not treat a generated command as a recorded one."
        )
    if changed:
        missing.append(
            "Confirm the affected resource IDs, ordered state changes and original values in the saved evidence before replaying the procedure."
        )
    missing.append(
        "Use current resource IDs and allocated addresses. Confirm the original security policy, listener setup and any values absent from this report in results.json."
    )
    recipe = build_recipe(result, context)
    if category == "compute-placement":
        setup = [
            "Identify the disposable VM, its current compute host and availability zone, data ports and independent management access. Match the specific assertion in this result."
        ]
        actions = [
            step["title"] + ": " + step["expected"]
            for step in recipe["steps"]
            if step["phase"] == "run"
        ]
        restore = [
            "Keep the approved final placement. Do not submit an additional migration while reproducing a read-only placement assertion."
        ]
    return {
        "version": 2,
        "setup": setup,
        "actions": actions,
        "restore": restore,
        "commands": commands,
        "missing": missing,
        "changes_state": recipe["changes_state"],
        "protocol": protocol,
        "failure": failure,
        "recipe": recipe,
        "dependencies": [
            str(value)
            for value in (details.get("dependencies") or [])
            if isinstance(value, (str, int))
        ],
    }
