from __future__ import annotations

import copy
import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from neutron_flux.reporting_components.html import render_html
from neutron_flux.reporting_components.manual_recipes import build_recipe
from neutron_flux.reporting_components.manual_reproduction import manual_reproduction

from .test_report_workflow import _payload


def traffic_result(category="same-subnet", **details):
    return {
        "test_id": "MANUAL-CHECK",
        "category": category,
        "family": 4,
        "source": "Source VM (192.0.2.10)",
        "destination": "Destination VM (192.0.2.20)",
        "expected": "reachable",
        "details": {
            "source_server_id": "source-current-id",
            "destination_server_id": "destination-current-id",
            "protocol": "tcp",
            "probe": {
                "command": "python3 saved-original.py",
                "diagnostics": {"destination_port": 18080},
            },
            **details,
        },
    }


@pytest.mark.parametrize(
    "assertion",
    [
        "fresh-functional-matrix",
        "bound-to-destination",
        "endpoint-ready",
        "host-placement-known",
    ],
)
def test_read_only_placement_assertions_never_submit_migration(assertion):
    result = traffic_result("compute-placement", server_id="moving-id")
    result["expected"] = assertion
    guide = manual_reproduction(result)
    assert not guide["changes_state"]
    assert not any(
        "server migrate" in row["command"] for row in guide["recipe"]["steps"]
    )
    assert "Perform only the migration" not in " ".join(guide["actions"])


@pytest.mark.parametrize("stage", ["pre-migration", "initial-placement"])
def test_resolution_only_placement_summary_uses_supporting_guides_without_fake_vm(
    stage,
):
    result = {
        "category": "compute-placement",
        "expected": "Functional connectivity has been tested",
        "reporting_context": {"execution_stage": stage},
        "details": {"resolution_only": True, "planned_check_id": "BASELINE"},
    }
    recipe = build_recipe(
        result,
        {
            "planned_check_ledger": [
                {"id": "BASELINE", "prerequisites": ["A-B-TCP", "B-A-UDP"]}
            ]
        },
    )
    assert not recipe["changes_state"]
    assert not recipe["steps"]
    assert not any(row["name"] == "MOVING_SERVER_ID" for row in recipe["parameters"])
    assert "No endpoint VM UUIDs" in " ".join(recipe["incomplete"])
    assert "A-B-TCP" in " ".join(recipe["notes"])
    if stage == "pre-migration":
        assert "ICMP, TCP and UDP rows in both directions" in " ".join(recipe["notes"])


def test_server_start_responder_is_started_only_after_active_api_state():
    recipe = build_recipe(traffic_result("server-lifecycle", operation="server-start"))
    assert not any(
        "probe-server" in row["command"]
        for row in recipe["steps"]
        if row["phase"] == "prepare"
    )
    titles = [row["title"] for row in recipe["steps"]]
    assert titles.index("Verify the stopped starting state") < titles.index(
        "Perform the recorded start operation"
    )
    assert titles.index("Perform the recorded start operation") < titles.index(
        "Restart the temporary responder after guest recovery"
    )
    assert titles.index(
        "Restart the temporary responder after guest recovery"
    ) < titles.index("Check service state after the operation")


def test_security_deny_is_read_only_but_allow_has_an_exact_restore():
    denied = build_recipe(traffic_result("security-group", operation="security-deny"))
    assert not denied["changes_state"]
    assert not any(
        "rule create" in row["command"] or "rule delete" in row["command"]
        for row in denied["steps"]
    )
    allowed = build_recipe(traffic_result("security-group", operation="security-allow"))
    assert allowed["changes_state"]
    assert any(
        '--remote-group "$SOURCE_SECURITY_GROUP_ID"' in row["command"]
        for row in allowed["steps"]
    )
    assert any(
        'rule delete "$RULE_ID"' in row["command"] and row["phase"] == "restore"
        for row in allowed["steps"]
    )


def test_floating_ip_recipe_orders_api_withdrawal_and_exact_restoration():
    result = traffic_result("floating-ip-lifecycle", operation="fip-withdraw")
    recipe = build_recipe(result)
    commands = [row["command"] for row in recipe["steps"]]
    detach = next(
        index
        for index, command in enumerate(commands)
        if "floating ip unset --port" in command
    )
    restore = next(
        index
        for index, command in enumerate(commands)
        if "floating ip set --port" in command
    )
    assert detach < restore
    assert "NF_WAIT_FIP" in commands[detach]
    assert '--fixed-ip-address "$DESTINATION_FIXED_IP"' in commands[restore]
    assert not any("floating ip delete" in command for command in commands)
    # Python polling inputs must also be exported by the copyable block.
    assert {"FLOATING_IP_ID", "DESTINATION_PORT_ID", "DESTINATION_FIXED_IP"} <= set(
        recipe["steps"][restore]["parameters"]
    )


def test_current_nat_identity_and_token_are_shared_not_replaced_in_history():
    result = traffic_result(
        "floating-ip-peer", nat_path="self-hairpin", protocol="icmp"
    )
    result["details"]["probe"]["diagnostics"] = {
        "icmp_destination_attestation": {
            "command": "observer --token old-token --address 192.0.2.20"
        },
        "expected_translated_sources": ["198.51.100.4"],
    }
    original = copy.deepcopy(result)
    guide = manual_reproduction(result)
    recipes = guide["recipe"]["steps"]
    capture = next(row for row in recipes if "icmp-observer" in row["command"])
    ping = next(row for row in recipes if row["command"].startswith("ping "))
    assert '--token "$TOKEN"' in capture["command"]
    assert '-p "$TOKEN"' in ping["command"]
    assert '--expected-peer-ip "$EXPECTED_PEER_IP"' in capture["command"]
    assert "same VM" in " ".join(guide["recipe"]["notes"])
    assert (
        guide["commands"][0]["command"]
        == "observer --token old-token --address 192.0.2.20"
    )
    assert result == original


def test_performance_uses_recorded_profile_identities_ports_and_reverse_role():
    result = traffic_result(
        "network-performance",
        measurement="udp",
        path={
            "source_ip": "192.0.2.10",
            "destination_ip": "192.0.2.20",
            "source_server_id": "a",
            "destination_server_id": "b",
            "reverse_destination_ip": "198.51.100.10",
        },
    )
    result["details"].pop("protocol")
    result["details"].pop("source_server_id")
    result["details"].pop("destination_server_id")
    tcp = traffic_result(destination_server_id="b", protocol="tcp")
    udp = traffic_result(
        destination_server_id="b",
        protocol="udp",
        probe={"diagnostics": {"destination_port": 18081}},
    )
    recipe = build_recipe(
        result,
        {
            "results": [tcp, udp],
            "configuration": {
                "performance_duration_seconds": 3,
                "performance_repeats": 2,
                "performance_tcp_streams": [1, 4],
                "performance_udp_rates_mbps": [10],
                "performance_udp_packet_sizes": [128, 1200],
            },
        },
    )
    parameters = {row["name"]: row["recorded"] for row in recipe["parameters"]}
    assert {
        name: parameters[name]
        for name in (
            "DURATION",
            "REPEATS",
            "RATE_MBPS",
            "PACKET_SIZE",
            "TCP_PORT",
            "UDP_PORT",
        )
    } == {
        "DURATION": "3",
        "REPEATS": "2",
        "RATE_MBPS": "10",
        "PACKET_SIZE": "128",
        "TCP_PORT": "18080",
        "UDP_PORT": "18081",
    }
    reverse = next(
        row
        for row in recipe["steps"]
        if row["title"] == "Run the reverse-direction sample"
    )
    assert '--source "$DESTINATION_FIXED_IP"' in reverse["command"]
    assert '--expected-probe-id "$SOURCE_SERVER_ID"' in reverse["command"]
    assert parameters["REVERSE_TARGET_IP"] == "198.51.100.10"
    assert recipe["protocol"] == "UDP"


def test_mtu_boundary_recipe_does_not_claim_to_reproduce_tcp_mss():
    recipe = build_recipe(traffic_result("network-performance", measurement="mtu-mss"))
    assert any(
        "does not reproduce the TCP client/server MSS" in gap
        for gap in recipe["incomplete"]
    )


@pytest.mark.parametrize(
    "category,operation",
    [
        ("same-subnet", "probe"),
        ("server-lifecycle", "server-stop"),
        ("server-lifecycle", "server-start"),
        ("floating-ip-lifecycle", "fip-withdraw"),
        ("router-interface-lifecycle", "router-interface"),
        ("security-group", "security-allow"),
        ("router-static-routing", "static-route-install"),
    ],
)
def test_generated_shell_and_embedded_poll_programs_are_syntax_valid(
    category, operation
):
    recipe = build_recipe(traffic_result(category, operation=operation))
    for step in recipe["steps"]:
        command = "(\nset -eu\n" + step["command"] + "\n)\n"
        syntax = subprocess.run(
            ["bash", "-n"], input=command, text=True, capture_output=True, check=False
        )
        assert syntax.returncode == 0, syntax.stderr
        for program in re.findall(r"<<'(NF_[A-Z_]+)'\n(.*?)\n\1", command, re.S):
            compile(program[1], "manual-poll", "exec")


def test_manual_prepare_copy_uses_edits_without_changing_historical_evidence(
    tmp_path: Path,
):
    payload = _payload()
    row = payload["results"][0]
    row["details"].update(protocol="tcp", destination_server_id="historical-id")
    row["details"]["probe"].update(
        command="python3 saved-original.py", diagnostics={"destination_port": 18080}
    )
    report = tmp_path / "report.html"
    report.write_text(render_html(payload))
    script = Path(__file__).with_name("manual_recipes_dom.cjs")
    result = subprocess.run(
        ["node", str(script), str(report)],
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["passed"]
