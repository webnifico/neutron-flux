from __future__ import annotations

import contextlib
import copy
import io
import json
import re
import subprocess
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from neutron_flux.models import ProbeResult
from neutron_flux.models import TestSpec as FluxTestSpec
from neutron_flux.mtu_probes import fragmentation_probe_code
from neutron_flux.reporting_components.dashboard_model import build_dashboard_model
from neutron_flux.reporting_components.html import render_html
from support.tests._shared import build_plan
from support.tests.test_engine_handlers import _engine
from support.tests.test_offline_reports_and_concurrent_load import _payload


def _completed(returncode=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def _execute_generated(code: str, run) -> dict:
    module = types.ModuleType("subprocess")
    module.PIPE = object()
    module.run = run
    original = sys.modules.get("subprocess")
    sys.modules["subprocess"] = module
    output = io.StringIO()
    try:
        with contextlib.redirect_stdout(output):
            exec(code, {})
    finally:
        if original is None:
            sys.modules.pop("subprocess", None)
        else:
            sys.modules["subprocess"] = original
    return json.loads(output.getvalue().splitlines()[-1])


def test_jumbo_probe_separates_df_path_mtu_from_ipv4_fragmentation():
    modes: list[str] = []

    def run(command, **_kwargs):
        if command[0] == "ping":
            mode = command[command.index("-M") + 1]
            modes.append(mode)
            if mode == "do":
                return _completed(1, "", "100% packet loss")
            return _completed(0, "1 packets transmitted, 1 received, 0% packet loss")
        if command[:5] == ["ip", "-4", "-j", "route", "get"]:
            return _completed(
                0, json.dumps([{"dev": "ens4", "prefsrc": "10.0.0.5", "mtu": 1500}])
            )
        if command[:4] == ["ip", "-j", "link", "show"]:
            return _completed(0, json.dumps([{"ifname": "ens4", "mtu": 9000}]))
        if command[:4] == ["ip", "-j", "address", "show"]:
            return _completed(0, json.dumps([{"ifname": "ens4", "addr_info": []}]))
        raise AssertionError(command)

    result = _execute_generated(
        fragmentation_probe_code("10.0.0.5", "198.51.100.10", 4, 9000, 1500),
        run,
    )
    assert result["tested_packet_size"] == 9000
    assert result["path_mtu"] == 1500
    assert result["capability"] == "supported"
    assert result["fragmentation_model"] == "ipv4-fragmentation-permitted"
    assert result["router_fragmentation_applicable"] is True
    assert modes.count("do") == 3
    assert modes.count("dont") == 3


def test_ipv6_jumbo_probe_states_source_fragmentation_boundary():
    code = fragmentation_probe_code("fd00::10", "fd00::20", 6, 9000, 1500)
    assert "ipv6-source-fragmentation-only" in code
    assert "router_fragmentation_applicable" in code
    assert "'-M', pmtud_mode" in code


def test_plan_profiles_router_snat_and_floating_ip_egress(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    router_snat = [x for x in plan.tests if x.category == "source-nat-packet-size"]
    floating_egress = [
        x for x in plan.tests if x.category.startswith("floating-ip-egress-")
    ]
    assert router_snat
    assert floating_egress
    assert all(x.operation == "snat-packet-size-profile" for x in router_snat)
    assert {
        "fip-egress-source-address",
        "fip-egress-mtu",
        "fip-egress-fragmentation",
    } == {x.operation for x in floating_egress}
    assert all(x.metadata["require_no_floating_ip"] for x in router_snat)
    assert all(
        x.metadata["egress_translation_mode"] == "router-source-nat"
        for x in router_snat
    )
    assert all(x.metadata["require_floating_ip"] for x in floating_egress)
    assert all(
        x.metadata["egress_translation_mode"] == "floating-ip-egress"
        for x in floating_egress
    )
    assert all("execution_policy" not in x.metadata for x in floating_egress)
    assert max(plan.tests.index(x) for x in router_snat) < min(
        plan.tests.index(x) for x in plan.tests if x.category == "floating-ip"
    )


def test_floating_ip_egress_verifies_translation_with_provider_observer(
    config_factory,
):
    engine, provider, project, groups, _records = _engine(config_factory)
    groups["target"].source_nat_enabled = True
    groups["target"].fips[project.label] = {"id": "fip-id", "address": "203.0.113.10"}
    engine.lifecycle["fip:target"] = {"address": "203.0.113.10"}
    provider.metadata["probe_service"] = {"ready": True, "tcp_port": 18080}
    engine.builder.capture_router_state = mock.Mock(
        return_value={
            "external_gateway_info": {
                "enable_snat": True,
                "external_fixed_ips": [{"ip_address": "203.0.113.1"}],
            }
        }
    )
    engine.probes.tcp.endpoint_peer_identity.return_value = ProbeResult(
        outcome="reachable",
        success=True,
        elapsed_ms=5,
        attempts=1,
        diagnostics={"observed_peer_ip": "203.0.113.10"},
    )
    recorded: list[tuple[tuple, dict]] = []
    engine.reporter = SimpleNamespace(result=lambda *a, **kw: recorded.append((a, kw)))
    spec = FluxTestSpec(
        id="FIP-EGRESS-SOURCE-ADDRESS",
        category="floating-ip-egress-source-address",
        operation="fip-egress-source-address",
        family=4,
        expectation="provider-observes-floating-ip",
        expectation_reason="test floating-IP egress",
        authoritative=True,
        dependencies=["target", "source"],
        source_group_id="target",
        destination_group_id="source",
        source_side="B",
        destination_side="A",
        source_subnet_id="subnet",
        destination_subnet_id="subnet",
        protocol="tcp",
        metadata={
            "egress_translation_mode": "floating-ip-egress",
            "require_floating_ip": True,
        },
    )
    engine._run_fip_egress_source_address(spec)
    args, kwargs = recorded[-1]
    assert args[2] == "PASS"
    assert (
        kwargs["details"]["translated_source_ip_observed_by_provider"] == "203.0.113.10"
    )
    assert kwargs["details"]["translation_matches_expected_identity"] is True
    engine.probes.tcp.endpoint_peer_identity.assert_called_once()


def _topology_payload() -> dict:
    payload = _payload("sample-topology")
    payload["plan"] = {
        "tenant_groups": [
            {
                "id": "project-v4",
                "kind": "tenant-pool",
                "families": [4],
                "pool_id": "pool-v4",
                "pool_name": "SelfServeIPv4",
                "address_scope_id": "scope-v4",
                "prefix_length": 27,
            }
        ]
    }
    payload["resources"] = [
        {
            "resource_type": "subnet",
            "id": "subnet-v4",
            "name": "generated-subnet",
            "parent_id": "network-v4",
            "metadata": {
                "pool_id": "pool-v4",
                "scope_id": "scope-v4",
                "cidr": "10.0.3.96/27",
                "group_id": "project-v4",
            },
        }
    ]
    result = copy.deepcopy(payload["results"][0])
    result.update(
        {
            "test_id": "PROJECT-PATH",
            "source": "Project endpoint A (10.0.3.107)",
            "destination": "Flux runner (192.0.2.10)",
            "scenario": "Project-network external egress through router source NAT",
        }
    )
    result["details"] = {
        "path_kind": "source-nat-to-runner",
        "egress_translation_mode": "router-source-nat",
        "source_network_mtu": 9000,
        "runner_interface_mtu": 9000,
        "external_provider_network_mtu": 1500,
        "expected_no_fragment_path_mtu": 1500,
        "translated_source_ip_observed_by_runner": "203.0.113.1",
        "expected_translation_ips": ["203.0.113.1"],
        "translation_matches_expected_identity": True,
        "mtu_profile": {
            "discovered_mtu": 1500,
            "discovery_confidence": "expected-confirmed",
        },
        "fragmentation_profile": {
            "capability": "supported",
            "fragmentation_model": "ipv4-fragmentation-permitted",
            "tested_packet_size": 9000,
            "reason": "source-sized packet crossed when fragmentation was permitted",
        },
    }
    payload["results"] = [result]
    return payload


def test_dashboard_models_recorded_subnet_pool_and_jumbo_capability(tmp_path: Path):
    payload = _topology_payload()
    model = build_dashboard_model(payload)
    assert model["model_version"] == 15
    assert "topology" not in model
    assert model["environment"]["subnet_pools"][0]["name"] == "SelfServeIPv4"
    path = model["paths"][0]
    assert path["source_addressing"]["cidr"] == "10.0.3.96/27"
    assert path["source_addressing"]["subnet_pool_name"] == "SelfServeIPv4"
    mtu = path["measurements"]["mtu-mss"]["values"]
    assert mtu["source_mtu"] == 9000
    assert mtu["destination_mtu"] == 9000
    assert mtu["external_provider_mtu"] == 1500
    assert mtu["forward_fragmentation_capability"] == "supported"
    assert mtu["translated_source_ip"] == "203.0.113.1"

    html = render_html(payload)
    for marker in (
        "Technical path evidence",
        "Recorded endpoint pair",
        "Recorded route lookup",
        "Network inventory",
        "Confirmed MTU",
    ):
        assert marker in html
    assert "direct L2" not in html
    assert "direct L3" not in html
    scripts = [
        body
        for attrs, body in re.findall(
            r"<script([^>]*)>(.*?)</script>", html, re.S | re.I
        )
        if "application/json" not in attrs.lower() and body.strip()
    ]
    script = tmp_path / "sample-dashboard.js"
    script.write_text("\n".join(scripts), encoding="utf-8")
    subprocess.run(["node", "--check", str(script)], check=True, capture_output=True)


def test_operator_labels_replace_legacy_tenant_wording():
    payload = _payload("sample-operator-language")
    payload["results"][0].update(
        {
            "display_name": "Tenant same-network connectivity — IPv4 A to B TCP",
            "scenario": "Tenant-visible network performance",
            "message": "Completed tenant network test through a tenant router with extra routes",
            "source": "IPv4 tenant connectivity through Public3:A (10.0.0.10)",
            "destination": "IPv4 tenant connectivity through Public3:B (10.0.0.11)",
        }
    )
    payload["results"][0]["details"] = {}
    result = build_dashboard_model(payload)["results"][0]
    assert (
        result["title"]
        == "Test TCP connectivity between VMs on the same project subnet"
    )
    assert result["scenario_label"] == "Network path performance"
    assert "tenant" not in result["operator_message"].lower()
    assert "tenant" not in result["source_display"]["label"].lower()
    assert "tenant" not in result["destination_display"]["label"].lower()
    assert "static routes" in result["operator_message"].lower()
