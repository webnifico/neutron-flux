from __future__ import annotations

import re
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from neutron_flux.models import ResourceRecord
from neutron_flux.reporting_components.dashboard_model import build_dashboard_model
from neutron_flux.reporting_components.html import render_html
from neutron_flux.runtime.router import RouterRuntimeMixin
from support.tests.test_topology_and_jumbo_paths import _topology_payload


class _RouterRecorder(RouterRuntimeMixin):
    def __init__(self, resource: ResourceRecord):
        self.reporter = SimpleNamespace(
            resources=[resource],
            update_resource=mock.Mock(),
        )


def test_persists_exact_router_interface_and_external_gateway_addresses():
    resource = ResourceRecord(
        sequence=1,
        resource_type="router",
        id="router-1",
        name="router-one",
        parent_id=None,
        metadata={},
        created_at="2026-07-25T00:00:00Z",
    )
    recorder = _RouterRecorder(resource)
    recorder._record_router_addresses(
        "router-1",
        interface_addresses=[
            {
                "subnet_id": "subnet-a",
                "network_id": "network-a",
                "ip_address": "10.0.3.97",
                "purpose": "project subnet A",
            }
        ],
        external_gateway_info={
            "network_id": "external-network",
            "enable_snat": True,
            "external_fixed_ips": [
                {"subnet_id": "external-subnet", "ip_address": "203.0.113.14"}
            ],
        },
    )

    assert resource.metadata["interface_addresses"] == [
        {
            "subnet_id": "subnet-a",
            "network_id": "network-a",
            "ip_address": "10.0.3.97",
            "purpose": "project subnet A",
        }
    ]
    assert resource.metadata["external_gateway_addresses"] == [
        {"subnet_id": "external-subnet", "ip_address": "203.0.113.14"}
    ]
    assert resource.metadata["external_network_id"] == "external-network"
    recorder.reporter.update_resource.assert_called_once_with(resource)


def _router_address_payload() -> dict:
    payload = _topology_payload()
    payload.setdefault("discovery", {})
    payload["discovery"]["networks"] = [
        {
            "id": "network-v4",
            "name": "Project network A",
            "network_type": "geneve",
            "mtu": 8942,
            "external": False,
            "shared": False,
        },
        {
            "id": "external-network",
            "name": "Public3",
            "network_type": "flat",
            "physical_network": "provider3",
            "mtu": 1500,
            "external": True,
            "shared": True,
        },
    ]
    payload["discovery"]["subnets"] = [
        {
            "id": "subnet-v4",
            "name": "project-subnet-a",
            "cidr": "10.0.3.96/27",
            "gateway_ip": "10.0.3.97",
            "network_id": "network-v4",
            "subnetpool_id": "pool-v4",
            "address_scope_id": "scope-v4",
            "allocation_pools": [{"start": "10.0.3.98", "end": "10.0.3.126"}],
        },
        {
            "id": "external-subnet",
            "name": "Public3 subnet",
            "cidr": "203.0.113.0/24",
            "gateway_ip": "203.0.113.1",
            "network_id": "external-network",
            "subnetpool_id": None,
            "address_scope_id": None,
            "allocation_pools": [{"start": "203.0.113.10", "end": "203.0.113.200"}],
        },
    ]
    payload["resources"].extend(
        [
            {
                "resource_type": "network",
                "id": "network-v4",
                "name": "generated-project-network-a",
                "parent_id": None,
                "metadata": {
                    "role": "tenant-pool",
                    "group_id": "project-v4",
                    "scenario_side": "a",
                },
            },
            {
                "resource_type": "router",
                "id": "router-1",
                "name": "generated-router-a",
                "parent_id": None,
                "metadata": {
                    "role": "tenant-pool",
                    "group_id": "project-v4",
                    "external_network_id": "external-network",
                    "external_subnet_id": "external-subnet",
                    "interface_addresses": [
                        {
                            "subnet_id": "subnet-v4",
                            "network_id": "network-v4",
                            "ip_address": "10.0.3.97",
                            "purpose": "router-connected project subnet",
                        }
                    ],
                    "external_gateway_addresses": [
                        {
                            "subnet_id": "external-subnet",
                            "ip_address": "203.0.113.14",
                        }
                    ],
                },
            },
        ]
    )
    return payload


def test_network_labels_and_paths_include_recorded_subnet_facts():
    model = build_dashboard_model(_router_address_payload())

    networks = {row["id"]: row for row in model["environment"]["networks"]}
    assert networks["network-v4"]["label"] == "Project network A — 10.0.3.96/27"
    assert networks["external-network"]["label"] == "Public3 — 203.0.113.0/24"

    assert "topology" not in model

    path = model["paths"][0]
    assert (
        path["source_addressing"]["network_label"] == "Project network A — 10.0.3.96/27"
    )
    assert path["source_addressing"]["gateway_ip"] == "10.0.3.97"


def test_older_flux_created_subnet_gateway_is_not_reconstructed():
    payload = _topology_payload()
    model = build_dashboard_model(payload)
    subnet = next(
        row for row in model["environment"]["subnets"] if row["id"] == "subnet-v4"
    )
    assert subnet["gateway_ip"] is None
    assert subnet["gateway_ip_source"] is None


def test_dashboard_renders_network_cidrs_without_router_reconstruction(
    tmp_path: Path,
):
    html = render_html(_router_address_payload())
    for marker in (
        "Network inventory",
        "Project network A — 10.0.3.96/27",
        "Public3 — 203.0.113.0/24",
    ):
        assert marker in html
    assert "Router interfaces and gateway addresses" not in html
    assert "203.0.113.14 / 10.0.3.97" not in html
    assert "inferred" not in html.lower()

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
