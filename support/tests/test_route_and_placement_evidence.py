from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

from neutron_flux.engine import TestEngine as FluxTestEngine
from neutron_flux.models import Endpoint, ProbeResult
from neutron_flux.models import TestSpec as FluxTestSpec
from neutron_flux.policy import PolicyEvaluator
from neutron_flux.reporting_components.dashboard_findings import finding_measurements
from neutron_flux.reporting_components.dashboard_model import (
    build_dashboard_model,
    friendly_title,
)
from neutron_flux.reporting_components.report_payload import (
    _recorded_route_observations,
)


def _endpoint(label: str, side: str, address: str) -> Endpoint:
    return Endpoint(
        label=label,
        server_id=f"server-{side.lower()}",
        server_name=f"server-{side.lower()}",
        management_port_id=f"mgmt-{side.lower()}",
        management_ip=f"10.254.0.{10 if side == 'A' else 11}",
        test_port_id=f"test-{side.lower()}",
        test_mac=f"fa:16:3e:00:00:{'01' if side == 'A' else '02'}",
        fixed_ips={"subnet": address},
        host="admin-only-host",
        availability_zone="az1",
        volume_id=None,
        side=side,
    )


def test_route_lookup_is_persisted_once_per_direction_with_host_evidence():
    engine = object.__new__(FluxTestEngine)
    engine.policy = PolicyEvaluator()
    engine.diagnostics = mock.Mock()
    engine.reporter = mock.Mock()
    from neutron_flux.engine_state import RouteObservationCache

    engine._route_observation_cache = RouteObservationCache()
    route = {
        "returncode": 0,
        "command": "ip -4 route get 10.0.0.11 from 10.0.0.10",
        "stdout": "10.0.0.11 dev eth1 src 10.0.0.10",
        "stderr": "",
    }
    engine.builder = SimpleNamespace(
        inspect_endpoint_route=mock.Mock(return_value=route)
    )
    source = _endpoint("project:A", "A", "10.0.0.10")
    destination = _endpoint("project:B", "B", "10.0.0.11")

    for suffix in ("ICMP", "TCP"):
        spec = FluxTestSpec(
            id=f"SAME-4-{suffix}",
            category="same-subnet",
            operation="probe",
            family=4,
            expectation="reachable",
            expectation_reason="same project subnet",
            authoritative=True,
            dependencies=["group"],
            protocol=suffix.lower(),
            display_name=f"Same-subnet connectivity — IPv4 {suffix}",
        )
        probe = ProbeResult(
            outcome="reachable",
            success=True,
            elapsed_ms=1,
            attempts=1,
            source_ip="10.0.0.10",
            destination_ip="10.0.0.11",
            protocol=suffix.lower(),
        )
        engine._record(spec, probe, source, destination)

    engine.builder.inspect_endpoint_route.assert_called_once_with(
        source, "10.0.0.10", "10.0.0.11", 4
    )
    details = engine.reporter.result.call_args_list[-1].kwargs["details"]
    assert details["probe"]["diagnostics"]["endpoint_route"] == route
    assert details["compute_placement"] == "same compute host"
    assert details["source_compute_host"] == source.host
    assert details["destination_compute_host"] == destination.host


def test_route_report_includes_the_exact_command_and_output():
    observations = _recorded_route_observations(
        {
            "details": {
                "probe": {
                    "diagnostics": {
                        "endpoint_route": {
                            "returncode": 0,
                            "command": "ip -4 route get 10.0.0.11 from 10.0.0.10",
                            "stdout": "10.0.0.11 via 10.0.0.1 dev eth1 src 10.0.0.10",
                        }
                    }
                }
            }
        }
    )

    assert observations == [
        {
            "observer": "Source endpoint",
            "output": (
                "ip -4 route get 10.0.0.11 from 10.0.0.10\n"
                "10.0.0.11 via 10.0.0.1 dev eth1 src 10.0.0.10"
            ),
        }
    ]


def test_udp_finding_uses_global_worst_value_and_titles_keep_protocol():
    results = [
        {
            "details": {
                "measurement": "udp",
                "metrics": {"forward": [{"loss_pct": float(index)}]},
            }
        }
        for index in range(1, 8)
    ]

    rows = finding_measurements(results)

    assert rows[0] == {
        "label": "Worst across affected UDP tests",
        "value": "7.000%",
    }
    assert friendly_title(
        {
            "display_name": "Project same-subnet connectivity — IPv4 A to B UDP",
            "details": {"protocol": "udp"},
        }
    ).endswith("· UDP")


def test_environment_counts_discovered_created_and_total_subnets():
    payload = {
        "run": {"run_id": "sample", "final_status": "PASS"},
        "configuration": {},
        "results": [],
        "resources": [
            {
                "resource_type": "subnet",
                "id": "created-subnet",
                "name": "created-subnet",
                "metadata": {},
                "cleanup_state": "DELETED",
            }
        ],
        "discovery": {
            "cloud": "cloud",
            "project_name": "project",
            "subnet_count": 1,
            "subnets": [{"id": "discovered-subnet"}],
            "networks": [],
        },
        "cleanup": {"complete": True},
    }

    environment = build_dashboard_model(payload)["environment"]

    assert environment["discovered_subnet_count"] == 1
    assert environment["created_subnet_count"] == 1
    assert environment["subnet_count"] == 2
