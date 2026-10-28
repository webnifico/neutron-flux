from __future__ import annotations

from types import SimpleNamespace

from neutron_flux.models import Endpoint, PlannedGroup, RuntimeGroup
from neutron_flux.models import TestSpec as FluxTestSpec
from neutron_flux.performance import PerformanceRunner
from neutron_flux.reporting import Reporter


def _endpoint(label: str, side: str, address: str, host: str) -> Endpoint:
    return Endpoint(
        label=label,
        server_id=f"server-{label}",
        server_name=f"server-{label}",
        management_port_id=f"management-{label}",
        management_ip="10.254.0.10" if side == "A" else "10.254.0.11",
        test_port_id=f"test-{label}",
        test_mac="fa:16:3e:00:00:01",
        fixed_ips={"subnet": address},
        host=host,
        availability_zone="az1",
        volume_id=None,
        side=side,
    )


def test_performance_planner_requires_a_functional_tcp_path(config_factory, tmp_path):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    reporter = Reporter(config, "performance-requires-tcp")
    reporter.result(
        "BASE-ICMP",
        "same-subnet",
        "PASS",
        "ICMP reachable while TCP was not proven",
        family=4,
        expected="reachable",
        observed="reachable",
        authoritative=True,
    )
    runtime = RuntimeGroup(
        plan=PlannedGroup(
            "group",
            "provider",
            "Provider path",
            "network",
            "network",
            ["subnet"],
            [4],
        ),
        network_id="network",
        network_name="network",
        subnet_ids=["subnet"],
        router_id=None,
        endpoints=[
            _endpoint("icmp-a", "A", "192.0.2.10", "compute1"),
            _endpoint("icmp-b", "B", "192.0.2.11", "compute2"),
        ],
        source_nat_enabled=None,
        fips={},
    )
    engine = SimpleNamespace(
        _endpoint_address=lambda group_id, side, subnet_id: (
            runtime.endpoint(side),
            runtime.endpoint(side).fixed_ips["subnet"],
        ),
        _network_mtu=lambda group_id: 1500,
    )
    source = FluxTestSpec(
        id="BASE-ICMP",
        category="same-subnet",
        operation="probe",
        family=4,
        expectation="reachable",
        expectation_reason="ICMP path passed",
        authoritative=True,
        dependencies=["group"],
        source_group_id="group",
        destination_group_id="group",
        source_side="A",
        destination_side="B",
        source_subnet_id="subnet",
        destination_subnet_id="subnet",
        protocol="icmp",
        phase="intra",
    )
    runner = PerformanceRunner(config, SimpleNamespace(), reporter, engine)
    assert runner.plan_specs([source], stage="group-local") == []


def test_performance_ping_and_mtu_probes_force_c_locale(config_factory, tmp_path):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    reporter = Reporter(config, "performance-locale")
    captured = {}

    class Builder:
        def ssh_endpoint(self, endpoint, command, *, timeout=None):
            captured["command"] = command
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    "1 packets transmitted, 1 received, 0% packet loss\n"
                    "64 bytes from 192.0.2.11: time=0.5 ms\n"
                ),
                stderr="",
            )

    runner = PerformanceRunner(config, Builder(), reporter, SimpleNamespace())
    runner._ping(
        _endpoint("locale-a", "A", "192.0.2.10", "compute1"),
        "192.0.2.10",
        "192.0.2.11",
        4,
    )
    assert captured["command"].startswith("LC_ALL=C LANG=C ping ")
    code = runner._mtu_client_code("192.0.2.10", "192.0.2.11", 4, 1500)
    assert "environment['LC_ALL'] = 'C'" in code
    assert "environment['LANG'] = 'C'" in code
