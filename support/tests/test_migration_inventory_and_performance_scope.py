from __future__ import annotations

import contextlib
import io
import json
import sys
import types
from types import SimpleNamespace
from unittest import mock

from neutron_flux.errors import DependentMeasurementUnavailable
from neutron_flux.models import Endpoint, ProbeResult
from neutron_flux.models import TestSpec as FluxTestSpec
from neutron_flux.performance import PerformanceRunner
from neutron_flux.policy import PolicyEvaluator, TopologyPolicy
from neutron_flux.reporting import Reporter
from neutron_flux.resources import ResourceBuilder


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


def _tcp_spec(test_id: str, *, source_side: str, destination_side: str) -> FluxTestSpec:
    return FluxTestSpec(
        id=test_id,
        category="same-subnet",
        operation="probe",
        family=4,
        expectation="reachable",
        expectation_reason="functional TCP passed",
        authoritative=True,
        dependencies=["group"],
        source_group_id="group",
        destination_group_id="group",
        source_side=source_side,
        destination_side=destination_side,
        source_subnet_id="subnet",
        destination_subnet_id="subnet",
        protocol="tcp",
        phase="intra",
    )


def test_migration_inventory_uses_server_option_and_falls_back_from_rejected_microversion(
    config_factory,
):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder.logger = mock.Mock()
    builder._json_with_transient_retry = mock.Mock(
        side_effect=[
            None,
            [
                {
                    "server_uuid": "server-1",
                    "status": "done",
                    "source_compute": "compute1",
                    "dest_compute": "compute2",
                }
            ],
        ]
    )

    rows, error = builder._migration_rows("server-1")

    assert error is None
    assert rows and rows[0]["server_uuid"] == "server-1"
    first = builder._json_with_transient_retry.call_args_list[0].args
    second = builder._json_with_transient_retry.call_args_list[1].args
    assert first[:2] == ("--os-compute-api-version", "2.56")
    assert first[-2:] == ("--server", "server-1")
    assert second[:2] == ("--os-compute-api-version", "2.latest")
    assert second[-2:] == ("--server", "server-1")
    assert builder._migration_compute_api_prefix == (
        "--os-compute-api-version",
        "2.latest",
    )
    assert builder._migration_command_args(
        "server-1", "server", "migrate", "server-1"
    ) == (
        "--os-compute-api-version",
        "2.latest",
        "server",
        "migrate",
        "server-1",
    )


def test_endpoint_performance_requires_both_functional_tcp_directions(
    config_factory,
):
    config = config_factory(performance_max_paths=0)
    reporter = mock.Mock(scope="az1")
    reporter.logger = mock.Mock()
    results = {
        "A-B": SimpleNamespace(status="PASS"),
        "B-A": SimpleNamespace(status="FAIL"),
    }
    reporter.get_result.side_effect = lambda test_id: results.get(test_id)
    endpoints = {
        "A": _endpoint("a", "A", "192.0.2.10", "compute1"),
        "B": _endpoint("b", "B", "192.0.2.11", "compute2"),
    }
    engine = SimpleNamespace(
        lifecycle={},
        _endpoint_address=lambda _group, side, _subnet: (
            endpoints[side],
            endpoints[side].fixed_ips["subnet"],
        ),
        _network_mtu=lambda _group: 1500,
    )
    forward = _tcp_spec("A-B", source_side="A", destination_side="B")
    reverse = _tcp_spec("B-A", source_side="B", destination_side="A")
    runner = PerformanceRunner(config, SimpleNamespace(), reporter, engine)

    assert runner.plan_specs([forward, reverse], stage="group-local") == []

    results["B-A"] = SimpleNamespace(status="PASS")
    planned = PerformanceRunner(config, SimpleNamespace(), reporter, engine).plan_specs(
        [forward, reverse], stage="group-local"
    )
    assert len(planned) == 7
    assert all(
        item.metadata["directions"] == ["forward", "reverse"] for item in planned
    )


def test_floating_ip_performance_is_forward_only(config_factory):
    config = config_factory(performance_max_paths=0)
    reporter = mock.Mock(scope="az1")
    reporter.logger = mock.Mock()
    reporter.get_result.return_value = SimpleNamespace(status="PASS")
    target = _endpoint("target", "A", "10.10.0.2", "compute1")
    target.fixed_ips = {"runtime": "10.10.0.2"}
    engine = SimpleNamespace(
        lifecycle={
            "fip:tenant": {
                "id": "fip-id",
                "address": "198.51.100.20",
                "fixed_ip": "10.10.0.2",
                "source_ip": "192.0.2.10",
                "source": None,
                "target": target,
                "source_mode": "runner",
                "authoritative": True,
                "baseline": True,
            }
        },
        _network_mtu=lambda _group: 1500,
    )
    spec = FluxTestSpec(
        id="FIP",
        category="floating-ip",
        operation="fip-baseline",
        family=4,
        expectation="reachable",
        expectation_reason="authoritative ingress passed",
        authoritative=True,
        dependencies=["tenant"],
        destination_group_id="tenant",
        destination_subnet_id="runtime",
        protocol="tcp",
    )
    runner = PerformanceRunner(config, SimpleNamespace(), reporter, engine)
    runner._local_path_mtu = mock.Mock(return_value=1500)

    planned = runner.plan_specs([spec], stage="cross-topology")

    measurements = {item.metadata["performance_measurement"] for item in planned}
    assert len(planned) == 6
    assert "asymmetry" not in measurements
    assert all(item.metadata["directions"] == ["forward"] for item in planned)


def test_mtu_all_probe_failure_returns_null_not_header_size(config_factory):
    code = PerformanceRunner._mtu_client_code("192.0.2.10", "192.0.2.11", 4, 1500)
    fake_subprocess = types.ModuleType("subprocess")
    fake_subprocess.PIPE = object()
    fake_subprocess.run = lambda *args, **kwargs: SimpleNamespace(
        returncode=1,
        stdout="",
        stderr="100% packet loss",
    )
    original = sys.modules.get("subprocess")
    sys.modules["subprocess"] = fake_subprocess
    output = io.StringIO()
    try:
        with contextlib.redirect_stdout(output):
            exec(code, {})
    finally:
        if original is None:
            sys.modules.pop("subprocess", None)
        else:
            sys.modules["subprocess"] = original

    result = json.loads(output.getvalue().strip())
    assert result["reachable"] is False
    assert result["discovered_payload"] is None
    assert result["discovered_mtu"] is None

    runner = PerformanceRunner(
        config_factory(), SimpleNamespace(), mock.Mock(), SimpleNamespace()
    )
    assert (
        runner._mtu_health(
            {
                "forward": {
                    "reachable": False,
                    "discovered_mtu": None,
                    "expected_max_mss": None,
                }
            },
            1500,
        )
        == "unverified"
    )


def test_one_root_performance_failure_does_not_multiply_errors(
    config_factory,
    tmp_path,
):
    errors: dict[str, BaseException] = {}
    runner = PerformanceRunner(
        config_factory(action="run", report_dir=tmp_path / "reports"),
        SimpleNamespace(),
        Reporter(
            config_factory(action="run", report_dir=tmp_path / "reports"),
            "sample-cascade",
        ),
        SimpleNamespace(),
    )

    result = runner._capture_measurement(
        errors,
        ("tcp-throughput", "concurrency", "repeatability"),
        lambda: (_ for _ in ()).throw(RuntimeError("reverse TCP timed out")),
    )

    assert result is None
    assert isinstance(errors["tcp-throughput"], RuntimeError)
    assert isinstance(errors["concurrency"], DependentMeasurementUnavailable)
    assert isinstance(errors["repeatability"], DependentMeasurementUnavailable)


def test_unassigned_routing_metadata_records_non_authoritative_observation():
    decision = TopologyPolicy.project_expectation(
        TopologyPolicy.routing_relationship(None, "routing-group"), 6
    )
    expectation, reason, authoritative = (
        decision.expectation,
        decision.reason,
        decision.authoritative,
    )
    assert expectation == "observation"
    assert authoritative is False
    spec = FluxTestSpec(
        id="OBS",
        category="tenant-provider-connectivity",
        operation="probe",
        family=4,
        expectation=expectation,
        expectation_reason=reason,
        authoritative=authoritative,
        dependencies=[],
    )
    decision = PolicyEvaluator().evaluate(
        spec,
        ProbeResult(
            outcome="blocked",
            success=False,
            elapsed_ms=1,
            attempts=1,
        ),
    )
    assert decision.status == "UNVERIFIED"
    assert decision.authoritative is False
