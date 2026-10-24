from __future__ import annotations

import dataclasses
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.cleanup import CleanupManager
from neutron_flux.errors import SuiteError
from neutron_flux.models import Endpoint, RunCheckpoint
from neutron_flux.performance import PerformanceRunner
from neutron_flux.state import StateStore
from neutron_flux.utils import iso_utc


def _fip_runner(config_factory):
    config = config_factory(performance_max_paths=0)
    reporter = mock.Mock(scope="az1")
    reporter.get_result.return_value = SimpleNamespace(status="PASS")
    reporter.logger = mock.Mock()
    target = Endpoint(
        label="tenant:A",
        server_id="target",
        server_name="target",
        management_port_id="mgmt",
        management_ip="10.0.0.2",
        test_port_id="port",
        test_mac=None,
        fixed_ips={"runtime": "10.10.0.2"},
        host="compute1",
        availability_zone="az1",
        volume_id=None,
        side="A",
    )
    state = {
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
    engine = SimpleNamespace(
        lifecycle={"fip:tenant": state},
        _network_mtu=lambda group: 1500,
    )
    runner = PerformanceRunner(config, SimpleNamespace(), reporter, engine)
    runner._local_path_mtu = mock.Mock(return_value=1500)
    from neutron_flux.models import TestSpec

    spec = TestSpec(
        id="FIP-BASELINE-TCP-TENANT",
        category="floating-ip",
        operation="fip-baseline",
        family=4,
        expectation="reachable",
        expectation_reason="authoritative FIP ingress",
        authoritative=True,
        dependencies=["tenant"],
        source_group_id=None,
        destination_group_id="tenant",
        source_side="A",
        destination_side="A",
        source_subnet_id=None,
        destination_subnet_id="runtime",
        protocol="tcp",
        phase="cross",
    )
    planned = runner.plan_specs([spec], stage="cross-topology")
    resolved = runner._resolve(runner._planned[planned[0].id])
    return runner, resolved


def test_fip_reverse_uses_fixed_ip_and_preserves_public_path(config_factory):
    runner, path = _fip_runner(config_factory)
    assert path.source_ip == "192.0.2.10"
    assert path.destination_ip == "198.51.100.20"
    assert path.forward_source_ip == "192.0.2.10"
    assert path.forward_destination_ip == "198.51.100.20"
    assert path.reverse_source_ip == "10.10.0.2"
    assert path.reverse_destination_ip == "192.0.2.10"
    assert path.reverse_expected_peer_ip == "198.51.100.20"

    calls = []

    def run_json(endpoint, code, timeout):
        calls.append((endpoint.label, code, timeout))
        return {
            "mbps": 10.0,
            "streams": 1,
            "bytes": 1,
            "client_mss": 1460,
            "server_mss": 1460,
            "peer_ip": "198.51.100.20",
        }

    runner._run_json = run_json
    result = runner._tcp_upload(
        path.destination,
        path.reverse_source_ip,
        path.reverse_destination_ip,
        4,
        streams=1,
        expected_peer_ip=path.reverse_expected_peer_ip,
    )
    assert "SOURCE = '10.10.0.2'" in calls[-1][1]
    assert "DESTINATION = '192.0.2.10'" in calls[-1][1]
    assert "198.51.100.20" not in calls[-1][1]
    assert result["peer_verified"] is True


def test_fip_reverse_tcp_and_udp_require_observed_snat_peer(config_factory):
    runner, path = _fip_runner(config_factory)
    runner._run_json = mock.Mock(return_value={"peer_ip": "10.10.0.2"})
    with pytest.raises(SuiteError, match="expected SNAT source 198.51.100.20"):
        runner._tcp_upload(
            path.destination,
            path.reverse_source_ip,
            path.reverse_destination_ip,
            4,
            streams=1,
            expected_peer_ip=path.reverse_expected_peer_ip,
        )
    # Supply a valid measurement so this check reaches the distinct SNAT peer
    # contract rather than failing first on missing receiver statistics.
    runner._run_json.return_value = {
        "peer_ip": "10.10.0.2",
        "session_id": 1,
        "sent": 100,
        "received": 100,
        "loss_pct": 0.0,
        "mbps": 10.0,
        "pps": 9765.625,
        "jitter_ms": 0.0,
        "duplicates": 0,
        "out_of_order": 0,
    }
    with pytest.raises(SuiteError, match="Reverse floating-IP UDP flow"):
        runner._udp_measurement(
            path.destination,
            path.reverse_source_ip,
            path.reverse_destination_ip,
            4,
            10,
            128,
            expected_peer_ip=path.reverse_expected_peer_ip,
        )


def test_probe_server_reports_tcp_and_udp_peer_addresses(config_factory):
    runner, path = _fip_runner(config_factory)
    from neutron_flux.probe_service import ProbeServiceManager

    code = ProbeServiceManager(18080, 18081)._server_code(path.source)
    assert "peer_ip = str(conn.getpeername()[0])" in code
    assert "'peer_ip': peer_ip" in code
    assert "'peer_ip': str(peer[0])" in code


def _orphan_manager(config_factory, *, report_dir):
    config = config_factory(
        action="cleanup",
        report_dir=report_dir,
        cleanup_orphans=True,
        cleanup_assume_yes=True,
        cleanup_include_active=False,
        orphan_grace_minutes=30,
    )
    manager = CleanupManager.__new__(CleanupManager)
    manager.config = config
    manager.logger = mock.Mock()
    manager.osc = mock.Mock()
    return manager


def _cloud_server(run_id: str, *, state="running"):
    now = iso_utc()
    return {
        "ID": "server-id",
        "Name": f"{run_id}-controller",
        "Properties": {
            "neutron_flux_run_id": run_id,
            "neutron_flux_state": state,
            "neutron_flux_heartbeat": now,
        },
        "Updated At": now,
    }


def _wire_server_inventory(manager, row):
    manager._orphan_list = mock.Mock(
        side_effect=lambda preferred, fallback: (
            [row] if preferred[:2] == ["server", "list"] else []
        )
    )
    manager._enrich_orphan_server = lambda candidate, source, **_kwargs: candidate


def _checkpoint(run_id: str, report_dir, *, state="CANCELLED", cleanup="INCOMPLETE"):
    now = iso_utc()
    return RunCheckpoint(
        run_id=run_id,
        state=state,
        action="run",
        phase="operator-cancelled",
        current_batch=None,
        started_at=now,
        updated_at=now,
        last_activity=now,
        completed_test_ids=[],
        failed_test_ids=[],
        pending_test_ids=[],
        active_group_ids=[],
        manifest_path=str(report_dir / "runs" / run_id / "resources.jsonl"),
        report_dir=str(report_dir),
        cleanup_state=cleanup,
    )


def test_terminal_local_checkpoint_overrides_fresh_cloud_heartbeat(
    config_factory, tmp_path
):
    report_dir = tmp_path / "reports"
    run_id = "nflux-20260723222020-2efa6f"
    StateStore(report_dir).save(_checkpoint(run_id, report_dir))
    manager = _orphan_manager(config_factory, report_dir=report_dir)
    _wire_server_inventory(manager, _cloud_server(run_id, state="running"))
    inventory = manager._discover_project_orphans()
    assert [item["id"] for item in inventory["candidates"]] == ["server-id"]
    assert inventory["protected"] == []
    detail = inventory["runs"][run_id]
    assert detail["terminal_state"] is True
    assert "terminal local checkpoint" in detail["reason"]


def test_live_local_lock_protects_even_terminal_checkpoint(config_factory, tmp_path):
    report_dir = tmp_path / "reports"
    run_id = "nflux-20260723222020-2efa6f"
    store = StateStore(report_dir)
    store.save(_checkpoint(run_id, report_dir))
    manager = _orphan_manager(config_factory, report_dir=report_dir)
    _wire_server_inventory(manager, _cloud_server(run_id, state="cancelled"))
    with store.lock(run_id):
        inventory = manager._discover_project_orphans()
    assert inventory["candidates"] == []
    assert [item["id"] for item in inventory["protected"]] == ["server-id"]
    assert "live local" in inventory["runs"][run_id]["reason"]


def test_local_performance_listener_exits_and_releases_ports(config_factory):
    import socket

    runner, path = _fip_runner(config_factory)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        tcp_port = probe.getsockname()[1]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        udp_port = probe.getsockname()[1]
    runner.config = dataclasses.replace(
        runner.config, tcp_port=tcp_port, udp_port=udp_port
    )
    bidirectional_path = dataclasses.replace(
        path,
        plan=dataclasses.replace(path.plan, directions=("forward", "reverse")),
    )
    with runner._local_probe_server(bidirectional_path):
        with socket.create_connection(("127.0.0.1", tcp_port), timeout=2) as client:
            client.sendall(b"hello\n")
            assert client.recv(6) == b"hello\n"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as check:
        check.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        check.bind(("127.0.0.1", tcp_port))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as check:
        check.bind(("127.0.0.1", udp_port))
