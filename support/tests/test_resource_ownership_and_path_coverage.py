from __future__ import annotations

import dataclasses
import datetime as dt
import json
import subprocess
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.cleanup import CleanupManager
from neutron_flux.config import Config
from neutron_flux.errors import RunCancelledError
from neutron_flux.models import Endpoint
from neutron_flux.openstack import OpenStack
from neutron_flux.performance import PerformanceRunner
from neutron_flux.reporting import Reporter
from neutron_flux.reporting_components.html import _performance_coverage
from neutron_flux.resources import ResourceBuilder


def _security_rows():
    return [
        {
            "ID": "udp4",
            "IP Protocol": "udp",
            "Ethertype": "IPv4",
            "IP Range": "0.0.0.0/0",
            "Port Range": "18081:18081",
            "Direction": "ingress",
            "Remote Security Group": None,
            "Remote Address Group": None,
        },
        {
            "ID": "icmp4",
            "IP Protocol": "icmp",
            "Ethertype": "IPv4",
            "IP Range": "0.0.0.0/0",
            "Port Range": "",
            "Direction": "ingress",
            "Remote Security Group": None,
            "Remote Address Group": None,
        },
        {
            "ID": "egress4",
            "IP Protocol": None,
            "Ethertype": "IPv4",
            "IP Range": "0.0.0.0/0",
            "Port Range": "",
            "Direction": "egress",
            "Remote Security Group": None,
            "Remote Address Group": None,
        },
        {
            "ID": "tcp4",
            "IP Protocol": "tcp",
            "Ethertype": "IPv4",
            "IP Range": "0.0.0.0/0",
            "Port Range": "18080:18080",
            "Direction": "ingress",
            "Remote Security Group": None,
            "Remote Address Group": None,
        },
    ]


def test_security_rule_parser_handles_osc_headings_once(config_factory):
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.osc = mock.Mock()
    builder.osc.json.return_value = _security_rows()
    builder._address_group_cache = {}

    rules = builder.list_security_group_rules("sg-b")
    assert rules[-1]["protocol"] == "tcp"
    assert rules[-1]["remote_ip_prefix"] == "0.0.0.0/0"
    assert builder._rule_port_range(rules[-1]) == (18080, 18080)

    allowed, matching = builder.security_group_allows_port(
        "sg-b", 4, "tcp", 18080, source_security_group_id="sg-a", rules=rules
    )
    assert allowed is True
    assert [item["id"] for item in matching] == ["tcp4"]

    allowed, matching = builder.security_group_allows_port(
        "sg-b", 4, "tcp", 18082, source_security_group_id="sg-a", rules=rules
    )
    assert allowed is False
    assert matching == []

    port, authoritative, matching = builder.choose_security_control_port(
        destination_security_group_id="sg-b",
        source_security_group_id="sg-a",
        family=4,
    )
    assert (port, authoritative, matching) == (18082, True, [])
    # One explicit inventory plus the earlier direct inventory; never 128 API calls.
    assert builder.osc.json.call_count == 2
    assert "--long" not in builder.osc.json.call_args.args


def test_probe_reuses_verified_surviving_process(config_factory):
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.logger = mock.Mock()
    builder.security_control_ports = {4: 18082, 6: 18082}
    builder.probe_service = mock.Mock()
    builder.probe_service.is_running.return_value = False
    builder._existing_probe_service_ready = mock.Mock(
        return_value=(
            True,
            {
                "listeners": {"4": {"tcp": True, "udp": True}},
                "processes": [{"pid": 42, "start_ticks": "100"}],
                "inspection_complete": True,
            },
        )
    )
    builder._launch_probe_process = mock.Mock()
    endpoint = Endpoint(
        label="A",
        server_id="server-a",
        server_name="server-a",
        management_port_id="mgmt-a",
        management_ip="10.0.0.2",
        test_port_id="test-a",
        test_mac="fa:16:3e:00:00:01",
        fixed_ips={"s4": "192.0.2.2"},
        host="compute1",
        availability_zone="az1",
        volume_id=None,
        side="A",
    )
    builder._start_probe_server(endpoint, reuse_existing=True)
    builder.probe_service.start.assert_not_called()
    assert endpoint.metadata["probe_service"]["mode"] == "adopted-surviving-process"


def test_openstack_returncode_130_is_operator_cancel(monkeypatch, tmp_path):
    logger = SimpleNamespace(log=lambda *_args, **_kwargs: None)
    osc = OpenStack(logger)
    monkeypatch.setattr(
        "neutron_flux.openstack.run_cancellable",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 130, "", "cancelled"
        ),
    )
    with pytest.raises(RunCancelledError):
        osc.run("network", "list", check=False)


def test_default_performance_paths_are_unlimited():
    args = SimpleNamespace(
        action="plan",
        config=None,
        image="debian-13",
        flavor="x1.nano",
        storage="host",
        volume_size=None,
        volume_type=None,
        external_networks="Public1",
        zones=None,
        zone_mode=None,
        performance_max_paths=None,
        fabric=None,
        fabric_pairs=None,
        fabric_runs=None,
        fabric_duration=None,
        migration_mode=None,
        migration_storage=None,
        live_attempts=None,
        cold_fallback=None,
        live_continuity=None,
        junit=None,
        evidence=None,
        output_dir=None,
        paths=[],
        orphans=False,
        dry_run=False,
        yes=False,
        include_active=False,
        orphan_grace_minutes=None,
    )
    config = Config.from_args(args)
    assert config.performance_max_paths == 0


def test_cancelled_cloud_state_is_not_protected_by_fresh_heartbeat(config_factory):
    manager = CleanupManager.__new__(CleanupManager)
    manager.config = config_factory(
        cleanup_include_active=False, orphan_grace_minutes=30
    )
    manager.logger = mock.Mock()
    manager.osc = mock.Mock()
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    row = {
        "ID": "server-id",
        "Name": "nflux-20260723222020-2efa6f-controller",
        "Properties": {
            "neutron_flux_run_id": "nflux-20260723222020-2efa6f",
            "neutron_flux_state": "cancelled",
            "neutron_flux_heartbeat": now,
        },
        "Updated At": now,
    }
    manager._orphan_list = mock.Mock(
        side_effect=lambda preferred, fallback: (
            [row] if preferred[:2] == ["server", "list"] else []
        )
    )
    manager._enrich_orphan_server = lambda candidate, source, **_kwargs: candidate
    inventory = manager._discover_project_orphans()
    assert len(inventory["candidates"]) == 1
    assert inventory["protected"] == []
    assert inventory["runs"]["nflux-20260723222020-2efa6f"]["terminal_state"] is True


def test_reporter_displays_performance_warning(config_factory, tmp_path):
    config = dataclasses.replace(config_factory(), action="run", report_dir=tmp_path)
    reporter = Reporter(config, "nflux-20260723222020-abcdef")
    reporter.result(
        "PERF-1",
        "network-performance",
        "PASS",
        "measurement completed; assessment=warning",
        details={
            "performance": True,
            "health": "warning",
            "warning_reasons": ["UDP loss above advisory threshold"],
        },
        display_name="UDP quality",
    )
    reporter.logger.close()
    text = reporter.report_path.read_text()
    assert "[PASS WITH WARNING] UDP quality" in text
    assert "Advisory: UDP loss above advisory threshold" in text
    assert "[FAIL]" not in text
    stored = json.loads(reporter.result_journal_path.read_text().splitlines()[-1])
    assert stored["status"] == "PASS"
    assert stored["details"]["warning_reasons"] == ["UDP loss above advisory threshold"]


def test_orphan_unknown_flux_resource_is_not_deleted_and_fails_closed(
    config_factory, tmp_path
):
    config = config_factory(
        action="cleanup",
        report_dir=tmp_path / "reports",
        cleanup_orphans=True,
        cleanup_assume_yes=True,
    )
    reporter = Reporter(config, "orphan-unknown")
    manager = CleanupManager(mock.Mock(), reporter, mock.Mock(), config)
    manager.osc.json.return_value = {"project_id": "project-id"}
    manager._discover_project_orphans = mock.Mock(
        return_value={
            "candidates": [],
            "protected": [],
            "unknown": [
                {
                    "resource_type": "server",
                    "id": "server-unknown",
                    "name": "nflux-malformed-controller",
                    "reason": "no valid run ID",
                }
            ],
            "runs": {},
        }
    )
    manager._write_recovery_artifacts = mock.Mock()

    assert manager.cleanup_orphans() is False
    assert reporter.cleanup_summary["complete"] is False
    assert reporter.cleanup_summary["orphan_sweep"]["unknown_resources_remaining"] == 1
    manager._write_recovery_artifacts.assert_called_once()
    reporter.logger.close()


def test_unclassified_flux_marker_is_reported_but_not_adopted(config_factory):
    manager = CleanupManager.__new__(CleanupManager)
    manager.config = config_factory()
    manager.logger = mock.Mock()
    manager.osc = mock.Mock()
    manager._orphan_list = mock.Mock(
        side_effect=lambda preferred, fallback: (
            [{"ID": "bad-server", "Name": "nflux-malformed-controller"}]
            if preferred[:2] == ["server", "list"]
            else []
        )
    )
    manager.osc.json.return_value = {
        "ID": "bad-server",
        "Name": "nflux-malformed-controller",
    }
    inventory = manager._discover_project_orphans()
    assert inventory["candidates"] == []
    assert inventory["protected"] == []
    assert inventory["unknown"][0]["id"] == "bad-server"


def _perf_spec(index: int) -> object:
    from neutron_flux.models import TestSpec

    return TestSpec(
        id=f"PATH-{index}",
        category="same-subnet",
        operation="probe",
        family=4,
        expectation="reachable",
        expectation_reason="functional TCP passed",
        authoritative=True,
        dependencies=[f"group-{index}"],
        source_group_id=f"group-{index}",
        destination_group_id=f"group-{index}",
        source_side="A",
        destination_side="B",
        source_subnet_id="subnet",
        destination_subnet_id="subnet",
        protocol="tcp",
        phase="intra",
    )


def _reverse_perf_spec(spec: object) -> object:
    from neutron_flux.models import TestSpec

    assert isinstance(spec, TestSpec)
    return dataclasses.replace(
        spec,
        id=f"{spec.id}-REVERSE",
        source_side=spec.destination_side,
        destination_side=spec.source_side,
        source_subnet_id=spec.destination_subnet_id,
        destination_subnet_id=spec.source_subnet_id,
    )


def test_unlimited_performance_selects_every_unique_path(config_factory):
    config = config_factory(performance_max_paths=0)
    reporter = mock.Mock(scope="az1")
    reporter.get_result.return_value = SimpleNamespace(status="PASS")
    reporter.logger = mock.Mock()
    endpoints = {}
    for index in range(12):
        endpoints[(f"group-{index}", "A")] = Endpoint(
            label=f"g{index}:A",
            server_id=f"a-{index}",
            server_name=f"a-{index}",
            management_port_id=f"ma-{index}",
            management_ip=f"10.0.{index}.2",
            test_port_id=f"ta-{index}",
            test_mac=None,
            fixed_ips={"subnet": f"192.0.{index}.2"},
            host="c1",
            availability_zone="az1",
            volume_id=None,
            side="A",
        )
        endpoints[(f"group-{index}", "B")] = Endpoint(
            label=f"g{index}:B",
            server_id=f"b-{index}",
            server_name=f"b-{index}",
            management_port_id=f"mb-{index}",
            management_ip=f"10.0.{index}.3",
            test_port_id=f"tb-{index}",
            test_mac=None,
            fixed_ips={"subnet": f"192.0.{index}.3"},
            host="c2",
            availability_zone="az1",
            volume_id=None,
            side="B",
        )
    engine = SimpleNamespace(
        lifecycle={},
        _endpoint_address=lambda group, side, subnet: (
            endpoints[(group, side)],
            endpoints[(group, side)].fixed_ips["subnet"],
        ),
        _network_mtu=lambda group: 1500,
    )
    runner = PerformanceRunner(config, SimpleNamespace(), reporter, engine)
    source_specs = []
    for index in range(12):
        forward = _perf_spec(index)
        source_specs.extend([forward, _reverse_perf_spec(forward)])
    planned = runner.plan_specs(source_specs, stage="group-local")
    assert len(planned) == 12 * 7
    assert runner.session.selected_by_stage["group-local"] == 12
    event = reporter.event.call_args
    assert event.kwargs["eligible_paths"] == 12
    assert event.kwargs["selected_paths"] == 12
    assert event.kwargs["omitted_paths"] == 0
    assert event.kwargs["unlimited"] is True


def test_floating_ip_path_uses_complete_existing_performance_suite(config_factory):
    from neutron_flux.models import TestSpec

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
    runner = PerformanceRunner(config, SimpleNamespace(), reporter, engine)
    runner._local_path_mtu = mock.Mock(return_value=1500)
    planned = runner.plan_specs([spec], stage="cross-topology")
    assert len(planned) == 6
    assert {item.metadata["performance_measurement"] for item in planned} == {
        "tcp-throughput",
        "latency",
        "udp",
        "mtu-mss",
        "concurrency",
        "repeatability",
    }
    path = runner._planned[planned[0].id]
    assert path.path_kind == "floating-ip"
    assert path.directions == ("forward",)
    resolved = runner._resolve(path)
    assert resolved.source.metadata["performance_local"] is True
    assert resolved.destination_ip == "198.51.100.20"


def test_fip_batch_migrates_the_fip_target_endpoint():
    from neutron_flux.execution.placement import PlacementValidationMixin
    from neutron_flux.models import TestSpec

    def endpoint(side: str) -> Endpoint:
        return Endpoint(
            label=f"tenant:{side}",
            server_id=side,
            server_name=side,
            management_port_id=f"m-{side}",
            management_ip=f"10.0.0.{2 if side == 'A' else 3}",
            test_port_id=f"p-{side}",
            test_mac=None,
            fixed_ips={"runtime": f"10.10.0.{2 if side == 'A' else 3}"},
            host="compute1",
            availability_zone="az1",
            volume_id=None,
            side=side,
        )

    runtime = SimpleNamespace(endpoint=lambda side: endpoint(side))
    PlacementHarness = type("PlacementHarness", (PlacementValidationMixin,), {})
    holder = PlacementHarness()
    holder.active = {"tenant": runtime}
    spec = TestSpec(
        id="FIP",
        category="floating-ip",
        operation="fip-baseline",
        family=4,
        expectation="reachable",
        expectation_reason="",
        authoritative=True,
        dependencies=["tenant"],
        destination_group_id="tenant",
        protocol="tcp",
    )
    source, destination = holder._placement_endpoints(("tenant",), [spec])
    assert source.side == "A"
    assert destination.side == "B"


def test_cancelled_run_is_a_junit_lifecycle_skip():
    from neutron_flux.junit_report import build_junit

    xml = build_junit(
        {
            "run": {"run_id": "cancelled", "final_status": "CANCELLED"},
            "results": [],
            "cleanup": {"complete": True},
        }
    )
    assert 'tests="1"' in xml
    assert 'errors="0"' in xml
    assert 'skipped="1"' in xml
    assert "<skipped" in xml


def test_flux_owned_groups_remove_only_unexpected_inherited_ingress(config_factory):
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.name_prefix = "nflux-test"
    builder.run_tag = "neutron-flux-nflux-20260723222020-abcdef"
    builder.management_cidr = "10.254.1.0/24"
    builder.reporter = mock.Mock()
    builder.logger = mock.Mock()
    builder.tracker = mock.Mock()
    builder.probe_service = mock.Mock()
    builder.security_control_ports = {4: 18082, 6: 18082}
    builder.security_control_authoritative = {4: False, 6: False}
    builder.security_control_matching_rules = {4: [], 6: []}
    builder.security_group_rules = {}
    builder._address_group_cache = {}
    builder.shared_security_group_bundle = None
    builder._create_security_group = mock.Mock(
        side_effect=["controller", "mgmt", "data-a", "data-b"]
    )
    inventories = {
        group: [
            {
                "ID": f"{group}-egress4",
                "IP Protocol": None,
                "Ethertype": "IPv4",
                "IP Range": "0.0.0.0/0",
                "Port Range": "",
                "Direction": "egress",
                "Remote Security Group": None,
            },
            {
                "ID": f"{group}-egress6",
                "IP Protocol": None,
                "Ethertype": "IPv6",
                "IP Range": "::/0",
                "Port Range": "",
                "Direction": "egress",
                "Remote Security Group": None,
            },
        ]
        for group in ("controller", "mgmt", "data-a", "data-b")
    }
    inventories["data-b"].append(
        {
            "ID": "unexpected-broad-ingress",
            "IP Protocol": "tcp",
            "Ethertype": "IPv4",
            "IP Range": "0.0.0.0/0",
            "Port Range": "",
            "Direction": "ingress",
            "Remote Security Group": None,
        }
    )
    deleted = []
    created = 0

    def json_call(*args, **kwargs):
        nonlocal created
        if args[:4] == ("security", "group", "rule", "list"):
            return list(inventories[str(args[4])])
        if args[:4] == ("security", "group", "rule", "create"):
            created += 1
            return {"id": f"created-{created}"}
        return []

    def run_call(*args, **kwargs):
        if args[:4] == ("security", "group", "rule", "delete"):
            rule_id = str(args[4])
            deleted.append(rule_id)
            for rules in inventories.values():
                rules[:] = [item for item in rules if item.get("ID") != rule_id]
        return subprocess.CompletedProcess(args, 0, "", "")

    builder.osc = SimpleNamespace(json=json_call, run=run_call)
    builder._create_security_groups(select_control_ports=False)
    assert deleted == ["unexpected-broad-ingress"]
    assert all(
        not item.endswith("egress4") and not item.endswith("egress6")
        for item in deleted
    )
    event = builder.reporter.event.call_args
    assert event.kwargs["removed_unexpected_ingress_rule_ids"] == [
        "unexpected-broad-ingress"
    ]


def test_performance_coverage_reports_actual_path_outcomes():
    event = {
        "type": "performance-coverage",
        "details": {
            "stage": "group-local",
            "eligible_paths": 2,
            "selected_paths": 2,
            "omitted_paths": 0,
            "configured_max_paths": 0,
            "unlimited": True,
            "eligible_by_topology": {"same-subnet": 2},
            "selected_by_topology": {"same-subnet": 2},
            "omitted_by_topology": {},
        },
    }
    measurements = [
        "tcp-throughput",
        "latency",
        "udp",
        "mtu-mss",
        "asymmetry",
        "concurrency",
        "repeatability",
    ]
    rows = []
    for path_id, bad in (("P-A", False), ("P-B", True)):
        for measurement in measurements:
            rows.append(
                {
                    "status": "ERROR" if bad and measurement == "udp" else "PASS",
                    "details": {
                        "performance": True,
                        "measurement": measurement,
                        "path": {
                            "path_id": path_id,
                            "source_category": "same-subnet",
                        },
                    },
                }
            )
    coverage = _performance_coverage([event], rows)
    assert coverage["eligible"] == 2
    assert coverage["selected"] == 2
    assert coverage["completed"] == 1
    assert coverage["errors"] == 1
    assert coverage["topologies"]["same-subnet"]["completed"] == 1
    assert coverage["topologies"]["same-subnet"]["errors"] == 1


def test_orphan_dry_run_reports_stale_protected_and_unknown_truthfully(
    config_factory, tmp_path
):
    config = config_factory(
        action="cleanup",
        report_dir=tmp_path / "reports",
        cleanup_orphans=True,
        cleanup_dry_run=True,
    )
    reporter = Reporter(config, "orphan-dry-run")
    manager = CleanupManager(mock.Mock(), reporter, mock.Mock(), config)
    manager.osc.json.return_value = {"project_id": "project-id"}
    inventory = {
        "candidates": [
            {
                "resource_type": "server",
                "id": "stale",
                "name": "nflux-stale",
                "run_id": "nflux-20260723214135-26c78c",
                "evidence": ["tag"],
            }
        ],
        "protected": [
            {
                "resource_type": "server",
                "id": "active",
                "name": "nflux-active",
                "run_id": "nflux-20260723222020-2efa6f",
                "evidence": ["tag"],
            }
        ],
        "unknown": [
            {
                "resource_type": "port",
                "id": "unknown",
                "name": "nflux-malformed",
                "reason": "no valid run ID",
            }
        ],
        "runs": {
            "nflux-20260723214135-26c78c": {
                "selected": True,
                "protected": False,
                "resource_count": 1,
                "states": ["cancelled"],
                "reason": "terminal state",
            },
            "nflux-20260723222020-2efa6f": {
                "selected": False,
                "protected": True,
                "resource_count": 1,
                "states": ["running"],
                "reason": "fresh active run",
            },
        },
    }
    manager._discover_project_orphans = mock.Mock(return_value=inventory)
    assert manager.cleanup_orphans() is True
    summary = reporter.cleanup_summary
    assert summary["complete"] is None
    assert summary["orphan_sweep"]["stale_resources_remaining"] == 1
    assert summary["orphan_sweep"]["protected_resources_remaining"] == 1
    assert summary["orphan_sweep"]["unknown_resources_remaining"] == 1
    assert summary["dry_run_unknown"] == ["port:unknown:nflux-malformed"]
    reporter.logger.close()


def test_orphan_cleanup_repeats_until_newly_exposed_resources_are_gone(
    config_factory, tmp_path
):
    config = config_factory(
        action="cleanup",
        report_dir=tmp_path / "reports",
        cleanup_orphans=True,
        cleanup_assume_yes=True,
    )
    reporter = Reporter(config, "orphan-fixed-point")
    tracker = mock.Mock()
    manager = CleanupManager(mock.Mock(), reporter, tracker, config)
    manager.osc.json.return_value = {"project_id": "project-id"}
    manager.osc.json.return_value = {"project_id": "project"}
    stale_server = {
        "resource_type": "server",
        "id": "server-1",
        "name": "nflux-old-server",
        "run_id": "nflux-20260723214135-26c78c",
        "evidence": ["tag"],
    }
    stale_port = {
        "resource_type": "port",
        "id": "port-1",
        "name": "nflux-old-port",
        "run_id": "nflux-20260723214135-26c78c",
        "evidence": ["tag"],
    }
    run = {
        "selected": True,
        "protected": False,
        "resource_count": 1,
        "states": ["cancelled"],
        "reason": "terminal state",
    }
    protected_run = {
        "selected": False,
        "protected": True,
        "resource_count": 1,
        "states": ["running"],
        "reason": "fresh active run",
        "heartbeat_age_seconds": 30,
    }
    initial = {
        "candidates": [stale_server],
        "protected": [],
        "unknown": [],
        "runs": {"nflux-20260723214135-26c78c": run},
    }
    second = {
        "candidates": [stale_port],
        "protected": [],
        "unknown": [],
        "runs": {"nflux-20260723214135-26c78c": run},
    }
    final = {
        "candidates": [],
        "protected": [
            {
                "resource_type": "server",
                "id": "active",
                "name": "nflux-active",
                "run_id": "nflux-20260723222020-2efa6f",
                "evidence": ["tag"],
            }
        ],
        "unknown": [],
        "runs": {"nflux-20260723222020-2efa6f": protected_run},
    }
    manager._discover_project_orphans = mock.Mock(
        side_effect=[initial, second, second, final, final, final]
    )

    def cleanup_pass(**_kwargs):
        reporter.cleanup_summary["deleted"] += 1
        return True

    manager.cleanup = mock.Mock(side_effect=cleanup_pass)
    manager._clear_recovery_artifacts = mock.Mock()
    manager._write_recovery_artifacts = mock.Mock()
    manager.logger = mock.Mock()

    assert manager.cleanup_orphans() is True
    assert manager.cleanup.call_count == 2
    assert reporter.cleanup_summary["orphan_sweep"]["passes"] == [
        {"pass": 1, "candidates": 1, "deleted": 1, "remaining_stale": 1},
        {"pass": 2, "candidates": 1, "deleted": 1, "remaining_stale": 0},
    ]
    sweep = reporter.cleanup_summary["orphan_sweep"]
    assert sweep["stale_resources_remaining"] == 0
    assert sweep["protected_resources_remaining"] == 1
    assert sweep["project_resources_remaining"] == 1
    assert reporter.cleanup_summary["complete"] is True
    assert not any(
        "found no Neutron Flux resources" in str(call.args[0])
        for call in manager.logger.log.call_args_list
    )
    reporter.logger.close()


def test_endpoint_server_names_keep_distinct_side_suffixes(config_factory):
    from neutron_flux.models import PlannedGroup

    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.logger = mock.Mock()
    builder.name_prefix = "nflux-20260723222020-abcdef-very-long-prefix"
    builder.management_network_id = "mgmt-net"
    builder.management_subnet_id = "mgmt-subnet"
    builder.endpoint_management_sg_id = "mgmt-sg"
    builder.test_sg_ids = {"A": "data-a", "B": "data-b"}
    builder.test_sg_id = "data-a"
    created_names = []
    port_number = 0

    def create_port(name, *_args, **_kwargs):
        nonlocal port_number
        port_number += 1
        is_mgmt = _kwargs["role"] == "endpoint-management"
        return {
            "id": f"port-{port_number}",
            "fixed_ips": [
                {
                    "subnet_id": "mgmt-subnet" if is_mgmt else "test-subnet",
                    "ip_address": f"10.0.0.{port_number + 1}"
                    if is_mgmt
                    else f"192.0.2.{port_number + 1}",
                }
            ],
            "mac_address": f"fa:16:3e:00:00:{port_number:02x}",
            "port_security_enabled": True,
        }

    def create_server(name, *_args, **_kwargs):
        created_names.append(name)
        return {
            "server_id": f"server-{len(created_names)}",
            "server_name": name,
            "host": "compute1",
            "availability_zone": "az1",
            "volume_id": None,
        }

    builder._create_port = mock.Mock(side_effect=create_port)
    builder._create_server = mock.Mock(side_effect=create_server)
    builder._wait_for_ssh = mock.Mock(return_value=True)
    builder._configure_endpoint = mock.Mock()
    builder._require_ipv4 = mock.Mock()
    group = PlannedGroup(
        id="provider-873c019d-1a5c-42cf-9841-9671bba18045",
        kind="provider",
        label="Provider Public3",
        network_id="network",
        network_name="Public3",
        subnet_ids=["test-subnet"],
        families=[4],
    )
    endpoints = builder._create_endpoints(
        group, "network", ["test-subnet"], sides=("A", "B"), generation=1
    )
    assert [item.side for item in endpoints] == ["A", "B"]
    assert {name.rsplit("-", 1)[-1] for name in created_names} == {"a", "b"}
    assert created_names[0] != created_names[1]
