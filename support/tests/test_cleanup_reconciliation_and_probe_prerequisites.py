from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

from neutron_flux.cancellation import (
    begin_cleanup_after_cancellation,
    request_cancellation,
    reset_cancellation,
    run_cancellable,
)
from neutron_flux.cleanup import CleanupManager
from neutron_flux.execution.placement import PlacementValidationMixin
from neutron_flux.models import Endpoint, PlannedGroup, RuntimeGroup
from neutron_flux.models import TestSpec as FluxTestSpec
from neutron_flux.reporting import Reporter, ResourceTracker

from .test_engine_handlers import _engine, _probe, _spec


class _PlacementExecutor(PlacementValidationMixin):
    pass


def _inventory(candidate: bool = True):
    run_id = "nflux-20260724214901-4a2719"
    candidates = (
        [
            {
                "resource_type": "router",
                "id": "router-1",
                "name": f"{run_id}-access-router",
                "run_id": run_id,
                "evidence": "explicit Neutron Flux tag/property",
            }
        ]
        if candidate
        else []
    )
    return {
        "candidates": candidates,
        "protected": [],
        "unknown": [],
        "runs": (
            {
                run_id: {
                    "selected": True,
                    "protected": False,
                    "resource_count": 1,
                    "reason": "terminal local checkpoint",
                }
            }
            if candidate
            else {}
        ),
    }


def test_cleanup_commands_are_not_recancelled_by_original_signal():
    reset_cancellation()
    try:
        assert request_cancellation("received signal 2") is True
        begin_cleanup_after_cancellation()
        result = run_cancellable(["bash", "-c", "exit 143"])
        assert result.returncode == 143
    finally:
        reset_cancellation()


def test_scoped_az_tag_preserves_bastion_floating_ip_ownership(
    config_factory, tmp_path
):
    config = config_factory(action="cleanup", report_dir=tmp_path / "reports")
    reporter = Reporter(config, "orphan-inspection")
    manager = CleanupManager(mock.Mock(), reporter, ResourceTracker(reporter), config)
    run_id = "nflux-20260724214901-4a2719"

    candidate = manager._owned_orphan_candidate(
        "floating_ip",
        {
            "ID": "fip-1",
            "Floating IP Address": "172.20.5.133",
            "Tags": [f"neutron-flux-{run_id}-az-bc-van2"],
            "Description": f"neutron-flux-{run_id}-az-bc-van2",
        },
    )

    assert candidate is not None
    assert candidate["id"] == "fip-1"
    assert candidate["run_id"] == run_id
    reporter.logger.close()


def test_final_clean_rediscovery_recovers_first_pass_dependency_errors(
    config_factory, tmp_path
):
    config = config_factory(
        action="cleanup",
        report_dir=tmp_path / "reports",
        cleanup_orphans=True,
        cleanup_assume_yes=True,
    )
    reporter = Reporter(config, "orphan-delete")
    osc = mock.Mock()
    osc.json.return_value = {"project_id": "project-id"}
    manager = CleanupManager(osc, reporter, ResourceTracker(reporter), config)
    initial = _inventory(True)
    empty = _inventory(False)
    manager._discover_project_orphans = mock.Mock(
        side_effect=[initial, initial, initial, empty, empty, empty]
    )

    def cleanup_side_effect(*_args, **_kwargs):
        if manager.cleanup.call_count == 1:
            reporter.cleanup_summary["errors"].append(
                "router delete was temporarily blocked by a floating IP"
            )
            return False
        return True

    manager.cleanup = mock.Mock(side_effect=cleanup_side_effect)

    assert manager.cleanup_orphans() is True
    assert reporter.cleanup_summary["complete"] is True
    assert reporter.cleanup_summary["errors"] == []
    assert reporter.cleanup_summary["recovered_errors"] == [
        "router delete was temporarily blocked by a floating IP"
    ]
    assert reporter.cleanup_summary["orphan_sweep"]["stale_resources_remaining"] == 0
    reporter.logger.close()


def test_security_deny_is_unverified_when_ordinary_path_is_dead(
    config_factory,
):
    engine, _source, _target, _groups, records = _engine(config_factory)
    engine.builder.security_group_allows_port = mock.Mock(return_value=(False, []))
    engine.builder.add_temporary_security_rule = mock.Mock(return_value="rule-id")
    engine.probes.tcp.endpoint.return_value = _probe(False)

    deny = _spec("security-deny", category="security-group")
    engine._run_security_deny(deny)

    assert deny.authoritative is False
    assert records[-1][1].outcome == "inconclusive"
    engine.probes.tcp.endpoint_port.assert_not_called()

    allow = _spec("security-allow", category="security-group")
    engine._run_security_allow(allow)

    assert allow.authoritative is False
    assert records[-1][1].outcome == "inconclusive"
    engine.builder.add_temporary_security_rule.assert_not_called()


def test_oversized_mtu_rejection_is_unverified_when_boundary_failed(
    config_factory,
):
    engine, _source, _target, _groups, records = _engine(config_factory)
    engine.reporter = SimpleNamespace(
        get_result=lambda test_id: SimpleNamespace(
            test_id=test_id,
            status="FAIL",
            observed="blocked",
        )
    )
    spec = _spec("probe", category="mtu", protocol="mtu+1")
    spec.id = "AZ-BC-VAN2-MTU-LOCAL-LIMIT-4-provider-test"
    spec.expectation = "blocked"

    engine._run_endpoint_probe(spec)

    assert spec.authoritative is False
    assert records[-1][1].outcome == "inconclusive"
    engine.probes.endpoint.assert_not_called()
    assert records[-1][1].diagnostics["prerequisite_status"] == "FAIL"


def test_migration_is_not_started_when_every_functional_baseline_failed(
    config_factory,
):
    source = Endpoint(
        label="group:A",
        server_id="server-a",
        server_name="server-a",
        management_port_id="mgmt-a",
        management_ip="10.254.0.10",
        test_port_id="test-a",
        test_mac="fa:16:3e:00:00:0a",
        fixed_ips={"subnet": "192.0.2.10"},
        host="compute7",
        availability_zone="bc-van2",
        volume_id=None,
        side="A",
    )
    destination = Endpoint(
        label="group:B",
        server_id="server-b",
        server_name="server-b",
        management_port_id="mgmt-b",
        management_ip="10.254.0.11",
        test_port_id="test-b",
        test_mac="fa:16:3e:00:00:0b",
        fixed_ips={"subnet": "192.0.2.11"},
        host="compute8",
        availability_zone="bc-van2",
        volume_id=None,
        side="B",
    )
    plan_group = PlannedGroup(
        "group",
        "provider",
        "Provider",
        "network-id",
        "Public3",
        ["subnet"],
        [4],
    )
    runtime = RuntimeGroup(
        plan=plan_group,
        network_id="network-id",
        network_name="Public3",
        subnet_ids=["subnet"],
        router_id=None,
        endpoints=[source, destination],
        source_nat_enabled=None,
        fips={},
    )
    specs = [
        FluxTestSpec(
            id=f"BASE-{protocol.upper()}",
            category="same-subnet",
            operation="probe",
            family=4,
            expectation="reachable",
            expectation_reason="same subnet",
            authoritative=True,
            dependencies=["group"],
            source_group_id="group",
            destination_group_id="group",
            source_side="A",
            destination_side="B",
            source_subnet_id="subnet",
            destination_subnet_id="subnet",
            protocol=protocol,
            display_name=protocol,
            scenario="Provider subnet connectivity",
        )
        for protocol in ("icmp", "tcp", "udp", "mtu")
    ]
    recorded = []
    results = {
        spec.id: SimpleNamespace(test_id=spec.id, status="FAIL") for spec in specs
    }
    reporter = SimpleNamespace(
        get_result=lambda test_id: results.get(test_id),
        result=lambda test_id, category, status, message, **kwargs: recorded.append(
            SimpleNamespace(
                test_id=test_id,
                category=category,
                status=status,
                message=message,
                **kwargs,
            )
        ),
    )
    builder = SimpleNamespace(
        select_compute_migration_target=mock.Mock(),
        cold_migrate_endpoint=mock.Mock(),
        live_migrate_endpoint=mock.Mock(),
    )
    executor = _PlacementExecutor()
    executor.config = config_factory(
        action="run",
        compute_host_connectivity_enabled=True,
        migration_mode="live-preferred",
    )
    executor.reporter = reporter
    executor.logger = mock.Mock()
    executor.builder = builder
    executor.active = {"group": runtime}
    executor.runtime_specs = []
    executor._append_runtime_specs = lambda items: executor.runtime_specs.extend(items)

    engine = SimpleNamespace(run_specs=mock.Mock())
    executor._run_compute_placement_validation(specs, engine, dependencies=("group",))

    assert len(recorded) == 1
    assert recorded[0].status == "UNVERIFIED"
    assert recorded[0].observed == "functional-baseline-unavailable"
    assert recorded[0].details["lifecycle_cloud_operation_performed"] is False
    builder.select_compute_migration_target.assert_not_called()
    builder.cold_migrate_endpoint.assert_not_called()
    builder.live_migrate_endpoint.assert_not_called()
    engine.run_specs.assert_not_called()
