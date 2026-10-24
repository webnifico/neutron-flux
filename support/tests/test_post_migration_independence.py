from __future__ import annotations

from types import SimpleNamespace

from neutron_flux.execution.placement import PlacementValidationMixin
from neutron_flux.models import ComputeHostInfo, Endpoint, MigrationResult
from neutron_flux.models import TestSpec as FluxTestSpec


class _Executor(PlacementValidationMixin):
    pass


def _endpoint(label: str, side: str, host: str) -> Endpoint:
    return Endpoint(
        label=label,
        server_id=f"server-{side.lower()}",
        server_name=f"server-{side.lower()}",
        management_port_id=f"mgmt-{side.lower()}",
        management_ip=f"10.254.0.{10 if side == 'A' else 11}",
        test_port_id=f"test-{side.lower()}",
        test_mac=f"fa:16:3e:00:00:{'0a' if side == 'A' else '0b'}",
        fixed_ips={"subnet": f"192.0.2.{10 if side == 'A' else 11}"},
        host=host,
        availability_zone="az1",
        volume_id=None,
        side=side,
        metadata={"group_id": "group"},
    )


def _spec(
    test_id: str, source_side: str, destination_side: str, protocol: str
) -> FluxTestSpec:
    return FluxTestSpec(
        id=test_id,
        category="mtu" if protocol.startswith("mtu") else "same-subnet",
        operation="probe",
        family=4,
        expectation="blocked" if protocol == "mtu+1" else "reachable",
        expectation_reason="planned post-migration validation",
        authoritative=True,
        dependencies=["group"],
        source_group_id="group",
        destination_group_id="group",
        source_side=source_side,
        destination_side=destination_side,
        source_subnet_id="subnet",
        destination_subnet_id="subnet",
        protocol=protocol,
        phase="intra",
        display_name=test_id,
        scenario="Representative MTU validation"
        if protocol.startswith("mtu")
        else "Same-network connectivity",
    )


def test_failed_readiness_does_not_block_the_exact_fourteen_post_migration_checks(
    config_factory,
):
    source = _endpoint("group:A", "A", "compute1")
    destination = _endpoint("group:B", "B", "compute2")
    runtime = SimpleNamespace(
        endpoint=lambda side: source if side == "A" else destination
    )
    target = ComputeHostInfo("compute1", "az1", True, True, {"agg"}, {"agg"})

    protocols = ("icmp", "tcp", "udp")
    specs = (
        [_spec(f"same-a-b-{protocol}", "A", "B", protocol) for protocol in protocols]
        + [_spec(f"same-b-a-{protocol}", "B", "A", protocol) for protocol in protocols]
        + [
            _spec("mtu-boundary", "A", "B", "mtu"),
        ]
    )
    # Two equivalent topology generations reproduce the observed 14-row cascade.
    specs = specs + [
        FluxTestSpec(**{**spec.__dict__, "id": f"second-{spec.id}"}) for spec in specs
    ]

    def migrate(moving, selected):
        old_host = moving.host
        moving.host = selected.host
        return MigrationResult(
            server_id=moving.server_id,
            source_host=old_host,
            destination_host=selected.host,
            source_availability_zone="az1",
            destination_availability_zone="az1",
            confirmed=True,
            automatically_confirmed=False,
            port_binding_verified=True,
            endpoint_ready=False,
            endpoint_recovery_error="transient probe startup failed: address already in use",
            details={"migration_mode": "cold"},
        )

    recorded = []
    reporter = SimpleNamespace(
        result=lambda test_id, category, status, message, **kwargs: recorded.append(
            SimpleNamespace(
                test_id=test_id,
                category=category,
                status=status,
                message=message,
                **kwargs,
            )
        ),
        has_result=lambda test_id: False,
    )
    executor = _Executor()
    executor.config = config_factory(
        action="run",
        migration_mode="cold-only",
        compute_host_connectivity_enabled=True,
    )
    executor.reporter = reporter
    executor.logger = SimpleNamespace(
        section=lambda *args, **kwargs: None, log=lambda *args, **kwargs: None
    )
    executor.builder = SimpleNamespace(
        select_compute_migration_target=lambda *args, **kwargs: (target, "eligible"),
        cold_migrate_endpoint=migrate,
    )
    executor.active = {"group": runtime}
    executor.runtime_specs = []
    executor._append_runtime_specs = lambda items: executor.runtime_specs.extend(items)
    executor._run_performance = lambda *args, **kwargs: None

    batches = []
    engine = SimpleNamespace(run_specs=lambda items: batches.append(list(items)))

    executor._run_compute_placement_validation(specs, engine, dependencies=("group",))

    assert len(batches) == 1
    assert len(batches[0]) == 14
    assert all(
        item.scenario == "Intra-compute connectivity"
        or item.scenario == "Representative MTU validation"
        for item in batches[0]
    )
    assert not [item for item in recorded if item.status == "BLOCKED_BY_SETUP_ERROR"]
    readiness = [
        item
        for item in recorded
        if item.scenario == "Post-migration endpoint readiness"
    ]
    assert len(readiness) == 1
    assert readiness[0].status == "FAIL"
