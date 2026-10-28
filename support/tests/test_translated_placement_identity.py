"""Exercise consecutive translation workflows on retained concrete endpoints."""

from __future__ import annotations

import copy
import dataclasses
from contextlib import nullcontext
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.check_ledger import check_ledger
from neutron_flux.check_plan import build_check_plan, cross_batch_key
from neutron_flux.engine import TestEngine as FluxTestEngine
from neutron_flux.errors import SuiteError
from neutron_flux.executor import AdaptiveExecutor
from neutron_flux.models import (
    ComputeHostInfo,
    MigrationResult,
    Plan,
    ProbeResult,
    RuntimeGroup,
)
from neutron_flux.reporting import Reporter

from ._shared import build_plan, endpoint


@pytest.fixture
def translated_cloud(config_factory, discovery_fixture, tmp_path, monkeypatch):
    reporters = []

    def make(*, planned_bindings=True):
        config = config_factory(
            action="run",
            performance_enabled=False,
            migration_mode="live-only",
            live_migration_continuity=False,
            convergence_interval=0,
        )
        base = build_plan(config, discovery_fixture, tmp_path)
        private = next(
            group
            for group in base.groups
            if group.kind == "private-translation-project-network"
            and group.floating_subnet_id == "s1v4"
        )
        provider = next(group for group in base.groups if group.id == "provider-n1")
        snat = [
            spec
            for spec in base.tests
            if spec.operation == "probe"
            and spec.metadata.get("require_no_floating_ip")
            and spec.source_group_id == private.id
        ]
        floating = [
            spec
            for spec in base.tests
            if spec.operation == "fip-baseline"
            and spec.destination_group_id == private.id
        ]
        assert len(snat) == len(floating) == 3
        assert cross_batch_key(snat[0])[:2] == cross_batch_key(floating[0])[:2]
        assert cross_batch_key(snat[0]) != cross_batch_key(floating[0])
        plan = Plan([provider], [private], {}, [], tests=[*snat, *floating])
        if planned_bindings:
            build_check_plan(plan, config)
        reporter = Reporter(config, f"translated-{len(reporters)}")
        reporters.append(reporter)
        reporter.plan = plan
        reporter.save_plan()
        private_endpoint = dataclasses.replace(
            endpoint("private"),
            fixed_ips={"private-subnet": "10.10.0.10"},
            host="compute1",
        )
        provider_endpoint = dataclasses.replace(
            endpoint("provider"),
            fixed_ips={"s1v4": "172.20.0.10"},
            host="compute2",
        )
        runtimes = [
            RuntimeGroup(
                private,
                "private-network",
                "private",
                ["private-subnet"],
                "router-private",
                [private_endpoint],
                True,
                {},
                metadata={"floating_ip_fixed_subnet_id": "private-subnet"},
            ),
            RuntimeGroup(
                provider,
                "n1",
                "Public1",
                ["s1v4"],
                None,
                [provider_endpoint],
                None,
                {},
            ),
        ]
        migrations = []
        packet_calls = []

        def route(source, source_ip, destination_ip, family):
            return {
                "returncode": 0,
                "device": "ens4",
                "source": source_ip,
                "interfaces": [
                    {
                        "ifname": "ens4",
                        "address": source.test_mac,
                        "addr_info": [
                            {"local": ip} for ip in source.fixed_ips.values()
                        ],
                    }
                ],
            }

        def packets(protocol, source, source_ip, destination_ip, family, **kwargs):
            packet_calls.append(
                (protocol, source.server_id, source.host, destination_ip)
            )
            return ProbeResult(
                outcome="reachable",
                success=True,
                elapsed_ms=1,
                attempts=1,
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol=protocol,
            )

        def ensure_fips(runtime, *, side, **kwargs):
            member = runtime.endpoint(side)
            runtime.fips[member.label] = {"id": "test-fip", "address": "172.20.0.20"}

        def migrate(moving, target, stationary):
            migrations.append((moving.server_id, moving.host, target.host))
            original = moving.host
            moving.host = target.host
            return MigrationResult(
                moving.server_id,
                original,
                target.host,
                "az1",
                "az1",
                True,
                False,
                True,
                details={"migration_mode": "live"},
            )

        builder = SimpleNamespace(
            discovery=discovery_fixture,
            runtime_groups=runtimes,
            group_failures={},
            ssh_endpoint=mock.Mock(),
            ssh_controller=mock.Mock(),
            inspect_endpoint_route=route,
            ensure_group_fips=ensure_fips,
            wait_floating_ip_association=lambda *args, **kwargs: {
                "matched": True,
                "port_id": private_endpoint.test_port_id,
                "fixed_ip_address": "10.10.0.10",
                "floating_ip_address": "172.20.0.20",
            },
            select_compute_migration_target=lambda moving, peer, *, desired_relation: (
                ComputeHostInfo(
                    peer.host if desired_relation == "same" else "compute2",
                    "az1",
                    True,
                    True,
                ),
                "eligible",
            ),
            live_migrate_endpoint=migrate,
            cloud_operation_coordinator=SimpleNamespace(
                transaction=lambda *args, **kwargs: nullcontext(),
                annotate_current_transaction=lambda **kwargs: None,
            ),
        )

        class PacketBoundaryEngine(FluxTestEngine):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.probes = SimpleNamespace(
                    endpoint=packets,
                    runner_fip=SimpleNamespace(
                        run=lambda address, cidr, **kwargs: (
                            ProbeResult(
                                "reachable", True, 1, 1, destination_ip=address
                            ),
                            False,
                        )
                    ),
                )
                self.diagnostics = SimpleNamespace(collect=lambda *args: (None, {}))

            def _verified_fip_probe(
                self,
                protocol,
                source,
                source_ip,
                floating_ip,
                destination,
                fixed_ip,
                **kwargs,
            ):
                # Packet I/O boundary only. Real handler selection, association
                # validation, path verification, policy and Reporter remain active.
                return packets(protocol, source, source_ip, floating_ip, 4)

        monkeypatch.setattr("neutron_flux.executor.TestEngine", PacketBoundaryEngine)
        executor = AdaptiveExecutor(
            config, plan, builder, reporter, mock.Mock(), mock.Mock(), SimpleNamespace()
        )
        executor.active = {runtime.plan.id: runtime for runtime in runtimes}
        executor._refresh_checkpoint = lambda: None
        executor._checkpoint = lambda **kwargs: None
        return SimpleNamespace(
            executor=executor,
            reporter=reporter,
            plan=plan,
            snat=snat,
            floating=floating,
            endpoints=(private_endpoint, provider_endpoint),
            migrations=migrations,
            packet_calls=packet_calls,
        )

    yield make
    for reporter in reporters:
        reporter.logger.close()


@pytest.mark.parametrize("planned_bindings", [True, False])
def test_snat_then_floating_ip_reuses_vms_without_colliding_placement_evidence(
    translated_cloud,
    planned_bindings,
):
    cloud = translated_cloud(planned_bindings=planned_bindings)
    approved = copy.deepcopy(cloud.plan.checks)
    identities = tuple(endpoint.server_id for endpoint in cloud.endpoints)
    cloud.executor._run_cross_phase()
    assert tuple(endpoint.server_id for endpoint in cloud.endpoints) == identities
    assert cloud.executor.group_loads == 0
    assert cloud.migrations == [
        (identities[1], "compute2", "compute1"),
        (identities[1], "compute1", "compute2"),
    ]
    assert cloud.plan.checks == approved
    assert all(row.status == "PASS" for row in cloud.reporter.results)
    baselines = [
        row
        for row in cloud.reporter.results
        if row.category == "compute-placement"
        and row.scenario == "Compute migration safety barrier"
    ]
    assert len(baselines) == 2
    assert len({row.test_id for row in baselines}) == 2
    assert [(row.source, row.destination) for row in baselines] == [
        ("compute1", "compute2"),
        ("compute1", "compute1"),
    ]
    sample_ids = [
        identity
        for baseline in baselines
        for round_ in baseline.details["rounds"]
        for identity in round_["test_ids"]
    ]
    assert len(sample_ids) == len(set(sample_ids)) == 6
    samples = [cloud.reporter.get_result(identity) for identity in sample_ids]
    assert {row.details["operation"] for row in samples} == {"probe", "fip-baseline"}
    post = [spec for spec in cloud.plan.tests if spec.metadata.get("source_spec_id")]
    assert len(post) == len({spec.id for spec in post}) == 6
    assert {spec.metadata["source_spec_id"] for spec in post} == {
        spec.id for spec in [*cloud.snat, *cloud.floating]
    }
    assert {spec.metadata["compute_placement"] for spec in post} == {
        "intra-compute",
        "inter-compute",
    }
    if planned_bindings:
        for baseline, specs in zip(
            baselines, (cloud.snat, cloud.floating), strict=True
        ):
            binding = specs[0].metadata["check_bindings"]["placement"][
                "MIGRATION-FUNCTIONAL-BASELINE"
            ]
            assert baseline.details["planned_check_id"] == binding
            for round_ in baseline.details["rounds"]:
                assert all(
                    cloud.reporter.get_result(identity).details["planned_check_id"]
                    == binding
                    for identity in round_["test_ids"]
                )
        assert {row["outcome"] for row in check_ledger(cloud.reporter)} == {"PASSED"}
    # Keep Reporter's strict immutability: exact repeats are idempotent, while
    # conflicting evidence under a reused identity must still fail loudly.
    baseline = baselines[-1]
    material = dataclasses.asdict(baseline)
    material.pop("test_id")
    material.pop("started_at")
    material.pop("duration_ms")
    before = len(cloud.reporter.results)
    assert cloud.reporter.result(baseline.test_id, **material) is baseline
    assert len(cloud.reporter.results) == before
    conflicting = {
        key: value
        for key, value in material.items()
        if key not in {"contract", "path_signature"}
    }
    with pytest.raises(SuiteError, match="Conflicting duplicate test result ID"):
        cloud.reporter.result(
            baseline.test_id, **{**conflicting, "message": "different evidence"}
        )
