from __future__ import annotations

import subprocess
from collections import Counter
from types import SimpleNamespace

import pytest

from neutron_flux.engine import TestEngine as FluxTestEngine
from neutron_flux.errors import RetryableMigrationError
from neutron_flux.models import ComputeHostInfo, MigrationResult, ProbeResult
from neutron_flux.openstack import OpenStack
from neutron_flux.reporting_components.dashboard_findings import finding_summary

from ._shared import _placement_executor, endpoint


def _attestation(status: str, instance_id: str | None) -> dict[str, object]:
    return {"status": status, "instance_id": instance_id}


@pytest.mark.parametrize(
    ("before", "after", "expected"),
    [
        (
            _attestation("healthy", "instance-1"),
            _attestation("healthy", "instance-1"),
            "blocked",
        ),
        (
            _attestation("healthy", "instance-1"),
            _attestation("unhealthy", None),
            "error",
        ),
        (
            _attestation("healthy", "instance-1"),
            _attestation("healthy", "instance-2"),
            "inconclusive",
        ),
        (
            _attestation("unavailable", None),
            _attestation("healthy", "instance-1"),
            "inconclusive",
        ),
    ],
)
def test_blocked_tcp_requires_one_stable_healthy_destination_service(
    before: dict[str, object],
    after: dict[str, object],
    expected: str,
):
    probe = ProbeResult("blocked", False, 10, 1, protocol="tcp")

    FluxTestEngine._apply_blocked_tcp_attestation(probe, before, after)

    assert probe.outcome == expected
    attestation = probe.diagnostics["destination_tcp_service_attestation"]
    assert attestation["network_observation_accepted"] is (expected == "blocked")
    if expected != "blocked":
        assert probe.diagnostics["raw_outcome_before_service_attestation"] == "blocked"


def test_exact_pair_cold_fallback_uses_safe_reverse_direction(config_factory):
    source = endpoint("source", "A")
    destination = endpoint("destination", "B")
    source.host = "compute1"
    destination.host = "compute2"
    source.metadata["requested_host"] = "compute1"
    destination.metadata["requested_host"] = "compute2"
    compute1 = ComputeHostInfo("compute1", "az1", True, True, {"agg"}, {"agg"})
    compute2 = ComputeHostInfo("compute2", "az1", True, True, {"agg"}, {"agg"})
    calls: list[tuple[str, str, str]] = []

    def select(moving, stationary, *, desired_relation):
        assert desired_relation == "same"
        if moving is destination:
            assert stationary is source
            return [compute1], "eligible"
        assert moving is source
        assert stationary is destination
        return [compute2], "eligible"

    def live_migrate(moving, target, stationary):
        calls.append(("live", moving.label, target.host))
        raise RetryableMigrationError(
            "NoValidHost on compute1",
            unavailable=True,
            target_unsuitable=True,
        )

    def cold_migrate(moving, target):
        calls.append(("cold", moving.label, target.host))
        old_host = str(moving.host)
        moving.host = target.host
        return MigrationResult(
            server_id=moving.server_id,
            source_host=old_host,
            destination_host=target.host,
            source_availability_zone="az1",
            destination_availability_zone="az1",
            confirmed=True,
            automatically_confirmed=False,
            port_binding_verified=True,
            details={"migration_mode": "cold"},
        )

    builder = SimpleNamespace(
        select_compute_migration_targets=select,
        live_migrate_endpoint=live_migrate,
        cold_migrate_endpoint=cold_migrate,
    )
    config = config_factory(
        action="run",
        migration_mode="live-preferred",
        target_host_pairs=[("compute1", "compute2")],
        live_migration_attempts=1,
        storage="volume",
    )
    executor, spec, recorded = _placement_executor(
        config,
        source,
        destination,
        builder,
    )
    engine = SimpleNamespace(run_specs=lambda specs: None)

    executor._run_compute_placement_validation(
        [spec], engine, dependencies=("placement-group",)
    )

    assert calls == [
        ("live", "destination", "compute1"),
        ("cold", "source", "compute2"),
    ]
    assert source.host == destination.host == "compute2"
    live_result = next(
        result for result in recorded if result.scenario == "Live migration capability"
    )
    assert live_result.status == "UNVERIFIED"
    assert "will attempt" in live_result.message
    assert live_result.details["cold_fallback"] == {
        "available": True,
        "reason": "validated reverse direction selected after compute1 was proven unsuitable",
        "moving_endpoint": "source",
        "target_host": "compute2",
    }
    lifecycle = next(
        result
        for result in recorded
        if result.scenario == "Compute migration and placement lifecycle"
    )
    assert lifecycle.status == "PASS"


def test_openstack_commands_ignore_ambient_compute_microversion(monkeypatch, tmp_path):
    observed_environment = {}

    def invoke(command, **kwargs):
        observed_environment.update(kwargs["env"])
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setenv("OS_COMPUTE_API_VERSION", "2.56")
    monkeypatch.setattr("neutron_flux.openstack.run_cancellable", invoke)
    osc = OpenStack(SimpleNamespace(log=lambda *args, **kwargs: None))

    osc.run(
        "--os-compute-api-version",
        "2.latest",
        "server",
        "migration",
        "list",
        "--server",
        "server-1",
    )

    assert "OS_COMPUTE_API_VERSION" not in observed_environment


def test_connectivity_failure_summary_calls_a_contradiction_conclusive():
    summary = finding_summary(
        "connectivity",
        [{"status": "FAIL"}],
        path_count=1,
        measurements=[],
        status_counts=Counter({"FAIL": 1}),
    )

    assert "contradicted the declared expected behaviour" in summary
    assert "did not produce a conclusive" not in summary
