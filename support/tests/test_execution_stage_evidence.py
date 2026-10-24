"""Execution context follows recorded workflow facts and exact plan bindings."""

from __future__ import annotations

import copy
from contextlib import nullcontext
from dataclasses import asdict
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.engine import TestEngine as FluxTestEngine
from neutron_flux.execution.placement import PlacementValidationMixin
from neutron_flux.models import TestSpec as FluxTestSpec
from neutron_flux.pair_workflow import CoordinatedPairExecutor
from neutron_flux.reporting_components.operator_context import contextual_results
from neutron_flux.result_context import result_context

from ._shared import endpoint
from .test_host_pair_workflow import planned
from .test_translated_placement_identity import (
    translated_cloud as translated_stage_cloud,  # noqa: F401
)


def _spec(**metadata):
    return FluxTestSpec(
        "arbitrary-check",
        "mtu",
        "mtu-scenario",
        4,
        "reachable",
        "test evidence",
        True,
        ["group"],
        metadata=metadata,
    )


@pytest.mark.parametrize(
    "metadata,override,expected",
    [
        ({}, None, "initial-testing"),
        (
            {"check_bindings": {"placement": {"MIGRATION": "reserved"}}},
            None,
            "pre-migration",
        ),
        ({"pre_migration_functional_barrier": True}, None, "pre-migration"),
        (
            {
                "pre_migration_functional_barrier": True,
                "execution_stage": "post-live-migration",
            },
            "post-live-migration",
            "pre-migration",
        ),
        ({"execution_stage": "post-cold-migration"}, None, "post-cold-migration"),
        ({}, "post-endpoint-recreation", "post-endpoint-recreation"),
    ],
)
def test_actual_functional_dispatch_records_stage_without_mutating_plan(
    metadata, override, expected, monkeypatch
):
    engine = object.__new__(FluxTestEngine)
    engine.reporter = mock.Mock()
    engine.reporter.has_result.return_value = False
    engine.execution_stage_override = override
    executed = []
    engine._run_one = executed.append
    monkeypatch.setattr(
        "neutron_flux.engine.ACTIVITY.scope", lambda **kwargs: nullcontext()
    )
    spec = _spec(**metadata)
    before = copy.deepcopy(spec)
    engine.run_specs([spec])
    assert len(executed) == 1
    assert executed[0].metadata["execution_stage"] == expected
    assert spec == before


def test_consecutive_translated_workflows_keep_before_and_after_evidence(
    request,
):
    cloud = request.getfixturevalue("translated_stage_cloud")(planned_bindings=True)
    cloud.executor._run_cross_phase()
    rows = [
        row for row in cloud.reporter.results if row.category != "compute-placement"
    ]
    assert len(rows) == 18  # Initial checks, fresh safety checks and post-move checks.
    assert {row.details["execution_stage"] for row in rows} == {
        "pre-migration",
        "post-live-migration",
    }
    assert (
        sum(row.details["execution_stage"] == "post-live-migration" for row in rows)
        == 6
    )
    assert all(row.status == "PASS" for row in rows)


def test_readback_external_target_does_not_inherit_peer_vm_placement():
    executor = object.__new__(PlacementValidationMixin)
    spec = _spec(
        destination_compute_host="stale", destination_availability_zone="stale-az"
    )
    spec.operation = "egress"
    spec.category = "egress"
    spec.metadata["target"] = "1.1.1.1"
    source, peer = endpoint("source"), endpoint("peer")
    (post,) = executor._placement_probe_specs(
        [spec],
        relation="inter-compute",
        source=source,
        destination=peer,
        execution_stage="post-cold-migration",
    )
    assert post.metadata["execution_stage"] == "post-cold-migration"
    assert "destination_compute_host" not in post.metadata
    assert "destination_availability_zone" not in post.metadata
    assert spec.metadata["destination_compute_host"] == "stale"


def test_historical_report_joins_reserved_stages_without_id_or_host_heuristics():
    metadata = {
        "base_test_id": "unscoped-source",
        "availability_zone": "az-test",
        "check_bindings": {
            "placement": {"MIGRATION": "opaque-move"},
            "post-migration": "opaque-readback",
        },
    }
    payload = {
        "plan": {
            "tests": [{"id": "scoped-source", "phase": "intra", "metadata": metadata}],
            "checks": [
                {
                    "id": "opaque-performance",
                    "kind": "performance",
                    "stage": "group-local",
                    "prerequisites": ["scoped-source"],
                },
                {
                    "id": "opaque-readback",
                    "kind": "migration",
                    "stage": "post-migration",
                },
            ],
        },
        "results": [
            {
                "test_id": "unrelated-1",
                "category": "network-performance",
                "status": "PASS",
                "details": {
                    "planned_check_id": "opaque-performance",
                    "path": {
                        "stage": "group-local",
                        "source_spec_id": "unscoped-source",
                    },
                    "availability_zone": "az-test",
                },
            },
            {
                "test_id": "unrelated-2",
                "category": "mtu",
                "status": "PASS",
                "details": {
                    "planned_check_id": "opaque-readback",
                    "source_spec_id": "unscoped-source",
                    "availability_zone": "az-test",
                    "check_bindings": metadata["check_bindings"],
                },
            },
            {
                "test_id": "unrelated-3",
                "category": "same-subnet",
                "status": "PASS",
                "details": {
                    "source_compute_host": "same",
                    "destination_compute_host": "same",
                    "path": {"stage": "group-local"},
                },
            },
        ],
    }
    before = copy.deepcopy(payload)
    rows = contextual_results(payload)
    assert [result_context(row)["timing"] for row in rows] == [
        "Before migration",
        "After migration",
        "Migration timing not recorded",
    ]
    assert payload == before


@pytest.mark.parametrize(
    "pairs",
    [
        [("hyper001", "hyper001")],
        [("hyper001", "hyper001"), ("hyper001", "hyper002")],
    ],
)
def test_historical_initial_only_workflow_keeps_initial_timing_in_mixed_plan(
    pairs, config_factory, discovery_fixture
):
    plan = planned(
        config_factory(target_host_pairs=pairs, performance_enabled=True),
        discovery_fixture,
    )
    sources = [
        next(
            spec
            for spec in plan.tests
            if spec.operation == "probe"
            and "performance" in spec.metadata.get("check_bindings", {})
            and spec.metadata["pair_placement"] == "initial"
            and spec.metadata["pair_initial_host_hints"] == list(pair)
        )
        for pair in pairs
    ]
    results, expected = [], []
    for pair, source in zip(pairs, sources, strict=True):
        timing = "Initial testing" if pair[0] == pair[1] else "Before migration"
        performance_id = source.metadata["check_bindings"]["performance"][
            "group-local"
        ]["latency"]
        results.extend(
            [
                {
                    "test_id": source.id,
                    "category": source.category,
                    "status": "PASS",
                    "details": {},
                },
                {
                    "test_id": f"measurement-{source.id}",
                    "category": "network-performance",
                    "status": "PASS",
                    "details": {
                        "planned_check_id": performance_id,
                        "path": {
                            "source_spec_id": source.id,
                            "stage": "group-local",
                        },
                    },
                },
            ]
        )
        expected.extend([timing, timing])
    payload = {"plan": asdict(plan), "results": results}
    before = copy.deepcopy(payload)
    assert [result_context(row)["timing"] for row in contextual_results(payload)] == (
        expected
    )
    assert payload == before


@pytest.mark.parametrize(
    "stage,timing",
    [
        ("initial-testing", "Initial testing"),
        ("pre-migration", "Before migration"),
        ("post-live-migration", "After migration"),
        ("post-endpoint-recreation", "After endpoint recreation"),
    ],
)
def test_initial_only_historical_fallback_preserves_recorded_runtime_stage(
    stage, timing, config_factory, discovery_fixture
):
    plan = planned(
        config_factory(target_host_pairs=[("hyper001", "hyper001")]),
        discovery_fixture,
    )
    source = plan.tests[0]
    payload = {
        "plan": asdict(plan),
        "results": [
            {
                "test_id": source.id,
                "category": source.category,
                "status": "PASS",
                "details": {"execution_stage": stage},
            }
        ],
    }
    assert result_context(contextual_results(payload)[0])["timing"] == timing


def test_historical_external_target_discards_inherited_vm_context():
    context = result_context(
        {
            "category": "egress",
            "status": "PASS",
            "destination": "1.1.1.1",
            "details": {
                "operation": "egress",
                "destination_compute_host": "peer-vm-host",
                "destination_availability_zone": "peer-vm-zone",
                "destination_network_name": "peer-vm-network",
                "address_path": {
                    "destination": {
                        "network_name": "peer-vm-network",
                        "floating_ip_status": "verified attached",
                    }
                },
                "path": {
                    "destination_compute_host": "peer-vm-host",
                    "destination_availability_zone": "peer-vm-zone",
                },
            },
        }
    )
    assert context["destination"]["probe_address"] == "1.1.1.1"
    assert context["destination"]["compute_host"] is None
    assert context["destination"]["availability_zone"] is None
    assert context["destination"]["fixed_ip"] is None
    assert context["destination"]["network"] is None
    assert context["destination"]["floating_ip_status"] is None


@pytest.mark.parametrize(
    "stage", ["post-live-migration", "post-cold-migration", "post-endpoint-recreation"]
)
def test_pair_readback_uses_completed_operation_stage(
    stage, config_factory, monkeypatch
):
    executor = object.__new__(CoordinatedPairExecutor)
    executor.scope = {
        "pair_scope_id": "scope",
        "requested_source_host": "one",
        "requested_destination_host": "two",
        "pair_placement": "opposite",
        "host_qualification_cycle": 1,
    }
    executor.active = {}
    executor.builder = SimpleNamespace(discovery=None)
    executor.reporter = mock.Mock()
    executor.logger = mock.Mock()
    executor.config = config_factory()
    executor.plan = SimpleNamespace(tests=[])
    executor._completed_execution_stage = stage
    executor._run_performance = mock.Mock()
    monkeypatch.setattr(
        "neutron_flux.pair_workflow.TestEngine",
        lambda *args: SimpleNamespace(run_specs=mock.Mock()),
    )
    engine = executor._run_pair_stage([_spec()], "intra")
    assert engine.execution_stage_override == stage


@pytest.mark.parametrize(
    "transition,profile,same_zone,expected",
    [
        (False, "full", True, "initial-testing"),
        (True, "full", True, "pre-migration"),
        (True, "connectivity", True, "pre-endpoint-recreation"),
        (True, "full", False, "pre-endpoint-recreation"),
    ],
)
def test_pair_initial_stage_follows_the_planned_operation(
    transition, profile, same_zone, expected, config_factory, monkeypatch
):
    executor = object.__new__(CoordinatedPairExecutor)
    executor.scope = {
        "pair_scope_id": "scope",
        "requested_source_host": "one",
        "requested_destination_host": "two",
        "pair_placement": "initial",
        "host_qualification_cycle": 1,
        "qualification_strategy": "rolling",
        "qualification_profile": profile,
        "same_availability_zone": same_zone,
    }
    executor.active = {}
    executor.builder = SimpleNamespace(discovery=None)
    executor.reporter = mock.Mock()
    executor.logger = mock.Mock()
    executor.config = config_factory()
    executor.plan = SimpleNamespace(
        tests=[SimpleNamespace(operation="pair-transition")] if transition else []
    )
    executor._run_performance = mock.Mock()
    monkeypatch.setattr(
        "neutron_flux.pair_workflow.TestEngine",
        lambda *args: SimpleNamespace(run_specs=mock.Mock()),
    )
    specs = [_spec() for _ in range(3)]
    for spec, protocol in zip(specs, ("icmp", "tcp", "udp"), strict=True):
        spec.operation, spec.protocol = "probe", protocol
    engine = executor._run_pair_stage(specs, "intra")
    assert engine.execution_stage_override == expected
