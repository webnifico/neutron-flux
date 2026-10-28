"""Compose public options through the complete production plan pipeline."""

from __future__ import annotations

import itertools
from collections import Counter
from unittest import mock

import pytest

from neutron_flux import cli
from neutron_flux.check_plan import build_check_plan, endpoint_sides
from neutron_flux.config import Config
from neutron_flux.host_qualification import HostQualificationPlanner
from neutron_flux.pair_suite import estimate_pair_suite, expand_pair_suite
from neutron_flux.pair_workflow import workflow_plans
from neutron_flux.planning import Planner
from neutron_flux.translation_safety import validate_plan_translation_safety

from .test_host_qualification import _Inventory, _service
from .test_network_matrix_packet_ownership import (
    _assert_reference_integrity,
    _selected_discovery,
)

LOAD_OPTIONS = {
    "off": [],
    "ordered": ["--concurrent-vm-pairs", "1,2,4,32"],
    "unsorted": ["--concurrent-vm-pairs", "32,1,4,2"],
}


def _build_composed(config, discovery, inventory):
    planner = Planner(config, discovery, mock.Mock())
    base = planner.build()
    base.host_qualification = HostQualificationPlanner(
        config, discovery, base, inventory, mock.Mock()
    ).build()
    plan = expand_pair_suite(base)
    estimate_pair_suite(planner, plan)
    build_check_plan(plan, config)
    return base, plan


def _assert_owned_paths_and_budget(base, plan, config, discovery):
    _assert_reference_integrity(plan, discovery)
    validate_plan_translation_safety(plan)
    lanes = workflow_plans(plan)
    assert lanes
    coverage = Counter()
    transitions = 0
    for lane in lanes:
        initial = [
            spec for spec in lane.tests if spec.metadata["pair_placement"] == "initial"
        ]
        opposite = [
            spec
            for spec in lane.tests
            if spec.metadata["pair_placement"] == "opposite"
            and spec.operation != "pair-transition"
        ]
        assert initial
        same_host_scope = (
            initial[0].metadata["requested_source_host"]
            == initial[0].metadata["requested_destination_host"]
        )
        moves = [spec for spec in lane.tests if spec.operation == "pair-transition"]
        assert len(moves) == (0 if same_host_scope else 1)
        if same_host_scope:
            assert opposite == []
        else:
            assert {spec.metadata["base_test_id"] for spec in initial} == {
                spec.metadata["base_test_id"] for spec in opposite
            }
        assert {spec.metadata["pair_placement"] for spec in lane.tests} <= {
            "initial",
            "opposite",
        }
        for spec in initial:
            coverage[spec.metadata["base_test_id"]] += 1
            if spec.phase != "intra":
                # Cross-topology paths own one endpoint per dependency. Same-
                # router peer paths own A/B of the existing two-VM topology.
                assert sum(len(sides) for _, sides in endpoint_sides(spec)) == 2
            elif spec.dependencies:
                assert len(spec.dependencies) == 1
            for group_id in filter(
                None, (spec.source_group_id, spec.destination_group_id)
            ):
                assert group_id in spec.dependencies
            assert (
                spec.metadata["requested_source_host"]
                in spec.metadata["pair_selected_host_zones"]
            )
            assert (
                spec.metadata["requested_destination_host"]
                in spec.metadata["pair_selected_host_zones"]
            )
        transitions += len(moves)
    expected = {
        spec.id for spec in base.tests if spec.scenario != "Controller readiness"
    }
    assert set(coverage) == expected
    assert set(coverage.values()) == {
        len(base.host_qualification.pairs) * base.host_qualification.cycles
    }
    assert (
        plan.estimated["targeted_migrations_maximum"]
        + plan.estimated["endpoint_recreations"]
        == transitions
    )
    assert plan.estimated["peak_endpoint_instances"] >= 2
    assert (
        plan.estimated["endpoint_vm_boots_maximum"]
        >= plan.estimated["endpoint_vm_boots"]
    )
    if config.fabric_scale_enabled:
        maximum = max(config.fabric_scale_pairs)
        assert plan.estimated["peak_endpoint_instances"] >= 2 * maximum
        assert plan.estimated["peak_instances"] >= 2 * maximum + 2
        scopes = {
            spec.metadata["pair_scope_id"]
            for spec in plan.tests
            if spec.metadata.get("pair_scope_id")
        }
        assert plan.estimated["concurrent_load_endpoint_boots"] == 2 * maximum * len(
            scopes
        )
        assert any(check["kind"] == "load" for check in plan.checks)
    else:
        assert not any(check["kind"] == "load" for check in plan.checks)
        assert plan.estimated["peak_endpoint_instances"] == 2
    if config.storage == "host":
        assert plan.estimated["peak_volumes"] == 0
    else:
        assert plan.estimated["peak_volumes"] >= plan.estimated["peak_instances"]
    performance_checks = [
        check for check in plan.checks if check["kind"] == "performance"
    ]
    assert performance_checks
    assert {check["measurement"] for check in performance_checks} >= {
        "tcp-throughput",
        "udp",
        "latency",
        "mtu-mss",
    }
    before = [check["id"] for check in plan.checks]
    build_check_plan(plan, config)
    assert [check["id"] for check in plan.checks] == before
    assert len(before) == len(set(before))


@pytest.mark.parametrize(
    "storage,migration,profile,load",
    list(
        itertools.product(
            ("host", "volume"),
            ("live", "cold"),
            ("standard", "exhaustive"),
            LOAD_OPTIONS,
        )
    ),
)
def test_public_option_cross_product_preserves_owned_paths_and_resource_bounds(
    discovery_fixture, tmp_path, storage, migration, profile, load
):
    args = cli.parser().parse_args(
        [
            "run",
            "--image",
            "debian-13",
            "--flavor",
            "small",
            "--external-networks",
            "Public1,Public2,Public3",
            "--storage",
            storage,
            "--migration-mode",
            migration,
            "--performance-profile",
            profile,
            "--target-host-pairs",
            "host-a:host-b",
            *LOAD_OPTIONS[load],
            *(["--volume-type", "fast"] if storage == "volume" else []),
        ]
    )
    cli._validate_action_arguments(args)
    config = Config.from_args(args)
    config.report_dir = tmp_path
    base, plan = _build_composed(
        config,
        discovery_fixture,
        _Inventory([_service(host, "az1") for host in ("host-a", "host-b")]),
    )
    _assert_owned_paths_and_budget(base, plan, config, discovery_fixture)
    assert config.effective_migration_storage == (
        "host" if storage == "host" else "shared"
    )
    assert config.live_migration_continuity == (migration == "live")
    assert config.performance_repeats == (3 if profile == "exhaustive" else 2)


@pytest.mark.parametrize(
    "scope,networks,repeat",
    [
        ("single-host", ["n3"], 1),
        ("pair", ["n1"], 3),
        ("cross-az-pair", ["n1", "n2", "n3"], 3),
        ("two-pairs", ["n1", "n2", "n3"], 1),
        ("aggregate", ["n3"], 3),
    ],
)
def test_scope_family_and_repeat_compose_with_the_same_packet_contract(
    discovery_fixture, tmp_path, scope, networks, repeat
):
    flags = {
        "single-host": ["--target-hosts", "host-a"],
        "pair": ["--target-host-pairs", "host-a:host-b"],
        "cross-az-pair": ["--target-host-pairs", "host-a:host-b"],
        "two-pairs": ["--target-host-pairs", "host-a:host-b,host-c:host-d"],
        "aggregate": ["--target-aggregates", "edge"],
    }[scope]
    discovery = _selected_discovery(discovery_fixture, networks)
    names = ",".join(network.name for network in discovery.networks)
    args = cli.parser().parse_args(
        [
            "run",
            "--image",
            "debian-13",
            "--flavor",
            "small",
            "--external-networks",
            names,
            "--storage",
            "volume",
            "--volume-type",
            "fast",
            "--migration-mode",
            "live",
            "--performance-profile",
            "exhaustive",
            "--repeat",
            str(repeat),
            "--ping-target-ipv4",
            "203.0.113.10",
            "--ping-target-ipv6",
            "2001:db8::10",
            *flags,
        ]
    )
    cli._validate_action_arguments(args)
    config = Config.from_args(args)
    config.report_dir = tmp_path
    inventory = _Inventory(
        [
            _service(
                host, "az2" if scope == "cross-az-pair" and host == "host-b" else "az1"
            )
            for host in ("host-a", "host-b", "host-c", "host-d")
        ],
        aggregates=[
            {"id": "agg", "name": "edge", "hosts": ["host-a", "host-b", "host-c"]}
        ],
    )
    base, plan = _build_composed(config, discovery, inventory)
    _assert_owned_paths_and_budget(base, plan, config, discovery)
    assert config.repeat_count == repeat
    if networks == ["n3"]:
        assert not any(
            spec.family == 6 and spec.operation == "egress" for spec in plan.tests
        )
        assert any(
            item["resource"] == "External IPv6 reachability" for item in plan.skipped
        )
    if scope == "cross-az-pair":
        assert plan.estimated["targeted_migrations_maximum"] == 0
        assert plan.estimated["endpoint_recreations"] > 0
