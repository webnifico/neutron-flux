"""Command scope and host qualification contracts."""

from __future__ import annotations

from unittest import mock

import pytest

from neutron_flux.cli import _validate_action_arguments, parser
from neutron_flux.errors import SuiteError
from neutron_flux.host_qualification import HostQualificationPlanner
from neutron_flux.test_selection import select_plan_tests

from .test_host_pair_workflow import planned
from .test_host_qualification import _Inventory, _service
from .test_planned_check_inventory import network_plan


def _validate(*argv: str) -> None:
    _validate_action_arguments(parser().parse_args(list(argv)))


@pytest.mark.parametrize("action", ["status", "cleanup", "report", "compare", "trend"])
def test_performance_profile_is_rejected_outside_plan_run(action):
    argv = [action]
    if action == "reconcile":
        argv += [
            "--operation-id",
            "op",
            "--resolution",
            "succeeded",
            "--evidence-file",
            "e.json",
            "--resolution-message",
            "ok",
        ]
    elif action == "report":
        argv += ["results.json"]
    elif action == "compare":
        argv += ["a.json", "b.json"]
    elif action == "trend":
        argv += ["results.json"]
    argv += ["--performance-profile", "exhaustive"]
    with pytest.raises(SuiteError, match="performance-profile"):
        _validate(*argv)


def test_one_resolved_target_host_automatically_tests_same_host(
    config_factory, discovery_fixture
):
    config = config_factory(target_hosts=["hyper001"], include_same_host=False)
    base = network_plan()
    planner = HostQualificationPlanner(
        config,
        discovery_fixture,
        base,
        _Inventory([_service("hyper001", "az1")]),
        mock.Mock(),
    )
    result = planner.build()
    assert result is not None
    assert [(pair.source_host, pair.destination_host) for pair in result.pairs] == [
        ("hyper001", "hyper001")
    ]


def test_one_target_host_is_valid_when_same_host_was_explicitly_requested(
    config_factory, discovery_fixture
):
    config = config_factory(target_hosts=["hyper001"], include_same_host=True)
    base = network_plan()
    plan = HostQualificationPlanner(
        config,
        discovery_fixture,
        base,
        _Inventory([_service("hyper001", "az1")]),
        mock.Mock(),
    ).build()
    assert plan is not None
    assert [(pair.source_host, pair.destination_host) for pair in plan.pairs] == [
        ("hyper001", "hyper001")
    ]


def test_include_derived_base_selection_retains_coordinated_migration_transitions(
    config_factory, discovery_fixture
):
    config = config_factory(
        target_host_pairs=[("hyper001", "hyper002")],
        include_derived_tests=True,
        performance_enabled=False,
    )
    plan = planned(config, discovery_fixture)
    representative = next(
        spec
        for spec in plan.tests
        if spec.operation == "probe"
        and spec.protocol == "tcp"
        and spec.metadata.get("base_test_id")
    )
    base_test_id = representative.metadata["base_test_id"]
    selected = select_plan_tests(plan, [base_test_id], include_derived=True)

    transitions = [
        spec for spec in selected.tests if spec.operation == "pair-transition"
    ]
    assert [spec.metadata["pair_placement"] for spec in transitions] == [
        "opposite",
    ]
    selected_ids = {spec.id for spec in selected.tests}
    assert all(
        set(spec.requires + spec.requires_pass) <= selected_ids for spec in transitions
    )

    for transition in transitions:
        batch = transition.metadata["workflow_batch"]
        source_placement = transition.metadata["transition_from"]
        protocols = {
            spec.protocol
            for spec in selected.tests
            if spec.metadata.get("workflow_batch") == batch
            and spec.metadata.get("pair_placement") == source_placement
            and spec.operation == "probe"
            and spec.authoritative
            and spec.expectation == "reachable"
        }
        assert {"icmp", "tcp", "udp"} <= protocols


def test_include_derived_concrete_selection_does_not_widen_to_other_placements(
    config_factory, discovery_fixture
):
    config = config_factory(target_host_pairs=[("hyper001", "hyper002")])
    plan = planned(config, discovery_fixture)
    concrete = next(
        spec
        for spec in plan.tests
        if spec.operation == "probe" and spec.protocol == "tcp"
    )
    selected = select_plan_tests(plan, [concrete.id], include_derived=True)
    scopes = {
        spec.metadata.get("pair_scope_id")
        for spec in selected.tests
        if spec.metadata.get("pair_scope_id")
    }
    assert scopes == {concrete.metadata["pair_scope_id"]}
    assert not any(spec.operation == "pair-transition" for spec in selected.tests)
