"""Translation owners change host while their provider observers remain fixed."""

from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.errors import SuiteError
from neutron_flux.host_qualification import HostQualificationPlanner
from neutron_flux.network_contract import PRIVATE_TRANSLATION_PROJECT_NETWORK
from neutron_flux.pair_placement import opposite_hosts
from neutron_flux.pair_suite import expand_pair_suite
from neutron_flux.pair_workflow import CoordinatedPairExecutor, workflow_plans
from neutron_flux.planning import Planner

from .test_host_qualification import _Inventory, _service
from .test_performance_and_html import _endpoint


@pytest.mark.parametrize("moving_index", [0, 1])
@pytest.mark.parametrize(
    "hosts",
    [("host1", "host1"), ("host2", "host2"), ("host1", "host2"), ("host2", "host1")],
)
def test_opposite_relation_preserves_the_selected_observer(hosts, moving_index):
    targets = opposite_hosts(
        hosts, {"host1": "az1", "host2": "az2"}, moving_index=moving_index
    )
    stationary = 1 - moving_index
    assert targets[stationary] == hosts[stationary]
    assert targets[moving_index] != hosts[moving_index]
    assert (targets[0] == targets[1]) != (hosts[0] == hosts[1])
    assert set(targets) <= {"host1", "host2"}


def test_opposite_relation_rejects_an_undefined_moving_endpoint():
    with pytest.raises(SuiteError, match="moving endpoints"):
        opposite_hosts(
            ("host1", "host2"), {"host1": "az1", "host2": "az1"}, moving_index=2
        )


@pytest.mark.parametrize(
    "hosts",
    [
        ("hyper001", "hyper001"),
        ("hyper002", "hyper002"),
        ("hyper001", "hyper002"),
        ("hyper002", "hyper001"),
    ],
)
@pytest.mark.parametrize("reverse_member_order", [False, True])
def test_every_provider_translation_workflow_moves_its_private_owner(
    config_factory, discovery_fixture, hosts, reverse_member_order
):
    config = config_factory(target_host_pairs=[("hyper001", "hyper002")])
    base = Planner(config, discovery_fixture, mock.Mock()).build()
    base.host_qualification = HostQualificationPlanner(
        config,
        discovery_fixture,
        base,
        _Inventory([_service("hyper001", "az1"), _service("hyper002", "az1")]),
        mock.Mock(),
    ).build()
    plan = expand_pair_suite(base)
    covered = set()
    owner_positions = set()
    for lane in workflow_plans(plan):
        kinds = {group.kind for group in lane.groups}
        if kinds != {"provider", PRIVATE_TRANSLATION_PROJECT_NETWORK}:
            continue
        initial = [
            spec for spec in lane.tests if spec.metadata["pair_placement"] == "initial"
        ]
        opposite = [
            spec
            for spec in lane.tests
            if spec.metadata["pair_placement"] == "opposite"
            and spec.operation != "pair-transition"
        ]
        transition = next(
            spec for spec in lane.tests if spec.operation == "pair-transition"
        )
        executor = object.__new__(CoordinatedPairExecutor)
        executor.scope = dict(initial[0].metadata)
        executor.groups = {group.id: group for group in lane.groups}
        executor.reporter = mock.Mock()
        groups = list(initial[0].dependencies)
        if reverse_member_order:
            groups.reverse()
        assert len(groups) == 2
        members = [
            (group, _endpoint(group, "A", f"192.0.2.{index + 10}", hosts[index]))
            for index, group in enumerate(groups)
        ]
        before_ids = [spec.id for spec in lane.tests]
        executor._prepare_opposite_placement(opposite, transition, members)
        targets = [
            executor.groups[group].metadata["target_hosts"][ep.side]
            for group, ep in members
        ]
        moving = next(
            index
            for index, (group, _) in enumerate(members)
            if executor.groups[group].kind == PRIVATE_TRANSLATION_PROJECT_NETWORK
        )
        owner_positions.add(moving)
        observer = 1 - moving
        assert targets[moving] != hosts[moving]
        assert targets[observer] == hosts[observer]
        assert (targets[0] == targets[1]) != (hosts[0] == hosts[1])
        assert sum(a != b for a, b in zip(hosts, targets, strict=True)) == 1
        assert (
            transition.metadata["pair_moving_server_id"] == members[moving][1].server_id
        )
        assert transition.metadata["pair_moving_reason"] == "private translation owner"
        for group, ep in members:
            assert (
                executor.groups[group].metadata["target_availability_zones"][ep.side]
                == "az1"
            )
        assert [spec.id for spec in lane.tests] == before_ids
        assert sum(spec.operation == "pair-transition" for spec in lane.tests) == 1
        assert all(
            spec.metadata["pair_moving_group_id"] == members[moving][0]
            for spec in opposite
        )
        covered.update(spec.operation for spec in initial)
    assert {
        "fip-baseline",
        "snat-packet-size-profile",
        "fip-egress-source-address",
    } <= covered
    # Group-role selection remains correct if dependency ordering changes.
    assert owner_positions == ({1} if reverse_member_order else {0})


def test_two_private_owners_keep_one_transition_and_the_existing_second_member_policy():
    executor = object.__new__(CoordinatedPairExecutor)
    executor.scope = {
        "requested_source_host": "host1",
        "requested_destination_host": "host2",
        "pair_selected_host_zones": {"host1": "az1", "host2": "az1"},
    }
    executor.groups = {
        group: SimpleNamespace(kind=PRIVATE_TRANSLATION_PROJECT_NETWORK)
        for group in ("private-one", "private-two")
    }
    executor.reporter = mock.Mock()
    executor._set_hosts = mock.Mock()
    members = [
        (group, _endpoint(group, "A", f"192.0.2.{index + 10}", host))
        for index, (group, host) in enumerate(
            (("private-one", "host1"), ("private-two", "host2"))
        )
    ]
    transition = SimpleNamespace(metadata={}, display_name="")
    executor._prepare_opposite_placement([], transition, members)
    assert transition.metadata["pair_scope_hosts"] == ["host1", "host1"]
    assert transition.metadata["pair_moving_group_id"] == "private-two"
    assert (
        transition.metadata["pair_moving_reason"] == "second endpoint in the topology"
    )


@pytest.mark.parametrize("private_index", [0, 1])
@pytest.mark.parametrize(
    "hosts",
    [("host1", "host1"), ("host2", "host2"), ("host1", "host2"), ("host2", "host1")],
)
def test_cross_zone_translation_workflows_keep_the_second_endpoint_policy(
    private_index, hosts
):
    executor = object.__new__(CoordinatedPairExecutor)
    zones = {"host1": "az1", "host2": "az2"}
    executor.scope = {
        "requested_source_host": "host1",
        "requested_destination_host": "host2",
        "pair_selected_host_zones": zones,
    }
    group_ids = (
        ["private", "provider"] if private_index == 0 else ["provider", "private"]
    )
    executor.groups = {
        group: SimpleNamespace(
            kind=PRIVATE_TRANSLATION_PROJECT_NETWORK
            if group == "private"
            else "provider"
        )
        for group in group_ids
    }
    executor.reporter = mock.Mock()
    executor._set_hosts = mock.Mock()
    members = [
        (group, _endpoint(group, "A", f"192.0.2.{index + 10}", hosts[index]))
        for index, group in enumerate(group_ids)
    ]
    for _, endpoint in members:
        endpoint.availability_zone = zones[str(endpoint.host)]
    transition = SimpleNamespace(metadata={}, display_name="")
    executor._prepare_opposite_placement([], transition, members)
    assert transition.metadata["pair_scope_hosts"] == list(opposite_hosts(hosts, zones))
    assert transition.metadata["pair_scope_zones"] == [
        zones[host] for host in opposite_hosts(hosts, zones)
    ]
    assert transition.metadata["pair_moving_group_id"] == group_ids[1]
    assert (
        transition.metadata["pair_moving_reason"] == "second endpoint in the topology"
    )
