"""Two compute relations, independent of selected pair count and load concurrency.

Host inventory, Nova and packet boundaries are synthetic. These assertions use
production expansion, grouping, estimates, scope verification and reporting.
"""

from __future__ import annotations

import copy
from collections import Counter
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.check_plan import build_check_plan
from neutron_flux.errors import RunCancelledError, SuiteError
from neutron_flux.executor import AdaptiveExecutor
from neutron_flux.host_qualification import HostQualificationPlanner
from neutron_flux.models import RuntimeGroup
from neutron_flux.pair_placement import opposite_hosts
from neutron_flux.pair_suite import (
    estimate_pair_suite,
    expand_pair_suite,
    run_pair_suite,
)
from neutron_flux.pair_workflow import CoordinatedPairExecutor, workflow_plans
from neutron_flux.planning import Planner
from neutron_flux.reporting_components.operator_context import host_scope_summary

from .test_cli_contract import configured
from .test_host_pair_workflow import planned
from .test_host_qualification import _Inventory, _service
from .test_performance_and_html import _endpoint
from .test_placement_reporting import _pair_scoped_payload
from .test_planned_check_inventory import network_plan


@pytest.mark.parametrize("pair_count", [1, 2, 4, 8])
def test_pair_count_and_concurrency_do_not_add_host_combinations(
    config_factory,
    discovery_fixture,
    pair_count,
):
    pairs = [(f"host{2 * i + 1}", f"host{2 * i + 2}") for i in range(pair_count)]
    config = config_factory(
        target_host_pairs=pairs + [(b, a) for a, b in pairs],
        fabric_scale_enabled=True,
        fabric_scale_pairs=[1, 2, 4, 8],
        performance_enabled=False,
    )
    base = network_plan()
    # Unselected hosts in inventory must not add qualification work.
    inventory = _Inventory(
        [
            _service(host, "az1")
            for host in [
                *(x for pair in pairs for x in pair),
                "unselected1",
                "unselected2",
            ]
        ]
    )
    base.host_qualification = HostQualificationPlanner(
        config,
        discovery_fixture,
        base,
        inventory,
        mock.Mock(),
    ).build()
    assert [
        (p.source_host, p.destination_host) for p in base.host_qualification.pairs
    ] == pairs
    plan = expand_pair_suite(base)
    build_check_plan(plan, config)
    estimate_pair_suite(Planner(config, discovery_fixture, mock.Mock()), plan)
    assert len(workflow_plans(plan)) == pair_count
    for lane in workflow_plans(plan):
        assert Counter(s.metadata["pair_placement"] for s in lane.tests) == {
            "initial": 6,
            "opposite": 7,
        }
        assert sum(s.operation == "pair-transition" for s in lane.tests) == 1
        for slot in ("initial", "opposite"):
            paths = [
                s
                for s in lane.tests
                if s.metadata["pair_placement"] == slot and s.operation == "probe"
            ]
            assert {(s.source_side, s.destination_side, s.protocol) for s in paths} == {
                (a, b, protocol)
                for a, b in (("A", "B"), ("B", "A"))
                for protocol in ("icmp", "tcp", "udp")
            }
    assert plan.estimated["targeted_migrations_maximum"] == pair_count
    assert plan.estimated["host_pair_placement_suites"] == 2 * pair_count
    assert len([c for c in plan.checks if c["kind"] == "load"]) == 2 * pair_count
    assert config.fabric_scale_pairs == [1, 2, 4, 8]
    assert all(not p.same_host for p in plan.host_qualification.pairs)


@pytest.mark.parametrize("levels", ["1", "2", "4", "8", "1,2,4,8"])
def test_public_concurrent_controls_remain_independent_of_two_placements(levels):
    config = configured(
        "--target-host-pairs",
        "host1:host2,host2:host1",
        "--concurrent-vm-pairs",
        levels,
        "--concurrent-repeats",
        "3",
        "--concurrent-duration",
        "20",
    )
    assert config.target_host_pairs == [("host1", "host2")]
    assert config.fabric_scale_pairs == [int(x) for x in levels.split(",")]
    assert (config.fabric_scale_runs, config.fabric_scale_duration_seconds) == (3, 20)
    assert config.live_migration_attempts == 5
    assert config.migration_submission_budget == 6


@pytest.mark.parametrize("hosts", [("a", "a"), ("a", "b"), ("b", "b"), ("b", "a")])
def test_opposite_mapping_changes_one_endpoint_and_relation_only(hosts):
    target = opposite_hosts(hosts, {"a": "az1", "b": "az1"})
    assert sum(a != b for a, b in zip(hosts, target, strict=True)) == 1
    assert (hosts[0] == hosts[1]) != (target[0] == target[1])
    assert target[0] == hosts[0]
    assert set(target) <= {"a", "b"}


@pytest.mark.parametrize(
    "hosts,zones",
    [
        (("a", "b"), {"a": "az1"}),
        (("a", "outside"), {"a": "az1", "b": "az1"}),
        (("", "b"), {"a": "az1", "b": "az1"}),
        (("a", "a"), {"a": "az1", "b": "az1", "c": "az1"}),
    ],
)
def test_opposite_mapping_rejects_undefined_or_out_of_scope_hosts(hosts, zones):
    with pytest.raises(SuiteError):
        opposite_hosts(hosts, zones)


@pytest.mark.parametrize("fault", ["policy", "uncoordinated", "third-slot"])
def test_legacy_or_mixed_policy_is_rejected_before_any_execution(
    config_factory,
    discovery_fixture,
    fault,
):
    config = config_factory(target_host_pairs=[("hyper001", "hyper002")])
    plan = planned(config, discovery_fixture)
    meta = plan.tests[0].metadata
    if fault == "policy":
        meta.pop("pair_placement_policy")
    elif fault == "uncoordinated":
        meta["coordinated_pair"] = False
    else:
        meta["pair_placement"] = "same-b"
    boundaries = [mock.Mock() for _ in range(5)]
    with pytest.raises(SuiteError, match="fresh run"):
        run_pair_suite(config, plan, *boundaries)
    assert all(not b.mock_calls for b in boundaries)


def test_compatibility_expansion_flag_cannot_restore_three_placements(
    config_factory,
    discovery_fixture,
):
    config = config_factory(target_host_pairs=[("hyper001", "hyper002")])
    template = planned(config, discovery_fixture)
    base = network_plan()
    base.host_qualification = template.host_qualification
    expanded = expand_pair_suite(base, coordinated=False)
    assert all(s.metadata["coordinated_pair"] for s in expanded.tests)
    assert sum(s.operation == "pair-transition" for s in expanded.tests) == 1
    assert expand_pair_suite(expanded, coordinated=False) is expanded
    assert {s.metadata["pair_placement"] for s in expanded.tests} == {
        "initial",
        "opposite",
    }


@pytest.mark.parametrize(
    "hosts",
    [("hyper001", "hyper001"), ("hyper002", "hyper002"), ("hyper002", "hyper001")],
)
def test_valid_retained_initial_endpoints_are_not_normalized(
    config_factory,
    discovery_fixture,
    hosts,
):
    config = config_factory(target_host_pairs=[("hyper001", "hyper002")])
    plan = planned(config, discovery_fixture)
    reporter = mock.Mock()
    reporter.plan = plan
    reporter.results = []
    builder = SimpleNamespace(
        runtime_groups=[], group_failures={}, verify_server_placement=mock.Mock()
    )
    executor = CoordinatedPairExecutor(
        config,
        workflow_plans(plan)[0],
        builder,
        reporter,
        mock.Mock(),
        mock.Mock(),
        mock.Mock(),
    )
    group = executor.plan.groups[0]
    eps = [
        _endpoint(str(i), side, f"192.0.2.{i + 10}", host)
        for i, (side, host) in enumerate(zip(("A", "B"), hosts, strict=True))
    ]
    for ep in eps:
        ep.availability_zone = "az1"
    runtime = RuntimeGroup(group, "network", "network", ["subnet"], None, eps, None, {})
    executor.active[group.id] = runtime
    executor._release = mock.Mock(side_effect=AssertionError("initial normalization"))
    with mock.patch.object(AdaptiveExecutor, "_ensure"):
        executor._ensure((group.id,), required_sides={group.id: ("A", "B")})
    assert executor.active[group.id] is runtime
    assert tuple(ep.host for ep in runtime.endpoints) == hosts
    assert tuple(executor.groups[group.id].metadata["target_hosts"].values()) == hosts
    executor._release.assert_not_called()


@pytest.mark.parametrize("fault", ["cancel", "scope", "az"])
def test_current_pair_placement_guard_cannot_accept_invalid_observation(
    config_factory,
    discovery_fixture,
    fault,
):
    config = config_factory(target_host_pairs=[("hyper001", "hyper002")])
    plan = planned(config, discovery_fixture)
    reporter = mock.Mock(plan=plan, results=[])
    builder = SimpleNamespace(
        runtime_groups=[], group_failures={}, verify_server_placement=mock.Mock()
    )
    executor = CoordinatedPairExecutor(
        config,
        workflow_plans(plan)[0],
        builder,
        reporter,
        mock.Mock(),
        mock.Mock(),
        mock.Mock(),
    )
    group = executor.plan.groups[0]
    ep = _endpoint("a", "A", "192.0.2.1", "hyper001")
    ep.availability_zone = "az1"
    runtime = RuntimeGroup(group, "net", "net", [], None, [ep], None, {})
    if fault == "cancel":
        builder.verify_server_placement.side_effect = RunCancelledError("stop")
        expected = RunCancelledError
    elif fault == "scope":
        ep.host = "unrequested"
        expected = SuiteError
    else:
        ep.availability_zone = "az9"
        expected = SuiteError
    with pytest.raises(expected):
        executor._verify_runtime(runtime)


def test_failed_side_cleanup_never_creates_opposite_endpoint():
    executor = object.__new__(CoordinatedPairExecutor)
    endpoint = _endpoint("a", "A", "192.0.2.1", "host1")
    runtime = SimpleNamespace(endpoints=[endpoint])
    executor.active = {"group": runtime}
    executor.groups = {"group": mock.Mock()}
    executor.builder = mock.Mock()
    executor.cleanup_manager = mock.Mock()
    executor.cleanup_manager.cleanup_group_side.return_value = False
    executor._record_unresolved_group = mock.Mock()
    with pytest.raises(SuiteError, match="Could not release"):
        executor._rotate("group", endpoint)
    executor.builder.build_group_side.assert_not_called()
    assert runtime.endpoints == [endpoint]
    executor._record_unresolved_group.assert_called_once_with("group")


def test_new_reports_explain_two_relations_without_rewriting_old_results():
    old = _pair_scoped_payload()
    saved = copy.deepcopy(old)
    assert host_scope_summary(old)["placement_policy"] == "historical"
    new = copy.deepcopy(old)
    for spec in new["plan"]["tests"]:
        spec["metadata"].update(
            pair_placement_policy="initial-opposite-v1", pair_placement="initial"
        )
    summary = host_scope_summary(new)
    assert summary["placement_policy"] == "initial-opposite-v1"
    assert "One intra-compute and one inter-compute placement" in summary["note"]
    assert "no third stage or return trip" in summary["note"]
    assert "same-host A, inter-host A:B, then same-host B" not in summary["note"]
    assert old == saved
