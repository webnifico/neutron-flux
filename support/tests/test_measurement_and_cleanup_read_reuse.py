"""Efficiency checks retain evidence freshness, coverage and failure semantics."""

from __future__ import annotations

import dataclasses
import json
import threading
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.cleanup import CleanupManager
from neutron_flux.errors import RunCancelledError, SuiteError
from neutron_flux.executor import AdaptiveExecutor
from neutron_flux.mtu_contract import make_mtu_observation
from neutron_flux.openstack import OpenStack
from neutron_flux.pair_suite import PairScopeExecutor
from neutron_flux.performance import PerformanceRunner
from neutron_flux.resources import ResourceBuilder
from neutron_flux.scheduling import READ_WORKERS

from ._shared import completed, endpoint
from .test_concurrent_execution import spec


def performance_runner(config_factory, *, same_network=True, limit=0):
    endpoints = {
        side: dataclasses.replace(endpoint(label=side, side=side), host=f"host-{side}")
        for side in ("A", "B")
    }
    network_ids = {"ga": "shared", "gb": "shared" if same_network else "other"}
    mtu = {"shared": 1500, "other": 1450}

    def observe(group_id, _side):
        network_id = network_ids[group_id]
        return make_mtu_observation(
            label=network_id,
            reported_mtu=mtu[network_id],
            authority="Neutron",
            authoritative=True,
            resource_type="network",
            resource_id=network_id,
        )

    engine = SimpleNamespace(
        lifecycle={},
        groups={},
        _endpoint_address=lambda _group, side, subnet: (
            endpoints[side],
            endpoints[side].fixed_ips[subnet],
        ),
        _network_identity=lambda group, _side: (network_ids[group], network_ids[group]),
        _network_mtu_observation=mock.Mock(side_effect=observe),
    )
    reporter = mock.Mock(scope="")
    reporter.get_result.return_value = SimpleNamespace(status="PASS")
    runner = PerformanceRunner(
        config_factory(performance_max_paths=limit), mock.Mock(), reporter, engine
    )
    return runner, engine, endpoints, mtu


def reciprocal_specs(family):
    forward = dataclasses.replace(
        spec(f"IP{family}-FORWARD"),
        protocol="tcp",
        family=family,
        source_group_id="ga",
        destination_group_id="gb",
        source_side="A",
        destination_side="B",
        source_subnet_id=f"s{family}",
        destination_subnet_id=f"s{family}",
        dependencies=["ga", "gb"],
    )
    reverse = dataclasses.replace(
        forward,
        id=f"IP{family}-REVERSE",
        source_group_id="gb",
        destination_group_id="ga",
        source_side="B",
        destination_side="A",
    )
    return [forward, reverse]


@pytest.mark.parametrize("family", [4, 6])
def test_performance_planning_needs_no_live_mtu_reads(config_factory, family):
    runner, engine, _, _ = performance_runner(config_factory)
    engine._network_mtu_observation.side_effect = AssertionError(
        "planning did an API read"
    )
    rows = runner.plan_specs(reciprocal_specs(family), stage="cross-topology")
    assert len(rows) == 7
    assert {row.family for row in rows} == {family}
    assert all(row.metadata["directions"] == ["forward", "reverse"] for row in rows)
    engine._network_mtu_observation.assert_not_called()


def test_path_cap_and_reverse_qualification_still_apply_before_measurement(
    config_factory,
):
    runner, engine, _, _ = performance_runner(config_factory, limit=1)
    paths = runner._select_paths(
        reciprocal_specs(4) + reciprocal_specs(6), stage="cross-topology"
    )
    assert len(paths) == 1
    assert runner.session.eligible_by_stage["cross-topology"] == 2
    assert runner.session.omitted_by_stage["cross-topology"] == 1
    engine._network_mtu_observation.assert_not_called()
    fresh, _, _, _ = performance_runner(config_factory)
    assert fresh._select_paths(reciprocal_specs(4)[:1], stage="cross-topology") == []


@pytest.mark.parametrize("same_network,expected_reads", [(True, 1), (False, 2)])
def test_mtu_is_read_once_per_actual_network_and_refreshed_for_next_path(
    config_factory, same_network, expected_reads
):
    runner, engine, _, mtu = performance_runner(
        config_factory, same_network=same_network
    )
    path = runner._select_paths(reciprocal_specs(4), stage="cross-topology")[0]
    first = runner._resolve(path)
    assert engine._network_mtu_observation.call_count == expected_reads
    assert first.source_mtu == 1500
    assert first.destination_mtu == (1500 if same_network else 1450)
    assert first.source_mtu_evidence is not first.destination_mtu_evidence
    first.source_mtu_evidence["effective_mtu"] = 1
    assert first.destination_mtu_evidence["effective_mtu"] > 1
    mtu["shared"] = 1400
    second = runner._resolve(path)
    assert engine._network_mtu_observation.call_count == 2 * expected_reads
    assert second.source_mtu == 1400
    assert second.destination_mtu == (1400 if same_network else 1450)


@pytest.mark.parametrize("local_source", [True, False])
def test_floating_ip_planning_and_resolution_keep_source_and_bind_semantics(
    config_factory, local_source
):
    runner, engine, endpoints, _ = performance_runner(config_factory)
    engine.lifecycle["fip:gb"] = {
        "authoritative": True,
        "baseline": True,
        "target": endpoints["B"],
        "address": "203.0.113.20",
        "fixed_ip": "192.0.2.10",
        "source_ip": "198.51.100.10",
        "source": None if local_source else endpoints["A"],
        "source_mode": "runner" if local_source else "endpoint",
    }
    baseline = dataclasses.replace(reciprocal_specs(4)[0], operation="fip-baseline")
    paths = runner._select_paths([baseline], stage="floating-ip")
    assert len(paths) == 1
    assert paths[0].directions == ("forward",)
    engine._network_mtu_observation.assert_not_called()
    runner._local_path_mtu = mock.Mock(return_value=1400)
    resolved = runner._resolve(paths[0])
    assert resolved.destination_ip == "203.0.113.20"
    assert resolved.destination_bind_ip == "192.0.2.10"
    assert resolved.reverse_expected_peer_ip == "203.0.113.20"
    assert resolved.source_ip == "198.51.100.10"
    assert resolved.placement == (
        "runner-to-cloud" if local_source else "cross-compute"
    )
    assert engine._network_mtu_observation.call_count == 1
    assert runner._local_path_mtu.call_count == int(local_source)


def cleanup_manager(config_factory, responses):
    manager = object.__new__(CleanupManager)
    manager.config = config_factory(progress_interval=0)
    manager.logger = mock.Mock()
    manager.osc = OpenStack(manager.logger)
    manager.osc.run = mock.Mock(side_effect=responses)
    return manager


@pytest.mark.parametrize("resource_type", ["server", "volume"])
def test_cleanup_poll_reuses_same_fresh_observation_for_progress(
    config_factory, monkeypatch, resource_type
):
    manager = cleanup_manager(
        config_factory,
        [
            completed(stdout=json.dumps({"status": "deleting", "attachments": []})),
            completed(
                1,
                stderr=f"No {resource_type} with a name or ID of resource-1 was found",
            ),
        ],
    )
    monkeypatch.setattr(
        "neutron_flux.cleanup_components.deletion.time.sleep", lambda _seconds: None
    )
    assert manager._wait_absent(resource_type, "resource-1", 10)
    assert manager.osc.run.call_count == 2
    assert all(
        call.args[-2:] == ("-f", "json") for call in manager.osc.run.call_args_list
    )
    assert any(
        "status=deleting" in call.args[0] for call in manager.logger.log.call_args_list
    )


@pytest.mark.parametrize(
    "response",
    [
        completed(1, stderr="HTTP 401 Unauthorized"),
        completed(1, stderr="HTTP 403 Forbidden"),
        completed(1, stderr="HTTP 503 Service Unavailable"),
        completed(stdout="not json"),
        completed(stdout="[]"),
    ],
)
def test_cleanup_read_errors_never_become_absence(config_factory, response):
    manager = cleanup_manager(config_factory, [response])
    with pytest.raises(SuiteError, match="Could not determine whether"):
        manager._wait_absent("server", "resource-1", 10)
    assert manager.osc.run.call_count == 1


def test_cleanup_observation_propagates_cancellation_and_supports_exists_adapter(
    config_factory,
):
    manager = cleanup_manager(config_factory, [RunCancelledError("received signal 2")])
    with pytest.raises(RunCancelledError, match="received signal 2"):
        manager._wait_absent("volume", "resource-1", 10)
    manager.osc = SimpleNamespace(exists=mock.Mock(return_value=False))
    assert manager._wait_absent("volume", "resource-1", 10)
    manager.osc.exists.assert_called_once_with("volume", "resource-1")


@pytest.mark.parametrize(
    "pending",
    [
        {"status": "BUILD"},
        {"OS-EXT-STS:task_state": "migrating"},
        {"OS-EXT-SRV-ATTR:host": "other"},
        {"OS-EXT-STS:power_state": 4},
    ],
)
def test_pending_nova_skips_port_reads_but_settlement_still_requires_two_matches(
    config_factory, pending
):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(convergence_interval=0)
    builder.logger = mock.Mock()
    ready = {
        "status": "ACTIVE",
        "OS-EXT-STS:task_state": None,
        "OS-EXT-SRV-ATTR:host": "expected",
        "OS-EXT-STS:power_state": 1,
    }
    servers = iter([{**ready, **pending}, ready, ready, ready, ready])
    # The second eligible poll changes bindings. It must reset the consecutive
    # observation count, requiring two further matching complete observations.
    bindings = iter(["expected", "wrong", "expected", "expected"])

    def observe(kind, _action, _id, **_kwargs):
        if kind == "server":
            return next(servers)
        return {
            "device_id": "vm",
            "binding:host_id": next(bindings),
            "status": "ACTIVE",
        }

    builder.osc = SimpleNamespace(json=mock.Mock(side_effect=observe))
    result = builder._wait_for_server_settlement(
        "vm",
        ["port"],
        expected_statuses={"active"},
        expected_host="expected",
        require_power_state=True,
        stable_observations=2,
        timeout=5,
    )
    assert result == ready
    assert [call.args[0] for call in builder.osc.json.call_args_list] == [
        "server",
        "server",
        "port",
        "server",
        "port",
        "server",
        "port",
        "server",
        "port",
    ]


def batch_key(*groups):
    return (groups, tuple((group, ("A",)) for group in groups))


def test_mtu_batches_can_reuse_endpoints_without_crossing_mutation_or_dependency():
    executor = object.__new__(AdaptiveExecutor)
    executor.active = {"a": SimpleNamespace(endpoints=[SimpleNamespace(side="A")])}
    ab, cd, be, mutation, ef = [
        batch_key(*groups)
        for groups in [("a", "b"), ("c", "d"), ("b", "e"), ("s",), ("e", "f")]
    ]
    batches = {
        ab: [spec("ab", operation="mtu-scenario")],
        cd: [spec("cd")],
        be: [spec("be", operation="mtu-scenario")],
        mutation: [spec("mutation", operation="router-disable")],
        ef: [spec("ef")],
    }
    assert executor._reuse_ordered_cross_batches(batches) == [ab, be, cd, mutation, ef]
    batches[be][0].requires = ["cd"]
    assert executor._reuse_ordered_cross_batches(batches) == list(batches)
    batches[be][0].requires = []
    executor.config = SimpleNamespace(performance_enabled=True, performance_max_paths=1)
    assert executor._reuse_ordered_cross_batches(batches) == list(batches)


def test_pair_batch_reuse_accounts_for_required_host():
    executor = object.__new__(PairScopeExecutor)
    executor.scope = {"pair_scope_hosts": ["hyper001", "hyper002"]}
    executor.active = {
        "a": SimpleNamespace(endpoints=[SimpleNamespace(side="A", host="hyper002")])
    }
    incompatible, compatible = batch_key("a", "z"), batch_key("b", "a")
    batches = {incompatible: [spec("first")], compatible: [spec("second")]}
    assert executor._reuse_ordered_cross_batches(batches) == [compatible, incompatible]


def verification_manager(config_factory):
    manager = object.__new__(CleanupManager)
    manager.config = config_factory()
    manager.reporter = SimpleNamespace(
        resources=[
            SimpleNamespace(resource_type="server", id=str(index), name=f"vm-{index}")
            for index in range(READ_WORKERS * 2)
        ]
    )
    manager.osc = OpenStack(mock.Mock())
    return manager


def test_final_cleanup_reads_overlap_within_limit_and_preserve_leftover_order(
    config_factory,
):
    manager = verification_manager(config_factory)
    barrier = threading.Barrier(READ_WORKERS)

    def presence(_kind, _id):
        barrier.wait(timeout=5)
        return False

    def allocation(*args, **_kwargs):
        if args[4] == "0":
            return completed(stdout='{"allocations": {}}')
        return completed(stdout='{"allocations": {"provider": {"VCPU": 1}}}')

    manager.osc.exists = mock.Mock(side_effect=presence)
    manager.osc.run = mock.Mock(side_effect=allocation)
    issues = manager._verify_placement_allocations()
    assert issues == [
        f"placement_allocation:{index}:vm-{index}"
        for index in range(1, READ_WORKERS * 2)
    ]
    assert manager.osc.exists.call_count == READ_WORKERS * 2
    assert manager.osc.run.call_count == READ_WORKERS * 2


def test_unavailable_plugin_checked_once_without_hiding_uncertain_server_presence(
    config_factory,
):
    manager = verification_manager(config_factory)

    def presence(_kind, resource_id):
        if resource_id == "1":
            raise SuiteError("HTTP 503")
        return False

    manager.osc.exists = mock.Mock(side_effect=presence)
    manager.osc.run = mock.Mock(
        return_value=completed(
            2,
            stderr="openstack: 'resource provider allocation show' is not an openstack command",
        )
    )
    issues = manager._verify_placement_allocations()
    assert len(issues) == 1 and "server presence unknown: HTTP 503" in issues[0]
    assert manager.osc.exists.call_count == READ_WORKERS * 2
    assert manager.osc.run.call_count == 1
    manager.osc.run.reset_mock()
    manager._verify_placement_allocations()
    assert (
        manager.osc.run.call_count == 1
    )  # No stale capability cache on a later sweep.
