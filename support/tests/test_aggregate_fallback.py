from __future__ import annotations

import dataclasses
import shlex
from unittest import mock

import pytest

from neutron_flux.cli import _hydrate_config_from_plan, parser
from neutron_flux.config import Config
from neutron_flux.errors import CommandError, CommandTimeoutError
from neutron_flux.host_qualification import HostQualificationPlanner
from neutron_flux.plan_contract import (
    configuration_snapshot,
    drift_diff,
    inventory_snapshot,
)
from neutron_flux.replay_plan import _replay_command
from neutron_flux.reporting import Reporter
from neutron_flux.resources import ResourceBuilder
from neutron_flux.zones import ZonePreflight

from ._shared import _placement_executor, _zone_launch_selection, endpoint
from .test_host_qualification import _plan, _service

KEY = "placement.compute_host_connectivity.require_shared_aggregate"
LAUNCH = [
    "--image",
    "debian-13",
    "--flavor",
    "s-g-1cpu-2gb",
    "--storage",
    "host",
    "--external-networks",
    "Public",
]
DENIED = CommandError(["openstack", "aggregate", "list"], 1, "", "403 Forbidden")
TIMED_OUT = CommandTimeoutError(["openstack", "aggregate", "list"], 5)


class Inventory:
    def __init__(self, rows, details=None, services=None):
        self.rows = rows
        self.details = details or {}
        self.services = services or [
            _service("c1", "zone-a"),
            _service("c2", "zone-a"),
            _service("c3", "zone-a"),
        ]

    def json(self, *args, **kwargs):
        if args[:3] == ("compute", "service", "list"):
            result = self.services
        elif args[:2] == ("aggregate", "list"):
            result = self.rows
        elif args[:2] == ("aggregate", "show"):
            result = self.details.get(args[2])
        else:
            raise AssertionError(args)
        if isinstance(result, Exception):
            raise result
        return result

    def optional_json(self, *args, **kwargs):
        return None


def builder_for(config, osc):
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config
    builder.osc = osc
    builder.reporter = mock.Mock()
    builder.logger = mock.Mock()
    builder._compute_host_inventory_cache = None
    return builder


def endpoints():
    source, peer = endpoint("source", "A"), endpoint("peer", "B")
    source.host, peer.host = "c1", "c2"
    source.availability_zone = peer.availability_zone = "zone-a"
    return source, peer


CASES = [
    (None, [], {}, True, "complete", 0),
    (True, [], {}, False, "complete", 0),
    (False, [], {}, True, "complete", 0),
    (None, [{"id": "a"}], {"a": {"hosts": ["c1", "c2"]}}, True, "complete", 1),
    (None, [{"id": "a"}], {"a": {"hosts": ["unselected-host"]}}, False, "complete", 1),
    (None, [{"id": "a"}], {"a": {"hosts": []}}, False, "complete", 1),
    (None, [{"id": "a"}], {"a": {"name": "hidden-members"}}, False, "partial", 1),
    (None, [{"id": "a"}], {"a": DENIED}, False, "partial", 1),
    (None, [{"id": "a"}], {"a": TIMED_OUT}, False, "partial", 1),
    (None, [{"id": "a"}], {}, False, "partial", 1),
    (None, ["bad-row"], {}, False, "partial", 1),
    (None, [{}], {}, False, "partial", 1),
    (None, None, {}, False, "unavailable", None),
    (None, {}, {}, False, "unavailable", None),
    (None, DENIED, {}, False, "unavailable", None),
    (None, TIMED_OUT, {}, False, "unavailable", None),
    (False, DENIED, {}, True, "unavailable", None),
    (False, TIMED_OUT, {}, True, "unavailable", None),
]


@pytest.mark.parametrize("migration_mode", ["cold-only", "live-preferred"])
@pytest.mark.parametrize("requirement,rows,details,allowed,state,count", CASES)
def test_policy_from_real_discovery_controls_exact_destination(
    config_factory, migration_mode, requirement, rows, details, allowed, state, count
):
    config = config_factory(
        require_shared_compute_aggregate=requirement, migration_mode=migration_mode
    )
    builder = builder_for(config, Inventory(rows, details))
    targets, reason = builder.select_compute_migration_targets(
        *endpoints(), desired_relation="same"
    )
    assert [host.host for host in targets] == (["c2"] if allowed else [])
    assert reason == "eligible" if allowed else reason != "eligible"
    assert builder._aggregate_inventory_state == state
    assert builder._aggregate_inventory_count == count
    event = builder.reporter.event.call_args.kwargs
    assert event["aggregate_count"] == count and event["inventory_state"] == state


@pytest.mark.parametrize(
    "field,value",
    [("State", "down"), ("Status", "disabled"), ("Zone", "zone-b"), ("Zone", "")],
)
def test_empty_inventory_never_bypasses_destination_health_or_az(
    config_factory, field, value
):
    osc = Inventory([])
    osc.services[1][field] = value
    builder = builder_for(config_factory(), osc)
    targets, reason = builder.select_compute_migration_targets(
        *endpoints(), desired_relation="same"
    )
    assert not targets and reason != "eligible"


@pytest.mark.parametrize(
    "field,value",
    [("State", "down"), ("Status", "disabled"), ("Zone", "zone-b"), ("Zone", "")],
)
def test_empty_inventory_never_bypasses_source_health_or_stale_az(
    config_factory, field, value
):
    osc = Inventory([])
    osc.services[0][field] = value
    builder = builder_for(config_factory(), osc)
    assert not builder.select_compute_migration_targets(
        *endpoints(), desired_relation="same"
    )[0]


def test_exact_pair_attempts_stay_within_requested_hosts(config_factory):
    config = config_factory(
        target_host_pairs=[("c1", "c2")], migration_mode="cold-only"
    )
    builder = builder_for(config, Inventory([]))
    source, peer = endpoints()
    source.metadata["requested_host"] = "c1"
    peer.metadata["requested_host"] = "c2"
    executor, _spec, _recorded = _placement_executor(config, source, peer, builder)
    attempts, _reason = executor._compute_migration_attempts(
        source, peer, desired_relation="same"
    )
    assert [(moving.host, target.host) for moving, _peer, target in attempts] == [
        ("c2", "c1"),
        ("c1", "c2"),
    ]
    assert all(target.host != "c3" for _moving, _peer, target in attempts)


@pytest.mark.parametrize("change", [None, DENIED, TIMED_OUT, [{"id": "elsewhere"}]])
def test_refresh_cannot_reuse_previous_empty_inventory(config_factory, change):
    osc = Inventory([])
    builder = builder_for(config_factory(), osc)
    assert builder.select_compute_migration_targets(
        *endpoints(), desired_relation="same"
    )[0]
    osc.rows = change
    targets, _ = builder.select_compute_migration_targets(
        *endpoints(), desired_relation="same"
    )
    assert not targets
    assert (
        builder._aggregate_inventory_count is None
        or builder._aggregate_inventory_count == 1
    )
    osc.rows = []
    assert builder.select_compute_migration_targets(
        *endpoints(), desired_relation="same"
    )[0]


@pytest.mark.parametrize(
    "rows,details,cohort",
    [([], {}, 2), (None, {}, 1), ([{"id": "a"}], {"a": {"hosts": ["elsewhere"]}}, 1)],
)
def test_automatic_policy_matches_az_scoring_multizone_and_targeted_estimates(
    config_factory, discovery_fixture, rows, details, cohort
):
    services = [
        _service(host, zone)
        for host, zone in (
            ("c1", "zone-a"),
            ("c2", "zone-a"),
            ("c3", "zone-b"),
            ("c4", "zone-b"),
        )
    ]
    osc = Inventory(rows, details, services)
    config = config_factory(
        availability_zones_all=True, zone_mode="both", allow_cross_az_networking=True
    )
    builder = builder_for(config, osc)
    hosts = builder.compute_host_inventory()
    assert (
        builder._availability_zone_score("zone-a", [hosts["c1"], hosts["c2"]])[2]
        == cohort
    )
    reporter = Reporter(config, "aggregate-zones")
    try:
        preflight = ZonePreflight(
            config, discovery_fixture, _plan(), osc, reporter, _zone_launch_selection()
        )
        zone_plan = preflight.build()
        assert zone_plan.zones == ["zone-a", "zone-b"]
        assert all(
            c.migration_cohort_size == cohort for c in zone_plan.capabilities.values()
        )
    finally:
        reporter.logger.close()
    config.availability_zones_all = False
    config.zone_mode = "per-zone"
    config.target_host_pairs = [("c1", "c2")]
    qualification = HostQualificationPlanner(
        config, discovery_fixture, _plan(), osc, mock.Mock()
    ).build()
    assert qualification.estimates["targeted_migrations"] == (1 if cohort == 2 else 0)
    assert qualification.eligible_pairs  # Connectivity coverage remains valid.


def test_unrelated_aggregate_changes_approved_auto_inventory(
    config_factory, discovery_fixture
):
    config = config_factory(target_host_pairs=[("c1", "c2")])
    osc = Inventory([])
    plan = _plan()
    planner = HostQualificationPlanner(
        config, discovery_fixture, plan, osc, mock.Mock()
    )
    plan.host_qualification = planner.build()
    approved = inventory_snapshot(discovery_fixture, plan)
    fingerprint = plan.host_qualification.inventory_fingerprint
    osc.rows = [{"id": "unrelated"}]
    osc.details = {"unrelated": {"hosts": ["elsewhere"]}}
    plan.host_qualification = planner.build()
    current = inventory_snapshot(discovery_fixture, plan)
    assert fingerprint != plan.host_qualification.inventory_fingerprint
    assert any(
        row["path"].startswith("aggregate_policy")
        for row in drift_diff(approved, current)
    )
    assert approved["hosts"] == current["hosts"]
    assert plan.host_qualification.estimates["targeted_migrations"] == 0


@pytest.mark.parametrize("requirement,rows,details,allowed,state,count", CASES)
def test_qualification_discovery_and_runtime_agree(
    config_factory, discovery_fixture, requirement, rows, details, allowed, state, count
):
    config = config_factory(
        target_host_pairs=[("c1", "c2")], require_shared_compute_aggregate=requirement
    )
    osc = Inventory(rows, details)
    qualification = HostQualificationPlanner(
        config, discovery_fixture, _plan(), osc, mock.Mock()
    ).build()
    assert qualification.aggregate_policy["inventory_state"] == state
    assert qualification.aggregate_policy["aggregate_count"] == count
    assert qualification.estimates["targeted_migrations"] == int(allowed)


def test_legacy_plan_and_replay_keep_strict_policy(
    config_factory, monkeypatch, tmp_path
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NEUTRON_FLUX_CONFIG", raising=False)
    snapshot = configuration_snapshot(config_factory())
    snapshot.pop("execution_settings")
    snapshot["migration"].pop("require_shared_aggregate")
    restored = config_factory()
    with mock.patch(
        "neutron_flux.cli.load_plan_contract",
        return_value=({"configuration": snapshot}, None),
    ):
        _hydrate_config_from_plan(restored, tmp_path / "plan.json")
    assert restored.require_shared_compute_aggregate is True
    legacy_configuration = dataclasses.asdict(config_factory())
    legacy_configuration.pop("require_shared_compute_aggregate")
    command = _replay_command({"configuration": legacy_configuration})
    replayed = Config.from_args(parser().parse_args(shlex.split(command)[2:]))
    assert replayed.require_shared_compute_aggregate is True
