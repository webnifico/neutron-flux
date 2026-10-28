"""Resume must reconcile owned resources before testing fresh quota headroom."""

from __future__ import annotations

import copy
import dataclasses
import json
from unittest import mock

import pytest

from neutron_flux.capability_preflight import CapabilityPreflight
from neutron_flux.errors import SuiteError
from neutron_flux.models import QuotaInfo
from neutron_flux.plan_contract import (
    create_plan_contract,
    load_plan_contract,
    verify_plan_contract,
)
from neutron_flux.planning import Planner

from .test_suite_orchestration import _suite


class PlanningReached(Exception):
    pass


@pytest.mark.parametrize("tracked", [False, True])
def test_resume_reclaims_old_quota_before_planning(
    config_factory, discovery_fixture, tmp_path, monkeypatch, tracked
):
    suite = _suite(config_factory, tmp_path, resume_run_id="suite-test")
    config = suite.config
    baseline = copy.deepcopy(discovery_fixture)
    original_build = Planner.build
    plan = original_build(Planner(config, baseline, suite.logger))
    peak = int(plan.estimated["peak_instances"])
    baseline.quota_info = {"instances": QuotaInfo("instances", peak, 0)}
    approved = create_plan_contract(config, baseline, plan)
    saved = tmp_path / "plan.json"
    saved.write_text(json.dumps(approved))
    suite.checkpoint.plan_path = str(saved)
    if tracked:
        suite.tracker.add("server", "old-server", "old-endpoint")
    state = {"clean": False}

    def discover():
        return dataclasses.replace(
            baseline,
            quota_info={
                "instances": QuotaInfo("instances", peak, 0 if state["clean"] else peak)
            },
        )

    def cleanup(**kwargs):
        assert kwargs["adopt_discovered"] is True
        state["clean"] = True
        for resource in suite.reporter.resources:
            suite.tracker.mark_deleted(resource, "deleted")
        return True

    def checked_build(planner):
        result = original_build(planner)
        assert result.estimated["peak_instances"] == peak
        raise PlanningReached

    suite._preflight_commands = mock.Mock()
    suite.cleanup_manager.cleanup = mock.Mock(side_effect=cleanup)
    monkeypatch.setattr(
        "neutron_flux.suite.Discoverer.discover", lambda _self: discover()
    )
    monkeypatch.setattr("neutron_flux.suite.resolve_launch_selection", mock.Mock())
    monkeypatch.setattr(Planner, "build", checked_build)
    with pytest.raises(PlanningReached):
        suite.execute()
    suite.cleanup_manager.cleanup.assert_called_once()
    assert state["clean"] is True
    assert suite.discovery.quota_info["instances"].used == 0
    suite.reporter.logger.close()


def test_resume_discovers_orphans_even_when_manifest_is_empty(config_factory, tmp_path):
    suite = _suite(config_factory, tmp_path, resume_run_id="suite-test")
    suite.cleanup_manager.cleanup = mock.Mock(return_value=True)
    assert not suite.reporter.resources
    suite._cleanup_stale_resume_resources()
    suite.cleanup_manager.cleanup.assert_called_once()
    assert suite.cleanup_manager.cleanup.call_args.kwargs["adopt_discovered"] is True
    suite.reporter.logger.close()


def test_quota_usage_changes_do_not_change_the_approved_workload(
    config_factory, discovery_fixture
):
    config = config_factory()
    discovery_fixture.quota_info = {"instances": QuotaInfo("instances", 100, 1)}
    plan = Planner(config, discovery_fixture, mock.Mock()).build()
    approved = create_plan_contract(config, discovery_fixture, plan)
    current = copy.deepcopy(approved)
    row = current["inventory"]["quotas"][0]
    row["used"] += 1
    row["reserved"] += 1
    row["available"] -= 2
    assert verify_plan_contract(approved, current) == []
    row["limit"] += 1
    assert any(
        item["path"] == "inventory.quotas"
        for item in verify_plan_contract(approved, current)
    )


def test_live_quota_capability_evidence_does_not_change_the_approved_workload(
    config_factory, discovery_fixture
):
    config = config_factory()
    discovery_fixture.quota_info = {"instances": QuotaInfo("instances", 100, 1)}
    plan = Planner(config, discovery_fixture, mock.Mock()).build()

    def contract():
        preflight = CapabilityPreflight(
            config, discovery_fixture, plan, mock.Mock(), mock.Mock()
        )
        preflight._quota_headroom()
        return create_plan_contract(
            config, discovery_fixture, plan, {"checks": preflight.checks}
        )

    approved = contract()
    discovery_fixture.quota_info["instances"].used += 1
    current = contract()
    assert verify_plan_contract(approved, current) == []
    assert (
        approved["inventory"]["capabilities"][0]["evidence"]["instances"]["available"]
        == 99
    )
    discovery_fixture.quota_info["instances"].used = 100
    assert verify_plan_contract(approved, contract())


def test_resume_still_rejects_insufficient_fresh_quota(
    config_factory, discovery_fixture, tmp_path, monkeypatch
):
    suite = _suite(config_factory, tmp_path, resume_run_id="suite-test")
    plan = Planner(suite.config, discovery_fixture, suite.logger).build()
    peak = int(plan.estimated["peak_instances"])
    discovery_fixture.quota_info = {"instances": QuotaInfo("instances", peak, 0)}
    saved = tmp_path / "plan.json"
    saved.write_text(
        json.dumps(create_plan_contract(suite.config, discovery_fixture, plan))
    )
    suite.checkpoint.plan_path = str(saved)
    exhausted = dataclasses.replace(
        discovery_fixture,
        quota_info={"instances": QuotaInfo("instances", peak, peak)},
    )
    suite._preflight_commands = mock.Mock()
    suite.cleanup_manager.cleanup = mock.Mock(return_value=True)
    discover = mock.Mock(return_value=exhausted)
    monkeypatch.setattr("neutron_flux.suite.Discoverer.discover", discover)
    monkeypatch.setattr("neutron_flux.suite.resolve_launch_selection", mock.Mock())
    with pytest.raises(SuiteError, match="quota|Quota"):
        suite.execute()
    suite.cleanup_manager.cleanup.assert_called_once()
    assert discover.call_count == 2
    assert suite.resources_started is False
    suite.reporter.logger.close()


def test_quota_snapshot_tampering_still_fails_fingerprint(
    config_factory, discovery_fixture, tmp_path
):
    config = config_factory()
    discovery_fixture.quota_info = {"instances": QuotaInfo("instances", 100, 1)}
    plan = Planner(config, discovery_fixture, mock.Mock()).build()
    approved = create_plan_contract(config, discovery_fixture, plan)
    approved["inventory"]["quotas"][0]["used"] += 1
    saved = tmp_path / "plan.json"
    saved.write_text(json.dumps(approved))
    with pytest.raises(SuiteError, match="fingerprint"):
        load_plan_contract(saved)


@pytest.mark.parametrize("change", ["project", "cloud", "network", "fingerprint"])
def test_resume_rejects_changed_scope_before_cleanup(
    config_factory, discovery_fixture, tmp_path, monkeypatch, change
):
    suite = _suite(config_factory, tmp_path, resume_run_id="suite-test")
    plan = Planner(suite.config, discovery_fixture, suite.logger).build()
    approved = create_plan_contract(suite.config, discovery_fixture, plan)
    current = copy.deepcopy(discovery_fixture)
    if change == "project":
        current.project_id = "different-project"
    elif change == "cloud":
        current.cloud = "different-cloud"
    elif change == "network":
        current.networks[0].mtu = 1200
    else:
        approved["configuration"]["flavor"] = "modified-after-signing"
    saved = tmp_path / "plan.json"
    saved.write_text(json.dumps(approved))
    suite.checkpoint.plan_path = str(saved)
    suite._preflight_commands = mock.Mock()
    suite.cleanup_manager.cleanup = mock.Mock()
    monkeypatch.setattr("neutron_flux.suite.Discoverer.discover", lambda _self: current)
    with pytest.raises(SuiteError, match="Resume inventory changed|fingerprint"):
        suite.execute()
    suite.cleanup_manager.cleanup.assert_not_called()
    suite.reporter.logger.close()


def test_resume_stops_when_old_resources_cannot_be_reconciled(
    config_factory, discovery_fixture, tmp_path, monkeypatch
):
    suite = _suite(config_factory, tmp_path, resume_run_id="suite-test")
    plan = Planner(suite.config, discovery_fixture, suite.logger).build()
    saved = tmp_path / "plan.json"
    saved.write_text(
        json.dumps(create_plan_contract(suite.config, discovery_fixture, plan))
    )
    suite.checkpoint.plan_path = str(saved)
    suite._preflight_commands = mock.Mock()
    suite.cleanup_manager.cleanup = mock.Mock(return_value=False)
    monkeypatch.setattr(
        "neutron_flux.suite.Discoverer.discover", lambda _self: discovery_fixture
    )
    launch = mock.Mock()
    monkeypatch.setattr("neutron_flux.suite.resolve_launch_selection", launch)
    with pytest.raises(SuiteError, match="could not be safely reconciled"):
        suite.execute()
    assert suite.checkpoint.cleanup_state == "INCOMPLETE"
    launch.assert_not_called()
    suite.reporter.logger.close()
