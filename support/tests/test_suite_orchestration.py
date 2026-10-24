from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.errors import SuiteError
from neutron_flux.models import RunCheckpoint
from neutron_flux.reporting import ResourceTracker
from neutron_flux.suite import Suite as FluxSuite
from neutron_flux.utils import iso_utc

from ._shared import make_reporter


def _checkpoint(tmp_path, action="run"):
    now = iso_utc()
    return RunCheckpoint(
        run_id="suite-test",
        state="NEW",
        action=action,
        phase="init",
        current_batch=None,
        started_at=now,
        updated_at=now,
        last_activity=now,
        completed_test_ids=[],
        failed_test_ids=[],
        pending_test_ids=[],
        active_group_ids=[],
        manifest_path=str(tmp_path / "manifest.jsonl"),
        report_dir=str(tmp_path),
    )


def _suite(config_factory, tmp_path, **config_overrides):
    config = config_factory(
        action=config_overrides.pop("action", "run"),
        report_dir=tmp_path / "reports",
        **config_overrides,
    )
    reporter = make_reporter(config, run_id="suite-test")
    state_store = mock.Mock()
    checkpoint = _checkpoint(tmp_path, config.action)
    suite = FluxSuite(config, reporter, state_store, checkpoint)
    suite.osc = mock.Mock()
    suite.cleanup_manager.osc = suite.osc
    suite.tracker = ResourceTracker(reporter)
    return suite


def test_suite_bootstrap_contract_requires_both_control_results(
    config_factory, tmp_path
):
    suite = _suite(config_factory, tmp_path)
    with pytest.raises(SuiteError, match="CONTROL-OBSERVATION-PORTS, CONTROL-SSH"):
        suite._validate_bootstrap_results()

    suite.reporter.has_result = lambda result_id: (
        result_id
        in {
            "CONTROL-OBSERVATION-PORTS",
            "CONTROL-SSH",
        }
    )
    suite._validate_bootstrap_results()


def test_suite_preflight_checks_action_specific_commands(
    config_factory, tmp_path, monkeypatch
):
    suite = _suite(config_factory, tmp_path, action="run")
    available = {"openstack": "/bin/openstack", "ssh": "/bin/ssh"}
    monkeypatch.setattr("neutron_flux.suite.shutil.which", available.get)

    with pytest.raises(SuiteError, match="ssh-keygen"):
        suite._preflight_commands()
    suite.osc.run.assert_not_called()

    available["ssh-keygen"] = "/bin/ssh-keygen"
    suite._preflight_commands()
    suite.osc.run.assert_called_once_with("token", "issue")


def test_plan_preflight_requires_only_openstack(config_factory, tmp_path, monkeypatch):
    suite = _suite(config_factory, tmp_path, action="plan")
    monkeypatch.setattr(
        "neutron_flux.suite.shutil.which",
        lambda command: "/bin/openstack" if command == "openstack" else None,
    )

    suite._preflight_commands()
    suite.osc.run.assert_called_once_with("token", "issue")


def test_cleanup_if_required_stops_transient_probes_before_resource_policy(
    config_factory, tmp_path
):
    suite = _suite(config_factory, tmp_path)
    suite.builder = mock.Mock()
    suite.resources_started = False

    assert suite.cleanup_if_required(successful_execution=False) is None
    suite.builder.stop_all_probes.assert_called_once_with()
    suite.cleanup_manager.cleanup = mock.Mock()
    suite.cleanup_manager.cleanup.assert_not_called()


def test_cleanup_if_required_retains_resources_when_policy_requests_it(
    config_factory, tmp_path
):
    suite = _suite(
        config_factory,
        tmp_path,
        keep_resources=True,
        auto_cleanup_on_failure=False,
    )
    suite.resources_started = True
    suite.builder = mock.Mock()
    suite.reporter.resources = [
        SimpleNamespace(
            resource_type="server",
            id="server-id",
            name="retained",
            delete_status="pending",
        )
    ]
    suite._save_checkpoint = mock.Mock()

    assert suite.cleanup_if_required(successful_execution=True) is None
    assert suite.reporter.cleanup_summary["attempted"] is False
    assert suite.reporter.cleanup_summary["leftovers"] == ["server:server-id:retained"]
    suite._save_checkpoint.assert_called_once_with(
        "COMPLETED", "resources-retained", None
    )


def test_cleanup_if_required_uses_single_zone_cleanup_manager(config_factory, tmp_path):
    suite = _suite(config_factory, tmp_path)
    suite.resources_started = True
    suite.builder = mock.Mock()
    suite.cleanup_manager.cleanup = mock.Mock(return_value=True)
    suite._save_checkpoint = mock.Mock()

    assert suite.cleanup_if_required(successful_execution=True) is True
    suite.cleanup_manager.cleanup.assert_called_once_with()
    assert suite.checkpoint.cleanup_state == "COMPLETE"
    suite._save_checkpoint.assert_any_call("CLEANING", "cleanup", None)
    suite._save_checkpoint.assert_any_call("COMPLETED", "cleanup-complete", None)


def test_cleanup_if_required_uses_multi_zone_cleanup(config_factory, tmp_path):
    suite = _suite(config_factory, tmp_path)
    suite.resources_started = True
    suite.zone_orchestrator = mock.Mock()
    suite.zone_orchestrator.cleanup_all.return_value = False
    suite._save_checkpoint = mock.Mock()

    assert suite.cleanup_if_required(successful_execution=False) is False
    suite.zone_orchestrator.stop_all_probes.assert_called_once_with()
    suite.zone_orchestrator.cleanup_all.assert_called_once_with()
    assert suite.checkpoint.cleanup_state == "INCOMPLETE"


def test_cleanup_existing_routes_orphan_and_manifest_modes(config_factory, tmp_path):
    orphan_suite = _suite(
        config_factory, tmp_path, action="cleanup", cleanup_orphans=True
    )
    orphan_suite.cleanup_manager.cleanup_orphans = mock.Mock(return_value=True)
    orphan_suite._save_checkpoint = mock.Mock()
    assert orphan_suite.cleanup_existing() == 0
    orphan_suite.cleanup_manager.cleanup_orphans.assert_called_once_with()

    manifest_suite = _suite(
        config_factory,
        tmp_path / "manifest",
        action="cleanup",
        cleanup_orphans=False,
    )
    manifest_suite.cleanup_manager.cleanup = mock.Mock(return_value=False)
    manifest_suite._save_checkpoint = mock.Mock()
    assert manifest_suite.cleanup_existing() == 3
    manifest_suite.cleanup_manager.cleanup.assert_called_once_with(
        run_tag=manifest_suite.reporter.run_tag,
        name_prefix=manifest_suite.reporter.name_prefix,
    )


def test_heartbeat_persists_checkpoint_and_tolerates_state_store_error(
    config_factory, tmp_path, monkeypatch
):
    suite = _suite(config_factory, tmp_path)
    suite.builder = mock.Mock()
    suite.state_store.save.side_effect = OSError("temporary write failure")
    times = iter([10.0, 70.0])
    monkeypatch.setattr("neutron_flux.suite.time.monotonic", lambda: next(times))

    suite._heartbeat()
    suite._heartbeat()

    assert suite.state_store.save.call_count == 2
    suite.builder.update_cloud_heartbeat.assert_called_with("active")
