from __future__ import annotations

import json
from pathlib import Path

import pytest

from neutron_flux.errors import SuiteError
from neutron_flux.reporting import Reporter
from neutron_flux.results_io import load_results
from neutron_flux.state import StateStore


def _payload() -> dict:
    return {
        "schema_version": 1,
        "run": {
            "run_id": "run-one",
            "started_at": "2026-07-22T00:00:00Z",
            "final_status": "PASS",
        },
        "summary": {"counts": {"PASS": 1}, "total_results": 1},
        "results": [
            {
                "test_id": "T1",
                "category": "connectivity",
                "status": "PASS",
                "duration_ms": 1,
                "details": {},
            }
        ],
        "cleanup": {
            "attempted": True,
            "complete": True,
            "deleted": 0,
            "leftovers": [],
            "errors": [],
        },
    }


def test_offline_results_reject_duplicate_test_ids(tmp_path: Path):
    payload = _payload()
    payload["results"].append(dict(payload["results"][0]))
    payload["summary"] = {"counts": {"PASS": 2}, "total_results": 2}
    source = tmp_path / "results.json"
    source.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SuiteError, match="duplicate test_id 'T1'"):
        load_results(source)


def test_state_store_rejects_symlinked_report_root(tmp_path: Path):
    real = tmp_path / "real-reports"
    real.mkdir()
    link = tmp_path / "reports"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(
        SuiteError, match="Report directory must not be a symbolic link"
    ):
        StateStore(link)


def test_reporter_rejects_symlinked_report_root(config_factory, tmp_path: Path):
    real = tmp_path / "real-reports"
    real.mkdir()
    link = tmp_path / "reports"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(
        SuiteError, match="Report directory must not be a symbolic link"
    ):
        Reporter(config_factory(report_dir=link, action="run"), "run-one")


def test_recent_incomplete_lock_is_not_reclaimed(tmp_path: Path):
    store = StateStore(tmp_path / "reports")
    lock = store.run_dir("run") / "run.lock"
    lock.write_text("", encoding="utf-8")

    assert store._stale_lock(lock) is False


def test_old_incomplete_lock_is_reclaimable(tmp_path: Path, monkeypatch):
    import os
    import time

    store = StateStore(tmp_path / "reports")
    lock = store.run_dir("run") / "run.lock"
    lock.write_text("", encoding="utf-8")
    old = time.time() - 120
    os.utime(lock, (old, old))

    assert store._stale_lock(lock) is True


def test_setup_error_dominates_requested_test_failure_exit(
    config_factory, tmp_path: Path
):
    reporter = Reporter(
        config_factory(report_dir=tmp_path / "reports", action="run"),
        "mixed-severity",
    )
    reporter.result("FAILED", "connectivity", "FAIL", "validation failed")
    reporter.result(
        "BLOCKED",
        "connectivity",
        "BLOCKED_BY_SETUP_ERROR",
        "setup failed",
    )
    reporter.cleanup_summary.update({"attempted": True, "complete": True})

    assert reporter.finalize(1) == 1


def test_lock_rejects_zero_and_negative_pids_as_stale(tmp_path: Path):
    store = StateStore(tmp_path / "reports")
    lock = store.run_dir("run") / "run.lock"
    for payload in ("0", "-1", "true", '{"pid": 0}', '{"pid": -2}', '{"pid": true}'):
        lock.write_text(payload, encoding="utf-8")
        assert store._stale_lock(lock) is True


def test_state_store_refuses_to_persist_structurally_invalid_checkpoint(tmp_path: Path):
    from neutron_flux.models import RunCheckpoint
    from neutron_flux.utils import iso_utc

    store = StateStore(tmp_path / "reports")
    now = iso_utc()
    checkpoint = RunCheckpoint(
        run_id="run",
        state="RUNNING",
        action="run",
        phase="tests",
        current_batch=None,
        started_at=now,
        updated_at=now,
        last_activity=now,
        completed_test_ids=["T1"],
        failed_test_ids=["T2"],
        pending_test_ids=[],
        active_group_ids=[],
        manifest_path="manifest",
        report_dir="report",
        cleanup_state="NOT_STARTED",
    )
    with pytest.raises(SuiteError, match="failed_test_ids must be a subset"):
        store.save(checkpoint)
    assert not store.state_path("run").exists()


def test_router_cloud_operation_state_survives_readback_failure(config_factory):
    from types import SimpleNamespace
    from unittest import mock

    from neutron_flux.errors import SuiteError
    from support.tests.test_engine_handlers import _engine, _probe, _spec

    engine, _source, _target, _groups, _records = _engine(config_factory)
    engine.probes.endpoint.return_value = _probe(True)
    engine.builder.osc.run.return_value = SimpleNamespace(
        returncode=0, stdout="", stderr=""
    )
    engine.builder.wait_router_interface = mock.Mock(
        side_effect=SuiteError("temporary Neutron readback failure")
    )

    with pytest.raises(SuiteError, match="temporary Neutron"):
        engine._run_router_withdraw(
            _spec("router-withdraw", category="router-interface", protocol="icmp")
        )

    state = engine.lifecycle["router:target"]
    assert state["cloud_operation_performed"] is True
    assert state["cloud_operation_confirmed"] is False

    engine.builder.wait_router_interface = mock.Mock(return_value={"matched": True})
    engine._wait_endpoint_state.return_value = _probe(True)
    engine._run_router_return(
        _spec("router-return", category="router-interface", protocol="icmp")
    )
    assert engine.builder.osc.run.call_count == 2


def test_server_stop_state_survives_status_readback_failure(config_factory):
    from types import SimpleNamespace
    from unittest import mock

    from neutron_flux.errors import SuiteError
    from support.tests.test_engine_handlers import _engine, _probe, _spec

    engine, _source, target, _groups, _records = _engine(config_factory)
    engine.probes.endpoint.return_value = _probe(True)
    engine.builder.osc.run.return_value = SimpleNamespace(
        returncode=0, stdout="", stderr=""
    )
    engine.builder._wait_for_status = mock.Mock(
        side_effect=SuiteError("temporary Nova readback failure")
    )

    with pytest.raises(SuiteError, match="temporary Nova"):
        engine._run_server_stop(
            _spec("server-stop", category="server-lifecycle", protocol="tcp")
        )

    state = engine.lifecycle["server:target:B"]
    assert state["cloud_operation_performed"] is True
    assert state["cloud_operation_confirmed"] is False

    engine.builder._wait_for_status = mock.Mock()
    engine.builder._wait_for_ssh = mock.Mock(return_value=True)
    engine.builder.reconfigure_endpoint = mock.Mock()
    engine._wait_endpoint_state.return_value = _probe(True)
    engine._run_server_start(
        _spec("server-start", category="server-lifecycle", protocol="tcp")
    )
    engine.builder.reconfigure_endpoint.assert_called_once_with(target)


def test_set_one_extra_route_accepts_command_error_when_state_already_matches(
    config_factory,
):
    from types import SimpleNamespace
    from unittest import mock

    from neutron_flux.resources import ResourceBuilder

    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder.osc = mock.Mock()
    builder.osc.run.return_value = SimpleNamespace(
        returncode=1, stdout="", stderr="route already exists"
    )
    builder.wait_router_route = mock.Mock(return_value={"matched": True})
    runtime = SimpleNamespace(
        metadata={
            "routes": {
                "A": {
                    "router_id": "router-1",
                    "destination": "192.0.2.0/24",
                    "gateway": "198.51.100.1",
                }
            }
        }
    )

    builder.set_one_extra_route(runtime, side="A", enabled=True)
    builder.wait_router_route.assert_called()


def test_extra_route_remove_state_survives_readback_failure(config_factory):
    from unittest import mock

    from neutron_flux.errors import SuiteError
    from support.tests.test_engine_handlers import _engine, _probe, _spec

    engine, _source, _target, groups, _records = _engine(config_factory)
    engine.lifecycle["extra-route:target"] = {
        "family": 4,
        "baseline_blocked": True,
        "routes_installed": True,
        "route_setup_error": None,
        "removed_route_side": None,
    }
    groups["target"].metadata["routes"] = {
        "A": {
            "router_id": "router-1",
            "destination": "192.0.2.0/24",
            "gateway": "198.51.100.1",
        }
    }
    engine.probes.endpoint.return_value = _probe(True)
    engine.builder.set_one_extra_route = mock.Mock(
        side_effect=SuiteError("route confirmation failed")
    )

    with pytest.raises(SuiteError, match="route confirmation failed"):
        engine._run_extra_route_remove(
            _spec("extra-route-remove", category="router-extra-route", protocol="icmp")
        )

    state = engine.lifecycle["extra-route:target"]
    assert state["removed_route_side"] == "A"
    assert state["route_removal_confirmed"] is False

    engine.builder.set_one_extra_route = mock.Mock()
    engine._wait_endpoint_state.return_value = _probe(True)
    engine._run_extra_route_restore(
        _spec("extra-route-restore", category="router-extra-route", protocol="icmp")
    )
    engine.builder.set_one_extra_route.assert_called_once_with(
        groups["target"], side="A", enabled=True
    )


def test_extra_route_add_attempts_immediate_rollback_on_partial_failure(config_factory):
    from unittest import mock

    from neutron_flux.errors import SuiteError
    from support.tests.test_engine_handlers import _engine, _spec

    engine, _source, _target, _groups, _records = _engine(config_factory)
    engine.lifecycle["extra-route:target"] = {
        "family": 4,
        "baseline_blocked": True,
        "routes_installed": False,
        "route_setup_error": None,
        "removed_route_side": None,
    }
    engine.builder.set_extra_routes = mock.Mock(
        side_effect=[SuiteError("partial route add"), None]
    )

    with pytest.raises(SuiteError, match="partial route add"):
        engine._run_extra_route_add(
            _spec("extra-route-add", category="router-extra-route", protocol="icmp")
        )

    assert engine.builder.set_extra_routes.call_args_list == [
        mock.call(_groups["target"], enabled=True),
        mock.call(_groups["target"], enabled=False),
    ]
    state = engine.lifecycle["extra-route:target"]
    assert state["routes_installed"] is False
    assert state["route_setup_error"] == "partial route add"


def test_security_rule_create_recovers_id_from_neutron_state(config_factory):
    from unittest import mock

    from neutron_flux.resources import ResourceBuilder

    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.logger = mock.Mock()
    builder.security_group_rules = {}
    builder.osc = mock.Mock()
    builder.osc.json.return_value = None
    exact = {
        "id": "recovered-rule",
        "direction": "ingress",
        "ethertype": "IPv4",
        "protocol": "tcp",
        "port_range_min": 18082,
        "port_range_max": 18082,
        "remote_group_id": "source-sg",
    }
    builder.list_security_group_rules = mock.Mock(
        side_effect=[[], [], [exact], [exact]]
    )

    assert (
        builder.add_temporary_security_rule(
            destination_security_group_id="destination-sg",
            source_security_group_id="source-sg",
            family=4,
            protocol="tcp",
            port=18082,
        )
        == "recovered-rule"
    )


def test_security_rule_delete_reconciles_nonzero_response_when_rule_is_absent(
    config_factory,
):
    from types import SimpleNamespace
    from unittest import mock

    from neutron_flux.resources import ResourceBuilder

    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.logger = mock.Mock()
    builder.test_sg_id = "destination-sg"
    builder.security_group_rules = {}
    builder.osc = mock.Mock()
    builder.osc.run.return_value = SimpleNamespace(
        returncode=1, stdout="", stderr="503 response lost"
    )
    builder.list_security_group_rules = mock.Mock(return_value=[])

    builder.delete_security_rule("rule-id", "destination-sg")
    builder.logger.log.assert_called_once()


def test_security_rule_inventory_failure_is_not_treated_as_empty(config_factory):
    from unittest import mock

    from neutron_flux.errors import CommandError
    from neutron_flux.resources import ResourceBuilder

    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.osc = mock.Mock()
    builder.osc.json.side_effect = CommandError(
        ["openstack", "security", "group", "rule", "list"],
        1,
        "",
        "503 unavailable",
    )
    with pytest.raises(CommandError):
        builder.list_security_group_rules("destination-sg")


def test_security_rule_delete_waits_for_eventual_absence(config_factory):
    from types import SimpleNamespace
    from unittest import mock

    from neutron_flux.resources import ResourceBuilder

    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(convergence_timeout=1, convergence_interval=0)
    builder.logger = mock.Mock()
    builder.test_sg_id = "destination-sg"
    builder.security_group_rules = {}
    builder.osc = mock.Mock()
    builder.osc.run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
    builder.list_security_group_rules = mock.Mock(side_effect=[[{"id": "rule-id"}], []])

    builder.delete_security_rule("rule-id", "destination-sg")
    assert builder.list_security_group_rules.call_count == 2


def test_security_rule_create_keeps_returned_id_when_refresh_fails(config_factory):
    from unittest import mock

    from neutron_flux.errors import SuiteError
    from neutron_flux.resources import ResourceBuilder

    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.logger = mock.Mock()
    builder.security_group_rules = {}
    builder.osc = mock.Mock()
    builder.osc.json.return_value = {"id": "rule-id"}
    builder._exact_temporary_security_rule_ids = mock.Mock(return_value=set())
    builder.list_security_group_rules = mock.Mock(
        side_effect=SuiteError("temporary inventory failure")
    )

    assert (
        builder.add_temporary_security_rule(
            destination_security_group_id="destination-sg",
            source_security_group_id="source-sg",
            family=4,
            protocol="tcp",
            port=18082,
        )
        == "rule-id"
    )
    builder.logger.log.assert_called_once()


def test_security_rule_create_retries_transient_inventory_failure(config_factory):
    from unittest import mock

    from neutron_flux.errors import SuiteError
    from neutron_flux.resources import ResourceBuilder

    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(convergence_timeout=1, convergence_interval=0)
    builder.logger = mock.Mock()
    builder.security_group_rules = {}
    builder.osc = mock.Mock()
    builder.osc.json.return_value = None
    builder._exact_temporary_security_rule_ids = mock.Mock(
        side_effect=[set(), SuiteError("503 unavailable"), {"rule-id"}]
    )

    assert (
        builder.add_temporary_security_rule(
            destination_security_group_id="destination-sg",
            source_security_group_id="source-sg",
            family=4,
            protocol="tcp",
            port=18082,
        )
        == "rule-id"
    )


def test_lock_rejects_fractional_pid_as_corrupt(tmp_path: Path):
    store = StateStore(tmp_path / "reports")
    lock = store.run_dir("run") / "run.lock"
    lock.write_text('{"pid": 123.75}', encoding="utf-8")
    assert store._stale_lock(lock) is True
