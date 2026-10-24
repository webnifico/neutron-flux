from __future__ import annotations

import json
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux import cli
from neutron_flux.errors import SuiteError
from neutron_flux.plan_contract import configuration_snapshot
from neutron_flux.replay_plan import _replay_command
from neutron_flux.reporting_components.html import render_html

from .test_cli_contract import BASE, configured
from .test_report_workflow import _embedded_payload, _payload


@pytest.mark.parametrize("value", ["admin", "project", "client"])
def test_retired_mode_flag_is_rejected(value):
    with pytest.raises(SystemExit) as exc:
        cli.parser().parse_args([*BASE, "--access-mode", value])
    assert exc.value.code == 2


def test_default_workflow_keeps_compute_checks_and_mode_free_snapshots():
    config = configured()
    assert config.compute_host_connectivity_enabled
    assert config.live_migration_continuity
    snapshot = configuration_snapshot(config)
    assert "access_mode" not in snapshot
    assert "access_mode" not in snapshot["execution_settings"]
    assert snapshot["migration"]["enabled"]


@pytest.mark.parametrize("stored", [None, "admin", "client", "project"])
def test_plan_resume_accepts_only_administrator_contracts(
    config_factory, monkeypatch, tmp_path, stored
):
    config = config_factory()
    snapshot = configuration_snapshot(config)
    snapshot["image"] = "recorded-image"
    if stored is not None:
        snapshot["access_mode"] = stored
    monkeypatch.setattr(
        cli,
        "load_plan_contract",
        lambda *a, **k: ({"configuration": snapshot}, {}),
    )
    if stored in {"client", "project"}:
        with pytest.raises(SuiteError, match="retired project execution contract"):
            cli._hydrate_config_from_plan(config, tmp_path / "plan.json")
        assert config.image != "recorded-image"
    else:
        # Real snapshots repeat image in their immutable execution settings.
        snapshot["execution_settings"]["image"] = "recorded-image"
        cli._hydrate_config_from_plan(config, tmp_path / "plan.json")
        assert config.image == "recorded-image"
        assert config.compute_host_connectivity_enabled


def test_repeat_resume_rejects_retired_contract_in_linked_pass(config_factory):
    initial = SimpleNamespace(
        run_id="initial",
        state="COMPLETED",
        pending_test_ids=[],
        metadata={"repeat_next_id": "second", "pass_exit_code": 0},
    )
    second = SimpleNamespace(run_id="second", metadata={"access_mode": "client"})
    store = mock.Mock()
    store.state_path.return_value.is_file.return_value = True
    store.load.return_value = second
    with pytest.raises(SuiteError, match="cleanup remains available"):
        cli._resume_pass(config_factory(), store, initial)
    store.load.assert_called_once_with("second")


@pytest.mark.parametrize("stored", [None, "admin", "client", "project"])
def test_replay_does_not_change_retired_execution_semantics(stored):
    config = {
        "image": "debian",
        "flavor": "small",
        "storage": "host",
        "external_networks": ["public"],
    }
    if stored is not None:
        config["access_mode"] = stored
    command = _replay_command({"configuration": config})
    if stored in {"client", "project"}:
        assert command is None
    else:
        assert command is not None
        assert "--access-mode" not in command
        assert "--migration-mode live" in command


def test_report_keeps_host_evidence_without_execution_mode_labels():
    html = render_html(_payload())
    embedded = _embedded_payload(html)
    assert "access_mode" not in embedded["configuration"]
    assert "compute1" in json.dumps(embedded)
    assert "compute2" in json.dumps(embedded)
    assert 'id="sideMode"' not in html
    assert 'id="topMode"' not in html
    assert "executionModeLabel" not in html
