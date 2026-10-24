from __future__ import annotations

import dataclasses
from unittest import mock

import pytest

from neutron_flux.cleanup import CleanupManager
from neutron_flux.cli import parser
from neutron_flux.models import Plan, RunCheckpoint
from neutron_flux.reporting import Reporter
from neutron_flux.state import StateStore
from neutron_flux.utils import iso_utc


def _manager(config_factory, *, report_dir):
    config = config_factory(
        action="cleanup",
        report_dir=report_dir,
        cleanup_orphans=True,
        cleanup_assume_yes=True,
        cleanup_include_active=False,
        orphan_grace_minutes=30,
    )
    manager = CleanupManager.__new__(CleanupManager)
    manager.config = config
    manager.logger = mock.Mock()
    manager.osc = mock.Mock()
    return manager


def _server(run_id: str, *, state: str):
    now = iso_utc()
    return {
        "ID": "server-id",
        "Name": f"{run_id}-controller",
        "Properties": {
            "neutron_flux_run_id": run_id,
            "neutron_flux_state": state,
            "neutron_flux_heartbeat": now,
        },
        "Updated At": now,
    }


def _wire(manager, row):
    manager._orphan_list = mock.Mock(
        side_effect=lambda preferred, fallback: (
            [row] if preferred[:2] == ["server", "list"] else []
        )
    )
    manager._enrich_orphan_server = lambda candidate, source, **_kwargs: candidate


def _checkpoint(run_id: str, report_dir, *, cleanup_state: str = "RETAINED"):
    now = iso_utc()
    return RunCheckpoint(
        run_id=run_id,
        state="COMPLETED",
        action="run",
        phase="resources-retained",
        current_batch=None,
        started_at=now,
        updated_at=now,
        last_activity=now,
        completed_test_ids=[],
        failed_test_ids=[],
        pending_test_ids=[],
        active_group_ids=[],
        manifest_path=str(report_dir / "runs" / run_id / "resources.jsonl"),
        report_dir=str(report_dir),
        cleanup_state=cleanup_state,
    )


def test_plain_orphan_cleanup_selects_cloud_retained_resources(
    config_factory, tmp_path
):
    run_id = "nflux-20260723222020-2efa6f"
    manager = _manager(config_factory, report_dir=tmp_path / "reports")
    _wire(manager, _server(run_id, state="retained"))

    inventory = manager._discover_project_orphans()

    assert [item["id"] for item in inventory["candidates"]] == ["server-id"]
    assert inventory["protected"] == []
    assert "retained" not in inventory
    detail = inventory["runs"][run_id]
    assert detail["selected"] is True
    assert detail["retained_state"] is True
    assert "previously retained" in detail["reason"]


def test_plain_orphan_cleanup_selects_locally_retained_resources(
    config_factory, tmp_path
):
    report_dir = tmp_path / "reports"
    run_id = "nflux-20260723222020-2efa6f"
    StateStore(report_dir).save(_checkpoint(run_id, report_dir))
    manager = _manager(config_factory, report_dir=report_dir)
    _wire(manager, _server(run_id, state="running"))

    inventory = manager._discover_project_orphans()

    assert [item["id"] for item in inventory["candidates"]] == ["server-id"]
    assert inventory["runs"][run_id]["retained_state"] is True


def test_live_lock_still_protects_previously_retained_run(config_factory, tmp_path):
    report_dir = tmp_path / "reports"
    run_id = "nflux-20260723222020-2efa6f"
    store = StateStore(report_dir)
    store.save(_checkpoint(run_id, report_dir))
    manager = _manager(config_factory, report_dir=report_dir)
    _wire(manager, _server(run_id, state="retained"))

    with store.lock(run_id):
        inventory = manager._discover_project_orphans()

    assert inventory["candidates"] == []
    assert [item["id"] for item in inventory["protected"]] == ["server-id"]
    assert "live local" in inventory["runs"][run_id]["reason"]


def test_include_retained_flag_is_removed():
    with pytest.raises(SystemExit):
        parser().parse_args(["cleanup", "--orphans", "--include-retained"])
    help_text = parser().format_help()
    assert "--include-retained" not in help_text


def test_cleanup_report_has_no_retained_exemption(config_factory, tmp_path):
    config = dataclasses.replace(
        config_factory(), action="cleanup", report_dir=tmp_path / "reports"
    )
    reporter = Reporter(config, "orphan-cleanup-sample")
    reporter.plan = Plan([], [], {}, [], tests=[])
    reporter.cleanup_summary.update(
        {
            "attempted": True,
            "complete": True,
            "deleted": 3,
            "orphan_sweep": {
                "passes": [{"pass": 1, "candidates": 3, "deleted": 3}],
                "stale_resources_remaining": 0,
                "protected_resources_remaining": 0,
                "unknown_resources_remaining": 0,
                "project_resources_remaining": 0,
                "candidate_runs": ["nflux-20260723222020-2efa6f"],
            },
        }
    )

    assert reporter.finalize(0) == 0
    text = reporter.report_path.read_text()
    html = reporter.html_report_path.read_text()
    assert "Orphaned resources remaining:       0" in text
    assert "Orphan candidate runs: nflux-20260723222020-2efa6f" in text
    assert "Intentionally retained" not in text
    assert "retainedRunRows" not in html
    assert "Orphaned remaining" in html
