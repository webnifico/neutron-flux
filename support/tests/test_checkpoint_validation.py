from __future__ import annotations

import dataclasses
import json

import pytest

from neutron_flux.errors import SuiteError
from neutron_flux.models import RunCheckpoint
from neutron_flux.state import StateStore
from neutron_flux.utils import iso_utc


def checkpoint(run_id: str, report_dir) -> RunCheckpoint:
    now = iso_utc()
    return RunCheckpoint(
        run_id=run_id,
        state="RUNNING",
        action="run",
        phase="tests",
        current_batch=None,
        started_at=now,
        updated_at=now,
        last_activity=now,
        completed_test_ids=["done"],
        failed_test_ids=[],
        pending_test_ids=["pending"],
        active_group_ids=["group"],
        manifest_path=str(report_dir / "manifest.jsonl"),
        report_dir=str(report_dir),
        cleanup_state="NOT_STARTED",
    )


def write_raw(store: StateStore, run_id: str, raw: dict) -> None:
    path = store.run_dir(run_id) / "state.json"
    path.write_text(json.dumps(raw) + "\n", encoding="utf-8")


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("state", "UNKNOWN", "state is invalid"),
        ("action", "report", "action is invalid"),
        ("cleanup_state", "MAYBE", "cleanup_state is invalid"),
        ("completed_test_ids", "done", "must be an array"),
        ("pending_test_ids", ["same", "same"], "duplicate ID"),
        ("metadata", [], "metadata must be an object"),
    ],
)
def test_checkpoint_rejects_invalid_structures(tmp_path, field, value, message):
    store = StateStore(tmp_path / "reports")
    item = checkpoint("invalid-run", store.run_dir("invalid-run"))
    raw = dataclasses.asdict(item)
    raw[field] = value
    write_raw(store, item.run_id, raw)

    with pytest.raises(SuiteError, match=message):
        store.load(item.run_id)


def test_checkpoint_rejects_failed_ids_not_completed(tmp_path):
    store = StateStore(tmp_path / "reports")
    item = checkpoint("invalid-failed", store.run_dir("invalid-failed"))
    raw = dataclasses.asdict(item)
    raw["failed_test_ids"] = ["not-completed"]
    write_raw(store, item.run_id, raw)

    with pytest.raises(SuiteError, match="subset of completed_test_ids"):
        store.load(item.run_id)


def test_checkpoint_rejects_completed_pending_overlap(tmp_path):
    store = StateStore(tmp_path / "reports")
    item = checkpoint("invalid-overlap", store.run_dir("invalid-overlap"))
    raw = dataclasses.asdict(item)
    raw["pending_test_ids"] = ["done"]
    write_raw(store, item.run_id, raw)

    with pytest.raises(SuiteError, match="overlap"):
        store.load(item.run_id)
