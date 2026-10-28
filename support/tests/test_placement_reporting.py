from __future__ import annotations

import copy

from neutron_flux.cli import parser
from neutron_flux.reporting_components.html import render_html
from neutron_flux.reporting_components.operator_context import host_scope_summary
from support.tests.test_migration_and_performance_reporting import _performance_payload


def _pair_scoped_payload():
    payload = _performance_payload()
    metadata = payload["plan"]["tests"][0]["metadata"]
    metadata["pair_scope_id"] = "PAIR-SCOPE-1"
    return payload


def test_pair_scoped_summary_reports_actual_requested_pair_placement():
    payload = _pair_scoped_payload()
    summary = host_scope_summary(payload)

    assert summary["pair_scoped"] is True
    assert summary["requested_pairs"] == ["compute1 ↔ compute2"]
    assert summary["observed_requested_pairs"] == ["compute1 → compute2"]
    assert summary["unscoped_observed_pairs"] == []
    assert "same-host A, inter-host A:B, then same-host B" in summary["note"]
    assert "scheduler placement" not in summary["note"].lower()


def test_pair_scoped_summary_collects_all_three_observed_placements():
    payload = _pair_scoped_payload()
    original = payload["results"][0]
    rows = []
    for index, (source_host, destination_host) in enumerate(
        [
            ("compute1", "compute1"),
            ("compute1", "compute2"),
            ("compute2", "compute2"),
        ],
        start=1,
    ):
        row = copy.deepcopy(original)
        row["result_id"] = f"result-{index}"
        row["test_id"] = f"PERF-HQ-{index}"
        row["details"]["path"].update(
            source_compute_host=source_host,
            destination_compute_host=destination_host,
        )
        rows.append(row)
    payload["results"] = rows

    assert host_scope_summary(payload)["observed_requested_pairs"] == [
        "compute1 → compute1",
        "compute1 → compute2",
        "compute2 → compute2",
    ]


def test_unscoped_result_does_not_claim_scheduler_placement():
    payload = _pair_scoped_payload()
    payload["results"][0]["details"]["path"].update(
        stage="group-local", source_spec_id="absent"
    )
    summary = host_scope_summary(payload)

    assert summary["observed_requested_pairs"] == []
    assert summary["unscoped_observed_pairs"]
    assert "scheduler placement" not in summary["note"].lower()


def test_html_uses_requested_pair_and_unscoped_terminology():
    html = render_html(_pair_scoped_payload())

    assert "Recorded traffic host pairs" in html
    assert "Unscoped / legacy topology" in html
    assert "General topology hosts" not in html
    assert "No two-host placement recorded" not in html
    assert "General topology · scheduler placement" not in html


def test_target_host_pair_help_matches_complete_pair_scope():
    action = next(
        item for item in parser()._actions if item.dest == "target_host_pairs"
    )
    help_text = str(action.help)

    assert "test each selected pair" in help_text
    assert "one intra, one inter, one transition" in help_text
    assert "general topology suite still uses scheduler placement" not in help_text
