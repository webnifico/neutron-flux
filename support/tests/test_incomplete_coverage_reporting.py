from __future__ import annotations

from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest

from neutron_flux.comparison import _index, _run_metrics
from neutron_flux.errors import SuiteError
from neutron_flux.reporting_components.summary import SummaryRendererMixin
from neutron_flux.results_io import output_directory
from neutron_flux.trends import _values


def _payload(*, blocked: int = 0, errors: int = 0):
    results = []
    for index in range(blocked):
        results.append(
            {
                "test_id": f"blocked-{index}",
                "status": "BLOCKED_BY_SETUP_ERROR",
                "category": "security-group",
                "authoritative": True,
                "details": {},
            }
        )
    for index in range(errors):
        results.append(
            {
                "test_id": f"error-{index}",
                "status": "ERROR",
                "category": "security-group",
                "authoritative": True,
                "details": {},
            }
        )
    return {
        "run": {"run_id": "run", "final_status": "ERROR"},
        "results": results,
        "summary": {
            "counts": dict(Counter(item["status"] for item in results)),
            "total_results": len(results),
        },
        "cleanup": {"complete": True},
    }


def test_run_comparison_separates_setup_blocked_from_execution_error():
    metrics = _run_metrics(_payload(blocked=2, errors=1))
    assert metrics["errors"] == (1.0, "lower")
    assert metrics["not_run"] == (2.0, "lower")


def test_trend_separates_setup_blocked_from_execution_error():
    values = _values(_payload(blocked=2, errors=1))
    assert values["error"] == 1
    assert values["blocked_by_setup_error"] == 2


def test_category_verdict_treats_setup_blocked_as_not_run_gap():
    counts = Counter({"BLOCKED_BY_SETUP_ERROR": 2})
    assert SummaryRendererMixin._category_verdict(counts) == "NOT RUN"
    mixed = Counter({"PASS": 3, "BLOCKED_BY_SETUP_ERROR": 1})
    assert SummaryRendererMixin._category_verdict(mixed) == "PASS WITH GAPS"


def test_inapplicable_checks_do_not_create_execution_gaps():
    assert (
        SummaryRendererMixin._category_verdict(
            Counter({"PASS": 402, "NOT_APPLICABLE": 2})
        )
        == "PASS"
    )
    assert (
        SummaryRendererMixin._category_verdict(Counter({"NOT_APPLICABLE": 2}))
        == "NOT APPLICABLE"
    )
    assert (
        SummaryRendererMixin._category_verdict(
            Counter({"PASS": 402, "NOT_APPLICABLE": 2, "HEALTH_WARNING": 1})
        )
        == "PASS WITH WARNINGS"
    )
    assert SummaryRendererMixin._display_status("NOT_APPLICABLE") == "NOT APPLICABLE"


def test_zone_and_category_tables_separate_inapplicability_from_not_run():
    class Reporter(SummaryRendererMixin):
        def _primary_summary_results(self):
            return [
                SimpleNamespace(
                    category="same-subnet",
                    status=status,
                    details={"availability_zone": "zone-a", "health": health},
                )
                for status, health in (
                    ("PASS", "warning"),
                    ("PASS", "good"),
                    ("NOT_APPLICABLE", "neutral"),
                )
            ]

    reporter = Reporter()
    zone_lines = []
    category_lines = []
    reporter._append_zone_summary(zone_lines, 150)
    reporter._append_category_summary(category_lines, 150)
    zone = next(row for row in zone_lines if row.startswith("zone-a"))
    category = next(row for row in category_lines if "PASS WITH WARNINGS" in row)
    for row in (zone, category):
        assert "PASS WITH WARNINGS" in row
        # Pass, fail, unverified, errors, N/A, not run, total. A warning is a
        # classification of an executed PASS, never an extra result.
        assert row.split()[-7:] == ["2", "0", "0", "0", "1", "0", "3"]


def test_offline_output_directory_rejects_final_symlink(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "output"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(SuiteError, match="must not be a symbolic link"):
        output_directory(link, default=tmp_path / "unused")


def test_multi_az_fabric_comparison_identity_is_scope_aware():
    payload = {"results": []}
    for scope in ("az-one", "az-two"):
        payload["results"].append(
            {
                "test_id": f"{scope}-FABRIC-SCALE",
                "status": "PASS",
                "category": "network-performance",
                "details": {
                    "performance": True,
                    "measurement": "fabric-scale",
                    "execution_scope": scope,
                    "availability_zone": scope,
                    "metrics": {"levels": []},
                },
            }
        )
    indexed = _index(payload)
    assert len(indexed) == 2


def test_atomic_writer_rejects_replaced_parent_symlink(tmp_path: Path):
    from neutron_flux.results_io import atomic_write_text

    target = tmp_path / "target"
    target.mkdir()
    parent = tmp_path / "output"
    parent.symlink_to(target, target_is_directory=True)
    with pytest.raises(SuiteError, match="parent must not be a symbolic link"):
        atomic_write_text(parent / "report.txt", "unsafe")
    assert not (target / "report.txt").exists()


def test_trend_chart_dom_matches_separated_unit_series():
    from neutron_flux.trends import _trend_html

    payload = {
        "summary": {
            "run_count": 0,
            "failed_runs": 0,
            "cleanup_failures": 0,
            "latest_run": None,
        },
        "runs": [],
    }
    rendered = _trend_html(payload)
    for chart_id in (
        "lat",
        "latRatio",
        "udpLoss",
        "udpJitter",
        "fabricDegradation",
        "fabricLatency",
    ):
        assert f'id="{chart_id}"' in rendered
        assert f"chart('{chart_id}'," in rendered
    assert 'id="udp"' not in rendered
    assert 'id="fabricQuality"' not in rendered
