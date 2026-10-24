from __future__ import annotations

import re
import subprocess
from pathlib import Path

from neutron_flux.reporting_components.html import render_html
from support.tests.test_offline_reports_and_concurrent_load import _payload


def _script(html: str) -> str:
    blocks: list[str] = []
    for attrs, body in re.findall(r"<script([^>]*)>(.*?)</script>", html, re.S | re.I):
        if "application/json" in attrs.lower():
            continue
        if body.strip():
            blocks.append(body)
    return "\n".join(blocks)


def test_dashboard_uses_task_oriented_workspaces_and_lazy_views(tmp_path: Path):
    html = render_html(_payload("sample-dashboard"))
    markers = (
        'data-view="overview"',
        'data-view="findings"',
        'data-view="paths"',
        'data-view="tests"',
        'data-view="performance"',
        'data-view="run"',
        'id="pathSearch"',
        'id="findingSearch"',
        'id="testSearch"',
        'class="test-card"',
        "function activateView(",
        "function renderPaths(",
        "function renderTests(",
        "function renderPerformance(",
    )
    for marker in markers:
        assert marker in html
    script = tmp_path / "sample-dashboard.js"
    script.write_text(_script(html), encoding="utf-8")
    subprocess.run(["node", "--check", str(script)], check=True, capture_output=True)


def test_dashboard_replaces_wide_results_table_with_cards():
    html = render_html(_payload("sample-results"))
    assert '<div id="testList"></div>' in html
    assert '<table class="results-table">' not in html
    assert "Tests and coverage" in html
    assert 'class="test-card"' in html


def test_path_explorer_groups_complete_path_evidence():
    html = render_html(_payload("sample-paths"))
    assert "Technical path evidence" in html
    assert "Single-stream TCP" in html
    assert "Worst loaded ratio" in html
    assert "Worst eligible UDP loss" in html
    assert "Endpoint-limited UDP loss" in html
    assert "Confirmed MTU" in html
    assert "renderPerformance" in html
