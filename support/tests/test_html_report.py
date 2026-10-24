from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from neutron_flux.reporting_components.html import render_html
from support.tests.test_offline_reports_and_concurrent_load import _payload


def _executable_script(html: str) -> str:
    blocks: list[str] = []
    for attrs, body in re.findall(r"<script([^>]*)>(.*?)</script>", html, re.S | re.I):
        if "application/json" in attrs.lower():
            continue
        if body.strip():
            blocks.append(body)
    assert blocks
    return "\n".join(blocks)


def _embedded_payload(html: str) -> dict:
    match = re.search(
        r'<script id="run-data" type="application/json">(.*?)</script>',
        html,
        re.S,
    )
    assert match
    return json.loads(match.group(1))


def test_redesigned_report_has_clear_unit_aware_chart_structure(tmp_path: Path):
    html = render_html(_payload("readable-report", tcp_mbps=9400, latency_ms=0.75))
    expected = (
        'id="performanceSummary"',
        'id="performancePaths"',
        'id="concurrentLoad"',
        "Performance tests",
        "Single-stream TCP",
        "Actual result and why",
        "Loaded ratio",
        "Confirmed MTU",
        "How these values are read",
        "const human=",
        "function renderPerformance()",
        "endpointPair=path=>",
        "Review queue",
    )
    for marker in expected:
        assert marker in html
    script = tmp_path / "report.js"
    script.write_text(_executable_script(html), encoding="utf-8")
    subprocess.run(["node", "--check", str(script)], check=True, capture_output=True)


def test_report_unit_formatters_use_human_network_units(tmp_path: Path):
    html = render_html(_payload("unit-report"))
    script = _executable_script(html)
    start = script.index("const finite=")
    end = script.index("const dateText=")
    helpers = script[start:end]
    probe = tmp_path / "units.js"
    probe.write_text(
        helpers
        + "\nconsole.log(JSON.stringify(["
        + "human(9400,'throughput'),human(.25,'throughput'),"
        + "human(720000,'pps'),human(.72,'latency'),"
        + "human(null,'percent')]))\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["node", str(probe)], check=True, capture_output=True, text=True
    )
    values = json.loads(completed.stdout)
    assert values == ["9.4 Gbit/s", "250 Kbit/s", "720 kpps", "720 µs", "—"]


def test_fabric_measurements_are_not_filtered_out_for_lacking_path_id():
    payload = _payload("fabric-report")
    fabric = {
        **payload["results"][0],
        "test_id": "FABRIC-WITHOUT-PATH-ID",
        "display_name": "Concurrent VM-pair load",
        "details": {
            "performance": True,
            "measurement": "concurrent-path-load",
            "health": "good",
            "availability_zone": "zone-a",
            "metrics": {
                "levels": [
                    {
                        "pairs": 4,
                        "pairs_used": 4,
                        "median_aggregate_mbps": 18_500,
                    }
                ]
            },
        },
    }
    payload["results"].append(fabric)
    payload["performance"].append(fabric)

    report = _embedded_payload(render_html(payload))
    rows = report["dashboard"]["concurrent_load"]
    assert len(rows) == 1
    assert rows[0]["result_id"] == "FABRIC-WITHOUT-PATH-ID"
    assert rows[0]["levels"] == [
        {
            "pairs": 4,
            "pairs_used": 4,
            "cross_compute_pairs": None,
            "same_compute_pairs": None,
            "median_aggregate_mbps": 18_500,
            "minimum_aggregate_mbps": None,
            "maximum_aggregate_mbps": None,
            "median_pair_mbps": None,
            "minimum_pair_mbps": None,
            "minimum_fairness": None,
            "median_idle_p95_ms": None,
            "median_loaded_p95_ms": None,
            "median_loaded_latency_ratio": None,
            "median_loaded_tcp_aggregate_mbps": None,
            "maximum_loaded_icmp_loss_pct": None,
            "maximum_loaded_udp_application_loss_pct": None,
            "maximum_loaded_udp_jitter_ms": None,
            "minimum_udp_sender_achievement_pct": None,
            "total_retransmissions": None,
            "total_loaded_retransmissions": None,
            "per_pair_degradation_pct": None,
        }
    ]
