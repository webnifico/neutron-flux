from __future__ import annotations

import json
import subprocess
from pathlib import Path

from neutron_flux.comparison import _comparison_html, compare_payloads
from neutron_flux.trends import _trend_html, trend_payload


def _run(run_id: str, results: list[dict], *, performance: dict | None = None) -> dict:
    counts: dict[str, int] = {}
    for item in results:
        status = str(item.get("status") or "UNKNOWN")
        counts[status] = counts.get(status, 0) + 1
    return {
        "schema_version": 1,
        "run": {
            "run_id": run_id,
            "started_at": f"2026-07-{20 + len(run_id):02d}T00:00:00+00:00",
            "final_status": "PASS",
        },
        "summary": {"counts": counts, "performance": performance or {}},
        "results": results,
        "cleanup": {"complete": True},
    }


def _result(test_id: str, status: str = "PASS", *, health: str | None = None) -> dict:
    details = {"health": health} if health else {}
    return {
        "test_id": test_id,
        "display_name": test_id,
        "category": "network",
        "status": status,
        "details": details,
    }


def _fabric(level: dict) -> dict:
    return {
        "test_id": "FABRIC-SCALE",
        "display_name": "Fabric scale",
        "category": "network-performance",
        "status": "PASS",
        "details": {
            "performance": True,
            "measurement": "fabric-scale",
            "health": "good",
            "metrics": {"levels": [level]},
            "path": {},
        },
    }


def _check_javascript(html: str, tmp_path: Path) -> None:
    marker = "<script>"
    scripts: list[str] = []
    cursor = 0
    while True:
        start = html.find(marker, cursor)
        if start < 0:
            break
        end = html.find("</script>", start)
        assert end > start
        scripts.append(html[start + len(marker) : end])
        cursor = end + 9
    assert scripts
    path = tmp_path / "report.js"
    path.write_text("\n".join(scripts), encoding="utf-8")
    subprocess.run(["node", "--check", str(path)], check=True, capture_output=True)


def test_comparison_marks_new_bad_results_and_lost_good_coverage_as_regressions():
    baseline = _run("base", [_result("GOOD")])
    candidate = _run("candidate", [_result("NEW-BAD", "FAIL")])

    comparison = compare_payloads(baseline, candidate)
    assessments = {item["label"]: item["assessment"] for item in comparison["entries"]}

    assert assessments["GOOD"] == "regressed"
    assert assessments["NEW-BAD"] == "regressed"
    assert comparison["summary"]["regressed"] == 2


def test_comparison_includes_fabric_quality_and_degradation_metrics():
    baseline = _run(
        "base",
        [
            _fabric(
                {
                    "pairs": 4,
                    "median_aggregate_mbps": 4000,
                    "median_pair_mbps": 1000,
                    "minimum_pair_mbps": 900,
                    "median_fairness": 0.99,
                    "median_loaded_p95_ms": 2,
                    "median_loaded_latency_ratio": 2,
                    "maximum_loaded_loss_pct": 0,
                    "maximum_loaded_udp_jitter_ms": 0.2,
                    "total_retransmissions": 1,
                    "per_pair_degradation_pct": 0,
                }
            )
        ],
    )
    candidate = _run(
        "candidate",
        [
            _fabric(
                {
                    "pairs": 4,
                    "median_aggregate_mbps": 3000,
                    "median_pair_mbps": 700,
                    "minimum_pair_mbps": 500,
                    "median_fairness": 0.80,
                    "median_loaded_p95_ms": 8,
                    "median_loaded_latency_ratio": 8,
                    "maximum_loaded_loss_pct": 3,
                    "maximum_loaded_udp_jitter_ms": 2.5,
                    "total_retransmissions": 40,
                    "per_pair_degradation_pct": 30,
                }
            )
        ],
    )

    entry = compare_payloads(baseline, candidate)["entries"][0]

    assert entry["assessment"] == "regressed"
    assert entry["metrics"]["pairs_4_minimum_pair_mbps"]["assessment"] == "regressed"
    assert (
        entry["metrics"]["pairs_4_loaded_udp_application_loss_pct"]["assessment"]
        == "regressed"
    )
    assert (
        entry["metrics"]["pairs_4_per_pair_degradation_pct"]["assessment"]
        == "regressed"
    )


def test_trend_reads_legacy_load_keys_and_emits_canonical_values(tmp_path):
    first = _run("a", [], performance={})
    second = _run(
        "bb",
        [],
        performance={
            "warning_results": 2,
            "fabric_max_pairs": 8,
            "fabric_best_aggregate_mbps": 7200,
            "fabric_lowest_pair_mbps": 650,
            "fabric_worst_degradation_pct": 35,
            "fabric_worst_loaded_latency_ratio": 6,
            "fabric_worst_udp_jitter_ms": 1.2,
        },
    )

    payload = trend_payload_from_payloads([first, second], tmp_path)
    assert payload["runs"][1]["warnings"] == 2
    assert payload["runs"][1]["concurrent_load_max_pairs"] == 8
    assert payload["runs"][1]["concurrent_load_highest_observed_aggregate_mbps"] == 7200

    html = _trend_html(payload)
    assert "Concurrent-load aggregate throughput" in html
    assert "Fabric capacity" not in html
    assert "let started=false" in html
    _check_javascript(html, tmp_path)


def trend_payload_from_payloads(payloads: list[dict], tmp_path: Path) -> dict:
    paths: list[Path] = []
    for index, payload in enumerate(payloads):
        path = tmp_path / f"run-{index}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        paths.append(path)
    return trend_payload(paths)


def test_comparison_javascript_is_valid(tmp_path):
    payload = compare_payloads(
        _run("base", [_result("A")]), _run("candidate", [_result("A")])
    )
    _check_javascript(_comparison_html(payload), tmp_path)
