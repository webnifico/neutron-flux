from __future__ import annotations

import copy
import json
import re
import subprocess
from pathlib import Path

from neutron_flux.reporting_components.html import render_html
from support.tests.test_report_workflow import _payload


def _report(html: str) -> dict:
    match = re.search(
        r'<script id="run-data" type="application/json">(.*?)</script>', html, re.S
    )
    assert match
    return json.loads(match.group(1))


def test_readable_context_separates_compute_placement_from_migration_timing():
    payload = _payload()
    before = payload["results"][0]
    before["details"].update({"phase": "intra", "protocol": "tcp"})
    before["details"]["path"]["stage"] = "pre-migration"
    after = copy.deepcopy(before)
    after["test_id"] = "PROJECT-ROUTE-TCP-AFTER"
    after["details"]["path"]["stage"] = "post-migration"
    after["details"]["path"]["destination_compute_host"] = "compute1"
    payload["results"].append(after)
    original = copy.deepcopy(payload)

    rows = _report(render_html(payload))["dashboard"]["results"]
    assert rows[0]["human_context"]["timing"] == "Before migration"
    assert rows[1]["human_context"]["timing"] == "After migration"
    assert "different" in rows[0]["human_context"]["placement"].lower()
    assert "same" in rows[1]["human_context"]["placement"].lower()
    assert rows[0]["human_context"]["source"]["fixed_ip"] == "10.0.3.107"
    assert rows[0]["human_context"]["destination"]["compute_host"] == "compute2"
    assert rows[0]["human_context"]["source"]["availability_zone"] == "zone-a"
    assert payload == original


def test_supporting_attempts_keep_human_context_and_expected_denial(tmp_path: Path):
    payload = _payload()
    result = payload["results"][0]
    result.update(
        {
            "test_id": "PRIVATE-ROUTE-BLOCKED",
            "category": "router-static-routing",
            "display_name": "Static-route baseline",
            "expected": "blocked",
            "observed": "blocked",
            "message": "TCP blocked as expected",
        }
    )
    result["details"].update({"operation": "static-route-baseline", "protocol": "tcp"})
    result["details"]["path"]["stage"] = "pre-migration"
    result["details"]["probe"]["stdout"] = "Destination unreachable: No route"
    sample = copy.deepcopy(result)
    sample["test_id"] = "PRIVATE-ROUTE-SAMPLE"
    sample["details"]["check_sample"] = True
    payload["results"].append(sample)
    payload["planned_check_ledger"] = [
        {
            "id": "PRIVATE-ROUTE-CHECK",
            "title": "TCP access before adding static routes",
            "kind": "connectivity",
            "stage": "initial",
            "condition": "TCP is blocked",
            "outcome": "PASSED",
            "reason": "TCP blocked as expected",
            "prerequisites": [],
            "result_id": "PRIVATE-ROUTE-BLOCKED",
            "evidence_ids": ["PRIVATE-ROUTE-BLOCKED", "PRIVATE-ROUTE-SAMPLE"],
        }
    ]
    original = copy.deepcopy(payload)
    html = render_html(payload)
    report = _report(html)
    row = report["dashboard"]["results"][0]
    assert row["status"] == "PASS"
    assert row["human_context"]["action"] == "Before adding static routes"
    supporting = report["dashboard"]["evidence_entries"]["PRIVATE-ROUTE-SAMPLE"]
    assert supporting["status"] == "PASS"
    assert supporting["human_context"]["action"] == "Before adding static routes"
    assert supporting["expected"]
    assert supporting["operator_explanation"]["why_this_status"]
    assert supporting["evidence"]["stdout"] == "Destination unreachable: No route"
    assert payload == original
    file = tmp_path / "report.html"
    file.write_text(html)
    check = Path(__file__).with_name("report_dom_check.js")
    subprocess.run(
        ["node", str(check), str(file), report["report_renderer_version"]],
        check=True,
        capture_output=True,
        text=True,
    )


def test_multiline_measurements_remain_separate_in_visible_report(tmp_path: Path):
    payload = _payload()
    result = payload["results"][0]
    result.update(
        test_id="UDP-PROFILES",
        category="network-performance",
        expected="profile-recorded",
        observed="profile-measured",
    )
    sample = {
        "packet_size": 128,
        "configured_rate_mbps": 10,
        "offered_mbps": 10,
        "sender_mbps": 9.99,
        "receiver_goodput_mbps": 9.98,
        "pps": 9746.5,
        "jitter_ms": 0.007,
        "loss_pct": 0,
        "load_valid": True,
        "endpoint_limited": False,
        "calibration_selected": True,
    }
    result["details"].update(
        measurement="udp",
        health="warning",
        warning_reasons=[
            "UDP reverse 10 Mbit/s with 128-byte datagrams was endpoint-limited (receiver-overload); calibrated sustainable rate 5 Mbit/s; endpoint-limited samples were excluded from network-loss grading"
        ],
        metrics={
            "forward": [sample],
            "reverse": [
                {
                    **sample,
                    "endpoint_limited": True,
                    "load_valid": False,
                    "endpoint_limit_reason": "receiver-overload",
                    "loss_pct": 0.5,
                },
                {**sample, "offered_mbps": 5},
            ],
        },
    )
    supporting = copy.deepcopy(result)
    supporting["test_id"] = "UDP-SAMPLE"
    supporting["details"]["check_sample"] = True
    payload["results"].append(supporting)
    payload["planned_check_ledger"] = [
        {
            "id": "UDP-CHECK",
            "title": "Measure UDP delivery",
            "kind": "performance",
            "stage": "initial",
            "condition": "UDP profiles complete",
            "outcome": "PASSED",
            "reason": "Profiles completed",
            "prerequisites": [],
            "result_id": "UDP-PROFILES",
            "evidence_ids": ["UDP-PROFILES", "UDP-SAMPLE"],
        }
    ]
    file = tmp_path / "multiline.html"
    file.write_text(render_html(payload))
    script = r"""
const fs=require('node:fs'),assert=require('node:assert/strict');
const {JSDOM,VirtualConsole}=require('jsdom');
const dom=new JSDOM(fs.readFileSync(process.argv[1],'utf8'),{
 runScripts:'dangerously',virtualConsole:new VirtualConsole(),url:'https://report.invalid/report.html',
 beforeParse(w){w.scrollTo=()=>{};w.HTMLElement.prototype.scrollIntoView=()=>{};}
});
const w=dom.window,d=w.document;
w.eval('openTest(tests[0].sequence)');
const actual=d.querySelector('[data-result-pane="result"] .modern-result-pair>div:nth-child(2) p');
assert.ok(actual.textContent.includes('\n'));
assert.ok(actual.textContent.includes('Source → destination'));
assert.ok(actual.textContent.includes('Destination → source'));
assert.ok(actual.textContent.includes('Observation:'));
assert.ok(actual.textContent.toLowerCase().includes('receiver'));
assert.equal(w.getComputedStyle(actual).whiteSpace,'pre-line');
const sample=d.querySelector('[data-result-pane="result"] .sample-outcome p:nth-child(2)');
assert.ok(sample.textContent.includes('\n'));
assert.equal(w.getComputedStyle(sample).whiteSpace,'pre-line');
const holder=d.createElement('div');holder.innerHTML=w.eval('executionTable(tests)');d.body.append(holder);
const cell=holder.querySelector('.observed-value');
assert.ok(cell.textContent.includes('\n'));
assert.equal(w.getComputedStyle(cell).whiteSpace,'pre-line');
dom.window.close();
"""
    completed = subprocess.run(
        ["node", "-e", script, str(file)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
