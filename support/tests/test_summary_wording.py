from __future__ import annotations

import copy
import json
import re
import subprocess

from neutron_flux.reporting_components.html_template import HTML_TEMPLATE
from neutron_flux.reporting_components.report_payload import (
    _compact_result,
    _coverage_summary,
)


def _function(name: str) -> str:
    match = re.search(rf"^function {name}\([^\n]*", HTML_TEMPLATE, re.MULTILINE)
    assert match, name
    return match.group(0)


def _run_javascript(body: str) -> dict:
    helpers = r"""
const assert=require('node:assert/strict');
const nodes={};
const document={getElementById(id){return nodes[id]??=(
 {innerHTML:'',textContent:'',value:'all',classList:{toggle(){}}}
);}};
const esc=value=>String(value??'');
const countText=(n,label)=>`${n} ${label}${n===1?'':'s'}`;
const statusText=value=>String(value).replaceAll('_',' ');
const finalIsBad=value=>['ERROR','CLEANUP INCOMPLETE','FAILED'].includes(value);
const finalIsCaution=value=>['PASS WITH WARNINGS','PARTIAL','WARNING','INCOMPLETE'].includes(value);
const finite=value=>typeof value==='number'&&Number.isFinite(value);
const mbps=value=>finite(value)?`${value} Mbit/s`:'—';
const ms=mbps,ratio=mbps,pct=mbps,trim=value=>String(value);
function renderPerformanceTests(){}
"""
    completed = subprocess.run(
        ["node", "-e", helpers + "\n" + body],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return json.loads(completed.stdout)


def test_complete_warning_verdict_does_not_claim_incomplete_execution():
    result = _run_javascript(
        _function("verdictText")
        + r"""
const counts={},summary={},D={run:{final_status:'PASS WITH WARNINGS'}};
const complete=verdictText();
counts.BLOCKED_BY_SETUP_ERROR=1;
const blocked=verdictText();
counts.BLOCKED_BY_SETUP_ERROR=0;
D.run.final_status='CLEANUP INCOMPLETE';
const incomplete=verdictText();
D.run.final_status='PARTIAL';
const partial=verdictText();
console.log(JSON.stringify({complete,blocked,incomplete,partial}));
"""
    )
    assert result["complete"] == (
        "Run complete; review the recorded observations and advisories."
    )
    assert "did not produce a conclusive pass" in result["blocked"]
    assert "before this run can be treated as complete" in result["incomplete"]
    assert "before this run can be treated as complete" in result["partial"]


def test_scope_counts_use_logical_checks_instead_of_supporting_evidence():
    result = _run_javascript(
        _function("renderHostScope")
        + r"""
const M={host_scope:{enabled:true,counts:{targeted:731,control:2},note:'Selected hosts'}};
const tests=[...Array.from({length:536},()=>({host_scope:{code:'targeted'}})),
 {host_scope:{code:'control'}},{host_scope:{code:'control'}}];
renderHostScope();
console.log(JSON.stringify({html:nodes.hostScope.innerHTML}));
"""
    )
    assert "536 requested-pair" in result["html"]
    assert "2 controller" in result["html"]
    assert "731" not in result["html"]


def test_empty_incidents_keep_links_to_passing_observations():
    result = _run_javascript(
        _function("passingReviewGroups")
        + "\n"
        + _function("renderFindings")
        + r"""
const findings=[],M={operator_overview:{groups:[
 {kind:'migration-interruption-observation',label:'Migration interruption',count:4,statuses:{PASS:4}},
 {kind:'measurement-rate-limited',label:'UDP VM rate limit',count:13,statuses:{PASS:13}},
 {kind:'advisory',label:'Measurement observations',count:11,statuses:{PASS:11}},
 {kind:'incomplete',label:'Setup failed',count:1,statuses:{ERROR:1}}
]}};
renderFindings();
console.log(JSON.stringify({count:nodes.findingCount.textContent,
 incidents:nodes.findingList.innerHTML,observations:nodes.findingObservations.innerHTML}));
"""
    )
    assert result["count"] == "0 of 0 grouped incidents"
    assert "listed separately below" in result["incidents"]
    for kind in (
        "migration-interruption-observation",
        "measurement-rate-limited",
        "advisory",
    ):
        assert f'data-review-kind="{kind}"' in result["observations"]
    assert 'data-review-kind="incomplete"' not in result["observations"]


def test_disabled_load_is_not_reported_as_a_zero_measurement():
    result = _run_javascript(
        _function("renderPerformance")
        + r"""
const D={summary:{performance:{concurrent_load_max_pairs:null}},
 configuration:{concurrent_vm_pair_load:{enabled:false}}},environment={},M={};
renderPerformance();
const disabled={summary:nodes.performanceSummary.innerHTML,detail:nodes.concurrentLoad.innerHTML};
D.configuration.concurrent_vm_pair_load.enabled=true;
D.summary.performance.concurrent_load_max_pairs=4;
D.summary.performance.concurrent_load_highest_observed_aggregate_mbps=1000;
renderPerformance();
console.log(JSON.stringify({disabled,measured:nodes.performanceSummary.innerHTML}));
"""
    )
    assert (
        "Max simultaneous pairs</span><strong>Not run" in result["disabled"]["summary"]
    )
    assert "load disabled" in result["disabled"]["summary"]
    assert "disabled for this run" in result["disabled"]["detail"]
    assert "Max simultaneous pairs</span><strong>4" in result["measured"]
    assert "1000 Mbit/s aggregate" in result["measured"]


def test_measurement_settings_and_fairness_have_distinct_meanings():
    assert '["Performance profile",config.performance_profile' in HTML_TEMPLATE
    assert (
        '["Measurement duration and repeats",config.performance_enabled'
        in HTML_TEMPLATE
    )
    assert '["Performance profile",config.performance_enabled' not in HTML_TEMPLATE
    assert "throughput was shared across parallel TCP flows" in HTML_TEMPLATE
    assert "fairness across VM pairs separately" in HTML_TEMPLATE
    # This label translation runs after the workflow/navigation overrides.
    assert "['Findings','Grouped incidents']" in HTML_TEMPLATE
    assert HTML_TEMPLATE.index(
        "['Findings','Grouped incidents']"
    ) > HTML_TEMPLATE.index("const chromeBeforeRail=renderChrome")


def test_applicable_path_counts_preserve_real_missing_diagnostics():
    results = [
        {"result_id": "control", "category": "controller-bootstrap"},
        {"result_id": "perf", "category": "network-performance"},
        {"result_id": "good", "category": "same-subnet"},
        {"result_id": "missing", "category": "same-subnet"},
    ]
    paths = [
        {
            "result_ids": ["control"],
            "source": {},
            "destination": {"ip": "192.0.2.10"},
        },
        {
            "result_ids": ["perf"],
            "source": {"ip": "192.0.2.11"},
            "destination": {"ip": "192.0.2.12"},
        },
        {
            "result_ids": ["good"],
            "source": {"ip": "192.0.2.13"},
            "destination": {"ip": "192.0.2.14"},
            "route_observations": [{"output": "192.0.2.14 dev eth0"}],
        },
        {
            "result_ids": ["missing"],
            "source": {},
            "destination": {"ip": "192.0.2.15"},
        },
        {"result_ids": ["unknown"], "source": {}, "destination": {}},
    ]
    payload = {
        "summary": {
            "performance_coverage": {"selected": 1, "completed": 1, "omitted": 0}
        }
    }
    coverage = _coverage_summary(payload, results, paths)
    scope = coverage["evidence_scope"]
    assert scope["traffic_paths"] == 4
    assert scope["traffic_paths_with_endpoint_ips"] == 2
    assert scope["functional_guest_paths"] == 3
    assert scope["functional_guest_paths_with_route_output"] == 1
    assert scope["controller_access_paths"] == 1
    assert scope["controller_paths_without_runner_ip"] == 1
    assert scope["standalone_performance_paths"] == 1
    assert scope["performance_paths_completed"] == 1
    assert scope["performance_paths_selected"] == 1
    # Preserve old exported counters for consumers; only scoped display changes.
    assert coverage["path_count"] == 5
    assert coverage["paths_with_endpoint_ips"] == 2
    assert coverage["paths_with_route_observations"] == 1


def test_saved_detail_rows_explain_separate_record_types_and_measurement_scope():
    result = _run_javascript(
        _function("savedDetailRows")
        + r"""
const tests=Array.from({length:538},()=>({})),paths=[],coverage={
 planned_tests:538,path_count:125,measured_paths:34,
 evidence_scope:{traffic_paths:124,traffic_paths_with_endpoint_ips:124,
 functional_guest_paths:98,functional_guest_paths_with_route_output:98,
 controller_access_paths:1,controller_paths_without_runner_ip:1,
 standalone_performance_paths:26,performance_paths_selected:26,
 performance_paths_completed:26,performance_paths_omitted:0}};
console.log(JSON.stringify({rows:savedDetailRows()}));
"""
    )
    rows = {row[0]: row[1:] for row in result["rows"]}
    assert rows["Source and destination IP addresses"][0] == "124 of 124 traffic paths"
    assert (
        "records without a saved runner IP: 1"
        in rows["Source and destination IP addresses"][1]
    )
    assert rows["Functional guest routing output"][0] == "98 of 98 paths"
    assert (
        "standalone performance records (26)"
        in rows["Functional guest routing output"][1]
    )
    assert rows["Performance suite completion"][0] == "26 of 26 selected paths"
    assert "not every connectivity record" in rows["Performance suite completion"][1]
    assert "34" not in json.dumps(rows)


def test_saved_detail_rows_keep_real_missing_counts_visible():
    result = _run_javascript(
        _function("savedDetailRows")
        + r"""
const tests=[],paths=[],coverage={evidence_scope:{
 traffic_paths:4,traffic_paths_with_endpoint_ips:3,functional_guest_paths:3,
 functional_guest_paths_with_route_output:2,controller_access_paths:0,
 controller_paths_without_runner_ip:0,standalone_performance_paths:1,
 performance_paths_selected:null,performance_paths_completed:null,
 performance_paths_omitted:null}};
console.log(JSON.stringify({rows:savedDetailRows()}));
"""
    )
    rows = {row[0]: row[1:] for row in result["rows"]}
    assert (
        "Traffic paths missing one or both IPs: 1"
        in rows["Source and destination IP addresses"][1]
    )
    assert (
        "Functional paths missing route output: 1"
        in rows["Functional guest routing output"][1]
    )
    assert rows["Performance suite completion"][0] == "Not recorded"


def test_compact_labels_are_normalized_without_rewriting_raw_evidence():
    old = "IPv6 project-network connectivity with routing metadata unassigned through Public:B"
    result = {
        "result_id": "KEEP-ORIGINAL-ID",
        "test_id": "KEEP-ORIGINAL-ID",
        "category": "same-subnet",
        "status": "PASS",
        "test_name": old,
        "execution_name": old,
        "message": old,
        "expected": "reachable",
        "observed": "reachable",
        "source_display": {"label": old, "ip": "2001:db8::1"},
        "destination_display": {"label": old, "ip": "2001:db8::2"},
        "details": {"command": old, "stdout": old},
    }
    original = copy.deepcopy(result)
    row = _compact_result(1, result)
    for key in ("test_name", "execution_name", "message"):
        assert "routing metadata unassigned" not in row[key]
        assert row[key].endswith(":B")
    for endpoint in (row["source"], row["destination"]):
        assert "external routing not tested" in endpoint["label"]
        assert endpoint["label"].endswith("Public:B")
    assert row["evidence"]["stdout"] == old
    assert row["result_id"] == "KEEP-ORIGINAL-ID"
    assert result == original


def test_rate_review_link_includes_checks_that_also_have_an_advisory():
    result = _run_javascript(
        _function("filteredTests")
        + "\n"
        + _function("bind")
        + r"""
const M={operator_overview:{groups:[{
 kind:'measurement-rate-limited',result_ids:['rate-only','rate-and-advisory']
}]}},findings=[],pathById=new Map();
let focusedFinding=null,focusedPath=null,focusedTest=null,activeView='overview';
const tests=[
 {result_id:'rate-only',operator_explanation:{kind:'measurement-rate-limited'},search_text:''},
 {result_id:'rate-and-advisory',operator_explanation:{kind:'advisory'},search_text:''},
 {result_id:'not-calibrated',operator_explanation:{kind:'advisory'},search_text:''}
];
const listeners={};
document.querySelectorAll=()=>[];
document.addEventListener=()=>{};
document.body={addEventListener:(event,handler)=>{listeners[event]=handler;}};
const originalGet=document.getElementById;
document.getElementById=function(id){const node=originalGet(id);node.addEventListener=()=>{};return node;};
function renderTests(){}
function renderFindings(){}
function renderPaths(){}
function renderPerformance(){}
function clearContext(){}
function testMoment(){return 'Before migration';}
function activateView(view){activeView=view;}
bind();
listeners.click({target:{closest(selector){
 return selector==='[data-review-kind]'?{dataset:{reviewKind:'measurement-rate-limited'}}:null;
}}});
const linked=filteredTests().map(test=>test.result_id);
delete M.operator_overview.groups[0].result_ids;
const legacy=filteredTests().map(test=>test.result_id);
M.operator_overview.groups[0].result_ids=[];
const empty=filteredTests().map(test=>test.result_id);
console.log(JSON.stringify({activeView,linked,legacy,empty}));
"""
    )
    assert result["activeView"] == "tests"
    assert result["linked"] == ["rate-only", "rate-and-advisory"]
    assert result["legacy"] == ["rate-only"]
    assert result["empty"] == []
