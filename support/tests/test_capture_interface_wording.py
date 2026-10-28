from __future__ import annotations

import copy
import json
import re
import subprocess

from neutron_flux.reporting_components.html_template import HTML_TEMPLATE
from neutron_flux.reporting_components.manual_reproduction import manual_reproduction

from .test_summary_wording import _function, _run_javascript


def test_cleanup_only_report_does_not_claim_network_tests_passed():
    result = _run_javascript(
        _function("verdictText")
        + """
const tests=[],counts={},summary={cleanup_complete:true},
 D={run:{action:'cleanup',final_status:'PASS'}};
const complete=verdictText();
summary.cleanup_complete=false;
D.run.final_status='CLEANUP INCOMPLETE';
const incomplete=verdictText();
console.log(JSON.stringify({complete,incomplete}));
"""
    )
    assert result["complete"] == (
        "Cleanup completed for the eligible resource scope; no network tests ran."
    )
    assert result["incomplete"] == "Cleanup requires review; no network tests ran."
    assert "expected behaviour" not in result["complete"]


def test_readable_labels_preserve_grammatical_blocked_check_description():
    terms = re.search(r"const reportTerms=\[[\s\S]*?\n\];", HTML_TEMPLATE)
    assert terms
    completed = subprocess.run(
        [
            "node",
            "-e",
            terms.group(0)
            + "\n"
            + _function("readableText")
            + "\nconsole.log(JSON.stringify(readableText('These dependent checks were not executed.')));",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(completed.stdout) == "These dependent checks were not executed."


def test_unresolved_resource_records_are_not_called_present_resources():
    function = re.search(
        r"function renderRun\(\)\{[\s\S]*?\n\}(?=\nfunction activateView)",
        HTML_TEMPLATE,
    )
    assert function
    result = _run_javascript(
        """
const D={run:{},resources:{total:264,by_cleanup_state:{FAILED:24}},
 cleanup:{verification_issue_count:53}},environment={},M={},
 summary={cleanup_complete:false,cleanup_present:24,
 cleanup_unresolved_resources:24,cleanup_verification_issues:53};
const testSelectionLabel='All planned tests';
const dateText=value=>String(value),bytes=value=>String(value);
"""
        + function.group(0)
        + "\nrenderRun();console.log(JSON.stringify({html:nodes.cleanupSummary.innerHTML}));"
    )
    assert "Tracked resources unresolved" in result["html"]
    assert "cleanup or verification" in result["html"]
    assert "Cleanup verification issues" in result["html"]
    assert "not a count of distinct resources still present" in result["html"]
    assert '<span class="eyebrow">Resources still present' not in result["html"]


def test_self_hairpin_manual_guide_keeps_both_roles_on_the_same_vm():
    result = {
        "category": "floating-ip-peer",
        "details": {
            "nat_path": "self-hairpin",
            "protocol": "icmp",
            "probe": {
                "command": "ping -4 -I 10.0.0.2 192.0.2.2",
                "diagnostics": {
                    "icmp_destination_attestation": {
                        "command": "python3 destination_observer.py"
                    }
                },
            },
        },
    }
    original = copy.deepcopy(result)
    guide = manual_reproduction(result)
    setup = " ".join(guide["setup"])
    assert "Use one test VM" in setup
    assert "its own floating-IP association" in setup
    assert "separate terminals on the same VM" in setup
    assert "destination, not the source" not in setup
    assert "independent observer" not in setup
    assert [command["command"] for command in guide["commands"]] == [
        "python3 destination_observer.py",
        "ping -4 -I 10.0.0.2 192.0.2.2",
    ]
    assert result == original


def test_peer_floating_ip_manual_guide_uses_the_recorded_actors():
    guide = manual_reproduction(
        {"category": "floating-ip-peer", "details": {"nat_path": "peer"}}
    )
    setup = " ".join(guide["setup"])
    assert "source, destination and direction shown in the evidence" in setup
    assert "separate observer only when the recorded check requires one" in setup
    assert "Use one test VM" not in setup


def test_cleanup_selection_does_not_claim_a_network_test_plan():
    declaration = re.search(r"^const testSelectionLabel=[^\n]+", HTML_TEMPLATE, re.M)
    assert declaration
    completed = subprocess.run(
        [
            "node",
            "-e",
            "const D={run:{action:'cleanup'}};\n"
            + declaration.group(0)
            + "\nconsole.log(JSON.stringify(testSelectionLabel));",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(completed.stdout) == ("Cleanup only · no network tests selected")


def test_group_counts_include_saved_results_without_claiming_they_all_ran():
    terms = re.search(r"const reportTerms=\[[\s\S]*?\n\];", HTML_TEMPLATE)
    assert terms
    completed = subprocess.run(
        [
            "node",
            "-e",
            terms.group(0)
            + "\n"
            + _function("readableText")
            + "\nconsole.log(JSON.stringify(readableText('24 executions · 12 matching executions · 538 recorded rows')));",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(completed.stdout) == (
        "24 saved results · 12 matching results · 538 saved test results"
    )


def test_host_selection_counts_do_not_claim_zero_post_migration_tests():
    result = _run_javascript(
        _function("renderHostScope")
        + """
const M={host_scope:{enabled:true}},tests=[
 {host_scope:{code:'targeted'},timing:'Before migration'},
 {host_scope:{code:'targeted'},timing:'After migration'}];
renderHostScope();
console.log(JSON.stringify({html:nodes.hostScope.innerHTML}));
"""
    )
    assert "2 requested-pair" in result["html"]
    assert "0 additional post-migration" in result["html"]
    assert "include checks before and after migration when planned" in result["html"]
    assert "0 after migration" not in result["html"]


def test_readable_counts_and_blocking_reasons_use_complete_grammar():
    terms = re.search(r"const reportTerms=\[[\s\S]*?\n\];", HTML_TEMPLATE)
    assert terms
    completed = subprocess.run(
        [
            "node",
            "-e",
            terms.group(0)
            + "\n"
            + _function("readableText")
            + "\nconsole.log(JSON.stringify([readableText('Blocked by router setup'),readableText('1 executions · 1 test types · 1 availability zones · 11 test types')]));",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(completed.stdout) == [
        "Could not run because of router setup",
        "1 saved result · 1 test type · 1 availability zone · 11 test types",
    ]
    assert "the cause may be uncertain" in HTML_TEMPLATE
