from __future__ import annotations

import copy
import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from neutron_flux.constants import DISPLAY_VERSION
from neutron_flux.diagnostics import DiagnosticCollector
from neutron_flux.junit_report import build_junit
from neutron_flux.operator_evidence import diagnostic_snapshot, evidence_facts
from neutron_flux.operator_explanations import (
    explain_result,
    explanation_lines,
    lifecycle_explanations,
    operator_overview,
)
from neutron_flux.report_diagnostics import with_diagnostic_artifacts
from neutron_flux.report_exports import render_incident_summary
from neutron_flux.reporting_components.dashboard_model import build_dashboard_model
from neutron_flux.reporting_components.html import render_html
from neutron_flux.results_io import render_results_text
from neutron_flux.utils import unique_safe_name
from support.tests.test_report_workflow import _embedded_payload, _payload
from support.tests.test_translated_migration_reporting import _observation_pass


def _failure():
    result = copy.deepcopy(_payload()["results"][0])
    result.update(
        status="FAIL",
        category="source-nat-packet-size",
        observed="source-nat-provider-observer-failed",
        message="Provider connection failed",
        expected="profile-complete",
    )
    result["details"].update(
        egress_translation_mode="router-source-nat",
        mtu_profile=None,
        fragmentation_profile=None,
        tcp_baseline={
            "success": False,
            "attempts": 1,
            "diagnostics": {
                "failure_phase": "connect",
                "error_type": "TimeoutError",
                "error": "timed out",
                "destination_port": 18080,
                "connected": False,
                "request_sent": False,
            },
        },
    )
    return result


@pytest.mark.parametrize(
    "status,kind",
    [
        ("PASS", "passed"),
        ("FAIL", "check-failed"),
        ("ERROR", "execution-error"),
        ("UNVERIFIED", "measurement-incomplete"),
        ("BLOCKED_BY_SETUP_ERROR", "prerequisite-blocked"),
        ("BLOCKED_BY_PREREQUISITE", "prerequisite-blocked"),
        ("NOT_RUN_CANCELLED", "cancelled"),
        ("NOT_APPLICABLE", "not-applicable"),
        ("SKIP", "not-applicable"),
        ("NEW", "unknown-status"),
    ],
)
def test_statuses_explain_the_verdict_without_inventing_a_cause(status, kind):
    result = {"status": status, "message": "Original recorded reason", "details": {}}
    original = copy.deepcopy(result)
    story = explain_result(result)
    assert story["kind"] == kind
    if status.startswith("BLOCKED") or status in {
        "NOT_RUN_CANCELLED",
        "SKIP",
        "NOT_APPLICABLE",
    }:
        assert (
            "did not run" in story["observed"]
            or "No traffic probe ran" in story["observed"]
        )
        assert story["recorded_message"] == "Original recorded reason"
    else:
        assert story["what_happened"] == "Original recorded reason"
    assert story["why_this_status"] and story["next_check"]
    assert result == original


def test_snat_failure_explains_failed_step_and_evidence_limits():
    story = explain_result(_failure())
    assert story["headline"] == "TCP connection timed out"
    assert "18080" in story["what_happened"]
    assert "MTU and fragmentation were not measured" in story["why_this_status"]
    assert "Only one attempt" in " ".join(story["limitations"])
    assert "cause is not established" in " ".join(story["limitations"])
    assert "host compute1" in story["location"][0]["value"]
    assert {"label": "TCP connection established", "value": "No"} in story["facts"]


@pytest.mark.parametrize("observation", ["reachable", "blocked"])
def test_undeclared_policy_is_an_observation_not_a_probe_failure(observation):
    result = {
        "status": "UNVERIFIED",
        "expected": "observation",
        "observed": observation,
        "details": {
            "routing_policy": {
                "expectation": "observation",
                "reason": "No routing relationship declared",
            }
        },
    }
    story = explain_result(result)
    assert story["kind"] == "routing-expectation-missing"
    assert "Neither PASS nor FAIL" in story["why_this_status"]
    assert story["observed"] == observation


def test_incomplete_comparison_is_distinct_from_udp_loss():
    story = explain_result(
        {
            "status": "UNVERIFIED",
            "details": {
                "measurement": "asymmetry",
                "metrics": {"udp_compared_profiles": 5, "udp_unmatched_profiles": 2},
            },
        }
    )
    assert story["kind"] == "comparison-incomplete"
    assert "does not establish packet loss" in story["why_this_status"]
    assert {"label": "Unmatched UDP profiles", "value": "2"} in story["facts"]


def test_advisory_pass_is_visible_and_keeps_sample_eligibility_warning():
    result = {
        "status": "PASS",
        "details": {
            "health": "warning",
            "thresholds_enforced": False,
            "warning_reasons": [
                "Endpoint-limited samples excluded from network-loss grading"
            ],
        },
    }
    story = explain_result(result)
    assert story["attention"] is True
    assert story["kind"] == "advisory"
    assert "not a failed validation" in story["why_this_status"]
    assert "excluded" in story["warnings"][0]
    assert operator_overview({"results": [result]})["groups"][0]["count"] == 1


def test_blocking_result_id_is_explicit_and_error_message_is_embedded():
    result = {
        "status": "BLOCKED_BY_SETUP_ERROR",
        "message": "SSH preparation failed",
        "details": {"root_setup_result_id": "SETUP-1"},
    }
    assert "SETUP-1" in "\n".join(explanation_lines(result))
    error = explain_result(
        {
            "status": "ERROR",
            "details": {"error": "HTTP 403: Policy does not allow forced placement"},
        }
    )
    assert "HTTP 403" in str(error["facts"])
    assert "does not establish a network" in error["why_this_status"]


def _snapshot(test_id):
    return {
        "test": test_id,
        "guests": {
            "destination": {
                "server_id": "server-2",
                "usable": True,
                "status": "collected",
                "output": "### ip route show table all\ndefault via 10.0.0.1 dev ens4\n### sockets\ntcp LISTEN 0 64 0.0.0.0:18080 0.0.0.0:*\n",
            }
        },
        "openstack": {
            "destination-port-port2": {
                "status": "ACTIVE",
                "binding_host_id": "compute2",
                "fixed_ips": [{"ip_address": "10.0.0.2"}],
            }
        },
    }


def test_snapshot_facts_have_routes_listener_and_port_status_without_causal_claims():
    result = _failure()
    result["details"]["diagnostic_snapshot"] = diagnostic_snapshot(
        _snapshot(result["test_id"])
    )
    facts = evidence_facts(result)
    assert any("default via 10.0.0.1" in row["value"] for row in facts)
    assert any("LISTEN" in row["value"] for row in facts)
    assert any(
        "ACTIVE; addresses 10.0.0.2; bound to compute2" in row["value"] for row in facts
    )
    assert "later snapshot, not a packet trace" in facts[-1]["value"]


def test_offline_snapshot_is_matched_by_test_id_and_does_not_rewrite_contract(tmp_path):
    result = _failure()
    result["details"]["diagnostic_directory"] = "/untrusted/absolute/path"
    payload = {"results": [result]}
    original = copy.deepcopy(payload)
    directory = tmp_path / "failures" / unique_safe_name(result["test_id"], 120)
    directory.mkdir(parents=True)
    snapshot = _snapshot(result["test_id"])
    (directory / "diagnostics.json").write_text(json.dumps(snapshot))
    (directory / "destination.txt").write_text(
        snapshot["guests"]["destination"]["output"]
    )
    enriched = with_diagnostic_artifacts(payload, tmp_path)
    assert (
        enriched["results"][0]["operator_diagnostics"]["test_id"] == result["test_id"]
    )
    assert enriched["results"][0]["details"] == original["results"][0]["details"]
    assert payload == original
    snapshot["test"] = "DIFFERENT-TEST"
    (directory / "diagnostics.json").write_text(json.dumps(snapshot))
    assert (
        "operator_diagnostics"
        not in with_diagnostic_artifacts(payload, tmp_path)["results"][0]
    )


@pytest.mark.parametrize("symlink_target", ["directory", "file", "guest"])
def test_report_loader_never_follows_diagnostic_symlinks(tmp_path, symlink_target):
    result = _failure()
    result["details"]["diagnostic_directory"] = "/not-used"
    directory = tmp_path / "failures" / unique_safe_name(result["test_id"], 120)
    directory.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    snapshot = _snapshot(result["test_id"])
    secret = "DO NOT EMBED THIS FILE"
    (outside / "secret").write_text(secret)
    (outside / "diagnostics.json").write_text(json.dumps(snapshot))
    if symlink_target == "directory":
        directory.rmdir()
        directory.symlink_to(outside, target_is_directory=True)
    elif symlink_target == "file":
        (directory / "diagnostics.json").symlink_to(outside / "diagnostics.json")
    else:
        (directory / "diagnostics.json").write_text(json.dumps(snapshot))
        (directory / "destination.txt").symlink_to(outside / "secret")
    output = with_diagnostic_artifacts({"results": [result]}, tmp_path)
    assert secret not in json.dumps(output)


def test_missing_diagnostics_are_explicit_not_silently_assumed_healthy(tmp_path):
    result = _failure()
    result["details"]["diagnostic_directory"] = "/missing"
    row = with_diagnostic_artifacts({"results": [result]}, tmp_path)["results"][0]
    story = explain_result(row)
    assert any("could not be embedded" in line for line in story["limitations"])


def test_snapshot_bound_and_failed_collection_are_visible():
    snapshot = diagnostic_snapshot(
        {
            "guests": {
                "source": {
                    "usable": False,
                    "error": "SSH unavailable",
                    "output": "x" * 20000,
                }
            }
        }
    )
    assert snapshot["guests"]["source"]["output"].endswith("[truncated]")
    facts = evidence_facts({"details": {"diagnostic_snapshot": snapshot}})
    assert any(row["value"] == "SSH unavailable" for row in facts)


def test_missing_guest_transcript_is_reported_as_an_evidence_gap(tmp_path):
    result = _failure()
    result["details"]["diagnostic_directory"] = "/old-run-location"
    directory = tmp_path / "failures" / unique_safe_name(result["test_id"], 120)
    directory.mkdir(parents=True)
    snapshot = _snapshot(result["test_id"])
    snapshot["guests"]["destination"].pop("output")
    (directory / "diagnostics.json").write_text(json.dumps(snapshot))
    enriched = with_diagnostic_artifacts({"results": [result]}, tmp_path)
    story = explain_result(enriched["results"][0])
    assert any(
        "Saved guest transcript is unavailable" in row["value"]
        for row in story["facts"]
    )


def test_lifecycle_problems_are_explained_without_test_rows():
    issues = lifecycle_explanations(
        {
            "error": "openstack image show failed: discovery timeout",
            "setup_failures": [{"message": "Controller SSH unavailable"}],
            "cleanup": {
                "complete": False,
                "leftovers": [{"type": "port", "id": "port-1"}],
                "errors": ["Port is still in use"],
            },
        }
    )
    assert len(issues) == 3
    assert "discovery timeout" in issues[0]["what_happened"]
    assert "port-1" in issues[2]["what_happened"]
    assert all(issue["next_check"] for issue in issues)


def test_all_report_formats_carry_the_same_failed_step():
    payload = _payload()
    result = _failure()
    result["details"]["diagnostic_snapshot"] = diagnostic_snapshot(
        _snapshot(result["test_id"])
    )
    payload["results"] = [result]
    payload["run"]["final_status"] = "FAIL"
    payload["summary"].update(counts={"FAIL": 1}, total_results=1)
    payload["dashboard"] = build_dashboard_model(payload)
    original = copy.deepcopy(payload)
    outputs = [
        render_results_text(payload),
        render_incident_summary(payload),
        build_junit(payload, include_evidence=False),
    ]
    html = render_html(payload)
    embedded = _embedded_payload(html)
    story = embedded["dashboard"]["results"][0]["operator_explanation"]
    assert "MTU and fragmentation were not measured" in story["why_this_status"]
    assert all(
        "MTU and fragmentation were not measured" in output for output in outputs
    )
    assert all("default via 10.0.0.1" in output for output in outputs)
    assert (
        embedded["dashboard"]["findings"][0]["operator_cases"][0]["explanation"]["kind"]
        == "connection-failed"
    )
    assert ET.fromstring(outputs[-1]).find("testcase/failure") is not None
    assert payload == original


def test_collector_embeds_diagnostics_for_future_reports(tmp_path):
    builder = SimpleNamespace(
        ssh_endpoint=Mock(
            return_value=SimpleNamespace(
                stdout="### sockets\ntcp LISTEN 0 64 0.0.0.0:18080 0.0.0.0:*\n",
                stderr="",
                returncode=0,
            )
        ),
        osc=SimpleNamespace(json=Mock(return_value={"status": "ACTIVE"})),
    )
    endpoint = SimpleNamespace(
        label="VM A",
        server_id="vm-a",
        management_ip="10.0.0.1",
        test_port_id="port-a",
        management_port_id=None,
    )
    probe = SimpleNamespace(
        outcome="blocked",
        command="probe",
        stdout="",
        stderr="timed out",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        protocol="TCP",
        elapsed_ms=5000,
        attempts=1,
    )
    collector = DiagnosticCollector(builder, SimpleNamespace(run_dir=tmp_path))
    _classification, details = collector.collect(
        SimpleNamespace(id="TEST", category="same-subnet"), probe, endpoint, None
    )
    assert "LISTEN" in details["diagnostic_snapshot"]["guests"]["source"]["output"]
    assert details["diagnostic_snapshot"]["resources"][0]["status"] == "ACTIVE"


def test_local_pmtu_constraint_and_unexpected_reachability_are_distinct():
    mtu = explain_result(
        {"status": "UNVERIFIED", "observed": "local-mtu-rejected", "details": {}}
    )
    assert mtu["kind"] == "local-mtu-limit"
    isolation = explain_result(
        {
            "status": "FAIL",
            "expected": "blocked",
            "observed": "reachable",
            "details": {},
        }
    )
    assert isolation["kind"] == "isolation-failed"


def test_non_connect_probe_phases_and_migration_followups():
    result = _failure()
    result["details"]["tcp_baseline"]["diagnostics"].update(
        failure_phase="receive", error_type="OSError"
    )
    assert "return route" in explain_result(result)["next_check"]
    result["details"]["tcp_baseline"]["diagnostics"]["failure_phase"] = "socket-create"
    assert "source address/interface" in explain_result(result)["next_check"]
    result.update(category="compute-placement")
    assert "Nova migration record" in explain_result(result)["next_check"]


def test_javascript_report_runs_all_views_and_reason_filter(tmp_path):
    """Execute the real script with a small DOM stub; no claim of visual QA."""
    payload = _payload()
    payload["results"] = [_failure()]
    payload["run"]["final_status"] = "FAIL"
    payload["summary"].update(counts={"FAIL": 1}, total_results=1)
    report = tmp_path / "report.html"
    report.write_text(render_html(payload))
    runner = Path(__file__).with_name("report_dom_check.js")
    completed = subprocess.run(
        ["node", str(runner), str(report), DISPLAY_VERSION],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "report checks passed" in completed.stdout


def test_migration_observation_report_badges_measurements_and_note(tmp_path):
    payload = _payload()
    payload["results"] = [_observation_pass()]
    payload["summary"].update(counts={"PASS": 1}, total_results=1)
    report = tmp_path / "migration-observation-report.html"
    report.write_text(render_html(payload))
    runner = Path(__file__).with_name("report_dom_check.js")
    completed = subprocess.run(
        ["node", str(runner), str(report), DISPLAY_VERSION],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "migration observation checks passed" in completed.stdout


def _readable_flow(operation, category, expected, observed):
    return {
        "test_id": "HUMAN-CONTEXT",
        "status": "PASS",
        "category": category,
        "source": "Provider Public:A (192.0.2.10)",
        "destination": "Private IPv4 translation through Public:B (10.0.0.20)",
        "family": 4,
        "expected": expected,
        "observed": observed,
        "message": "Legacy technical wording remains in the record",
        "details": {
            "operation": operation,
            "protocol": "tcp",
            # This old grouping label is deliberately inconsistent with hosts.
            "phase": "intra",
            "pair_placement_policy": "initial-opposite-v1",
            "pair_placement": "initial",
            "source_compute_host": "compute-a",
            "destination_compute_host": "compute-b",
            "source_availability_zone": "az-a",
            "destination_availability_zone": "az-a",
            "address_path": {
                "source": {
                    "fixed_ip": "192.0.2.10",
                    "probe_address": "192.0.2.10",
                    "network_name": "Public",
                },
                "destination": {
                    "fixed_ip": "10.0.0.20",
                    "floating_ip": "192.0.2.20",
                    "probe_address": "192.0.2.20",
                },
            },
            "probe": {
                "diagnostics": {
                    "connected": observed == "reachable",
                    "echo_validated": observed == "reachable",
                    "converged": True,
                    "achieved_consecutive": 3 if observed == "blocked" else 2,
                }
            },
        },
    }


@pytest.mark.parametrize(
    "operation,category,expected,observed,reason",
    [
        (
            "security-deny",
            "security-group",
            "blocked",
            "blocked",
            "No security-group rule allows",
        ),
        (
            "security-allow",
            "security-group",
            "reachable",
            "reachable",
            "temporary security-group rule allows",
        ),
        (
            "security-restore",
            "security-group",
            "blocked",
            "blocked",
            "allow rule has been removed",
        ),
        (
            "server-stop",
            "server-lifecycle",
            "withdrawn",
            "blocked",
            "destination VM is stopped",
        ),
        (
            "server-start",
            "server-lifecycle",
            "restored",
            "reachable",
            "destination VM has restarted",
        ),
        (
            "static-route-baseline",
            "router-static-routing",
            "blocked",
            "blocked",
            "do not yet have the static routes",
        ),
        (
            "static-route-install",
            "router-static-routing",
            "reachable",
            "reachable",
            "static routes have been added",
        ),
        (
            "static-route-withdraw",
            "router-static-routing",
            "withdrawn",
            "blocked",
            "static route has been removed",
        ),
        (
            "static-route-restore",
            "router-static-routing",
            "restored",
            "reachable",
            "static route has been restored",
        ),
        (
            "fip-withdraw",
            "floating-ip-lifecycle",
            "withdrawn",
            "blocked",
            "floating IP has been detached",
        ),
        (
            "fip-return",
            "floating-ip-lifecycle",
            "restored",
            "reachable",
            "floating IP has been reattached",
        ),
    ],
)
def test_every_config_change_has_full_context_and_an_explicit_pass_reason(
    operation, category, expected, observed, reason
):
    result = _readable_flow(operation, category, expected, observed)
    # Historical withdrawal rows retained the original path's positive
    # reachability reason. The negative expectation must follow the actual action.
    result["details"]["expectation_reason"] = (
        "the source and floating IP occupy the provider subnet"
    )
    original = copy.deepcopy(result)
    story = explain_result(result)
    rendered = "\n".join(explanation_lines(result))
    assert reason in story["expected"]
    assert "Purpose:" in rendered and "Path:" in rendered
    assert "compute-a" in rendered and "compute-b" in rendered
    assert "different compute hosts" in rendered
    assert (
        "192.0.2.10" in rendered
        and "192.0.2.20" in rendered
        and "10.0.0.20" in rendered
    )
    assert "Before migration" in rendered
    assert "Expected result:" in rendered and "Actual result:" in rendered
    assert "Why this passed:" in rendered
    assert "recorded check met its expectation" not in rendered
    assert "source and floating IP occupy" not in story["expected"]
    if observed == "blocked":
        assert "connection did not open" in story["observed"]
        assert "deliberately unavailable" in story["why_this_status"]
    else:
        assert "returned the correct test data" in story["observed"]
    assert result == original


def test_udp_success_explains_validated_application_reply():
    result = _readable_flow("probe", "same-subnet", "reachable", "reachable")
    result["details"]["protocol"] = "udp"
    result["details"]["probe"]["diagnostics"] = {
        "request_sent": True,
        "response_received": True,
        "response_validated": True,
    }
    assert (
        "UDP listener returned the correct test data"
        in explain_result(result)["observed"]
    )


def test_ordinary_pass_after_migration_has_complete_context_without_baseline_jargon():
    result = _readable_flow("probe", "same-subnet", "reachable", "reachable")
    result["details"].update(
        pair_placement="opposite", placement_origin="after-transition"
    )
    story = explain_result(result)
    rendered = "\n".join(explanation_lines(result))
    assert "After placement transition" in rendered
    assert "different compute hosts" in rendered
    assert "initial" not in rendered.lower() and "opposite" not in rendered.lower()
    assert story["headline"] == "TCP connectivity confirmed"


def test_unrun_context_is_planned_and_never_claims_a_successful_probe():
    result = _readable_flow(
        "fip-withdraw", "floating-ip-lifecycle", "withdrawn", "blocked"
    )
    result.update(
        status="BLOCKED_BY_SETUP_ERROR", message="Destination VM could not be created"
    )
    story = explain_result(result)
    rendered = "\n".join(explanation_lines(result))
    assert "Planned condition:" in rendered
    assert "did not run" in rendered.lower()
    assert "connection did not open" not in story["what_happened"]
    assert "could not execute this check" in story["why_this_status"]
    assert story["recorded_message"] == result["message"]


@pytest.mark.parametrize(
    "measurement,metrics,expected_value",
    [
        (
            "tcp-throughput",
            {
                "forward": {"streams": {"1": {"median_mbps": 1234.5}}},
                "reverse": {"streams": {"1": {"median_mbps": 998.2}}},
            },
            "1,234.5 Mbps",
        ),
        (
            "latency",
            {
                "idle": {"forward": {"p95_ms": 1.25}},
                "loaded": {"forward": {"p95_ms": 2.75}},
            },
            "2.75 ms",
        ),
        (
            "udp",
            {
                "comparison": {
                    "forward": [
                        {"load_valid": True, "endpoint_limited": False, "loss_pct": 0.5}
                    ]
                }
            },
            "0.5 %",
        ),
        (
            "mtu-mss",
            {
                "forward": {
                    "discovered_mtu": 1500,
                    "client_mss": 1448,
                    "server_mss": 1448,
                }
            },
            "1,448 bytes",
        ),
        (
            "asymmetry",
            {"throughput_difference_pct": 3.5, "udp_loss_difference_pct_points": 0.25},
            "0.25 percentage points",
        ),
        (
            "concurrency",
            {"forward": {"aggregate_mbps_by_stream_count": {"1": 1000, "4": 1100}}},
            "1,100 Mbps",
        ),
        ("repeatability", {"forward_variation_pct": 2.5}, "2.5 %"),
    ],
)
def test_measurement_pass_explains_direction_units_and_what_pass_certifies(
    measurement, metrics, expected_value
):
    result = _readable_flow(
        "", "network-performance", "profile-recorded", "profile-measured"
    )
    result["details"].update(
        measurement=measurement, metrics=metrics, thresholds_enforced=False
    )
    original = copy.deepcopy(result)
    story = explain_result(result)
    assert expected_value in story["observed"]
    assert "required measurement completed successfully" in story["why_this_status"]
    assert "path, VM placement and test load" in story["why_this_status"]
    assert "Expected behaviour observed" != story["headline"]
    assert result == original


def test_migration_summary_identifies_the_moved_vm_and_all_completion_components():
    result = _observation_pass()
    result["details"]["transitions"][0].update(
        endpoint="Private VM A",
        source_host="compute-b",
        destination_host="compute-a",
        confirmed=True,
    )
    original = copy.deepcopy(result)
    story = explain_result(result)
    assert "Private VM A moved from compute-b to compute-a" in story["what_happened"]
    assert "TCP connection stayed established" in story["observed"]
    assert "traffic recovered after the move" in story["observed"]
    assert "migration completion was verified" in story["observed"]
    assert "[OBSERVATION] Above tolerance" in story["what_happened"]
    assert result == original


def test_related_migration_evidence_is_used_only_for_display_and_keeps_the_raw_row():
    parent = _observation_pass()
    result = {
        "test_id": "HISTORICAL-SUPPORT-ROW",
        "category": "compute-placement",
        "status": "PASS",
        "expected": "placement-achieved",
        "observed": "migration-assessed",
        "message": "Legacy raw component booleans and measurements",
        "details": {"check_sample": True, "transition_check_id": "EXACT-PARENT-ID"},
        "reporting_context": {
            "related_transitions": copy.deepcopy(parent["details"]["transitions"]),
            "evidence_source_result_id": "EXACT-PARENT-ID",
        },
    }
    original = copy.deepcopy(result)
    story = explain_result(result)
    assert "TCP connection stayed established" in story["observed"]
    assert "traffic recovered" in story["observed"]
    assert story["kind"] == "migration-interruption-observation"
    assert story["recorded_message"] == result["message"]
    assert result == original


def test_fragmentation_pass_preserves_guest_attribution_and_packet_size():
    result = _readable_flow(
        "",
        "floating-ip-egress-fragmentation",
        "fragmentation-behaviour-classified",
        "fragmentation-supported",
    )
    result["details"].update(
        fragmentation_profile={
            "tested_packet_size": 8942,
            "capability": "supported",
            "fragmentation_location_label": "Source guest fragmented the packet",
        }
    )
    story = explain_result(result)
    assert "8,942 bytes" in story["observed"]
    assert "Source guest fragmented" in story["observed"]
    assert "router fragmented" not in story["observed"].lower()


def test_mtu_boundary_summary_keeps_local_rejection_distinct_from_a_network_drop():
    result = _readable_flow("", "mtu", "mtu-behavior-assessed", "boundary-confirmed")
    result["message"] = (
        "The 1500-byte packet arrived; the source rejected the 1501-byte packet locally before transmission."
    )
    result["details"]["network_mtu"] = 1500
    story = explain_result(result)
    assert "source rejected" in story["observed"]
    assert "before transmission" in story["observed"]
    assert "network dropped" not in story["observed"]
    assert "advertised-size packet arrived" in story["why_this_status"]
    assert "larger-packet check completed" in story["why_this_status"]
