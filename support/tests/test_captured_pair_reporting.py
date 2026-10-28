from __future__ import annotations

import copy
import dataclasses
import datetime as dt
import json
from collections import Counter
from pathlib import Path

from neutron_flux.models import HostQualificationPlan, Plan
from neutron_flux.models import TestResult as FluxResult
from neutron_flux.models import TestSpec as FluxSpec
from neutron_flux.operator_explanations import explain_result
from neutron_flux.report_exports import render_incident_summary
from neutron_flux.reporting import Reporter
from neutron_flux.reporting_components.html import build_run_payload
from neutron_flux.reporting_components.operator_context import contextual_results
from neutron_flux.result_context import result_context


def _capture():
    return json.loads(
        Path(__file__)
        .with_name("fixtures")
        .joinpath("captured_pair_reporting_context.json")
        .read_text()
    )


def _reporter(config_factory, tmp_path):
    capture = _capture()
    reporter = Reporter(config_factory(report_dir=tmp_path / "reports"), "capture")
    reporter.results = [FluxResult(**row) for row in capture["results"]]
    reporter.plan = Plan(
        [],
        [],
        {},
        [],
        tests=[FluxSpec(**row) for row in capture["plan"]["tests"]],
        host_qualification=HostQualificationPlan(
            enabled=True,
            generated_at=None,
            inventory_fingerprint=None,
            strategy="rolling",
            profile="full",
            cycles=1,
            include_same_host=False,
        ),
    )
    return reporter, capture


def test_runtime_summary_joins_the_captured_monitored_path_and_safety_samples(
    config_factory, tmp_path
):
    reporter, capture = _reporter(config_factory, tmp_path)
    original = copy.deepcopy(reporter.results)
    rows = reporter._presentation_results()
    migration = rows["PAIR-TRANSITION-a1c13d7c62e9da96-opposite"]
    context = result_context(migration)
    assert context["family"] == "IPv4"
    assert "Provider One VM B" in context["action"]
    assert context["source"]["compute_host"] == "compute-c"
    assert context["destination"]["compute_host"] == "compute-d"
    assert context["after_placement"] == "Both VMs on compute-c (same compute host)"
    assert (
        "Stationary peer's recorded compute host: Provider One VM A on compute-c"
        in context["lines"]
    )
    baseline = next(
        row
        for row in rows.values()
        if row["test_id"].startswith("PLACEMENT-MIGRATION-FUNCTIONAL-BASELINE")
    )
    context = result_context(baseline)
    assert context["family"] == "IPv4 and IPv6"
    assert "different compute hosts" in context["placement"]
    assert "Compute hosts were not recorded" not in context["placement"]
    assert reporter.results == original
    assert [row["details"] for row in rows.values()] == [
        row["details"] for row in capture["results"]
    ]


def test_captured_post_performance_has_the_same_timing_in_summary_and_saved_explanation(
    config_factory, tmp_path
):
    reporter, _capture_payload = _reporter(config_factory, tmp_path)
    before = copy.deepcopy(reporter.results)
    payload = build_run_payload(
        reporter,
        final_status="PASS",
        finished=dt.datetime.now(dt.timezone.utc),
        counts=Counter(row.status for row in reporter.results),
        include_dashboard=False,
    )
    presentation = reporter._presentation_results()
    for row in reporter.results:
        if row.category != "network-performance":
            continue
        expected = (
            "After migration"
            if row.details["pair_placement"] == "opposite"
            else "Before migration"
        )
        assert result_context(presentation[row.test_id])["timing"] == expected
        assert (
            payload["operator_report"]["results"][row.test_id]["context"]["timing"]
            == expected
        )
    assert reporter.results == before
    assert payload["results"] == [dataclasses.asdict(row) for row in before]


def test_captured_self_hairpin_identifies_stationary_owner_and_moving_peer():
    payload = _capture()
    original = copy.deepcopy(payload)
    rows = contextual_results(payload)
    hairpins = [row for row in rows if row["details"].get("nat_path") == "self-hairpin"]
    assert len(hairpins) == 4
    after = [
        row for row in hairpins if result_context(row)["timing"] == "After migration"
    ]
    stories = [" ".join(result_context(row)["lines"]) for row in after]
    assert any(
        "this self-hairpin VM stayed on compute-c" in story
        and "Private VM B moved from compute-d to compute-c" in story
        for story in stories
    )
    assert any(
        "This self-hairpin VM moved from compute-d to compute-c" in story
        for story in stories
    )
    assert payload == original


def test_captured_external_egress_identifies_stationary_source_without_host_for_target():
    rows = contextual_results(_capture())
    after = next(
        row
        for row in rows
        if row["category"] == "egress"
        and result_context(row)["timing"] == "After migration"
    )
    context = result_context(after)
    assert context["destination"]["compute_host"] is None
    assert (
        "Provider One VM B moved from compute-d to compute-c; this source VM stayed on compute-c"
        in " ".join(context["lines"])
    )


def test_safety_summary_accepts_external_egress_source_and_cloud_peer_paths():
    payload = _capture()
    rows = contextual_results(payload)
    baseline = next(
        row
        for row in rows
        if row["test_id"].startswith("PLACEMENT-MIGRATION-FUNCTIONAL-BASELINE")
    )
    external = next(row for row in rows if row["category"] == "egress")
    baseline["reporting_context"]["supporting_paths"].append(external)
    context = result_context(baseline)
    assert "different compute hosts" in context["placement"]
    assert "external destinations have no Flux compute host" in context["placement"]


def test_incident_summary_rebuilds_context_from_plan_and_sibling_records():
    payload = _capture()
    baseline = next(
        row
        for row in payload["results"]
        if row["test_id"].startswith("PLACEMENT-MIGRATION-FUNCTIONAL-BASELINE")
    )
    baseline["status"] = "FAIL"
    text = render_incident_summary(payload)
    assert "Checked path: Provider One VM A" in text
    assert "Traffic: ICMP, TCP and UDP over IPv4 and IPv6" in text


def test_missing_or_conflicting_migration_identity_does_not_claim_stationary_owner():
    payload = _capture()
    payload["results"] = [
        row for row in payload["results"] if row["category"] != "compute-placement"
    ]
    for row in contextual_results(payload):
        if row["details"].get("nat_path") == "self-hairpin":
            assert not any(
                line.startswith("Migration scope:")
                for line in result_context(row)["lines"]
            )


def test_live_projection_does_not_serialize_unrelated_heavy_evidence(
    config_factory, tmp_path
):
    reporter, _payload = _reporter(config_factory, tmp_path)

    class UnrelatedEvidence:
        def __deepcopy__(self, memo):
            raise AssertionError("unrelated evidence was serialized")

    unrelated = copy.copy(reporter.results[0])
    unrelated.test_id = "UNRELATED-HEAVY-RESULT"
    unrelated.details = {"metrics": UnrelatedEvidence()}
    reporter.results.append(unrelated)
    unused_spec = copy.copy(reporter.plan.tests[0])
    unused_spec.id = "UNRELATED-HEAVY-SPEC"
    unused_spec.metadata = {"metrics": UnrelatedEvidence()}
    reporter.plan.tests.append(unused_spec)
    for row in reporter.results[:-1]:
        projection = reporter._presentation_result(row)
        context = result_context(projection)
        if row.test_id == "PAIR-TRANSITION-a1c13d7c62e9da96-opposite":
            assert (
                context["after_placement"]
                == "Both VMs on compute-c (same compute host)"
            )
        if (
            row.category == "network-performance"
            and row.details["pair_placement"] == "opposite"
        ):
            assert context["timing"] == "After migration"
        assert projection["details"] is row.details


def test_live_resolution_projection_follows_exact_planner_binding(
    config_factory, tmp_path
):
    reporter, _payload = _reporter(config_factory, tmp_path)
    spec = reporter.plan.tests[0]
    spec.metadata = {
        **spec.metadata,
        "check_bindings": {"placement": {"HOST-DISCOVERY": "DISCOVERY-RESOLUTION"}},
    }
    reporter.plan.checks = [{"id": "DISCOVERY-RESOLUTION", "stage": "migration"}]
    result = FluxResult(
        test_id="DISCOVERY-RESOLUTION",
        category="compute-placement",
        status="PASS",
        family=None,
        source=None,
        destination=None,
        message="Resolution recorded",
        started_at="",
        duration_ms=0,
        details={"planned_check_id": "DISCOVERY-RESOLUTION", "resolution_only": True},
    )

    projection = reporter._presentation_result(result)

    assert result_context(projection)["timing"] == "Initial placement discovery"
    assert projection["details"] is result.details


def test_recorded_endpoint_recreation_is_never_labeled_as_migration():
    payload = _capture()
    transition = next(
        row
        for row in payload["results"]
        if row["test_id"] == "PAIR-TRANSITION-a1c13d7c62e9da96-opposite"
    )
    transition["details"]["transitions"] = [
        {
            "method": "endpoint-recreation",
            "source_host": "compute-d",
            "destination_host": "compute-c",
        }
    ]
    rows = contextual_results(payload)
    recreated = next(row for row in rows if row["test_id"] == transition["test_id"])
    context = result_context(recreated)
    assert context["timing"] == "During endpoint recreation"
    assert context["test"] == "Recreate one endpoint and verify its compute placement"
    assert "migration" not in context["path"].lower()
    assert not any(line.startswith("VM move:") for line in context["lines"])
    assert (
        explain_result(recreated)["headline"] == "Recreated endpoint placement verified"
    )
    after = next(
        row
        for row in rows
        if row["category"] == "network-performance"
        and row["details"]["pair_placement"] == "opposite"
    )
    assert result_context(after)["timing"] == "After endpoint recreation"
    # A different pair scope cannot borrow this transition's method.
    transition_spec = next(
        spec for spec in payload["plan"]["tests"] if spec["id"] == transition["test_id"]
    )
    transition_spec["metadata"]["host_qualification_pair_id"] = "OTHER-PAIR"
    after = next(
        row for row in contextual_results(payload) if row["test_id"] == after["test_id"]
    )
    assert result_context(after)["timing"] == "After placement transition"
