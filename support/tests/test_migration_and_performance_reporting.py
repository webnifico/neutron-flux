from __future__ import annotations

import copy
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.errors import SuiteError
from neutron_flux.performance import PerformanceRunner
from neutron_flux.reporting_components.dashboard_model import build_dashboard_model
from neutron_flux.reporting_components.html import render_html
from neutron_flux.reporting_components.summary import SummaryRendererMixin
from neutron_flux.resources import ResourceBuilder
from neutron_flux.result_contract import normalize_result_record
from support.tests.test_diagnostics_and_measurement_classification import (
    _resolved_path,
    _spec,
)
from support.tests.test_report_workflow import _embedded_payload, _payload


@pytest.mark.parametrize("status,expected", [("completed", True), ("error", False)])
def test_completed_migration_uses_list_evidence(config_factory, status, expected):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder._migration_rows = lambda server_id: (
        [
            {
                "Id": 5941,
                "Source Compute": "hyper002",
                "Dest Compute": "hyper001",
                "Type": "live-migration",
                "Status": status,
            }
        ],
        None,
    )
    builder._json_with_transient_retry = mock.Mock(
        side_effect=SuiteError("completed migration is not available from show")
    )
    verified, error, row = builder._verify_nova_migration_record(
        SimpleNamespace(server_id="server-1", label="moving endpoint"),
        "hyper002",
        "hyper001",
        {"5940"},
        expected_types={"live-migration"},
    )
    assert verified is expected
    assert bool(error) is (not expected)
    assert row["Id"] == 5941
    builder._json_with_transient_retry.assert_not_called()


def _performance_payload():
    payload = _payload()
    result = payload["results"][0]
    result.update(
        category="network-performance",
        status="UNVERIFIED",
        test_id="PERF-HQ-ASYMMETRY",
        display_name="Directional asymmetry",
        expected="directional-balance-recorded",
        observed="directional-balance-evidence-incomplete",
        message="UDP application-delivery loss difference 0%; directional comparison incomplete",
    )
    result["details"].update(
        performance=True,
        measurement="asymmetry",
        health="unverified",
        metrics={"udp_compared_profiles": 5, "udp_unmatched_profiles": 2},
    )
    result["details"]["path"].update(
        source_spec_id="HQ-SOURCE", stage="host-qualification"
    )
    payload["plan"] = {
        "tests": [
            {
                "id": "HQ-SOURCE",
                "metadata": {
                    "host_qualification": True,
                    "host_qualification_pair_id": "HQ-1-2",
                    "host_qualification_cycle": 1,
                    "requested_source_host": "compute1",
                    "requested_destination_host": "compute2",
                },
            }
        ],
        "host_qualification": {
            "enabled": True,
            "pairs": [
                {
                    "pair_id": "HQ-1-2",
                    "source_host": "compute1",
                    "destination_host": "compute2",
                    "same_availability_zone": True,
                    "status": "PLANNED",
                }
            ],
        },
    }
    payload.pop("dashboard", None)
    return payload


def test_directional_comparison_is_not_a_udp_loss_finding():
    model = build_dashboard_model(_performance_payload())
    assert model["findings"][0]["root_key"] == "direction"
    assert "matching" in model["findings"][0]["summary"].lower()


def test_target_pair_includes_its_performance_results_without_changing_raw_data():
    payload = _performance_payload()
    payload["results"] = [normalize_result_record(row) for row in payload["results"]]
    original = copy.deepcopy(payload)
    model = build_dashboard_model(payload)
    pair = model["host_qualification"]["pairs"][0]
    assert pair["status_counts"] == {"UNVERIFIED": 1}
    assert pair["finding_count"] == 1
    assert payload == original


def test_cached_older_dashboard_is_rebuilt_with_host_scope():
    payload = _performance_payload()
    payload["dashboard"] = {"model_version": 6, "report_shape_version": 4}
    report = _embedded_payload(render_html(payload))["dashboard"]
    assert report["host_scope"]["requested_pairs"] == ["compute1 ↔ compute2"]
    assert report["results"][0]["host_scope"]["requested_pair"] == "compute1 ↔ compute2"
    assert report["paths"][0]["host_scopes"][0]["code"] == "targeted"
    assert report["results"][0]["zones"] == ["zone-a"]


def test_post_migration_scope_keeps_requested_pair_and_observed_same_host():
    payload = _performance_payload()
    path = payload["results"][0]["details"]["path"]
    path.update(stage="post-live-migration", destination_compute_host="compute1")
    report = _embedded_payload(render_html(payload))["dashboard"]
    scope = report["results"][0]["host_scope"]
    assert scope == {
        "code": "post-migration",
        "label": "Targeted pair after migration",
        "requested_pair": "compute1 ↔ compute2",
        "observed_pair": "compute1 → compute1",
    }


def test_unreferenced_performance_is_not_assigned_to_a_requested_pair():
    payload = _performance_payload()
    payload["results"][0]["details"]["path"].update(
        stage="group-local", source_spec_id="absent"
    )
    model = build_dashboard_model(payload)
    assert model["host_qualification"]["pairs"][0]["status_counts"] == {}
    assert model["results"][0]["host_scope"]["code"] == "general"


def test_performance_planning_and_recording_preserve_requested_pair(config_factory):
    reporter = mock.Mock()
    runner = PerformanceRunner(
        config_factory(action="run", performance_enabled=True),
        SimpleNamespace(),
        reporter,
        SimpleNamespace(),
    )
    path = _resolved_path()
    source = _spec(path.plan.source_spec_id)
    source.metadata = {
        "host_qualification_pair_id": "HQ-1-2",
        "host_qualification_cycle": 3,
        "requested_source_host": "compute1",
        "requested_destination_host": "compute2",
    }
    runner._select_paths = lambda specs, stage: [path.plan]
    specs = runner.plan_specs(iter([source]), stage="host-qualification")
    spec = next(
        spec
        for spec in specs
        if spec.metadata["performance_measurement"] == "tcp-throughput"
    )
    runner._record_measurement(spec, path, {"health": "good", "metrics": {}}, started=0)
    details = reporter.result.call_args.kwargs["details"]
    assert details["host_qualification_pair_id"] == "HQ-1-2"
    assert details["host_qualification_cycle"] == 3
    assert details["requested_source_host"] == "compute1"
    assert details["path"]["source_compute_host"] == path.source.host


@pytest.mark.parametrize(
    "category,measurement,root",
    [
        ("network-performance", "latency", "latency"),
        ("compute-placement", "", "migration"),
    ],
)
def test_finding_type_is_not_overridden_by_udp_words(category, measurement, root):
    payload = _performance_payload()
    result = payload["results"][0]
    result.update(
        category=category, status="FAIL", message="TCP continuity failed; UDP loss 0%"
    )
    result["details"]["measurement"] = measurement
    assert build_dashboard_model(payload)["findings"][0]["root_key"] == root


def test_snat_connect_timeout_is_not_presented_as_an_mtu_failure():
    payload = _payload()
    result = payload["results"][0]
    result.update(
        category="source-nat-packet-size",
        status="FAIL",
        display_name="Router SNAT packet-size and fragmentation profile",
        expected="profile-complete",
        observed="source-nat-provider-observer-failed",
    )
    result["details"].update(
        egress_translation_mode="router-source-nat",
        mtu_profile=None,
        tcp_baseline={
            "success": False,
            "attempts": 1,
            "diagnostics": {
                "failure_phase": "connect",
                "error_type": "TimeoutError",
                "destination_port": 18080,
                "connected": False,
            },
        },
    )
    payload.pop("dashboard", None)
    report = _embedded_payload(render_html(payload))["dashboard"]
    finding = report["findings"][0]
    assert "TCP connection" in finding["title"]
    assert "not measured" in finding["impact"]
    assert "cause" in finding["evidence_summary"].lower()
    assert "18080" in report["results"][0]["observed"]


def test_zone_summary_counts_performance_and_explicitly_accounts_for_unknowns():
    renderer = SummaryRendererMixin()
    renderer.config = SimpleNamespace(availability_zones=[])
    renderer.plan = None
    renderer.results = [
        SimpleNamespace(
            details={
                "path": {
                    "source_availability_zone": "zone-a",
                    "destination_availability_zone": "zone-a",
                }
            },
            category="network-performance",
            status="PASS",
            test_id="PERF-1",
        ),
        SimpleNamespace(
            details={},
            category="controller-bootstrap",
            status="PASS",
            test_id="CONTROL",
        ),
    ]
    lines = []
    renderer._append_zone_summary(lines, 120)
    assert any(line.startswith("zone-a ") and line.split()[-1] == "1" for line in lines)
    assert any("Run scope / AZ not recorded" in line for line in lines)
