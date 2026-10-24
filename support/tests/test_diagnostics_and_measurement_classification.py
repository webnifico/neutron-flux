from __future__ import annotations

import copy
import dataclasses
import json
import subprocess
import types
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

from neutron_flux.diagnostics import DiagnosticCollector
from neutron_flux.errors import (
    DependentMeasurementUnavailable,
    PathReachabilityError,
    SuiteError,
)
from neutron_flux.execution.placement_migration import PlacementMigrationMixin
from neutron_flux.junit_report import build_junit
from neutron_flux.models import ProbeResult
from neutron_flux.models import TestSpec as FluxTestSpec
from neutron_flux.performance import (
    PerformancePath,
    PerformanceRunner,
    ResolvedPerformancePath,
)
from neutron_flux.performance_measurements import PerformanceMeasurementMixin
from neutron_flux.planner_components.estimates import performance_estimate
from neutron_flux.reporting import Reporter
from neutron_flux.reporting_components.dashboard_model import build_dashboard_model
from neutron_flux.reporting_components.html import build_run_payload
from neutron_flux.results_io import render_results_text

from ._shared import endpoint


def _spec(test_id: str, *, measurement: str | None = None) -> FluxTestSpec:
    return FluxTestSpec(
        id=test_id,
        category="network-performance" if measurement else "connectivity",
        operation=f"performance-{measurement}" if measurement else "probe",
        family=4,
        expectation="measurement-complete" if measurement else "reachable",
        expectation_reason="SAMPLE regression contract",
        authoritative=True,
        dependencies=["source", "destination"],
        source_group_id="source",
        destination_group_id="destination",
        source_side="A",
        destination_side="A",
        source_subnet_id="source-subnet",
        destination_subnet_id="destination-subnet",
        protocol="performance" if measurement else "tcp",
        metadata={
            "performance_measurement": measurement,
            "performance_path_id": "SAMPLE-PATH",
        }
        if measurement
        else {},
        display_name=test_id,
        scenario="Network path performance" if measurement else "Connectivity",
    )


def _resolved_path() -> ResolvedPerformancePath:
    source = endpoint("source")
    destination = dataclasses.replace(
        endpoint("destination"),
        server_id="server-destination",
        management_port_id="mgmt-destination",
        test_port_id="test-destination",
        management_ip="10.254.0.11",
        fixed_ips={"s4": "192.0.2.11"},
        host="compute2",
        availability_zone="az2",
    )
    return ResolvedPerformancePath(
        plan=PerformancePath(
            path_id="SAMPLE-PATH",
            source_spec_id="BASE-TCP",
            category="provider-network-connectivity",
            family=4,
            source_group_id="source",
            destination_group_id="destination",
            source_side="A",
            destination_side="A",
            source_subnet_id="source-subnet",
            destination_subnet_id="destination-subnet",
            stage="cross-zone",
            execution_scope="cross-zone",
        ),
        source=source,
        destination=destination,
        source_ip="192.0.2.10",
        destination_ip="192.0.2.11",
        source_mtu=1500,
        destination_mtu=1500,
        placement="different-host",
        availability_scope="cross-zone",
    )


def test_diagnostics_use_each_endpoint_controller_and_mark_stdio_failure(tmp_path):
    calls: list[tuple[str, str, str]] = []

    class Builder:
        def __init__(self, zone: str, *, fail: bool = False):
            self.availability_zone = zone
            self.fail = fail
            self.osc = SimpleNamespace(json=self._show)

        def ssh_endpoint(self, target, _command):
            calls.append((self.availability_zone, "ssh", target.server_id))
            if self.fail:
                return subprocess.CompletedProcess(
                    ["ssh"], 255, "", "stdio forwarding failed\n"
                )
            return subprocess.CompletedProcess(["ssh"], 0, "guest evidence\n", "")

        def _show(self, resource_type, _action, resource_id, **_kwargs):
            calls.append((self.availability_zone, resource_type, resource_id))
            return {"id": resource_id, "controller": self.availability_zone}

    source = dataclasses.replace(endpoint("source"), availability_zone="az1")
    destination = dataclasses.replace(
        endpoint("destination"),
        server_id="server-destination",
        management_port_id="mgmt-destination",
        test_port_id="test-destination",
        management_ip="10.254.0.11",
        availability_zone="az2",
    )
    source_builder = Builder("az1")
    destination_builder = Builder("az2", fail=True)
    collector = DiagnosticCollector(
        source_builder,
        SimpleNamespace(run_dir=tmp_path),
        endpoint_builders={destination.server_id: destination_builder},
    )
    likely, details = collector.collect(
        _spec("CROSS-ZONE-DIAGNOSTIC"),
        ProbeResult(
            outcome="blocked",
            success=False,
            elapsed_ms=1000,
            attempts=1,
            stderr="network is unreachable",
            protocol="tcp",
        ),
        source,
        destination,
    )

    failure_dir = Path(details["diagnostic_directory"])
    payload = json.loads((failure_dir / "diagnostics.json").read_text())
    assert likely == "ROUTING"
    assert details["diagnostic_classification"]["causal_claim"] is False
    assert ("az1", "ssh", source.server_id) in calls
    assert ("az2", "ssh", destination.server_id) in calls
    assert payload["guests"]["source"]["controller_scope"] == "az1"
    assert payload["guests"]["destination"]["controller_scope"] == "az2"
    assert payload["guests"]["destination"]["usable"] is False
    assert payload["guests"]["destination"]["status"] == "failed"
    destination_text = (failure_dir / "destination.txt").read_text()
    assert destination_text.startswith("NEUTRON FLUX DIAGNOSTIC COLLECTION FAILED")
    assert "stdio forwarding failed" in destination_text.lower()


def test_one_path_failure_is_fail_and_dependents_are_unverified(
    config_factory,
):
    reporter = Reporter(config_factory(action="run"), "sample-path-failure")
    runner = PerformanceRunner(
        reporter.config,
        SimpleNamespace(),
        reporter,
        SimpleNamespace(lifecycle={}),
    )
    path = _resolved_path()
    root = _spec("PERF-ROOT", measurement="tcp-throughput")
    dependents = [
        _spec("PERF-LATENCY", measurement="latency"),
        _spec("PERF-UDP", measurement="udp"),
    ]
    incident_reason = "No route to host"
    runner._record_measurement_error(
        root, path, PathReachabilityError(incident_reason), started=0.0
    )
    for spec in dependents:
        runner._record_measurement_error(
            spec,
            path,
            DependentMeasurementUnavailable(
                f"not run because the path was unreachable: {incident_reason}"
            ),
            started=0.0,
        )

    root_result = reporter.get_result(root.id)
    dependent_results = [reporter.get_result(spec.id) for spec in dependents]
    assert root_result is not None and root_result.status == "FAIL"
    assert root_result.details["failure_class"] == "network-path-unreachable"
    assert root_result.authoritative is True
    assert all(
        result is not None and result.status == "UNVERIFIED"
        for result in dependent_results
    )
    assert all(
        result.details["failure_class"] == "dependent-measurement"
        for result in dependent_results
        if result
    )
    assert {
        result.details["dependent_on_incident_id"]
        for result in dependent_results
        if result
    } == {root_result.details["root_incident_id"]}
    reporter.logger.close()


def test_non_routing_performance_errors_remain_errors():
    setup_error = SuiteError("performance server did not become ready")
    command_timeout = SuiteError("command timed out after 30 seconds")
    route_error = SuiteError("[Errno 101] Network is unreachable")

    assert (
        PerformanceMeasurementMixin._classify_measurement_exception(setup_error)
        is setup_error
    )
    assert (
        PerformanceMeasurementMixin._classify_measurement_exception(command_timeout)
        is command_timeout
    )
    classified = PerformanceMeasurementMixin._classify_measurement_exception(
        route_error
    )
    assert isinstance(classified, PathReachabilityError)


def _continuity(
    *, recovered: bool | None, tcp_survived: bool, icmp_loss: float, udp_loss: float
):
    from ._evidence import complete_continuity

    return complete_continuity(
        tcp_survived=tcp_survived,
        recovered=recovered,
        icmp_loss=icmp_loss,
        udp_loss=udp_loss,
        outage=2.0 if icmp_loss else 0.0,
        icmp_limit=0.0,
    )


def test_migration_loss_above_limits_is_observed_only_after_verified_recovery():
    status, observed, message, details = (
        PlacementMigrationMixin._live_continuity_verdict(
            _continuity(recovered=True, tcp_survived=True, icmp_loss=4.0, udp_loss=5.0)
        )
    )
    assert status == "PASS"
    assert observed == "traffic-continuity-measured"
    assert details["continuity_failure_reasons"] == []
    assert details["interruption_observations"] == details["tolerance_failure_reasons"]
    assert details["migration_outcomes"]["interruption_tolerance"] == "OBSERVATION"
    assert details["health"] == "warning"
    assert "exceeded" in message

    status, observed, _message, details = (
        PlacementMigrationMixin._live_continuity_verdict(
            _continuity(recovered=False, tcp_survived=True, icmp_loss=4.0, udp_loss=5.0)
        )
    )
    assert status == "FAIL"
    assert observed == "traffic-interrupted"
    assert details["interruption_observations"] == []
    assert any(
        "connectivity had not recovered" in item
        for item in details["continuity_failure_reasons"]
    )


def test_adaptive_udp_excludes_endpoint_limited_load_from_network_grading():
    runner = PerformanceRunner.__new__(PerformanceRunner)
    runner.config = SimpleNamespace(
        performance_udp_adaptive_calibration=True,
        performance_udp_calibration_min_rate_mbps=5,
        performance_udp_calibration_max_attempts=4,
        performance_udp_calibration_backoff_factor=0.5,
        performance_udp_sender_achievement_threshold_pct=90.0,
        performance_udp_loss_threshold_pct=1.0,
        performance_udp_reordering_threshold_pct=0.5,
    )

    def fake_udp(
        _self, _endpoint, _source, _destination, _family, rate, _size, **_kwargs
    ):
        if rate == 50:
            return {
                "mbps": 18.0,
                "sender_mbps": 20.0,
                "loss_pct": 64.0,
                "jitter_ms": 20.0,
                "pps": 1000,
                "receiver_drop_attribution": "not-observed",
                "receiver_socket_rxq_overflow": 0,
                "duplicates": 0,
                "reordered": 0,
                "received": 100,
            }
        return {
            "mbps": 24.5,
            "sender_mbps": 25.0,
            "loss_pct": 0.2,
            "jitter_ms": 0.4,
            "pps": 2400,
            "receiver_drop_attribution": "not-observed",
            "receiver_socket_rxq_overflow": 0,
            "duplicates": 0,
            "reordered": 0,
            "received": 1000,
        }

    runner._udp_measurement = types.MethodType(fake_udp, runner)
    samples = runner._adaptive_udp_samples(
        endpoint(), "192.0.2.10", "192.0.2.11", 4, 50, 128
    )

    assert [row["requested_mbps"] for row in samples] == [50, 25]
    assert samples[0]["endpoint_limited"] is True
    assert samples[0]["calibration_selected"] is False
    assert samples[1]["endpoint_limited"] is False
    assert samples[1]["calibration_selected"] is True
    assert samples[1]["calibration_selected_rate_mbps"] == 25
    assert runner._udp_health({"forward": samples}) == "good"


def test_mtu_probe_resets_and_verifies_route_cache_first():
    runner = PerformanceRunner.__new__(PerformanceRunner)
    events: list[str] = []

    def reset(_self, *_args):
        events.append("reset")
        return {
            "attempted": True,
            "verified": True,
            "after_route": "192.0.2.11 dev eth0",
        }

    def probe(_self, *_args):
        events.append("probe")
        return {"discovered_mtu": 1500}

    runner._reset_route_pmtu_cache = types.MethodType(reset, runner)
    runner._mtu_probe = types.MethodType(probe, runner)
    result = runner._fresh_mtu_probe(endpoint(), "192.0.2.10", "192.0.2.11", 4, 1500)

    assert events == ["reset", "probe"]
    assert result["route_pmtu_cache_reset_verified"] is True
    code = PerformanceRunner._route_cache_reset_code(
        "192.0.2.10", "192.0.2.11", 4, 1500
    )
    assert "route', 'flush', 'cache'" in code
    assert "route', 'get'" in code
    assert "stale_pmtu_after_reset" in code


def test_incidents_group_cascade_and_exclude_pass_advisories_and_observations():
    from .test_report_workflow import _payload

    payload = _payload()
    prototype = payload["results"][0]
    root = copy.deepcopy(prototype)
    root.update({"test_id": "ROOT", "status": "FAIL", "message": "path unreachable"})
    root["details"]["root_incident_id"] = "path-1"
    root["details"]["failure_class"] = "network-path-unreachable"

    dependents = []
    for name in ("LATENCY", "UDP"):
        item = copy.deepcopy(prototype)
        item.update({"test_id": name, "status": "UNVERIFIED", "message": "not run"})
        item["details"]["dependent_on_incident_id"] = "path-1"
        item["details"]["root_incident_id"] = "path-1"
        item["details"]["failure_class"] = "dependent-measurement"
        dependents.append(item)

    advisory = copy.deepcopy(prototype)
    advisory.update({"test_id": "ADVISORY", "status": "PASS"})
    advisory["details"].update({"root_incident_id": "path-1", "health": "warning"})

    observation = copy.deepcopy(prototype)
    observation.update(
        {
            "test_id": "OBSERVATION",
            "status": "UNVERIFIED",
            "expected": "observation",
            "authoritative": False,
        }
    )
    observation["details"]["observation_only"] = True

    payload["results"] = [root, *dependents, advisory, observation]
    model = build_dashboard_model(payload)

    assert len(model["findings"]) == 1
    finding = model["findings"][0]
    assert finding["incident_key"] == "incident:path-1"
    assert finding["result_count"] == 3
    assert set(finding["result_ids"]) == {"ROOT", "LATENCY", "UDP"}


def test_multi_zone_performance_estimate_applies_limit_per_execution_stage():
    specs: list[FluxTestSpec] = []
    for zone in ("az1", "az2"):
        for direction in ("forward", "reverse"):
            source, destination = ("a", "b") if direction == "forward" else ("b", "a")
            specs.append(
                FluxTestSpec(
                    id=f"{zone}-{direction}",
                    category="same-subnet",
                    operation="probe",
                    family=4,
                    expectation="reachable",
                    expectation_reason="test",
                    authoritative=True,
                    dependencies=[source, destination],
                    source_group_id=source,
                    destination_group_id=destination,
                    source_subnet_id=f"{source}-subnet",
                    destination_subnet_id=f"{destination}-subnet",
                    protocol="tcp",
                    phase="intra",
                    metadata={"availability_zone": zone},
                )
            )
    for direction in ("forward", "reverse"):
        source, destination = ("a", "b") if direction == "forward" else ("b", "a")
        specs.append(
            FluxTestSpec(
                id=f"cross-{direction}",
                category="cross-zone-connectivity",
                operation="probe",
                family=4,
                expectation="reachable",
                expectation_reason="test",
                authoritative=True,
                dependencies=[source, destination],
                source_group_id=source,
                destination_group_id=destination,
                source_subnet_id=f"{source}-subnet",
                destination_subnet_id=f"{destination}-subnet",
                protocol="tcp",
                phase="cross-zone",
                metadata={},
            )
        )
    config = SimpleNamespace(
        performance_max_paths=1,
        performance_duration_seconds=15,
        performance_repeats=2,
        performance_tcp_streams=[1, 4],
        performance_ping_count=10,
        performance_ping_warmup_count=2,
        performance_udp_rates_mbps=[10, 50],
        performance_udp_packet_sizes=[128, 1200],
        performance_udp_adaptive_calibration=True,
        performance_udp_calibration_max_attempts=4,
    )

    estimate = performance_estimate(config, specs)
    assert estimate["performance_path_candidates"] == 3
    assert estimate["performance_paths_selected"] == 3
    assert estimate["performance_execution_stages"] == 3
    assert estimate["performance_result_rows"] == 21
    assert (
        estimate["performance_estimated_seconds_maximum"]
        > estimate["performance_estimated_seconds_minimum"]
    )


def test_raw_performance_is_stored_once_and_junit_is_compact(config_factory):
    config = config_factory(
        action="run",
        junit_report_enabled=True,
        evidence_enabled=True,
        html_report_enabled=True,
    )
    reporter = Reporter(config, "sample-compact-report")
    marker = "RAW-MEASUREMENT-MARKER-" + ("x" * 20000)
    reporter.result(
        "PERF-SAMPLE-UDP",
        "network-performance",
        "UNVERIFIED",
        "endpoint-limited calibration",
        family=4,
        source="source (192.0.2.10)",
        destination="destination (192.0.2.11)",
        details={
            "performance": True,
            "measurement": "udp",
            "health": "unverified",
            "metrics": {"raw_measurement": marker},
        },
        expected="udp-quality-measured",
        observed="unverified",
        authoritative=False,
    )
    payload = build_run_payload(
        reporter,
        final_status="PASS WITH WARNINGS",
        finished=reporter.started,
        counts=Counter({"UNVERIFIED": 1}),
    )
    encoded = json.dumps(payload, sort_keys=True)

    assert payload["performance"]["storage"] == "canonical-results"
    assert payload["performance"]["result_ids"] == ["PERF-SAMPLE-UDP"]
    assert payload["performance"]["result_count"] == 1
    assert payload["dashboard"]["results"][0].get("details") is None
    assert encoded.count(marker) == 1

    xml = build_junit(payload, include_evidence=True)
    root = ET.fromstring(xml)
    system_out = root.findtext("./testcase/system-out") or ""
    assert len(system_out) < 5000
    assert "canonical_evidence" in system_out
    assert marker not in system_out
    assert "RAW-MEASUREMENT-MARKER" not in xml
    text_report = render_results_text(payload)
    assert marker not in text_report
    assert "Full recorded evidence: results.json" in text_report
    assert "results[test_id='PERF-SAMPLE-UDP'].details" in text_report
    assert len(text_report) < 10000
    reporter.logger.close()
