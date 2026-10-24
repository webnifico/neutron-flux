from __future__ import annotations

import datetime as dt
import subprocess
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.cleanup import CleanupManager
from neutron_flux.cloud_operation import CloudOperationCoordinator
from neutron_flux.errors import CommandTimeoutError
from neutron_flux.performance import PerformanceRunner
from neutron_flux.performance_results import _performance_result_summary
from neutron_flux.reporting import Reporter, ResourceTracker
from neutron_flux.reporting_components.dashboard_findings import finding_measurements
from neutron_flux.reporting_components.dashboard_model import _measurement_summary
from neutron_flux.reporting_components.html import _performance_summary
from neutron_flux.reporting_components.report_payload import _compact_cleanup


@pytest.mark.parametrize(
    "resource_type,kind",
    [("port", "port-delete"), ("server", "server-delete"), ("volume", "cleanup")],
)
def test_active_independent_deletion_does_not_quarantine_peer(
    config_factory, resource_type, kind
):
    reporter = Reporter(config_factory(action="cleanup"), "sample-concurrent-cleanup")
    tracker = ResourceTracker(reporter)
    first = tracker.add(resource_type, "first", "first")
    peer = tracker.add(resource_type, "peer", "peer")
    coordinator = CloudOperationCoordinator(reporter)
    coordinator._sleep = mock.Mock()
    manager = CleanupManager(
        SimpleNamespace(exists=lambda *_: True),
        reporter,
        tracker,
        reporter.config,
        cloud_operation_coordinator=coordinator,
    )
    manager._wait_absent = lambda *_: True
    manager._deletion_timeout = lambda *_: 1
    accepted, release = threading.Event(), threading.Event()

    def delete(resource):
        coordinator.execute(
            kind,
            (resource_type, "delete", resource.id),
            lambda: subprocess.CompletedProcess([], 0, "", ""),
        )
        if resource is first:
            accepted.set()
            assert release.wait(5)

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            task = pool.submit(manager._delete_record, first, delete)
            try:
                assert accepted.wait(5)
                # Duplicate work, unscoped cleanup and journal replay stay blocked.
                assert coordinator.cleanup_blocker(first.id) is not None
                assert coordinator.cleanup_blocker() is not None
                replayed = CloudOperationCoordinator(
                    SimpleNamespace(
                        logger=mock.Mock(), run_dir=reporter.run_dir, event=mock.Mock()
                    )
                )
                assert replayed.cleanup_blocker(peer.id) is not None
                manager._delete_record(peer, delete)
                assert peer.delete_status == "deleted"
            finally:
                release.set()
            task.result(timeout=5)
        assert first.delete_status == "deleted"
        assert coordinator.cloud_operation_summary()["unresolved_count"] == 0
        assert reporter.cleanup_summary["leftovers"] == []
    finally:
        reporter.logger.close()


@pytest.mark.parametrize("outcome", ["ambiguous", "abandoned", "unknown-scope"])
def test_unresolved_deletion_still_blocks_peer(config_factory, outcome):
    reporter = Reporter(config_factory(action="cleanup"), "sample-unsafe-cleanup")
    coordinator = CloudOperationCoordinator(reporter)
    coordinator._sleep = mock.Mock()
    try:
        if outcome == "unknown-scope":
            with coordinator.transaction("port-delete", "unknown scope"):
                coordinator.execute(
                    "port-delete",
                    ("port", "delete", "first"),
                    lambda: subprocess.CompletedProcess([], 0, "", ""),
                )
                # Explicitly lack a reliable target in the journal as well.
                coordinator._latest[coordinator.current_transaction.operation_ids[0]][
                    "resource_ids"
                ] = []
                assert coordinator.cleanup_blocker("peer") is not None
        else:
            with pytest.raises((CommandTimeoutError, RuntimeError)):
                with coordinator.transaction(
                    "port-delete", "unsafe deletion", resource_ids=["first"]
                ):

                    def submit():
                        if outcome == "ambiguous":
                            raise CommandTimeoutError(
                                ["openstack", "port", "delete", "first"], 60
                            )
                        return subprocess.CompletedProcess([], 0, "", "")

                    coordinator.execute(
                        "port-delete", ("port", "delete", "first"), submit
                    )
                    raise RuntimeError("verification interrupted")
            assert coordinator.cleanup_blocker("first") is not None
            assert coordinator.cleanup_blocker("peer") is not None
    finally:
        reporter.logger.close()


def runner(config_factory):
    value = PerformanceRunner.__new__(PerformanceRunner)
    value.config = config_factory(
        performance_asymmetry_threshold_pct=50.0, performance_udp_loss_threshold_pct=1.0
    )
    return value


def sample(loss, **flags):
    return {
        "loss_pct": loss,
        "jitter_ms": 0.1,
        "packet_size": 128,
        "requested_mbps": 5,
        "load_valid": True,
        "endpoint_limited": False,
        "calibration_selected": True,
        **flags,
    }


def result(metrics):
    return {
        "test_id": "udp",
        "status": "UNVERIFIED",
        "details": {"measurement": "udp", "metrics": metrics},
    }


def asymmetry(value, metrics):
    tcp = {"streams": {"1": {"median_mbps": 1183.0}}}
    return value._asymmetry(
        tcp, tcp, {"forward": {"p95_ms": 1}, "reverse": {"p95_ms": 1}}, metrics
    )


@pytest.mark.parametrize(
    "flags",
    [
        {"endpoint_limited": True},
        {"load_valid": False},
        {"calibration_selected": False},
    ],
)
def test_excluded_udp_samples_do_not_leak_into_grading_or_reporting(
    config_factory, flags
):
    metrics = {
        "forward": [sample(73.19589036420112, **flags), sample(0)],
        "reverse": [sample(70.27750281598799, **flags), sample(0)],
    }
    value = runner(config_factory)
    assert value._udp_assessable_rows(metrics) == [
        ("forward", metrics["forward"][1]),
        ("reverse", metrics["reverse"][1]),
    ]
    assert asymmetry(value, metrics)["udp_loss_difference_pct_points"] == 0
    assert asymmetry(value, metrics)["health"] == "good"
    assert _performance_summary([result(metrics)])["worst_udp_loss_pct"] == 0
    values = _measurement_summary(result(metrics))["values"]
    assert values["forward_loss_pct"] == values["reverse_loss_pct"] == 0
    findings = finding_measurements([result(metrics)])
    assert findings[0]["value"] == "0.000%"
    assert "73.20%" not in _performance_result_summary("udp", metrics)


def test_all_endpoint_limited_udp_remains_unknown(config_factory):
    metrics = {
        "forward": [sample(83.013, endpoint_limited=True)],
        "reverse": [sample(83.457, endpoint_limited=True)],
    }
    value = runner(config_factory)
    assert value._udp_health(metrics) == "unverified"
    comparison = asymmetry(value, metrics)
    assert comparison["udp_loss_difference_pct_points"] is None
    assert comparison["health"] == "unverified"
    assert _performance_summary([result(metrics)])["worst_udp_loss_pct"] is None
    assert (
        _measurement_summary(result(metrics))["values"].get("forward_loss_pct") is None
    )
    findings = finding_measurements([result(metrics)])
    assert all(row["label"] != "Worst across affected UDP tests" for row in findings)
    assert any("endpoint" in row["label"].lower() for row in findings)


def test_eligible_udp_loss_is_still_reported(config_factory):
    metrics = {"forward": [sample(0)], "reverse": [sample(7)]}
    value = runner(config_factory)
    assert asymmetry(value, metrics)["health"] == "warning"
    assert asymmetry(value, metrics)["udp_loss_difference_pct_points"] == 7
    assert _performance_summary([result(metrics)])["worst_udp_loss_pct"] == 7
    assert _measurement_summary(result(metrics))["values"]["reverse_loss_pct"] == 7
    assert finding_measurements([result(metrics)])[0]["value"] == "7.000%"


def test_udp_asymmetry_compares_matching_packet_sizes_and_rates(config_factory):
    metrics = {
        "forward": [sample(0, requested_mbps=5), sample(20, requested_mbps=50)],
        "reverse": [sample(0, requested_mbps=5), sample(20, requested_mbps=10)],
    }
    measured = asymmetry(runner(config_factory), metrics)
    assert measured["udp_loss_difference_pct_points"] == 0
    assert measured["udp_compared_profiles"] == 1
    assert measured["udp_unmatched_profiles"] == 2


def test_udp_asymmetry_does_not_compare_unmatched_rates(config_factory):
    metrics = {
        "forward": [sample(0, requested_mbps=5)],
        "reverse": [sample(7, requested_mbps=50)],
    }
    measured = asymmetry(runner(config_factory), metrics)
    assert measured["udp_loss_difference_pct_points"] is None
    assert measured["health"] == "unverified"


def test_interrupted_cleanup_summary_counts_absent_resources(config_factory):
    reporter = Reporter(config_factory(action="cleanup"), "sample-cleanup-count")
    tracker = ResourceTracker(reporter)
    try:
        tracker.mark_deleted(tracker.add("port", "deleted", "deleted"))
        tracker.mark_deleted(
            tracker.add("volume", "absent", "absent"), "already-absent"
        )
        tracker.add("network", "pending", "pending")
        manager = CleanupManager(mock.Mock(), reporter, tracker, reporter.config)
        manager._record_interrupted_cleanup("received signal 2")
        summary = reporter._summary(
            "CANCELLED", dt.datetime.now(dt.timezone.utc), Counter()
        )
        assert "2 resource(s) confirmed absent" in summary
        assert reporter.cleanup_summary["deleted"] == 1
        assert reporter.cleanup_summary["confirmed_deleted_count"] == 2
        assert (
            _compact_cleanup(reporter.cleanup_summary)["confirmed_deleted_count"] == 2
        )
        assert reporter.cleanup_summary["unverified_resource_count"] == 1
    finally:
        reporter.logger.close()


def test_udp_directional_difference_is_computed_per_matching_profile(config_factory):
    metrics = {
        "forward": [sample(0, requested_mbps=5), sample(20, requested_mbps=50)],
        "reverse": [sample(20, requested_mbps=5), sample(0, requested_mbps=50)],
    }
    measured = asymmetry(runner(config_factory), metrics)
    assert measured["udp_loss_difference_pct_points"] == 20
    assert measured["health"] == "warning"


@pytest.mark.parametrize(
    "flags", [{"load_valid": False}, {"calibration_selected": False}]
)
def test_no_eligible_udp_does_not_fall_back_to_excluded_samples(config_factory, flags):
    metrics = {"forward": [sample(83, **flags)], "reverse": [sample(70, **flags)]}
    value = runner(config_factory)
    assert value._udp_assessable_rows(metrics) == []
    assert value._udp_health(metrics) == "unverified"
    assert _performance_summary([result(metrics)])["worst_udp_loss_pct"] is None
    assert asymmetry(value, metrics)["udp_loss_difference_pct_points"] is None


def test_offline_rebuild_refreshes_udp_summary_without_rewriting_evidence(
    tmp_path, monkeypatch
):
    import json

    from neutron_flux.offline_reports import regenerate

    from .test_offline_analysis_hardening import _run

    row = result(
        {
            "forward": [sample(83, endpoint_limited=True), sample(0)],
            "reverse": [sample(0)],
        }
    )
    row["category"] = "network-performance"
    payload = _run("old", [row], performance={"worst_udp_loss_pct": 83})
    payload["run"]["final_status"] = "CANCELLED"
    payload["cleanup"] = {
        "complete": None,
        "interrupted": True,
        "deleted": 11,
        "confirmed_deleted_count": 15,
    }
    source = tmp_path / "old.json"
    source.write_text(json.dumps(payload))
    original = source.read_bytes()
    rendered = []
    monkeypatch.setattr(
        "neutron_flux.offline_reports.render_html",
        lambda value: rendered.append(value) or "<html></html>",
    )
    regenerate(source, destination=tmp_path / "rebuilt")
    display = rendered[0]
    assert display["summary"]["performance"]["worst_udp_loss_pct"] == 0
    assert (
        display["summary"]["performance"]["worst_endpoint_limited_udp_loss_pct"] == 83
    )
    assert display["results"][0]["status"] == "UNVERIFIED"
    assert display["results"][0]["details"]["metrics"] == row["details"]["metrics"]
    assert source.read_bytes() == original
    assert _compact_cleanup(display["cleanup"])["confirmed_deleted_count"] == 15
