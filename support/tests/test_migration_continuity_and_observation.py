from __future__ import annotations

import json
import subprocess

from neutron_flux.execution.placement_migration import PlacementMigrationMixin
from neutron_flux.models import Plan
from neutron_flux.offline_reports import _current_offline_interpretation
from neutron_flux.probes import ProbeContext, TCPProbe
from neutron_flux.replay_plan import build_replay_plan
from neutron_flux.reporting import Reporter

from ._shared import endpoint


def _completed(returncode: int, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess(["probe"], returncode, stdout, stderr)


def test_provider_observer_returns_translated_peer_identity():
    diagnostics = {
        "connected": True,
        "request_sent": True,
        "response_received": True,
        "response_validated": True,
        "observed_peer_ip": "203.0.113.10",
        "observer_probe_id": "probe-id",
        "observer_instance_id": "instance-id",
    }
    context = ProbeContext(
        lambda _endpoint, _command: _completed(
            0,
            "NFLUX_TCP_PEER " + json.dumps(diagnostics),
        ),
        lambda _command: _completed(0),
        18080,
        18081,
    )

    result = TCPProbe(context).endpoint_peer_identity(
        endpoint("source", "A"),
        "192.0.2.10",
        "192.0.2.20",
        4,
    )

    assert result.outcome == "reachable"
    assert result.attempts == 1
    assert result.diagnostics["observed_peer_ip"] == "203.0.113.10"
    assert result.diagnostics["observer_mode"] == "provider-endpoint-probe-service"


def _continuity(
    *, tcp_survived: bool, icmp_loss: float, udp_loss: float, outage: float
):
    from ._evidence import complete_continuity

    return complete_continuity(
        tcp_survived=tcp_survived, icmp_loss=icmp_loss, udp_loss=udp_loss, outage=outage
    )


def test_isolated_subsecond_migration_miss_is_advisory_not_failure():
    status, observed, _message, details = (
        PlacementMigrationMixin._live_continuity_verdict(
            _continuity(
                tcp_survived=True,
                icmp_loss=0.32,
                udp_loss=0.06,
                outage=0.0,
            )
        )
    )
    assert status == "PASS"
    assert observed == "traffic-continuity-measured"
    assert details["continuity_failure_reasons"] == []


def test_material_migration_interruption_still_fails():
    status, observed, message, _details = (
        PlacementMigrationMixin._live_continuity_verdict(
            _continuity(
                tcp_survived=False,
                icmp_loss=1.31,
                udp_loss=4.41,
                outage=3.0,
            )
        )
    )
    assert status == "FAIL"
    assert observed == "traffic-interrupted"
    assert "TCP session did not complete" in message
    assert "ICMP failed observations 1.31% exceeded 1.00%" in message


def test_partial_status_preserves_successful_zone_coverage(config_factory):
    reporter = Reporter(config_factory(action="run"), "sample-partial-status")
    reporter.plan = Plan([], [], {}, [], tests=[])
    reporter.cleanup_summary.update({"attempted": True, "complete": True})
    reporter.record_setup_failure(
        "bc-van2 controller setup failed", availability_zone="bc-van2"
    )
    reporter.result(
        "AZ-BC-VAN1-SAME-ICMP",
        "same-subnet",
        "PASS",
        "reachable",
        expected="reachable",
        observed="reachable",
        scenario="Provider subnet connectivity",
    )
    reporter.finalize(0)
    assert "Final status:    PARTIAL" in reporter.report_path.read_text()


def _result(test_id: str, *, status: str, observed: str, authoritative: bool = True):
    return {
        "test_id": test_id,
        "display_name": test_id,
        "category": "connectivity",
        "scenario": "Connectivity",
        "status": status,
        "family": 4,
        "source": "az1/source (192.0.2.10)",
        "destination": "az1/destination (192.0.2.20)",
        "message": "evidence",
        "details": {},
        "expected": "reachable" if authoritative else "observation",
        "observed": observed,
        "authoritative": authoritative,
    }


def test_replay_excludes_observations_and_collapses_duplicate_symptoms():
    payload = {
        "schema_version": 1,
        "tool": "neutron-flux",
        "tool_version": "0.1.0 (prerelease)",
        "run": {"run_id": "sample-replay", "action": "run", "final_status": "FAIL"},
        "configuration": {},
        "results": [
            _result("FAIL-A", status="FAIL", observed="blocked"),
            _result("FAIL-B", status="FAIL", observed="blocked"),
            _result(
                "OBSERVATION",
                status="UNVERIFIED",
                observed="blocked",
                authoritative=False,
            ),
        ],
        "cleanup": {"attempted": True, "complete": True},
        "setup_failures": [],
    }
    replay = build_replay_plan(payload)
    assert len(replay["cases"]) == 1
    assert replay["cases"][0]["target_result_id"] == "FAIL-A"
    assert replay["collapsed_target_count"] == 1


def test_offline_interpretation_reclassifies_old_isolated_ping_miss():
    item = {
        "status": "FAIL",
        "category": "compute-placement",
        "message": "ICMP loss exceeded 0.00%",
        "details": _continuity(
            tcp_survived=True,
            icmp_loss=0.32,
            udp_loss=0.06,
            outage=0.0,
        ),
    }
    item["details"]["thresholds"]["icmp_loss_pct"] = 0.0
    item["details"]["icmp"]["raw_samples"] = [
        {"sequence": 1, "ok": False},
        {"sequence": 2, "ok": True},
    ]
    interpretation = _current_offline_interpretation(item)
    assert interpretation is not None
    assert interpretation[0] == "PASS"
    assert "not a material live-migration continuity failure" in interpretation[1]
