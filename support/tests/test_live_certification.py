from __future__ import annotations

import dataclasses
import hashlib
import importlib.util
import json
import pathlib
import signal
import sys
from typing import Any
from unittest import mock

import pytest

from neutron_flux.config import Config
from neutron_flux.constants import RELEASE_IDENTIFIER, VERSION

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "support" / "scripts" / "live-certify.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("neutron_flux_live_certify", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def live_certify():
    return _load_module()


def test_live_certification_defaults_are_current_source_points(
    live_certify, config_factory
):
    available = live_certify.discover_literal_injection_points()
    config = config_factory(
        migration_mode="live-preferred",
        compute_host_connectivity_enabled=True,
    )
    selected = live_certify.default_injection_points(config)

    assert set(selected) <= available
    assert "before-live-migration" in selected
    assert "after-live-handoff" in selected
    assert "before-server-delete" in selected
    assert "before-static-network-config" not in available
    assert "before-source-nat-cloud-operation" not in available
    assert "before-source-nat-restore" not in available


def test_live_certification_rejects_stale_and_wildcard_points(live_certify):
    with pytest.raises(live_certify.CertificationError, match="absent"):
        live_certify.validate_injection_points(
            ["before-stale-point"], {"before-controller-create"}
        )
    with pytest.raises(live_certify.CertificationError, match="Wildcard"):
        live_certify.validate_injection_points(["*"], {"*"})


def test_live_certification_cold_only_omits_unreachable_live_points(
    live_certify, config_factory
):
    config = config_factory(
        migration_mode="cold-only",
        compute_host_connectivity_enabled=True,
    )
    points = live_certify.default_injection_points(config)

    assert "before-live-migration" not in points
    assert "after-live-handoff" not in points
    assert "before-server-delete" in points


def test_live_certification_preserves_complete_effective_configuration(
    live_certify, config_factory, tmp_path
):
    config = config_factory(
        action="run",
        report_dir=tmp_path / "reports",
        storage="volume",
        volume_size=37,
        volume_type="premium",
        ssh_user="debian",
        availability_zones=["az1", "az2"],
        availability_zones_all=False,
        zone_mode="both",
        compute_host_connectivity_enabled=True,
        require_shared_compute_aggregate=False,
        compute_migration_max_attempts=1,
        migration_mode="live-only",
        migration_storage="shared",
        live_migration_attempts=1,
        cold_migration_fallback=False,
        live_migration_continuity=False,
        target_hosts=[],
        target_aggregates=[],
        target_host_pairs=[],
        include_same_host=True,
        qualification_strategy="rolling",
        qualification_profile="performance",
        qualification_cycles=3,
        performance_enabled=False,
        performance_duration_seconds=7,
        performance_repeats=5,
        performance_max_paths=11,
        performance_tcp_streams=[1, 2, 6],
        performance_udp_rates_mbps=[17, 33],
        performance_udp_packet_sizes=[256, 1400],
        performance_ping_count=71,
        performance_ping_warmup_count=9,
        performance_enforce_thresholds=True,
        performance_udp_sender_achievement_threshold_pct=91.5,
        performance_udp_loss_threshold_pct=2.5,
        performance_udp_reordering_threshold_pct=0.7,
        performance_loaded_latency_ratio_threshold=8.0,
        performance_asymmetry_threshold_pct=35.0,
        performance_variation_threshold_pct=14.0,
        fabric_scale_enabled=True,
        fabric_scale_pairs=[1, 3, 7],
        fabric_scale_runs=4,
        fabric_scale_duration_seconds=19,
        html_report_enabled=False,
        junit_report_enabled=False,
        evidence_enabled=False,
        test_ids=[],
        keep_resources=True,
        auto_cleanup_on_failure=False,
    )

    mapping = live_certify.resolved_mapping(config, "before-server-delete")

    assert mapping["volume"] == {"size": 37, "type": "premium"}
    assert mapping["placement"]["availability_zones"] == ["az1", "az2"]
    assert mapping["placement"]["zone_mode"] == "both"
    migration = mapping["placement"]["compute_host_connectivity"]["migration"]
    assert migration == {
        "mode": "live-only",
        "storage": "shared",
        "live_attempts": 1,
        "cold_fallback": False,
        "continuity": False,
    }
    assert mapping["qualification"] == {
        "include_same_host": True,
        "strategy": "rolling",
        "profile": "performance",
        "cycles": 3,
    }
    performance = mapping["performance"]
    assert performance["enabled"] is False
    assert performance["duration_seconds"] == 7
    assert performance["tcp_streams"] == [1, 2, 6]
    assert performance["thresholds"]["udp_sender_achievement_pct"] == 91.5
    assert performance["concurrent_vm_pair_load"] == {
        "enabled": True,
        "pairs": [1, 3, 7],
        "runs": 4,
        "duration_seconds": 19,
    }
    assert mapping["reporting"] == {
        "html": False,
        "junit": False,
        "evidence": False,
    }
    assert mapping["testing"]["failure_injection"] == "before-server-delete"
    assert mapping["cleanup"]["keep_resources"] is False
    assert mapping["cleanup"]["on_failure"] is True


def test_live_certification_preserves_qualification_pairs(live_certify, config_factory):
    config = config_factory(
        target_hosts=[],
        target_aggregates=[],
        target_host_pairs=[("compute1", "compute2")],
        include_same_host=False,
        qualification_strategy="stable",
        qualification_profile="connectivity",
        qualification_cycles=2,
    )

    qualification = live_certify.resolved_mapping(config)["qualification"]

    assert qualification["target_host_pairs"] == ["compute1:compute2"]
    assert qualification["strategy"] == "stable"
    assert qualification["profile"] == "connectivity"
    assert qualification["cycles"] == 2


def test_live_certification_generated_mapping_round_trips_through_config(
    live_certify, config_factory, tmp_path
):
    original = config_factory(
        action="run",
        report_dir=tmp_path / "reports",
        storage="volume",
        volume_size=23,
        volume_type="gold",
        zone_mode="per-zone",
        migration_mode="live-preferred",
        migration_storage="shared",
        performance_enabled=True,
        fabric_scale_enabled=True,
        fabric_scale_pairs=[1, 2],
        fabric_scale_runs=3,
        fabric_scale_duration_seconds=11,
    )
    path = live_certify.write_config(original, "before-server-delete")
    try:
        loaded = live_certify.load_worker_snapshot(path)
    finally:
        path.unlink(missing_ok=True)

    assert loaded.zone_mode == original.zone_mode
    assert loaded.migration_mode == original.migration_mode
    assert loaded.volume_size == 23
    assert loaded.volume_type == "gold"
    assert loaded.performance_enabled is True
    assert loaded.fabric_scale_enabled is True
    assert loaded.fabric_scale_pairs == [1, 2]
    assert loaded.fabric_scale_runs == 3
    assert loaded.fabric_scale_duration_seconds == 11
    assert loaded.failure_injection == "before-server-delete"


def test_live_certification_rejects_unserializable_scheduler_invariant(
    live_certify, config_factory
):
    with pytest.raises(live_certify.CertificationError, match="max_active_endpoints=3"):
        live_certify.resolved_mapping(config_factory(max_active_endpoints=3))


@pytest.mark.parametrize(
    "az_settings",
    [
        {},
        {"allow_cross_az_volumes": True, "allow_cross_az_networking": True},
        {"allow_cross_az_volumes": True, "network_az": "nova", "router_az": "edge"},
    ],
)
def test_live_certification_classifies_every_config_field_and_round_trips_behavior(
    live_certify, config_factory, tmp_path, az_settings
):
    original = config_factory(
        action="run",
        report_dir=tmp_path / "reports",
        storage="volume" if az_settings.get("allow_cross_az_volumes") else "host",
        migration_mode="cold-only",
        migration_storage="auto",
        cold_migration_fallback=False,
        live_migration_continuity=False,
        performance_enabled=False,
        html_report_enabled=False,
        junit_report_enabled=False,
        evidence_enabled=False,
        quiet_period_scale=0.5,
        operation_gap_scale=0.25,
        **az_settings,
    )
    path = live_certify.write_config(original)
    try:
        loaded = live_certify.load_worker_snapshot(path)
    finally:
        path.unlink(missing_ok=True)

    preserved = {
        "repeat_count",
        "repeat_index",
        "repeat_root_id",
        "repeat_next_id",
        "repeat_exit_code",
        "action",
        "prefix",
        "report_dir",
        "image",
        "flavor",
        "storage",
        "ssh_user",
        "availability_zones",
        "availability_zones_all",
        "zone_mode",
        "allow_cross_az_volumes",
        "allow_cross_az_networking",
        "network_az",
        "router_az",
        "mgmt_cidr",
        "no_routing_group_ipv4_cidr",
        "no_routing_group_ipv6_cidr",
        "include_no_routing_group_controls",
        "ipv4_targets",
        "ipv6_targets",
        "tcp_port",
        "udp_port",
        "ssh_timeout",
        "resource_timeout",
        "convergence_timeout",
        "convergence_interval",
        "quiet_period_scale",
        "operation_gap_scale",
        "progress_interval",
        "keep_resources",
        "auto_cleanup_on_failure",
        "volume_size",
        "volume_type",
        "max_active_endpoints",
        "cleanup_timeouts",
        "external_networks",
        "exclude_external_networks",
        "routing_contracts",
        "failure_injection",
        "compute_host_connectivity_enabled",
        "require_shared_compute_aggregate",
        "compute_migration_max_attempts",
        "migration_mode",
        "migration_storage",
        "live_migration_attempts",
        "cold_migration_fallback",
        "live_migration_continuity",
        "orphan_grace_minutes",
        "performance_profile",
        "performance_enabled",
        "performance_duration_seconds",
        "performance_repeats",
        "performance_max_paths",
        "performance_tcp_streams",
        "performance_udp_rates_mbps",
        "performance_udp_packet_sizes",
        "performance_udp_adaptive_calibration",
        "performance_udp_calibration_min_rate_mbps",
        "performance_udp_calibration_max_attempts",
        "performance_udp_calibration_backoff_factor",
        "performance_ping_count",
        "performance_ping_warmup_count",
        "performance_enforce_thresholds",
        "performance_udp_sender_achievement_threshold_pct",
        "performance_udp_loss_threshold_pct",
        "performance_udp_reordering_threshold_pct",
        "performance_loaded_latency_ratio_threshold",
        "performance_asymmetry_threshold_pct",
        "performance_variation_threshold_pct",
        "fabric_scale_enabled",
        "fabric_scale_pairs",
        "fabric_scale_runs",
        "fabric_scale_duration_seconds",
        "html_report_enabled",
        "junit_report_enabled",
        "evidence_enabled",
        "target_hosts",
        "target_aggregates",
        "target_host_pairs",
        "include_same_host",
        "qualification_strategy",
        "qualification_profile",
        "qualification_cycles",
        "test_ids",
        "include_derived_tests",
    }
    action_state = {
        "ipv4_targets_configured",
        "ipv6_targets_configured",
        "input_sources",
        "cleanup_orphans",
        "cleanup_dry_run",
        "cleanup_assume_yes",
        "cleanup_include_active",
        "resume_run_id",
    }
    assert {field.name for field in dataclasses.fields(Config)} == (
        preserved | action_state
    )
    for field in sorted(preserved):
        assert getattr(loaded, field) == getattr(original, field), field


def test_live_certification_records_release_archive_and_git_identity(
    live_certify, tmp_path
):
    archive = tmp_path / f"neutron-flux-v{RELEASE_IDENTIFIER}.zip"
    archive.write_bytes(b"deterministic candidate archive")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    identity = live_certify.release_identity_from_environment(
        {
            "CERTIFICATION_CANDIDATE_ARCHIVE": str(archive),
            "CERTIFICATION_CANDIDATE_SHA256": digest.upper(),
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": "example/neutron-flux",
            "GITHUB_SHA": "commit-sha",
            "GITHUB_REF": f"refs/tags/v{RELEASE_IDENTIFIER}",
            "GITHUB_RUN_ID": "1234",
        }
    )

    assert identity["package_version"] == VERSION
    assert identity["release_identifier"] == RELEASE_IDENTIFIER
    assert identity["candidate_archive"] == archive.name
    assert identity["candidate_sha256"] == digest
    assert identity["candidate_hash_verified"] is True
    assert identity["github_sha"] == "commit-sha"
    assert identity["github_ref"] == f"refs/tags/v{RELEASE_IDENTIFIER}"


def test_live_certification_github_run_requires_verified_candidate_hash(
    live_certify, tmp_path
):
    with pytest.raises(
        live_certify.CertificationError, match="requires a deterministic"
    ):
        live_certify.release_identity_from_environment(
            {"GITHUB_ACTIONS": "true", "GITHUB_SHA": "commit-sha"}
        )
    with pytest.raises(live_certify.CertificationError, match="64 hexadecimal"):
        live_certify.release_identity_from_environment(
            {
                "CERTIFICATION_CANDIDATE_ARCHIVE": "candidate.zip",
                "CERTIFICATION_CANDIDATE_SHA256": "bad",
            }
        )
    archive = tmp_path / "candidate.zip"
    archive.write_bytes(b"candidate")
    with pytest.raises(live_certify.CertificationError, match="SHA-256 mismatch"):
        live_certify.release_identity_from_environment(
            {
                "CERTIFICATION_CANDIDATE_ARCHIVE": str(archive),
                "CERTIFICATION_CANDIDATE_SHA256": "0" * 64,
            }
        )


def _candidate_environment(tmp_path: pathlib.Path) -> dict[str, str]:
    archive = tmp_path / f"neutron-flux-v{RELEASE_IDENTIFIER}.zip"
    archive.write_bytes(b"candidate archive")
    return {
        "CERTIFICATION_CANDIDATE_ARCHIVE": str(archive),
        "CERTIFICATION_CANDIDATE_SHA256": hashlib.sha256(
            archive.read_bytes()
        ).hexdigest(),
    }


def test_live_certification_settings_require_exact_candidate_binding(
    live_certify, config_factory
):
    with pytest.raises(
        live_certify.CertificationError, match="exact candidate archive"
    ):
        live_certify.settings_from_environment(
            config_factory(),
            {
                "SUCCESS_RUNS": "10",
                "INTERRUPTED_RUNS": "10",
                "INJECTED_RUNS": "10",
            },
        )


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("SUCCESS_RUNS", "0"),
        ("INTERRUPTED_RUNS", "-1"),
        ("INJECTED_RUNS", "not-a-number"),
        ("INTERRUPTION_PHASE_TIMEOUT_SECONDS", "0"),
    ],
)
def test_live_certification_requires_positive_counts(
    live_certify, config_factory, name, value
):
    environment = {
        "SUCCESS_RUNS": "10",
        "INTERRUPTED_RUNS": "10",
        "INJECTED_RUNS": "10",
        "INTERRUPTION_PHASE_TIMEOUT_SECONDS": "60",
        name: value,
    }
    with pytest.raises(live_certify.CertificationError, match="positive integer"):
        live_certify.settings_from_environment(config_factory(), environment)


def test_live_certification_requires_one_run_per_point_and_phase(
    live_certify, config_factory
):
    config = config_factory(migration_mode="live-preferred")
    with pytest.raises(live_certify.CertificationError, match="every required phase"):
        live_certify.settings_from_environment(
            config,
            {
                "SUCCESS_RUNS": "1",
                "INTERRUPTED_RUNS": "1",
                "INJECTED_RUNS": "10",
                "CERTIFICATION_INTERRUPTION_PHASES": "group-local,cleanup",
            },
        )
    with pytest.raises(
        live_certify.CertificationError, match="every required injection"
    ):
        live_certify.settings_from_environment(
            config,
            {
                "SUCCESS_RUNS": "1",
                "INTERRUPTED_RUNS": "4",
                "INJECTED_RUNS": "1",
                "CERTIFICATION_INJECTION_POINTS": (
                    "after-controller-create,before-server-delete"
                ),
            },
        )


def test_live_certification_explicit_point_and_phase_selection_is_auditable(
    live_certify, config_factory, tmp_path
):
    environment = {
        **_candidate_environment(tmp_path),
        "SUCCESS_RUNS": "2",
        "INTERRUPTED_RUNS": "2",
        "INJECTED_RUNS": "2",
        "CERTIFICATION_INJECTION_POINTS": (
            "after-controller-create,before-server-delete"
        ),
        "CERTIFICATION_INTERRUPTION_PHASES": "group-local,cleanup",
        "INTERRUPTION_PHASE_TIMEOUT_SECONDS": "77",
        "CERTIFICATION_OUTPUT_DIR": str(tmp_path / "artifacts"),
    }
    settings = live_certify.settings_from_environment(
        config_factory(),
        environment,
    )

    assert settings.injection_points == (
        "after-controller-create",
        "before-server-delete",
    )
    assert settings.interruption_phases == ("group-local", "cleanup")
    assert settings.phase_timeout_seconds == 77
    assert settings.artifact_output_dir == (tmp_path / "artifacts").resolve()


def _orphan_payload(**overrides: int) -> dict[str, Any]:
    counts = {
        "stale_resources_remaining": 0,
        "protected_resources_remaining": 0,
        "unknown_resources_remaining": 0,
        "project_resources_remaining": 0,
    }
    counts.update(overrides)
    return {"cleanup": {"orphan_sweep": counts}}


def test_live_certification_orphan_sweep_requires_zero_owned_resources(
    live_certify,
):
    assert live_certify.validate_orphan_sweep(_orphan_payload()) == {
        "stale_resources_remaining": 0,
        "protected_resources_remaining": 0,
        "unknown_resources_remaining": 0,
        "project_resources_remaining": 0,
    }
    with pytest.raises(live_certify.CertificationError, match="stale=1"):
        live_certify.validate_orphan_sweep(
            _orphan_payload(
                stale_resources_remaining=1,
                project_resources_remaining=1,
            )
        )
    with pytest.raises(live_certify.CertificationError, match="unknown=1"):
        live_certify.validate_orphan_sweep(
            _orphan_payload(
                unknown_resources_remaining=1,
                project_resources_remaining=1,
            )
        )


def _outcome(live_certify, workflow: str, run_id: str, **overrides: Any):
    values: dict[str, Any] = {
        "workflow": workflow,
        "run_id": run_id,
        "exit_code": 0,
        "cleanup_state": "COMPLETE",
        "checkpoint_state": "COMPLETED",
        "final_status": "PASS",
        "evidence_verified": True,
    }
    values.update(overrides)
    return live_certify.RunOutcome(**values)


def test_live_certification_missed_injection_is_a_failure(live_certify):
    outcome = _outcome(
        live_certify,
        "injected",
        "run-missed",
        exit_code=0,
        final_status="PASS",
        injection_point="before-server-delete",
        target_reached=False,
    )

    with pytest.raises(live_certify.CertificationError, match="was not reached"):
        live_certify.validate_injected_outcome(outcome)


def test_live_certification_interruption_requires_observed_cancellation(
    live_certify,
):
    valid = _outcome(
        live_certify,
        "interrupted",
        "run-cancelled",
        exit_code=130,
        final_status="CANCELLED",
        checkpoint_state="CANCELLED",
        interruption_phase="cleanup",
        target_reached=True,
        signal_sent="SIGTERM",
    )
    live_certify.validate_interrupted_outcome(valid)

    completed = dataclasses.replace(valid, exit_code=0, final_status="PASS")
    with pytest.raises(live_certify.CertificationError, match="not observed"):
        live_certify.validate_interrupted_outcome(completed)


def test_live_certification_run_is_mocked_and_writes_auditable_summaries(
    live_certify, config_factory, tmp_path, monkeypatch
):
    report_dir = tmp_path / "reports"
    base = config_factory(action="run", report_dir=report_dir)
    settings = live_certify.CertificationSettings(
        successful_runs=1,
        interrupted_runs=1,
        injected_runs=1,
        injection_points=("before-server-delete",),
        interruption_phases=("cleanup",),
        phase_timeout_seconds=60,
        artifact_output_dir=None,
    )
    successful = _outcome(live_certify, "successful", "success-1")
    interrupted = _outcome(
        live_certify,
        "interrupted",
        "interrupted-1",
        exit_code=130,
        final_status="CANCELLED",
        checkpoint_state="CANCELLED",
        interruption_phase="cleanup",
        target_reached=True,
        signal_sent="SIGTERM",
    )
    injected = _outcome(
        live_certify,
        "injected",
        "injected-1",
        exit_code=2,
        final_status="ERROR",
        checkpoint_state="FAILED",
        injection_point="before-server-delete",
        target_reached=True,
    )
    monkeypatch.setattr(
        live_certify, "successful_run", mock.Mock(return_value=successful)
    )
    monkeypatch.setattr(
        live_certify, "interrupted_run", mock.Mock(return_value=interrupted)
    )
    monkeypatch.setattr(live_certify, "injected_run", mock.Mock(return_value=injected))
    orphan_counts = live_certify.validate_orphan_sweep(_orphan_payload())
    orphan = mock.Mock(return_value=("orphan-check-1", orphan_counts))
    monkeypatch.setattr(live_certify, "independent_orphan_verification", orphan)

    summary = live_certify.run_certification(base, settings)

    assert summary["status"] == "PASS"
    assert [item["workflow"] for item in summary["runs"]] == [
        "successful",
        "interrupted",
        "injected",
    ]
    assert summary["orphan_verification"]["run_id"] == "orphan-check-1"
    assert (
        json.loads(
            (report_dir / live_certify.SUMMARY_JSON_NAME).read_text(encoding="utf-8")
        )["status"]
        == "PASS"
    )
    text = (report_dir / live_certify.SUMMARY_TEXT_NAME).read_text(encoding="utf-8")
    assert "Required interruption phases: cleanup" in text
    assert "Required injection points: before-server-delete" in text
    orphan.assert_called_once_with(base)


def test_live_certification_failure_still_runs_independent_orphan_check(
    live_certify, config_factory, tmp_path, monkeypatch
):
    base = config_factory(action="run", report_dir=tmp_path / "reports")
    settings = live_certify.CertificationSettings(
        successful_runs=1,
        interrupted_runs=1,
        injected_runs=1,
        injection_points=("before-server-delete",),
        interruption_phases=("cleanup",),
        phase_timeout_seconds=60,
        artifact_output_dir=None,
    )
    monkeypatch.setattr(
        live_certify,
        "successful_run",
        mock.Mock(
            return_value=_outcome(
                live_certify,
                "successful",
                "failed-success",
                exit_code=2,
                final_status="ERROR",
            )
        ),
    )
    orphan = mock.Mock(
        return_value=(
            "orphan-check-after-failure",
            live_certify.validate_orphan_sweep(_orphan_payload()),
        )
    )
    monkeypatch.setattr(live_certify, "independent_orphan_verification", orphan)

    summary = live_certify.run_certification(base, settings)

    assert summary["status"] == "FAIL"
    assert summary["errors"][0]["type"] == "CertificationError"
    assert len(summary["runs"]) == 1
    orphan.assert_called_once_with(base)


def test_live_certification_artifact_staging_copies_run_evidence(
    live_certify, config_factory, tmp_path
):
    report_dir = tmp_path / "reports"
    run_dir = report_dir / "runs" / "run-1"
    run_dir.mkdir(parents=True)
    (run_dir / "report.txt").write_text("evidence\n", encoding="utf-8")
    base = config_factory(report_dir=report_dir)
    summary = live_certify._base_summary(base)
    summary.update(
        {
            "status": "PASS",
            "finished_at": "2026-08-28T00:00:00Z",
            "runs": [{"run_id": "run-1", "workflow": "successful"}],
        }
    )
    destination = tmp_path / "artifacts"

    live_certify.stage_artifacts(summary, base, destination)

    assert (destination / "runs" / "run-1" / "report.txt").read_text() == "evidence\n"
    assert (destination / live_certify.SUMMARY_JSON_NAME).is_file()
    assert (destination / live_certify.SUMMARY_TEXT_NAME).is_file()


def test_live_certification_workflow_is_active_guarded_and_retains_evidence():
    active = ROOT / ".github" / "workflows" / "live-certification.yml"
    text = active.read_text(encoding="utf-8")

    assert active.is_file()
    assert "configuration_path" not in text
    assert "CONFIGURATION_PATH" not in text
    assert "${{ runner.temp }}/neutron-flux-live-certification" in text
    assert "DESTROY DISPOSABLE PROJECT" in text
    assert "CERTIFICATION_CLI_ARGUMENTS" in text
    assert "CERTIFICATION_OUTPUT_DIR" in text
    assert "candidate_sha256" in text
    assert "support/scripts/build-release.py" in text
    assert "sha256sum" in text
    assert "CERTIFICATION_CANDIDATE_ARCHIVE=${ARTIFACT_DIR}" in text
    assert "actions/upload-artifact@v4" in text
    assert "if: always()" in text
    assert "runs-on: [self-hosted, openstack-neutron-flux]" in text


def test_live_certification_tests_never_launch_a_real_process(live_certify):
    # The only orchestration test above replaces every live workflow function.
    # This guard makes accidental direct use of invoke/Popen in this test module
    # visible during review.
    source = pathlib.Path(__file__).read_text(encoding="utf-8")
    assert "live_certify." + "invoke(" not in source
    assert "live_certify." + "interrupted_run(" not in source
    assert "subprocess." + "Popen(" not in source
    assert -signal.SIGTERM == -15
