#!/usr/bin/env python3
"""Destructive live certification harness for Neutron Flux.

The harness requires an operator-supplied Neutron Flux configuration and
already-loaded OpenStack credentials. It runs complete, interrupted, and
failure-injected workflows, verifies cleanup after every workflow, then ends
with an independent project-scoped orphan dry run.

Nothing in this module is exercised against OpenStack by the offline unit
suite. Unit tests mock process execution and validate the configuration,
point registry, evidence, and workflow contract only.
"""

import ast
import dataclasses
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterable, Mapping
from types import SimpleNamespace
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from neutron_flux.check_ledger import check_ledger  # noqa: E402
from neutron_flux.config import Config  # noqa: E402
from neutron_flux.constants import (  # noqa: E402
    DISPLAY_VERSION,
    RELEASE_IDENTIFIER,
    RELEASE_STAGE,
    RESULT_STATUSES,
    VERSION,
)
from neutron_flux.coverage_ledger import _outcome as coverage_outcome  # noqa: E402
from neutron_flux.logical_results import grades_execution  # noqa: E402
from neutron_flux.result_contract import validate_result_contract  # noqa: E402

SUMMARY_JSON_NAME = "live-certification-summary.json"
SUMMARY_TEXT_NAME = "live-certification-summary.txt"

# Every default below is a literal failure-injection call in current production
# code. validate_injection_points() also discovers those calls from the source
# tree before any cloud operation, so a renamed or removed point cannot be
# silently skipped by live certification.
BASE_INJECTION_POINTS = (
    "after-controller-create",
    "after-server-active",
    "before-probe-service",
    "before-fip-association",
    "before-fip-withdraw",
    "before-router-interface-withdraw",
    "before-server-stop",
    "before-server-delete",
)
LIVE_MIGRATION_INJECTION_POINTS = (
    "before-live-migration",
    "after-live-handoff",
)

# These are durable root-checkpoint phases, not log strings. tests-complete is
# the boundary between test execution and final cleanup/report publication.
KNOWN_INTERRUPTION_PHASES = frozenset(
    {
        "controller-bootstrap",
        "availability-zone-bootstrap",
        "group-local",
        "cross-topology",
        "tests-complete",
        "cleanup",
        "cleanup-complete",
    }
)


class CertificationError(RuntimeError):
    """A live-certification contract was not satisfied."""


@dataclasses.dataclass(frozen=True)
class CertificationSettings:
    successful_runs: int
    interrupted_runs: int
    injected_runs: int
    injection_points: tuple[str, ...]
    interruption_phases: tuple[str, ...]
    phase_timeout_seconds: int
    artifact_output_dir: pathlib.Path | None
    release_identity: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class RunOutcome:
    workflow: str
    run_id: str
    exit_code: int
    cleanup_state: str | None
    checkpoint_state: str | None
    final_status: str | None
    injection_point: str | None = None
    interruption_phase: str | None = None
    target_reached: bool | None = None
    signal_sent: str | None = None
    recovery_cleanup_exit_code: int | None = None
    recovery_cleanup_run_id: str | None = None
    evidence_verified: bool = False
    evidence_errors: list[str] = dataclasses.field(default_factory=list)

    def as_dict(self, report_dir: pathlib.Path) -> dict[str, Any]:
        return {
            **dataclasses.asdict(self),
            "run_dir": str(report_dir / "runs" / self.run_id),
        }


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _csv_values(value: str | None) -> tuple[str, ...]:
    if value is None:
        return ()
    return tuple(
        dict.fromkeys(item.strip() for item in value.split(",") if item.strip())
    )


def _positive_integer(name: str, default: int, environ: Mapping[str, str]) -> int:
    raw = environ.get(name, str(default))
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise CertificationError(
            f"{name} must be a positive integer; received {raw!r}"
        ) from exc
    if value < 1:
        raise CertificationError(f"{name} must be a positive integer; received {value}")
    return value


def _uses_multi_zone_root(config: Config) -> bool:
    return bool(
        config.availability_zones_all
        or config.availability_zones
        or config.zone_mode in {"cross-zone", "both"}
    )


def default_injection_points(config: Config) -> tuple[str, ...]:
    points = list(BASE_INJECTION_POINTS)
    if (
        config.compute_host_connectivity_enabled
        and config.migration_mode != "cold-only"
    ):
        points.extend(LIVE_MIGRATION_INJECTION_POINTS)
    return tuple(points)


def default_interruption_phases(config: Config) -> tuple[str, ...]:
    if _uses_multi_zone_root(config):
        return ("availability-zone-bootstrap", "tests-complete", "cleanup")
    return ("controller-bootstrap", "group-local", "tests-complete", "cleanup")


def discover_literal_injection_points(
    source_root: pathlib.Path | None = None,
) -> frozenset[str]:
    """Return statically named injection points called by production modules."""

    root = source_root or (ROOT / "neutron_flux")
    points: set[str] = set()
    for path in sorted(root.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError) as exc:
            raise CertificationError(
                f"Could not inspect failure-injection source {path}: {exc}"
            ) from exc
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            argument: ast.expr | None = None
            if isinstance(node.func, ast.Name) and node.func.id == "inject_failure":
                if len(node.args) >= 2:
                    argument = node.args[1]
            elif (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "_inject_failure"
                and node.args
            ):
                argument = node.args[0]
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                points.add(argument.value)
    return frozenset(points)


def validate_injection_points(
    points: Iterable[str], available: Iterable[str] | None = None
) -> tuple[str, ...]:
    selected = tuple(
        dict.fromkeys(str(point).strip() for point in points if str(point).strip())
    )
    if not selected:
        raise CertificationError(
            "At least one required failure-injection point is needed"
        )
    if "*" in selected:
        raise CertificationError(
            "Wildcard failure injection is not a certifiable point selection"
        )
    actual = frozenset(available or discover_literal_injection_points())
    stale = sorted(set(selected) - actual)
    if stale:
        raise CertificationError(
            "Certification references failure-injection point(s) absent from current "
            "production code: " + ", ".join(stale)
        )
    return selected


def validate_interruption_phases(phases: Iterable[str]) -> tuple[str, ...]:
    selected = tuple(
        dict.fromkeys(str(phase).strip() for phase in phases if str(phase).strip())
    )
    if not selected:
        raise CertificationError("At least one required interruption phase is needed")
    unknown = sorted(set(selected) - KNOWN_INTERRUPTION_PHASES)
    if unknown:
        raise CertificationError(
            "Unknown root-checkpoint interruption phase(s): " + ", ".join(unknown)
        )
    return selected


def release_identity_from_environment(
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    values = os.environ if environ is None else environ
    archive = str(values.get("CERTIFICATION_CANDIDATE_ARCHIVE") or "").strip()
    digest = str(values.get("CERTIFICATION_CANDIDATE_SHA256") or "").strip().lower()
    if bool(archive) != bool(digest):
        raise CertificationError(
            "CERTIFICATION_CANDIDATE_ARCHIVE and "
            "CERTIFICATION_CANDIDATE_SHA256 must be supplied together"
        )
    if digest and re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise CertificationError(
            "CERTIFICATION_CANDIDATE_SHA256 must contain exactly 64 hexadecimal characters"
        )
    candidate_verified = False
    archive_path: pathlib.Path | None = None
    if archive:
        archive_path = pathlib.Path(archive).expanduser().resolve()
        if not archive_path.is_file():
            raise CertificationError(
                f"CERTIFICATION_CANDIDATE_ARCHIVE is not a regular file: {archive_path}"
            )
        archive_hash = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        if archive_hash != digest:
            raise CertificationError(
                "Candidate archive SHA-256 mismatch: "
                f"expected {digest}, observed {archive_hash}"
            )
        candidate_verified = True
    if str(values.get("GITHUB_ACTIONS") or "").strip().lower() == "true":
        if not archive or not digest or not candidate_verified:
            raise CertificationError(
                "GitHub live certification requires a deterministic candidate archive "
                "whose SHA-256 was verified before execution"
            )
    return {
        "package_version": VERSION,
        "release_identifier": RELEASE_IDENTIFIER,
        "release_stage": RELEASE_STAGE,
        "display_version": DISPLAY_VERSION,
        "github_repository": values.get("GITHUB_REPOSITORY"),
        "github_sha": values.get("GITHUB_SHA"),
        "github_ref": values.get("GITHUB_REF"),
        "github_run_id": values.get("GITHUB_RUN_ID"),
        "candidate_archive": archive_path.name if archive_path else None,
        "candidate_sha256": digest or None,
        "candidate_hash_verified": candidate_verified,
    }


def settings_from_environment(
    config: Config, environ: Mapping[str, str] | None = None
) -> CertificationSettings:
    values = os.environ if environ is None else environ
    explicit_points = _csv_values(values.get("CERTIFICATION_INJECTION_POINTS"))
    points = validate_injection_points(
        explicit_points or default_injection_points(config)
    )
    explicit_phases = _csv_values(values.get("CERTIFICATION_INTERRUPTION_PHASES"))
    phases = validate_interruption_phases(
        explicit_phases or default_interruption_phases(config)
    )
    successful_runs = _positive_integer("SUCCESS_RUNS", 10, values)
    interrupted_runs = _positive_integer("INTERRUPTED_RUNS", 10, values)
    injected_runs = _positive_integer("INJECTED_RUNS", 10, values)
    phase_timeout = _positive_integer(
        "INTERRUPTION_PHASE_TIMEOUT_SECONDS", 14400, values
    )
    if interrupted_runs < len(phases):
        raise CertificationError(
            f"INTERRUPTED_RUNS={interrupted_runs} cannot exercise every required "
            f"phase once; at least {len(phases)} runs are required"
        )
    if injected_runs < len(points):
        raise CertificationError(
            f"INJECTED_RUNS={injected_runs} cannot exercise every required injection "
            f"point once; at least {len(points)} runs are required"
        )
    output_text = str(values.get("CERTIFICATION_OUTPUT_DIR") or "").strip()
    output_dir = (
        pathlib.Path(output_text).expanduser().resolve() if output_text else None
    )
    release_identity = release_identity_from_environment(values)
    if not release_identity.get("candidate_hash_verified"):
        raise CertificationError(
            "Live certification requires the exact candidate archive and its "
            "verified SHA-256; set CERTIFICATION_CANDIDATE_ARCHIVE and "
            "CERTIFICATION_CANDIDATE_SHA256"
        )
    return CertificationSettings(
        successful_runs=successful_runs,
        interrupted_runs=interrupted_runs,
        injected_runs=injected_runs,
        injection_points=points,
        interruption_phases=phases,
        phase_timeout_seconds=phase_timeout,
        artifact_output_dir=output_dir,
        release_identity=release_identity,
    )


def _scheduled(values: tuple[str, ...], count: int) -> list[str]:
    return [values[index % len(values)] for index in range(count)]


def resolved_mapping(
    config: Config, failure_injection: str | None = None
) -> dict[str, Any]:
    """Project a validated Config back into a complete effective run mapping.

    Cleanup retention is deliberately overridden: certification always enables
    cleanup on failure and never retains disposable resources.
    """

    # This is a fixed scheduler safety invariant, not a YAML setting. Refuse a
    # synthetic or future Config value that cannot be represented instead of
    # silently resetting it when the temporary configuration is loaded.
    if config.max_active_endpoints != 2:
        raise CertificationError(
            "Certification cannot serialize max_active_endpoints="
            f"{config.max_active_endpoints}; current Config requires the fixed value 2"
        )

    zones: str | list[str]
    if config.availability_zones_all:
        zones = "all"
    else:
        zones = list(config.availability_zones)
    network: dict[str, Any] = {
        "management_cidr": config.mgmt_cidr,
        "include_no_routing_group_controls": (config.include_no_routing_group_controls),
        "no_routing_group_ipv4_cidr": config.no_routing_group_ipv4_cidr,
        "no_routing_group_ipv6_cidr": config.no_routing_group_ipv6_cidr,
    }
    if config.external_networks:
        network["external_networks"] = list(config.external_networks)
    elif config.exclude_external_networks:
        network["exclude_external_networks"] = list(config.exclude_external_networks)
    if config.routing_contracts:
        network["routing_contracts"] = [
            {
                "source": str(item["source"]),
                "destination": str(item["destination"]),
                "family": item.get("family")
                if item.get("family") is not None
                else "any",
                "expectation": str(item["expectation"]),
                "protocols": [str(item["protocol"])],
                "direction": "forward",
                "reason": str(item.get("reason") or ""),
            }
            for item in config.routing_contracts
        ]

    mapping: dict[str, Any] = {
        "version": 1,
        "pacing": {
            "quiet_period_scale": config.quiet_period_scale,
            "operation_gap_scale": config.operation_gap_scale,
        },
        "image": config.image,
        "flavor": config.flavor,
        "storage": config.storage,
        "guest": {"ssh_user": config.ssh_user},
        "general": {
            "prefix": config.prefix,
            "report_dir": str(config.report_dir),
        },
        "placement": {
            "availability_zones": zones,
            "zone_mode": config.zone_mode,
            "allow_cross_az_volumes": config.allow_cross_az_volumes,
            "allow_cross_az_networking": config.allow_cross_az_networking,
            "network_az": config.network_az,
            "router_az": config.router_az,
            "compute_host_connectivity": {
                "enabled": config.compute_host_connectivity_enabled,
                "require_shared_aggregate": (config.require_shared_compute_aggregate),
                "max_migration_attempts": config.compute_migration_max_attempts,
                "migration": {
                    "mode": config.migration_mode,
                    "storage": config.migration_storage,
                    "live_attempts": config.live_migration_attempts,
                    "cold_fallback": config.cold_migration_fallback,
                    "continuity": config.live_migration_continuity,
                },
            },
        },
        "qualification": {
            "include_same_host": config.include_same_host,
            "strategy": config.qualification_strategy,
            "profile": config.qualification_profile,
            "cycles": config.qualification_cycles,
        },
        "network": network,
        "probes": {
            "ipv4_targets": list(config.ipv4_targets),
            "ipv6_targets": list(config.ipv6_targets),
            "tcp_port": config.tcp_port,
            "udp_port": config.udp_port,
        },
        "timeouts": {
            "ssh": config.ssh_timeout,
            "resource": config.resource_timeout,
            "convergence": config.convergence_timeout,
            "convergence_interval": config.convergence_interval,
            "progress_interval": config.progress_interval,
        },
        "cleanup": {
            "keep_resources": False,
            "on_failure": True,
            "orphan_grace_minutes": config.orphan_grace_minutes,
            "timeouts": dict(config.cleanup_timeouts),
        },
        "performance": {
            "profile": config.performance_profile,
            "enabled": config.performance_enabled,
            "duration_seconds": config.performance_duration_seconds,
            "repeats": config.performance_repeats,
            "max_paths": config.performance_max_paths,
            "tcp_streams": list(config.performance_tcp_streams),
            "udp_rates_mbps": list(config.performance_udp_rates_mbps),
            "udp_packet_sizes": list(config.performance_udp_packet_sizes),
            "udp_calibration": {
                "enabled": config.performance_udp_adaptive_calibration,
                "min_rate_mbps": config.performance_udp_calibration_min_rate_mbps,
                "max_attempts": config.performance_udp_calibration_max_attempts,
                "backoff_factor": config.performance_udp_calibration_backoff_factor,
            },
            "ping_count": config.performance_ping_count,
            "ping_warmup_count": config.performance_ping_warmup_count,
            "enforce_thresholds": config.performance_enforce_thresholds,
            "thresholds": {
                "udp_sender_achievement_pct": (
                    config.performance_udp_sender_achievement_threshold_pct
                ),
                "udp_loss_pct": config.performance_udp_loss_threshold_pct,
                "udp_reordering_pct": (config.performance_udp_reordering_threshold_pct),
                "loaded_latency_ratio": (
                    config.performance_loaded_latency_ratio_threshold
                ),
                "directional_asymmetry_pct": (
                    config.performance_asymmetry_threshold_pct
                ),
                "repeatability_variation_pct": (
                    config.performance_variation_threshold_pct
                ),
            },
            "concurrent_vm_pair_load": {
                "enabled": config.fabric_scale_enabled,
                "pairs": list(config.fabric_scale_pairs),
                "runs": config.fabric_scale_runs,
                "duration_seconds": config.fabric_scale_duration_seconds,
            },
        },
        "reporting": {
            "html": config.html_report_enabled,
            "junit": config.junit_report_enabled,
            "evidence": config.evidence_enabled,
        },
        "testing": {"failure_injection": failure_injection},
    }
    if config.storage == "volume":
        mapping["volume"] = {
            "size": config.volume_size,
            "type": config.volume_type,
        }
    qualification = mapping["qualification"]
    if config.target_hosts:
        qualification["target_hosts"] = list(config.target_hosts)
    if config.target_aggregates:
        qualification["target_aggregates"] = list(config.target_aggregates)
    if config.target_host_pairs:
        qualification["target_host_pairs"] = [
            f"{source}:{destination}"
            for source, destination in config.target_host_pairs
        ]
    if config.test_ids:
        mapping["execution"] = {
            "tests": list(config.test_ids),
            "include_derived_tests": config.include_derived_tests,
        }
    return mapping


def write_config(base: Config, failure_injection: str | None = None) -> pathlib.Path:
    handle = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", prefix="neutron-flux-cert-", delete=False
    )
    with handle:
        snapshot = dataclasses.asdict(
            dataclasses.replace(
                base,
                failure_injection=failure_injection,
                keep_resources=False,
                auto_cleanup_on_failure=True,
            )
        )
        json.dump(snapshot, handle, indent=2, default=str)
        handle.write("\n")
    return pathlib.Path(handle.name)


def load_worker_snapshot(path: pathlib.Path) -> Config:
    values = json.loads(path.read_text())
    for key in ("report_dir",):
        if values.get(key) is not None:
            values[key] = pathlib.Path(values[key])
    values["target_host_pairs"] = [
        tuple(pair) for pair in values.get("target_host_pairs", [])
    ]
    return Config(**values)


def worker_command(path: pathlib.Path, *arguments: str) -> list[str]:
    return [
        sys.executable,
        str(pathlib.Path(__file__).resolve()),
        "--certification-worker",
        str(path),
        *arguments,
    ]


def worker_main(path: pathlib.Path, arguments: list[str]) -> int:
    from unittest.mock import patch

    from neutron_flux import cli

    base = load_worker_snapshot(path)

    def configure(args):
        return dataclasses.replace(
            base,
            action=args.action,
            cleanup_orphans=args.action == "cleanup",
            cleanup_include_active=True,
            cleanup_assume_yes=args.action == "cleanup",
            cleanup_dry_run=args.dry_run,
        )

    with patch.object(Config, "from_args", side_effect=configure):
        return cli.main(arguments)


def state_files(report_dir: pathlib.Path) -> set[pathlib.Path]:
    return set((report_dir / "runs").glob("*/state.json"))


def new_run_id(
    report_dir: pathlib.Path,
    before: set[pathlib.Path],
    *,
    timeout_seconds: int = 60,
) -> str:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        created = state_files(report_dir) - before
        if len(created) == 1:
            return next(iter(created)).parent.name
        if len(created) > 1:
            raise CertificationError(
                "More than one new root checkpoint appeared during one certification "
                "workflow; use an isolated report directory"
            )
        time.sleep(0.25)
    raise CertificationError(
        f"Neutron Flux did not create a root checkpoint within {timeout_seconds} seconds"
    )


def _read_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise CertificationError(f"{label} was not produced: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CertificationError(f"Could not read {label} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise CertificationError(f"{label} must contain a JSON object: {path}")
    return value


def checkpoint_for(report_dir: pathlib.Path, run_id: str) -> dict[str, Any]:
    return _read_json(report_dir / "runs" / run_id / "state.json", "run checkpoint")


def results_for(report_dir: pathlib.Path, run_id: str) -> dict[str, Any]:
    return _read_json(
        report_dir / "runs" / run_id / "results.json", "structured results"
    )


def report_text(report_dir: pathlib.Path, run_id: str) -> str:
    path = report_dir / "runs" / run_id / "report.txt"
    if not path.is_file():
        raise CertificationError(f"Run {run_id} did not produce {path}")
    return path.read_text(encoding="utf-8")


def invoke(
    config_path: pathlib.Path, *arguments: str
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    return subprocess.run(
        worker_command(config_path, *arguments),
        cwd=ROOT,
        env=env,
        text=True,
        check=False,
    )


def validate_run_evidence(
    report_dir: pathlib.Path,
    run_id: str,
    *,
    successful: bool,
    recovery_cleanup_run_id: str | None = None,
) -> None:
    """Validate durable evidence, including lane checkpoints and check coverage."""
    run_dir = report_dir / "runs" / run_id
    checkpoint = checkpoint_for(report_dir, run_id)
    payload = results_for(report_dir, run_id)
    cleanup_payload = (
        results_for(report_dir, recovery_cleanup_run_id)
        if recovery_cleanup_run_id
        else payload
    )
    cleanup = cleanup_payload.get("cleanup")
    if not isinstance(cleanup, dict) or cleanup.get("complete") is not True:
        raise CertificationError(f"Run {run_id} lacks verified complete cleanup")
    if any(
        cleanup.get(key)
        for key in (
            "errors",
            "leftovers",
            "unresolved_operations",
            "unverified_resource_count",
            "interrupted",
        )
    ):
        raise CertificationError(
            f"Run {run_id} has cleanup errors or unresolved resources"
        )
    resources = cleanup_payload.get("resources")
    if not isinstance(resources, list) or any(
        not isinstance(item, dict)
        or item.get("delete_status") not in {"deleted", "already-absent"}
        for item in resources
    ):
        raise CertificationError(f"Run {run_id} has unverified resource deletion")
    operations = cleanup_payload.get("cloud_operations")
    if (
        not isinstance(operations, dict)
        or operations.get("unresolved_count") != 0
        or any(
            operations.get(key)
            for key in ("unresolved_operation_ids", "external_unresolved_operations")
        )
    ):
        raise CertificationError(f"Run {run_id} has unresolved cloud operations")
    if recovery_cleanup_run_id:
        recovery = checkpoint_for(report_dir, recovery_cleanup_run_id)
        if (
            recovery.get("state") != "COMPLETED"
            or recovery.get("cleanup_state") != "COMPLETE"
        ):
            raise CertificationError(f"Run {run_id} recovery checkpoint is incomplete")
        validate_orphan_sweep(cleanup_payload)
    terminal = (
        {"COMPLETED"}
        if successful
        else {"COMPLETED", "FAILED", "CANCELLED", "CLEANUP_INCOMPLETE", "INTERRUPTED"}
    )
    if checkpoint.get("state") not in terminal:
        raise CertificationError(f"Run {run_id} root checkpoint is not terminal")
    if not recovery_cleanup_run_id and checkpoint.get("cleanup_state") != "COMPLETE":
        raise CertificationError(f"Run {run_id} root cleanup checkpoint is incomplete")
    plan = payload.get("plan")
    if not isinstance(plan, dict):
        if successful:
            raise CertificationError(f"Run {run_id} lacks its approved plan")
        plan = {}
    expected_zones = {
        str(zone)
        for spec in plan.get("tests", [])
        for zone in [spec.get("metadata", {}).get("availability_zone")]
        if zone
    }
    observed_zones: set[str] = set()
    for path in sorted((run_dir / "zones").glob("*/state/runs/*/state.json")):
        lane = _read_json(path, "zone checkpoint")
        zone = str(lane.get("metadata", {}).get("availability_zone") or "")
        if zone in observed_zones or not zone:
            raise CertificationError(f"Run {run_id} has ambiguous zone checkpoints")
        observed_zones.add(zone)
        if lane.get("state") not in terminal:
            raise CertificationError(
                f"Run {run_id} zone {zone} checkpoint is not terminal"
            )
        if not recovery_cleanup_run_id and lane.get("cleanup_state") != "COMPLETE":
            raise CertificationError(f"Run {run_id} zone {zone} cleanup is incomplete")
        if successful and (
            lane.get("pending_test_ids")
            or lane.get("failed_test_ids")
            or lane.get("error")
        ):
            raise CertificationError(
                f"Run {run_id} zone {zone} has unfinished or failed checks"
            )
    if not expected_zones <= observed_zones:
        raise CertificationError(f"Run {run_id} is missing zone checkpoints")
    if not successful:
        return
    if (
        checkpoint.get("pending_test_ids")
        or checkpoint.get("failed_test_ids")
        or checkpoint.get("error")
    ):
        raise CertificationError(
            f"Run {run_id} root checkpoint has unfinished or failed checks"
        )
    if payload.get("error") or payload.get("setup_failures"):
        raise CertificationError(f"Run {run_id} reported an execution or setup error")
    checks = plan.get("checks")
    ledger = payload.get("planned_check_ledger")
    if not isinstance(checks, list) or not checks or not isinstance(ledger, list):
        raise CertificationError(f"Run {run_id} lacks planned-check coverage")
    expected = [item.get("id") for item in checks]
    actual = [item.get("id") for item in ledger]
    if (
        None in expected
        or len(set(expected)) != len(expected)
        or len(set(actual)) != len(actual)
        or set(expected) != set(actual)
    ):
        raise CertificationError(
            f"Run {run_id} planned-check coverage is incomplete or duplicated"
        )
    results = payload.get("results")
    if not isinstance(results, list) or not results:
        raise CertificationError(f"Run {run_id} lacks executed results")
    result_ids = {item.get("test_id") for item in results}
    if len(result_ids) != len(results) or any(
        item.get("status") not in RESULT_STATUSES
        or (
            grades_execution(item)
            and item.get("status") not in {"PASS", "NOT_APPLICABLE"}
        )
        for item in results
    ):
        raise CertificationError(
            f"Run {run_id} has failed, blocked, unverified or duplicate results"
        )
    bindings = {spec["id"]: spec.get("metadata") or {} for spec in plan["tests"]}
    for result in results:
        contract = result.get("contract")
        if contract not in (None, {}):
            try:
                validate_result_contract(
                    contract,
                    status=result.get("status"),
                    expected=result.get("expected"),
                    observed=result.get("observed"),
                    authoritative=result.get("authoritative"),
                )
            except (TypeError, ValueError) as exc:
                raise CertificationError(
                    f"Run {run_id} has an inconsistent result contract: {exc}"
                ) from exc
        if grades_execution(result):
            continue
        approved = bindings.get(result["test_id"], {})
        details = result.get("details") or {}
        if (
            approved.get("check_sample") is not True
            or approved.get("planned_check_id") not in expected
            or details.get("planned_check_id") != approved.get("planned_check_id")
        ):
            raise CertificationError(f"Run {run_id} has unapproved supporting evidence")
    for row in ledger:
        evidence = row.get("evidence_ids") or []
        if (
            row.get("outcome") not in {"PASSED", "INAPPLICABLE"}
            or not row.get("reason")
            or not set(evidence) <= result_ids
        ):
            raise CertificationError(
                f"Run {run_id} has invalid evidence for check {row.get('id')}"
            )
    resolution_path = run_dir / "check-outcomes.json"
    resolutions = (
        _read_json(resolution_path, "saved check outcomes")
        if resolution_path.is_file()
        else {}
    )
    replay = SimpleNamespace(
        plan=SimpleNamespace(
            checks=checks,
            tests=[
                SimpleNamespace(id=spec["id"], metadata=spec.get("metadata") or {})
                for spec in plan["tests"]
            ],
        ),
        results=[SimpleNamespace(**row) for row in results],
        _lock=threading.RLock(),
        _check_resolutions=resolutions,
    )
    try:
        recomputed = {row["id"]: row for row in check_ledger(replay)}
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise CertificationError(
            f"Run {run_id} has malformed check evidence: {exc}"
        ) from exc
    if any(
        any(
            row.get(key) != recomputed[row["id"]].get(key)
            for key in ("outcome", "reason", "result_id", "evidence_ids")
        )
        for row in ledger
    ):
        raise CertificationError(
            f"Run {run_id} has inconsistent check-to-result bindings"
        )
    coverage = payload.get("coverage_ledger")
    if not isinstance(coverage, list) or not coverage:
        raise CertificationError(f"Run {run_id} has incomplete execution coverage")
    result_outcomes = {
        item["test_id"]: coverage_outcome(
            SimpleNamespace(**{"expected": None, "details": {}, **item})
        )
        for item in results
    }
    if (
        {row.get("result_id") for row in coverage} != result_ids
        or len(coverage) != len(result_ids)
        or any(
            row.get("outcome") != result_outcomes.get(row.get("result_id"))
            for row in coverage
        )
    ):
        raise CertificationError(f"Run {run_id} has inconsistent execution coverage")


def _outcome(
    workflow: str,
    report_dir: pathlib.Path,
    run_id: str,
    exit_code: int,
    **values: Any,
) -> RunOutcome:
    checkpoint = checkpoint_for(report_dir, run_id)
    try:
        payload = results_for(report_dir, run_id)
    except CertificationError:
        payload = {}
    run_value = payload.get("run")
    run = run_value if isinstance(run_value, dict) else {}
    evidence_errors: list[str] = []
    recovery_run_id = values.get("recovery_cleanup_run_id")
    try:
        validate_run_evidence(
            report_dir,
            run_id,
            successful=workflow == "successful",
            recovery_cleanup_run_id=recovery_run_id,
        )
    except CertificationError as exc:
        evidence_errors.append(str(exc))
    cleanup_state: str | None
    if recovery_run_id and not evidence_errors:
        cleanup_state = "COMPLETE"
    else:
        cleanup_state = str(checkpoint.get("cleanup_state") or "") or None
    return RunOutcome(
        workflow=workflow,
        run_id=run_id,
        exit_code=exit_code,
        cleanup_state=cleanup_state,
        evidence_verified=not evidence_errors,
        evidence_errors=evidence_errors,
        checkpoint_state=str(checkpoint.get("state") or "") or None,
        final_status=str(run.get("final_status") or "") or None,
        **values,
    )


def successful_run(base: Config) -> RunOutcome:
    config_path = write_config(base)
    before = state_files(base.report_dir)
    try:
        result = invoke(config_path, "run")
        run_id = new_run_id(base.report_dir, before)
        return _outcome("successful", base.report_dir, run_id, result.returncode)
    finally:
        config_path.unlink(missing_ok=True)


def _wait_for_phase(
    report_dir: pathlib.Path,
    run_id: str,
    process: subprocess.Popen[Any],
    target_phase: str,
    timeout_seconds: int,
) -> bool:
    state_path = report_dir / "runs" / run_id / "state.json"
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline and process.poll() is None:
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            state = {}
        if state.get("phase") == target_phase:
            return True
        time.sleep(0.25)
    return False


def interrupted_run(
    base: Config, target_phase: str, *, phase_timeout_seconds: int
) -> RunOutcome:
    config_path = write_config(base)
    before = state_files(base.report_dir)
    env = os.environ.copy()
    process = subprocess.Popen(worker_command(config_path, "run"), cwd=ROOT, env=env)
    run_id: str | None = None
    reached = False
    signal_name: str | None = None
    recovery_code: int | None = None
    recovery_run_id: str | None = None
    try:
        run_id = new_run_id(base.report_dir, before)
        reached = _wait_for_phase(
            base.report_dir,
            run_id,
            process,
            target_phase,
            phase_timeout_seconds,
        )
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            signal_name = "SIGTERM"
        try:
            exit_code = process.wait(timeout=base.resource_timeout + 600)
        except subprocess.TimeoutExpired:
            process.kill()
            signal_name = "SIGKILL_AFTER_TIMEOUT"
            exit_code = process.wait(timeout=60)

        checkpoint = checkpoint_for(base.report_dir, run_id)
        if checkpoint.get("cleanup_state") != "COMPLETE":
            before_cleanup = state_files(base.report_dir)
            cleanup = invoke(config_path, "cleanup")
            recovery_code = cleanup.returncode
            recovery_run_id = new_run_id(base.report_dir, before_cleanup)
        return _outcome(
            "interrupted",
            base.report_dir,
            run_id,
            exit_code,
            interruption_phase=target_phase,
            target_reached=reached,
            signal_sent=signal_name,
            recovery_cleanup_exit_code=recovery_code,
            recovery_cleanup_run_id=recovery_run_id,
        )
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=60)
        config_path.unlink(missing_ok=True)


def _contains_injection_evidence(value: Any, marker: str) -> bool:
    if isinstance(value, str):
        return marker in value
    if isinstance(value, dict):
        return any(
            _contains_injection_evidence(item, marker) for item in value.values()
        )
    if isinstance(value, list):
        return any(_contains_injection_evidence(item, marker) for item in value)
    return False


def injected_run(base: Config, point: str) -> RunOutcome:
    config_path = write_config(base, point)
    cleanup_config_path = write_config(base)
    before = state_files(base.report_dir)
    recovery_code: int | None = None
    recovery_run_id: str | None = None
    try:
        result = invoke(config_path, "run")
        run_id = new_run_id(base.report_dir, before)
        marker = f"Injected failure at {point}"
        text = report_text(base.report_dir, run_id)
        try:
            payload = results_for(base.report_dir, run_id)
        except CertificationError:
            payload = {}
        reached = marker in text or _contains_injection_evidence(payload, marker)
        checkpoint = checkpoint_for(base.report_dir, run_id)
        if checkpoint.get("cleanup_state") != "COMPLETE":
            before_cleanup = state_files(base.report_dir)
            cleanup = invoke(cleanup_config_path, "cleanup")
            recovery_code = cleanup.returncode
            recovery_run_id = new_run_id(base.report_dir, before_cleanup)
        return _outcome(
            "injected",
            base.report_dir,
            run_id,
            result.returncode,
            injection_point=point,
            target_reached=reached,
            recovery_cleanup_exit_code=recovery_code,
            recovery_cleanup_run_id=recovery_run_id,
        )
    finally:
        config_path.unlink(missing_ok=True)
        cleanup_config_path.unlink(missing_ok=True)


def validate_successful_outcome(outcome: RunOutcome) -> None:
    if outcome.exit_code != 0:
        raise CertificationError(
            f"Successful workflow {outcome.run_id} exited {outcome.exit_code}"
        )
    if not outcome.evidence_verified or outcome.evidence_errors:
        raise CertificationError(
            f"Run {outcome.run_id} evidence validation failed: "
            + "; ".join(outcome.evidence_errors or ["evidence was not verified"])
        )
    if outcome.cleanup_state != "COMPLETE":
        raise CertificationError(
            f"Successful workflow {outcome.run_id} did not complete cleanup"
        )
    if outcome.final_status not in {"PASS", "PASS WITH WARNINGS"}:
        raise CertificationError(
            f"Successful workflow {outcome.run_id} reported {outcome.final_status!r}"
        )


def validate_interrupted_outcome(outcome: RunOutcome) -> None:
    if not outcome.evidence_verified or outcome.evidence_errors:
        raise CertificationError(
            f"Run {outcome.run_id} evidence validation failed: "
            + "; ".join(outcome.evidence_errors or ["evidence was not verified"])
        )
    if not outcome.target_reached:
        raise CertificationError(
            f"Interrupted workflow {outcome.run_id} never reached required phase "
            f"{outcome.interruption_phase}"
        )
    if not outcome.signal_sent:
        raise CertificationError(
            f"Interrupted workflow {outcome.run_id} received no termination signal"
        )
    if outcome.exit_code not in {3, 130, -signal.SIGTERM}:
        raise CertificationError(
            f"Interrupted workflow {outcome.run_id} exited {outcome.exit_code}; "
            "the requested cancellation was not observed"
        )
    if outcome.recovery_cleanup_exit_code not in {None, 0}:
        raise CertificationError(
            f"Interrupted recovery cleanup for {outcome.run_id} exited "
            f"{outcome.recovery_cleanup_exit_code}"
        )
    if outcome.cleanup_state != "COMPLETE":
        raise CertificationError(
            f"Interrupted workflow {outcome.run_id} did not recover to complete cleanup"
        )


def validate_injected_outcome(outcome: RunOutcome) -> None:
    if not outcome.evidence_verified or outcome.evidence_errors:
        raise CertificationError(
            f"Run {outcome.run_id} evidence validation failed: "
            + "; ".join(outcome.evidence_errors or ["evidence was not verified"])
        )
    if not outcome.target_reached:
        raise CertificationError(
            f"Required injection point {outcome.injection_point} was not reached by "
            f"workflow {outcome.run_id}"
        )
    if outcome.exit_code not in {1, 2, 3}:
        raise CertificationError(
            f"Injected workflow {outcome.run_id} exited {outcome.exit_code}; "
            "the injected failure did not produce a failure exit"
        )
    if outcome.recovery_cleanup_exit_code not in {None, 0}:
        raise CertificationError(
            f"Injected recovery cleanup for {outcome.run_id} exited "
            f"{outcome.recovery_cleanup_exit_code}"
        )
    if outcome.cleanup_state != "COMPLETE":
        raise CertificationError(
            f"Injected workflow {outcome.run_id} did not recover to complete cleanup"
        )


def validate_orphan_sweep(payload: Mapping[str, Any]) -> dict[str, int]:
    cleanup = payload.get("cleanup")
    if not isinstance(cleanup, dict):
        raise CertificationError("Orphan verification results lack cleanup evidence")
    sweep = cleanup.get("orphan_sweep")
    if not isinstance(sweep, dict):
        raise CertificationError(
            "Orphan verification results lack orphan_sweep evidence"
        )
    counts: dict[str, int] = {}
    for key in (
        "stale_resources_remaining",
        "protected_resources_remaining",
        "unknown_resources_remaining",
        "project_resources_remaining",
    ):
        value = sweep.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise CertificationError(
                f"Orphan verification field cleanup.orphan_sweep.{key} is invalid: "
                f"{value!r}"
            )
        counts[key] = value
    if any(counts[key] for key in counts):
        raise CertificationError(
            "Independent orphan verification found managed project resources: "
            f"stale={counts['stale_resources_remaining']}, "
            f"protected={counts['protected_resources_remaining']}, "
            f"unknown={counts['unknown_resources_remaining']}, "
            f"project_total={counts['project_resources_remaining']}"
        )
    return counts


def independent_orphan_verification(base: Config) -> tuple[str, dict[str, int]]:
    config_path = write_config(base)
    before = state_files(base.report_dir)
    try:
        result = invoke(config_path, "cleanup", "--dry-run")
        run_id = new_run_id(base.report_dir, before)
        if result.returncode != 0:
            raise CertificationError(
                f"Independent orphan dry run {run_id} exited {result.returncode}"
            )
        counts = validate_orphan_sweep(results_for(base.report_dir, run_id))
        return run_id, counts
    finally:
        config_path.unlink(missing_ok=True)


def _base_summary(base: Config) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "tool": "Neutron Flux",
        "release_identity": release_identity_from_environment({}),
        "status": "RUNNING",
        "started_at": _utc_now(),
        "finished_at": None,
        "report_dir": str(base.report_dir),
        "effective_configuration": resolved_mapping(base),
        "safety_overrides": {
            "cleanup.keep_resources": False,
            "cleanup.on_failure": True,
        },
        "settings": {},
        "resume_validation": {
            "tested": False,
            "reason": "Interrupted workflows verify cleanup recovery; execution resume requires a separate live acceptance run.",
        },
        "runs": [],
        "orphan_verification": None,
        "errors": [],
    }


def _summary_text(summary: Mapping[str, Any]) -> str:
    settings = (
        summary.get("settings") if isinstance(summary.get("settings"), dict) else {}
    )
    identity = (
        summary.get("release_identity")
        if isinstance(summary.get("release_identity"), dict)
        else {}
    )
    lines = [
        "Neutron Flux live certification summary",
        "=" * 40,
        f"Status: {summary.get('status')}",
        f"Release: {identity.get('release_identifier')}",
        f"Package version: {identity.get('package_version')}",
        f"GitHub ref: {identity.get('github_ref')}",
        f"GitHub SHA: {identity.get('github_sha')}",
        f"Candidate archive: {identity.get('candidate_archive')}",
        f"Candidate SHA-256: {identity.get('candidate_sha256')}",
        f"Candidate hash verified: {identity.get('candidate_hash_verified')}",
        f"Started: {summary.get('started_at')}",
        f"Finished: {summary.get('finished_at')}",
        f"Report directory: {summary.get('report_dir')}",
        "Execution resume: NOT TESTED by this harness; separate live acceptance is required.",
        f"Successful runs required: {settings.get('successful_runs', 'unknown')}",
        f"Interrupted runs required: {settings.get('interrupted_runs', 'unknown')}",
        f"Failure-injected runs required: {settings.get('injected_runs', 'unknown')}",
        "Required interruption phases: "
        + ", ".join(settings.get("interruption_phases") or []),
        "Required injection points: "
        + ", ".join(settings.get("injection_points") or []),
        "Runs:",
    ]
    for run in summary.get("runs") or []:
        target = (
            run.get("injection_point") or run.get("interruption_phase") or "complete"
        )
        lines.append(
            f"- {run.get('workflow')}: {run.get('run_id')} target={target} "
            f"reached={run.get('target_reached')} exit={run.get('exit_code')} "
            f"cleanup={run.get('cleanup_state')}"
        )
    orphan = summary.get("orphan_verification")
    if isinstance(orphan, dict):
        lines.append(
            "Independent orphan verification: "
            f"run={orphan.get('run_id')} "
            f"stale={orphan.get('stale_resources_remaining')} "
            f"protected={orphan.get('protected_resources_remaining')} "
            f"unknown={orphan.get('unknown_resources_remaining')}"
        )
    errors = summary.get("errors") or []
    if errors:
        lines.append("Errors:")
        for error in errors:
            lines.append(f"- {error.get('type')}: {error.get('message')}")
    return "\n".join(lines) + "\n"


def write_summary(
    summary: dict[str, Any], destination: pathlib.Path
) -> tuple[pathlib.Path, pathlib.Path]:
    destination.mkdir(parents=True, exist_ok=True)
    json_path = destination / SUMMARY_JSON_NAME
    text_path = destination / SUMMARY_TEXT_NAME
    json_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    text_path.write_text(_summary_text(summary), encoding="utf-8")
    return json_path, text_path


def stage_artifacts(
    summary: dict[str, Any], base: Config, destination: pathlib.Path
) -> None:
    """Copy run evidence into a workflow-owned artifact directory."""

    destination.mkdir(parents=True, exist_ok=True)
    runs_destination = destination / "runs"
    run_ids = [
        str(item[key])
        for item in summary.get("runs") or []
        for key in ("run_id", "recovery_cleanup_run_id")
        if item.get(key)
    ]
    orphan = summary.get("orphan_verification")
    if isinstance(orphan, dict) and orphan.get("run_id"):
        run_ids.append(str(orphan["run_id"]))
    if destination.resolve() != base.report_dir.resolve():
        for run_id in dict.fromkeys(run_ids):
            source = base.report_dir / "runs" / run_id
            if source.is_dir():
                shutil.copytree(source, runs_destination / run_id, dirs_exist_ok=True)
    write_summary(summary, destination)


def _record_error(summary: dict[str, Any], exc: BaseException) -> None:
    summary["errors"].append(
        {
            "type": type(exc).__name__,
            "message": str(exc),
            "recorded_at": _utc_now(),
        }
    )


def run_certification(base: Config, settings: CertificationSettings) -> dict[str, Any]:
    summary = _base_summary(base)
    if settings.release_identity:
        summary["release_identity"] = dict(settings.release_identity)
    summary["settings"] = {
        "successful_runs": settings.successful_runs,
        "interrupted_runs": settings.interrupted_runs,
        "injected_runs": settings.injected_runs,
        "interruption_phases": list(settings.interruption_phases),
        "injection_points": list(settings.injection_points),
        "phase_timeout_seconds": settings.phase_timeout_seconds,
        "artifact_output_dir": (
            str(settings.artifact_output_dir) if settings.artifact_output_dir else None
        ),
    }
    try:
        for index in range(settings.successful_runs):
            outcome = successful_run(base)
            summary["runs"].append(outcome.as_dict(base.report_dir))
            validate_successful_outcome(outcome)
            print(
                f"[certify] successful {index + 1}/{settings.successful_runs}: "
                f"{outcome.run_id}"
            )

        phases = _scheduled(settings.interruption_phases, settings.interrupted_runs)
        for index, phase in enumerate(phases, start=1):
            outcome = interrupted_run(
                base,
                phase,
                phase_timeout_seconds=settings.phase_timeout_seconds,
            )
            summary["runs"].append(outcome.as_dict(base.report_dir))
            validate_interrupted_outcome(outcome)
            print(
                f"[certify] interrupted {index}/{settings.interrupted_runs}: "
                f"{outcome.run_id}; phase={phase}; "
                f"reached={outcome.target_reached}"
            )

        points = _scheduled(settings.injection_points, settings.injected_runs)
        for index, point in enumerate(points, start=1):
            outcome = injected_run(base, point)
            summary["runs"].append(outcome.as_dict(base.report_dir))
            validate_injected_outcome(outcome)
            print(
                f"[certify] injected {index}/{settings.injected_runs}: "
                f"{outcome.run_id}; point={point}; "
                f"reached={outcome.target_reached}"
            )
    except Exception as exc:
        _record_error(summary, exc)
    finally:
        try:
            run_id, counts = independent_orphan_verification(base)
            summary["orphan_verification"] = {"run_id": run_id, **counts}
        except Exception as exc:
            _record_error(summary, exc)
        summary["finished_at"] = _utc_now()
        summary["status"] = "PASS" if not summary["errors"] else "FAIL"
        write_summary(summary, base.report_dir)
        if settings.artifact_output_dir is not None:
            try:
                stage_artifacts(summary, base, settings.artifact_output_dir)
            except Exception as exc:
                _record_error(summary, exc)
                summary["status"] = "FAIL"
                write_summary(summary, base.report_dir)
                write_summary(summary, settings.artifact_output_dir)
    return summary


def main() -> int:
    try:
        from neutron_flux.cli import _validate_action_arguments, parser

        arguments = parser().parse_args(["run", *sys.argv[1:]])
        _validate_action_arguments(arguments)
        base = Config.from_args(arguments)
        if base.repeat_count != 1:
            raise CertificationError(
                "Certification uses its own workflow repeats; omit --repeat"
            )
        settings = settings_from_environment(base)
    except Exception as exc:
        print(f"[certify] configuration error: {exc}", file=sys.stderr)
        return 2

    summary = run_certification(base, settings)
    print(f"[certify] summary: {base.report_dir / SUMMARY_TEXT_NAME}")
    if settings.artifact_output_dir is not None:
        print(f"[certify] staged evidence: {settings.artifact_output_dir}")
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--certification-worker":
        raise SystemExit(worker_main(pathlib.Path(sys.argv[2]), sys.argv[3:]))
    raise SystemExit(main())
