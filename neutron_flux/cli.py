from __future__ import annotations

import argparse
import pathlib
import signal
import sys
import uuid
from collections.abc import Sequence
from contextlib import nullcontext
from typing import Any

from .cancellation import (
    begin_cleanup_after_cancellation,
    cleanup_in_progress,
    force_cancellation_abort,
    hard_abort_reason,
    hard_abort_requested,
    request_cancellation,
    reset_cancellation,
)
from .cli_help import format_action_help
from .comparison import compare_files
from .config import Config
from .configuration.snapshots import (
    restore_execution_settings,
    validate_saved_execution,
)
from .constants import (
    DISPLAY_VERSION,
    EXIT_EXECUTION_ERROR,
    EXIT_SUCCESS,
    EXIT_UNSUPPORTED_TOPOLOGY,
    TOOL_NAME,
)
from .errors import RunCancelledError, SuiteError, UnsupportedTopologyError
from .log import terminal_text
from .logical_results import grades_execution
from .models import RunCheckpoint
from .offline_reports import regenerate
from .plan_contract import load_plan_contract
from .progress import reporter_progress
from .reporting import Reporter
from .state import StateStore
from .suite import Suite
from .trends import trend_files
from .utils import iso_utc, safe_name, utc_now

_ACTIONS = ("plan", "run", "status", "cleanup", "report", "compare", "trend")

_GLOBAL_HELP = f"""usage: {TOOL_NAME} COMMAND [OPTIONS]

OpenStack network validation. Configuration is CLI-only.

Commands:
  plan       Preview coverage and resource requirements without creating resources
  run        Run the complete suite, write reports, and clean up
  status     Show the latest run checkpoint
  cleanup    Find and remove all Flux-owned resources in the current project
  report     Rebuild reports from results.json
  compare    Compare two results files
  trend      Summarize multiple results files

Use '{TOOL_NAME} COMMAND --help' for the options for that command.
Use --version to display the release.
Full reference: support/docs/CLI-REFERENCE.md
"""


class _ActionAwareArgumentParser(argparse.ArgumentParser):
    def format_help(self) -> str:
        return _GLOBAL_HELP

    def parse_args(self, args=None, namespace=None):
        raw = list(sys.argv[1:] if args is None else args)
        if "-h" in raw or "--help" in raw:
            action = next((item for item in raw if item in _ACTIONS), None)
            self._print_message(
                format_action_help(self, action, _unused_action_options(action))
                if action
                else _GLOBAL_HELP,
                sys.stdout,
            )
            self.exit(0)
        # Offline commands accept several paths.  A shared option between those
        # paths must not make the remaining inputs look like unknown arguments.
        return self.parse_intermixed_args(raw, namespace)


def parser() -> argparse.ArgumentParser:
    result = _ActionAwareArgumentParser(prog=TOOL_NAME, allow_abbrev=False)
    result.add_argument("action", nargs="?", choices=_ACTIONS, default="run")
    result.add_argument(
        "paths", nargs="*", help="input results for report/compare/trend"
    )
    result.add_argument(
        "--version", action="version", version=f"%(prog)s {DISPLAY_VERSION}"
    )
    result.add_argument(
        "--output-dir", metavar="PATH", help="run history or report output directory"
    )
    result.add_argument(
        "--image",
        metavar="IMAGE",
        help="required image name or UUID; SSH account is inferred from image metadata/name",
    )
    result.add_argument(
        "--flavor", metavar="FLAVOR", help="required flavor name or UUID"
    )
    result.add_argument(
        "--storage",
        choices=["host", "volume"],
        help="required root-disk location; volume size is derived from flavor/image requirements",
    )
    result.add_argument(
        "--volume-type",
        metavar="TYPE",
        help="Cinder volume type; requires --storage volume",
    )
    result.add_argument(
        "--external-networks",
        metavar="NETWORK[,NETWORK...]",
        help="required external network names/UUIDs; comma-separated",
    )
    result.add_argument(
        "--zones",
        metavar="ZONE[,ZONE...]|all",
        help="compute AZs; multiple AZs include within- and between-AZ coverage; default: automatic single AZ",
    )
    result.add_argument(
        "--target-hosts",
        metavar="HOST[,HOST...]",
        help="test every unique pair of selected hosts; one host tests same-host placement",
    )
    result.add_argument(
        "--target-aggregates",
        metavar="AGGREGATE[,AGGREGATE...]",
        help="test all pairs of hosts in selected aggregates",
    )
    result.add_argument(
        "--target-host-pairs",
        metavar="HOST:HOST[,HOST:HOST...]",
        help="test each selected pair in its initial placement and the opposite relation; one intra, one inter, one transition",
    )
    result.add_argument(
        "--repeat",
        metavar="N",
        type=int,
        help="complete passes through the selected suite (minimum 1; default: 1)",
    )
    result.add_argument(
        "--migration-mode",
        choices=["live", "cold"],
        help="default: live with cold fallback after proven retryable failures; migrations stay inside a compute AZ",
    )
    result.add_argument(
        "--live-attempts",
        metavar="N",
        type=int,
        help="maximum live submissions per migration, including the first (minimum 1; default: 5; no fixed upper cap)",
    )
    result.add_argument(
        "--shared-aggregate",
        choices=["auto", "required", "ignore"],
        help="migration aggregate-membership policy (default: auto)",
    )
    result.add_argument(
        "--performance-profile",
        choices=["standard", "exhaustive"],
        help="performance sampling depth (default: standard); all eligible paths are measured",
    )
    result.add_argument(
        "--concurrent-vm-pairs",
        metavar="N[,N...]",
        help="enable simultaneous traffic at these VM-pair counts, e.g. 1,2,4 (each 1-32)",
    )
    result.add_argument(
        "--concurrent-repeats",
        metavar="N",
        type=int,
        help="measurements per simultaneous-pair count (1-10; default: 2)",
    )
    result.add_argument(
        "--concurrent-duration",
        metavar="SECONDS",
        type=int,
        help="seconds per simultaneous-traffic measurement (3-120; default: 15)",
    )
    result.add_argument(
        "--ping-target-ipv4",
        metavar="IP",
        help="override the external IPv4 ping destination (default: 1.1.1.1)",
    )
    result.add_argument(
        "--ping-target-ipv6",
        metavar="IP",
        help="override the external IPv6 ping destination (default: 2606:4700:4700::1111)",
    )
    result.add_argument(
        "--resume",
        metavar="RUN_ID",
        help="resume an interrupted run using its recorded settings",
    )
    result.add_argument(
        "--keep-resources",
        action="store_true",
        help="retain test resources after success or failure for inspection",
    )
    result.add_argument(
        "--dry-run",
        action="store_true",
        help="cleanup: preview all Flux-owned resources without changing the cloud",
    )
    result.add_argument(
        "--yes",
        action="store_true",
        help="cleanup: delete all Flux-owned resources without prompting, including active runs and orphans",
    )
    return result


_EXECUTION_OPTIONS = {
    "image",
    "flavor",
    "storage",
    "volume_type",
    "external_networks",
    "zones",
    "target_hosts",
    "target_aggregates",
    "target_host_pairs",
    "repeat",
    "migration_mode",
    "live_attempts",
    "shared_aggregate",
    "performance_profile",
    "concurrent_vm_pairs",
    "concurrent_repeats",
    "concurrent_duration",
    "ping_target_ipv4",
    "ping_target_ipv6",
    "resume",
    "keep_resources",
}


def _provided(args, names):
    return [
        "--" + name.replace("_", "-")
        for name in sorted(names)
        if getattr(args, name, None) is not None and getattr(args, name) is not False
    ]


def _unused_action_options(action):
    excluded = set()
    if action not in {"plan", "run"}:
        excluded.update(_EXECUTION_OPTIONS)
    if action != "run":
        excluded.update({"resume", "keep_resources"})
    if action != "cleanup":
        excluded.update({"dry_run", "yes"})
    return excluded


def _validate_action_arguments(args):
    invalid = _provided(args, _unused_action_options(args.action))
    if invalid:
        raise SuiteError(f"{args.action} does not use: " + ", ".join(invalid))
    if args.action not in {"report", "compare", "trend"} and args.paths:
        raise SuiteError(f"{args.action} does not accept positional paths")
    for name, value in vars(args).items():
        if isinstance(value, str) and not value.strip():
            raise SuiteError(f"--{name.replace('_', '-')} requires a non-empty value")
    if args.resume:
        conflicting = _provided(args, _EXECUTION_OPTIONS - {"resume", "keep_resources"})
        if conflicting:
            raise SuiteError(
                "--resume restores recorded settings and cannot combine with: "
                + ", ".join(conflicting)
            )


def _offline_action(args: argparse.Namespace) -> int | None:
    action = str(args.action)
    if action not in {"report", "compare", "trend"}:
        return None
    paths = list(getattr(args, "paths", []) or [])
    output_dir = getattr(args, "output_dir", None)
    try:
        if action == "report":
            if len(paths) != 1:
                raise SuiteError("report requires exactly one results.json path")
            written = regenerate(
                paths[0],
                destination=output_dir,
                junit=(getattr(args, "junit", None) is not False),
                evidence=True,
            )
        elif action == "compare":
            if len(paths) != 2:
                raise SuiteError(
                    "compare requires baseline and candidate results.json paths"
                )
            written = compare_files(paths[0], paths[1], destination=output_dir)
        else:
            if not paths:
                raise SuiteError(
                    "trend requires at least one results.json file or directory"
                )
            written = trend_files(paths, destination=output_dir)
    except (SuiteError, ValueError, OSError, TypeError) as exc:
        print(
            terminal_text(f"{TOOL_NAME}: {exc}", level="ERROR", stream=sys.stderr),
            file=sys.stderr,
        )
        return EXIT_EXECUTION_ERROR
    for label, path in written.items():
        print(f"{label}: {path}")
    return EXIT_SUCCESS


def _signal_handler(signum: int, _frame: Any) -> None:
    reason = f"received signal {signum}"
    if cleanup_in_progress():
        first_cleanup_signal = request_cancellation(reason)
        force_cancellation_abort(
            f"cleanup interrupted by {'signal' if first_cleanup_signal else 'repeated signal'} {signum}"
        )
        print(
            "\nCleanup abort requested. Neutron Flux is stopping cleanup and "
            "saving the verified state. Some managed resources may remain; "
            "run cleanup again for this run.",
            file=sys.stderr,
            flush=True,
        )
        return
    # The first signal initiates cooperative cancellation and interrupts the
    # main thread. Cleanup begins only after every execution worker has stopped.
    if request_cancellation(reason):
        print(
            "\nCancellation requested. Neutron Flux will stop active tests and "
            "clean up managed resources. Press Ctrl-C again only to abort "
            "cleanup; doing so can leave resources behind.",
            file=sys.stderr,
            flush=True,
        )
        raise KeyboardInterrupt(reason)
    force_cancellation_abort(f"repeated signal {signum}")
    print(
        "\nEmergency abort requested while active workers were stopping. "
        "Neutron Flux will save the durable run state before exiting; managed "
        "resources may remain.",
        file=sys.stderr,
        flush=True,
    )


def _successful_for_cleanup(requested_exit_code: int, reporter: Reporter) -> bool:
    required_validation_failed = any(
        item.status in {"FAIL", "ERROR", "BLOCKED_BY_SETUP_ERROR"}
        for item in reporter.results
    )
    return (
        requested_exit_code == 0
        and not required_validation_failed
        and not reporter.setup_failed
        and reporter.error is None
    )


def _hydrate_config_from_plan(config: Config, plan_path: pathlib.Path) -> None:
    contract, _plan = load_plan_contract(plan_path, prefer_runtime_plan=False)
    snapshot = contract.get("configuration") or {}
    qualification = snapshot.get("qualification") or {}
    performance = snapshot.get("performance") or {}
    concurrent_load = (
        snapshot.get("concurrent_vm_pair_load")
        or snapshot.get("concurrent_load")
        or snapshot.get("fabric")
        or {}
    )
    migration = snapshot.get("migration") or {}
    validate_saved_execution(snapshot)
    config.image = snapshot.get("image")
    config.flavor = snapshot.get("flavor")
    config.storage = snapshot.get("storage")
    config.volume_size = int(snapshot.get("volume_size") or config.volume_size)
    config.volume_type = snapshot.get("volume_type")
    config.external_networks = list(snapshot.get("networks") or [])
    config.availability_zones = list(snapshot.get("availability_zones") or [])
    config.availability_zones_all = bool(snapshot.get("availability_zones_all"))
    config.zone_mode = str(snapshot.get("zone_mode") or config.zone_mode)
    az_settings = snapshot.get("az_placement") or {}
    for key, default in (
        ("allow_cross_az_volumes", False),
        ("allow_cross_az_networking", False),
        ("network_az", None),
        ("router_az", None),
    ):
        value = az_settings.get(key, default)
        if key in config.input_sources and getattr(config, key) != value:
            raise SuiteError(f"The requested {key} does not match the immutable plan")
        setattr(config, key, value)
    config.target_hosts = list(qualification.get("target_hosts") or [])
    config.target_aggregates = list(qualification.get("target_aggregates") or [])
    config.target_host_pairs = [
        (str(item[0]), str(item[1]))
        for item in qualification.get("target_host_pairs") or []
        if isinstance(item, list) and len(item) == 2
    ]
    config.include_same_host = bool(qualification.get("include_same_host"))
    config.qualification_strategy = str(
        qualification.get("strategy") or config.qualification_strategy
    )
    config.qualification_profile = str(
        qualification.get("profile") or config.qualification_profile
    )
    config.qualification_cycles = int(
        qualification.get("cycles") or config.qualification_cycles
    )
    config.performance_profile = str(
        performance.get("profile") or config.performance_profile
    )
    config.performance_enabled = bool(
        performance.get("enabled", config.performance_enabled)
    )
    config.performance_duration_seconds = int(
        performance.get("duration_seconds") or config.performance_duration_seconds
    )
    config.performance_repeats = int(
        performance.get("repeats") or config.performance_repeats
    )
    config.performance_max_paths = int(
        performance.get("max_paths", config.performance_max_paths)
    )
    config.performance_tcp_streams = list(
        performance.get("tcp_streams") or config.performance_tcp_streams
    )
    config.performance_udp_rates_mbps = list(
        performance.get("udp_rates_mbps") or config.performance_udp_rates_mbps
    )
    config.performance_udp_packet_sizes = list(
        performance.get("udp_packet_sizes") or config.performance_udp_packet_sizes
    )
    config.performance_ping_count = int(
        performance.get("ping_count") or config.performance_ping_count
    )
    config.fabric_scale_enabled = bool(
        concurrent_load.get("enabled", config.fabric_scale_enabled)
    )
    config.fabric_scale_pairs = list(
        concurrent_load.get("pairs") or config.fabric_scale_pairs
    )
    config.fabric_scale_runs = int(
        concurrent_load.get("runs") or config.fabric_scale_runs
    )
    config.fabric_scale_duration_seconds = int(
        concurrent_load.get("duration_seconds") or config.fabric_scale_duration_seconds
    )
    config.migration_mode = str(migration.get("mode") or config.migration_mode)
    config.migration_storage = str(migration.get("storage") or config.migration_storage)
    config.live_migration_attempts = int(
        migration.get("live_attempts") or config.live_migration_attempts
    )
    config.cold_migration_fallback = bool(
        migration.get("cold_fallback", config.cold_migration_fallback)
    )
    config.live_migration_continuity = bool(
        migration.get("continuity", config.live_migration_continuity)
    )
    config.compute_host_connectivity_enabled = bool(migration.get("enabled", True))
    # Plans predating the recorded aggregate policy used the strict default.
    config.require_shared_compute_aggregate = migration.get(
        "require_shared_aggregate", True
    )
    restore_execution_settings(config, snapshot.get("execution_settings"))


def _new_run_id(prefix: str) -> str:
    return f"{safe_name(prefix, 16)}-{utc_now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"


def _resume_pass(config: Config, store: StateStore, checkpoint: RunCheckpoint):
    """Follow durable pass links; a crash between passes never repeats a pass."""
    visited = set()
    while True:
        if checkpoint.run_id in visited:
            raise SuiteError("Invalid repeat history: cyclic pass links")
        visited.add(checkpoint.run_id)
        metadata = checkpoint.metadata
        validate_saved_execution(metadata)
        config.repeat_index = int(metadata.get("repeat_index", 1))
        config.repeat_root_id = str(metadata.get("repeat_root_id") or checkpoint.run_id)
        config.repeat_next_id = metadata.get("repeat_next_id")
        config.repeat_exit_code = int(metadata.get("repeat_exit_code", 0))
        finished = (
            checkpoint.state == "COMPLETED"
            and not checkpoint.pending_test_ids
            and metadata.get("pass_exit_code") in {0, 1}
        )
        if not finished or not config.repeat_next_id:
            config.resume_run_id = checkpoint.run_id
            return checkpoint.run_id, checkpoint, checkpoint
        config.repeat_exit_code = max(
            config.repeat_exit_code, int(metadata["pass_exit_code"])
        )
        next_id = str(config.repeat_next_id)
        if store.state_path(next_id).is_file():
            checkpoint = store.load(next_id)
            continue
        config.repeat_index += 1
        config.repeat_next_id = None
        config.resume_run_id = None
        return next_id, None, checkpoint


def _new_checkpoint(
    config: Config, run_id: str, action: str, reporter: Reporter
) -> RunCheckpoint:
    now = iso_utc()
    return RunCheckpoint(
        run_id=run_id,
        state="INITIALIZING",
        action=action,
        phase="initializing",
        current_batch=None,
        started_at=now,
        updated_at=now,
        last_activity=now,
        completed_test_ids=[],
        failed_test_ids=[],
        pending_test_ids=[],
        active_group_ids=[],
        manifest_path=str(reporter.manifest_path),
        report_dir=str(reporter.run_dir),
        cleanup_state="NOT_STARTED",
        metadata={
            "repeat_count": config.repeat_count,
            "repeat_index": config.repeat_index,
            "repeat_root_id": config.repeat_root_id or run_id,
            "repeat_next_id": config.repeat_next_id,
            "repeat_exit_code": config.repeat_exit_code,
        },
    )


def _reconcile_final_checkpoint(checkpoint: RunCheckpoint, reporter: Reporter) -> None:
    """Synchronize terminal checkpoint IDs after report finalization.

    Reporter.finalize() materializes terminal rows for every planned check.
    Recompute both sides of the completed/pending partition together so a
    failed run cannot retain stale pending IDs that now have synthetic results.
    """
    completed = [item.test_id for item in reporter.results]
    checkpoint.metadata["test_progress"] = reporter_progress(reporter)
    completed_set = set(completed)
    checkpoint.completed_test_ids = completed
    checkpoint.failed_test_ids = [
        item.test_id
        for item in reporter.results
        if grades_execution(item) and item.status in {"FAIL", "ERROR"}
    ]
    plan = getattr(reporter, "plan", None)
    if plan is not None:
        checkpoint.pending_test_ids = [
            item.id
            for item in plan.tests
            if hasattr(item, "id") and item.id not in completed_set
        ]
    else:
        checkpoint.pending_test_ids = [
            item for item in checkpoint.pending_test_ids if item not in completed_set
        ]


def _execute_locked_action(
    config: Config,
    state_store: StateStore,
    run_id: str,
    checkpoint: RunCheckpoint | None,
    *,
    reopen_existing_run: bool,
) -> int:
    reporter_kwargs: dict[str, Any] = {
        "load_existing": reopen_existing_run,
    }
    if checkpoint is not None and reopen_existing_run:
        reporter_kwargs["identity"] = checkpoint.metadata
    reporter = Reporter(config, run_id, **reporter_kwargs)
    if checkpoint is None:
        checkpoint = _new_checkpoint(config, run_id, config.action, reporter)
        identity = {
            "run_tag": getattr(reporter, "run_tag", None),
            "name_prefix": getattr(reporter, "name_prefix", None),
        }
        checkpoint.metadata.update(
            {key: value for key, value in identity.items() if value}
        )
        state_store.save(checkpoint)
    else:
        checkpoint.action = config.action
        if config.resume_run_id:
            checkpoint.state = "INITIALIZING"
            checkpoint.phase = "resume-initializing"
            checkpoint.cleanup_state = "NOT_STARTED"
            checkpoint.error = None
        else:
            checkpoint.state = "CLEANING"
        state_store.save(checkpoint)

    reporter.logger.section(f"{TOOL_NAME} {DISPLAY_VERSION}: {config.action}")
    reporter.logger.log(f"Run ID: {run_id}")
    if config.repeat_count > 1:
        reporter.logger.log(f"Suite pass {config.repeat_index}/{config.repeat_count}")
    reporter.logger.log(f"Run directory: {reporter.run_dir}")
    reporter.logger.log("Configuration: CLI plus built-in optional defaults")
    if config.action in {"plan", "run"}:
        if config.migration_mode == "cold-only":
            migration_note = "cold-only"
        else:
            live_transport = (
                "block" if config.effective_migration_storage == "host" else "shared"
            )
            migration_note = f"{config.migration_mode}/{live_transport}"
        volume_note = ""
        if config.storage == "volume":
            volume_note = (
                f", volume_size={config.volume_size} GiB"
                f", volume_type={config.volume_type or 'Cinder default'}"
            )
        reporter.logger.log(
            f"Launch inputs: image={config.image}, flavor={config.flavor}, "
            f"storage={config.storage}, migration={migration_note}, "
            f"networks={','.join(config.external_networks)}, "
            f"zones={'all' if config.availability_zones_all else ','.join(config.availability_zones) or 'automatic-single'}, "
            f"zone_mode={config.zone_mode}{volume_note}"
        )
    elif config.action == "cleanup" and config.cleanup_orphans:
        mode = "dry-run" if config.cleanup_dry_run else "delete"
        reporter.logger.log(
            "Cleanup scope: cloud-discovered Neutron Flux resources in the "
            f"current project; mode={mode}; includes all runs and orphans"
        )

    suite = Suite(config, reporter, state_store, checkpoint)
    managed_signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    previous_signal_handlers = {
        signum: signal.getsignal(signum) for signum in managed_signals
    }
    reset_cancellation()
    if config.action == "cleanup":
        begin_cleanup_after_cancellation()
    for signum in managed_signals:
        signal.signal(signum, _signal_handler)

    requested_exit_code = 0
    successful_execution = False
    try:
        requested_exit_code = suite.execute()
        successful_execution = _successful_for_cleanup(requested_exit_code, reporter)
    except (KeyboardInterrupt, RunCancelledError) as exc:
        reporter.interrupted = True
        reporter.cancellation_reason = str(exc)
        reporter.logger.log(f"Run cancelled by operator: {exc}", "WARNING")
        # Execution workers have now unwound and joined. Permit only the
        # controlled terminal-state publication and cleanup phase to issue new
        # OpenStack commands.
        begin_cleanup_after_cancellation()
        # Materialize every missing planned row before any best-effort cloud
        # terminal-state publication.  Reporting must remain complete even when
        # the control plane is unhealthy during cancellation.
        if hasattr(suite, "record_cancelled_results"):
            suite.record_cancelled_results(str(exc))
        if hasattr(suite, "mark_terminal_state"):
            suite.mark_terminal_state("CANCELLED", str(exc))
        checkpoint.state = "CANCELLED"
        checkpoint.error = str(exc)
        requested_exit_code = 130
    except UnsupportedTopologyError as exc:
        reporter.set_error(exc)
        reporter.logger.log(str(exc), "ERROR")
        if hasattr(suite, "mark_terminal_state"):
            suite.mark_terminal_state("FAILED", str(exc))
        checkpoint.state = "FAILED"
        checkpoint.error = str(exc)
        requested_exit_code = EXIT_UNSUPPORTED_TOPOLOGY
    except Exception as exc:
        reporter.set_error(exc)
        reporter.logger.log(str(exc), "ERROR")
        if hasattr(suite, "mark_terminal_state"):
            suite.mark_terminal_state("FAILED", str(exc))
        checkpoint.state = "FAILED"
        checkpoint.error = str(exc)
        requested_exit_code = EXIT_EXECUTION_ERROR
    finally:
        hard_abort = hard_abort_requested()
        if hard_abort:
            reporter.interrupted = True
            reporter.cancellation_reason = (
                reporter.cancellation_reason
                or "emergency hard abort requested by a repeated signal"
            )
            checkpoint.state = "CANCELLED"
            checkpoint.error = reporter.cancellation_reason
            requested_exit_code = 130
        try:
            if config.action == "run" and not hard_abort:
                begin_cleanup_after_cancellation()
                complete = suite.cleanup_if_required(successful_execution)
                if complete is False:
                    requested_exit_code = 3
            elif config.action == "run" and hard_abort:
                unverified = sum(
                    item.delete_status not in {"deleted", "already-absent"}
                    for item in reporter.resources
                )
                reporter.cleanup_summary.update(
                    {
                        "attempted": False,
                        "complete": None,
                        "interrupted": True,
                        "interruption_reason": hard_abort_reason(),
                        "scope_verification": "not-started-after-emergency-abort",
                        "unverified_resource_count": unverified,
                    }
                )
        except RunCancelledError as cleanup_exc:
            reporter.cleanup_summary.update(
                {
                    "attempted": True,
                    "complete": None,
                    "interrupted": True,
                    "interruption_reason": str(cleanup_exc),
                    "scope_verification": "interrupted-before-final-verification",
                    "unverified_resource_count": sum(
                        item.delete_status not in {"deleted", "already-absent"}
                        for item in reporter.resources
                    ),
                }
            )
            checkpoint.state = "CLEANUP_INCOMPLETE"
            checkpoint.cleanup_state = "INCOMPLETE"
        except Exception as cleanup_exc:
            reporter.cleanup_summary["attempted"] = True
            reporter.cleanup_summary["complete"] = False
            reporter.cleanup_summary["errors"].append(str(cleanup_exc))
            marker = f"cleanup-verification:unknown:{cleanup_exc}"
            if marker not in reporter.cleanup_summary["leftovers"]:
                reporter.cleanup_summary["leftovers"].append(marker)
            reporter.logger.log(f"Cleanup failed: {cleanup_exc}", "ERROR")
            checkpoint.state = "CLEANUP_INCOMPLETE"
            checkpoint.cleanup_state = "INCOMPLETE"
            requested_exit_code = 3
        hard_abort = hard_abort_requested()
        if hard_abort:
            reporter.interrupted = True
            reporter.cancellation_reason = (
                reporter.cancellation_reason or hard_abort_reason()
            )
            reporter.cleanup_summary.setdefault("interrupted", True)
            reporter.cleanup_summary.setdefault(
                "interruption_reason", hard_abort_reason()
            )
            checkpoint.metadata["cleanup_interrupted"] = True
            checkpoint.metadata["cleanup_interruption_reason"] = hard_abort_reason()
            if reporter.cleanup_summary.get("attempted") or int(
                reporter.cleanup_summary.get("unverified_resource_count") or 0
            ):
                checkpoint.cleanup_state = "INCOMPLETE"
            checkpoint.error = reporter.cancellation_reason
            requested_exit_code = 130
        requested_exit_code = reporter.finalize(requested_exit_code)
        if checkpoint.cleanup_state == "INCOMPLETE":
            checkpoint.state = "CLEANUP_INCOMPLETE"
        elif reporter.interrupted:
            checkpoint.state = "CANCELLED"
        elif reporter.error or reporter.setup_failed:
            checkpoint.state = "FAILED"
            if not checkpoint.error and reporter.setup_failures:
                checkpoint.error = str(
                    reporter.setup_failures[0].get("message") or "setup failed"
                )
        else:
            checkpoint.state = "COMPLETED"
        checkpoint.metadata["pass_exit_code"] = requested_exit_code
        checkpoint.phase = "finished"
        checkpoint.current_batch = None
        _reconcile_final_checkpoint(checkpoint, reporter)
        if checkpoint.state == "COMPLETED":
            checkpoint.pending_test_ids = []
            checkpoint.active_group_ids = []
        checkpoint.last_activity = iso_utc()
        checkpoint.updated_at = checkpoint.last_activity
        if hasattr(suite, "sync_zone_checkpoints"):
            suite.sync_zone_checkpoints()
        state_store.save(checkpoint)
        if checkpoint.state == "CANCELLED" and hasattr(suite, "mark_terminal_state"):
            suite.mark_terminal_state("CANCELLED", checkpoint.error)
        reset_cancellation()
        for signum, handler in previous_signal_handlers.items():
            signal.signal(signum, handler)
    return requested_exit_code


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        _validate_action_arguments(args)
    except SuiteError as exc:
        print(
            terminal_text(f"{TOOL_NAME}: {exc}", level="ERROR", stream=sys.stderr),
            file=sys.stderr,
        )
        return EXIT_EXECUTION_ERROR
    offline_result = _offline_action(args)
    if offline_result is not None:
        return offline_result
    try:
        config = Config.from_args(args)
        state_store = StateStore(config.report_dir)
        if config.action == "status":
            checkpoint = state_store.latest()
            for path, error in state_store.corrupt_state_files:
                print(
                    terminal_text(
                        f"{TOOL_NAME}: warning: skipped corrupt checkpoint {path}: {error}",
                        level="WARNING",
                        stream=sys.stderr,
                    ),
                    file=sys.stderr,
                )
            print(terminal_text(state_store.print_status(checkpoint)))
            return 0
    except SuiteError as exc:
        print(
            terminal_text(f"{TOOL_NAME}: {exc}", level="ERROR", stream=sys.stderr),
            file=sys.stderr,
        )
        return (
            EXIT_UNSUPPORTED_TOPOLOGY
            if isinstance(exc, UnsupportedTopologyError)
            else EXIT_EXECUTION_ERROR
        )

    resume_existing_run = config.action == "run" and bool(config.resume_run_id)
    reopen_existing_run = (
        config.action == "cleanup" and not config.cleanup_orphans
    ) or resume_existing_run
    try:
        cloud_operation_lock = getattr(state_store, "cloud_operation_lock", None)
        if config.action in {"run", "cleanup"} and callable(cloud_operation_lock):
            cloud_operation_context = cloud_operation_lock()
        else:
            cloud_operation_context = nullcontext()
        with cloud_operation_context:
            if resume_existing_run:
                checkpoint = state_store.load(str(config.resume_run_id))
                validate_saved_execution(checkpoint.metadata)
                if checkpoint.action != "run":
                    raise SuiteError(
                        f"Run {checkpoint.run_id} was created by {checkpoint.action}, not run"
                    )
                run_id, checkpoint, settings_checkpoint = _resume_pass(
                    config, state_store, checkpoint
                )
                if (
                    checkpoint is not None
                    and checkpoint.state == "COMPLETED"
                    and not checkpoint.pending_test_ids
                ):
                    raise SuiteError(
                        f"Run {checkpoint.run_id} and its requested passes are already complete"
                    )
                if not settings_checkpoint.plan_path:
                    raise SuiteError(
                        f"Run {settings_checkpoint.run_id} has no saved immutable plan to resume"
                    )
                _hydrate_config_from_plan(
                    config, pathlib.Path(settings_checkpoint.plan_path)
                )
                if args.keep_resources:
                    config.keep_resources = True
                    config.auto_cleanup_on_failure = False
                reopen_existing_run = checkpoint is not None
                resume_existing_run = checkpoint is not None
            elif reopen_existing_run:
                checkpoint = state_store.latest(
                    incomplete_only=True,
                )
                run_id = checkpoint.run_id
            else:
                run_prefix = (
                    "orphan-cleanup" if config.cleanup_orphans else config.prefix
                )
                run_id = _new_run_id(run_prefix)
                checkpoint = None
            while True:
                if config.action == "run":
                    config.repeat_root_id = config.repeat_root_id or run_id
                    if (
                        config.repeat_index < config.repeat_count
                        and not config.repeat_next_id
                    ):
                        config.repeat_next_id = _new_run_id(config.prefix)
                with state_store.lock(run_id):
                    if resume_existing_run:
                        checkpoint = state_store.load(run_id)
                    result = _execute_locked_action(
                        config,
                        state_store,
                        run_id,
                        checkpoint,
                        reopen_existing_run=reopen_existing_run,
                    )
                if config.action != "run" or config.repeat_count == 1:
                    return result
                completed = state_store.load(run_id)
                config.repeat_exit_code = max(config.repeat_exit_code, result)
                if (
                    result not in {0, 1}
                    or completed.state != "COMPLETED"
                    or not config.repeat_next_id
                ):
                    return config.repeat_exit_code
                run_id = config.repeat_next_id
                config.repeat_index += 1
                config.repeat_next_id = None
                config.resume_run_id = None
                checkpoint = None
                resume_existing_run = reopen_existing_run = False
    except (SuiteError, OSError) as exc:
        print(
            terminal_text(f"{TOOL_NAME}: {exc}", level="ERROR", stream=sys.stderr),
            file=sys.stderr,
        )
        return EXIT_EXECUTION_ERROR
