"""Public CLI contract and its runtime/recovery boundaries."""

from __future__ import annotations

import dataclasses
import json
import shlex
import subprocess
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux import cli
from neutron_flux.az_policy import select_neutron_zone
from neutron_flux.config import Config
from neutron_flux.errors import (
    AmbiguousCloudOperationError,
    RetryableMigrationError,
    SuiteError,
)
from neutron_flux.models import ComputeHostInfo, RunCheckpoint
from neutron_flux.openstack import OpenStack
from neutron_flux.operation_recovery import recover_operations
from neutron_flux.replay_plan import RerunResolver, _replay_command
from neutron_flux.state import StateStore
from neutron_flux.utils import iso_utc

from ._shared import _placement_executor, endpoint

BASE = [
    "run",
    "--image",
    "debian-13",
    "--flavor",
    "small",
    "--storage",
    "host",
    "--external-networks",
    "public",
]
FLAGS = {
    "--help",
    "--version",
    "--output-dir",
    "--image",
    "--flavor",
    "--storage",
    "--volume-type",
    "--external-networks",
    "--zones",
    "--target-hosts",
    "--target-aggregates",
    "--target-host-pairs",
    "--repeat",
    "--migration-mode",
    "--live-attempts",
    "--shared-aggregate",
    "--performance-profile",
    "--concurrent-vm-pairs",
    "--concurrent-repeats",
    "--concurrent-duration",
    "--ping-target-ipv4",
    "--ping-target-ipv6",
    "--resume",
    "--keep-resources",
    "--dry-run",
    "--yes",
}
REMOVED = [
    "--access-mode",
    "--config",
    "--set",
    "--network-az",
    "--router-az",
    "--use-neutron-default-azs",
    "--use-cinder-default-az",
    "--ssh-user",
    "--volume-size",
    "--no-performance",
    "--performance-max-paths",
    "--load",
    "--no-load",
    "--settle-scale",
    "--operation-gap-scale",
    "--test",
    "--list-tests",
    "--from-plan",
    "--include-performance-and-migration",
    "--ipv4-targets",
    "--ipv6-targets",
    "--routing-expectation",
    "--junit",
    "--no-junit",
    "--orphan-grace-minutes",
    "--operation-id",
    "--resolution",
    "--evidence-file",
    "--resolution-message",
    "--run-id",
    "--orphans",
    "--include-active",
]


def configured(*extra):
    args = cli.parser().parse_args([*BASE, *extra])
    cli._validate_action_arguments(args)
    return Config.from_args(args)


def test_exactly_26_public_controls():
    options = {
        flag
        for action in cli.parser()._actions
        for flag in action.option_strings
        if flag != "-h"
    }
    assert options == FLAGS
    assert len(options) == 26


@pytest.mark.parametrize("flag", REMOVED)
def test_removed_controls_fail_before_cloud_access(flag):
    with pytest.raises(SystemExit) as exc:
        cli.parser().parse_args(["run", flag])
    assert exc.value.code == 2


@pytest.mark.parametrize("action", cli._ACTIONS)
def test_help_is_action_scoped(action, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.parser().parse_args([action, "--help"])
    assert exc.value.code == 0
    output = capsys.readouterr().out
    allowed = {
        option
        for item in cli.parser()._actions
        if item.dest not in cli._unused_action_options(action)
        for option in item.option_strings
    }
    assert all(flag in output for flag in allowed)
    assert "--config" not in output
    if action == "cleanup":
        assert "--image" not in output


def test_defaults_and_no_implicit_configuration(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "neutron-flux.yml").write_text(
        "storage: nonsense\nperformance: {enabled: false}"
    )
    monkeypatch.setenv("NEUTRON_FLUX_CONFIG", str(tmp_path / "neutron-flux.yml"))
    config = configured()
    assert config.migration_mode == "live-preferred"
    assert config.live_migration_attempts == 5
    assert config.migration_submission_budget == 6
    assert config.cold_migration_fallback and config.live_migration_continuity
    assert config.performance_enabled and config.performance_max_paths == 0
    assert config.junit_report_enabled and config.evidence_enabled
    assert not config.allow_cross_az_volumes
    assert config.ipv4_targets == ["1.1.1.1"]
    assert config.ipv6_targets == ["2606:4700:4700::1111"]
    assert config.repeat_count == 1


@pytest.mark.parametrize("number", [1, 3, 7, 1000, 10**12])
def test_live_attempts_have_no_upper_cap(number):
    config = configured("--live-attempts", str(number))
    assert config.live_migration_attempts == number
    assert config.migration_submission_budget == number + 1


@pytest.mark.parametrize(
    "flags",
    [
        ["--repeat", "0"],
        ["--live-attempts", "0"],
        ["--repeat", "-1"],
        ["--migration-mode", "cold", "--live-attempts", "1"],
        ["--concurrent-repeats", "2"],
        ["--volume-type", "fast"],
        ["--target-hosts", "a", "--zones", "z"],
        ["--ping-target-ipv4", "::1"],
        ["--ping-target-ipv6", "1.1.1.1"],
        ["--external-networks", "a,,b"],
    ],
)
def test_invalid_combinations_fail(flags):
    with pytest.raises(SuiteError):
        configured(*flags)


@pytest.mark.parametrize("action", ["status", "cleanup", "report", "compare", "trend"])
def test_execution_controls_rejected_outside_execution(action):
    with pytest.raises(SuiteError):
        cli._validate_action_arguments(
            cli.parser().parse_args([action, "--repeat", "0"])
        )


def test_concurrent_controls_are_explicit_and_persist():
    config = configured(
        "--concurrent-vm-pairs",
        "1,4,4",
        "--concurrent-repeats",
        "3",
        "--concurrent-duration",
        "20",
    )
    assert config.fabric_scale_enabled
    assert config.fabric_scale_pairs == [1, 4]
    assert (config.fabric_scale_runs, config.fabric_scale_duration_seconds) == (3, 20)
    assert not configured().fabric_scale_enabled


def test_cleanup_defaults_cover_all_runs():
    config = Config.from_args(cli.parser().parse_args(["cleanup", "--dry-run"]))
    assert (
        config.cleanup_orphans
        and config.cleanup_include_active
        and config.cleanup_dry_run
    )
    kept = configured("--keep-resources")
    assert kept.keep_resources and not kept.auto_cleanup_on_failure


@pytest.mark.parametrize("compute", ["bc-van1", "bc-van2", "bc-van3"])
@pytest.mark.parametrize(
    "network_zones",
    [
        {"bc-van1": True, "bc-van2": True, "bc-van3": True},
        {"nova": True},
        {"default": True},
    ],
)
def test_per_zone_network_and_router_placement(
    config_factory, discovery_fixture, compute, network_zones
):
    discovery = dataclasses.replace(
        discovery_fixture,
        network_extensions=["network_availability_zone", "router_availability_zone"],
    )
    inventory = {"network": network_zones, "router": network_zones}
    expected = compute if compute in network_zones else next(iter(network_zones))
    for kind in ("network", "router"):
        assert (
            select_neutron_zone(config_factory(), discovery, inventory, kind, compute)[
                "requested_availability_zone"
            ]
            == expected
        )


def test_router_prefers_compute_match_over_network_fallback(
    config_factory, discovery_fixture
):
    discovery = dataclasses.replace(
        discovery_fixture,
        network_extensions=["network_availability_zone", "router_availability_zone"],
    )
    inventory = {"network": {"nova": True}, "router": {"nova": True, "bc-van1": True}}
    assert (
        select_neutron_zone(
            config_factory(), discovery, inventory, "router", "bc-van1"
        )["requested_availability_zone"]
        == "bc-van1"
    )
    inventory["network"] = {"a": True, "b": True}
    assert (
        select_neutron_zone(
            config_factory(), discovery, inventory, "network", "bc-van1"
        )["requested_availability_zone"]
        is None
    )


@pytest.mark.parametrize("budget", [1, 3, 7])
def test_runtime_honors_every_live_attempt(config_factory, budget):
    source, destination = endpoint("source"), endpoint("destination")
    source.host = destination.host = "a"
    target = ComputeHostInfo("b", "az1", True, True, set(), set())
    builder = SimpleNamespace(
        live_migrate_endpoint=mock.Mock(
            side_effect=RetryableMigrationError("proven failure")
        )
    )
    executor, _, _ = _placement_executor(config_factory(), source, destination, builder)
    result = executor._execute_migration_attempts(
        [(source, destination, target)], migration_kind="live", submission_budget=budget
    )
    assert builder.live_migrate_endpoint.call_count == budget
    assert len(result[2]) == budget


def test_ambiguity_stops_retries_despite_large_budget(config_factory):
    source, destination = endpoint("source"), endpoint("destination")
    target = ComputeHostInfo("b", "az1", True, True, set(), set())
    builder = SimpleNamespace(
        live_migrate_endpoint=mock.Mock(
            side_effect=AmbiguousCloudOperationError("unknown")
        )
    )
    executor, _, _ = _placement_executor(config_factory(), source, destination, builder)
    executor._execute_migration_attempts(
        [(source, destination, target)], migration_kind="live", submission_budget=50
    )
    assert builder.live_migrate_endpoint.call_count == 1


def checkpoint(store, run_id, **metadata):
    now = iso_utc()
    result = RunCheckpoint(
        run_id=run_id,
        state="COMPLETED",
        action="run",
        phase="finished",
        current_batch=None,
        started_at=now,
        updated_at=now,
        last_activity=now,
        completed_test_ids=[],
        failed_test_ids=[],
        pending_test_ids=[],
        active_group_ids=[],
        manifest_path=str(store.run_dir(run_id) / "manifest.json"),
        report_dir=str(store.run_dir(run_id)),
        cleanup_state="COMPLETE",
        metadata=metadata,
    )
    store.save(result)
    return result


def test_repeat_runs_complete_passes_and_stops_on_cleanup_failure(
    tmp_path, monkeypatch
):
    calls = []

    def execute(config, store, run_id, old, **kwargs):
        calls.append((config.repeat_index, run_id, config.resume_run_id))
        result = 1 if config.repeat_index == 1 else 0
        checkpoint(
            store,
            run_id,
            repeat_index=config.repeat_index,
            repeat_next_id=config.repeat_next_id,
            pass_exit_code=result,
        )
        return result

    monkeypatch.setattr(cli, "_execute_locked_action", execute)
    assert (
        cli.main([*BASE, "--repeat", "3", "--output-dir", str(tmp_path / "reports")])
        == 1
    )
    assert [item[0] for item in calls] == [1, 2, 3]
    assert len({item[1] for item in calls}) == 3
    calls.clear()
    monkeypatch.setattr(
        cli,
        "_execute_locked_action",
        lambda config, store, run_id, old, **kw: (
            calls.append(run_id),
            checkpoint(store, run_id),
            3,
        )[-1],
    )
    assert (
        cli.main([*BASE, "--repeat", "3", "--output-dir", str(tmp_path / "failed")])
        == 3
    )
    assert len(calls) == 1


def test_resume_after_crash_between_passes(tmp_path):
    store = StateStore(tmp_path)
    first = checkpoint(
        store,
        "pass1",
        repeat_root_id="pass1",
        repeat_index=1,
        repeat_count=3,
        repeat_next_id="pass2",
        pass_exit_code=1,
    )
    config = configured()
    run_id, current, settings = cli._resume_pass(config, store, first)
    assert (run_id, current, settings.run_id) == ("pass2", None, "pass1")
    assert config.repeat_index == 2 and config.repeat_exit_code == 1
    second = checkpoint(
        store,
        "pass2",
        repeat_root_id="pass1",
        repeat_index=2,
        repeat_next_id="pass3",
        repeat_exit_code=1,
    )
    second.state = "CANCELLED"
    store.save(second)
    run_id, current, _ = cli._resume_pass(config, store, first)
    assert run_id == "pass2" and current.state == "CANCELLED"


def test_report_rerun_uses_only_current_cli():
    payload = {
        "configuration": {
            "image": "debian 13",
            "flavor": "small",
            "storage": "host",
            "external_networks": ["public"],
            "availability_zones": ["bc-van1", "bc-van2"],
            "migration": {"mode": "live-preferred", "live_attempts": 7},
        }
    }
    command = _replay_command(payload)
    args = cli.parser().parse_args(shlex.split(command)[2:])
    cli._validate_action_arguments(args)
    config = Config.from_args(args)
    assert config.live_migration_attempts == 7
    assert config.zone_mode == "both"
    guidance = RerunResolver(payload).for_result({"test_id": "OLD-ID"})
    assert guidance["kind"] == "full-suite" and guidance["exact_fragment"] is None


def recovery_harness(record, result):
    coordinator = mock.Mock()
    pending = [record]
    coordinator.unresolved_records.side_effect = lambda: list(pending)
    coordinator.resolve.side_effect = lambda *a, **kw: pending.clear()
    osc = mock.Mock()
    osc.run.return_value = result
    osc.is_not_found_result.side_effect = OpenStack.is_not_found_result
    return osc, coordinator


def test_recovery_resolves_proven_absent_deletion():
    record = {
        "operation_id": "delete1",
        "command": ["server", "delete", "server-id"],
        "kind": "server-delete",
    }
    osc, coordinator = recovery_harness(
        record, subprocess.CompletedProcess([], 1, "", "No Server found for server-id")
    )
    assert recover_operations(osc, coordinator, mock.Mock()) == []
    assert coordinator.resolve.call_args.kwargs["evidence"]["verified_absent"]
    assert all(call.args[1] == "show" for call in osc.run.call_args_list)


@pytest.mark.parametrize(
    "stderr",
    ["No Server found for nflux-new", "Connection timed out", "Authentication failed"],
)
def test_recovery_never_calls_missing_create_a_failure(stderr):
    record = {
        "operation_id": "create1",
        "command": ["server", "create", "nflux-new"],
        "kind": "server-create",
    }
    osc, coordinator = recovery_harness(
        record, subprocess.CompletedProcess([], 1, "", stderr)
    )
    assert recover_operations(osc, coordinator, mock.Mock()) == ["create1"]
    coordinator.resolve.assert_not_called()


def test_recovery_requires_terminal_correlated_migration():
    record = {
        "operation_id": "migration1",
        "command": ["server", "migrate", "server-id"],
        "kind": "migration",
        "source_host": "a",
        "destination_host": "b",
        "pre_state": {"migration_ids": ["old"]},
    }
    detail = {
        "status": "ACTIVE",
        "OS-EXT-STS:task_state": None,
        "OS-EXT-SRV-ATTR:host": "a",
    }
    osc, coordinator = recovery_harness(
        record, subprocess.CompletedProcess([], 0, json.dumps(detail), "")
    )
    osc.json.return_value = []
    assert recover_operations(osc, coordinator, mock.Mock()) == ["migration1"]
    osc.json.return_value = [
        {"ID": "new", "Source Compute": "a", "Dest Compute": "b", "Status": "error"}
    ]
    assert recover_operations(osc, coordinator, mock.Mock()) == []


def test_all_rejected_migration_destinations_are_not_retried(config_factory):
    source, destination = endpoint("source"), endpoint("destination")
    targets = [
        ComputeHostInfo(host, "az1", True, True, set(), set())
        for host in ("b", "c", "d")
    ]
    builder = SimpleNamespace(
        live_migrate_endpoint=mock.Mock(
            side_effect=RetryableMigrationError("unsuitable", target_unsuitable=True)
        )
    )
    executor, _, _ = _placement_executor(config_factory(), source, destination, builder)
    executor._execute_migration_attempts(
        [(source, destination, target) for target in targets],
        migration_kind="live",
        submission_budget=10,
    )
    assert [
        call.args[1].host for call in builder.live_migrate_endpoint.call_args_list
    ] == ["b", "c", "d"]


@pytest.mark.parametrize("successful", [True, False])
def test_keep_resources_on_success_and_failure(config_factory, successful):
    from neutron_flux.suite import Suite

    suite = object.__new__(Suite)
    suite.config = config_factory(keep_resources=True)
    suite.resources_started = True
    suite.zone_orchestrator = None
    suite.builder = mock.Mock()
    suite.reporter = SimpleNamespace(cleanup_summary={}, resources=[])
    suite.checkpoint = SimpleNamespace(cleanup_state="NOT_STARTED")
    suite._save_checkpoint = mock.Mock()
    suite.cleanup_manager = mock.Mock()
    assert suite.cleanup_if_required(successful) is None
    suite.builder.stop_all_probes.assert_called_once()
    suite.cleanup_manager.cleanup.assert_not_called()
    assert suite.checkpoint.cleanup_state == "RETAINED"


def test_automatic_volume_size_obeys_flavor_and_image(config_factory):
    from neutron_flux.runtime.launch import resolve_launch_selection

    config = config_factory(storage="volume")
    osc = mock.Mock()
    osc.json.side_effect = [
        {
            "id": "image",
            "name": "custom",
            "min_disk": 25,
            "virtual_size": 31 * 1024**3,
            "properties": {"os_admin_user": "clouduser"},
        },
        {"id": "flavor", "name": "large", "disk": 40, "ram": 1024, "vcpus": 1},
    ]
    selection = resolve_launch_selection(config, osc, mock.Mock())
    assert selection.ssh_user == "clouduser"
    assert config.volume_size == 40


def test_cleanup_requires_known_project_before_discovery(config_factory):
    from neutron_flux.cleanup import CleanupManager

    manager = object.__new__(CleanupManager)
    manager.config = config_factory()
    manager.osc = mock.Mock()
    manager.osc.json.return_value = {}
    manager.logger = mock.Mock()
    manager._discover_project_orphans = mock.Mock()
    with pytest.raises(SuiteError, match="project-scoped"):
        manager.cleanup_orphans()
    manager._discover_project_orphans.assert_not_called()


def test_cleanup_inventory_enforces_project_scope(config_factory):
    from neutron_flux.cleanup import CleanupManager

    manager = object.__new__(CleanupManager)
    manager.config = config_factory(cleanup_include_active=True)
    manager.cleanup_project_id = "ours"
    manager.reporter = SimpleNamespace(run_id="cleanup", resources=[])
    manager.osc = mock.Mock()
    manager.logger = mock.Mock()
    name = "nflux-20260930120000-aabbcc-net"

    def inventory(preferred, fallback):
        if preferred[0] in {
            "network",
            "subnet",
            "router",
            "port",
            "floating",
            "security",
        }:
            assert preferred[-2:] == ["--project", "ours"]
            assert fallback[-2:] == ["--project", "ours"]
        if preferred[0] == "network":
            return [
                {"ID": "ours-net", "Name": name, "Project": "ours"},
                {"ID": "theirs-net", "Name": name, "Project": "theirs"},
            ]
        return []

    manager._orphan_list = inventory
    result = manager._discover_project_orphans()
    assert [item["id"] for item in result["candidates"]] == ["ours-net"]
