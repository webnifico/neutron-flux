"""Cleanup inventory, repeated launch identity, resume locking and migration recovery."""

from __future__ import annotations

import json
import subprocess
from contextlib import contextmanager
from unittest import mock

import pytest

from neutron_flux import cli
from neutron_flux.cleanup import CleanupManager
from neutron_flux.config import Config
from neutron_flux.errors import (
    AmbiguousCloudOperationError,
    SuiteError,
    UnsafeMigrationStateError,
)
from neutron_flux.models import ComputeHostInfo, MigrationResult
from neutron_flux.openstack import OpenStack
from neutron_flux.reporting import Reporter, ResourceTracker
from neutron_flux.resources import ResourceBuilder
from neutron_flux.runtime.launch import resolve_launch_selection
from neutron_flux.state import StateStore

from ._shared import _placement_executor, endpoint
from .test_cli_contract import BASE, checkpoint


@pytest.mark.parametrize("payload", [None, {}, [None], ["invalid row"]])
def test_cleanup_requires_authoritative_inventory(tmp_path, payload):
    config = Config.from_args(
        cli.parser().parse_args(["cleanup", "--yes", "--output-dir", str(tmp_path)])
    )
    reporter = Reporter(config, "orphan-cleanup-20260930010101-a1b2c3")
    osc = OpenStack(reporter.logger)

    def response(*args, **kwargs):
        if args[:2] == ("token", "issue"):
            return subprocess.CompletedProcess(
                args, 0, '{"project_id":"project-a"}', ""
            )
        if args[:2] == ("volume", "list"):
            if payload is None:
                return subprocess.CompletedProcess(
                    args, 2, "", "'volume list' is not an openstack command"
                )
            return subprocess.CompletedProcess(args, 0, json.dumps(payload), "")
        return subprocess.CompletedProcess(args, 0, "[]", "")

    osc.run = mock.Mock(side_effect=response)
    manager = CleanupManager(osc, reporter, ResourceTracker(reporter), config)
    with pytest.raises(SuiteError, match="inventory"):
        manager.cleanup_orphans()
    assert reporter.cleanup_summary["complete"] is not True
    assert all("delete" not in call.args for call in osc.run.call_args_list)


def test_cleanup_accepts_basic_inventory_after_unsupported_long(config_factory):
    config = config_factory()
    reporter = mock.Mock()
    osc = mock.Mock()
    osc.json.side_effect = [None, [{"ID": "network-id", "Name": "network"}]]
    manager = CleanupManager(osc, reporter, mock.Mock(), config)
    assert manager._orphan_list(["network", "list", "--long"], ["network", "list"]) == [
        {"ID": "network-id", "Name": "network"}
    ]


@pytest.mark.parametrize("uuid_selector", ["image", "flavor", "both"])
def test_launch_preserves_image_and_flavor_selectors_across_passes(
    config_factory, uuid_selector
):
    image_id = "155f0344-d49b-4326-b899-d42d5da730d5"
    flavor_id = "00aee815-0b3f-4a2e-bbda-3253db396da0"
    config = config_factory(
        image=image_id if uuid_selector in {"image", "both"} else "debian-13",
        flavor=flavor_id if uuid_selector in {"flavor", "both"} else "small",
        repeat_count=2,
    )
    selected_image, selected_flavor = config.image, config.flavor

    def show(*args, **kwargs):
        if args == ("image", "show", selected_image):
            return {"id": image_id, "name": "debian-13", "min_disk": 1}
        if args == ("flavor", "show", selected_flavor):
            return {
                "id": flavor_id,
                "name": "small",
                "vcpus": 1,
                "ram": 1024,
                "disk": 20,
            }
        raise SuiteError("Display name is ambiguous after the first pass")

    osc = mock.Mock()
    osc.json.side_effect = show
    first = resolve_launch_selection(config, osc, mock.Mock())
    second = resolve_launch_selection(config, osc, mock.Mock())
    assert (first.image_id, first.flavor_id) == (second.image_id, second.flavor_id)
    assert (config.image, config.flavor) == (selected_image, selected_flavor)
    assert (second.image_name, second.flavor_name) == ("debian-13", "small")


def test_resume_revalidates_completion_after_cloud_scope_lock(tmp_path, monkeypatch):
    store = StateStore(tmp_path)
    previous = checkpoint(store, "pass1", pass_exit_code=130)
    previous.state = "CANCELLED"
    previous.plan_path = str(tmp_path / "plan.json")
    store.save(previous)

    @contextmanager
    def cloud_lock(self):
        # Another process finishes between the operator's request and our lock.
        current = self.load("pass1")
        current.state = "COMPLETED"
        current.metadata["pass_exit_code"] = 0
        self.save(current)
        yield

    execute = mock.Mock(return_value=0)
    monkeypatch.setattr(StateStore, "cloud_operation_lock", cloud_lock)
    monkeypatch.setattr(cli, "_hydrate_config_from_plan", mock.Mock())
    monkeypatch.setattr(cli, "_execute_locked_action", execute)
    assert cli.main(["run", "--resume", "pass1", "--output-dir", str(tmp_path)]) == 2
    execute.assert_not_called()
    assert store.load("pass1").state == "COMPLETED"


def test_repeated_passes_use_durable_identity_from_real_launch_resolution(
    tmp_path, monkeypatch
):
    calls = []
    image_id = "155f0344-d49b-4326-b899-d42d5da730d5"
    flavor_id = "00aee815-0b3f-4a2e-bbda-3253db396da0"

    def show(*args, **kwargs):
        if args == ("image", "show", image_id):
            return {"id": image_id, "name": "debian-13", "min_disk": 1}
        if args == ("flavor", "show", flavor_id):
            return {"id": flavor_id, "name": "small", "ram": 1024, "disk": 20}
        raise SuiteError("The display name is not a unique launch selector")

    def execute(config, store, run_id, old, **kwargs):
        selection = resolve_launch_selection(config, mock.Mock(json=show), mock.Mock())
        calls.append((config.repeat_index, selection.image_id, selection.flavor_id))
        checkpoint(
            store,
            run_id,
            repeat_index=config.repeat_index,
            repeat_next_id=config.repeat_next_id,
            pass_exit_code=0,
        )
        return 0

    monkeypatch.setattr(cli, "_execute_locked_action", execute)
    args = [*BASE, "--repeat", "3", "--output-dir", str(tmp_path)]
    args[args.index("--image") + 1] = image_id
    args[args.index("--flavor") + 1] = flavor_id
    assert cli.main(args) == 0
    assert calls == [(i, image_id, flavor_id) for i in (1, 2, 3)]


@pytest.mark.parametrize(
    ("rejection", "fallback_expected"),
    [
        ("Live migration is not supported", True),
        ("Live migration policy doesn't allow this operation (HTTP 403)", True),
        ("Requested live migration microversion is not supported", True),
        ("No valid host was found for this placement", False),
    ],
)
def test_live_capability_rejection_keeps_cold_fallback_eligible(
    rejection, fallback_expected
):
    config = Config.from_args(cli.parser().parse_args(BASE))
    config.live_migration_continuity = False
    source, destination = endpoint("source"), endpoint("destination")
    source.host, destination.host = "compute1", "compute2"
    source.availability_zone = destination.availability_zone = "az1"
    targets = {
        host: ComputeHostInfo(host, "az1", True, True, {"agg"}, {"agg"})
        for host in ("compute1", "compute2")
    }
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config
    builder.logger = mock.Mock()
    builder.reporter = mock.Mock()
    builder.osc = mock.Mock()
    builder.osc.run.return_value = subprocess.CompletedProcess([], 1, "", rejection)
    builder._record_migration_destination = mock.Mock()
    builder._pre_migration_control_plane_barrier = mock.Mock()
    builder._capture_endpoint_migration_state = lambda item: {"migration_ids": set()}
    builder._migration_command_args = lambda server_id, *args: args
    builder._recover_endpoint_after_failed_migration = lambda *args: (
        True,
        "authoritatively stable on the source host",
    )
    builder.select_compute_migration_targets = lambda moving, stationary, **kwargs: (
        [targets[stationary.host]],
        "eligible",
    )

    def cold(moving, target):
        previous = moving.host
        moving.host = target.host
        return MigrationResult(
            server_id=moving.server_id,
            source_host=previous,
            destination_host=target.host,
            source_availability_zone="az1",
            destination_availability_zone="az1",
            confirmed=True,
            automatically_confirmed=False,
            port_binding_verified=True,
            details={"migration_mode": "cold"},
        )

    builder.cold_migrate_endpoint = mock.Mock(side_effect=cold)
    executor, _, _ = _placement_executor(config, source, destination, builder)
    outcome = executor._attempt_configured_migration(
        dependencies=("placement-group",),
        source=source,
        destination=destination,
        current_relation="different",
        desired_relation="same",
        desired_label="same-host",
    )
    assert outcome is not None and outcome[5] is fallback_expected
    if fallback_expected:
        builder.cold_migrate_endpoint.assert_called_once()
        assert builder.osc.run.call_count == 5
        assert source.host == destination.host
        assert all(not attempt.get("target_unsuitable") for attempt in outcome[3])
    else:
        builder.cold_migrate_endpoint.assert_not_called()
        assert builder.osc.run.call_count == 1
        assert source.host != destination.host
        assert all(
            attempt["target_unsuitable"]
            for attempt in outcome[3]
            if attempt["migration_kind"] == "live"
        )


@pytest.mark.parametrize("mode", ["live", "cold"])
def test_unsupported_error_text_cannot_override_unknown_acceptance(mode):
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = Config.from_args(cli.parser().parse_args(BASE))
    builder.config.live_migration_continuity = False
    builder.logger = mock.Mock()
    builder.reporter = mock.Mock()
    builder.probe_service = mock.Mock()
    builder.osc = mock.Mock()
    builder.osc.run.return_value = subprocess.CompletedProcess(
        [], 1, "", f"HTTP 500: {mode} migration not supported"
    )
    builder._record_migration_destination = mock.Mock()
    builder._pre_migration_control_plane_barrier = mock.Mock()
    builder._capture_endpoint_migration_state = lambda item: {"migration_ids": set()}
    builder._migration_command_args = lambda server_id, *args: args
    # The durable journal has not established rejection. Unchanged host state
    # and an error-message substring cannot turn that uncertainty into failure.
    builder._current_command_was_rejected = lambda: False
    builder._wait_for_migration_acceptance = mock.Mock(
        side_effect=AmbiguousCloudOperationError("Acceptance is unknown")
    )
    builder._recover_endpoint_after_failed_migration = lambda *args: (
        True,
        "still on the source host",
    )
    builder._authoritative_migration_failure = lambda *args: (
        False,
        {"reason": "no terminal outcome"},
    )
    moving = endpoint("moving")
    moving.host, moving.availability_zone = "compute1", "az1"
    target = ComputeHostInfo("compute2", "az1", True, True, set(), set())
    with pytest.raises(UnsafeMigrationStateError, match="AMBIGUOUS"):
        getattr(builder, f"{mode}_migrate_endpoint")(moving, target)
    builder._wait_for_migration_acceptance.assert_called_once()
    builder.osc.run.assert_called_once()
