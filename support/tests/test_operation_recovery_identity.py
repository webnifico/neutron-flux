"""Replay interrupted creations by recorded identity, without resubmitting them."""

from __future__ import annotations

import json
import subprocess
from unittest import mock

import pytest

from neutron_flux.cloud_operation import (
    CloudOperationCoordinator,
    CloudOperationOutcome,
)
from neutron_flux.errors import CommandTimeoutError
from neutron_flux.openstack import OpenStack
from neutron_flux.operation_recovery import recover_operations
from neutron_flux.reporting import Reporter


@pytest.mark.parametrize("resource", [("server",), ("keypair",), ("server", "group")])
@pytest.mark.parametrize("prefix", ["nflux", "historical"])
def test_replayed_create_uses_exact_name_and_native_resource_identity(
    config_factory, tmp_path, resource, prefix
):
    reporter = Reporter(
        config_factory(action="cleanup", report_dir=tmp_path / "reports"),
        f"{prefix}-20261009010101-a1b2c3",
    )
    name = f"{reporter.name_prefix}-resource"
    command = (*resource, "create", name)
    submissions = []
    coordinator = CloudOperationCoordinator(reporter)
    coordinator._sleep = mock.Mock()

    def lost_response():
        submissions.append(command)
        raise CommandTimeoutError(command, 60)

    try:
        with pytest.raises(CommandTimeoutError):
            coordinator.execute(
                coordinator.classify_openstack_command(command), command, lost_response
            )
        # Discard the in-memory coordinator as a stopped process would do.
        replay = CloudOperationCoordinator(reporter)
        operation_id = replay.unresolved_records()[0]["operation_id"]
        detail = {"name": name}
        if resource == ("keypair",):
            detail.update(fingerprint="aa:bb:cc", public_key="ssh-rsa public-key")
        else:
            detail["id"] = "resource-uuid"
        if resource == ("server",):
            detail.update(status="ACTIVE", **{"OS-EXT-STS:task_state": None})
        osc = mock.Mock()
        osc.run.return_value = subprocess.CompletedProcess(
            [], 0, json.dumps(detail), ""
        )
        osc.is_not_found_result.side_effect = OpenStack.is_not_found_result

        assert recover_operations(osc, replay, reporter.logger) == []
        assert submissions == [command]
        assert osc.run.call_args.args == (*resource, "show", name, "-f", "json")
        persisted = CloudOperationCoordinator(reporter)
        assert persisted.unresolved_records() == []
        assert persisted._latest[operation_id]["outcome"] == (
            CloudOperationOutcome.SUCCEEDED.value
        )
        assert persisted._latest[operation_id]["evidence"]["created_resource"] == detail
    finally:
        reporter.logger.close()


@pytest.mark.parametrize(
    "detail",
    [
        None,
        {"name": "different-name", "id": "other-id", "status": "ACTIVE"},
        {"name": "historical-recorded-name", "status": "ACTIVE"},
        {"name": "historical-recorded-name", "id": "id", "status": "BUILD"},
        {
            "name": "historical-recorded-name",
            "id": "id",
            "status": "ACTIVE",
            "OS-EXT-STS:task_state": "spawning",
        },
    ],
)
def test_create_recovery_preserves_missing_or_incompatible_evidence(detail):
    record = {
        "operation_id": "create-id",
        "command": ["server", "create", "historical-recorded-name"],
        "kind": "server-create",
    }
    coordinator = mock.Mock()
    coordinator.unresolved_records.return_value = [record]
    osc = mock.Mock()
    osc.run.return_value = subprocess.CompletedProcess(
        [],
        1 if detail is None else 0,
        "" if detail is None else json.dumps(detail),
        "No Server found for historical-recorded-name" if detail is None else "",
    )
    osc.is_not_found_result.side_effect = OpenStack.is_not_found_result

    assert recover_operations(osc, coordinator, mock.Mock()) == ["create-id"]
    coordinator.resolve.assert_not_called()


def test_server_group_delete_recovery_verifies_its_exact_uuid():
    record = {
        "operation_id": "group-delete-id",
        "command": ["server", "group", "delete", "group-uuid"],
        "kind": "server-group",
    }
    coordinator = mock.Mock()
    pending = [record]
    coordinator.unresolved_records.side_effect = lambda: list(pending)
    coordinator.resolve.side_effect = lambda *_args, **_kwargs: pending.clear()
    osc = mock.Mock()
    osc.run.return_value = subprocess.CompletedProcess(
        [], 1, "", "No Server Group found for group-uuid"
    )
    osc.is_not_found_result.side_effect = OpenStack.is_not_found_result

    assert recover_operations(osc, coordinator, mock.Mock()) == []
    assert osc.run.call_args.args == (
        "server",
        "group",
        "show",
        "group-uuid",
        "-f",
        "json",
    )
    assert coordinator.resolve.call_args.args[1] == CloudOperationOutcome.SUCCEEDED
    assert coordinator.resolve.call_args.kwargs["evidence"]["verified_absent"] is True
