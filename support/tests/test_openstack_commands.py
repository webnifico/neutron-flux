from __future__ import annotations

import subprocess
from unittest import mock

import pytest

from neutron_flux.cleanup import CleanupManager
from neutron_flux.errors import PlacementUnavailableError
from neutron_flux.models import ResourceRecord
from neutron_flux.resources import ResourceBuilder
from neutron_flux.utils import iso_utc


def completed(returncode: int = 0, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess(["openstack"], returncode, stdout, stderr)


def test_migration_negotiates_2_latest_after_literal_256_rejection(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder.logger = mock.Mock()
    builder._json_with_transient_retry = mock.Mock(
        side_effect=[
            None,
            [{"server_uuid": "server-1", "status": "done"}],
        ]
    )

    rows, error = builder._migration_rows("server-1")

    assert error is None
    assert rows == [{"server_uuid": "server-1", "status": "done"}]
    first = builder._json_with_transient_retry.call_args_list[0].args
    second = builder._json_with_transient_retry.call_args_list[1].args
    assert first[:2] == ("--os-compute-api-version", "2.56")
    assert second[:2] == ("--os-compute-api-version", "2.latest")
    assert first[-2:] == second[-2:] == ("--server", "server-1")
    assert builder._migration_command_args(
        "server-1", "server", "migrate", "--host", "compute2", "server-1"
    ) == (
        "--os-compute-api-version",
        "2.latest",
        "server",
        "migrate",
        "--host",
        "compute2",
        "server-1",
    )


def test_unversioned_inventory_never_authorizes_targeted_cloud_operation(
    config_factory,
):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder.logger = mock.Mock()
    builder._json_with_transient_retry = mock.Mock(
        side_effect=[
            None,
            None,
            [{"server_uuid": "server-1", "status": "done"}],
        ]
    )

    rows, error = builder._migration_rows("server-1")

    assert error is None
    assert rows
    assert builder._migration_compute_api_prefix is None
    third = builder._json_with_transient_retry.call_args_list[2].args
    assert third[:3] == ("server", "migration", "list")
    assert third[-2:] == ("--server", "server-1")
    with pytest.raises(
        PlacementUnavailableError, match="no migration command was submitted"
    ):
        builder._migration_command_args(
            "server-1", "server", "migrate", "--host", "compute2", "server-1"
        )


def test_forced_server_delete_uses_global_compute_selector(config_factory):
    manager = object.__new__(CleanupManager)
    manager.config = config_factory()
    manager.logger = mock.Mock()
    manager.osc = mock.Mock()
    manager.osc.run.return_value = completed()
    manager.osc.exists.return_value = True
    manager._cleanup_progress_details = mock.Mock(return_value={})
    manager._wait_absent = mock.Mock(return_value=True)
    resource = ResourceRecord(1, "server", "server-id", "vm", None, {}, iso_utc())

    assert manager._server_delete_fallback(resource) is True
    assert manager.osc.run.call_args.args == (
        "--os-compute-api-version",
        "2.latest",
        "server",
        "delete",
        "--force",
        "server-id",
    )


def test_source_openstack_command_audit_passes():
    result = subprocess.run(
        ["python", "support/scripts/openstack-command-audit.py"],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "OpenStack command audit passed" in result.stdout
