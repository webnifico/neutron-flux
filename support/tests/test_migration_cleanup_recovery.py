"""A completed migration can release cleanup without hiding its failed check."""

from __future__ import annotations

import copy
import json
import pathlib
from unittest import mock

import pytest

from neutron_flux.cleanup import CleanupManager
from neutron_flux.cloud_operation import CloudOperationCoordinator
from neutron_flux.errors import SuiteError
from neutron_flux.migration_operation_recovery import recover_validation_only_migration
from neutron_flux.operation_recovery import recover_operations
from neutron_flux.reporting import Reporter, ResourceTracker


def _case(config_factory, tmp_path, monkeypatch):
    monkeypatch.setenv("OS_AUTH_URL", "https://identity.example/v3")
    monkeypatch.setenv("OS_PROJECT_ID", "project-a")
    config = config_factory(
        action="cleanup", report_dir=tmp_path, cleanup_assume_yes=True
    )
    reporter = Reporter(config, "nflux-20261017060610-37ec8f")
    coordinator = CloudOperationCoordinator(reporter)
    coordinator.settle = mock.Mock(return_value=0)
    fixture = (
        pathlib.Path(__file__).parent / "fixtures/migration_port_health_ambiguity.json"
    )
    record = json.loads(fixture.read_text())
    record.update(
        scope=coordinator.journal.scope,
        scope_fingerprint=coordinator.journal.scope_fingerprint,
    )
    coordinator._latest[record["operation_id"]] = record
    coordinator._restore_quarantine()
    server_id = record["evidence"]["server_id"]
    server = {
        "id": server_id,
        "project_id": "project-a",
        "status": "ACTIVE",
        "OS-EXT-STS:task_state": None,
        "OS-EXT-STS:power_state": 1,
        "OS-EXT-SRV-ATTR:host": "compute-b",
        "OS-EXT-AZ:availability_zone": "az-a",
    }
    migration = {
        "Id": 3318,
        "Server UUID": server_id,
        "Source Compute": "compute-a",
        "Dest Compute": "compute-b",
        "Type": "live-migration",
        "Status": "completed",
    }
    ports = {}
    for index, (identity, before) in enumerate(
        record["pre_state"]["stable_observations"][0]["ports"].items()
    ):
        ports[identity] = {
            "id": identity,
            "project_id": "project-a",
            "device_id": server_id,
            "device_owner": "compute:az-a",
            "binding_host_id": "compute-b",
            "status": "ACTIVE" if index == 0 else "DOWN",
            "mac_address": before["mac_address"],
            "fixed_ips": [
                {"subnet_id": subnet, "ip_address": ip}
                for subnet, ip in before["fixed_ips"]
            ],
            "security_group_ids": before["security_groups"],
        }
    volume_id = record["pre_state"]["migration_volume_ids"][0]
    volume = {
        "id": volume_id,
        "status": "in-use",
        "attachments": [{"server_id": server_id}],
    }
    reads = []

    def json_read(*args, **kwargs):
        reads.append(args)
        if args[:2] == ("token", "issue"):
            value = {"project_id": "project-a"}
        elif args[:2] == ("server", "show"):
            value = server
        elif args[2:5] == ("server", "migration", "list"):
            value = [migration]
        elif args[:2] == ("port", "list"):
            value = [{"ID": identity} for identity in ports]
        elif args[:2] == ("port", "show"):
            value = ports[args[-1]]
        elif args[:3] == ("server", "volume", "list"):
            value = [{"ID": volume_id}]
        elif args[:2] == ("volume", "show"):
            value = volume
        else:
            raise AssertionError(f"Unexpected cloud operation: {args}")
        return copy.deepcopy(value)

    osc = mock.Mock()
    osc.json.side_effect = json_read
    return reporter, coordinator, record, osc, server, migration, ports, volume, reads


def test_recorded_port_health_ambiguity_settles_after_three_fresh_reads(
    config_factory, tmp_path, monkeypatch
):
    reporter, coordinator, record, osc, *_ = _case(
        config_factory, tmp_path, monkeypatch
    )
    original = copy.deepcopy(record["evidence"])
    try:
        assert recover_validation_only_migration(osc, coordinator, record)
        assert not coordinator.unresolved_records()
        outcome = coordinator._latest[record["operation_id"]]
        assert outcome["outcome"] == "SUCCEEDED"
        evidence = outcome["evidence"]
        assert evidence["port_binding_verified"] is False
        assert evidence["completion_assessment"] == original["completion_assessment"]
        assert (
            evidence["operation_settlement_assessment"]["validation_status"] == "FAIL"
        )
        assert len(evidence["recovery_observations"]) == 3
        assert {item["migration_id"] for item in evidence["recovery_observations"]} == {
            "3318"
        }
        assert osc.json.call_count == 22
        assert coordinator.settle.call_count == 2
        assert all(
            "delete" not in call.args and "migrate" not in call.args
            for call in osc.json.call_args_list
        )
        assert coordinator.cloud_operation_summary()["quarantined_resources"] == {}
        # Durable append, not a rewrite of historical result/check verdicts.
        persisted = json.loads(coordinator.journal.path.read_text().splitlines()[-3])
        assert persisted["evidence"]["completion_assessment"]["status"] == "FAIL"
    finally:
        reporter.logger.close()


@pytest.mark.parametrize(
    "change",
    [
        "server-id",
        "task",
        "hidden-task",
        "host",
        "az",
        "power",
        "project",
        "migration-id",
        "migration-running",
        "migration-type",
        "migration-server",
        "migration-source",
        "port-owner",
        "port-binding",
        "port-mac",
        "port-ip",
        "port-sg",
        "volume-owner",
        "volume-state",
        "scope",
        "unknown-read",
        "changing-record",
        "missing-baseline",
        "selection",
        "command",
        "host-argument-missing",
        "malformed-command",
    ],
)
def test_uncertain_or_changed_ownership_never_releases_cleanup(
    change, config_factory, tmp_path, monkeypatch
):
    reporter, coordinator, record, osc, server, migration, ports, volume, reads = _case(
        config_factory, tmp_path, monkeypatch
    )
    original_read = osc.json.side_effect
    first_port = next(iter(ports.values()))
    if change == "server-id":
        server["id"] = "other"
    elif change == "task":
        server["OS-EXT-STS:task_state"] = "migrating"
    elif change == "hidden-task":
        server.pop("OS-EXT-STS:task_state")
    elif change == "host":
        server["OS-EXT-SRV-ATTR:host"] = "compute-a"
    elif change == "az":
        server["OS-EXT-AZ:availability_zone"] = "az-b"
    elif change == "power":
        server["OS-EXT-STS:power_state"] = 0
    elif change == "project":
        server["project_id"] = "other"
    elif change == "migration-id":
        migration["Id"] = None
    elif change == "migration-running":
        migration["Status"] = "running"
    elif change == "migration-type":
        migration["Type"] = "resize"
    elif change == "migration-server":
        migration["Server UUID"] = "other"
    elif change == "migration-source":
        migration["Source Compute"] = "other"
    elif change == "port-owner":
        first_port["device_id"] = "other"
    elif change == "port-binding":
        first_port["binding_host_id"] = "compute-a"
    elif change == "port-mac":
        first_port["mac_address"] = "fa:16:3e:ff:ff:ff"
    elif change == "port-ip":
        first_port["fixed_ips"] = []
    elif change == "port-sg":
        first_port["security_group_ids"] = []
    elif change == "volume-owner":
        volume["attachments"] = [{"server_id": "other"}]
    elif change == "volume-state":
        volume["status"] = "detaching"
    elif change == "scope":
        record["scope_fingerprint"] = "another-cloud"
    elif change == "unknown-read":
        osc.json.side_effect = SuiteError("API unavailable")
    elif change == "changing-record":

        def changing(*args, **kwargs):
            value = original_read(*args, **kwargs)
            if args[2:5] == ("server", "migration", "list"):
                value[0]["Id"] = 3318 + sum(
                    call[2:5] == ("server", "migration", "list") for call in reads
                )
            return value

        osc.json.side_effect = changing
    elif change == "missing-baseline":
        record["pre_state"].pop("migration_ids")
    elif change == "selection":
        record["pre_state"]["destination_selection"]["destination_host"] = "other"
    elif change == "command":
        record["command"][-1] = "other"
    elif change == "host-argument-missing":
        record["command"].append("--host")
    elif change == "malformed-command":
        record["command"].insert(-1, None)
    try:
        # The public recovery flow cannot fall back to its weaker legacy path.
        assert recover_operations(osc, coordinator, reporter.logger) == [
            record["operation_id"]
        ]
        assert coordinator._latest[record["operation_id"]]["outcome"] == "AMBIGUOUS"
        osc.run.assert_not_called()
    finally:
        reporter.logger.close()


def test_exact_run_cleanup_reconciles_before_dependency_ordered_deletion(
    config_factory, tmp_path, monkeypatch
):
    reporter, coordinator, record, osc, *_ = _case(
        config_factory, tmp_path, monkeypatch
    )
    tracker = ResourceTracker(reporter)
    for identity in record["resource_ids"]:
        tracker.add(
            "server" if identity == record["evidence"]["server_id"] else "port",
            identity,
            identity,
        )
    manager = CleanupManager(
        osc, reporter, tracker, reporter.config, cloud_operation_coordinator=coordinator
    )
    deleted = []

    def delete_all():
        assert not coordinator.unresolved_records()
        for resource in reporter.resources:
            tracker.mark_deleted(resource, "deleted")
            deleted.append(resource.id)

    manager._delete_all_types = delete_all
    manager._remove_local_keys = mock.Mock()
    manager._verify_placement_allocations = mock.Mock(return_value=[])
    try:
        assert manager.cleanup(adopt_discovered=False)
        assert set(deleted) == set(record["resource_ids"])
        assert reporter.cleanup_summary["unresolved_operations"] == []
        assert (
            coordinator._latest[record["operation_id"]]["evidence"][
                "completion_assessment"
            ]["status"]
            == "FAIL"
        )
    finally:
        reporter.logger.close()


def test_exact_cleanup_does_not_reconcile_other_run_or_dry_run(
    config_factory, tmp_path, monkeypatch
):
    reporter, coordinator, record, osc, *_ = _case(
        config_factory, tmp_path, monkeypatch
    )
    manager = CleanupManager(
        osc,
        reporter,
        ResourceTracker(reporter),
        reporter.config,
        cloud_operation_coordinator=coordinator,
    )
    manager._delete_all_types = mock.Mock()
    manager._remove_local_keys = mock.Mock()
    manager._verify_placement_allocations = mock.Mock(return_value=[])
    try:
        assert not manager.cleanup(adopt_discovered=False)
        osc.json.assert_not_called()
        manager.config.cleanup_dry_run = True
        for identity in record["resource_ids"]:
            manager.tracker.add("port", identity, identity)
        manager.cleanup(adopt_discovered=False)
        osc.json.assert_not_called()
        assert coordinator.unresolved_records()
    finally:
        reporter.logger.close()


def test_historical_journal_resolution_appends_without_rewriting_prior_failure(
    config_factory, tmp_path, monkeypatch
):
    reporter, coordinator, record, osc, *_ = _case(
        config_factory, tmp_path, monkeypatch
    )
    historical = tmp_path / "historical-cloud-operations.jsonl"
    original = json.dumps(record, sort_keys=True) + "\n"
    historical.write_text(original)
    coordinator._latest.clear()
    coordinator._external_unresolved = [{**record, "journal_path": str(historical)}]
    try:
        assert recover_operations(osc, coordinator, reporter.logger) == []
        text = historical.read_text()
        assert text.startswith(original)
        rows = list(map(json.loads, text.splitlines()))
        assert len(rows) == 2
        assert rows[0]["outcome"] == "AMBIGUOUS"
        assert rows[0]["evidence"]["completion_assessment"]["status"] == "FAIL"
        assert rows[1]["outcome"] == "SUCCEEDED"
        assert rows[1]["reconciled_from_outcome"] == "AMBIGUOUS"
        assert rows[1]["evidence"]["completion_assessment"]["status"] == "FAIL"
        assert rows[1]["evidence"]["original_validation_preserved"] is True
    finally:
        reporter.logger.close()
