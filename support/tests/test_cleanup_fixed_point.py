from __future__ import annotations

from unittest import mock

from neutron_flux.cloud_operation import CloudOperationCoordinator
from neutron_flux.operation_recovery import recover_operations

from ._shared import *  # noqa: F403, F405


class _LateVisibleNetworkCloud:
    """Small in-memory exact-run inventory with delayed list visibility."""

    def __init__(self, run_tag: str, name_prefix: str):
        self.run_tag = run_tag
        self.name_prefix = name_prefix
        self.network_visible = False
        self.network_present = True
        self.full_network_lists = 0
        self.delete_calls: list[tuple[str, ...]] = []

    @property
    def network_row(self) -> dict[str, object]:
        return {
            "ID": "late-network",
            "Name": f"{self.name_prefix}-late-network",
            "Tags": [self.run_tag],
        }

    def json(self, *args, **_kwargs):
        if args[:3] == ("network", "list", "--tags"):
            return (
                [self.network_row]
                if self.network_visible and self.network_present
                else []
            )
        if args == ("network", "list"):
            self.full_network_lists += 1
            if self.full_network_lists == 1:
                # The create settled immediately after the first complete
                # inventory returned. The bounded final sweep must catch it.
                self.network_visible = True
                return []
            return [self.network_row] if self.network_present else []
        if args[:3] == ("port", "list", "--network"):
            return []
        if args and args[-1] == "list":
            return []
        if "list" in args:
            return []
        return None

    def run(self, *args, **_kwargs):
        self.delete_calls.append(tuple(map(str, args)))
        if args[:2] == ("network", "delete") and args[-1] == "late-network":
            self.network_present = False
        return completed()

    def exists(self, resource_type: str, resource_id: str) -> bool:
        return (
            resource_type == "network"
            and resource_id == "late-network"
            and self.network_present
        )


class _PersistentlyVisibleNetworkCloud:
    def __init__(self, run_tag: str, name_prefix: str):
        self.row = {
            "ID": "returned-network",
            "Name": f"{name_prefix}-returned-network",
            "Tags": [run_tag],
        }
        self.delete_calls = 0

    def json(self, *args, **_kwargs):
        if args[:2] == ("network", "list"):
            return [self.row]
        if args[:3] == ("port", "list", "--network"):
            return []
        if "list" in args:
            return []
        return None

    def run(self, *args, **_kwargs):
        if args[:2] == ("network", "delete"):
            self.delete_calls += 1
        return completed()

    def exists(self, resource_type: str, resource_id: str) -> bool:
        return resource_type == "network" and resource_id == "returned-network"


class _SettlementBoundaryNetworkCloud(_LateVisibleNetworkCloud):
    """The resource becomes list-visible only when simulated time advances."""

    def json(self, *args, **_kwargs):
        if args[:2] == ("network", "list"):
            return (
                [self.network_row]
                if self.network_visible and self.network_present
                else []
            )
        if args[:3] == ("port", "list", "--network"):
            return []
        if args and args[-1] == "list":
            return []
        if "list" in args:
            return []
        return None


def _cleanup_manager(config_factory, tmp_path, run_id: str):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    reporter = Reporter(config, run_id)
    tracker = ResourceTracker(reporter)
    return (
        CleanupManager(mock.Mock(), reporter, tracker, config),
        reporter,
        tracker,
    )


def test_final_exact_run_sweep_deletes_late_visible_resource(
    config_factory,
    tmp_path,
):
    manager, reporter, tracker = _cleanup_manager(
        config_factory,
        tmp_path,
        "nflux-20260727010101-a1b2c3",
    )
    cloud = _LateVisibleNetworkCloud(reporter.run_tag, reporter.name_prefix)
    manager.osc = cloud
    manager._remove_local_keys = mock.Mock()
    manager._verify_placement_allocations = mock.Mock(return_value=[])
    manager._clear_recovery_artifacts = mock.Mock()

    assert manager.cleanup() is True

    assert reporter.cleanup_summary["complete"] is True
    assert reporter.cleanup_summary["adopted_orphans"] == 1
    verification = reporter.cleanup_summary["exact_run_verification"]
    assert verification["fixed_point"] is True
    assert [row["adopted"] for row in verification["passes"]] == [1, 0, 0]
    assert cloud.delete_calls.count(("network", "delete", "late-network")) == 1
    record = next(item for item in reporter.resources if item.id == "late-network")
    assert record.delete_status == "deleted"
    assert record.metadata["orphan_adopted"] is True
    reporter.logger.close()


def test_settlement_boundary_catches_resource_visible_seconds_later(
    config_factory,
    tmp_path,
):
    manager, reporter, _tracker = _cleanup_manager(
        config_factory,
        tmp_path,
        "nflux-20260727011111-a2b3c4",
    )
    cloud = _SettlementBoundaryNetworkCloud(
        reporter.run_tag,
        reporter.name_prefix,
    )
    manager.osc = cloud
    manager._remove_local_keys = mock.Mock()
    manager._verify_placement_allocations = mock.Mock(return_value=[])
    manager._clear_recovery_artifacts = mock.Mock()
    settlement_boundaries: list[int] = []

    def advance_visibility(next_pass: int) -> float:
        settlement_boundaries.append(next_pass)
        if next_pass == 2:
            cloud.network_visible = True
        return 5.0

    manager._wait_for_exact_run_inventory_settlement = advance_visibility

    assert manager.cleanup() is True

    verification = reporter.cleanup_summary["exact_run_verification"]
    assert verification["fixed_point"] is True
    assert [row["adopted"] for row in verification["passes"]] == [0, 1, 0, 0]
    assert verification["passes"][0]["settlement_seconds_after_pass"] == 5.0
    assert settlement_boundaries[0] == 2
    assert cloud.delete_calls.count(("network", "delete", "late-network")) == 1
    reporter.logger.close()


def test_production_settlement_uses_shared_cloud_operation_coordinator(
    config_factory,
    tmp_path,
):
    manager, reporter, _tracker = _cleanup_manager(
        config_factory,
        tmp_path,
        "nflux-20260727012121-a3b4c5",
    )
    coordinator = mock.Mock()
    manager.cloud_operation_coordinator = coordinator

    coordinator.settle.return_value = manager._FINAL_EXACT_RUN_SETTLEMENT_FLOOR_SECONDS
    seconds = manager._wait_for_exact_run_inventory_settlement(3)

    assert seconds == manager._FINAL_EXACT_RUN_SETTLEMENT_FLOOR_SECONDS
    coordinator.settle.assert_called_once_with(
        "network-topology",
        "allow exact-run OpenStack inventory visibility to settle before "
        "cleanup verification pass 3",
        seconds=seconds,
        fresh=True,
    )
    reporter.logger.close()


def test_exact_run_inventory_uncertainty_prevents_false_complete(
    config_factory,
    tmp_path,
):
    manager, reporter, _tracker = _cleanup_manager(
        config_factory,
        tmp_path,
        "nflux-20260727020202-b1c2d3",
    )

    def inventory(*args, **_kwargs):
        if args == ("network", "list"):
            raise SuiteError("503 while listing networks")
        return []

    manager.osc.json.side_effect = inventory
    manager.osc.exists.return_value = False
    manager._remove_local_keys = mock.Mock()
    manager._verify_placement_allocations = mock.Mock(return_value=[])

    assert manager.cleanup() is False

    verification = reporter.cleanup_summary["exact_run_verification"]
    assert verification["fixed_point"] is False
    assert len(verification["passes"]) == manager._FINAL_EXACT_RUN_SWEEP_PASSES
    assert all(row["discovery_errors"] for row in verification["passes"])
    assert reporter.cleanup_summary["complete"] is False
    assert any(
        item.startswith("exact-run-inventory:verification-error:")
        for item in reporter.cleanup_summary["leftovers"]
    )
    reporter.logger.close()


def test_transient_inventory_uncertainty_requires_two_later_clean_scans(
    config_factory,
    tmp_path,
):
    manager, reporter, _tracker = _cleanup_manager(
        config_factory,
        tmp_path,
        "nflux-20260727030303-c1d2e3",
    )
    full_network_calls = 0

    def inventory(*args, **_kwargs):
        nonlocal full_network_calls
        if args == ("network", "list"):
            full_network_calls += 1
            if full_network_calls <= 2:
                raise SuiteError("temporary network inventory failure")
        return []

    manager.osc.json.side_effect = inventory
    manager.osc.exists.return_value = False
    manager._remove_local_keys = mock.Mock()
    manager._verify_placement_allocations = mock.Mock(return_value=[])
    manager._clear_recovery_artifacts = mock.Mock()

    assert manager.cleanup() is True

    verification = reporter.cleanup_summary["exact_run_verification"]
    assert verification["fixed_point"] is True
    assert verification["initial_discovery_errors"]
    assert verification["passes"][0]["discovery_errors"]
    assert [row["consecutive_clean_scans"] for row in verification["passes"][-2:]] == [
        1,
        2,
    ]
    assert not any(
        item.startswith("exact-run-inventory:verification-error:")
        for item in reporter.cleanup_summary["leftovers"]
    )
    reporter.logger.close()


def test_continuously_appearing_exact_run_resources_hit_bounded_guard(
    config_factory,
    tmp_path,
):
    manager, reporter, tracker = _cleanup_manager(
        config_factory,
        tmp_path,
        "nflux-20260727040404-d1e2f3",
    )
    sequence = 0

    def adopt(_run_tag, _name_prefix, *, discovery_errors, inventory_state=None):
        nonlocal sequence
        assert discovery_errors == []
        sequence += 1
        tracker.add(
            "network",
            f"network-{sequence}",
            f"{reporter.name_prefix}-network-{sequence}",
            orphan_adopted=True,
        )
        if inventory_state is not None:
            inventory_state["visible_resources"] = [
                {
                    "resource_type": "network",
                    "id": f"network-{sequence}",
                    "name": f"{reporter.name_prefix}-network-{sequence}",
                }
            ]
        return 1

    def delete_all():
        for item in reporter.resources:
            if item.delete_status not in {"deleted", "already-absent"}:
                tracker.mark_deleted(item)

    manager._adopt_orphans = adopt
    manager._delete_all_types = delete_all
    manager._remove_local_keys = mock.Mock()
    manager._verify_placement_allocations = mock.Mock(return_value=[])
    manager.osc.exists.return_value = False

    assert manager.cleanup() is False

    verification = reporter.cleanup_summary["exact_run_verification"]
    assert verification["fixed_point"] is False
    assert len(verification["passes"]) == manager._FINAL_EXACT_RUN_SWEEP_PASSES
    assert all(row["adopted"] == 1 for row in verification["passes"])
    assert reporter.cleanup_summary["adopted_orphans"] == (
        manager._FINAL_EXACT_RUN_SWEEP_PASSES + 1
    )
    assert any(
        "did not produce two consecutive clean scans" in item
        for item in reporter.cleanup_summary["leftovers"]
    )
    reporter.logger.close()


def test_unfiltered_exact_run_inventory_is_mandatory(
    config_factory,
    tmp_path,
):
    manager, reporter, _tracker = _cleanup_manager(
        config_factory,
        tmp_path,
        "nflux-20260727050505-e1f2a3",
    )

    def inventory(*args, **_kwargs):
        if args[:3] == ("network", "list", "--tags"):
            return [
                {
                    "ID": "tagged-network",
                    "Name": f"{reporter.name_prefix}-tagged-network",
                }
            ]
        if args == ("network", "list"):
            return None
        return []

    manager.osc.json.side_effect = inventory
    errors: list[str] = []

    adopted = manager._adopt_orphans(
        reporter.run_tag,
        reporter.name_prefix,
        discovery_errors=errors,
    )

    assert adopted == 1
    assert any(
        "network inventory returned no authoritative list" in item for item in errors
    )
    assert reporter.resources[0].metadata["discovered_by"] == "exact-run-filter"
    reporter.logger.close()


def test_rediscovered_deleted_uuid_is_reopened_and_cannot_false_pass(
    config_factory,
    tmp_path,
):
    manager, reporter, tracker = _cleanup_manager(
        config_factory,
        tmp_path,
        "nflux-20260727051515-e2f3a4",
    )
    record = tracker.add(
        "network",
        "returned-network",
        f"{reporter.name_prefix}-returned-network",
    )
    tracker.mark_deleted(record)
    cloud = _PersistentlyVisibleNetworkCloud(
        reporter.run_tag,
        reporter.name_prefix,
    )
    manager.osc = cloud
    manager._wait_absent = mock.Mock(return_value=False)
    manager._remove_local_keys = mock.Mock()
    manager._verify_placement_allocations = mock.Mock(return_value=[])

    assert manager.cleanup() is False

    verification = reporter.cleanup_summary["exact_run_verification"]
    assert verification["fixed_point"] is False
    assert all(row["visible_count"] == 1 for row in verification["passes"])
    assert cloud.delete_calls >= 1
    assert record.cleanup_state == "FAILED"
    assert record.metadata["cleanup_rediscovery_reason"] == (
        "rediscovered-during-cleanup"
    )
    assert any(
        item.startswith("network:returned-network:")
        for item in reporter.cleanup_summary["leftovers"]
    )
    reporter.logger.close()


def test_reopened_resource_state_is_durable_for_resumed_cleanup(
    config_factory,
    tmp_path,
):
    _manager, reporter, tracker = _cleanup_manager(
        config_factory,
        tmp_path,
        "nflux-20260727052525-e3f4a5",
    )
    record = tracker.add("network", "network-resume", "network-resume")
    tracker.mark_deleted(record)
    tracker.mark_present(record, reason="visible-after-delete")

    loaded = ResourceTracker.load_manifest(reporter.manifest_path)

    assert len(loaded) == 1
    assert loaded[0].id == "network-resume"
    assert loaded[0].delete_status is None
    assert loaded[0].deleted_at is None
    assert loaded[0].cleanup_state == "PRESENT"
    assert loaded[0].metadata["cleanup_rediscovery_reason"] == ("visible-after-delete")
    reporter.logger.close()


def test_final_exact_run_sweep_is_disabled_for_scoped_cleanup(
    config_factory,
    tmp_path,
):
    manager, reporter, _tracker = _cleanup_manager(
        config_factory,
        tmp_path,
        "nflux-20260727060606-f1a2b3",
    )
    manager._delete_all_types = mock.Mock()
    manager._remove_local_keys = mock.Mock()
    manager._verify_placement_allocations = mock.Mock(return_value=[])
    manager._clear_recovery_artifacts = mock.Mock()
    manager._adopt_orphans = mock.Mock(side_effect=AssertionError("must not scan"))
    manager.osc.exists.return_value = False

    assert manager.cleanup(adopt_discovered=False) is True
    manager._adopt_orphans.assert_not_called()
    assert "exact_run_verification" not in reporter.cleanup_summary
    reporter.logger.close()


@pytest.mark.parametrize("post_create_failure", ["invalid-json", "manifest-write"])
@pytest.mark.parametrize("filtered_inventory_fails", [False, True])
def test_untracked_floating_ip_is_recovered_from_long_inventory(
    config_factory,
    tmp_path,
    monkeypatch,
    post_create_failure,
    filtered_inventory_fails,
):
    config = config_factory(action="run", quiet_period_scale=0, operation_gap_scale=0)
    reporter = Reporter(config, "nflux-20261016010101-abcdef")
    coordinator = CloudOperationCoordinator(reporter)
    coordinator._sleep = mock.Mock()
    tracker = ResourceTracker(reporter)
    osc = OpenStack(reporter.logger, coordinator)
    owned_id, foreign_id = "owned-floating-ip", "foreign-floating-ip"
    present = {foreign_id}
    commands = []
    detail = {
        "id": owned_id,
        "floating_ip_address": "198.51.100.20",
        "port_id": "access-port",
        "fixed_ip_address": "10.0.0.10",
        "description": f"neutron-flux-{reporter.run_id}",
        "tags": [reporter.run_tag],
    }

    def invoke(command, **_kwargs):
        args = tuple(command[1:])
        commands.append(args)
        if args[:3] == ("floating", "ip", "create"):
            present.add(owned_id)
            body = (
                "{truncated"
                if post_create_failure == "invalid-json"
                else json.dumps(detail)
            )
            return completed(stdout=body)
        if args[:3] == ("floating", "ip", "list"):
            if "--tags" in args and filtered_inventory_fails:
                return completed(1, stderr="Service Unavailable (HTTP 503)")
            identities = [owned_id] if "--tags" in args else [owned_id, foreign_id]
            rows = []
            for identity in identities:
                if identity not in present:
                    continue
                row = {
                    "ID": identity,
                    "Floating IP Address": "198.51.100.20"
                    if identity == owned_id
                    else "198.51.100.21",
                    "Fixed IP Address": "10.0.0.10",
                    "Port": "access-port",
                }
                if "--long" in args:
                    row["Description"] = (
                        detail["description"]
                        if identity == owned_id
                        else "operator allocation"
                    )
                    row["Tags"] = detail["tags"] if identity == owned_id else []
                rows.append(row)
            return completed(stdout=json.dumps(rows))
        if args[:3] == ("floating", "ip", "show"):
            if args[3] in present:
                return completed(stdout=json.dumps(detail))
            return completed(1, stderr=f"No FloatingIP found for {args[3]}")
        if args[:3] == ("floating", "ip", "delete"):
            assert args[3] == owned_id
            present.remove(owned_id)
            return completed()
        if "list" in args:
            return completed(stdout="[]")
        raise AssertionError(args)

    monkeypatch.setattr("neutron_flux.openstack.run_cancellable", invoke)
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config
    builder.reporter = reporter
    builder.logger = reporter.logger
    builder.tracker = tracker
    builder.osc = osc
    builder.cloud_operation_coordinator = coordinator
    builder.run_tag = reporter.run_tag
    try:
        persistence = (
            mock.patch.object(
                reporter,
                "update_resource",
                side_effect=OSError("manifest write failed"),
            )
            if post_create_failure == "manifest-write"
            else mock.patch.object(
                reporter, "update_resource", wraps=reporter.update_resource
            )
        )
        with persistence, pytest.raises((SuiteError, OSError)):
            builder._create_bastion_floating_ip(
                external_network_id="external",
                external_subnet_id="floating-subnet",
                access_port_id="access-port",
            )
        assert owned_id in present
        assert reporter.resources == []
        assert recover_operations(osc, coordinator, reporter.logger) == []

        manager = CleanupManager(
            osc, reporter, tracker, config, cloud_operation_coordinator=coordinator
        )
        assert manager.cleanup() is True
        assert reporter.cleanup_summary["complete"] is True
        assert reporter.cleanup_summary["leftovers"] == []
        assert present == {foreign_id}
        assert [record.id for record in reporter.resources] == [owned_id]
        assert any(
            args[:4] == ("floating", "ip", "list", "--long") for args in commands
        )
        # Ownership is read in the bounded list batch, without per-FIP SHOW.
        assert not any(
            args[:4] == ("floating", "ip", "show", foreign_id) for args in commands
        )
    finally:
        reporter.logger.close()


@pytest.mark.parametrize(
    "long_inventory",
    [
        None,
        {},
        ["malformed"],
        [{"ID": "unknown-floating-ip", "Floating IP Address": "198.51.100.20"}],
        [{"ID": "unknown-floating-ip", "Description": ""}],
        [{"ID": "unknown-floating-ip", "Tags": []}],
        [{"ID": "unknown-floating-ip", "Description": {}, "Tags": {}}],
        [{"Description": "neutron-flux-nflux-20261016010101-abcdef"}],
        [
            {
                "Floating IP Address": "198.51.100.20",
                "Description": "neutron-flux-nflux-20261016010101-abcdef",
                "Tags": [],
            }
        ],
        [
            {
                "ID": None,
                "Floating IP Address": "198.51.100.20",
                "Description": "neutron-flux-nflux-20261016010101-abcdef",
                "Tags": [],
            }
        ],
    ],
)
def test_incomplete_floating_ip_ownership_inventory_cannot_report_clean(
    config_factory, tmp_path, long_inventory
):
    manager, reporter, _tracker = _cleanup_manager(
        config_factory, tmp_path, "nflux-20261016010101-abcdef"
    )

    def inventory(*args, **_kwargs):
        if args[:3] == ("floating", "ip", "list"):
            if "--tags" in args:
                raise SuiteError("Service Unavailable (HTTP 503)")
            return long_inventory
        return []

    manager.osc.json.side_effect = inventory
    manager.osc.exists.return_value = False
    try:
        assert manager.cleanup() is False
        assert reporter.cleanup_summary["complete"] is False
        assert (
            reporter.cleanup_summary["exact_run_verification"]["fixed_point"] is False
        )
        assert reporter.resources == []
        manager.osc.run.assert_not_called()
    finally:
        reporter.logger.close()


def test_known_floating_ip_does_not_require_inventory_ownership_fields(
    config_factory, tmp_path
):
    manager, reporter, tracker = _cleanup_manager(
        config_factory, tmp_path, "nflux-20261016010101-abcdef"
    )
    record = tracker.add("floating_ip", "known-floating-ip", "198.51.100.20")

    def inventory(*args, **_kwargs):
        if args[:3] == ("floating", "ip", "list") and "--tags" not in args:
            return [{"ID": record.id, "Floating IP Address": record.name}]
        return []

    manager.osc.json.side_effect = inventory
    errors = []
    state = {}
    try:
        assert (
            manager._adopt_orphans(
                reporter.run_tag,
                reporter.name_prefix,
                discovery_errors=errors,
                inventory_state=state,
            )
            == 0
        )
        assert errors == []
        assert state["visible_count"] == 1
        assert reporter.resources == [record]
    finally:
        reporter.logger.close()


def test_unmanaged_floating_ip_with_empty_ownership_fields_is_protected(
    config_factory, tmp_path
):
    manager, reporter, _tracker = _cleanup_manager(
        config_factory, tmp_path, "nflux-20261016010101-abcdef"
    )

    def inventory(*args, **_kwargs):
        if args[:3] == ("floating", "ip", "list"):
            if "--tags" in args:
                raise SuiteError("Service Unavailable (HTTP 503)")
            return [{"ID": "foreign-floating-ip", "Description": "", "Tags": []}]
        return []

    manager.osc.json.side_effect = inventory
    try:
        assert manager.cleanup() is True
        assert reporter.cleanup_summary["complete"] is True
        assert reporter.resources == []
        manager.osc.run.assert_not_called()
    finally:
        reporter.logger.close()
