from __future__ import annotations

from ._shared import *  # noqa: F403, F405


def test_orphan_ownership_requires_explicit_marker_or_strict_legacy_name(
    config_factory, tmp_path
):
    config = config_factory(action="cleanup", report_dir=tmp_path / "reports")
    reporter = Reporter(config, "orphan-inspection")
    manager = CleanupManager(mock.Mock(), reporter, ResourceTracker(reporter), config)
    manager.osc.json.return_value = {"project_id": "project-id"}

    explicit = manager._owned_orphan_candidate(
        "network",
        {
            "ID": "network-1",
            "Name": "custom-name",
            "Tags": ["neutron-flux-custom-20260720120000-a1b2c3"],
        },
    )
    legacy = manager._owned_orphan_candidate(
        "keypair",
        {"Name": "nflux-20260720120000-a1b2c3-key"},
    )
    unrelated = manager._owned_orphan_candidate(
        "network",
        {"ID": "network-2", "Name": "my-neutron-flux-network"},
    )

    assert explicit and explicit["run_id"] == "custom-20260720120000-a1b2c3"
    assert legacy and legacy["run_id"] == "nflux-20260720120000-a1b2c3"
    assert unrelated is None
    reporter.logger.close()


def test_orphan_discovery_protects_fresh_cross_host_run_and_selects_stale_run(
    config_factory, tmp_path
):
    config = config_factory(
        action="cleanup",
        report_dir=tmp_path / "reports",
        cleanup_orphans=True,
        orphan_grace_minutes=30,
    )
    reporter = Reporter(config, "orphan-discovery")
    osc = mock.Mock()
    fresh_run = "nflux-20260720120000-a1b2c3"
    stale_run = "nflux-20260719120000-b1c2d3"

    def inventory(*args, **_kwargs):
        if args[:3] == ("server", "list", "--long"):
            return [
                {
                    "ID": "server-fresh",
                    "Name": f"{fresh_run}-controller",
                    "Updated At": iso_utc(),
                }
            ]
        if args[:2] == ("server", "show"):
            return {
                "ID": "server-fresh",
                "Name": f"{fresh_run}-controller",
                "Updated": iso_utc(),
                "Properties": {
                    "neutron_flux_run_id": fresh_run,
                    "neutron_flux_state": "active",
                    "neutron_flux_heartbeat": iso_utc(),
                },
            }
        if args[:3] == ("network", "list", "--long"):
            return [
                {
                    "ID": "network-stale",
                    "Name": f"{stale_run}-tenant-net",
                    "Tags": [f"neutron-flux-{stale_run}"],
                    "Updated At": "2026-07-19T12:05:00Z",
                }
            ]
        return []

    osc.json.side_effect = inventory
    manager = CleanupManager(osc, reporter, ResourceTracker(reporter), config)
    result = manager._discover_project_orphans()

    assert [item["id"] for item in result["protected"]] == ["server-fresh"]
    assert [item["id"] for item in result["candidates"]] == ["network-stale"]
    assert result["runs"][fresh_run]["protected"] is True
    assert result["runs"][stale_run]["selected"] is True
    reporter.logger.close()


def test_orphan_cleanup_dry_run_tracks_candidates_without_deleting(
    config_factory, tmp_path
):
    config = config_factory(
        action="cleanup",
        report_dir=tmp_path / "reports",
        cleanup_orphans=True,
        cleanup_dry_run=True,
        cleanup_assume_yes=False,
    )
    reporter = Reporter(config, "orphan-dry-run")
    tracker = ResourceTracker(reporter)
    manager = CleanupManager(mock.Mock(), reporter, tracker, config)
    manager.osc.json.return_value = {"project_id": "project-id"}
    manager._discover_project_orphans = mock.Mock(
        return_value={
            "candidates": [
                {
                    "resource_type": "network",
                    "id": "network-1",
                    "name": "nflux-20260719120000-b1c2d3-net",
                    "run_id": "nflux-20260719120000-b1c2d3",
                    "evidence": "strict legacy nflux run-name prefix",
                }
            ],
            "protected": [],
            "runs": {
                "nflux-20260719120000-b1c2d3": {
                    "selected": True,
                    "resource_count": 1,
                    "reason": "stale or missing cloud heartbeat",
                }
            },
        }
    )
    manager.cleanup = mock.Mock(return_value=True)

    assert manager.cleanup_orphans() is True
    manager.cleanup.assert_not_called()
    assert reporter.resources[0].id == "network-1"
    assert reporter.cleanup_summary["attempted"] is False
    assert reporter.cleanup_summary["dry_run_candidates"]
    reporter.logger.close()


def test_orphan_cleanup_yes_reuses_dependency_safe_cleanup_engine(
    config_factory, tmp_path
):
    config = config_factory(
        action="cleanup",
        report_dir=tmp_path / "reports",
        cleanup_orphans=True,
        cleanup_assume_yes=True,
    )
    reporter = Reporter(config, "orphan-delete")
    manager = CleanupManager(mock.Mock(), reporter, ResourceTracker(reporter), config)
    manager.osc.json.return_value = {"project_id": "project-id"}
    initial = {
        "candidates": [
            {
                "resource_type": "port",
                "id": "port-1",
                "name": "nflux-20260719120000-b1c2d3-port",
                "run_id": "nflux-20260719120000-b1c2d3",
                "evidence": "strict legacy nflux run-name prefix",
            }
        ],
        "protected": [],
        "unknown": [],
        "runs": {
            "nflux-20260719120000-b1c2d3": {
                "selected": True,
                "resource_count": 1,
                "reason": "stale or missing cloud heartbeat",
            }
        },
    }
    empty = {"candidates": [], "protected": [], "unknown": [], "runs": {}}
    manager._discover_project_orphans = mock.Mock(
        side_effect=[initial, empty, empty, empty]
    )
    manager.cleanup = mock.Mock(return_value=True)

    assert manager.cleanup_orphans() is True
    manager.cleanup.assert_called_once_with(
        adopt_discovered=False, completion_message=None
    )
    assert reporter.resources[0].metadata["orphan_run_id"].startswith("nflux-")
    reporter.logger.close()


def test_server_create_carries_cross_host_ownership_and_heartbeat_metadata(
    config_factory,
):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.server_sequence = 0
    builder.flavor_id = "f1"
    builder.keypair_name = "key"
    builder.image_id = "img"
    builder.image_name = "debian-13"
    builder.run_tag = "neutron-flux-nflux-20260720120000-a1b2c3"
    builder.tracker = mock.Mock()
    builder.logger = mock.Mock()
    builder.reporter = mock.Mock(run_id="nflux-20260720120000-a1b2c3")
    builder._wait_for_status = mock.Mock()
    builder.osc = mock.Mock()
    builder.osc.run.return_value = completed(stdout=json.dumps({"id": "server"}))
    builder.osc.json.return_value = {"id": "server", "status": "ACTIVE"}

    builder._wait_for_server_settlement = mock.Mock(
        return_value=builder.osc.json.return_value
    )
    builder._create_server("vm", ["p1"], role="endpoint")
    args = builder.osc.run.call_args.args
    rendered = " ".join(str(item) for item in args)
    assert "neutron_flux_managed=true" in rendered
    assert "neutron_flux_run_id=nflux-20260720120000-a1b2c3" in rendered
    assert "neutron_flux_state=active" in rendered
    assert "neutron_flux_heartbeat=" in rendered


def test_orphan_volume_cleanup_refuses_attachment_to_surviving_server(
    config_factory, tmp_path
):
    config = config_factory(action="cleanup", report_dir=tmp_path / "reports")
    reporter = Reporter(config, "orphan-volume-guard")
    osc = mock.Mock()
    osc.json.return_value = {"attachments": [{"server_id": "server-user"}]}
    osc.exists.return_value = True
    manager = CleanupManager(osc, reporter, ResourceTracker(reporter), config)
    record = ResourceRecord(
        1,
        "volume",
        "volume-1",
        "nflux-20260719120000-b1c2d3-root",
        None,
        {},
        iso_utc(),
    )

    with pytest.raises(SuiteError, match="refusing orphan deletion"):
        manager._delete_volume(record)
    osc.run.assert_not_called()
    reporter.logger.close()


def test_orphan_inventory_falls_back_when_long_listing_is_unsupported(
    config_factory, tmp_path
):
    config = config_factory(action="cleanup", report_dir=tmp_path / "reports")
    reporter = Reporter(config, "orphan-fallback")
    osc = mock.Mock()
    osc.json.side_effect = [
        None,
        [
            {
                "ID": "network-legacy",
                "Name": "nflux-20260719120000-b1c2d3-net",
            }
        ],
    ]
    manager = CleanupManager(osc, reporter, ResourceTracker(reporter), config)

    rows = manager._orphan_list(["network", "list", "--long"], ["network", "list"])

    assert rows[0]["ID"] == "network-legacy"
    assert osc.json.call_count == 2
    reporter.logger.close()


def test_orphan_discovery_finds_custom_prefix_server_from_nova_metadata(
    config_factory, tmp_path
):
    config = config_factory(
        action="cleanup",
        report_dir=tmp_path / "reports",
        cleanup_orphans=True,
        orphan_grace_minutes=30,
    )
    reporter = Reporter(config, "orphan-custom-prefix")
    osc = mock.Mock()
    custom_run = "labflux-20260719120000-c1d2e3"

    def inventory(*args, **_kwargs):
        if args[:3] == ("server", "list", "--long"):
            return [{"ID": "server-custom", "Name": "unhelpful-visible-name"}]
        if args[:2] == ("server", "show"):
            return {
                "ID": "server-custom",
                "Name": "unhelpful-visible-name",
                "Updated": "2026-07-19T12:00:00Z",
                "Properties": {
                    "neutron_flux_run_id": custom_run,
                    "neutron_flux_state": "active",
                    "neutron_flux_heartbeat": "2026-07-19T12:00:00Z",
                },
            }
        return []

    osc.json.side_effect = inventory
    manager = CleanupManager(osc, reporter, ResourceTracker(reporter), config)
    result = manager._discover_project_orphans()

    assert [item["run_id"] for item in result["candidates"]] == [custom_run]
    assert result["candidates"][0]["evidence"] == "explicit Nova server metadata"
    reporter.logger.close()


def test_host_root_migration_is_unverified_when_required_nova_fields_are_hidden(
    config_factory,
):
    from neutron_flux.models import ComputeHostInfo, MigrationResult

    source = endpoint("source", "A")
    destination = endpoint("destination", "B")
    source.host = "compute1"
    destination.host = "compute2"
    target = ComputeHostInfo("compute1", "az1", True, True, {"agg"}, {"agg"})

    def migrate(migrated, selected):
        old_host = migrated.host
        migrated.host = selected.host
        return MigrationResult(
            server_id=migrated.server_id,
            source_host=old_host,
            destination_host=selected.host,
            source_availability_zone="az1",
            destination_availability_zone="az1",
            confirmed=True,
            automatically_confirmed=False,
            port_binding_verified=True,
            migration_record_verified=None,
            migration_record_error="policy hid completed migration records",
            task_state_cleared=None,
            volume_attachment_verified=None,
            guest_marker_verified=True,
            endpoint_ready=True,
            details={},
        )

    builder = SimpleNamespace(
        select_compute_migration_target=lambda *args, **kwargs: (target, "eligible"),
        cold_migrate_endpoint=migrate,
    )
    executor, spec, recorded = _placement_executor(
        config_factory(action="run", storage="host", migration_mode="cold-only"),
        source,
        destination,
        builder,
    )
    engine = SimpleNamespace(run_specs=lambda specs: None)

    executor._run_compute_placement_validation(
        [spec], engine, dependencies=("placement-group",)
    )

    lifecycle = next(
        item for item in recorded if item.scenario == "Cold migration lifecycle"
    )
    assert lifecycle.status == "UNVERIFIED"
    assert lifecycle.observed == "nova-lifecycle-evidence-incomplete"
    assert "migration_record_verified" in lifecycle.message
    assert "task_state_cleared" in lifecycle.message
    assert (
        lifecycle.details["details"]["completion_assessment"]["status"] == "UNVERIFIED"
    )


def test_volume_root_migration_requires_attachment_continuity_evidence(
    config_factory,
):
    from neutron_flux.models import ComputeHostInfo, MigrationResult

    source = endpoint("source", "A")
    destination = endpoint("destination", "B")
    source.host = "compute1"
    destination.host = "compute2"
    target = ComputeHostInfo("compute1", "az1", True, True, {"agg"}, {"agg"})

    def migrate(migrated, selected):
        old_host = migrated.host
        migrated.host = selected.host
        return MigrationResult(
            server_id=migrated.server_id,
            source_host=old_host,
            destination_host=selected.host,
            source_availability_zone="az1",
            destination_availability_zone="az1",
            confirmed=True,
            automatically_confirmed=False,
            port_binding_verified=True,
            migration_record_verified=None,
            task_state_cleared=None,
            volume_attachment_verified=None,
            volume_validation_error="attachment fields hidden",
            guest_marker_verified=True,
            endpoint_ready=True,
            details={},
        )

    builder = SimpleNamespace(
        select_compute_migration_target=lambda *args, **kwargs: (target, "eligible"),
        cold_migrate_endpoint=migrate,
    )
    executor, spec, recorded = _placement_executor(
        config_factory(action="run", storage="volume", migration_mode="cold-only"),
        source,
        destination,
        builder,
    )
    engine = SimpleNamespace(run_specs=lambda specs: None)

    executor._run_compute_placement_validation(
        [spec], engine, dependencies=("placement-group",)
    )

    lifecycle = next(
        item for item in recorded if item.scenario == "Cold migration lifecycle"
    )
    assert lifecycle.status == "UNVERIFIED"
    assert lifecycle.observed == "volume-attachment-evidence-unavailable"


def test_visible_contradictory_migration_record_still_fails(config_factory):
    from neutron_flux.models import ComputeHostInfo, MigrationResult

    source = endpoint("source", "A")
    destination = endpoint("destination", "B")
    source.host = "compute1"
    destination.host = "compute2"
    target = ComputeHostInfo("compute1", "az1", True, True, {"agg"}, {"agg"})

    def migrate(migrated, selected):
        old_host = migrated.host
        migrated.host = selected.host
        return MigrationResult(
            server_id=migrated.server_id,
            source_host=old_host,
            destination_host=selected.host,
            source_availability_zone="az1",
            destination_availability_zone="az1",
            confirmed=True,
            automatically_confirmed=False,
            port_binding_verified=True,
            migration_record_verified=False,
            migration_record_error="destination host did not match",
            task_state_cleared=None,
            volume_attachment_verified=True,
            guest_marker_verified=True,
            endpoint_ready=True,
            details={},
        )

    builder = SimpleNamespace(
        select_compute_migration_target=lambda *args, **kwargs: (target, "eligible"),
        cold_migrate_endpoint=migrate,
    )
    executor, spec, recorded = _placement_executor(
        config_factory(action="run", storage="host", migration_mode="cold-only"),
        source,
        destination,
        builder,
    )
    engine = SimpleNamespace(run_specs=lambda specs: None)

    executor._run_compute_placement_validation(
        [spec], engine, dependencies=("placement-group",)
    )

    lifecycle = next(
        item for item in recorded if item.scenario == "Cold migration lifecycle"
    )
    assert lifecycle.status == "FAIL"
    assert lifecycle.observed == "migration-record-invalid"


def test_volume_show_fallback_verifies_expected_server_attachment(config_factory):
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory(
        action="run", storage="volume", migration_mode="cold-only"
    )
    builder._json_with_transient_retry = lambda *args, **kwargs: {
        "status": "in-use",
        "attachments": [{"server_id": "server-id", "volume_id": "volume-id"}],
    }

    verified, error, detail = builder._verify_expected_volume_attachment(
        "volume-id", "server-id"
    )

    assert verified is True
    assert error is None
    assert detail["status"] == "in-use"
