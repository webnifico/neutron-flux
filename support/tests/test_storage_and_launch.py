from __future__ import annotations

from ._shared import *  # noqa: F403, F405


def test_automatic_volume_backed_az_selection_prefers_same_cinder_az(config_factory):
    from neutron_flux.models import ComputeHostInfo

    inventory = {
        "az1-host": ComputeHostInfo("az1-host", "bc-van1", True, True, {"a"}, {"a"}),
        "az2-host": ComputeHostInfo("az2-host", "bc-van2", True, True, {"b"}, {"b"}),
    }
    builder = _az_builder(
        config_factory(action="run", prefer_ephemeral_boot=False), inventory
    )
    builder.osc = mock.Mock()
    builder.osc.optional_json.return_value = [
        {"Zone Name": "bc-van2", "Zone Status": "available"}
    ]
    builder._select_run_availability_zone()
    assert builder.selected_availability_zone == "bc-van2"
    assert builder.volume_availability_zones == {"bc-van2"}


def test_rejected_boot_volume_is_not_marked_deleted_until_absent(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run", convergence_interval=0)
    builder.osc = mock.Mock()
    builder.osc.run.return_value = completed(0)
    builder.osc.presence.return_value = SimpleNamespace(
        absent=False, unknown=True, detail="503 Service Unavailable"
    )
    builder.tracker = mock.Mock()
    builder.logger = mock.Mock()
    record = mock.Mock()
    builder._discard_failed_boot_volume("volume-1", record)
    builder.tracker.mark_deleted.assert_not_called()


def test_not_found_classifier_rejects_catalog_and_volume_type_errors():
    service = completed(1, stderr="No service with a name or ID of 'nova' exists.")
    endpoint_error = completed(
        1, stderr="No endpoint with a name or ID of 'public' exists."
    )
    volume_type = completed(
        1, stderr="No volume type with a name or ID of 'fast' exists."
    )
    server = completed(1, stderr="Server server-1 could not be found")
    assert OpenStack.is_not_found_result(service, expected_resource="server") is False
    assert (
        OpenStack.is_not_found_result(endpoint_error, expected_resource="server")
        is False
    )
    assert (
        OpenStack.is_not_found_result(volume_type, expected_resource="volume") is False
    )
    assert OpenStack.is_not_found_result(server, expected_resource="server") is True


def test_server_volume_inventory_is_unverified_for_malformed_payload(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder.logger = mock.Mock()
    builder._json_with_transient_retry = mock.Mock(
        return_value={"unexpected": "mapping"}
    )
    assert builder._server_volume_ids("server-1") is None


def test_ephemeral_az_selection_skips_cinder_inventory(config_factory):
    from neutron_flux.models import ComputeHostInfo

    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run", prefer_ephemeral_boot=True)
    builder._volume_availability_zone_inventory = mock.Mock(
        side_effect=AssertionError("Cinder must not be queried")
    )
    builder.compute_host_inventory = mock.Mock(
        return_value={
            "compute1": ComputeHostInfo(
                "compute1", "bc-van1", True, True, {"agg"}, {"agg"}
            )
        }
    )
    builder._aggregate_inventory_state = "complete"
    builder.logger = mock.Mock()
    builder.reporter = mock.Mock()
    builder._select_run_availability_zone()
    builder._volume_availability_zone_inventory.assert_not_called()
    assert builder.selected_availability_zone == "bc-van1"


def test_cinder_az_rejection_is_classified_for_candidate_fallback():
    assert ResourceBuilder._is_cinder_placement_unavailable_message(
        "Invalid availability zone bc-van2"
    )
    assert ResourceBuilder._is_cinder_placement_unavailable_message(
        "No valid backend was found"
    )
    assert not ResourceBuilder._is_cinder_placement_unavailable_message(
        "403 Forbidden: policy doesn't allow volume:create"
    )


def test_requested_volume_type_is_validated_before_resource_creation(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(
        action="run",
        storage="volume",
        volume_type="ceph_shared",
        input_sources={"image": "CLI", "flavor": "CLI", "storage": "CLI"},
    )
    builder.osc = mock.Mock()
    builder.osc.json.side_effect = [
        {
            "id": "image-1",
            "name": "debian-13",
            "min_disk": 10,
            "properties": {"os_admin_user": "debian"},
        },
        {"id": "flavor-1", "name": "x1.nano", "ram": 1024, "vcpus": 1, "disk": 0},
        {
            "id": "type-1",
            "name": "ceph_shared",
            "properties": {"RESKEY:availability_zones": "bc-van1,bc-van2"},
        },
    ]
    builder.logger = mock.Mock()
    builder._validate_selected_flavor_quota = mock.Mock()
    builder._resolve_image_flavor_user()
    assert (
        mock.call("volume", "type", "show", "ceph_shared")
        in builder.osc.json.call_args_list
    )
    assert builder.launch_selection.volume_type_availability_zones == frozenset(
        {"bc-van1", "bc-van2"}
    )


def test_launch_selection_uses_image_virtual_size_for_volume_sizing(config_factory):
    config = config_factory(
        action="plan",
        storage="volume",
        volume_size=20,
        input_sources={"image": "CLI", "flavor": "CLI", "storage": "CLI"},
    )
    osc = mock.Mock()
    osc.json.side_effect = [
        {
            "id": "image-1",
            "name": "debian-13",
            "min_disk": 0,
            "virtual_size": 40 * 1024**3 + 1,
            "properties": {"os_admin_user": "debian"},
        },
        {"id": "flavor-1", "name": "x1.nano", "ram": 1024, "vcpus": 1, "disk": 0},
    ]
    selection = resolve_launch_selection(config, osc, mock.Mock())
    assert selection.image_virtual_size_gib == 41
    assert selection.image_required_disk_gib == 41
    assert config.volume_size == 41


def test_created_volume_must_report_requested_compute_az(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run", storage="volume")
    builder.logger = mock.Mock()
    builder._discard_failed_boot_volume = mock.Mock()
    record = mock.Mock()
    with pytest.raises(
        PlacementUnavailableError, match="requested placement was not honoured"
    ):
        builder._validate_created_volume_availability_zone(
            "bc-van1", "bc-van2", "root-volume", "volume-1", record
        )
    builder._discard_failed_boot_volume.assert_called_once_with("volume-1", record)


def test_created_volume_missing_actual_az_is_rejected(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run", storage="volume")
    builder.logger = mock.Mock()
    builder._discard_failed_boot_volume = mock.Mock()
    with pytest.raises(PlacementUnavailableError, match="UNKNOWN"):
        builder._validate_created_volume_availability_zone(
            "bc-van1", "", "root-volume", "volume-1", None
        )
