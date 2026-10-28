from __future__ import annotations

import dataclasses
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.az_policy import select_neutron_zone, select_volume_zone
from neutron_flux.errors import SuiteError
from neutron_flux.models import ComputeHostInfo

from ._shared import _az_builder, _zone_launch_selection
from .test_service_zone_placement import _discovery, _runtime, _volume_runtime


@pytest.mark.parametrize("zone", ["bc-van1", "bc-van2", "bc-van3"])
@pytest.mark.parametrize("network_zones", [{}, {"nova": True}, {"a": True, "b": True}])
@pytest.mark.parametrize("network_supported", [True, False])
def test_router_matches_compute_even_when_network_does_not(
    config_factory, discovery_fixture, zone, network_zones, network_supported
):
    discovery = _discovery(
        discovery_fixture,
        network_zones,
        {"bc-van1": True, "bc-van2": True, "bc-van3": True},
    )
    if not network_supported:
        discovery.network_extensions.remove("network_availability_zone")
    builder = _runtime(config_factory(), discovery)
    builder.selected_availability_zone = zone
    assert builder._availability_zone_hint_args("router") == [
        "--availability-zone-hint",
        zone,
    ]
    assert builder._availability_zone_hint_args("network") == (
        ["--availability-zone-hint", "nova"]
        if network_supported and network_zones == {"nova": True}
        else []
    )


@pytest.mark.parametrize("kind", ["network", "router"])
@pytest.mark.parametrize("fallback", [{"shared": True}, {"a": True, "b": True}])
def test_unavailable_matching_neutron_az_records_fallback(
    config_factory, discovery_fixture, kind, fallback
):
    zones = {"bc-van3": False, **fallback}
    discovery = _discovery(discovery_fixture, zones, zones)
    result = select_neutron_zone(
        config_factory(),
        discovery,
        discovery.neutron_availability_zones,
        kind,
        "bc-van3",
    )
    assert result["requested_availability_zone"] == (
        "shared" if len(fallback) == 1 else None
    )
    assert result["matching_zone_unavailable"] is True
    assert result["advertised_zones"]["bc-van3"] is False


@pytest.mark.parametrize(
    "available,type_zones,expected",
    [
        ({"bc-van3", "storage"}, None, "bc-van3"),
        ({"bc-van3", "storage"}, {"bc-van3"}, "bc-van3"),
        ({"bc-van3", "storage"}, {"storage"}, None),
        ({"storage"}, None, None),
        ({"a", "b"}, None, None),
        (None, None, None),
        (None, {"bc-van3"}, None),
    ],
)
def test_volume_policy_uses_only_verified_compatible_matches(
    config_factory, available, type_zones, expected
):
    choice = select_volume_zone(
        config_factory(storage="volume"), available, type_zones, "bc-van3"
    )
    assert choice["requested_availability_zone"] == expected
    assert choice["compute_availability_zone"] == "bc-van3"


@pytest.mark.parametrize(
    "available,type_zones", [(set(), None), ({"storage"}, {"other"})]
)
def test_volume_defaults_do_not_hide_empty_or_incompatible_storage(
    config_factory, available, type_zones
):
    with pytest.raises(SuiteError):
        select_volume_zone(
            config_factory(storage="volume"), available, type_zones, "bc-van3"
        )


@pytest.mark.parametrize("available", [{"storage"}, None])
def test_default_volume_fallback_preserves_compute_type_and_actual_evidence(
    config_factory, available
):
    builder = _volume_runtime(
        config_factory(
            storage="volume",
            volume_type="premium",
        ),
        compute_az="bc-van3",
    )
    builder.volume_availability_zones = available
    builder._create_server_in_az(
        "test-vm",
        ["port1"],
        selected_az="bc-van3",
        role="endpoint",
    )
    calls = [c.args for c in builder.osc.json.call_args_list]
    volume = next(c for c in calls if c[:2] == ("volume", "create"))
    server = next(c for c in calls if c[:2] == ("server", "create"))
    assert "--availability-zone" not in volume
    assert volume[volume.index("--type") + 1] == "premium"
    assert server[server.index("--availability-zone") + 1] == "bc-van3"
    evidence = next(
        c.kwargs
        for c in builder.reporter.event.call_args_list
        if c.args[0] == "volume-availability-zone-selected"
    )
    assert evidence["compute_availability_zone"] == "bc-van3"
    assert evidence["volume_availability_zone"] == "storage"
    assert evidence["requested_volume_availability_zone"] is None
    assert evidence["matches_compute_zone"] is False


def test_default_volume_fallback_does_not_move_targeted_host_on_nova_rejection(
    config_factory,
):
    builder = _volume_runtime(config_factory(storage="volume"), reject_attach=True)
    with pytest.raises(SuiteError, match="Cross AZ volume attach is not allowed"):
        builder._create_server_in_az(
            "test-vm",
            ["port1"],
            selected_az="zone-a",
            target_host="host1",
            role="endpoint",
        )
    server_calls = [
        c.args
        for c in builder.osc.json.call_args_list
        if c.args[:2] == ("server", "create")
    ]
    assert len(server_calls) == 1
    assert (
        server_calls[0][server_calls[0].index("--availability-zone") + 1]
        == "zone-a:host1"
    )
    builder._discard_failed_boot_volume.assert_called_once()


def test_volume_default_does_not_invent_compute_zone_from_storage_name(config_factory):
    builder = _volume_runtime(config_factory(storage="volume"))
    builder._create_server_in_az(
        "test-vm", ["port1"], selected_az=None, role="controller"
    )
    server = next(
        c.args
        for c in builder.osc.json.call_args_list
        if c.args[:2] == ("server", "create")
    )
    assert "--availability-zone" not in server


def test_explicit_compute_zone_is_not_filtered_by_storage_type(config_factory):
    builder = _az_builder(
        config_factory(storage="volume", availability_zones=["bc-van3"]),
        {"host3": ComputeHostInfo("host3", "bc-van3", True, True, set(), set())},
    )
    builder.launch_selection = dataclasses.replace(
        _zone_launch_selection(),
        volume_type_availability_zones=frozenset({"storage"}),
    )
    builder._volume_availability_zone_inventory = mock.Mock(return_value={"storage"})
    builder._select_run_availability_zone()
    assert builder.selected_availability_zone == "bc-van3"
    assert builder.availability_zone_candidates == ["bc-van3"]


def test_matching_volume_request_cannot_be_silently_downgraded_to_fallback(
    config_factory,
):
    builder = _volume_runtime(config_factory(storage="volume"))
    builder.volume_availability_zones = {"zone-a", "storage"}
    builder.launch_selection = dataclasses.replace(
        _zone_launch_selection(), volume_type_availability_zones=None
    )
    with pytest.raises(SuiteError, match="requested placement was not honoured"):
        builder._create_server_in_az(
            "test-vm", ["port1"], selected_az="zone-a", role="endpoint"
        )
    assert not any(
        c.args[:2] == ("server", "create") for c in builder.osc.json.call_args_list
    )
    builder._discard_failed_boot_volume.assert_called_once()


def test_all_matching_services_request_compute_zone(config_factory, discovery_fixture):
    zone = "bc-van3"
    builder = _runtime(
        config_factory(storage="volume"),
        _discovery(discovery_fixture, {zone: True}, {zone: True}),
    )
    builder.selected_availability_zone = zone
    builder.volume_availability_zones = {zone}
    builder.launch_selection = _zone_launch_selection()
    builder._prepare_neutron_placement()
    for kind in ("network", "router"):
        assert builder._availability_zone_hint_args(kind) == [
            "--availability-zone-hint",
            zone,
        ]
    assert builder._volume_az_selection(zone)["requested_availability_zone"] == zone
    assert len(builder.reporter.event.call_args_list) == 3
    builder.osc.json.assert_not_called()


def test_volume_inventory_is_read_before_preparation_mutations(config_factory):
    builder = _az_builder(
        config_factory(storage="volume"),
        {
            "host3": ComputeHostInfo("host3", "bc-van3", True, True, set(), set()),
        },
    )
    builder.osc = mock.Mock()
    builder.osc.optional_json.return_value = [
        {"Zone Name": "storage", "Zone Status": "available"}
    ]
    builder._select_run_availability_zone()
    builder.osc.optional_json.assert_called_once_with(
        "availability", "zone", "list", "--volume", timeout=60
    )
    builder.osc.json.assert_not_called()
    builder.osc.run.assert_not_called()


@pytest.mark.parametrize("kind", ["network", "router"])
@pytest.mark.parametrize("accepted", ["bc-van1", None])
def test_controller_fallback_cannot_reuse_incompatible_hinted_topology(
    config_factory, discovery_fixture, kind, accepted
):
    builder = _runtime(config_factory(), _discovery(discovery_fixture))
    builder.selected_availability_zone = "bc-van1"
    builder.availability_zone_candidates = ["bc-van1", "bc-van3"]
    builder._create_server_in_az = mock.Mock(side_effect=SuiteError("must not submit"))
    builder.reporter.resources = [
        SimpleNamespace(
            resource_type=kind,
            id="existing",
            delete_status="present",
            metadata={
                "neutron_az_placement": {
                    "requested_availability_zone": accepted,
                    "advertised_zones": {"bc-van1": True, "bc-van3": True},
                }
            },
        )
    ]
    with pytest.raises(SuiteError, match="cannot reuse that topology"):
        builder._validate_controller_network_zone("bc-van3")
    builder._create_server_in_az.assert_not_called()


def test_shared_neutron_zone_still_allows_controller_compute_fallback(
    config_factory, discovery_fixture
):
    builder = _runtime(config_factory(), _discovery(discovery_fixture))
    builder.reporter.resources = [
        SimpleNamespace(
            resource_type=kind,
            id=kind,
            delete_status="present",
            metadata={
                "neutron_az_placement": {
                    "requested_availability_zone": "shared",
                    "advertised_zones": {"shared": True},
                }
            },
        )
        for kind in ("network", "router")
    ]
    builder._validate_controller_network_zone("bc-van3")


def test_controller_fallback_skips_conflicting_zone_without_submitting(
    config_factory, discovery_fixture
):
    from neutron_flux.errors import PlacementUnavailableError

    builder = _runtime(config_factory(), _discovery(discovery_fixture))
    builder.selected_availability_zone = "bc-van1"
    builder.availability_zone_candidates = ["bc-van1", "bc-van3"]
    builder._create_server_in_az = mock.Mock(
        side_effect=PlacementUnavailableError("No valid host")
    )
    builder.reporter.resources = [
        SimpleNamespace(
            resource_type="network",
            id="management",
            delete_status="present",
            metadata={
                "neutron_az_placement": {
                    "requested_availability_zone": "bc-van1",
                    "advertised_zones": {"bc-van1": True, "bc-van3": True},
                }
            },
        )
    ]
    with pytest.raises(PlacementUnavailableError, match="cannot reuse that topology"):
        builder._create_server(
            "controller", ["port1"], role="controller", allow_az_fallback=True
        )
    assert [
        c.kwargs["selected_az"] for c in builder._create_server_in_az.call_args_list
    ] == ["bc-van1"]
