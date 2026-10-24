from __future__ import annotations

import dataclasses
from collections import Counter
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.az_policy import (
    discover_neutron_zones,
    select_neutron_zone,
    validate_delegated_volume_zones,
)
from neutron_flux.cli import (
    parser,
)
from neutron_flux.errors import CommandError, SuiteError
from neutron_flux.models import ComputeHostInfo
from neutron_flux.reporting import Reporter, ResourceTracker
from neutron_flux.reporting_components.dashboard_environment import (
    build_network_inventory,
)
from neutron_flux.reporting_components.html import build_run_payload
from neutron_flux.reporting_components.report_payload import build_report_payload
from neutron_flux.resources import ResourceBuilder
from neutron_flux.zones import ZonePreflight

from ._shared import _az_builder, _zone_hosts, _zone_launch_selection, build_plan
from .test_host_qualification import _build, _Inventory, _service


def _discovery(discovery, network=None, router=None):
    return dataclasses.replace(
        discovery,
        network_extensions=[
            "availability_zone",
            "network_availability_zone",
            "router_availability_zone",
        ],
        neutron_availability_zones={"network": network or {}, "router": router or {}},
    )


def _runtime(config, discovery):
    builder = object.__new__(ResourceBuilder)
    builder.config = config
    builder.discovery = discovery
    builder.selected_availability_zone = "zone-a"
    builder.pending_neutron_az_validation = {}
    builder.osc = mock.Mock()
    builder.logger = mock.Mock()
    builder.reporter = mock.Mock()
    builder.reporter.resources = []
    return builder


@pytest.mark.parametrize("name", ["nova", "default", "network-services", "zone-a"])
@pytest.mark.parametrize("kind", ["network", "router"])
def test_sole_neutron_az_is_not_a_magic_name(
    config_factory, discovery_fixture, name, kind
):
    discovery = _discovery(discovery_fixture, {name: True}, {name: True})
    result = select_neutron_zone(
        config_factory(),
        discovery,
        discovery.neutron_availability_zones,
        kind,
        "zone-a",
    )
    assert result["requested_availability_zone"] == name
    assert result["selection_reason"] == (
        "compute-name-match" if name == "zone-a" else "sole-available-az"
    )


def test_network_and_router_inventory_is_separate_and_cached(discovery_fixture):
    discovery = _discovery(discovery_fixture)
    discovery.neutron_availability_zones = None
    osc = mock.Mock()
    osc.json.return_value = [
        {"Zone Name": "nova", "Zone Resource": "network", "Zone Status": "available"},
        {"Zone Name": "edge", "Zone Resource": "router", "Zone Status": "available"},
        {
            "Zone Name": "zone-a",
            "Zone Resource": "router",
            "Zone Status": "not available",
        },
    ]
    result = discover_neutron_zones(discovery, osc, timeout=60)
    assert result == {
        "network": {"nova": True},
        "router": {"edge": True, "zone-a": False},
    }
    assert discover_neutron_zones(discovery, osc, timeout=60) == result
    osc.json.assert_called_once_with(
        "availability", "zone", "list", "--network", "--long", timeout=60
    )


@pytest.mark.parametrize(
    "rows",
    [
        None,
        {},
        [42],
        [{"Zone Name": "nova", "Zone Status": "available"}],
        [{"Zone Name": "nova", "Zone Resource": "network", "Zone Status": "unknown"}],
    ],
)
def test_bad_neutron_inventory_never_invents_hints(discovery_fixture, rows):
    discovery = _discovery(discovery_fixture)
    discovery.neutron_availability_zones = None
    osc = mock.Mock()
    osc.json.return_value = rows
    with pytest.raises(SuiteError):
        discover_neutron_zones(discovery, osc, timeout=60)
    assert discovery.neutron_availability_zones is None


@pytest.mark.parametrize(
    "zones,pattern",
    [
        ({"nova": False}, "no available AZs"),
    ],
)
def test_neutron_fallback_does_not_hide_outages_or_ambiguity(
    config_factory, discovery_fixture, zones, pattern
):
    discovery = _discovery(discovery_fixture, zones)
    with pytest.raises(SuiteError, match=pattern):
        select_neutron_zone(
            config_factory(),
            discovery,
            discovery.neutron_availability_zones,
            "network",
            "zone-a",
        )


def test_matching_neutron_az_wins_over_single_default_label(
    config_factory, discovery_fixture
):
    discovery = _discovery(discovery_fixture, {"zone-a": True, "nova": True})
    result = select_neutron_zone(
        config_factory(),
        discovery,
        discovery.neutron_availability_zones,
        "network",
        "zone-a",
    )
    assert result["requested_availability_zone"] == "zone-a"


def test_delegated_networking_never_adds_hints_or_queries_admin_inventory(
    config_factory, discovery_fixture
):
    builder = _runtime(
        config_factory(allow_cross_az_networking=True),
        _discovery(discovery_fixture, {"somewhere": True}),
    )
    assert builder._availability_zone_hint_args() == []
    assert builder._availability_zone_hint_args("router") == []
    builder.osc.json.assert_not_called()


def test_missing_extension_uses_cloud_defaults_not_compute_hint(
    config_factory, discovery_fixture
):
    builder = _runtime(config_factory(), discovery_fixture)
    assert builder._availability_zone_hint_args() == []
    builder.osc.json.assert_not_called()
    assert builder._availability_zone_hint_args("router") == []


def test_creation_accepts_hint_before_scheduling_then_records_actual_az(
    config_factory, discovery_fixture
):
    builder = _runtime(config_factory(), _discovery(discovery_fixture, {"nova": True}))
    builder._validate_created_resource_zone(
        "network",
        "net1",
        {"availability_zone_hints": ["nova"], "availability_zones": []},
    )
    builder.osc.json.assert_not_called()
    assert builder.reporter.event.call_args.kwargs["placement_verified"] is False
    builder.osc.json.return_value = {
        "availability_zone_hints": ["nova"],
        "availability_zones": ["nova"],
    }
    builder._refresh_neutron_placements()
    assert builder.reporter.event.call_args.kwargs["placement_verified"] is True
    assert builder.pending_neutron_az_validation == {}


def test_empty_scheduled_az_never_becomes_a_verified_placement(
    config_factory, discovery_fixture
):
    builder = _runtime(config_factory(), _discovery(discovery_fixture, {"nova": True}))
    detail = {"availability_zone_hints": ["nova"], "availability_zones": []}
    builder._validate_created_resource_zone("network", "net1", detail)
    builder.osc.json.return_value = detail
    builder._refresh_neutron_placements()
    assert builder.reporter.event.call_args.kwargs["placement_verified"] is False
    assert builder.logger.log.call_args.args[1] == "WARNING"


def test_later_placement_cannot_silently_escape_neutron_hint(
    config_factory, discovery_fixture
):
    builder = _runtime(config_factory(), _discovery(discovery_fixture, {"nova": True}))
    builder._validate_created_resource_zone(
        "network", "net1", {"availability_zone_hints": ["nova"]}
    )
    builder.osc.json.return_value = {
        "availability_zone_hints": ["nova"],
        "availability_zones": ["other"],
    }
    with pytest.raises(SuiteError, match="outside requested Neutron AZ"):
        builder._refresh_neutron_placements()


def test_network_metadata_no_longer_blocks_compute_pair(
    config_factory, discovery_fixture
):
    for network in discovery_fixture.networks:
        network.raw.update(
            {"availability_zones": ["nova"], "status": "ACTIVE", "admin_state_up": True}
        )
    qualification = _build(
        config_factory(target_host_pairs=[("c1", "c2")]),
        discovery_fixture,
        _Inventory([_service("c1", "zone-a"), _service("c2", "zone-a")]),
    )
    assert qualification.estimates["eligible_hosts"] == 2
    assert qualification.estimates["eligible_pairs"] == 1


@pytest.mark.parametrize("allowed", [False, True])
def test_host_pair_volume_mismatch_uses_storage_defaults(
    config_factory, discovery_fixture, allowed
):
    inventory = _Inventory([_service("c1", "zone-a"), _service("c2", "zone-a")])
    inventory.optional_json = mock.Mock(
        return_value=[{"Zone Name": "storage", "Zone Status": "available"}]
    )
    qualification = _build(
        config_factory(
            storage="volume",
            allow_cross_az_volumes=allowed,
            target_host_pairs=[("c1", "c2")],
        ),
        discovery_fixture,
        inventory,
    )
    assert qualification.estimates["eligible_pairs"] == 1


@pytest.mark.parametrize("allowed", [False, True])
def test_compute_selection_keeps_requested_scope_with_storage_fallback(
    config_factory, allowed
):
    config = config_factory(storage="volume", allow_cross_az_volumes=allowed)
    builder = _az_builder(
        config, {"host1": ComputeHostInfo("host1", "zone-a", True, True, set(), set())}
    )
    builder.osc = mock.Mock()
    builder.osc.optional_json.return_value = [
        {"Zone Name": "storage", "Zone Status": "available"}
    ]
    builder._select_run_availability_zone()
    assert builder.selected_availability_zone == "zone-a"
    assert builder._volume_az_selection("zone-a")["requested_availability_zone"] is None


def _volume_runtime(
    config, *, actual_volume_az="storage", compute_az="zone-a", reject_attach=False
):
    builder = object.__new__(ResourceBuilder)
    builder.config = config
    builder.flavor_id = "flavor1"
    builder.keypair_name = "key1"
    builder.image_id = "image1"
    builder.image_name = "debian-13"
    builder.server_sequence = 0
    builder.run_tag = "sample-test"
    builder.launch_selection = dataclasses.replace(
        _zone_launch_selection(),
        volume_type_availability_zones=frozenset({actual_volume_az}),
    )
    builder.volume_availability_zones = {actual_volume_az}
    builder.logger = mock.Mock()
    builder.reporter = mock.Mock()
    builder.tracker = mock.Mock()
    builder.tracker.add.side_effect = lambda *_a, **kw: SimpleNamespace(metadata=kw)
    builder._recover_created_resource_by_name = mock.Mock(return_value=None)
    builder._discard_failed_boot_volume = mock.Mock()
    server = {
        "id": "server1",
        "status": "ACTIVE",
        "OS-EXT-SRV-ATTR:host": "host1",
        "OS-EXT-AZ:availability_zone": compute_az,
    }
    builder.verify_server_placement = mock.Mock(return_value={"server": server})
    builder.osc = mock.Mock()

    def json_call(*args, **kwargs):
        if args[:2] in {("volume", "create"), ("volume", "show")}:
            return {
                "id": "volume1",
                "status": "available",
                "availability_zone": actual_volume_az,
            }
        if args[:2] == ("server", "create") and reject_attach:
            raise CommandError(
                ["openstack", *args], 1, "", "Cross AZ volume attach is not allowed"
            )
        if args[:2] in {("server", "create"), ("server", "show")}:
            return server
        raise AssertionError(args)

    builder.osc.json.side_effect = json_call
    return builder


@pytest.mark.parametrize("allowed", [False, True])
@pytest.mark.parametrize("compute_az", ["zone-a", "zone-b"])
def test_volume_command_delegation_never_moves_compute_host(
    config_factory, allowed, compute_az
):
    volume_az = "storage" if allowed else compute_az
    builder = _volume_runtime(
        config_factory(
            storage="volume", allow_cross_az_volumes=allowed, volume_type="premium"
        ),
        actual_volume_az=volume_az,
        compute_az=compute_az,
    )
    result = builder._create_server_in_az(
        "test-vm",
        ["port1"],
        selected_az=compute_az,
        target_host="host1",
        role="endpoint",
    )
    calls = [c.args for c in builder.osc.json.call_args_list]
    volume = next(args for args in calls if args[:2] == ("volume", "create"))
    server = next(args for args in calls if args[:2] == ("server", "create"))
    assert ("--availability-zone" not in volume) is allowed
    assert volume[volume.index("--type") + 1] == "premium"
    assert server[server.index("--availability-zone") + 1] == f"{compute_az}:host1"
    assert result["availability_zone"] == compute_az


def test_cross_volume_flag_does_not_bypass_nova_rejection(config_factory):
    builder = _volume_runtime(
        config_factory(storage="volume", allow_cross_az_volumes=True),
        reject_attach=True,
    )
    with pytest.raises(SuiteError, match="Cross AZ volume attach is not allowed"):
        builder._create_server_in_az(
            "test-vm",
            ["port1"],
            selected_az="zone-a",
            target_host="host1",
            role="endpoint",
        )
    assert builder._discard_failed_boot_volume.call_count == 1
    assert (
        sum(c.args[:2] == ("server", "create") for c in builder.osc.json.call_args_list)
        == 1
    )


@pytest.mark.parametrize(
    "available,type_zones", [(set(), None), ({"storage"}, frozenset({"other"}))]
)
def test_volume_delegation_does_not_relax_type_or_capacity(
    config_factory, available, type_zones
):
    with pytest.raises(SuiteError):
        validate_delegated_volume_zones(
            config_factory(storage="volume", allow_cross_az_volumes=True),
            available,
            type_zones,
        )


@pytest.mark.parametrize("all_zones", [False, True])
@pytest.mark.parametrize("volume_zones", [{"storage"}, None])
def test_multi_zone_compute_scope_survives_delegated_storage(
    config_factory, discovery_fixture, tmp_path, monkeypatch, all_zones, volume_zones
):
    config = config_factory(
        storage="volume",
        allow_cross_az_volumes=True,
        availability_zones=[] if all_zones else ["bc-van1", "bc-van2"],
        availability_zones_all=all_zones,
        zone_mode="both",
    )
    discovery = _discovery(discovery_fixture, {"nova": True}, {"edge": True})
    monkeypatch.setattr(
        ResourceBuilder, "compute_host_inventory", lambda *_a, **_kw: _zone_hosts()
    )
    monkeypatch.setattr(
        ResourceBuilder, "_volume_availability_zone_inventory", lambda *_a: volume_zones
    )
    plan = build_plan(config, discovery, tmp_path)
    reporter = Reporter(config, "sample-zones")
    try:
        selection = dataclasses.replace(
            _zone_launch_selection(),
            volume_type_availability_zones=frozenset({"storage"}),
        )
        result = ZonePreflight(
            config, discovery, plan, mock.Mock(), reporter, selection
        ).build()
        assert result.zones == ["bc-van1", "bc-van2"]
        assert result.mode == "both"
    finally:
        reporter.logger.close()


def _cli(*flags):
    return parser().parse_args(
        [
            "run",
            "--image",
            "debian-13",
            "--flavor",
            "small",
            "--storage",
            "volume",
            "--external-networks",
            "Public",
            *flags,
        ]
    )


@pytest.mark.parametrize("actual_az", ["", "outside-type"])
def test_delegated_volume_rejects_missing_or_incompatible_actual_az(
    config_factory, actual_az
):
    builder = _volume_runtime(
        config_factory(storage="volume", allow_cross_az_volumes=True)
    )
    with pytest.raises(SuiteError, match="unknown or volume-type-incompatible"):
        builder._validate_created_volume_availability_zone(
            "zone-a", actual_az, "test-root", "volume1", None
        )
    builder._discard_failed_boot_volume.assert_called_once_with("volume1", None)


@pytest.mark.parametrize("status", ["not available", False])
def test_down_cinder_status_is_not_an_eligible_zone(config_factory, status):
    builder = _volume_runtime(config_factory(storage="volume"))
    builder.osc.optional_json.return_value = [
        {"Zone Name": "storage", "Zone Status": status}
    ]
    assert builder._volume_availability_zone_inventory() == set()


def test_reports_preserve_service_placement_and_do_not_invent_neutron_hints(
    config_factory, discovery_fixture
):
    config = config_factory(
        storage="volume",
        allow_cross_az_volumes=True,
        network_az="nova",
        router_az="edge",
    )
    builder = _runtime(
        config, _discovery(discovery_fixture, {"nova": True}, {"edge": True})
    )
    reporter = Reporter(config, "sample-evidence")
    builder.reporter = reporter
    try:
        record = ResourceTracker(reporter).add(
            "network", "net1", "test-net", availability_zone="zone-a"
        )
        inventory, _ = build_network_inventory({}, [dataclasses.asdict(record)], {})
        assert inventory[0]["availability_zone_hints"] == []
        builder._validate_created_resource_zone(
            "network",
            "net1",
            {"availability_zone_hints": ["nova"], "availability_zones": []},
        )
        builder.osc.json.return_value = {
            "availability_zone_hints": ["nova"],
            "availability_zones": ["nova"],
        }
        builder._refresh_neutron_placements()
        payload = build_run_payload(
            reporter, finished=reporter.started, final_status="PASS", counts=Counter()
        )
        compact = build_report_payload(payload)
        for data in (payload, compact):
            assert data["configuration"]["allow_cross_az_volumes"] is True
            assert (
                data["configuration"]["volume_az_policy"]
                == "prefer-compute-then-default"
            )
            assert data["configuration"]["network_az"] == "nova"
            assert data["configuration"]["router_az"] == "edge"
        evidence = payload["resources"][0]["metadata"]["neutron_az_placement"]
        assert evidence["compute_availability_zone"] == "zone-a"
        assert evidence["availability_zones"] == ["nova"]
        assert evidence["placement_verified"] is True
        inventory, _ = build_network_inventory({}, payload["resources"], {})
        assert inventory[0]["availability_zone_hints"] == ["nova"]
    finally:
        reporter.logger.close()
