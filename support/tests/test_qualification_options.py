from __future__ import annotations

from unittest import mock

import pytest

from neutron_flux.cli import parser
from neutron_flux.config import Config
from neutron_flux.errors import PlacementUnavailableError
from neutron_flux.host_qualification import HostQualificationPlanner
from neutron_flux.models import ComputeHostInfo
from neutron_flux.planning import Planner
from neutron_flux.replay_plan import _replay_command

from ._shared import _az_builder
from .test_host_qualification import _Inventory, _service
from .test_service_zone_placement import _discovery


def _cli_config(*flags):
    return Config.from_args(
        parser().parse_args(
            [
                "run",
                "--image",
                "debian-13",
                "--flavor",
                "small",
                "--storage",
                "volume",
                "--external-networks",
                "Public1",
                *flags,
            ]
        )
    )


@pytest.mark.parametrize("profile", ["connectivity", "full", "performance"])
@pytest.mark.parametrize("enabled", [False, True])
def test_host_qualification_estimates_only_enabled_performance(
    config_factory, discovery_fixture, profile, enabled
):
    config = config_factory(
        target_host_pairs=[("c1", "c2")],
        qualification_profile=profile,
        performance_enabled=enabled,
    )
    plan = Planner(config, discovery_fixture, mock.Mock()).build()
    qualification = HostQualificationPlanner(
        config,
        discovery_fixture,
        plan,
        _Inventory([_service("c1", "zone-a"), _service("c2", "zone-a")]),
        mock.Mock(),
    ).build()
    assert qualification is not None
    assert qualification.estimates["eligible_pairs"] == 1
    seconds = qualification.estimates["estimated_performance_seconds"]
    if enabled and profile in {"full", "performance"}:
        assert seconds > 0
    else:
        assert seconds == 0
    assert qualification.estimates["planned_host_sensitive_results"] > 0


def test_legacy_replay_does_not_invent_unrecorded_az_policies():
    command = _replay_command({"configuration": {"storage": "volume"}})
    assert command is None


def _default_compute_builder(config_factory, discovery_fixture, zones):
    builder = _az_builder(
        config_factory(storage="host"),
        {"host1": ComputeHostInfo("host1", "nova", True, True)},
    )
    builder.osc = mock.Mock()
    builder.discovery = _discovery(discovery_fixture, zones, zones)
    builder._select_run_availability_zone()
    assert builder.selected_availability_zone is None
    assert builder.availability_zone_candidates == [None]
    return builder


@pytest.mark.parametrize("kind", ["network", "router"])
def test_default_compute_az_still_matches_neutron_inventory(
    config_factory, discovery_fixture, kind
):
    builder = _default_compute_builder(
        config_factory, discovery_fixture, {"nova": True, "edge": True}
    )
    choice = builder._neutron_az_selection(kind)
    assert choice["compute_availability_zone"] == "nova"
    assert choice["selection_reason"] == "compute-name-match"
    assert builder._availability_zone_hint_args(kind) == [
        "--availability-zone-hint",
        "nova",
    ]
    builder.selected_availability_zone = "edge"  # Authoritative Nova boot evidence.
    assert builder._availability_zone_hint_args(kind) == [
        "--availability-zone-hint",
        "edge",
    ]


def test_default_compute_az_records_unavailable_neutron_match(
    config_factory, discovery_fixture
):
    builder = _default_compute_builder(
        config_factory, discovery_fixture, {"nova": False, "edge": True}
    )
    choice = builder._neutron_az_selection("network")
    assert choice["matching_zone_unavailable"] is True
    assert builder._availability_zone_hint_args() == [
        "--availability-zone-hint",
        "edge",
    ]


def test_rediscovery_drops_stale_compute_az_evidence(config_factory, discovery_fixture):
    builder = _default_compute_builder(
        config_factory, discovery_fixture, {"nova": True, "edge": True}
    )
    builder.compute_host_inventory.side_effect = PlacementUnavailableError(
        "unavailable"
    )
    builder._select_run_availability_zone()
    assert builder._availability_zone_hint_args() == []
