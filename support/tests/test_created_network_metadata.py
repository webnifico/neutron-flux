"""Created networks retain the attributes Neutron already returned."""

from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.network_contract import PROJECT_NETWORK
from neutron_flux.reporting import Reporter, ResourceTracker
from neutron_flux.resources import ResourceBuilder
from neutron_flux.runtime.availability import AvailabilityRuntimeMixin


class StopAfterNetwork(RuntimeError):
    """End a creation path at its next cloud boundary."""


@pytest.mark.parametrize(
    "creation_path", ["management", "bastion", "generated", "project"]
)
def test_each_network_creation_path_preserves_returned_attributes(
    creation_path, config_factory, discovery_fixture
):
    config = config_factory(mgmt_cidr="10.48.0.0/24")
    reporter = Reporter(config, f"network-attributes-{creation_path}")
    builder = object.__new__(ResourceBuilder)
    builder.config = config
    builder.discovery = discovery_fixture
    builder.reporter = reporter
    builder.tracker = ResourceTracker(reporter)
    builder.logger = mock.Mock()
    builder.name_prefix = f"nflux-attributes-{creation_path}"
    builder.run_tag = "neutron-flux-attributes"
    builder._availability_zone_hint_args = mock.Mock(return_value=[])
    builder._neutron_az_selection = mock.Mock(
        return_value={"requested_availability_zone": None}
    )
    calls = []

    def create(*args, **_kwargs):
        calls.append(args)
        if args[:2] != ("network", "create"):
            raise StopAfterNetwork
        return {
            "id": "network-id",
            "provider:network_type": "geneve",
            "provider:physical_network": None,
            "provider:segmentation_id": "148",
            "mtu": "1442",
        }

    builder.osc = SimpleNamespace(json=create)
    group = SimpleNamespace(
        id="project-group",
        kind=PROJECT_NETWORK,
        label="Project subnet",
        families=[4],
        pool_id="subnet-pool",
        prefix_length=24,
        floating_subnet_id=None,
        external_network_id="provider-network",
        external_network_name="Provider",
        external_subnet_id="provider-subnet",
        metadata={
            "floating_ip_target_allowed": False,
            "subnet_pool_fixed_ip_only": True,
            "source_nat_mode": "cloud-default",
            "source_nat_controlled_by_flux": False,
        },
    )
    try:
        with pytest.raises(StopAfterNetwork):
            if creation_path == "management":
                builder._create_management_network()
            elif creation_path == "bastion":
                builder._create_bastion_access_topology(
                    external_network=SimpleNamespace(id="provider-network"),
                    external_subnet=SimpleNamespace(id="provider-subnet"),
                    access_cidr="192.0.2.0/24",
                    network_name=f"{builder.name_prefix}-bastion-network",
                    subnet_name=f"{builder.name_prefix}-bastion-subnet",
                    router_name=f"{builder.name_prefix}-bastion-router",
                )
            elif creation_path == "generated":
                builder._create_generated_tenant_network(
                    group, generation=1, suffix="project-a"
                )
            else:
                builder._build_tenant_group(group, sides=("A", "B"), generation=1)
        record = reporter.resources[0]
        assert record.resource_type == "network"
        assert {
            key: record.metadata[key]
            for key in ("network_type", "physical_network", "segmentation_id", "mtu")
        } == {
            "network_type": "geneve",
            "physical_network": None,
            "segmentation_id": 148,
            "mtu": 1442,
        }
        # Capture uses the create response, without adding a network SHOW.
        assert [call[:2] for call in calls] == [
            ("network", "create"),
            ("subnet", "create"),
        ]
    finally:
        reporter.logger.close()


def test_placement_fallback_combines_exposed_network_attributes_without_extra_read():
    builder = AvailabilityRuntimeMixin()
    builder.config = SimpleNamespace(resource_timeout=90)
    record = SimpleNamespace(resource_type="network", id="network-id", metadata={})
    builder.reporter = SimpleNamespace(
        resources=[record], update_resource=mock.Mock(), event=mock.Mock()
    )
    builder.osc = mock.Mock()
    builder.osc.json.return_value = {
        "availability_zone_hints": ["az1"],
        "availability_zones": ["az1"],
        "Network Type": "vlan",
        "Physical Network": "provider1",
        "Segmentation ID": "102",
    }
    selection = {"requested_availability_zone": "az1"}
    builder._validate_created_resource_zone(
        "network", "network-id", {"mtu": 1500}, selection=selection
    )
    assert {
        key: record.metadata[key]
        for key in ("network_type", "physical_network", "segmentation_id", "mtu")
    } == {
        "network_type": "vlan",
        "physical_network": "provider1",
        "segmentation_id": 102,
        "mtu": 1500,
    }
    builder.osc.json.assert_called_once_with(
        "network", "show", "network-id", timeout=60
    )

    # A narrower later read must not erase attributes it does not expose.
    builder._validate_created_resource_zone(
        "network",
        "network-id",
        {"availability_zone_hints": ["az1"], "availability_zones": ["az1"]},
        selection=selection,
        after_scheduling=True,
    )
    assert record.metadata["network_type"] == "vlan"
    assert record.metadata["mtu"] == 1500
    assert builder.osc.json.call_count == 1


@pytest.mark.parametrize(
    "detail,expected",
    [
        ({}, {}),
        ({"provider:physical_network": "None"}, {"physical_network": None}),
        (
            {"provider:segmentation_id": None, "mtu": None},
            {"segmentation_id": None, "mtu": None},
        ),
        ({"mtu": "unavailable", "network_type": False}, {}),
        ({"mtu": 0, "segmentation_id": 0}, {"segmentation_id": 0}),
        ({"mtu": True, "segmentation_id": []}, {}),
    ],
)
def test_network_metadata_does_not_invent_missing_values(detail, expected):
    assert AvailabilityRuntimeMixin._created_network_metadata(detail) == expected
