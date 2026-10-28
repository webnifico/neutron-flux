from __future__ import annotations

from types import SimpleNamespace

import pytest

from neutron_flux.errors import SuiteError
from neutron_flux.models import Plan, PlannedGroup
from neutron_flux.models import TestSpec as FluxTestSpec
from neutron_flux.multi_zone import cross_zone_specs
from neutron_flux.zones import ZonePreflight


def provider_plan() -> Plan:
    group = PlannedGroup(
        id="provider",
        kind="provider",
        label="Provider",
        network_id="network",
        network_name="Public1",
        subnet_ids=["subnet"],
        families=[4],
    )
    spec = FluxTestSpec(
        id="PROVIDER-TCP",
        category="same-subnet",
        operation="probe",
        family=4,
        expectation="reachable",
        expectation_reason="provider path",
        authoritative=True,
        dependencies=[group.id],
        source_group_id=group.id,
        destination_group_id=group.id,
        source_side="A",
        destination_side="B",
        phase="intra",
        protocol="tcp",
    )
    return Plan([group], [], {}, [], tests=[spec])


def test_cross_zone_generation_refuses_case_colliding_zone_ids():
    with pytest.raises(SuiteError, match="test ID collision"):
        cross_zone_specs(provider_plan(), ["zone-a", "ZONE-A"])


def test_zone_preflight_rejects_case_ambiguous_selected_zones():
    preflight = object.__new__(ZonePreflight)
    preflight.osc = SimpleNamespace()
    preflight.config = SimpleNamespace(
        availability_zones_all=True,
        availability_zones=[],
        zone_mode="both",
        storage="host",
        compute_host_connectivity_enabled=False,
        require_shared_compute_aggregate=False,
    )
    preflight.discovery = SimpleNamespace(networks=[], quota_info={})
    preflight.plan = SimpleNamespace(estimated={})
    preflight.launch_selection = SimpleNamespace(flavor_vcpus=1, flavor_ram_mb=512)
    preflight.logger = SimpleNamespace(section=lambda message: None)
    preflight.reporter = SimpleNamespace(
        event=lambda *args, **kwargs: None,
        resources=[],
    )
    preflight._largest_migration_cohort = lambda hosts: len(hosts)
    preflight._validate_parallel_quota = lambda count: None

    class ProbeBuilder:
        work_dir = __import__("pathlib").Path("/tmp/nonexistent-flux-zone-test")
        _aggregate_inventory_state = "complete"

        def compute_host_inventory(self, refresh=True):
            from neutron_flux.models import ComputeHostInfo

            return {
                "one": ComputeHostInfo("one", "zone-a", True, True),
                "two": ComputeHostInfo("two", "ZONE-A", True, True),
            }

    import neutron_flux.zones as zones_module

    original = zones_module.ResourceBuilder
    zones_module.ResourceBuilder = lambda *args, **kwargs: ProbeBuilder()
    try:
        with pytest.raises(SuiteError, match="differ only by letter case"):
            preflight.build()
    finally:
        zones_module.ResourceBuilder = original
