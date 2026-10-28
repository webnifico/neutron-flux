from __future__ import annotations

import dataclasses
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.config import Config
from neutron_flux.errors import SuiteError
from neutron_flux.host_qualification import HostQualificationPlanner
from neutron_flux.models import (
    HostQualificationHost,
    HostQualificationPair,
    HostQualificationPlan,
    Plan,
    PlannedGroup,
)
from neutron_flux.models import (
    TestSpec as FluxTestSpec,
)
from neutron_flux.report_exports import (
    render_host_qualification_csv,
    render_incident_summary,
)
from neutron_flux.reporting_components.dashboard_model import build_dashboard_model


class _Inventory:
    def __init__(
        self,
        services: list[dict[str, object]],
        *,
        aggregates: list[dict[str, object]] | None = None,
    ):
        self.services = services
        self.aggregates = aggregates or []

    def json(self, *args: str, **_kwargs: object) -> object:
        if args[:3] == ("compute", "service", "list"):
            return self.services
        if args[:2] == ("aggregate", "list"):
            return [
                {"id": item["id"], "name": item["name"]} for item in self.aggregates
            ]
        if args[:2] == ("aggregate", "show"):
            return next(item for item in self.aggregates if str(item["id"]) == args[2])
        raise AssertionError(f"Unexpected OpenStack inventory query: {args!r}")

    def optional_json(self, *_args: str, **_kwargs: object) -> object:
        return None


def _service(
    host: str,
    zone: str,
    *,
    service_id: str | None = None,
    status: str = "enabled",
    state: str = "up",
) -> dict[str, object]:
    return {
        "ID": service_id or f"service-{host}",
        "Host": host,
        "Zone": zone,
        "Status": status,
        "State": state,
    }


def _plan() -> Plan:
    group = PlannedGroup(
        id="provider-public1",
        kind="provider",
        label="Public1",
        network_id="n1",
        network_name="Public1",
        subnet_ids=["s1v4"],
        families=[4],
    )
    spec = FluxTestSpec(
        id="PROVIDER-IPV4-A-TO-B",
        category="provider-subnet",
        operation="probe",
        family=4,
        expectation="reachable",
        expectation_reason="provider-network peers should communicate",
        authoritative=True,
        dependencies=[group.id],
        source_group_id=group.id,
        destination_group_id=group.id,
        source_side="A",
        destination_side="B",
        protocol="icmp",
        phase="intra",
    )
    return Plan([group], [], {"performance_estimated_seconds": 7}, [], tests=[spec])


def _build(
    config: Config,
    discovery_fixture,
    inventory: _Inventory,
) -> HostQualificationPlan:
    result = HostQualificationPlanner(
        config,
        discovery_fixture,
        _plan(),
        inventory,
        mock.Mock(),
    ).build()
    assert result is not None
    return result


def test_planner_builds_complete_pair_matrix_and_stable_estimate(
    config_factory,
    discovery_fixture,
):
    config = config_factory(
        target_hosts=["compute1", "compute2", "compute3"],
        include_same_host=True,
        qualification_cycles=2,
        qualification_strategy="auto",
    )
    inventory = _Inventory(
        [
            _service("compute1", "az1"),
            _service("compute2", "az1"),
            _service("compute3", "az2"),
        ]
    )

    first = _build(config, discovery_fixture, inventory)
    second = _build(config, discovery_fixture, inventory)

    assert first.strategy == "stable"
    assert len(first.hosts) == 3
    assert len(first.pairs) == 6
    assert sum(pair.same_host for pair in first.pairs) == 3
    assert {pair.execution_mode for pair in first.pairs} == {
        "exact-same-host",
        "exact-same-az",
        "independent-cross-az",
    }
    assert first.estimates["peak_endpoint_instances"] == 6
    assert first.estimates["endpoint_vm_boots"] == 6
    assert first.estimates["targeted_migrations"] == 0
    assert first.estimates["planned_host_sensitive_results"] == 12
    assert first.inventory_fingerprint == second.inventory_fingerprint


def test_exact_same_az_pairs_auto_select_rolling_targeted_migrations(
    config_factory,
    discovery_fixture,
):
    config = config_factory(
        target_host_pairs=[("compute1", "compute2")],
        qualification_strategy="auto",
        qualification_profile="full",
        qualification_cycles=2,
        compute_host_connectivity_enabled=True,
    )
    inventory = _Inventory(
        [
            _service("compute1", "az1"),
            _service("compute2", "az1"),
        ]
    )

    qualification = _build(config, discovery_fixture, inventory)

    assert qualification.strategy == "rolling"
    assert qualification.estimates["targeted_migrations"] == 2
    assert qualification.estimates["endpoint_vm_boots"] == 4


def test_aggregate_snapshot_and_duplicate_service_rows_are_not_silently_used(
    config_factory,
    discovery_fixture,
):
    config = config_factory(target_aggregates=["edge"])
    inventory = _Inventory(
        [
            _service("compute1.example", "az1", service_id="one"),
            _service("compute1.example", "az1", service_id="duplicate"),
            _service("compute2.example", "az1"),
        ],
        aggregates=[
            {
                "id": "42",
                "name": "edge",
                "hosts": ["compute1.example", "compute2.example"],
            }
        ],
    )

    qualification = _build(config, discovery_fixture, inventory)

    assert qualification.resolved_aggregate_ids == ["42"]
    assert qualification.resolved_aggregate_names == ["edge"]
    duplicate = next(
        host for host in qualification.hosts if host.host == "compute1.example"
    )
    assert duplicate.eligible is False
    assert any("2 nova-compute service rows" in item for item in duplicate.blockers)
    assert qualification.pairs[0].status == "BLOCKED_BY_PREREQUISITE"


def test_ambiguous_short_host_alias_is_rejected(
    config_factory,
    discovery_fixture,
):
    config = config_factory(target_hosts=["compute1"])
    inventory = _Inventory(
        [
            _service("compute1.a.example", "az1"),
            _service("compute1.b.example", "az1"),
        ]
    )

    with pytest.raises(SuiteError, match="alias 'compute1' is ambiguous"):
        _build(config, discovery_fixture, inventory)


def test_exact_pair_configuration_is_strict_and_deduplicates_reverse(
    monkeypatch,
    tmp_path,
):
    monkeypatch.chdir(tmp_path)
    args = SimpleNamespace(
        action="plan",
        config=None,
        image="debian-13",
        flavor="x1.nano",
        storage="host",
        volume_size=None,
        volume_type=None,
        external_networks="Public1,Public2,Public3",
        target_hosts=None,
        target_aggregates=None,
        target_host_pairs="compute1:compute2,compute2:compute1",
        include_same_host=False,
        qualification_strategy="rolling",
        qualification_profile="connectivity",
        qualification_cycles=3,
    )

    config = Config.from_args(args)

    assert config.target_host_pairs == [("compute1", "compute2")]
    assert config.qualification_strategy == "rolling"
    assert config.qualification_profile == "full"
    assert config.qualification_cycles == 1


def test_dashboard_exposes_host_cards_pair_matrix_and_cycle_statistics():
    plan = _plan()
    plan.host_qualification = HostQualificationPlan(
        enabled=True,
        generated_at="2026-07-26T00:00:00Z",
        inventory_fingerprint="a" * 64,
        strategy="stable",
        profile="full",
        cycles=2,
        include_same_host=False,
        hosts=[
            HostQualificationHost("compute1", "az1", True, True),
            HostQualificationHost("compute2", "az1", True, True),
        ],
        pairs=[
            HostQualificationPair(
                "HQ-PAIR",
                "compute1",
                "compute2",
                "az1",
                "az1",
                False,
                True,
                "exact-same-az",
            )
        ],
    )
    payload = {
        "run": {"final_status": "PASS"},
        "configuration": {"availability_zones": []},
        "discovery": {
            "networks": [],
            "subnets": [],
            "pools": [],
            "address_scopes": [],
        },
        "plan": dataclasses.asdict(plan),
        "resources": [],
        "events": [],
        "cleanup": {"complete": True},
        "results": [
            {
                "test_id": f"HQ-PAIR-C{cycle}-PREREQUISITE",
                "category": "host-qualification-prerequisite",
                "status": "PASS",
                "message": "Exact placement proven",
                "family": 4,
                "details": {
                    "host_qualification": True,
                    "host_qualification_pair_id": "HQ-PAIR",
                    "host_qualification_cycle": cycle,
                    "qualification_profile": "full",
                    "requested_source_host": "compute1",
                    "requested_destination_host": "compute2",
                    "source_availability_zone": "az1",
                    "destination_availability_zone": "az1",
                    "endpoints": [
                        {
                            "requested_host": "compute1",
                            "observed_host": "compute1",
                            "server_id": f"server-a-{cycle}",
                        },
                        {
                            "requested_host": "compute2",
                            "observed_host": "compute2",
                            "server_id": f"server-b-{cycle}",
                        },
                    ],
                },
            }
            for cycle in (1, 2)
        ],
    }

    qualification = build_dashboard_model(payload)["host_qualification"]

    assert qualification["enabled"] is True
    assert qualification["inventory_fingerprint"] == "a" * 64
    assert len(qualification["hosts"]) == 2
    assert qualification["pairs"][0]["completed_cycles"] == [1, 2]
    assert qualification["pairs"][0]["relationship"] == "Same AZ"
    assert qualification["pairs"][0]["rerun_fragment"].startswith(
        "--target-host-pairs compute1:compute2"
    )

    payload["dashboard"] = build_dashboard_model(payload)
    csv_text = render_host_qualification_csv(payload)
    incident = render_incident_summary(payload)
    assert "pair_id,cycle,total_cycles,source_host,destination_host" in csv_text
    assert len(csv_text.splitlines()) == 3
    assert "Host qualification: 1/1 pair rows" in incident
    assert "`" + ("a" * 64) + "`" in incident
