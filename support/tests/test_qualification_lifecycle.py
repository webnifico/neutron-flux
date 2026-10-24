from __future__ import annotations

import dataclasses
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.errors import PlacementUnavailableError, SuiteError
from neutron_flux.models import (
    Endpoint,
    HostQualificationHost,
    HostQualificationPair,
    HostQualificationPlan,
    Plan,
    PlannedGroup,
    RunCheckpoint,
    RuntimeGroup,
)
from neutron_flux.models import (
    TestSpec as FluxTestSpec,
)
from neutron_flux.resources import ResourceBuilder
from neutron_flux.utils import iso_utc


def _pair(
    pair_id: str = "HQ-PAIR-1-2",
    source: str = "compute1",
    destination: str = "compute2",
    source_zone: str = "az1",
    destination_zone: str = "az2",
) -> HostQualificationPair:
    return HostQualificationPair(
        pair_id,
        source,
        destination,
        source_zone,
        destination_zone,
        source == destination,
        source_zone == destination_zone,
        (
            "exact-same-host"
            if source == destination
            else "exact-same-az"
            if source_zone == destination_zone
            else "independent-cross-az"
        ),
    )


def _plan(
    *,
    strategy: str = "stable",
    cycles: int = 2,
    pairs: list[HostQualificationPair] | None = None,
) -> Plan:
    group = PlannedGroup(
        "provider-public1",
        "provider",
        "Public1",
        "n1",
        "Public1",
        ["s1"],
        [4],
    )
    spec = FluxTestSpec(
        "PROVIDER-ICMP",
        "provider-subnet",
        "probe",
        4,
        "reachable",
        "provider peers should communicate",
        True,
        [group.id],
        source_group_id=group.id,
        destination_group_id=group.id,
        source_side="A",
        destination_side="B",
        protocol="icmp",
        phase="intra",
        display_name="Provider ICMP",
    )
    selected_pairs = pairs or [_pair()]
    host_rows: dict[str, HostQualificationHost] = {}
    for pair in selected_pairs:
        host_rows[pair.source_host] = HostQualificationHost(
            pair.source_host,
            pair.source_availability_zone,
            True,
            True,
            service_ids=[f"service-{pair.source_host}"],
        )
        host_rows[pair.destination_host] = HostQualificationHost(
            pair.destination_host,
            pair.destination_availability_zone,
            True,
            True,
            service_ids=[f"service-{pair.destination_host}"],
        )
    qualification = HostQualificationPlan(
        True,
        "2026-07-26T00:00:00Z",
        "f" * 64,
        strategy,
        "full",
        cycles,
        False,
        hosts=list(host_rows.values()),
        pairs=selected_pairs,
    )
    return Plan(
        [group],
        [],
        {"performance_estimated_seconds": 1},
        [],
        tests=[spec],
        host_qualification=qualification,
    )


def _endpoint(host: str, side: str, zone: str) -> Endpoint:
    token = f"{host}-{side}".lower()
    return Endpoint(
        label=f"{host} side {side}",
        server_id=f"server-{token}",
        server_name=f"server-{token}",
        management_port_id=f"management-{token}",
        management_ip=f"10.0.0.{10 if side == 'A' else 11}",
        test_port_id=f"test-{token}",
        test_mac="fa:16:3e:00:00:01",
        fixed_ips={"s1": f"192.0.2.{10 if side == 'A' else 11}"},
        host=host,
        availability_zone=zone,
        volume_id=None,
        side=side,
        metadata={
            "requested_host": host,
            "placement_method": "nova-availability-zone-host",
        },
    )


class _Builder:
    def __init__(
        self,
        plan: Plan,
        *,
        fail_host: str | None = None,
        placement_override: str | None = None,
        generation_override: int | None = None,
    ):
        self.discovery = SimpleNamespace()
        self.plan = plan
        self.fail_host = fail_host
        self.placement_override = placement_override
        self.generation_override = generation_override
        self.runtime_groups: list[RuntimeGroup] = []
        self.build_calls: list[str] = []
        self.build_generations: list[int] = []
        self.side_build_calls: list[tuple[str, str]] = []
        self.side_build_generations: list[int] = []
        self.stop_calls: list[str] = []
        self.verify_calls: list[tuple[str, str | None]] = []

    def build_group(self, group, *, sides):
        generation = self.generation_override or len(self.build_generations) + 1
        target_hosts = group.metadata.get("target_hosts") or {}
        self.build_calls.append(group.id)
        self.build_generations.append(generation)
        endpoints = []
        for side in sides:
            host = str(target_hosts.get(side) or "")
            if host == self.fail_host:
                return None
            zone = str(
                (group.metadata.get("target_availability_zones") or {}).get(side) or ""
            )
            endpoints.append(_endpoint(host, side, zone))
        runtime = RuntimeGroup(
            group,
            "n1",
            "Public1",
            ["s1"],
            None,
            endpoints,
            None,
            {},
            self.generation_override or generation,
        )
        self.runtime_groups.append(runtime)
        return runtime

    def build_group_side(self, runtime, group, side):
        generation = runtime.generation + 1
        host = str(group.metadata["target_hosts"][side])
        if host == self.fail_host:
            raise SuiteError(f"simulated VM creation failure on {host}")
        zone = str(group.metadata["target_availability_zones"][side])
        runtime.endpoints.append(_endpoint(host, side, zone))
        runtime.generation = generation
        self.side_build_calls.append((side, host))
        self.side_build_generations.append(generation)

    def verify_server_placement(
        self,
        server_id,
        port_ids,
        *,
        expected_host,
        expected_availability_zone=None,
        **_kwargs,
    ):
        observed = self.placement_override or expected_host
        self.verify_calls.append((server_id, expected_host))
        return {
            "server_id": server_id,
            "server": {
                "status": "ACTIVE",
                "OS-EXT-SRV-ATTR:host": observed,
                "OS-EXT-AZ:availability_zone": expected_availability_zone,
            },
            "observed_host": observed,
            "observed_availability_zone": expected_availability_zone,
            "settled": True,
        }

    def compute_host_inventory(self, *, refresh):
        return {
            host.host: dataclasses.replace(host)
            for host in self.plan.host_qualification.hosts
        }

    def stop_group_probes(self, group_id):
        self.stop_calls.append(group_id)

    def stop_endpoint_probe(self, endpoint):
        self.stop_calls.append(endpoint.server_id)

    def group_failure_reason(self, group_id):
        return f"partial VM creation for {group_id}"


class _Cleanup:
    def __init__(self, builder: _Builder):
        self.builder = builder
        self.group_calls: list[str] = []
        self.side_calls: list[tuple[str, str]] = []
        self.complete = True

    def cleanup_group_side(self, group_id, side):
        self.side_calls.append((group_id, side))
        return self.complete

    def cleanup_group(self, group_id):
        self.group_calls.append(group_id)
        return self.complete


class _Store:
    def __init__(self):
        self.saved: list[RunCheckpoint] = []

    def save(self, checkpoint):
        self.saved.append(dataclasses.replace(checkpoint))


def _checkpoint(plan: Plan, metadata=None) -> RunCheckpoint:
    now = iso_utc()
    return RunCheckpoint(
        "execution-executor",
        "PLANNED",
        "run",
        "planning",
        None,
        now,
        now,
        now,
        [],
        [],
        [item.id for item in plan.tests],
        [],
        "manifest.jsonl",
        "reports",
        plan_path="plan.json",
        metadata=metadata or {},
    )


def test_public_placement_api_returns_supported_evidence(
    config_factory,
):
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder.reporter = SimpleNamespace(event=mock.Mock())
    builder._wait_for_server_settlement = mock.Mock(
        return_value={
            "Status": "ACTIVE",
            "OS-EXT-SRV-ATTR:host": "compute1",
            "OS-EXT-AZ:availability_zone": "az1",
        }
    )

    evidence = builder.verify_server_placement(
        "server-1",
        ["port-1", "port-2"],
        expected_host="compute1",
        expected_availability_zone="az1",
        stable_observations=3,
    )

    assert evidence["settled"] is True
    assert evidence["observed_host"] == "compute1"
    assert evidence["observed_availability_zone"] == "az1"
    assert evidence["stable_observations"] == 3
    builder.reporter.event.assert_called_once()


@pytest.mark.parametrize(
    ("host", "zone", "match"),
    [
        ("compute9", "az1", "requested host compute1"),
        ("compute1", "az9", "requested availability zone az1"),
    ],
)
def test_public_placement_api_rejects_host_or_az_mismatch(
    config_factory,
    host,
    zone,
    match,
):
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder.reporter = SimpleNamespace(event=mock.Mock())
    builder._wait_for_server_settlement = mock.Mock(
        return_value={
            "Status": "ACTIVE",
            "OS-EXT-SRV-ATTR:host": host,
            "OS-EXT-AZ:availability_zone": zone,
        }
    )

    with pytest.raises(PlacementUnavailableError, match=match):
        builder.verify_server_placement(
            "server-1",
            ["port-1"],
            expected_host="compute1",
            expected_availability_zone="az1",
        )
