from __future__ import annotations

import dataclasses
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.engine_handlers.endpoint import EndpointProbeHandlerMixin
from neutron_flux.models import ProbeResult, RuntimeGroup
from neutron_flux.openstack import OpenStack
from neutron_flux.pair_suite import pair_scope_plans

from ._shared import endpoint
from .test_full_pair_suite import executor_for, full_plan


@pytest.mark.parametrize("protocol", ["icmp", "tcp", "udp", "mtu"])
def test_only_packet_size_probes_read_the_neutron_mtu(protocol):
    spec = SimpleNamespace(
        id="ordinary-probe",
        category="same-subnet",
        protocol=protocol,
        source_group_id="group",
        destination_group_id="group",
        source_side="B",
        destination_side="A",
        source_subnet_id="subnet",
        destination_subnet_id="subnet",
        family=4,
        metadata={},
    )
    probe = ProbeResult(outcome="reachable", success=True, elapsed_ms=1, attempts=1)
    handler = SimpleNamespace(
        _endpoint_address=mock.Mock(return_value=(endpoint(), "10.0.0.2")),
        _network_mtu=mock.Mock(return_value=1450),
        probes=SimpleNamespace(endpoint=mock.Mock(return_value=probe)),
        _record=mock.Mock(),
    )
    EndpointProbeHandlerMixin._run_endpoint_probe(handler, spec)
    handler.probes.endpoint.assert_called_once()
    handler._record.assert_called_once()
    if protocol == "mtu":
        handler._network_mtu.assert_called_once_with("group", "B")
        assert handler.probes.endpoint.call_args.kwargs["network_mtu"] == 1450
    else:
        handler._network_mtu.assert_not_called()
        assert handler.probes.endpoint.call_args.kwargs["network_mtu"] is None


def test_new_group_verified_once_and_retained_group_rechecked(
    config_factory, discovery_fixture, tmp_path
):
    config, _, plan = full_plan(config_factory, discovery_fixture, tmp_path)
    lane = pair_scope_plans(plan)[0]
    executor = executor_for(lane, config)
    group = lane.groups[0]
    ep = dataclasses.replace(
        endpoint(), side="A", host="hyper001", availability_zone="az1"
    )
    runtime = RuntimeGroup(group, "net", "network", [], None, [ep], None, {})
    executor.builder.build_group.return_value = runtime
    executor._refresh_checkpoint = mock.Mock()
    executor._inject_failure = mock.Mock()
    executor._ensure((group.id,))
    assert executor.builder.build_group.call_count == 1
    assert executor.builder.verify_server_placement.call_count == 1
    executor._ensure((group.id,))
    assert executor.builder.build_group.call_count == 1
    assert executor.builder.verify_server_placement.call_count == 2


@pytest.mark.parametrize(
    "args,expected",
    [
        (
            ("--os-compute-api-version", "2.53", "server", "show", "private-id"),
            "openstack server show",
        ),
        (
            ("security", "group", "rule", "list", "private-id"),
            "openstack security group",
        ),
        (("port", "show", "private-id"), "openstack port show"),
        (("--os-password", "secret", "token", "issue"), "OpenStack CLI"),
    ],
)
def test_api_timing_labels_identify_work_without_arguments(args, expected):
    assert OpenStack._timing_label(args) == expected
