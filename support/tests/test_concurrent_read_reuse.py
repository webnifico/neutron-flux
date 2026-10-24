"""Regression checks for bounded reuse without losing evidence or cancellation."""

from __future__ import annotations

import copy
import dataclasses
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux import result_contract_compatibility
from neutron_flux.diagnostics import DiagnosticCollector
from neutron_flux.engine import TestEngine as Engine
from neutron_flux.engine_state import RouteObservationCache
from neutron_flux.errors import RunCancelledError, SuiteError
from neutron_flux.models import ProbeResult
from neutron_flux.reporting import Reporter
from neutron_flux.resources import ResourceBuilder
from neutron_flux.result_contract import normalize_result_record

from ._shared import completed, endpoint
from .test_concurrent_execution import spec
from .test_measurement_integrity import _contract_result
from .test_service_zone_placement import _volume_runtime


class RouteEngine(Engine):
    def _run_endpoint_probe(self, item):
        source = endpoint(item.source_side or "A")
        destination = endpoint(item.destination_side or "B")
        address = {"A": "192.0.2.10", "B": "192.0.2.11"}
        if item.family == 6:
            address = {"A": "fd00::10", "B": "fd00::11"}
        self._record(
            item,
            ProbeResult(
                outcome="reachable",
                success=True,
                elapsed_ms=1,
                attempts=1,
                source_ip=address[source.label],
                destination_ip=address[destination.label],
                protocol=item.protocol,
            ),
            source,
            destination,
        )

    def _run_mtu_scenario(self, item):
        self.reporter.result(item.id, item.category, "PASS", "Mutation completed")


@pytest.mark.parametrize("boundary", ["next-batch", "prerequisite", "lifecycle"])
def test_parallel_protocols_share_routes_only_within_one_wave(config_factory, boundary):
    config = config_factory()
    reporter = Reporter(config, "sample-routes")
    builder = SimpleNamespace(
        runtime_groups=[],
        ssh_endpoint=mock.Mock(),
        ssh_controller=mock.Mock(),
        inspect_endpoint_route=mock.Mock(
            return_value={"returncode": 0, "stdout": "first route"}
        ),
    )
    engine = RouteEngine(config, SimpleNamespace(), builder, reporter)
    first = [
        dataclasses.replace(
            spec(f"{family}-{source}-{protocol}"),
            family=family,
            source_side=source,
            destination_side=destination,
            protocol=protocol,
        )
        for family in (4, 6)
        for source, destination in (("A", "B"), ("B", "A"))
        for protocol in ("icmp", "tcp", "udp")
    ]
    second = [dataclasses.replace(row, id="next-" + row.id) for row in first]
    try:
        if boundary == "next-batch":
            engine.run_specs(first)
            builder.inspect_endpoint_route.return_value = {
                "returncode": 0,
                "stdout": "new route",
            }
            engine.run_specs(second)
        elif boundary == "prerequisite":
            second = [
                dataclasses.replace(row, requires=[first[0].id]) for row in second
            ]
            engine.run_specs([*second, *first])
        else:
            engine.run_specs(
                [*first, spec("mutation", operation="mtu-scenario"), *second]
            )
        assert builder.inspect_endpoint_route.call_count == 8
        records = {row.test_id: row for row in reporter.results}
        assert {row.id for row in [*first, *second]} <= records.keys()
        assert all(row.status == "PASS" for row in records.values())
        if boundary == "next-batch":
            for row in second:
                route = records[row.id].details["probe"]["diagnostics"][
                    "endpoint_route"
                ]
                assert route["stdout"] == "new route"
    finally:
        reporter.logger.close()


@pytest.mark.parametrize(
    "error", [None, RunCancelledError("cancelled"), KeyboardInterrupt()]
)
def test_concurrent_route_waiters_share_observation_or_propagate_cancellation(error):
    cache = RouteObservationCache()
    rendezvous = threading.Barrier(3)
    calls = []

    def read():
        calls.append(1)
        if error is not None:
            raise error
        return {"nested": {"output": "route"}}

    def observe():
        rendezvous.wait(timeout=3)
        return cache.observe(("vm", "source", "destination", 4), read)

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(observe) for _ in range(3)]
        if error is not None:
            for future in futures:
                with pytest.raises(type(error)):
                    future.result(timeout=3)
        else:
            results = [future.result(timeout=3) for future in futures]
            results[0]["nested"]["output"] = "changed"
            assert results[1:] == [{"nested": {"output": "route"}}] * 2
    assert calls == [1]


@pytest.mark.parametrize("settlement", [True, False])
def test_status_poll_supplies_creation_details_without_duplicate_reads(
    config_factory, settlement
):
    builder = _volume_runtime(
        config_factory(storage="volume", allow_cross_az_volumes=True)
    )
    builder.lifecycle_settlement_enabled = settlement
    builder._create_server_in_az(
        "vm", ["port"], selected_az="zone-a", target_host="host1", role="endpoint"
    )
    reads = [
        call.args[:2]
        for call in builder.osc.json.call_args_list
        if call.args[1] == "show"
    ]
    assert reads == [("volume", "show"), ("server", "show")]
    if settlement:
        seed = builder.verify_server_placement.call_args.kwargs["initial_server"]
        assert seed["status"] == "ACTIVE"
        assert seed["OS-EXT-SRV-ATTR:host"] == "host1"
    else:
        builder.verify_server_placement.assert_not_called()


@pytest.mark.parametrize(
    "pending",
    [
        {},
        {"status": "BUILD"},
        {"OS-EXT-STS:task_state": "spawning"},
        {"OS-EXT-STS:power_state": 0},
        {"OS-EXT-SRV-ATTR:host": "wrong"},
    ],
)
def test_initial_status_observation_still_requires_full_stable_settlement(
    config_factory, pending
):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(convergence_interval=0)
    builder.logger = mock.Mock()
    ready = {
        "status": "ACTIVE",
        "OS-EXT-STS:task_state": None,
        "OS-EXT-STS:power_state": 1,
        "OS-EXT-SRV-ATTR:host": "expected",
    }

    def observe(kind, *_args, **_kwargs):
        return (
            ready
            if kind == "server"
            else {"device_id": "vm", "binding:host_id": "expected", "status": "ACTIVE"}
        )

    builder.osc = SimpleNamespace(json=mock.Mock(side_effect=observe))
    assert (
        builder._wait_for_server_settlement(
            "vm",
            ["port"],
            expected_statuses={"active"},
            expected_host="expected",
            require_power_state=True,
            initial_server={**ready, **pending},
            timeout=3,
        )
        == ready
    )
    kinds = [call.args[0] for call in builder.osc.json.call_args_list]
    assert kinds.count("server") == (2 if pending else 1)
    assert kinds.count("port") == 2


def test_initial_active_observation_cannot_skip_bad_binding(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(convergence_interval=0)
    builder.logger = mock.Mock()
    ready = {
        "id": "vm",
        "status": "ACTIVE",
        "host": "expected",
        "OS-EXT-STS:task_state": None,
    }
    bindings = iter(["wrong", "expected", "expected"])

    def observe(kind, *_args, **_kwargs):
        return (
            ready
            if kind == "server"
            else {
                "id": "port",
                "device_id": "vm",
                "binding:host_id": next(bindings),
                "status": "ACTIVE",
            }
        )

    builder.osc = SimpleNamespace(json=mock.Mock(side_effect=observe))
    builder._wait_for_server_settlement(
        "vm",
        ["port"],
        expected_statuses={"active"},
        expected_host="expected",
        initial_server=ready,
        timeout=3,
    )
    assert [call.args[0] for call in builder.osc.json.call_args_list] == [
        "port",
        "server",
        "port",
        "server",
        "port",
    ]


def test_failed_status_uses_same_observed_fault(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.logger = mock.Mock()
    builder.osc = mock.Mock()
    builder.osc.json.return_value = {
        "status": "ERROR",
        "fault": {"message": "boot failed"},
    }
    with pytest.raises(SuiteError, match="boot failed"):
        builder._wait_for_status("server", "vm", {"active"}, {"error"})
    assert builder.osc.json.call_count == 1


def test_canonical_object_paths_avoid_rescanning_but_overrides_are_rejected():
    row = normalize_result_record(
        _contract_result(details={"network_id": "network", "port_id": "port"})
    )
    with mock.patch(
        "neutron_flux.result_contract_compatibility.openstack_object_candidates",
        wraps=result_contract_compatibility.openstack_object_candidates,
    ) as walk:
        assert normalize_result_record(row) == row
    assert walk.call_count == 1
    for mutation in ("id", "evidence_path", "extra"):
        changed = copy.deepcopy(row)
        changed["contract"]["expectation"]["openstack_objects"][0][mutation] = "invalid"
        with pytest.raises(ValueError, match="openstack_objects.*contradicts"):
            normalize_result_record(changed)


@pytest.mark.parametrize("stage", ["ssh", "cloud"])
def test_diagnostic_cancellation_stops_additional_collection(tmp_path, stage):
    builder = SimpleNamespace(
        ssh_endpoint=mock.Mock(return_value=completed(stdout="guest")), osc=mock.Mock()
    )
    target = builder.ssh_endpoint if stage == "ssh" else builder.osc.json
    target.side_effect = RunCancelledError("cancelled")
    collector = DiagnosticCollector(builder, SimpleNamespace(run_dir=tmp_path))
    probe = ProbeResult(outcome="error", success=False, attempts=1, elapsed_ms=1)
    with pytest.raises(RunCancelledError):
        collector.collect(spec("cancelled"), probe, endpoint("A"), endpoint("B"))
    assert builder.ssh_endpoint.call_count == 1
    assert builder.osc.json.call_count == (0 if stage == "ssh" else 1)
