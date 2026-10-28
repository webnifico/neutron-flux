from __future__ import annotations

import ipaddress
import json
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.cleanup import CleanupManager
from neutron_flux.engine import TestEngine as FluxTestEngine
from neutron_flux.errors import CommandError, RunCancelledError, SuiteError
from neutron_flux.log import Logger
from neutron_flux.models import RuntimeGroup
from neutron_flux.network_contract import PRIVATE_TRANSLATION_PROJECT_NETWORK
from neutron_flux.openstack import OpenStack
from neutron_flux.reporting import Reporter, ResourceTracker
from neutron_flux.resources import ResourceBuilder

from ._shared import build_plan, completed, endpoint

FIP_ID = "c3c11f8a-5da0-4ab3-b197-08fa46d6bc71"


def _row(**overrides):
    return {
        "ID": FIP_ID,
        "Floating IP Address": "198.51.100.20",
        "Fixed IP Address": "10.0.0.10",
        "Port": "test-target",
        **overrides,
    }


def _adapter(tmp_path, responses):
    adapter = OpenStack(Logger(tmp_path / "adapter.log"))
    adapter.run = mock.Mock(side_effect=responses)
    return adapter


def _formatter_error():
    return completed(1, stderr="Invalid formatter provided.")


@pytest.mark.parametrize("detached", [False, True])
def test_formatter_fallback_reads_exact_fip_association(tmp_path, detached):
    row = _row(**{"Port": None, "Fixed IP Address": None}) if detached else _row()
    adapter = _adapter(
        tmp_path,
        [_formatter_error(), completed(stdout=json.dumps([_row(ID="other"), row]))],
    )
    detail = adapter.json("floating", "ip", "show", FIP_ID, check=False)
    assert detail["id"] == FIP_ID
    assert detail["port_id"] == (None if detached else "test-target")
    assert detail["fixed_ip_address"] == (None if detached else "10.0.0.10")
    assert adapter.run.call_args.args[:3] == ("floating", "ip", "list")


@pytest.mark.parametrize(
    "rows",
    [
        [],
        [_row(ID="other")],
        [_row(), _row()],
        {"ID": FIP_ID},
        ["invalid"],
        [{"ID": FIP_ID}],
        [_row(**{"Port": []})],
    ],
)
def test_formatter_fallback_never_turns_missing_or_malformed_evidence_into_absence(
    tmp_path, rows
):
    adapter = _adapter(
        tmp_path, [_formatter_error(), completed(stdout=json.dumps(rows))]
    )
    assert adapter.presence("floating_ip", FIP_ID).unknown
    adapter.run.side_effect = [_formatter_error(), completed(stdout=json.dumps(rows))]
    with pytest.raises(SuiteError):
        adapter.json("floating", "ip", "show", FIP_ID, check=False)


@pytest.mark.parametrize(
    "error",
    [
        "Unauthorized (HTTP 401)",
        "Forbidden (HTTP 403)",
        "Service Unavailable (HTTP 503)",
    ],
)
def test_fallback_failure_stays_unknown(tmp_path, error):
    adapter = _adapter(tmp_path, [_formatter_error(), completed(1, stderr=error)])
    presence = adapter.presence("floating_ip", FIP_ID)
    assert presence.unknown
    assert error in presence.detail


@pytest.mark.parametrize(
    "command",
    [("floating", "ip", "create", "external"), ("port", "show", "test-target")],
)
def test_formatter_fallback_never_retries_cloud_operations_or_other_resource_types(
    tmp_path, command
):
    adapter = _adapter(tmp_path, [_formatter_error()])
    with pytest.raises(CommandError):
        adapter.json(*command, check=False)
    adapter.run.assert_called_once()


def test_other_show_failures_do_not_use_fallback(tmp_path):
    adapter = _adapter(tmp_path, [completed(1, stderr="Forbidden (HTTP 403)")])
    assert adapter.presence("floating_ip", FIP_ID).unknown
    adapter.run.assert_called_once()


def test_fallback_propagates_cancellation(tmp_path):
    adapter = _adapter(tmp_path, [_formatter_error(), RunCancelledError("cancelled")])
    with pytest.raises(RunCancelledError):
        adapter.presence("floating_ip", FIP_ID)


@pytest.fixture
def floating_runtime(config_factory, discovery_fixture, tmp_path):
    config = config_factory(action="run")
    plan = build_plan(config, discovery_fixture, tmp_path)
    group = next(
        g
        for g in plan.tenant_groups
        if g.kind == PRIVATE_TRANSLATION_PROJECT_NETWORK and g.floating_subnet_id
    )
    target = endpoint("target")
    target.fixed_ips = {"private-subnet": "10.0.0.10"}
    runtime = RuntimeGroup(
        plan=group,
        network_id="private",
        network_name="private",
        subnet_ids=["private-subnet"],
        router_id="router",
        endpoints=[target],
        source_nat_enabled=True,
        fips={},
        metadata={"floating_ip_fixed_subnet_id": "private-subnet"},
    )
    builder = object.__new__(ResourceBuilder)
    builder.config = config
    builder.run_tag = "neutron-flux-nflux-20260925000000-abcdef"
    builder.reporter = Reporter(config, "nflux-20260925000000-abcdef")
    builder.logger = builder.reporter.logger
    builder.tracker = ResourceTracker(builder.reporter)
    builder.discovery = discovery_fixture
    builder.osc = mock.Mock()
    subnet = discovery_fixture.subnet(group.floating_subnet_id)
    address = str(ipaddress.ip_network(subnet.cidr).network_address + 20)
    builder.osc.json.return_value = {"id": FIP_ID, "floating_ip_address": address}
    builder.capture_router_state = mock.Mock(return_value={"external_gateway_info": {}})
    builder.wait_floating_ip_association = mock.Mock(return_value={"matched": True})
    yield builder, runtime
    builder.logger.close()


@pytest.mark.parametrize(
    "failure", [SuiteError("formatter failed"), {"matched": False}]
)
def test_failed_association_retries_existing_fip_without_reallocating(
    floating_runtime, failure
):
    builder, runtime = floating_runtime
    builder.wait_floating_ip_association.side_effect = [failure, {"matched": True}]
    with pytest.raises(SuiteError):
        builder.ensure_group_fips(runtime)
    assert not runtime.fips
    assert [r.id for r in builder.reporter.resources] == [FIP_ID]
    builder.ensure_group_fips(runtime)
    builder.ensure_group_fips(runtime)
    builder.osc.json.assert_called_once()
    assert runtime.fips["target"]["id"] == FIP_ID
    assert builder.wait_floating_ip_association.call_count == 2


@pytest.mark.parametrize("address", ["203.0.113.254", "", None])
def test_invalid_create_address_is_tracked_and_never_reallocated(
    floating_runtime, address
):
    builder, runtime = floating_runtime
    builder.osc.json.return_value = {"id": FIP_ID, "floating_ip_address": address}
    for _ in range(2):
        with pytest.raises(SuiteError):
            builder.ensure_group_fips(runtime)
    assert [r.id for r in builder.reporter.resources] == [FIP_ID]
    builder.osc.json.assert_called_once()
    builder.wait_floating_ip_association.assert_not_called()


def test_cleanup_deletes_exact_tracked_fip_despite_show_formatter_error(
    floating_runtime, tmp_path
):
    builder, _runtime = floating_runtime
    record = builder.tracker.add("floating_ip", FIP_ID, "198.51.100.20")
    adapter = _adapter(
        tmp_path,
        [
            _formatter_error(),
            completed(stdout=json.dumps([_row()])),
            completed(),
            completed(stdout="[]"),
            completed(1, stderr=f"No FloatingIP found for {FIP_ID}"),
        ],
    )
    cleanup = CleanupManager(adapter, builder.reporter, builder.tracker, builder.config)
    cleanup._delete_record(record, cleanup._delete_floating_ip)
    assert record.delete_status == "deleted"
    assert adapter.run.call_args_list[2].args == ("floating", "ip", "delete", FIP_ID)
    assert adapter.run.call_count == 5


@pytest.mark.parametrize("status", ["ERROR", "FAIL", "UNVERIFIED"])
def test_return_is_blocked_when_tcp_baseline_did_not_pass(
    config_factory, discovery_fixture, tmp_path, status
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    spec = next(s for s in plan.tests if s.operation == "fip-return")
    baseline = next(
        s
        for s in plan.tests
        if s.operation == "fip-baseline"
        and s.protocol == "tcp"
        and s.destination_group_id == spec.destination_group_id
    )
    assert baseline.id in spec.requires_pass
    engine = object.__new__(FluxTestEngine)
    engine.reporter = SimpleNamespace(
        get_result=lambda _id: SimpleNamespace(status=status), result=mock.Mock()
    )
    engine.operations = {"fip-return": mock.Mock()}
    engine._run_spec(spec)
    assert engine.reporter.result.call_args.args[2] == "BLOCKED_BY_PREREQUISITE"
    engine.operations["fip-return"].assert_not_called()


def test_return_still_runs_after_failed_withdraw_when_baseline_passed(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    spec = next(s for s in plan.tests if s.operation == "fip-return")
    statuses = {
        s.id: "PASS" if s.operation == "fip-baseline" else "ERROR" for s in plan.tests
    }
    engine = object.__new__(FluxTestEngine)
    engine.reporter = SimpleNamespace(
        get_result=lambda test_id: SimpleNamespace(status=statuses[test_id])
    )
    engine.operations = {"fip-return": mock.Mock()}
    engine._run_spec(spec)
    engine.operations["fip-return"].assert_called_once_with(spec)


def test_peer_side_b_allocation_keeps_side_a_and_journals_each_mapping(
    floating_runtime,
):
    builder, runtime = floating_runtime
    first = runtime.endpoints[0]
    second = endpoint("second", "B")
    second.fixed_ips = {"private-subnet": "10.0.0.11"}
    runtime.endpoints.append(second)
    builder.ensure_group_fips(runtime)
    first_mapping = dict(runtime.fips[first.label])
    second_id = "987455e7-c6d9-44a5-b841-e9c00bc98bc4"
    address = str(ipaddress.ip_address(first_mapping["address"]) + 1)
    builder.osc.json.return_value = {"id": second_id, "floating_ip_address": address}
    builder.ensure_group_fips(runtime, side="B")
    builder.ensure_group_fips(runtime, side="B")
    assert builder.osc.json.call_count == 2
    args = builder.osc.json.call_args.args
    assert args[args.index("--port") + 1] == second.test_port_id
    assert args[args.index("--fixed-ip-address") + 1] == "10.0.0.11"
    assert runtime.fips[first.label] == first_mapping
    assert runtime.fips[second.label]["id"] == second_id
    assert [
        (r.id, r.metadata["endpoint_side"]) for r in builder.reporter.resources
    ] == [(FIP_ID, "A"), (second_id, "B")]
