from __future__ import annotations

from types import SimpleNamespace

from neutron_flux.engine_handlers.common import EngineCommonMixin
from neutron_flux.engine_handlers.mtu_scenario import MTUScenarioHandlerMixin
from neutron_flux.engine_handlers.router_lifecycle_scenario import (
    RouterLifecycleScenarioHandlerMixin,
)

from ._shared import *  # noqa: F403, F405


class _ResultCollector:
    def __init__(self):
        self.items = []

    def result(self, test_id, category, status, message, **kwargs):
        self.items.append(
            SimpleNamespace(
                test_id=test_id,
                category=category,
                status=status,
                message=message,
                **kwargs,
            )
        )


class _MTUHarness(MTUScenarioHandlerMixin):
    _address_evidence = EngineCommonMixin._address_evidence

    def __init__(self, probes):
        self._probes = list(probes)
        self.calls = []
        self.reporter = _ResultCollector()
        self.diagnostics = SimpleNamespace(collect=lambda *args: ("MTU", {}))
        self.source = endpoint("source", "A")
        self.destination = endpoint("destination", "B")
        self.source.host = self.destination.host = "compute1"
        self.source.availability_zone = self.destination.availability_zone = "az1"

    def _endpoint_address(self, group_id, side, subnet_id):
        if side == "A":
            return self.source, "192.0.2.10"
        return self.destination, "192.0.2.11"

    def _network_mtu(self, group_id):
        return 1500

    @property
    def probes(self):
        owner = self

        class _Registry:
            def endpoint(self, protocol, *args, **kwargs):
                owner.calls.append(protocol)
                return owner._probes.pop(0)

        return _Registry()


def _mtu_spec():
    return FluxTestSpec(
        id="MTU-ATOMIC",
        category="mtu",
        operation="mtu-scenario",
        family=4,
        expectation="mtu-behavior-assessed",
        expectation_reason="valid boundary and local oversized rejection",
        authoritative=True,
        dependencies=["group"],
        source_group_id="group",
        destination_group_id="group",
        source_side="A",
        destination_side="B",
        source_subnet_id="subnet",
        destination_subnet_id="subnet",
        protocol="mtu",
        metadata={"atomic_scenario": True},
    )


def test_mtu_atomic_scenario_passes_with_two_stage_evidence():
    boundary = ProbeResult(
        "reachable",
        True,
        10,
        2,
        protocol="mtu",
        diagnostics={"packet_size": 1500},
    )
    oversized = ProbeResult(
        "local-mtu-rejected",
        False,
        8,
        2,
        protocol="mtu+1",
        diagnostics={"packet_size": 1501, "local_mtu_evidence": {}},
    )
    harness = _MTUHarness([boundary, oversized])

    harness._run_mtu_scenario(_mtu_spec())

    assert harness.calls == ["mtu", "mtu+1"]
    assert len(harness.reporter.items) == 1
    result = harness.reporter.items[0]
    assert result.status == "PASS"
    assert result.details["stages"]["valid_boundary"]["status"] == "PASS"
    assert result.details["stages"]["oversized_rejection"]["status"] == "PASS"


@pytest.mark.parametrize(
    "outcome,status",
    [("reachable", "PASS"), ("inconclusive", "UNVERIFIED"), ("error", "ERROR")],
)
def test_oversized_mtu_observation_preserves_uncertain_and_error_outcomes(
    outcome, status
):
    harness = _MTUHarness(
        [
            ProbeResult("reachable", True, 10, 1, protocol="mtu"),
            ProbeResult(outcome, outcome == "reachable", 10, 1, protocol="mtu+1"),
        ]
    )
    harness._run_mtu_scenario(_mtu_spec())
    result = harness.reporter.items[0]
    assert result.status == status
    assert result.details["mtu_advisory"] is (outcome == "reachable")


def test_standard_mtu_scenario_resets_pmtu_cache_before_boundary_probe():
    boundary = ProbeResult(
        "reachable",
        True,
        10,
        1,
        protocol="mtu",
        diagnostics={"packet_size": 1500},
    )
    oversized = ProbeResult(
        "local-mtu-rejected",
        False,
        8,
        1,
        protocol="mtu+1",
        diagnostics={"packet_size": 1501, "local_mtu_evidence": {}},
    )
    harness = _MTUHarness([boundary, oversized])

    class Builder:
        @staticmethod
        def ssh_endpoint(_endpoint, command, *, timeout):
            harness.calls.append("cache-reset")
            assert command.startswith("python3 -c ")
            assert timeout == 30
            return completed(
                stdout=(
                    '{"attempted":true,"verified":true,"route_mtu_after_reset":null}'
                )
            )

    harness.builder = Builder()
    harness._run_mtu_scenario(_mtu_spec())

    result = harness.reporter.items[0]
    assert harness.calls == ["cache-reset", "mtu", "mtu+1"]
    assert result.details["route_pmtu_cache_reset_verified"] is True
    assert result.details["route_pmtu_cache_reset"]["attempted"] is True


def test_mtu_scenario_reports_fresh_network_mtu_rejection_as_advisory():
    boundary = ProbeResult(
        "packet-too-big",
        False,
        10,
        2,
        protocol="mtu",
        stdout="From 192.0.2.11 icmp_seq=1 Frag needed and DF set (mtu = 1442)",
        stderr="ping: sendmsg: Message too long",
        diagnostics={
            "packet_size": 1500,
            "packet_transmitted": True,
            "packet_too_big_feedback": [{"responder": "192.0.2.11", "mtu": 1442}],
        },
    )
    harness = _MTUHarness([boundary])
    harness._run_mtu_scenario(_mtu_spec())
    result = harness.reporter.items[0]
    assert result.status == "PASS"
    assert result.details["health"] == "warning"
    assert result.details["mtu_advisory"] is True
    assert result.observed == "path-mtu-below-advertised"
    assert "1442" in result.message and "1500" in result.message
    assert "cached" not in result.message
    assert harness.calls == ["mtu"]
    assert (
        result.details["stages"]["valid_boundary"]["diagnostics"]["packet_transmitted"]
        is True
    )


def test_mtu_atomic_scenario_records_interface_mismatch_without_oversized_probe():
    boundary = ProbeResult(
        "local-mtu-rejected",
        False,
        10,
        2,
        stderr="sendmsg: Message too long",
        protocol="mtu",
        diagnostics={
            "packet_size": 1500,
            "local_mtu_evidence": {
                "selected_interface": "ens4",
                "source_interface_mtu": 1424,
            },
        },
    )
    harness = _MTUHarness([boundary])

    harness._run_mtu_scenario(_mtu_spec())

    assert harness.calls == ["mtu"]
    result = harness.reporter.items[0]
    assert result.status == "PASS"
    assert result.details["health"] == "warning"
    assert result.details["mtu_advisory"] is True
    assert result.observed == "source-interface-mtu-below-advertised"
    assert result.details["stages"]["oversized_rejection"]["status"] == "NOT_RUN"


@pytest.mark.parametrize(
    "outcome,status",
    [("unreachable", "FAIL"), ("error", "ERROR"), ("inconclusive", "UNVERIFIED")],
)
def test_mtu_advisory_policy_preserves_delivery_and_execution_failures(outcome, status):
    harness = _MTUHarness([ProbeResult(outcome, False, 10, 1, protocol="mtu")])
    harness._run_mtu_scenario(_mtu_spec())
    result = harness.reporter.items[0]
    assert result.status == status
    assert result.details["mtu_advisory"] is False


def test_mtu_scenario_fallback_bound_is_never_authoritative():
    boundary = ProbeResult(
        "reachable",
        True,
        10,
        2,
        protocol="mtu",
        diagnostics={"packet_size": 1500},
    )
    oversized = ProbeResult(
        "local-mtu-rejected",
        False,
        8,
        2,
        protocol="mtu+1",
        diagnostics={"packet_size": 1501, "local_mtu_evidence": {}},
    )
    harness = _MTUHarness([boundary, oversized])
    harness._network_mtu_observation = lambda *_args: {
        "effective_mtu": 1500,
        "reported_mtu": None,
        "authoritative": False,
        "fallback_used": True,
        "authority": "Neutron network.mtu unavailable",
    }

    harness._run_mtu_scenario(_mtu_spec())

    result = harness.reporter.items[0]
    assert result.status == "UNVERIFIED"
    assert result.authoritative is False
    assert result.details["diagnostic_probe_status"] == "PASS"
    assert result.details["mtu_contract_authoritative"] is False
    assert "used only as a diagnostic probe bound" in result.message


def test_mtu_scenario_preserves_execution_error_with_missing_mtu():
    boundary = ProbeResult(
        "error",
        False,
        10,
        1,
        stderr="probe executable unavailable",
        protocol="mtu",
        diagnostics={"packet_size": 1500},
    )
    harness = _MTUHarness([boundary])
    harness._network_mtu_observation = lambda *_args: {
        "effective_mtu": 1500,
        "reported_mtu": None,
        "authoritative": False,
        "fallback_used": True,
        "authority": "Neutron network.mtu unavailable",
    }

    harness._run_mtu_scenario(_mtu_spec())

    result = harness.reporter.items[0]
    assert result.status == "ERROR"
    assert result.authoritative is False
    assert result.details["diagnostic_probe_status"] == "ERROR"


class _RouterHarness(RouterLifecycleScenarioHandlerMixin):
    _address_evidence = EngineCommonMixin._address_evidence

    def __init__(self, config, *, baseline, transitions, interface_transitions=None):
        self.config = config
        self.reporter = _ResultCollector()
        self.source = endpoint("source", "A")
        self.target = endpoint("target", "B")
        self.source.host = "compute1"
        self.target.host = "compute2"
        self.source.availability_zone = self.target.availability_zone = "az1"
        self.runtime = SimpleNamespace(
            plan=SimpleNamespace(kind="tenant-router-pair"),
            router_id="router-id",
            metadata={"side_subnet_ids": {"B": "subnet-b"}},
            subnet_ids=["subnet-a", "subnet-b"],
        )
        self.probes = SimpleNamespace(endpoint=lambda *args, **kwargs: baseline)
        self._transitions = list(transitions)
        self.commands = []
        self.interface_states = []
        self._interface_transitions = list(interface_transitions or [])

        def run(*args, **kwargs):
            self.commands.append(args)
            return completed()

        self.builder = SimpleNamespace(
            osc=SimpleNamespace(run=run),
            wait_router_interface=self._wait_router_interface,
        )

    def _endpoint_address(self, group_id, side, subnet_id):
        if side == "A":
            return self.source, "10.0.0.10"
        return self.target, "10.0.1.10"

    def _group(self, group_id):
        return self.runtime

    def _wait_router_interface(self, router_id, subnet_id, *, present):
        if self._interface_transitions:
            value = self._interface_transitions.pop(0)
            if isinstance(value, Exception):
                raise value
            state = dict(value)
            state.setdefault("router_id", router_id)
            state.setdefault("subnet_id", subnet_id)
        else:
            state = {
                "matched": True,
                "present": present,
                "router_id": router_id,
                "subnet_id": subnet_id,
            }
        self.interface_states.append(state)
        return state

    def _wait_endpoint_state(self, *args, **kwargs):
        value = self._transitions.pop(0)
        if isinstance(value, Exception):
            raise value
        return value

    @staticmethod
    def _concise(text):
        return str(text)


def _router_spec():
    return FluxTestSpec(
        id="ROUTER-LIFECYCLE",
        category="router-interface-lifecycle",
        operation="router-lifecycle-scenario",
        family=4,
        expectation="lifecycle-complete",
        expectation_reason="withdraw and restore",
        authoritative=True,
        dependencies=["tenant-router"],
        source_group_id="tenant-router",
        destination_group_id="tenant-router",
        source_side="A",
        destination_side="B",
        source_subnet_id="side-A",
        destination_subnet_id="side-B",
        protocol="tcp",
        metadata={"router_interface_side": "B", "atomic_scenario": True},
    )


def test_router_lifecycle_is_one_atomic_restored_result(config_factory):
    baseline = ProbeResult("reachable", True, 1, 1, protocol="tcp")
    blocked = ProbeResult("blocked", False, 2, 2, protocol="tcp")
    restored = ProbeResult("reachable", True, 2, 2, protocol="tcp")
    harness = _RouterHarness(
        config_factory(action="run"),
        baseline=baseline,
        transitions=[blocked, restored],
    )

    harness._run_router_lifecycle_scenario(_router_spec())

    assert harness.commands == [
        ("router", "remove", "subnet", "router-id", "subnet-b"),
        ("router", "add", "subnet", "router-id", "subnet-b"),
    ]
    assert len(harness.reporter.items) == 1
    result = harness.reporter.items[0]
    assert result.status == "PASS"
    assert all(
        result.details["stages"][name]["status"] == "PASS"
        for name in (
            "baseline",
            "remove_attachment",
            "withdrawn_connectivity",
            "restore_attachment",
            "restored_connectivity",
        )
    )


def test_router_lifecycle_baseline_failure_is_prerequisite_not_unverified(
    config_factory,
):
    baseline = ProbeResult("blocked", False, 1, 1, protocol="tcp")
    harness = _RouterHarness(
        config_factory(action="run"), baseline=baseline, transitions=[]
    )

    harness._run_router_lifecycle_scenario(_router_spec())

    assert harness.commands == []
    result = harness.reporter.items[0]
    assert result.status == "BLOCKED_BY_PREREQUISITE"
    assert result.details["stages"]["remove_attachment"]["status"] == "NOT_RUN"
    assert result.details["stages"]["restore_attachment"]["status"] == "NOT_RUN"


def test_router_lifecycle_restores_after_post_remove_exception(config_factory):
    baseline = ProbeResult("reachable", True, 1, 1, protocol="tcp")
    restored = ProbeResult("reachable", True, 2, 2, protocol="tcp")
    harness = _RouterHarness(
        config_factory(action="run"),
        baseline=baseline,
        transitions=[RuntimeError("probe failed"), restored],
    )

    harness._run_router_lifecycle_scenario(_router_spec())

    assert harness.commands[-1] == (
        "router",
        "add",
        "subnet",
        "router-id",
        "subnet-b",
    )
    result = harness.reporter.items[0]
    assert result.status == "ERROR"
    assert result.details["stages"]["restore_attachment"]["status"] == "PASS"
    assert result.details["stages"]["restored_connectivity"]["status"] == "PASS"


def test_router_lifecycle_reconciles_transient_interface_inventory_errors(
    config_factory,
):
    baseline = ProbeResult("reachable", True, 1, 1, protocol="tcp")
    blocked = ProbeResult("blocked", False, 2, 2, protocol="tcp")
    restored = ProbeResult("reachable", True, 2, 2, protocol="tcp")
    harness = _RouterHarness(
        config_factory(action="run"),
        baseline=baseline,
        transitions=[blocked, restored],
        interface_transitions=[
            RuntimeError("temporary removal inventory error"),
            {"matched": True, "present": False},
            RuntimeError("temporary restore inventory error"),
            {"matched": True, "present": True},
        ],
    )

    harness._run_router_lifecycle_scenario(_router_spec())

    result = harness.reporter.items[0]
    assert result.status == "PASS"
    assert result.details["stages"]["remove_attachment"]["status"] == "PASS"
    assert result.details["stages"]["restore_attachment"]["status"] == "PASS"
    assert result.details["stages"]["restored_connectivity"]["status"] == "PASS"


def test_router_lifecycle_restores_after_inconclusive_removal_readback(
    config_factory,
):
    baseline = ProbeResult("reachable", True, 1, 1, protocol="tcp")
    restored = ProbeResult("reachable", True, 2, 2, protocol="tcp")
    harness = _RouterHarness(
        config_factory(action="run"),
        baseline=baseline,
        transitions=[restored],
        interface_transitions=[
            {"matched": False, "present": False},
            {"matched": True, "present": True},
        ],
    )

    harness._run_router_lifecycle_scenario(_router_spec())

    assert harness.commands == [
        ("router", "remove", "subnet", "router-id", "subnet-b"),
        ("router", "add", "subnet", "router-id", "subnet-b"),
    ]
    result = harness.reporter.items[0]
    assert result.status == "ERROR"
    assert result.details["cloud_operation_submitted"] is True
    assert result.details["cloud_operation_performed"] is None
    assert result.details["removal_confirmed"] is False
    assert result.details["restoration_required"] is True
    assert result.details["restoration_confirmed"] is True
    assert result.details["stages"]["remove_attachment"]["status"] == "ERROR"
    assert result.details["stages"]["restore_attachment"]["status"] == "PASS"
    assert result.details["stages"]["restored_connectivity"]["status"] == "PASS"


def test_router_lifecycle_records_unconfirmed_restoration(config_factory):
    baseline = ProbeResult("reachable", True, 1, 1, protocol="tcp")
    blocked = ProbeResult("blocked", False, 2, 2, protocol="tcp")
    harness = _RouterHarness(
        config_factory(action="run"),
        baseline=baseline,
        transitions=[blocked],
        interface_transitions=[
            {"matched": True, "present": False},
            {"matched": False, "present": True},
        ],
    )

    harness._run_router_lifecycle_scenario(_router_spec())

    result = harness.reporter.items[0]
    assert result.status == "ERROR"
    assert result.observed == "restoration-failed"
    assert result.details["removal_confirmed"] is True
    assert result.details["restoration_confirmed"] is False
    assert result.details["stages"]["remove_attachment"]["status"] == "PASS"
    assert result.details["stages"]["restore_attachment"]["status"] == "ERROR"
    assert result.details["stages"]["restored_connectivity"]["status"] == "NOT_RUN"


def test_plan_has_no_provider_tenant_router_lifecycle_duplicates(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    lifecycle = [
        item for item in plan.tests if item.category == "router-interface-lifecycle"
    ]
    assert lifecycle
    assert all(item.operation == "router-lifecycle-scenario" for item in lifecycle)
    assert all(len(item.dependencies) == 1 for item in lifecycle)
    assert all(
        plan.group(item.dependencies[0]).kind == "one-router-project-networks"
        for item in lifecycle
    )
    assert not [
        item
        for item in lifecycle
        if any(
            plan.group(group_id).kind == "provider" for group_id in item.dependencies
        )
    ]


def test_mtu_advisory_keeps_run_successful_and_visible_in_reports(config_factory):
    import json

    from neutron_flux.models import Plan
    from neutron_flux.reporting import Reporter

    config = config_factory(action="run")
    reporter = Reporter(config, "mtu-advisory")
    reporter.plan = Plan([], [], {}, [], tests=[])
    reporter.cleanup_summary.update(attempted=True, complete=True)
    harness = _MTUHarness(
        [
            ProbeResult(
                "packet-too-big",
                False,
                10,
                1,
                protocol="mtu",
                diagnostics={
                    "packet_size": 1500,
                    "packet_too_big_feedback": [
                        {"responder": "192.0.2.11", "mtu": 1442}
                    ],
                },
            )
        ]
    )
    harness.reporter = reporter
    harness._run_mtu_scenario(_mtu_spec())
    assert reporter.finalize(0) == 0
    payload = json.loads(reporter.results_path.read_text())
    assert payload["run"]["final_status"] == "PASS WITH WARNINGS"
    text = reporter.report_path.read_text()
    assert "1 measurement warning" in text
    assert "1442" in text and "1500" in text
    assert reporter.results[0].status == "PASS"
    reporter.logger.close()
