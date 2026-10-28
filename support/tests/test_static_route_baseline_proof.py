"""Router changes require proven blockage, including convergence stability."""

from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.convergence import finish_convergence
from neutron_flux.engine import TestEngine as FluxTestEngine
from neutron_flux.models import ProbeResult
from neutron_flux.planning import Planner
from neutron_flux.policy import PolicyEvaluator

from .test_network_matrix_packet_ownership import _runtime_groups


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("stable_blocked_baseline", [False, True])
def test_static_route_installation_requires_stable_blocked_baseline(
    config_factory, discovery_fixture, family, stable_blocked_baseline
):
    config = config_factory()
    plan = Planner(config, discovery_fixture, mock.Mock()).build()
    baseline = next(
        spec
        for spec in plan.tests
        if spec.operation == "static-route-baseline" and spec.family == family
    )
    installation = next(
        spec
        for spec in plan.tests
        if spec.operation == "static-route-install"
        and spec.destination_group_id == baseline.destination_group_id
    )
    runtimes = _runtime_groups(plan, discovery_fixture)
    runtime = next(
        item for item in runtimes if item.plan.id == baseline.destination_group_id
    )
    observed = finish_convergence(
        ProbeResult("blocked", False, 1, 1),
        expected=False,
        required=3,
        consecutive=3 if stable_blocked_baseline else 1,
        attempts=3 if stable_blocked_baseline else 1,
        elapsed_ms=100,
        timeout=0.1,
        within_deadline=stable_blocked_baseline,
        observations=[{"outcome": "blocked", "success": False}],
    )
    assert observed.outcome == (
        "blocked" if stable_blocked_baseline else "inconclusive"
    )
    engine = object.__new__(FluxTestEngine)
    engine._runtime_groups = tuple(runtimes)
    engine.builder = SimpleNamespace(
        runtime_groups=runtimes, set_static_routes=mock.Mock()
    )
    engine.lifecycle = {}
    engine._record = mock.Mock()
    engine._wait_endpoint_state = mock.Mock(
        side_effect=[observed, ProbeResult("reachable", True, 1, 1)]
    )
    engine._run_static_route_baseline(baseline)
    state = engine.lifecycle[f"static-route:{runtime.plan.id}"]
    assert state["baseline_blocked"] is stable_blocked_baseline
    engine._run_static_route_install(installation)
    if stable_blocked_baseline:
        engine.builder.set_static_routes.assert_called_once_with(runtime, enabled=True)
        assert state["routes_installed"] is True
        assert engine._wait_endpoint_state.call_count == 2
        assert engine._record.call_args.args[1].outcome == "reachable"
    else:
        engine.builder.set_static_routes.assert_not_called()
        assert state["routes_installed"] is False
        assert engine._wait_endpoint_state.call_count == 1
        probe = engine._record.call_args.args[1]
        assert probe.outcome == "inconclusive"
        assert PolicyEvaluator().evaluate(installation, probe).status == "UNVERIFIED"
