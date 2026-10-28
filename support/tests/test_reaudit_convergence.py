"""Drive the real lifecycle helpers and policy with adversarial packet/clock inputs."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from neutron_flux.engine_handlers.floating_ip import FloatingIPLifecycleHandlerMixin
from neutron_flux.engine_handlers.server_router import ServerRouterLifecycleHandlerMixin
from neutron_flux.models import ProbeResult
from neutron_flux.models import TestSpec as Spec
from neutron_flux.policy import PolicyEvaluator

from ._shared import endpoint


class Clock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        assert seconds >= 0
        self.now += seconds


def exercise(
    monkeypatch,
    kind,
    expected,
    sequence,
    *,
    timeout=60,
    cost=5,
    interval=1,
    protocol="tcp",
):
    clock = Clock()
    monkeypatch.setattr("time.monotonic", clock.monotonic)
    monkeypatch.setattr("time.sleep", clock.sleep)
    calls = []

    def packet(*_args, **_kwargs):
        item = sequence[min(len(calls), len(sequence) - 1)]
        outcome, success = (
            item if isinstance(item, tuple) else (item, item == "reachable")
        )
        calls.append((outcome, success))
        clock.now += cost
        return ProbeResult(
            outcome,
            success,
            int(cost * 1000),
            1,
            source_ip="192.0.2.2",
            destination_ip="192.0.2.3",
            protocol=protocol,
            command="recorded-packet-command",
            diagnostics={"packet_evidence": len(calls)},
        )

    config = SimpleNamespace(convergence_timeout=timeout, convergence_interval=interval)
    if kind == "fip":
        handler = FloatingIPLifecycleHandlerMixin()
        handler.config = config
        handler._verified_fip_probe = packet
        state = {
            "runner": False,
            "source": endpoint(),
            "source_ip": "192.0.2.2",
            "address": "192.0.2.3",
            "target": endpoint(),
            "fixed_ip": "10.0.0.3",
        }
        result = handler._wait_fip_state(state, expected=expected)
    else:
        handler = ServerRouterLifecycleHandlerMixin()
        handler.config = config
        handler._execute_endpoint_probe = packet
        result = handler._wait_endpoint_state(
            endpoint(), "192.0.2.2", "192.0.2.3", 4, protocol, expected=expected
        )
    spec = Spec(
        id="convergence",
        category="lifecycle",
        operation="return" if expected else "withdraw",
        family=4,
        expectation="restored" if expected else "withdrawn",
        expectation_reason="stable state required",
        authoritative=True,
        dependencies=[],
    )
    verdict = PolicyEvaluator().evaluate(spec, result)
    return result, verdict, calls


@pytest.mark.parametrize("kind", ["fip", "endpoint"])
@pytest.mark.parametrize("expected", [True, False])
def test_last_matching_sample_at_normal_deadline_cannot_pass(
    monkeypatch, kind, expected
):
    wanted, opposite = (
        ("reachable", "blocked") if expected else ("blocked", "reachable")
    )
    result, verdict, calls = exercise(
        monkeypatch, kind, expected, [opposite] * 9 + [wanted]
    )
    assert verdict.status != "PASS"
    assert len(calls) == 10 and result.diagnostics["achieved_consecutive"] == 1
    assert result.diagnostics["converged"] is False
    assert result.diagnostics["last_probe_outcome"] == wanted
    assert result.command == "recorded-packet-command"
    assert result.diagnostics["convergence_observations"][-1]["outcome"] == wanted


@pytest.mark.parametrize("kind", ["fip", "endpoint"])
@pytest.mark.parametrize("expected", [True, False])
@pytest.mark.parametrize("protocol", ["icmp", "tcp", "udp"])
def test_stable_valid_state_still_passes_with_complete_evidence(
    monkeypatch, kind, expected, protocol
):
    wanted = "reachable" if expected else "blocked"
    required = 2 if expected else 3
    result, verdict, calls = exercise(
        monkeypatch, kind, expected, [wanted], protocol=protocol
    )
    assert verdict.status == "PASS"
    assert len(calls) == result.attempts == required
    assert result.diagnostics["converged"] is True
    assert result.diagnostics["required_consecutive"] == required
    assert result.diagnostics["achieved_consecutive"] == required
    assert len(result.diagnostics["convergence_observations"]) == required


@pytest.mark.parametrize("kind", ["fip", "endpoint"])
@pytest.mark.parametrize(
    "unknown", ["inconclusive", "error", "unknown", ("blocked", True), ("blocked", 0)]
)
def test_unknown_or_inconsistent_samples_reset_withdrawal(monkeypatch, kind, unknown):
    result, verdict, calls = exercise(
        monkeypatch, kind, False, ["blocked", unknown, "blocked", "blocked", "blocked"]
    )
    assert verdict.status == "PASS"
    assert len(calls) == result.attempts == 5
    assert result.diagnostics["achieved_consecutive"] == 3


@pytest.mark.parametrize("kind", ["fip", "endpoint"])
def test_two_inconclusive_and_one_blocked_never_establish_withdrawal(monkeypatch, kind):
    result, verdict, calls = exercise(
        monkeypatch,
        kind,
        False,
        ["inconclusive", "inconclusive", "blocked"],
        timeout=18,
    )
    assert len(calls) == 3
    assert verdict.status != "PASS"
    assert result.diagnostics["achieved_consecutive"] == 1


@pytest.mark.parametrize("kind", ["fip", "endpoint"])
@pytest.mark.parametrize("expected", [True, False])
def test_flapping_does_not_accumulate_nonconsecutive_matches(
    monkeypatch, kind, expected
):
    wanted, opposite = (
        ("reachable", "blocked") if expected else ("blocked", "reachable")
    )
    result, verdict, calls = exercise(
        monkeypatch, kind, expected, [wanted, opposite] * 5
    )
    assert verdict.status == "FAIL"
    assert len(calls) == 10
    assert result.diagnostics["achieved_consecutive"] == 0


@pytest.mark.parametrize("kind", ["fip", "endpoint"])
@pytest.mark.parametrize("expected", [True, False])
def test_final_probe_completing_after_deadline_cannot_pass(monkeypatch, kind, expected):
    required = 2 if expected else 3
    wanted = "reachable" if expected else "blocked"
    result, verdict, calls = exercise(
        monkeypatch, kind, expected, [wanted], timeout=required * 6 - 2
    )
    assert len(calls) == required
    assert verdict.status != "PASS"
    assert result.diagnostics["converged"] is False


@pytest.mark.parametrize("kind", ["fip", "endpoint"])
@pytest.mark.parametrize("expected", [True, False])
def test_final_probe_completing_exactly_at_deadline_is_valid(
    monkeypatch, kind, expected
):
    required = 2 if expected else 3
    wanted = "reachable" if expected else "blocked"
    result, verdict, _ = exercise(
        monkeypatch, kind, expected, [wanted], timeout=required * 6 - 1
    )
    assert verdict.status == "PASS"
    assert result.diagnostics["converged"] is True


@pytest.mark.parametrize("kind", ["fip", "endpoint"])
def test_no_probe_is_not_successful_withdrawal(monkeypatch, kind):
    result, verdict, calls = exercise(monkeypatch, kind, False, ["blocked"], timeout=0)
    assert calls == [] and result.attempts == 0
    assert verdict.status == "ERROR"
    assert result.diagnostics["converged"] is False


@pytest.mark.parametrize("kind", ["fip", "endpoint"])
@pytest.mark.parametrize("expected", [True, False])
@pytest.mark.parametrize("outcome", ["wrong-destination", "translation-mismatch"])
def test_convergence_does_not_downgrade_confirmed_identity_failures(
    monkeypatch, kind, expected, outcome
):
    result, verdict, calls = exercise(monkeypatch, kind, expected, [outcome])
    assert verdict.status == "FAIL"
    assert result.outcome == outcome
    assert result.diagnostics["last_probe_outcome"] == outcome
    assert result.diagnostics["achieved_consecutive"] == 0
    assert result.diagnostics["converged"] is False
    assert len(calls) == 10
