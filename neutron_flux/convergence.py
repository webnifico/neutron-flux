"""Finalize lifecycle observations without confusing a last sample with stability."""

from __future__ import annotations

import dataclasses
from typing import Any

from .models import ProbeResult


def finish_convergence(
    last: ProbeResult,
    *,
    expected: bool,
    required: int,
    consecutive: int,
    attempts: int,
    elapsed_ms: int,
    timeout: float,
    within_deadline: bool,
    observations: list[dict[str, Any]],
) -> ProbeResult:
    """Retain contradictory failures; a lone matching sample is not a PASS.

    Raw reachability and errors remain in diagnostics. Missing stability makes
    an otherwise matching observation inconclusive, not an invented blocked or
    reachable result. A contradictory, valid last observation still fails the
    normal policy evaluator. This helper never changes the original probe.
    """
    converged = consecutive >= required and within_deadline
    wanted = "reachable" if expected else "blocked"
    outcome = last.outcome
    coherent = outcome in {"reachable", "blocked"} and last.success is (
        outcome == "reachable"
    )
    if not converged and (
        outcome == wanted or (outcome in {"reachable", "blocked"} and not coherent)
    ):
        outcome = "inconclusive"
    return dataclasses.replace(
        last,
        outcome=outcome,
        success=last.success if outcome == last.outcome else False,
        elapsed_ms=elapsed_ms,
        attempts=attempts,
        diagnostics={
            **last.diagnostics,
            "required_consecutive": required,
            "achieved_consecutive": consecutive,
            "convergence_timeout": timeout,
            "converged": converged,
            "convergence_timed_out": not converged,
            "last_probe_outcome": last.outcome,
            "last_probe_success": last.success,
            "convergence_observations": list(observations),
            "convergence_observations_omitted": max(0, attempts - len(observations)),
        },
    )
