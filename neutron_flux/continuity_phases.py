"""Partition observations on the guest clock without deleting startup evidence.

Tolerance grading uses the protected ready-through-post-migration interval.
Submission and observed handoff additionally label phases; they are observation
boundaries, not claims about Nova's internal switchover timestamps.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from typing import Any


def continuity_outage_bounds(
    samples: list[dict[str, Any]],
    *,
    sample_interval_s: float = 0.25,
) -> dict[str, Any]:
    """Measure consecutive missed samples, not a proven continuous outage.

    The legacy outage keys remain stable for readers and threshold settings.
    Their values describe scheduled observations and sampling brackets only.
    """
    if not samples:
        return {
            "failed_observations": 0,
            "confirmed_failed_span_s": 0.0,
            "outage_lower_bound_s": 0.0,
            "outage_upper_bound_s": 0.0,
        }
    normalized: list[tuple[float, bool]] = []
    previous = 0.0
    for sample in samples:
        raw = sample.get("scheduled_t", sample.get("t", previous))
        try:
            scheduled = float(raw)
        except (TypeError, ValueError):
            scheduled = previous
        if not math.isfinite(scheduled) or scheduled < previous:
            scheduled = previous
        normalized.append((scheduled, sample.get("ok") is True))
        previous = scheduled
    best = {
        "failed_observations": 0,
        "confirmed_failed_span_s": 0.0,
        "outage_lower_bound_s": 0.0,
        "outage_upper_bound_s": 0.0,
        "first_failed_scheduled_t": None,
        "last_failed_scheduled_t": None,
        "previous_success_scheduled_t": None,
        "next_success_scheduled_t": None,
    }
    index = 0
    while index < len(normalized):
        if normalized[index][1]:
            index += 1
            continue
        start = index
        while index + 1 < len(normalized) and not normalized[index + 1][1]:
            index += 1
        end = index
        first_failed = normalized[start][0]
        last_failed = normalized[end][0]
        previous_success = normalized[start - 1][0] if start > 0 else None
        next_success = normalized[end + 1][0] if end + 1 < len(normalized) else None
        count = end - start + 1
        confirmed_span = max(0.0, last_failed - first_failed)
        lower = confirmed_span
        if count == 1:
            lower = 0.0
        upper_start = (
            previous_success
            if previous_success is not None
            else max(0.0, first_failed - sample_interval_s)
        )
        upper_end = (
            next_success
            if next_success is not None
            else last_failed + sample_interval_s
        )
        upper = max(lower, upper_end - upper_start)
        candidate = {
            "failed_observations": count,
            "confirmed_failed_span_s": confirmed_span,
            "outage_lower_bound_s": lower,
            "outage_upper_bound_s": upper,
            "first_failed_scheduled_t": first_failed,
            "last_failed_scheduled_t": last_failed,
            "previous_success_scheduled_t": previous_success,
            "next_success_scheduled_t": next_success,
        }
        if (
            candidate["outage_lower_bound_s"],
            candidate["failed_observations"],
        ) > (
            best["outage_lower_bound_s"],
            best["failed_observations"],
        ):
            best = candidate
        index += 1
    return best


def _time(value: object) -> float | None:
    if type(value) not in (int, float):
        return None
    return float(value) if math.isfinite(value) and value >= 0 else None


def _icmp(
    samples: list[dict[str, Any]],
    bounds: Callable[..., dict[str, Any]],
    interval: float,
) -> dict[str, Any]:
    successful = sum(sample.get("ok") is True for sample in samples)
    outage = bounds(samples, sample_interval_s=interval)
    return {
        "samples": len(samples),
        "successful": successful,
        "lost": len(samples) - successful,
        "loss_pct": 100.0 * (len(samples) - successful) / len(samples)
        if samples
        else None,
        "outage": outage,
        "longest_outage_s": outage["outage_lower_bound_s"],
        "raw_samples": samples,
    }


def partition_continuity(
    payload: dict[str, Any],
    state: dict[str, Any],
    bounds: Callable[..., dict[str, Any]],
    *,
    sample_interval_s: float,
) -> dict[str, Any]:
    """Use actual send/launch times; never infer UDP loss timing from totals."""
    readiness = payload.get("readiness")
    readiness = readiness if isinstance(readiness, dict) else {}
    ready = (
        _time(readiness.get("ready_at_s")) if readiness.get("ready") is True else None
    )
    end = _time(payload.get("observation_duration_s"))
    raw = payload.get("icmp")
    raw = raw if isinstance(raw, list) else []
    samples = [sample for sample in raw if isinstance(sample, dict)]
    sample_times = [
        _time(sample.get("started_t", sample.get("t"))) for sample in samples
    ]
    valid = bool(
        ready is not None
        and end is not None
        and ready < end
        and len(samples) == len(raw)
        and samples
        and all(t is not None and t <= end + sample_interval_s for t in sample_times)
        and all(type(sample.get("ok")) is bool for sample in samples)
        and all(a <= b for a, b in zip(sample_times, sample_times[1:], strict=False))
    )
    markers = state.get("phase_markers")
    markers = markers if isinstance(markers, dict) else {}
    submitted = _time(markers.get("migration_submitted"))
    placed = _time(markers.get("placement_verified"))
    markers_valid = bool(
        valid
        and submitted is not None
        and placed is not None
        and ready <= submitted <= placed <= end
    )
    udp = payload.get("udp")
    udp = udp if isinstance(udp, dict) else {}
    response = udp.get("response")
    response = response if isinstance(response, dict) else {}
    times = udp.get("send_times_s")
    sent = udp.get("sent")
    received = response.get("received")
    bitmap = None
    hex_value = response.get("received_bitmap_hex")
    if (
        response.get("sequence_bitmap_complete") is True
        and type(sent) is int
        and 0 < sent <= 131072
        and isinstance(hex_value, str)
        and len(hex_value) == ((sent + 7) // 8) * 2
    ):
        try:
            bitmap = bytes.fromhex(hex_value)
        except ValueError:
            pass
    delivery = None
    if bitmap is not None:
        delivery = [
            bool(bitmap[index >> 3] & (1 << (index & 7))) for index in range(sent)
        ]
    udp_valid = bool(
        valid
        and isinstance(times, list)
        and type(sent) is int
        and sent > 0
        and len(times) == sent
        and delivery is not None
        and all(_time(t) is not None and t <= end + sample_interval_s for t in times)
        and all(a <= b for a, b in zip(times, times[1:], strict=False))
        and type(received) is int
        and sum(delivery) == received
        and response.get("sent") == sent
        and type(udp.get("session_id")) is int
        and response.get("session_id") == udp["session_id"]
        and all(
            not (bitmap[index >> 3] & (1 << (index & 7)))
            for index in range(sent, len(bitmap) * 8)
        )
    )

    def section(
        start: float, stop: float, *, inclusive_end: bool = False
    ) -> dict[str, Any]:
        def selected(t: float) -> bool:
            return start <= t and (t <= stop if inclusive_end else t < stop)

        chosen = [
            sample
            for sample, t in zip(samples, sample_times, strict=True)
            if t is not None and selected(t)
        ]
        udp_summary: dict[str, Any] = {
            "verified": False,
            "reason": "Per-sequence receiver evidence unavailable; total loss cannot locate startup loss",
        }
        if udp_valid:
            indices = [index for index, t in enumerate(times) if selected(t)]
            delivered = sum(delivery[index] for index in indices)
            udp_summary = {
                "verified": bool(indices),
                "sent": len(indices),
                "received": delivered,
                "lost": len(indices) - delivered,
                "loss_pct": 100.0 * (len(indices) - delivered) / len(indices)
                if indices
                else None,
                "first_sequence": indices[0] if indices else None,
                "last_sequence": indices[-1] if indices else None,
            }
        return {
            "start_s": start,
            "end_s": stop,
            "icmp": _icmp(chosen, bounds, sample_interval_s),
            "udp": udp_summary,
        }

    phases: dict[str, Any] = {}
    if valid:
        phases["startup"] = section(0.0, ready)
        phases["protected"] = section(
            ready, end + sample_interval_s, inclusive_end=True
        )
        phases["protected"]["end_s"] = end
        if markers_valid:
            phases["pre_submission"] = section(ready, submitted)
            phases["migration"] = section(submitted, placed)
            phases["post_migration"] = section(
                placed, end + sample_interval_s, inclusive_end=True
            )
            phases["post_migration"]["end_s"] = end
    return {
        "schema_version": 1,
        "assessment_scope": "ready-through-post-migration",
        "threshold_policy": "Existing limits apply to the protected interval; startup is retained separately",
        "markers": dict(markers),
        "markers_verified": markers_valid,
        "ready_at_s": ready,
        "observation_end_s": end,
        "icmp_partition_verified": valid,
        "udp_partition_verified": udp_valid,
        "verified": bool(
            valid
            and udp_valid
            and (markers_valid or not state.get("phase_markers_required"))
        ),
        "phases": phases,
        "raw_icmp_observations": raw,
        "boundary_note": "Guest-monotonic submission and observed placement boundaries; not Nova internal switchover times",
    }
