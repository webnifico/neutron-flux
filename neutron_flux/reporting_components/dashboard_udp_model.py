from __future__ import annotations

import math
from typing import Any

from ..performance_metrics import udp_sample_assessable


def _num(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) else None


def _count(value: Any) -> int | None:
    parsed = _num(value)
    return (
        int(parsed)
        if parsed is not None and parsed >= 0 and parsed.is_integer()
        else None
    )


def _reordering(sample: dict[str, Any]) -> float | None:
    percentage = _num(sample.get("out_of_order_pct"))
    if percentage is not None:
        return percentage
    count, received = _count(sample.get("out_of_order")), _count(sample.get("received"))
    if count is not None and received is not None and received > 0:
        return 100.0 * count / received
    return None


def udp_measurement_values(metrics: dict[str, Any]) -> dict[str, Any]:
    """Separate sustainable UDP path metrics from excluded endpoint samples."""
    values: dict[str, Any] = {}
    for direction in ("forward", "reverse"):
        raw_samples = list(metrics.get(direction) or [])
        samples = [sample for sample in raw_samples if udp_sample_assessable(sample)]
        values[f"{direction}_excluded_samples"] = len(raw_samples) - len(samples)
        values[f"{direction}_endpoint_limited_loss_pct"] = max(
            (
                value
                for sample in raw_samples
                if sample.get("packet_size_supported") is not False
                and (
                    sample.get("endpoint_limited") is True
                    or sample.get("load_valid") is False
                )
                if (value := _num(sample.get("loss_pct"))) is not None
            ),
            default=None,
        )
        if samples:
            values[f"{direction}_loss_pct"] = max(
                (
                    value
                    for sample in samples
                    if (value := _num(sample.get("loss_pct"))) is not None
                ),
                default=None,
            )
            values[f"{direction}_jitter_ms"] = max(
                (
                    value
                    for sample in samples
                    if (value := _num(sample.get("jitter_ms"))) is not None
                ),
                default=None,
            )
            reordering_samples = [
                (percentage, sample)
                for sample in samples
                if (percentage := _reordering(sample)) is not None
            ]
            selected = max(reordering_samples, key=lambda item: item[0], default=None)
            best_reordering = (
                selected[1]
                if selected
                else max(
                    samples,
                    key=lambda sample: (
                        count
                        if (count := _count(sample.get("out_of_order"))) is not None
                        else -1
                    ),
                )
            )
            values[f"{direction}_reordering_pct"] = selected[0] if selected else None
            values[f"{direction}_reordering_count"] = _count(
                best_reordering.get("out_of_order")
            )
            values[f"{direction}_received"] = _count(best_reordering.get("received"))
            values[f"{direction}_sample_rate_mbps"] = _num(
                best_reordering.get("offered_mbps")
            )
            values[f"{direction}_sample_packet_size"] = _num(
                best_reordering.get("packet_size")
            )
    return values
