from __future__ import annotations

import math
import re
import statistics
from typing import Any


def udp_statistics_error(
    sample: dict[str, Any], *, require_complete: bool = False
) -> str | None:
    """Validate receiver evidence before it can support a UDP assessment."""
    import math

    required = (
        "sent",
        "received",
        "loss_pct",
        "mbps",
        "pps",
        "jitter_ms",
        "duplicates",
        "out_of_order",
    )
    for key in ("packet_size_supported", "control_statistics_available"):
        if key in sample and not isinstance(sample[key], bool):
            return f"invalid UDP evidence flag: {key}"
    if (
        sample.get("control_statistics_available") is False
        and sample.get("packet_size_supported") is not False
    ):
        return "UDP receiver statistics were unavailable"
    if require_complete:
        for key in required:
            if key not in sample:
                return f"missing UDP statistic: {key}"
    counts = (
        "session_id",
        "sent",
        "received",
        "application_received",
        "socket_dequeued",
        "wire_received",
        "duplicates",
        "lost",
        "out_of_order",
        "receiver_socket_rxq_overflow",
    )
    for key in counts:
        if key in sample:
            value = sample[key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                return f"invalid UDP count: {key}"
            maximum = (1 << 32) - 1 if key == "sent" else (1 << 64) - 1
            if value > maximum:
                return f"UDP count exceeds protocol limit: {key}"
    numbers = (
        "loss_pct",
        "mbps",
        "pps",
        "jitter_ms",
        "out_of_order_pct",
        "elapsed_s",
        "sender_elapsed_s",
        "receiver_active_elapsed_s",
        "sender_mbps",
        "receiver_goodput_mbps",
        "achieved_mbps",
    )
    for key in numbers:
        if key not in sample:
            continue
        value = sample[key]
        # Older summaries can explicitly omit unavailable optional aliases.
        if value is None and key in {"receiver_goodput_mbps", "achieved_mbps"}:
            continue
        try:
            finite = isinstance(value, (int, float)) and math.isfinite(value)
        except OverflowError:
            finite = False
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not finite
            or value < 0
            or (key in {"loss_pct", "out_of_order_pct"} and value > 100)
        ):
            return f"invalid UDP measurement: {key}"
    if "sent" in sample and "received" in sample:
        sent, received = sample["sent"], sample["received"]
        if received > sent:
            return "UDP received count exceeds sender count"
        if "lost" in sample and sample["lost"] != sent - received:
            return "UDP lost count disagrees with sender and receiver counts"
        expected_loss = (sent - received) * 100.0 / sent if sent else 0.0
        if "loss_pct" in sample and not math.isclose(
            sample["loss_pct"], expected_loss, rel_tol=1e-9, abs_tol=1e-9
        ):
            return "UDP loss percentage disagrees with packet counts"
    if "received" in sample:
        received = sample["received"]
        if (
            "application_received" in sample
            and sample["application_received"] != received
        ):
            return "UDP application count disagrees with receiver count"
        if sample.get("out_of_order", 0) > received:
            return "UDP reordering count exceeds receiver count"
        if received == 0 and any(sample.get(key, 0) > 0 for key in ("mbps", "pps")):
            return "UDP throughput was reported without received packets"
        if received > 0 and any(
            key in sample and sample[key] <= 0 for key in ("mbps", "pps")
        ):
            return "UDP received packets have no measured throughput"
        if "out_of_order_pct" in sample and "out_of_order" in sample:
            expected_reordering = (
                sample["out_of_order"] * 100.0 / received if received else 0.0
            )
            if not math.isclose(
                sample["out_of_order_pct"],
                expected_reordering,
                rel_tol=1e-9,
                abs_tol=1e-9,
            ):
                return "UDP reordering percentage disagrees with packet counts"
        for key in ("socket_dequeued", "wire_received"):
            if key in sample and sample[key] < received + sample.get("duplicates", 0):
                return f"UDP dequeued count is below received datagrams: {key}"
    return None


def udp_sample_assessable(sample: dict[str, Any]) -> bool:
    """Use selected, sustainable samples; preserve legacy unflagged evidence."""
    return (
        "loss_pct" in sample
        and sample.get("sent") != 0
        and sample.get("packet_size_supported") is not False
        and sample.get("endpoint_limited") is not True
        and sample.get("load_valid") is not False
        and sample.get("calibration_selected", True) is True
        and udp_statistics_error(
            sample, require_complete="control_statistics_available" in sample
        )
        is None
    )


def _parse_ping(returncode: int, stdout: str, stderr: str) -> dict[str, Any]:
    text = f"{stdout}\n{stderr}"
    transmitted = received = 0
    loss_pct = 100.0
    summary = re.search(
        r"(\d+) packets transmitted,\s*(\d+) (?:packets )?received.*?([\d.]+)% packet loss",
        text,
        re.DOTALL,
    )
    if summary:
        transmitted = int(summary.group(1))
        received = int(summary.group(2))
        loss_pct = float(summary.group(3))
    samples = [float(value) for value in re.findall(r"time[=<]([\d.]+)\s*ms", text)]
    if not samples:
        rtt = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms", text)
        if rtt:
            samples = [float(rtt.group(1)), float(rtt.group(2)), float(rtt.group(3))]
    return {
        "returncode": returncode,
        "transmitted": transmitted,
        "received": received,
        "loss_pct": loss_pct,
        "minimum_ms": min(samples) if samples else None,
        "average_ms": statistics.fmean(samples) if samples else None,
        "maximum_ms": max(samples) if samples else None,
        "p50_ms": _percentile(samples, 50),
        "p95_ms": _percentile(samples, 95),
        "p99_ms": _percentile(samples, 99),
        "samples_ms": samples,
        "confidence_95_ms": _confidence_interval_95(samples),
        "outliers_ms": _tukey_outliers(samples),
        "stderr": stderr.strip(),
    }


def _percentile(values: list[float], percentile: int) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * percentile / 100.0
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return ordered[lower]
    fraction = rank - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def _coefficient_of_variation(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = statistics.fmean(values)
    if mean == 0.0:
        return 0.0
    return statistics.stdev(values) / mean * 100.0


def _confidence_interval_95(values: list[float]) -> dict[str, Any]:
    """Return a small-sample Student-t confidence interval for the mean."""

    clean = _finite_values(values)
    count = len(clean)
    mean = statistics.fmean(clean) if clean else None
    if count < 2 or mean is None:
        return {
            "confidence_level": 0.95,
            "sample_count": count,
            "mean": mean,
            "lower": None,
            "upper": None,
            "margin": None,
            "method": "student-t",
        }
    critical = {
        1: 12.706,
        2: 4.303,
        3: 3.182,
        4: 2.776,
        5: 2.571,
        6: 2.447,
        7: 2.365,
        8: 2.306,
        9: 2.262,
        10: 2.228,
        11: 2.201,
        12: 2.179,
        13: 2.160,
        14: 2.145,
        15: 2.131,
        16: 2.120,
        17: 2.110,
        18: 2.101,
        19: 2.093,
        20: 2.086,
        21: 2.080,
        22: 2.074,
        23: 2.069,
        24: 2.064,
        25: 2.060,
        26: 2.056,
        27: 2.052,
        28: 2.048,
        29: 2.045,
        30: 2.042,
    }.get(count - 1, 1.96)
    margin = critical * statistics.stdev(clean) / math.sqrt(count)
    return {
        "confidence_level": 0.95,
        "sample_count": count,
        "mean": mean,
        "lower": mean - margin,
        "upper": mean + margin,
        "margin": margin,
        "method": "student-t",
    }


def _tukey_outliers(values: list[float]) -> dict[str, Any]:
    clean = _finite_values(values)
    if len(clean) < 4:
        return {
            "count": 0,
            "values": [],
            "lower_fence": None,
            "upper_fence": None,
            "method": "tukey-1.5-iqr",
        }
    q1 = _percentile(clean, 25)
    q3 = _percentile(clean, 75)
    if q1 is None or q3 is None:
        return {
            "count": 0,
            "values": [],
            "lower_fence": None,
            "upper_fence": None,
            "method": "tukey-1.5-iqr",
        }
    spread = q3 - q1
    lower = q1 - (1.5 * spread)
    upper = q3 + (1.5 * spread)
    outliers = [value for value in clean if value < lower or value > upper]
    return {
        "count": len(outliers),
        "values": outliers,
        "lower_fence": lower,
        "upper_fence": upper,
        "method": "tukey-1.5-iqr",
    }


def _finite_values(values: list[float]) -> list[float]:
    clean: list[float] = []
    for value in values:
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            continue
        if math.isfinite(parsed):
            clean.append(parsed)
    return clean


def _percent_difference(first: float, second: float) -> float:
    baseline = max(abs(first), abs(second))
    if baseline == 0.0:
        return 0.0
    return abs(first - second) / baseline * 100.0


def _jain_fairness(values: list[float]) -> float:
    if not values:
        return 0.0
    denominator = len(values) * sum(value * value for value in values)
    if denominator == 0.0:
        return 0.0
    return sum(values) ** 2 / denominator


def _last_line(value: str) -> str:
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    return lines[-1][:500] if lines else "unknown error"


__all__ = [
    "_coefficient_of_variation",
    "_confidence_interval_95",
    "_jain_fairness",
    "_last_line",
    "_parse_ping",
    "_percent_difference",
    "_percentile",
    "_tukey_outliers",
]
