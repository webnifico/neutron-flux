from __future__ import annotations

from collections import Counter
from typing import Any

from ..logical_results import logical_results
from ..operator_explanations import explain_result


def attention_summary(payload: dict[str, Any]) -> Counter[str]:
    """Count advisory conditions once per logical check without changing verdicts."""
    counts: Counter[str] = Counter()
    for result in logical_results(payload):
        if result.get("status") != "PASS":
            continue
        story = result.get("operator_explanation") or explain_result(result)
        if story.get("kind") == "migration-interruption-observation":
            counts["migration_observations"] += 1
        if story.get(
            "udp_rate_calibrated", story.get("kind") == "measurement-rate-limited"
        ):
            counts["udp_calibrations"] += 1
        if (result.get("details") or {}).get("health") == "warning":
            key = (
                "performance_warnings"
                if result.get("category") == "network-performance"
                else "other_measurement_warnings"
            )
            counts[key] += 1
    return counts


def attention_summary_parts(counts: Counter[str]) -> list[str]:
    parts = []
    for key, singular, plural in (
        (
            "migration_observations",
            "migration interruption observation",
            "migration interruption observations",
        ),
        (
            "udp_calibrations",
            "calibrated UDP measurement",
            "calibrated UDP measurements",
        ),
        (
            "performance_warnings",
            "performance measurement warning",
            "performance measurement warnings",
        ),
        (
            "other_measurement_warnings",
            "measurement warning outside performance tests",
            "measurement warnings outside performance tests",
        ),
    ):
        count = counts[key]
        if count:
            parts.append(f"{count} {singular if count == 1 else plural}")
    return parts


def attention_summary_lines(counts: Counter[str]) -> list[str]:
    if not any(counts.values()):
        return []
    lines = [
        f"Migration interruption observations: {counts['migration_observations']}",
        f"UDP measurements with rate calibration: {counts['udp_calibrations']}",
        f"Performance measurements with advisory warnings: {counts['performance_warnings']}",
    ]
    if counts["other_measurement_warnings"]:
        lines.append(
            "Other measurements with advisory warnings: "
            f"{counts['other_measurement_warnings']}"
        )
    return lines
