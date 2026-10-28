from __future__ import annotations

import html
import json
import math
import pathlib
from collections import Counter, defaultdict
from typing import Any

from .mtu_contract import confirmed_no_fragment_path_mtu
from .replay_plan import build_replay_plan, render_replay_plan_text
from .result_contract import (
    contract_shape,
    normalize_result_record,
    observation_shape,
    semantic_result_key,
    typed_verdict,
)
from .results_io import atomic_write_text, load_results, output_directory

_STATUS_SCORE = {
    "PASS": 6,
    "UNVERIFIED": 4,
    "SKIP": 3,
    "NOT_APPLICABLE": 3,
    "BLOCKED_BY_SETUP_ERROR": 1,
    "BLOCKED_BY_PREREQUISITE": 1,
    "NOT_RUN_CANCELLED": 1,
    "FAIL": 1,
    "ERROR": 0,
}


_HEALTH_SCORE = {
    "good": 2,
    "warning": 1,
    "critical": 0,
}

_FINAL_STATUS_SCORE = {
    "PASS": 6,
    "PASS WITH WARNINGS": 5,
    "FAIL": 2,
    "INCOMPLETE": 2,
    "PARTIAL": 2,
    "SETUP FAILED": 1,
    "ERROR": 1,
    "INTERRUPTED": 0,
    "CANCELLED": 0,
    "CLEANUP INCOMPLETE": 0,
}


def _canonical_measurement(value: Any) -> str:
    measurement = str(value or "")
    return "concurrent-path-load" if measurement == "fabric-scale" else measurement


def _result_key(item: dict[str, Any]) -> tuple[Any, ...]:
    return semantic_result_key(item)


def _number(value: Any) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) else None


def _worst(samples: Any, key: str) -> float | None:
    values = [
        _number(item.get(key)) for item in samples or [] if isinstance(item, dict)
    ]
    present = [item for item in values if item is not None]
    return max(present) if present else None


def _performance_metrics(item: dict[str, Any]) -> dict[str, tuple[float | None, str]]:
    details = item.get("details") or {}
    measurement = _canonical_measurement(details.get("measurement"))
    metrics = details.get("metrics") or {}
    if measurement == "tcp-throughput":
        return {
            "forward_mbps": (
                _number(
                    (
                        ((metrics.get("forward") or {}).get("streams") or {}).get("1")
                        or {}
                    ).get("median_mbps")
                ),
                "higher",
            ),
            "reverse_mbps": (
                _number(
                    (
                        ((metrics.get("reverse") or {}).get("streams") or {}).get("1")
                        or {}
                    ).get("median_mbps")
                ),
                "higher",
            ),
            "bidirectional_mbps": (
                _number((metrics.get("bidirectional") or {}).get("aggregate_mbps")),
                "higher",
            ),
        }
    if measurement == "latency":
        return {
            "forward_idle_p95_ms": (
                _number(
                    ((metrics.get("idle") or {}).get("forward") or {}).get("p95_ms")
                ),
                "lower",
            ),
            "reverse_idle_p95_ms": (
                _number(
                    ((metrics.get("idle") or {}).get("reverse") or {}).get("p95_ms")
                ),
                "lower",
            ),
            "forward_loaded_p95_ms": (
                _number(
                    ((metrics.get("loaded") or {}).get("forward") or {}).get("p95_ms")
                ),
                "lower",
            ),
            "reverse_loaded_p95_ms": (
                _number(
                    ((metrics.get("loaded") or {}).get("reverse") or {}).get("p95_ms")
                ),
                "lower",
            ),
            "forward_loaded_ratio": (
                _number((metrics.get("loaded_p95_ratio") or {}).get("forward")),
                "lower",
            ),
            "reverse_loaded_ratio": (
                _number((metrics.get("loaded_p95_ratio") or {}).get("reverse")),
                "lower",
            ),
        }
    if measurement == "udp":
        return {
            "forward_loss_pct": (_worst(metrics.get("forward"), "loss_pct"), "lower"),
            "reverse_loss_pct": (_worst(metrics.get("reverse"), "loss_pct"), "lower"),
            "forward_jitter_ms": (_worst(metrics.get("forward"), "jitter_ms"), "lower"),
            "reverse_jitter_ms": (_worst(metrics.get("reverse"), "jitter_ms"), "lower"),
        }
    if measurement == "mtu-mss":
        return {
            "forward_discovered_mtu": (
                _number(confirmed_no_fragment_path_mtu(metrics.get("forward") or {})),
                "equal",
            ),
            "reverse_discovered_mtu": (
                _number(confirmed_no_fragment_path_mtu(metrics.get("reverse") or {})),
                "equal",
            ),
            "expected_mtu": (_number(metrics.get("expected_mtu")), "equal"),
        }
    if measurement == "asymmetry":
        return {
            "throughput_difference_pct": (
                _number(metrics.get("throughput_difference_pct")),
                "lower",
            ),
            "latency_difference_pct": (
                _number(metrics.get("latency_difference_pct")),
                "lower",
            ),
            "udp_loss_difference_pct_points": (
                _number(metrics.get("udp_loss_difference_pct_points")),
                "lower",
            ),
        }
    if measurement == "repeatability":
        return {
            "worst_variation_pct": (
                _number(metrics.get("worst_variation_pct")),
                "lower",
            )
        }
    if measurement == "concurrent-path-load":
        values: dict[str, tuple[float | None, str]] = {}
        for level in metrics.get("levels") or []:
            pairs = int(level.get("pairs") or 0)
            prefix = f"pairs_{pairs}"
            values[f"{prefix}_aggregate_mbps"] = (
                _number(level.get("median_aggregate_mbps")),
                "higher",
            )
            values[f"{prefix}_median_pair_mbps"] = (
                _number(level.get("median_pair_mbps")),
                "higher",
            )
            values[f"{prefix}_minimum_pair_mbps"] = (
                _number(level.get("minimum_pair_mbps")),
                "higher",
            )
            values[f"{prefix}_fairness"] = (
                _number(level.get("median_fairness")),
                "higher",
            )
            values[f"{prefix}_loaded_p95_ms"] = (
                _number(level.get("median_loaded_p95_ms")),
                "lower",
            )
            values[f"{prefix}_loaded_latency_ratio"] = (
                _number(level.get("median_loaded_latency_ratio")),
                "lower",
            )
            explicit_udp_loss = _number(
                level.get("maximum_loaded_udp_application_loss_pct")
            )
            if explicit_udp_loss is None:
                explicit_udp_loss = _number(level.get("maximum_loaded_udp_loss_pct"))
            if explicit_udp_loss is None:
                explicit_udp_loss = _number(level.get("maximum_loaded_loss_pct"))
            values[f"{prefix}_loaded_udp_application_loss_pct"] = (
                explicit_udp_loss,
                "lower",
            )
            values[f"{prefix}_loaded_icmp_loss_pct"] = (
                _number(level.get("maximum_loaded_icmp_loss_pct")),
                "lower",
            )
            values[f"{prefix}_udp_jitter_ms"] = (
                _number(level.get("maximum_loaded_udp_jitter_ms")),
                "lower",
            )
            values[f"{prefix}_retransmissions"] = (
                _number(level.get("total_retransmissions")),
                "lower",
            )
            values[f"{prefix}_retransmissions_per_gib"] = (
                _number(level.get("retransmissions_per_gib")),
                "lower",
            )
            values[f"{prefix}_retransmissions_per_second"] = (
                _number(level.get("retransmissions_per_second")),
                "lower",
            )
            values[f"{prefix}_loaded_tcp_aggregate_mbps"] = (
                _number(level.get("median_loaded_tcp_aggregate_mbps")),
                "higher",
            )
            values[f"{prefix}_loaded_retransmissions"] = (
                _number(level.get("total_loaded_retransmissions")),
                "lower",
            )
            values[f"{prefix}_loaded_retransmissions_per_gib"] = (
                _number(level.get("loaded_retransmissions_per_gib")),
                "lower",
            )
            values[f"{prefix}_loaded_retransmissions_per_second"] = (
                _number(level.get("loaded_retransmissions_per_second")),
                "lower",
            )
            values[f"{prefix}_per_pair_degradation_pct"] = (
                _number(level.get("per_pair_degradation_pct")),
                "lower",
            )
        return values
    return {}


def _performance_confidence(
    item: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    details = item.get("details") or {}
    if details.get("measurement") != "tcp-throughput":
        return {}
    metrics = details.get("metrics") or {}
    output: dict[str, dict[str, Any]] = {}
    for direction in ("forward", "reverse"):
        summary = ((metrics.get(direction) or {}).get("streams") or {}).get("1") or {}
        confidence = summary.get("confidence_95_mbps")
        if isinstance(confidence, dict):
            output[f"{direction}_mbps"] = confidence
    return output


def _apply_statistical_confidence(
    change: dict[str, Any],
    baseline: dict[str, Any] | None,
    candidate: dict[str, Any] | None,
    direction: str,
) -> dict[str, Any]:
    change["baseline_confidence_95"] = baseline
    change["candidate_confidence_95"] = candidate
    if not baseline or not candidate:
        change["statistical_assessment"] = "not-available"
        return change
    baseline_lower = _number(baseline.get("lower"))
    baseline_upper = _number(baseline.get("upper"))
    candidate_lower = _number(candidate.get("lower"))
    candidate_upper = _number(candidate.get("upper"))
    if None in {
        baseline_lower,
        baseline_upper,
        candidate_lower,
        candidate_upper,
    }:
        change["statistical_assessment"] = "insufficient-samples"
        return change
    overlap = not (
        float(candidate_upper) < float(baseline_lower)
        or float(baseline_upper) < float(candidate_lower)
    )
    change["confidence_intervals_overlap"] = overlap
    if overlap and change.get("assessment") in {"improved", "regressed"}:
        change["raw_assessment"] = change["assessment"]
        change["assessment"] = "unchanged"
        change["statistical_assessment"] = "inconclusive-overlap"
    elif direction == "higher":
        change["statistical_assessment"] = (
            "significant-improvement"
            if float(candidate_lower) > float(baseline_upper)
            else "significant-regression"
            if float(candidate_upper) < float(baseline_lower)
            else "unchanged"
        )
    elif direction == "lower":
        change["statistical_assessment"] = (
            "significant-improvement"
            if float(candidate_upper) < float(baseline_lower)
            else "significant-regression"
            if float(candidate_lower) > float(baseline_upper)
            else "unchanged"
        )
    else:
        change["statistical_assessment"] = "not-applicable"
    return change


def _index(payload: dict[str, Any]) -> dict[tuple[Any, ...], dict[str, Any]]:
    output: dict[tuple[Any, ...], dict[str, Any]] = {}
    for raw in payload.get("results") or []:
        item = normalize_result_record(raw)
        key = _result_key(item)
        existing = output.get(key)
        if existing is None:
            output[key] = item
            continue
        # Keep the most severe duplicate so comparison never hides a problem.
        item_status = _STATUS_SCORE.get(str(item.get("status")), 0)
        existing_status = _STATUS_SCORE.get(str(existing.get("status")), 0)
        item_health = _HEALTH_SCORE.get(
            str((item.get("details") or {}).get("health") or "good"), 2
        )
        existing_health = _HEALTH_SCORE.get(
            str((existing.get("details") or {}).get("health") or "good"), 2
        )
        if item_status < existing_status or (
            item_status == existing_status and item_health < existing_health
        ):
            output[key] = item
    return output


def _path_without_test_key(item: dict[str, Any]) -> tuple[Any, ...] | None:
    signature = item.get("path_signature") or {}
    identity = dict(signature.get("identity") or {})
    identity.pop("contract_type", None)
    identity.pop("semantic_test", None)
    # Category and address family alone are not enough evidence that two
    # differently named tests are the same validation. Require an actual path,
    # placement, protocol, operation, lifecycle, host-pair, or measurement
    # discriminator before attempting ID-drift recovery.
    discriminators = {
        key: value
        for key, value in identity.items()
        if key not in {"category", "family"}
    }
    if not discriminators:
        return None
    encoded = json.dumps(
        identity,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return ("semantic-path-without-test-id", encoded)


def _comparison_pairs(
    left: dict[tuple[Any, ...], dict[str, Any]],
    right: dict[tuple[Any, ...], dict[str, Any]],
) -> list[tuple[tuple[Any, ...], dict[str, Any] | None, dict[str, Any] | None, str]]:
    pairs: list[
        tuple[tuple[Any, ...], dict[str, Any] | None, dict[str, Any] | None, str]
    ] = []
    matched_left: set[tuple[Any, ...]] = set()
    matched_right: set[tuple[Any, ...]] = set()

    for key in set(left) & set(right):
        pairs.append(
            (
                key,
                left[key],
                right[key],
                "Semantic contract and path identity were matched",
            )
        )
        matched_left.add(key)
        matched_right.add(key)

    left_fallback: dict[tuple[Any, ...], list[tuple[Any, ...]]] = defaultdict(list)
    right_fallback: dict[tuple[Any, ...], list[tuple[Any, ...]]] = defaultdict(list)
    for key, item in left.items():
        if key not in matched_left:
            fallback_key = _path_without_test_key(item)
            if fallback_key is not None:
                left_fallback[fallback_key].append(key)
    for key, item in right.items():
        if key not in matched_right:
            fallback_key = _path_without_test_key(item)
            if fallback_key is not None:
                right_fallback[fallback_key].append(key)

    for fallback_key in set(left_fallback) & set(right_fallback):
        left_keys = left_fallback[fallback_key]
        right_keys = right_fallback[fallback_key]
        # ID-drift matching is intentionally conservative. An ambiguous path is
        # left unmatched rather than pairing unrelated validations.
        if len(left_keys) != 1 or len(right_keys) != 1:
            continue
        left_key = left_keys[0]
        right_key = right_keys[0]
        matched_left.add(left_key)
        matched_right.add(right_key)
        pairs.append(
            (
                fallback_key,
                left[left_key],
                right[right_key],
                "Semantic path identity matched after a test-ID change",
            )
        )

    for key, item in left.items():
        if key not in matched_left:
            pairs.append(
                (key, item, None, "No matching semantic contract exists in both runs")
            )
    for key, item in right.items():
        if key not in matched_right:
            pairs.append(
                (key, None, item, "No matching semantic contract exists in both runs")
            )
    return sorted(pairs, key=lambda item: repr(item[0]))


def _metric_delta(
    baseline: float | None,
    candidate: float | None,
    direction: str,
) -> dict[str, Any]:
    if baseline is None or candidate is None:
        return {
            "baseline": baseline,
            "candidate": candidate,
            "delta": None,
            "delta_pct": None,
            "assessment": "not-comparable",
        }
    delta = candidate - baseline
    delta_pct = (delta / abs(baseline) * 100.0) if baseline else None
    if direction == "equal":
        # Equality metrics such as discovered MTU are categorical contracts:
        # even a small numeric change must remain visible in the comparison.
        assessment = "unchanged" if abs(delta) <= 1e-9 else "changed"
    else:
        tolerance = max(abs(baseline) * 0.02, 1e-9)
        if abs(delta) <= tolerance:
            assessment = "unchanged"
        elif direction == "higher":
            assessment = "improved" if delta > 0 else "regressed"
        else:
            assessment = "improved" if delta < 0 else "regressed"
    return {
        "baseline": baseline,
        "candidate": candidate,
        "delta": delta,
        "delta_pct": delta_pct,
        "assessment": assessment,
    }


def _run_metrics(payload: dict[str, Any]) -> dict[str, tuple[float | None, str]]:
    summary = payload.get("summary") or {}
    counts = summary.get("counts") or {}
    performance = summary.get("performance") or summary.get("performance_summary") or {}
    results = list(payload.get("results") or [])
    path_value = (
        performance.get("paths")
        if performance.get("paths") is not None
        else performance.get("paths_measured")
    )
    return {
        "total_results": (float(len(results)), "higher"),
        "authoritative_results": (
            float(sum(1 for item in results if item.get("authoritative") is True)),
            "higher",
        ),
        "performance_paths": (_number(path_value), "higher"),
        "failures": (_number(counts.get("FAIL") or 0), "lower"),
        "errors": (_number(counts.get("ERROR") or 0), "lower"),
        "not_run": (
            _number(
                (counts.get("BLOCKED_BY_SETUP_ERROR") or 0)
                + (counts.get("BLOCKED_BY_PREREQUISITE") or 0)
                + (counts.get("NOT_RUN_CANCELLED") or 0)
            ),
            "lower",
        ),
        "unverified": (_number(counts.get("UNVERIFIED") or 0), "lower"),
        "performance_warnings": (
            _number(
                performance.get("warnings") or performance.get("warning_results") or 0
            ),
            "lower",
        ),
    }


def _status_assessment(before_status: str, after_status: str) -> str:
    """Compare result states without treating lost execution as improvement."""
    if before_status == after_status:
        return "unchanged"
    executed = {"PASS", "FAIL", "ERROR"}
    unavailable = {
        "UNVERIFIED",
        "SKIP",
        "NOT_APPLICABLE",
        "BLOCKED_BY_SETUP_ERROR",
        "BLOCKED_BY_PREREQUISITE",
        "NOT_RUN_CANCELLED",
    }
    if before_status in executed and after_status in unavailable:
        # Losing an executed result is a regression even when the old result failed.
        return "regressed"
    if before_status in unavailable and after_status in executed:
        # Newly executing a test is only an improvement when it passes. A newly
        # observed FAIL/ERROR remains a regression in network quality.
        return "improved" if after_status == "PASS" else "regressed"
    if before_status in executed and after_status in executed:
        before_score = _STATUS_SCORE.get(before_status, 0)
        after_score = _STATUS_SCORE.get(after_status, 0)
        if after_score > before_score:
            return "improved"
        if after_score < before_score:
            return "regressed"
        return "changed"
    if before_status in unavailable and after_status in unavailable:
        return "changed"
    return "changed"


def _final_status_change(
    baseline: dict[str, Any], candidate: dict[str, Any]
) -> dict[str, Any]:
    before = str((baseline.get("run") or {}).get("final_status") or "").upper()
    after = str((candidate.get("run") or {}).get("final_status") or "").upper()
    if not before or not after:
        assessment = "not-comparable"
    elif before == after:
        assessment = "unchanged"
    elif before not in _FINAL_STATUS_SCORE or after not in _FINAL_STATUS_SCORE:
        assessment = "changed"
    elif _FINAL_STATUS_SCORE[after] > _FINAL_STATUS_SCORE[before]:
        assessment = "improved"
    elif _FINAL_STATUS_SCORE[after] == _FINAL_STATUS_SCORE[before]:
        assessment = "changed"
    else:
        assessment = "regressed"
    return {
        "baseline": before or None,
        "candidate": after or None,
        "assessment": assessment,
    }


def _cleanup_change(
    baseline: dict[str, Any], candidate: dict[str, Any]
) -> dict[str, Any]:
    before = (baseline.get("cleanup") or {}).get("complete")
    after = (candidate.get("cleanup") or {}).get("complete")
    if before is None or after is None:
        assessment = "not-comparable"
    elif before == after:
        assessment = "unchanged"
    elif after is True:
        assessment = "improved"
    else:
        assessment = "regressed"
    return {"baseline": before, "candidate": after, "assessment": assessment}


def _coverage_state(item: dict[str, Any] | None) -> str:
    if item is None:
        return "missing"
    verdict = typed_verdict(item)
    if verdict in {"PASS", "FAIL", "ERROR"}:
        return "observed"
    if verdict == "UNVERIFIED":
        return "partial"
    if verdict == "INAPPLICABLE":
        return "inapplicable"
    return "not-observed"


def _mention_shape(item: dict[str, Any]) -> dict[str, Any]:
    contract = item.get("contract") or {}
    expectation = contract.get("expectation") or {}
    observation = contract.get("observation") or {}
    authority = contract.get("authority") or {}
    return {
        "test_id": item.get("test_id"),
        "display_name": item.get("display_name"),
        "scenario": item.get("scenario"),
        "source": item.get("source"),
        "destination": item.get("destination"),
        "message": item.get("message"),
        "contract_description": contract.get("description"),
        "expectation_description": expectation.get("description"),
        "expectation_source_description": (expectation.get("source") or {}).get(
            "description"
        ),
        "observation_description": observation.get("description"),
        "authority_limitation": authority.get("limitation"),
    }


def _semantic_change_types(
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
    *,
    metric_changes: dict[str, Any],
) -> list[str]:
    if before is None and after is None:
        return ["not comparable"]
    if after is None:
        return [
            "coverage loss"
            if _coverage_state(before) == "observed"
            else "not comparable"
        ]
    if before is None:
        return ["not comparable"]

    before_contract = contract_shape(before)
    after_contract = contract_shape(after)
    if before_contract != after_contract:
        return ["contract changed"]

    before_coverage = _coverage_state(before)
    after_coverage = _coverage_state(after)
    if before_coverage == "observed" and after_coverage != "observed":
        return ["coverage loss"]

    before_verdict = typed_verdict(before)
    after_verdict = typed_verdict(after)
    verdict_scores = {
        "PASS": 6,
        "UNVERIFIED": 4,
        "INAPPLICABLE": 3,
        "NOT_RUN": 2,
        "BLOCKED": 1,
        "FAIL": 1,
        "ERROR": 0,
    }
    if verdict_scores.get(after_verdict, 0) < verdict_scores.get(before_verdict, 0):
        return ["verdict regression"]

    changed_metrics = any(
        item.get("assessment") not in {"unchanged", "not-comparable"}
        for item in metric_changes.values()
    )
    if observation_shape(before) != observation_shape(after) or changed_metrics:
        return ["observation changed"]
    if _mention_shape(before) != _mention_shape(after):
        return ["mention drift"]
    return ["unchanged"]


def compare_payloads(
    baseline: dict[str, Any], candidate: dict[str, Any]
) -> dict[str, Any]:
    left = _index(baseline)
    right = _index(candidate)
    entries: list[dict[str, Any]] = []
    for key, before, after, comparison_reason in _comparison_pairs(left, right):
        before_status = str((before or {}).get("status") or "MISSING")
        after_status = str((after or {}).get("status") or "MISSING")
        if before is None:
            after_health = str(
                ((after or {}).get("details") or {}).get("health") or ""
            ).lower()
            status_assessment = (
                "regressed"
                if after_status in {"FAIL", "ERROR"}
                or _HEALTH_SCORE.get(after_health, 2) < 2
                else "added"
            )
        elif after is None:
            status_assessment = (
                "regressed" if before_status in {"PASS", "FAIL", "ERROR"} else "removed"
            )
        else:
            status_assessment = _status_assessment(before_status, after_status)
            before_health = str(
                (before.get("details") or {}).get("health") or ""
            ).lower()
            after_health = str((after.get("details") or {}).get("health") or "").lower()
            if before_health or after_health:
                before_health_score = _HEALTH_SCORE.get(before_health, 2)
                after_health_score = _HEALTH_SCORE.get(after_health, 2)
                if after_health_score < before_health_score:
                    status_assessment = "regressed"
                elif (
                    status_assessment == "unchanged"
                    and after_health_score > before_health_score
                ):
                    status_assessment = "improved"
        metric_changes: dict[str, Any] = {}
        before_metrics = _performance_metrics(before or {})
        after_metrics = _performance_metrics(after or {})
        before_confidence = _performance_confidence(before or {})
        after_confidence = _performance_confidence(after or {})
        for metric in sorted(set(before_metrics) | set(after_metrics)):
            baseline_value, direction = before_metrics.get(metric, (None, "equal"))
            candidate_value, candidate_direction = after_metrics.get(
                metric, (None, direction)
            )
            metric_changes[metric] = _apply_statistical_confidence(
                _metric_delta(
                    baseline_value,
                    candidate_value,
                    candidate_direction or direction,
                ),
                before_confidence.get(metric),
                after_confidence.get(metric),
                candidate_direction or direction,
            )
        overall = status_assessment
        metric_assessments = {
            item.get("assessment") for item in metric_changes.values()
        }
        if "regressed" in metric_assessments:
            overall = "regressed"
        elif overall == "unchanged" and "changed" in metric_assessments:
            overall = "changed"
        elif overall == "unchanged" and "improved" in metric_assessments:
            overall = "improved"
        change_types = _semantic_change_types(
            before, after, metric_changes=metric_changes
        )
        entries.append(
            {
                "key": list(key),
                "change_type": change_types[0],
                "change_types": change_types,
                "comparable": change_types[0] != "not comparable",
                "comparison_reason": comparison_reason,
                "baseline_contract": contract_shape(before) if before else None,
                "candidate_contract": contract_shape(after) if after else None,
                "baseline_verdict": typed_verdict(before) if before else None,
                "candidate_verdict": typed_verdict(after) if after else None,
                "baseline_path_signature": (before or {}).get("path_signature"),
                "candidate_path_signature": (after or {}).get("path_signature"),
                "label": (after or before or {}).get("display_name")
                or (after or before or {}).get("test_id"),
                "category": (after or before or {}).get("category"),
                "scenario": (after or before or {}).get("scenario"),
                "baseline_status": before_status,
                "candidate_status": after_status,
                "baseline_health": ((before or {}).get("details") or {}).get("health"),
                "candidate_health": ((after or {}).get("details") or {}).get("health"),
                "assessment": overall,
                "baseline_test_id": (before or {}).get("test_id"),
                "candidate_test_id": (after or {}).get("test_id"),
                "metrics": metric_changes,
            }
        )
    counts = Counter(item["assessment"] for item in entries)
    semantic_counts = Counter(item["change_type"] for item in entries)
    unavailable_statuses = {
        "MISSING",
        "UNVERIFIED",
        "SKIP",
        "NOT_APPLICABLE",
        "BLOCKED_BY_SETUP_ERROR",
        "BLOCKED_BY_PREREQUISITE",
        "NOT_RUN_CANCELLED",
    }
    lost_coverage = sum(
        1
        for item in entries
        if item.get("candidate_status") in unavailable_statuses
        and item.get("baseline_status") in {"PASS", "FAIL", "ERROR"}
        and item.get("candidate_status") != item.get("baseline_status")
    )
    baseline_run_metrics = _run_metrics(baseline)
    candidate_run_metrics = _run_metrics(candidate)
    run_metrics: dict[str, Any] = {}
    for metric in sorted(set(baseline_run_metrics) | set(candidate_run_metrics)):
        before_value, direction = baseline_run_metrics.get(metric, (None, "equal"))
        after_value, after_direction = candidate_run_metrics.get(
            metric, (None, direction)
        )
        run_metrics[metric] = _metric_delta(
            before_value, after_value, after_direction or direction
        )
    final_status_change = _final_status_change(baseline, candidate)
    cleanup_change = _cleanup_change(baseline, candidate)
    run_regressions = (
        sum(1 for item in run_metrics.values() if item.get("assessment") == "regressed")
        + (1 if final_status_change.get("assessment") == "regressed" else 0)
        + (1 if cleanup_change.get("assessment") == "regressed" else 0)
    )
    return {
        "schema_version": 1,
        "kind": "neutron-flux-comparison",
        "baseline": baseline.get("run") or {},
        "candidate": candidate.get("run") or {},
        "summary": {
            **dict(counts),
            "semantic_change_types": dict(semantic_counts),
            "contract_changed": semantic_counts.get("contract changed", 0),
            "observation_changed": semantic_counts.get("observation changed", 0),
            "verdict_regression": semantic_counts.get("verdict regression", 0),
            "coverage_loss": semantic_counts.get("coverage loss", 0),
            "mention_drift": semantic_counts.get("mention drift", 0),
            "not_comparable": semantic_counts.get("not comparable", 0),
            "semantic_unchanged": semantic_counts.get("unchanged", 0),
            "lost_coverage": lost_coverage,
            "run_regressions": run_regressions,
        },
        "run_changes": {
            "final_status": final_status_change,
            "metrics": run_metrics,
            "cleanup": cleanup_change,
        },
        "entries": entries,
    }


def _comparison_text(payload: dict[str, Any]) -> str:
    lines = [
        "NEUTRON FLUX RUN COMPARISON",
        "=" * 100,
        f"Baseline: {payload.get('baseline', {}).get('run_id', 'unknown')}",
        f"Candidate: {payload.get('candidate', {}).get('run_id', 'unknown')}",
        "",
        "SUMMARY",
        "-" * 100,
    ]
    for key in ("regressed", "improved", "changed", "added", "removed", "unchanged"):
        lines.append(f"{key.title():<20} {payload.get('summary', {}).get(key, 0):>8}")
    lines.append("")
    for key, count in (
        payload.get("summary", {}).get("semantic_change_types") or {}
    ).items():
        lines.append(f"{key.title():<20} {count:>8}")
    lines.extend(["", "RUN-LEVEL CHANGES", "-" * 100])
    final_status = (payload.get("run_changes") or {}).get("final_status") or {}
    lines.append(
        f"Final status: {final_status.get('baseline')} -> {final_status.get('candidate')} "
        f"({final_status.get('assessment')})"
    )
    cleanup = (payload.get("run_changes") or {}).get("cleanup") or {}
    lines.append(
        f"Cleanup: {cleanup.get('baseline')} -> {cleanup.get('candidate')} "
        f"({cleanup.get('assessment')})"
    )
    for name, metric in (
        (payload.get("run_changes") or {}).get("metrics") or {}
    ).items():
        lines.append(
            f"{name}: {metric.get('baseline')} -> {metric.get('candidate')} "
            f"({metric.get('assessment')}, delta={metric.get('delta_pct')})"
        )
    lines.extend(["", "DETAILS", "-" * 100])
    ordered = sorted(
        payload.get("entries") or [],
        key=lambda item: (
            0 if item.get("assessment") == "regressed" else 1,
            str(item.get("category")),
            str(item.get("label")),
        ),
    )
    for item in ordered:
        lines.append(
            f"[{str(item.get('assessment')).upper()} / "
            f"{str(item.get('change_type')).upper()}] {item.get('label')} | "
            f"{item.get('baseline_status')} -> {item.get('candidate_status')}"
        )
        for name, metric in (item.get("metrics") or {}).items():
            lines.append(
                f"  {name}: {metric.get('baseline')} -> {metric.get('candidate')} "
                f"({metric.get('assessment')}, delta={metric.get('delta_pct')})"
            )
    return "\n".join(lines) + "\n"


def _comparison_html(payload: dict[str, Any]) -> str:
    data = json.dumps(payload, separators=(",", ":"), allow_nan=False).replace(
        "</", "<\\/"
    )
    title = html.escape(
        f"Neutron Flux comparison — {payload.get('candidate', {}).get('run_id', 'candidate')}"
    )
    return f"""<!doctype html>
<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{title}</title>
<style>
:root{{--bg:#07111f;--panel:#101d2d;--line:#2c4664;--text:#ecf4ff;--muted:#aebed1;--good:#42d392;--bad:#ff6b7a;--warn:#ffcb66;--accent:#67d8ff}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,sans-serif}}main{{max-width:1700px;margin:auto;padding:28px}}h1{{margin:0 0 6px}}.muted{{color:var(--muted)}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:22px 0}}.card,.panel{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}}.card strong{{display:block;font-size:28px}}table{{width:100%;border-collapse:collapse}}th,td{{padding:10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}th{{position:sticky;top:0;background:#14243a}}.wrap{{max-height:75vh;overflow:auto}}.pill{{display:inline-block;padding:4px 8px;border-radius:999px;font-weight:700;font-size:12px}}.regressed{{background:#49202b;color:#ffabb7}}.improved{{background:#153c32;color:#8cf4c6}}.unchanged{{background:#1c3350;color:#a9ceff}}.added,.removed,.changed,.not-comparable{{background:#493d1e;color:#ffe5a7}}.semantic{{background:#17384a;color:#a9e8ff}}details pre{{white-space:pre-wrap;background:#091625;padding:10px;border-radius:8px}}input,select{{background:#091625;color:var(--text);border:1px solid var(--line);padding:9px;border-radius:8px;margin:0 8px 12px 0}}
</style></head><body><main><h1>Neutron Flux run comparison</h1><p class=\"muted\" id=\"runs\"></p><div class=\"cards\" id=\"cards\"></div><div class=\"panel\"><h2>Run-level changes</h2><div id=\"runChanges\"></div></div><div class=\"panel\"><input id=\"q\" placeholder=\"Search tests, contracts and metrics\"><select id=\"assessment\"><option value=\"\">All assessments</option><option>regressed</option><option>improved</option><option>changed</option><option>added</option><option>removed</option><option>unchanged</option></select><select id=\"semantic\"><option value=\"\">All semantic changes</option><option>contract changed</option><option>observation changed</option><option>verdict regression</option><option>coverage loss</option><option>mention drift</option><option>not comparable</option><option>unchanged</option></select><div class=\"wrap\"><table><thead><tr><th>Assessment</th><th>Semantic change</th><th>Test</th><th>Typed verdict</th><th>Metric changes</th></tr></thead><tbody id=\"rows\"></tbody></table></div></div></main>
<script id=\"data\" type=\"application/json\">{data}</script><script>
const D=JSON.parse(document.getElementById('data').textContent),esc=v=>String(v??'').replace(/[&<>\"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}}[c]));
document.getElementById('runs').textContent=`${{D.baseline.run_id||'baseline'}} → ${{D.candidate.run_id||'candidate'}}`;
const cards=[['regressed',D.summary.regressed],['verdict regression',D.summary.verdict_regression],['contract changed',D.summary.contract_changed],['observation changed',D.summary.observation_changed],['coverage loss',D.summary.coverage_loss],['mention drift',D.summary.mention_drift],['not comparable',D.summary.not_comparable],['unchanged',D.summary.semantic_unchanged],['run regressions',D.summary.run_regressions]];document.getElementById('cards').innerHTML=cards.map(([k,v])=>`<div class=\"card\"><span class=\"muted\">${{esc(k)}}</span><strong>${{v||0}}</strong></div>`).join('');
const finalStatus=D.run_changes?.final_status||{{}},cleanup=D.run_changes?.cleanup||{{}},runMetrics=D.run_changes?.metrics||{{}};document.getElementById('runChanges').innerHTML=`<div><strong>Final status</strong>: ${{esc(finalStatus.baseline)}} → ${{esc(finalStatus.candidate)}} <span class=\"pill ${{finalStatus.assessment}}\">${{esc(finalStatus.assessment)}}</span></div><div><strong>Cleanup</strong>: ${{esc(cleanup.baseline)}} → ${{esc(cleanup.candidate)}} <span class=\"pill ${{cleanup.assessment}}\">${{esc(cleanup.assessment)}}</span></div>`+Object.entries(runMetrics).map(([k,m])=>`<div><strong>${{esc(k)}}</strong>: ${{m.baseline??'—'}} → ${{m.candidate??'—'}} <span class=\"pill ${{m.assessment}}\">${{esc(m.assessment)}}</span></div>`).join('');
function render(){{const q=document.getElementById('q').value.toLowerCase(),a=document.getElementById('assessment').value,s=document.getElementById('semantic').value;const rows=D.entries.filter(x=>(!a||x.assessment===a)&&(!s||x.change_type===s)&&(!q||JSON.stringify(x).toLowerCase().includes(q)));document.getElementById('rows').innerHTML=rows.map(x=>`<tr><td><span class=\"pill ${{x.assessment}}\">${{esc(x.assessment)}}</span></td><td><span class=\"pill semantic\">${{esc(x.change_type)}}</span><br><span class=\"muted\">${{esc(x.comparison_reason||'')}}</span></td><td><strong>${{esc(x.label)}}</strong><br><span class=\"muted\">${{esc(x.category||'')}} · ${{esc(x.scenario||'')}}</span></td><td>${{esc(x.baseline_verdict||x.baseline_status)}} → ${{esc(x.candidate_verdict||x.candidate_status)}}<br><span class=\"muted\">${{esc(x.baseline_status)}} → ${{esc(x.candidate_status)}}</span></td><td>${{Object.entries(x.metrics||{{}}).map(([k,m])=>`<div><strong>${{esc(k)}}</strong>: ${{m.baseline??'—'}} → ${{m.candidate??'—'}} <span class=\"pill ${{m.assessment}}\">${{esc(m.assessment)}}</span></div>`).join('')||'—'}}<details><summary>Raw comparison</summary><pre>${{esc(JSON.stringify(x,null,2))}}</pre></details></td></tr>`).join('');
}}
document.getElementById('q').addEventListener('input',render);document.getElementById('assessment').addEventListener('change',render);document.getElementById('semantic').addEventListener('change',render);render();
</script></body></html>"""


def compare_files(
    baseline_path: str | pathlib.Path,
    candidate_path: str | pathlib.Path,
    *,
    destination: str | pathlib.Path | None = None,
) -> dict[str, pathlib.Path]:
    baseline = load_results(baseline_path)
    candidate = load_results(candidate_path)
    candidate_source = pathlib.Path(candidate_path).expanduser().resolve()
    output = output_directory(
        destination, default=candidate_source.parent / "comparison"
    )
    payload = compare_payloads(baseline, candidate)
    json_path = output / "comparison.json"
    text_path = output / "comparison.txt"
    html_path = output / "comparison.html"
    replay_json_path = output / "replay-plan.json"
    replay_text_path = output / "replay-plan.txt"
    replay_plan = build_replay_plan(candidate)
    atomic_write_text(
        json_path,
        json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n",
    )
    atomic_write_text(text_path, _comparison_text(payload))
    atomic_write_text(html_path, _comparison_html(payload))
    atomic_write_text(
        replay_json_path,
        json.dumps(
            replay_plan,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n",
    )
    atomic_write_text(replay_text_path, render_replay_plan_text(replay_plan))
    return {
        "json": json_path,
        "text": text_path,
        "html": html_path,
        "replay_plan_json": replay_json_path,
        "replay_plan_text": replay_text_path,
    }


__all__ = ["compare_files", "compare_payloads"]
