from __future__ import annotations

import math
from typing import Any

from .mtu_contract import confirmed_no_fragment_path_mtu
from .performance_metrics import (
    _jain_fairness,
    _percent_difference,
    udp_sample_assessable,
)


def directional_comparison_meaning(
    metrics: dict[str, Any], component: str
) -> str | None:
    """Describe the recorded comparison without treating every advisory as a breach."""
    health = metrics.get(component + "_health")
    if health not in {"good", "warning", "unverified"}:
        return None
    if component != "udp":
        return {
            "good": "Within the configured advisory threshold",
            "warning": "Above the configured advisory threshold",
            "unverified": "Incomplete evidence",
        }[health]

    def number(key: str) -> float | None:
        value = metrics.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        try:
            parsed = float(value)
        except OverflowError:
            return None
        return parsed if math.isfinite(parsed) and parsed >= 0 else None

    delta = number("udp_loss_difference_pct_points")
    if health == "unverified" or delta is None:
        return "Incomplete evidence"
    partial = (
        str(metrics.get("udp_comparison_scope") or "").startswith("partial-")
        or (number("udp_unmatched_profiles") or 0) > 0
        or (number("udp_packet_size_rejected_profiles") or 0) > 0
    )
    threshold = number("udp_loss_advisory_threshold_pct_points")
    exceeded = delta > threshold if threshold is not None else None
    if partial:
        if exceeded is True:
            return "Above the configured advisory threshold; packet-size/rate coverage is partial"
        if exceeded is False:
            return "Within the advisory threshold for matching profiles; packet-size/rate coverage is partial"
        if delta == 0:
            return "Matching profiles have equal measured loss; packet-size/rate coverage is partial"
        return "Partial packet-size/rate coverage; this warning alone does not establish a threshold breach"
    return (
        "Above the configured advisory threshold"
        if exceeded is True or (exceeded is None and health == "warning")
        else "Within the configured advisory threshold"
    )


class PerformanceAnalysisMixin:
    """Derived performance metrics shared by directional measurement families."""

    @staticmethod
    def _attach_mss(
        mtu: dict[str, Any],
        tcp_metrics: dict[str, Any],
        family: int,
    ) -> None:
        overhead = 60 if family == 6 else 40
        for key, item in mtu.items():
            tcp = tcp_metrics[key]["streams"]["1"]
            discovered = confirmed_no_fragment_path_mtu(item)
            item["expected_max_mss"] = (
                max(0, int(discovered) - overhead) if discovered is not None else None
            )
            item["mss_constraint_source"] = (
                "confirmed-no-fragment-path-mtu"
                if discovered is not None
                else "path-boundary-unverified"
            )
            item["client_mss"] = int(tcp.get("client_mss") or 0)
            item["server_mss"] = int(tcp.get("server_mss") or 0)

    @staticmethod
    def _latency_metrics(
        idle: dict[str, dict[str, Any]], loaded: dict[str, dict[str, Any]]
    ) -> dict[str, Any]:
        result: dict[str, Any] = {"idle": idle, "loaded": loaded}
        ratios: dict[str, float | None] = {}
        for direction in idle:
            idle_p95 = float(idle[direction].get("p95_ms") or 0.0)
            loaded_p95 = float(loaded[direction].get("p95_ms") or 0.0)
            ratios[direction] = loaded_p95 / idle_p95 if idle_p95 > 0.0 else None
        result["loaded_p95_ratio"] = ratios
        return result

    def _asymmetry(
        self,
        forward_tcp: dict[str, Any],
        reverse_tcp: dict[str, Any],
        latency: dict[str, dict[str, Any]],
        udp: dict[str, Any],
    ) -> dict[str, Any]:
        forward_mbps = float(forward_tcp["streams"]["1"]["median_mbps"])
        reverse_mbps = float(reverse_tcp["streams"]["1"]["median_mbps"])
        throughput_pct = _percent_difference(forward_mbps, reverse_mbps)
        forward_latency = float(latency["forward"].get("p95_ms") or 0.0)
        reverse_latency = float(latency["reverse"].get("p95_ms") or 0.0)
        latency_pct = _percent_difference(forward_latency, reverse_latency)

        comparison = udp.get("comparison")
        comparable = comparison if isinstance(comparison, dict) else udp

        def profiles(direction: str) -> dict[tuple[Any, Any], float]:
            grouped: dict[tuple[Any, Any], float] = {}
            for item in comparable.get(direction) or []:
                if not udp_sample_assessable(item) or (
                    comparison is not None and not item.get("comparison_selected")
                ):
                    continue
                key = (
                    item.get("packet_size"),
                    item.get("requested_mbps", item.get("offered_mbps")),
                )
                grouped[key] = max(
                    grouped.get(key, 0.0), float(item.get("loss_pct") or 0.0)
                )
            return grouped

        forward, reverse = profiles("forward"), profiles("reverse")
        matched = forward.keys() & reverse.keys()
        unmatched = (
            int(comparable.get("incomplete_profiles", 0))
            if comparison is not None
            else len(forward.keys() ^ reverse.keys())
        )
        size_rejected = (
            int(comparable.get("packet_size_rejected_profiles", 0))
            if comparison is not None
            else 0
        )
        unexplained_unmatched = max(0, unmatched - size_rejected)
        forward_loss = max((forward[key] for key in matched), default=None)
        reverse_loss = max((reverse[key] for key in matched), default=None)
        udp_loss_delta = max(
            (abs(forward[key] - reverse[key]) for key in matched), default=None
        )
        worst = max(throughput_pct, latency_pct)
        health = (
            "warning"
            if worst > self.config.performance_asymmetry_threshold_pct
            or (
                udp_loss_delta is not None
                and udp_loss_delta > self.config.performance_udp_loss_threshold_pct
            )
            else "unverified"
            if udp_loss_delta is None or unexplained_unmatched
            else "warning"
            if size_rejected
            else "good"
        )
        return {
            "forward_tcp_mbps": forward_mbps,
            "reverse_tcp_mbps": reverse_mbps,
            "throughput_difference_pct": throughput_pct,
            "forward_idle_p95_ms": forward_latency,
            "reverse_idle_p95_ms": reverse_latency,
            "latency_difference_pct": latency_pct,
            "forward_worst_udp_loss_pct": forward_loss,
            "reverse_worst_udp_loss_pct": reverse_loss,
            "udp_loss_difference_pct_points": udp_loss_delta,
            "udp_loss_advisory_threshold_pct_points": self.config.performance_udp_loss_threshold_pct,
            "udp_compared_profiles": len(matched),
            "udp_unmatched_profiles": unmatched,
            "udp_packet_size_rejected_profiles": size_rejected,
            "udp_comparison_scope": (
                "partial-eligible-matched-packet-size-and-rate"
                if size_rejected
                else "eligible-matched-packet-size-and-rate"
            ),
            "tcp_health": "warning"
            if throughput_pct > self.config.performance_asymmetry_threshold_pct
            else "good",
            "latency_health": "warning"
            if latency_pct > self.config.performance_asymmetry_threshold_pct
            else "good",
            "udp_health": "unverified"
            if udp_loss_delta is None or unexplained_unmatched
            else "warning"
            if size_rejected
            or udp_loss_delta > self.config.performance_udp_loss_threshold_pct
            else "good",
            "health": health,
        }

    @staticmethod
    def _concurrency(tcp_metrics: dict[str, Any]) -> dict[str, Any]:
        directions: dict[str, Any] = {}
        health = "good"
        for direction in ("forward", "reverse"):
            data = tcp_metrics.get(direction)
            if not isinstance(data, dict):
                continue
            streams = data["streams"]
            values = {
                key: float(value["median_mbps"]) for key, value in streams.items()
            }
            single = values.get("1", 0.0)
            maximum = max(values.values(), default=0.0)
            fairness: dict[str, float] = {}
            for key, value in streams.items():
                run = value["runs"][0]
                stream_values = [float(item) for item in run.get("stream_mbps", [])]
                fairness[key] = _jain_fairness(stream_values)
                if fairness[key] < 0.75:
                    health = "warning"
            directions[direction] = {
                "aggregate_mbps_by_stream_count": values,
                "best_aggregate_mbps": maximum,
                "gain_over_single_pct": (
                    ((maximum - single) / single) * 100.0 if single > 0 else 0.0
                ),
                "fairness": fairness,
            }
        return {**directions, "health": health}

    def _repeatability(self, tcp_metrics: dict[str, Any]) -> dict[str, Any]:
        variations = {
            direction: float(data["streams"]["1"]["variation_pct"])
            for direction in ("forward", "reverse")
            if isinstance((data := tcp_metrics.get(direction)), dict)
        }
        worst = max(variations.values(), default=0.0)
        return {
            **{
                f"{direction}_variation_pct": value
                for direction, value in variations.items()
            },
            "worst_variation_pct": worst,
            "threshold_pct": self.config.performance_variation_threshold_pct,
            "health": (
                "warning"
                if worst > self.config.performance_variation_threshold_pct
                else "good"
            ),
        }
