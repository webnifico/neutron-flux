from __future__ import annotations

import ast
import dataclasses
import json
import os
import shlex
import subprocess
import time
from typing import TYPE_CHECKING, Any

from .errors import (
    DependentMeasurementUnavailable,
    MeasurementExecutionError,
    PathReachabilityError,
    RunCancelledError,
    SSHExecutionError,
    SuiteError,
)
from .execution_diagnostics import capture_execution_diagnostics
from .models import Endpoint, ProbeResult, TestSpec
from .mtu_contract import (
    confirmed_no_fragment_path_mtu,
    local_mtu_constraint,
    route_mtu_from_evidence,
)
from .performance_metrics import _last_line, udp_sample_assessable, udp_statistics_error
from .result_context import recorded_execution_stage
from .result_contract import performance_expectation, performance_observation
from .utils import iso_utc

if TYPE_CHECKING:
    from .performance import PerformancePath, ResolvedPerformancePath


def qualification_details(metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in metadata.items()
        if key.startswith(("host_qualification", "pair_"))
        or key in {"requested_source_host", "requested_destination_host"}
    }


def performance_spec_metadata(
    source_metadata: dict[str, dict[str, Any]],
    path: PerformancePath,
    measurement: str,
    stage: str,
) -> dict[str, Any]:
    binding = source_metadata.get(path.source_spec_id, {}).get("check_bindings", {})
    identity = binding.get("performance", {}).get(stage, {}).get(measurement)
    return {
        **({"planned_check_id": identity} if identity else {}),
        **qualification_details(source_metadata.get(path.source_spec_id, {})),
        "performance_path_id": path.path_id,
        "performance_measurement": measurement,
        "source_spec_id": path.source_spec_id,
        "source_category": path.category,
        "stage": stage,
        "execution_stage": recorded_execution_stage(
            source_metadata.get(path.source_spec_id, {})
        ),
        "directions": list(path.directions),
    }


def _finite_number(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number == number and abs(number) != float("inf") else None


def _format_number(value: Any, *, digits: int = 1) -> str | None:
    number = _finite_number(value)
    return f"{number:.{digits}f}" if number is not None else None


def _udp_sample_context(direction: str, row: dict[str, Any]) -> str:
    requested = _finite_number(
        row.get("requested_mbps")
        if row.get("requested_mbps") is not None
        else row.get("offered_mbps")
    )
    packet_size = row.get("packet_size")
    pair_index = row.get("pair_index")
    parts = [direction]
    if requested is not None:
        parts.append(f"{requested:g} Mbit/s requested")
    if packet_size is not None:
        parts.append(f"{int(packet_size)}-byte datagrams")
    if pair_index is not None:
        parts.append(f"pair {pair_index}")
    return ", ".join(parts)


def _fragmentation_summary(fragmentation: dict[str, Any]) -> str:
    capability = str(fragmentation.get("capability") or "")
    if capability == "not-supported":
        return (
            "source fragmentation observed; successful destination reassembly and "
            "delivery unconfirmed"
        )
    if capability == "not-required":
        return "not required at the tested packet size"
    if capability == "unverified":
        return "capability unverified"
    label = fragmentation.get("fragmentation_location_label") or fragmentation.get(
        "fragmentation_location"
    )
    if label:
        return str(label).replace("-", " ")
    if capability == "supported":
        return "succeeded; location unverified"
    return "location unverified"


def _performance_result_summary(measurement: str, metrics: dict[str, Any]) -> str:
    if measurement == "tcp-throughput":
        parts: list[str] = []
        for direction in ("forward", "reverse"):
            item = metrics.get(direction)
            if not isinstance(item, dict):
                continue
            single = (item.get("streams") or {}).get("1") or {}
            median = _format_number(single.get("median_mbps"))
            if median is not None:
                parts.append(f"{direction} single-stream median {median} Mbps")
        bidirectional = _format_number(
            (metrics.get("bidirectional") or {}).get("aggregate_mbps")
        )
        if bidirectional is not None:
            parts.append(f"bidirectional aggregate {bidirectional} Mbps")
        return "; ".join(parts) or "TCP throughput evidence was recorded"

    if measurement == "latency":
        parts = []
        for direction in ("forward", "reverse"):
            idle = _format_number(
                ((metrics.get("idle") or {}).get(direction) or {}).get("p95_ms"),
                digits=2,
            )
            loaded = _format_number(
                ((metrics.get("loaded") or {}).get(direction) or {}).get("p95_ms"),
                digits=2,
            )
            ratio = _format_number(
                (metrics.get("loaded_p95_ratio") or {}).get(direction), digits=2
            )
            if idle is not None or loaded is not None:
                item = f"{direction} p95 idle {idle or 'unavailable'} ms, loaded {loaded or 'unavailable'} ms"
                if ratio is not None:
                    item += f", loaded/idle {ratio}x"
                parts.append(item)
        return "; ".join(parts) or "Latency evidence was recorded"

    if measurement == "udp":
        parts = []
        endpoint_limited_count = 0
        comparison = metrics.get("comparison") or {}
        packet_size_rejected_count = sum(
            row.get("packet_size_supported") is False
            for direction in ("forward", "reverse")
            for row in comparison.get(direction) or []
            if isinstance(row, dict)
        )
        for direction in ("forward", "reverse"):
            rows = [
                row for row in metrics.get(direction) or [] if isinstance(row, dict)
            ]
            endpoint_limited_count += sum(
                1
                for row in rows
                if row.get("packet_size_supported") is not False
                and (
                    row.get("endpoint_limited") is True
                    or row.get("load_valid") is False
                )
            )
            packet_size_rejected_count += sum(
                row.get("packet_size_supported") is False for row in rows
            )
            assessable = [row for row in rows if udp_sample_assessable(row)]
            if not assessable:
                if rows:
                    parts.append(
                        f"{direction} has no eligible UDP samples; network loss not graded"
                    )
                continue
            loss_row = max(
                assessable, key=lambda row: float(row.get("loss_pct") or 0.0)
            )
            jitter_row = max(
                assessable, key=lambda row: float(row.get("jitter_ms") or 0.0)
            )
            goodput_row = max(
                assessable,
                key=lambda row: float(
                    row.get("receiver_goodput_mbps")
                    if row.get("receiver_goodput_mbps") is not None
                    else row.get("achieved_mbps")
                    if row.get("achieved_mbps") is not None
                    else row.get("mbps") or 0.0
                ),
            )
            pps_row = max(assessable, key=lambda row: float(row.get("pps") or 0.0))
            direction_parts = [
                f"application loss {float(loss_row.get('loss_pct') or 0.0):.2f}% "
                f"({_udp_sample_context(direction, loss_row)})",
                f"jitter {float(jitter_row.get('jitter_ms') or 0.0):.3f} ms "
                f"({_udp_sample_context(direction, jitter_row)})",
                f"receiver goodput {float(goodput_row.get('receiver_goodput_mbps') if goodput_row.get('receiver_goodput_mbps') is not None else goodput_row.get('achieved_mbps') if goodput_row.get('achieved_mbps') is not None else goodput_row.get('mbps') or 0.0):.1f} Mbit/s "
                f"({_udp_sample_context(direction, goodput_row)})",
                f"application receive rate {float(pps_row.get('pps') or 0.0):.0f} packets/s "
                f"({_udp_sample_context(direction, pps_row)})",
            ]
            sender_rows = [
                row
                for row in rows
                if row.get("packet_size_supported") is not False
                and _finite_number(row.get("sender_achievement_pct")) is not None
            ]
            if sender_rows:
                limited = min(
                    sender_rows,
                    key=lambda row: float(row.get("sender_achievement_pct") or 0.0),
                )
                direction_parts.append(
                    f"minimum sender achievement "
                    f"{float(limited.get('sender_achievement_pct') or 0.0):.1f}% "
                    f"({_udp_sample_context(direction, limited)})"
                )
            parts.append("; ".join(direction_parts))
        if endpoint_limited_count:
            parts.append(
                f"{endpoint_limited_count} calibration sample(s) labelled "
                "endpoint-limited and excluded from network-loss grading"
            )
        if packet_size_rejected_count:
            parts.append(
                f"{packet_size_rejected_count} requested UDP profile(s) rejected by "
                "a local packet-size constraint; excluded from throughput and "
                "network-loss grading"
            )
        return "; ".join(parts) or "UDP evidence was unavailable"

    if measurement == "mtu-mss":
        parts = []
        advertised = metrics.get("expected_mtu")
        if advertised is not None:
            parts.append(f"advertised path MTU {advertised} bytes")
        for direction in ("forward", "reverse"):
            item = metrics.get(direction)
            if not isinstance(item, dict):
                continue
            fragmentation = item.get("fragmentation") or {}
            path_mtu = confirmed_no_fragment_path_mtu(item)
            local_mtu, local_class = local_mtu_constraint(item)
            if path_mtu is not None:
                boundary_text = (
                    f"{direction} confirmed no-fragment path MTU {path_mtu} bytes"
                )
            elif local_class == "cached-route-pmtu":
                boundary_text = (
                    f"{direction} cached route PMTU "
                    f"{local_mtu if local_mtu is not None else 'unavailable'} bytes; "
                    "current path boundary unverified"
                )
            elif local_class == "interface-mtu-constraint":
                boundary_text = (
                    f"{direction} source-interface MTU constraint "
                    f"{local_mtu if local_mtu is not None else 'unavailable'} bytes; "
                    "current path boundary unverified"
                )
            elif local_class:
                boundary_text = (
                    f"{direction} local MTU constraint "
                    f"{local_mtu if local_mtu is not None else 'unavailable'} bytes; "
                    "current path boundary unverified"
                )
            else:
                boundary_text = f"{direction} no-fragment path MTU unverified"
            fragments = [
                boundary_text,
                f"PMTUD {str(item.get('pmtud_status') or 'unverified').replace('-', ' ')}",
                f"fragmentation {_fragmentation_summary(fragmentation)}",
                f"TCP MSS client/server {item.get('client_mss', 'unavailable')}/{item.get('server_mss', 'unavailable')}",
            ]
            parts.append(", ".join(fragments))
        return "; ".join(parts) or "Packet-size path evidence was recorded"

    if measurement == "asymmetry":
        throughput = _format_number(metrics.get("throughput_difference_pct"), digits=2)
        latency = _format_number(metrics.get("latency_difference_pct"), digits=2)
        udp = _format_number(metrics.get("udp_loss_difference_pct_points"), digits=2)
        return (
            f"directional difference: throughput {throughput or 'unavailable'}%, "
            f"latency {latency or 'unavailable'}%, UDP application-delivery loss "
            f"{udp or 'unavailable'} percentage points"
        )

    if measurement == "concurrency":
        parts = []
        for direction in ("forward", "reverse"):
            item = metrics.get(direction)
            if not isinstance(item, dict):
                continue
            best = _format_number(item.get("best_aggregate_mbps"))
            fairness_values = [
                float(value)
                for value in (item.get("fairness") or {}).values()
                if _finite_number(value) is not None
            ]
            minimum_fairness = min(fairness_values) if fairness_values else None
            text = f"{direction} best aggregate {best or 'unavailable'} Mbps"
            if minimum_fairness is not None:
                text += f", minimum fairness {minimum_fairness:.3f}"
            parts.append(text)
        return "; ".join(parts) or "Concurrent-flow evidence was recorded"

    if measurement == "repeatability":
        worst = _format_number(metrics.get("worst_variation_pct"), digits=2)
        forward = _format_number(metrics.get("forward_variation_pct"), digits=2)
        reverse = _format_number(metrics.get("reverse_variation_pct"), digits=2)
        details = []
        if forward is not None:
            details.append(f"forward {forward}%")
        if reverse is not None:
            details.append(f"reverse {reverse}%")
        suffix = f" ({', '.join(details)})" if details else ""
        return f"worst repeated-run variation {worst or 'unavailable'}%{suffix}"

    return "Network measurement evidence was recorded"


class PerformanceResultMixin:
    """Health assessment, result recording, and command result handling."""

    @staticmethod
    def _tcp_health(metrics: dict[str, Any]) -> str:
        directional = [
            metrics[direction]
            for direction in ("forward", "reverse")
            if isinstance(metrics.get(direction), dict)
        ]
        if not directional:
            return "unverified"
        for item in directional:
            if float(item["streams"]["1"]["median_mbps"]) <= 0.0:
                return "critical"
        return "good"

    def _latency_health(self, metrics: dict[str, Any]) -> str:
        losses = [
            float(
                ((metrics.get(mode) or {}).get(direction) or {}).get("loss_pct") or 0.0
            )
            for mode in ("idle", "loaded")
            for direction in ("forward", "reverse")
        ]
        if losses and max(losses) >= 100.0:
            return "critical"
        ratios = [
            float(value)
            for value in metrics["loaded_p95_ratio"].values()
            if value is not None
        ]
        if any(value > 0.0 for value in losses) or (
            ratios
            and max(ratios) > self.config.performance_loaded_latency_ratio_threshold
        ):
            return "warning"
        return "good"

    @staticmethod
    def _udp_sample_rows(
        metrics: dict[str, Any],
    ) -> list[tuple[str, dict[str, Any]]]:
        return [
            (direction, item)
            for direction in ("forward", "reverse")
            for item in list(metrics.get(direction) or [])
            if isinstance(item, dict)
        ]

    @classmethod
    def _udp_assessable_rows(
        cls, metrics: dict[str, Any]
    ) -> list[tuple[str, dict[str, Any]]]:
        rows = cls._udp_sample_rows(metrics)
        return [row for row in rows if udp_sample_assessable(row[1])]

    @classmethod
    def _udp_packet_size_rows(
        cls, metrics: dict[str, Any]
    ) -> list[tuple[str, dict[str, Any]]]:
        rows = cls._udp_sample_rows(metrics)
        comparison = metrics.get("comparison")
        if isinstance(comparison, dict):
            rows.extend(cls._udp_sample_rows(comparison))
        return [row for row in rows if row[1].get("packet_size_supported") is False]

    @staticmethod
    def _udp_reordering_pct(item: dict[str, Any]) -> float:
        explicit = item.get("out_of_order_pct")
        if explicit is not None:
            return float(explicit)
        received = int(item.get("received") or 0)
        reordered = int(item.get("out_of_order") or 0)
        return (reordered * 100.0 / received) if received else 0.0

    def _udp_health(self, metrics: dict[str, Any]) -> str:
        rows = self._udp_sample_rows(metrics)
        if not rows:
            return "unverified"
        if any(
            item.get("packet_size_supported") is not False
            and item.get("calibration_selected", True) is True
            and (
                "loss_pct" not in item
                or udp_statistics_error(
                    item,
                    require_complete="control_statistics_available" in item,
                )
                is not None
            )
            for _, item in rows
        ):
            return "unverified"
        unresolved_endpoint_limits = any(
            item.get("endpoint_limited") is True
            and item.get("calibration_selected") is True
            for _, item in rows
        )
        legacy_unsustainable_rows = any(
            item.get("endpoint_limited") is None and item.get("load_valid") is False
            for _, item in rows
        )
        assessable_rows = self._udp_assessable_rows(metrics)
        if (
            not assessable_rows
            or unresolved_endpoint_limits
            or legacy_unsustainable_rows
        ):
            return "unverified"
        samples = [item for _, item in assessable_rows]
        losses = [float(item.get("loss_pct") or 0.0) for item in samples]
        if losses and max(losses) >= 100.0:
            return "critical"
        if any(
            bool(metrics.get(direction))
            and not any(
                row_direction == direction for row_direction, _ in assessable_rows
            )
            for direction in ("forward", "reverse")
        ):
            return "unverified"
        worst_reordering = max(
            (self._udp_reordering_pct(item) for item in samples), default=0.0
        )
        if (
            (losses and max(losses) > self.config.performance_udp_loss_threshold_pct)
            or any(int(item.get("duplicates") or 0) > 0 for item in samples)
            or worst_reordering > self.config.performance_udp_reordering_threshold_pct
            or bool(self._udp_packet_size_rows(metrics))
        ):
            return "warning"
        return "good"

    @staticmethod
    def _mtu_health(metrics: dict[str, Any], expected_mtu: int) -> str:
        warning = False
        unverified = not bool(metrics.get("contract_authoritative", True))
        critical = False
        contract_authoritative = bool(metrics.get("contract_authoritative", True))
        directional = [
            metrics[direction]
            for direction in ("forward", "reverse")
            if isinstance(metrics.get(direction), dict)
        ]
        if not directional:
            return "unverified"
        for item in directional:
            if item.get("route_pmtu_cache_reset_verified") is False:
                unverified = True
            discovered = item.get("discovered_mtu")
            confidence = str(item.get("discovery_confidence") or "legacy")
            expected_classification = str(
                item.get("expected_probe_classification") or ""
            )
            persistence = item.get("post_migration_persistence") or {}
            persistence_class = str(persistence.get("classification") or "")
            if persistence_class in {"transient-recovered", "local-constraint-cleared"}:
                warning = True
            elif persistence_class == "unstable":
                unverified = True
            if expected_classification == "packet-too-big":
                warning = True
                if confirmed_no_fragment_path_mtu(item) is None:
                    unverified = True
            elif expected_classification == "local-mtu-rejected":
                evidence = item.get("local_mtu_evidence") or {}
                local_class = str(item.get("local_constraint_classification") or "")
                route_mtu = route_mtu_from_evidence(
                    evidence if isinstance(evidence, dict) else {}
                )
                interface_mtu = (
                    _finite_number(evidence.get("source_interface_mtu"))
                    if isinstance(evidence, dict)
                    else None
                )
                if not local_class:
                    if (
                        route_mtu is not None
                        and route_mtu < expected_mtu
                        and (interface_mtu is None or route_mtu < interface_mtu)
                    ):
                        local_class = "cached-route-pmtu"
                    elif interface_mtu is not None and interface_mtu < expected_mtu:
                        local_class = "interface-mtu-constraint"
                    else:
                        local_class = "local-mtu-constraint-unverified"
                if local_class == "interface-mtu-constraint" and contract_authoritative:
                    warning = True
                else:
                    unverified = True
            elif confidence in {
                "unstable",
                "unreachable",
                "unsupported",
                "cached-route-pmtu",
                "local-mtu-constraint-unverified",
            }:
                unverified = True
            elif item.get("reachable") is False or discovered is None:
                unverified = True
            elif (
                confidence == "confirmed-lower-boundary"
                and int(discovered) < expected_mtu
            ):
                if contract_authoritative:
                    warning = True
                else:
                    unverified = True
            elif confidence == "legacy" and int(discovered) < expected_mtu:
                if contract_authoritative:
                    warning = True
                else:
                    unverified = True
            expected_mss = item.get("expected_max_mss")
            observed_mss = [item.get(key) for key in ("client_mss", "server_mss")]
            if expected_mss is not None and any(
                value is not None and int(value) > int(expected_mss)
                for value in observed_mss
            ):
                critical = True
            if any(value is None or int(value) <= 0 for value in observed_mss):
                warning = True
            if item.get("above_expected_reachable"):
                warning = True
            if item.get("probe_mode") == "fragmentation-permitted-fallback":
                if confidence == "legacy":
                    warning = True
                else:
                    unverified = True
            fragmentation = item.get("fragmentation") or {}
            if fragmentation.get("capability") in {
                "unverified",
                "not-supported",
                "path-supports-source-mtu",
            }:
                warning = True
            if (
                fragmentation.get("capability") == "supported"
                and fragmentation.get("fragmentation_location") == "unverified"
            ):
                warning = True
        if critical:
            return "critical"
        if unverified:
            return "unverified"
        return "warning" if warning else "good"

    def _warning_reasons(
        self, measurement: str, metrics: dict[str, Any], health: str
    ) -> list[str]:
        if health == "good" and measurement != "udp":
            return []
        reasons: list[str] = []
        if measurement == "udp":
            rows = self._udp_sample_rows(metrics)
            assessable_rows = self._udp_assessable_rows(metrics)
            samples = [item for _, item in assessable_rows]
            size_constraints = {
                (
                    direction,
                    int(item.get("packet_size") or 0),
                    item.get("kernel_path_mtu"),
                )
                for direction, item in self._udp_packet_size_rows(metrics)
            }
            for direction, size, kernel_mtu in sorted(
                size_constraints, key=lambda item: (item[0], item[1])
            ):
                reasons.append(
                    f"UDP {direction} {size}-byte datagrams were rejected locally "
                    "with Message too long (EMSGSIZE)"
                    + (
                        f"; the socket reported route PMTU {kernel_mtu} bytes"
                        if kernel_mtu is not None
                        else "; the socket did not report a route PMTU"
                    )
                    + "; this requested size was not validated. Smaller payloads "
                    "are separate throughput profiles and do not establish that "
                    "the advertised MTU works"
                )
            if assessable_rows:
                worst_direction, worst_loss_sample = max(
                    assessable_rows,
                    key=lambda row: float(row[1].get("loss_pct") or 0.0),
                    default=("unknown", {}),
                )
                worst_loss = float(worst_loss_sample.get("loss_pct") or 0.0)
                if worst_loss > self.config.performance_udp_loss_threshold_pct:
                    reasons.append(
                        f"worst UDP application-delivery loss {worst_loss:.2f}% at "
                        f"{_udp_sample_context(worst_direction, worst_loss_sample)} "
                        f"exceeds advisory threshold "
                        f"{self.config.performance_udp_loss_threshold_pct:.2f}%"
                    )
                    drop_attribution = str(
                        worst_loss_sample.get("receiver_drop_attribution") or ""
                    )
                    if drop_attribution == (
                        "receiver-kernel-drop-attribution-unavailable"
                    ):
                        reasons.append(
                            "receiver kernel/socket drop attribution was unavailable; "
                            "the reported UDP loss is application-delivery loss, not "
                            "a proven wire-loss measurement"
                        )

            limited_rows = [
                (direction, item)
                for direction, item in rows
                if item.get("packet_size_supported") is not False
                and (
                    item.get("endpoint_limited") is True
                    or (
                        item.get("endpoint_limited") is None
                        and item.get("load_valid") is False
                    )
                )
            ]
            limited_groups: dict[tuple[str, int, int], list[dict[str, Any]]] = {}
            for direction, item in limited_rows:
                key = (
                    direction,
                    int(
                        item.get("configured_rate_mbps")
                        or item.get("requested_mbps")
                        or item.get("offered_mbps")
                        or 0
                    ),
                    int(item.get("packet_size") or 0),
                )
                limited_groups.setdefault(key, []).append(item)
            for (
                direction,
                configured_rate,
                packet_size,
            ), group in limited_groups.items():
                selected_rates = [
                    _finite_number(item.get("calibration_selected_rate_mbps"))
                    for item in group
                ]
                selected_rate = next(
                    (value for value in selected_rates if value is not None), None
                )
                endpoint_reasons = sorted(
                    {
                        str(item.get("endpoint_limit_reason") or "endpoint capacity")
                        for item in group
                    }
                )
                reasons.append(
                    f"UDP {direction} {configured_rate} Mbit/s with "
                    f"{packet_size}-byte datagrams was endpoint-limited "
                    f"({', '.join(endpoint_reasons)})"
                    + (
                        f"; calibrated sustainable rate {selected_rate:g} Mbit/s"
                        if selected_rate is not None
                        else "; no sustainable calibration rate was established"
                    )
                    + "; endpoint-limited samples were excluded from "
                    "network-loss grading"
                )

            duplicates = sum(int(item.get("duplicates") or 0) for item in samples)
            if duplicates:
                reasons.append(f"{duplicates} duplicate UDP packet(s) were observed")
            if assessable_rows:
                worst_direction, worst_sample = max(
                    assessable_rows,
                    key=lambda row: self._udp_reordering_pct(row[1]),
                    default=("unknown", {}),
                )
                worst_reordering = self._udp_reordering_pct(worst_sample)
                if (
                    worst_reordering
                    > self.config.performance_udp_reordering_threshold_pct
                ):
                    reordered = int(worst_sample.get("out_of_order") or 0)
                    received = int(worst_sample.get("received") or 0)
                    rate = int(worst_sample.get("offered_mbps") or 0)
                    packet_size = int(worst_sample.get("packet_size") or 0)
                    reasons.append(
                        f"{worst_direction} UDP at {rate} Mbit/s with "
                        f"{packet_size}-byte packets received {reordered} of "
                        f"{received} unique packets out of order "
                        f"({worst_reordering:.3f}%), above advisory threshold "
                        f"{self.config.performance_udp_reordering_threshold_pct:.3f}%"
                    )
        elif measurement == "latency":
            losses = [
                float(
                    ((metrics.get(mode) or {}).get(direction) or {}).get("loss_pct")
                    or 0.0
                )
                for mode in ("idle", "loaded")
                for direction in ("forward", "reverse")
            ]
            if losses and max(losses) > 0.0:
                reasons.append(
                    f"latency probes observed up to {max(losses):.2f}% packet loss"
                )
            ratios = [
                float(value)
                for value in (metrics.get("loaded_p95_ratio") or {}).values()
                if value is not None
            ]
            if (
                ratios
                and max(ratios) > self.config.performance_loaded_latency_ratio_threshold
            ):
                reasons.append(
                    f"loaded p95 latency increased by {max(ratios):.2f}×, above advisory "
                    f"threshold {self.config.performance_loaded_latency_ratio_threshold:.2f}×"
                )
        elif measurement == "mtu-mss":
            contract_authoritative = bool(metrics.get("contract_authoritative", True))
            if not contract_authoritative:
                reasons.append(
                    "The advertised MTU contract is unverified because at least one "
                    "path constraint came from a diagnostic fallback instead of an "
                    "authoritative Neutron or kernel MTU value"
                )
            for direction in ("forward", "reverse"):
                item = metrics.get(direction)
                if not isinstance(item, dict):
                    continue
                if item.get("route_pmtu_cache_reset_verified") is False:
                    reset = item.get("route_pmtu_cache_reset") or {}
                    reset_error = (
                        reset.get("error")
                        or reset.get("flush_stderr")
                        or "route/PMTU cache state could not be verified clean"
                    )
                    reasons.append(
                        f"{direction} route/PMTU cache reset was not verified: "
                        f"{reset_error}"
                    )
                raw_discovered = item.get("discovered_mtu")
                discovered = int(raw_discovered) if raw_discovered is not None else 0
                expected = int(metrics.get("expected_mtu") or 0)
                confidence = str(item.get("discovery_confidence") or "legacy")
                expected_classification = str(
                    item.get("expected_probe_classification") or ""
                )
                if expected_classification == "packet-too-big":
                    reasons.append(
                        f"{direction} received fresh ICMP Packet Too Big / "
                        f"fragmentation-needed feedback: advertised {expected} bytes, "
                        f"reported MTU {item.get('reported_path_mtu') or 'unknown'} bytes; "
                        + (
                            f"confirmed no-fragment path MTU {discovered} bytes"
                            if confirmed_no_fragment_path_mtu(item) is not None
                            else "the exact no-fragment path MTU remains unverified"
                        )
                    )
                elif expected_classification == "local-mtu-rejected":
                    evidence = item.get("local_mtu_evidence") or {}
                    interface = evidence.get("selected_interface") or "unknown"
                    interface_mtu = evidence.get("source_interface_mtu")
                    route_mtu = route_mtu_from_evidence(
                        evidence if isinstance(evidence, dict) else {}
                    )
                    local_class = str(item.get("local_constraint_classification") or "")
                    if not local_class:
                        if (
                            route_mtu is not None
                            and expected
                            and route_mtu < expected
                            and (
                                interface_mtu is None
                                or int(route_mtu) < int(interface_mtu)
                            )
                        ):
                            local_class = "cached-route-pmtu"
                        elif (
                            interface_mtu is not None
                            and expected
                            and int(interface_mtu) < expected
                        ):
                            local_class = "interface-mtu-constraint"
                        else:
                            local_class = "local-mtu-constraint-unverified"
                    evidence_parts = [f"interface={interface}"]
                    if interface_mtu is not None:
                        evidence_parts.append(f"interface_mtu={interface_mtu}")
                    if route_mtu is not None:
                        evidence_parts.append(f"route_mtu={route_mtu}")
                    if local_class == "cached-route-pmtu":
                        reasons.append(
                            f"{direction} source guest had a cached per-destination "
                            f"route PMTU of {route_mtu or discovered or 'unknown'} bytes "
                            f"({', '.join(evidence_parts)}); packets above it were not "
                            "transmitted, so the current path MTU was not independently "
                            "confirmed"
                        )
                    elif local_class == "interface-mtu-constraint":
                        reasons.append(
                            f"{direction} source interface MTU was below the advertised "
                            f"network MTU ({', '.join(evidence_parts)})"
                        )
                    else:
                        reasons.append(
                            f"{direction} packet was rejected locally before transmission "
                            f"({', '.join(evidence_parts)}); the current path MTU was not "
                            "independently measured"
                        )
                elif confidence in {"unstable", "unreachable", "unsupported"}:
                    reasons.append(
                        f"{direction} MTU was unverified: "
                        f"{item.get('discovery_reason') or confidence}"
                    )
                elif (
                    confidence == "confirmed-lower-boundary"
                    and discovered
                    and expected
                    and discovered < expected
                ):
                    reasons.append(
                        f"{direction} MTU observation: confirmed no-fragment MTU "
                        f"{discovered}, advertised {expected}; the difference is advisory"
                    )
                elif (
                    confidence == "legacy"
                    and discovered
                    and expected
                    and discovered < expected
                ):
                    reasons.append(
                        f"{direction} discovered MTU {discovered} is below expected {expected}"
                    )
                if item.get("above_expected_reachable"):
                    reasons.append(
                        f"{direction} repeatedly accepted a packet above the expected MTU boundary"
                    )
                if item.get("probe_mode") == "fragmentation-permitted-fallback":
                    reasons.append(
                        f"{direction} could not verify DF/PMTUD because ping required a fragmentation-permitted fallback"
                    )
                fragmentation = item.get("fragmentation") or {}
                capability = str(fragmentation.get("capability") or "")
                if capability == "unverified":
                    reasons.append(
                        f"{direction} fragmentation capability was unverified: "
                        f"{fragmentation.get('reason') or 'no stable evidence'}"
                    )
                elif capability == "path-supports-source-mtu":
                    reasons.append(
                        f"{direction} accepted the source-network MTU with fragmentation disabled; "
                        "the routed path appears wider than the earlier path-MTU expectation"
                    )
                elif capability == "not-supported":
                    reasons.append(
                        f"{direction} source fragmented the tested packet, but "
                        "successful destination reassembly and delivery were not "
                        "observed; this does not establish that fragmentation is "
                        "unsupported for every packet size"
                    )
                elif (
                    capability == "supported"
                    and fragmentation.get("fragmentation_location") == "unverified"
                ):
                    reasons.append(
                        f"{direction} fragmentation succeeded, but its location was "
                        "not safely attributable from source and destination counters"
                    )
                persistence = item.get("post_migration_persistence") or {}
                persistence_class = str(persistence.get("classification") or "")
                if persistence_class == "transient-recovered":
                    reasons.append(
                        f"{direction} post-migration MTU reduction was transient and "
                        "returned to the advertised boundary during convergence"
                    )
                elif persistence_class == "local-constraint-cleared":
                    reasons.append(
                        f"{direction} immediate post-migration local MTU/PMTU "
                        "constraint cleared, after which consecutive samples "
                        "confirmed the advertised path MTU"
                    )
                elif persistence_class == "persistent-lower-boundary":
                    samples = (
                        persistence.get("samples")
                        or persistence.get("observations")
                        or []
                    )
                    count = (
                        len(samples)
                        if isinstance(samples, list)
                        else persistence.get("sample_count")
                    )
                    reasons.append(
                        f"{direction} lower no-fragment path MTU was reproduced in "
                        f"{count or 'multiple'} consecutive settlement samples"
                    )
                elif persistence_class == "persistent-cached-route-pmtu":
                    reasons.append(
                        f"{direction} repeated settlement samples retained the same "
                        "cached per-destination route PMTU; packets above it were "
                        "not transmitted, so the current end-to-end path MTU "
                        "remained unverified"
                    )
                elif persistence_class == "persistent-interface-mtu-constraint":
                    reasons.append(
                        f"{direction} repeated settlement samples retained the same "
                        "source-interface MTU constraint; the interface remained "
                        "below the advertised network MTU"
                    )
                elif persistence_class == "persistent-local-mtu-constraint-unverified":
                    reasons.append(
                        f"{direction} repeated settlement samples retained the same "
                        "local MTU constraint, but its source and the current "
                        "end-to-end path boundary remained unverified"
                    )
                elif persistence_class == "unstable":
                    reasons.append(
                        f"{direction} post-migration MTU did not converge to a stable "
                        "boundary within the bounded settlement window"
                    )
                if any(
                    item.get(key) is None or int(item.get(key) or 0) <= 0
                    for key in ("client_mss", "server_mss")
                ):
                    reasons.append(f"{direction} TCP MSS evidence was incomplete")
        elif measurement == "asymmetry":
            throughput = float(metrics.get("throughput_difference_pct") or 0.0)
            latency = float(metrics.get("latency_difference_pct") or 0.0)
            udp = float(metrics.get("udp_loss_difference_pct_points") or 0.0)
            if metrics.get("udp_loss_difference_pct_points") is None:
                reasons.append(
                    "UDP directional comparison is unverified: no matching "
                    "eligible packet-size/rate samples were available"
                )
            elif metrics.get("udp_unmatched_profiles"):
                reasons.append(
                    "UDP directional comparison covers only matching eligible "
                    "packet-size/rate samples; other profiles remain unverified"
                )
            if throughput > self.config.performance_asymmetry_threshold_pct:
                reasons.append(
                    f"throughput differs by {throughput:.2f}%, above advisory threshold "
                    f"{self.config.performance_asymmetry_threshold_pct:.2f}%"
                )
            if latency > self.config.performance_asymmetry_threshold_pct:
                reasons.append(
                    f"latency differs by {latency:.2f}%, above advisory threshold "
                    f"{self.config.performance_asymmetry_threshold_pct:.2f}%"
                )
            if udp > self.config.performance_udp_loss_threshold_pct:
                reasons.append(
                    f"directional UDP application-delivery loss differs by "
                    f"{udp:.2f} percentage points"
                )
        elif measurement == "concurrency":
            fairness_values = [
                float(value)
                for direction in ("forward", "reverse")
                for value in (
                    (metrics.get(direction) or {}).get("fairness") or {}
                ).values()
            ]
            if fairness_values and min(fairness_values) < 0.75:
                reasons.append(
                    f"minimum concurrent-flow fairness was {min(fairness_values):.3f}, below 0.750"
                )
        elif measurement == "repeatability":
            worst = float(metrics.get("worst_variation_pct") or 0.0)
            if worst > self.config.performance_variation_threshold_pct:
                reasons.append(
                    f"throughput variation was {worst:.2f}%, above advisory threshold "
                    f"{self.config.performance_variation_threshold_pct:.2f}%"
                )
        if not reasons and health in {"warning", "critical"}:
            reasons.append(f"measurement health was assessed as {health}")
        return list(dict.fromkeys(reasons))

    def _record_measurement(
        self,
        spec: TestSpec,
        path: ResolvedPerformancePath,
        payload: dict[str, Any],
        *,
        started: float,
    ) -> None:
        health = str(payload["health"])
        status = "PASS"
        if health == "unverified":
            status = "UNVERIFIED"
        elif health == "critical" or (
            health == "warning" and self.config.performance_enforce_thresholds
        ):
            status = "FAIL"
        measurement = str(spec.metadata["performance_measurement"])
        warning_reasons = self._warning_reasons(measurement, payload["metrics"], health)
        metric_summary = _performance_result_summary(measurement, payload["metrics"])
        message = f"{metric_summary}; assessment={health}" + (
            f"; {'; '.join(warning_reasons)}" if warning_reasons else ""
        )
        timing = getattr(self, "_measurement_timings", {}).get(measurement, {})
        execution_windows = (
            [timing]
            if timing
            else list(getattr(self, "_measurement_timings", {}).values())
        )
        commands = [
            dict(item)
            for item in getattr(self, "_performance_executions", [])
            if any(
                str(window.get("started_at") or "")
                <= item["started_at"]
                <= str(window.get("finished_at") or "")
                for window in execution_windows
            )
        ]
        self.reporter.result(
            spec.id,
            spec.category,
            status,
            message,
            family=path.plan.family,
            source=f"{path.source.label} ({path.source_ip})",
            destination=f"{path.destination.label} ({path.destination_ip})",
            started=started,
            started_at=timing.get("started_at"),
            duration_ms=timing.get("duration_ms"),
            details={
                **qualification_details(spec.metadata),
                "execution_stage": spec.metadata.get("execution_stage"),
                "command_evidence": commands,
                "performance": True,
                "measurement": measurement,
                "timing": timing,
                "mtu_advisory": measurement == "mtu-mss" and health == "warning",
                "health": health,
                "warning_reasons": warning_reasons,
                "metrics": payload["metrics"],
                "path": self._path_details(path),
                "address_path": self._performance_address_evidence(spec, path),
                "thresholds_enforced": self.config.performance_enforce_thresholds,
            },
            expected=spec.expectation,
            observed=performance_observation(
                measurement,
                status=status,
                health=health,
                verdict_basis=(
                    "operator-threshold-policy"
                    if status == "FAIL" and health == "warning"
                    else "network-path-functional-contract"
                ),
            ),
            authoritative=status != "UNVERIFIED",
            display_name=spec.display_name,
            scenario=spec.scenario,
        )

    def _record_measurement_error(
        self,
        spec: TestSpec,
        path: ResolvedPerformancePath,
        exc: BaseException,
        *,
        started: float,
    ) -> None:
        message = str(exc).strip() or type(exc).__name__
        dependency = isinstance(exc, DependentMeasurementUnavailable)
        path_failure = isinstance(exc, PathReachabilityError)
        dependent_on_path_failure = dependency and (
            "path was unreachable" in message.lower()
            or "path was unreachable" in str(exc).lower()
        )
        status = "UNVERIFIED" if dependency else "FAIL" if path_failure else "ERROR"
        incident_kind = (
            "unreachable" if path_failure or dependent_on_path_failure else "execution"
        )
        incident_id = f"performance-path:{path.plan.path_id}:{incident_kind}"
        incident_id = getattr(exc, "root_incident_id", incident_id)
        timing = getattr(self, "_measurement_timings", {}).get(
            str(spec.metadata.get("performance_measurement")), {}
        )
        diagnostic_details = {}
        if not dependency:
            try:
                diagnostic_details = capture_execution_diagnostics(
                    self.builder,
                    self.reporter,
                    spec.id,
                    (path.source, path.destination),
                    exc,
                )
            except RunCancelledError:
                raise
            except (
                RuntimeError,
                OSError,
                ValueError,
                TypeError,
                AttributeError,
            ) as diagnostic_error:
                diagnostic_details = {
                    "diagnostic_collection_error": str(diagnostic_error)
                }
        self.reporter.result(
            spec.id,
            spec.category,
            status,
            (
                f"Performance measurement was not calculated: {message}"
                if dependency
                else (
                    f"The network path was unreachable: {message}"
                    if path_failure
                    else f"Could not complete this performance measurement: {message}"
                )
            ),
            family=path.plan.family,
            source=f"{path.source.label} ({path.source_ip})",
            destination=f"{path.destination.label} ({path.destination_ip})",
            started=started,
            started_at=timing.get("started_at"),
            duration_ms=timing.get("duration_ms", 0 if dependency else None),
            details={
                **qualification_details(spec.metadata),
                "execution_stage": spec.metadata.get("execution_stage"),
                **diagnostic_details,
                "execution_error": getattr(exc, "evidence", {}),
                "udp_incomplete_profile": getattr(self, "_udp_active_profile", {})
                if spec.metadata.get("performance_measurement") == "udp"
                else {},
                "partial_udp_samples": getattr(self, "_partial_udp_samples", {}),
                "timing": timing,
                "performance": True,
                "measurement": spec.metadata.get("performance_measurement"),
                "health": "unverified" if dependency else "critical",
                "dependency_unavailable": dependency,
                "root_path_failure": path_failure,
                "address_path": self._performance_address_evidence(spec, path),
                "dependent_on_path_failure": dependent_on_path_failure,
                "root_incident_id": incident_id,
                "dependent_on_incident_id": incident_id if dependency else None,
                "failure_class": (
                    "network-path-unreachable"
                    if path_failure
                    else "dependent-measurement"
                    if dependency
                    else "flux-execution-error"
                ),
                "path": self._path_details(path),
            },
            expected=performance_expectation(
                spec.metadata.get("performance_measurement")
            ),
            observed=performance_observation(
                spec.metadata.get("performance_measurement"),
                status=status,
            ),
            authoritative=path_failure,
            display_name=spec.display_name,
            scenario=spec.scenario,
        )

    def _record_path_error(
        self,
        specs: list[TestSpec],
        path: PerformancePath,
        exc: BaseException,
        started: float,
    ) -> None:
        message = str(exc).strip() or type(exc).__name__
        incident_id = f"performance-path:{path.path_id}:resolution"
        for index, spec in enumerate(specs):
            root = index == 0
            self.reporter.result(
                spec.id,
                spec.category,
                "ERROR" if root else "UNVERIFIED",
                (
                    f"Could not resolve the performance path: {message}"
                    if root
                    else f"Measurement was not run because path resolution failed: {message}"
                ),
                family=path.family,
                started=started,
                details={
                    **qualification_details(spec.metadata),
                    "execution_stage": spec.metadata.get("execution_stage"),
                    "performance": True,
                    "measurement": spec.metadata.get("performance_measurement"),
                    "health": "critical" if root else "unverified",
                    "root_path_error": root,
                    "root_incident_id": incident_id,
                    "dependent_on_incident_id": None if root else incident_id,
                    "failure_class": (
                        "flux-execution-error" if root else "dependent-measurement"
                    ),
                    "path": dataclasses.asdict(path),
                },
                expected=performance_expectation(
                    spec.metadata.get("performance_measurement")
                ),
                observed=performance_observation(
                    spec.metadata.get("performance_measurement"),
                    status="ERROR" if root else "UNVERIFIED",
                ),
                authoritative=root,
                display_name=spec.display_name,
                scenario=spec.scenario,
            )

    def _performance_address_evidence(
        self, spec: TestSpec, path: ResolvedPerformancePath
    ) -> dict[str, Any]:
        recorder = getattr(getattr(self, "engine", None), "_address_evidence", None)
        if not callable(recorder):
            return {}
        return recorder(
            spec,
            ProbeResult(
                "reachable",
                True,
                0,
                0,
                source_ip=path.source_ip,
                destination_ip=path.destination_ip,
            ),
            path.source,
            path.destination,
        )

    @staticmethod
    def _path_details(path: ResolvedPerformancePath) -> dict[str, Any]:
        return {
            "path_id": path.plan.path_id,
            "source_spec_id": path.plan.source_spec_id,
            "source_category": path.plan.category,
            "stage": path.plan.stage,
            "execution_scope": path.plan.execution_scope,
            "path_kind": path.plan.path_kind,
            "lifecycle_key": path.plan.lifecycle_key,
            "directions": list(path.plan.directions),
            "family": path.plan.family,
            "source_group_id": path.plan.source_group_id,
            "destination_group_id": path.plan.destination_group_id,
            "source_label": path.source.label,
            "destination_label": path.destination.label,
            "source_server_id": path.source.server_id,
            "destination_server_id": path.destination.server_id,
            "source_server_name": path.source.server_name,
            "destination_server_name": path.destination.server_name,
            "source_test_mac": path.source.test_mac,
            "destination_test_mac": path.destination.test_mac,
            "source_ip": path.source_ip,
            "destination_ip": path.destination_ip,
            "destination_bind_ip": path.destination_bind_ip,
            "reverse_source_ip": path.reverse_source_ip,
            "reverse_destination_ip": path.reverse_destination_ip,
            "reverse_expected_peer_ip": path.reverse_expected_peer_ip,
            "source_compute_host": path.source.host,
            "destination_compute_host": path.destination.host,
            "source_availability_zone": path.source.availability_zone,
            "destination_availability_zone": path.destination.availability_zone,
            "placement": path.placement,
            "availability_scope": path.availability_scope,
            "expected_mtu": path.expected_mtu,
            "mtu_contract": path.mtu_contract,
            "source_mtu_evidence": path.source_mtu_evidence,
            "destination_mtu_evidence": path.destination_mtu_evidence,
            "additional_mtu_evidence": list(path.additional_mtu_evidence),
            "router_ids": list(path.router_ids),
            "router_backend_evidence": path.router_backend_evidence,
        }

    @staticmethod
    def _retryable_performance_command_error(exc: BaseException) -> bool:
        text = str(exc).lower()
        return any(
            marker in text
            for marker in (
                "no route to host",
                "network is unreachable",
                "connection refused",
                "timed out",
                "udp performance server did not return statistics",
            )
        )

    def _run_json_with_transient_retry(
        self, endpoint: Endpoint, code: str, *, timeout: int
    ) -> dict[str, Any]:
        failures: list[str] = []
        attempt_evidence: list[dict[str, Any]] = []
        maximum_attempts = 2
        for attempt in range(1, maximum_attempts + 1):
            try:
                value = self._run_json(endpoint, code, timeout=timeout)
            except RunCancelledError:
                raise
            except Exception as exc:
                failures.append(str(exc).strip() or type(exc).__name__)
                attempt_evidence.append(
                    {
                        "attempt": attempt,
                        "error": failures[-1],
                        "evidence": dict(getattr(exc, "evidence", {})),
                    }
                )
                retryable = self._retryable_performance_command_error(exc)
                if attempt >= maximum_attempts or not retryable:
                    if isinstance(exc, MeasurementExecutionError):
                        exc.evidence["attempts"] = failures
                        exc.evidence["attempt_history"] = attempt_evidence
                        if len(failures) > 1:
                            exc.args = (
                                f"performance command failed after {len(failures)} attempts on {endpoint.label}: first={failures[0]}; last={failures[-1]}",
                            )
                        raise
                    if len(failures) == 1:
                        raise
                    message = (
                        f"performance command failed after {len(failures)} attempts "
                        f"on {endpoint.label}: first={failures[0]}; "
                        f"last={failures[-1]}"
                    )
                    if isinstance(exc, PathReachabilityError):
                        raise PathReachabilityError(message) from exc
                    raise SuiteError(message) from exc
                self.reporter.logger.log(
                    f"Transient performance command failure on {endpoint.label}; "
                    f"retrying once: {failures[-1]}",
                    "WARNING",
                )
                self.reporter.event(
                    "performance-command-retry",
                    "Retrying one transient performance command failure",
                    endpoint=endpoint.label,
                    attempt=attempt,
                    maximum_attempts=maximum_attempts,
                    error=failures[-1],
                )
                time.sleep(2.0)
                continue
            if failures:
                self.reporter.event(
                    "performance-command-retry-succeeded",
                    "Transient performance command succeeded on retry",
                    endpoint=endpoint.label,
                    attempt=attempt,
                    maximum_attempts=maximum_attempts,
                    first_error=failures[0],
                )
            return value
        raise SuiteError(f"performance command did not execute on {endpoint.label}")

    def _execute_performance_command(
        self,
        endpoint: Endpoint,
        command: str,
        *,
        timeout: int,
        local_command: list[str],
    ) -> subprocess.CompletedProcess[str]:
        started_at = iso_utc()
        if endpoint.metadata.get("performance_local"):
            result = subprocess.run(
                local_command,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
                env={**os.environ, "LC_ALL": "C", "LANG": "C"},
            )
        else:
            try:
                result = self.builder.ssh_endpoint(endpoint, command, timeout=timeout)
            except RunCancelledError:
                raise
            except MeasurementExecutionError as exc:
                exc.evidence.setdefault("server_id", endpoint.server_id)
                raise
            except (SuiteError, OSError, subprocess.TimeoutExpired) as exc:
                raise SSHExecutionError(
                    str(exc),
                    evidence={
                        "endpoint": endpoint.label,
                        "server_id": endpoint.server_id,
                        "endpoint_address": endpoint.management_ip,
                        "command": command,
                        "timeout_seconds": timeout,
                    },
                ) from exc
        if result.returncode == 255 and not endpoint.metadata.get("performance_local"):
            raise SSHExecutionError(
                f"SSH performance command failed on {endpoint.label}: {_last_line(result.stderr or result.stdout or '')}",
                evidence={
                    "server_id": endpoint.server_id,
                    "endpoint": endpoint.label,
                    "endpoint_address": endpoint.management_ip,
                    "command": command,
                    "returncode": result.returncode,
                    "stdout": (result.stdout or "")[-16000:],
                    "stderr": (result.stderr or "")[-16000:],
                },
            )
        self.__dict__.setdefault("_performance_executions", []).append(
            {
                "endpoint": endpoint.label,
                "server_id": endpoint.server_id,
                "endpoint_address": endpoint.management_ip,
                "location": "runner"
                if endpoint.metadata.get("performance_local")
                else "guest",
                "command": command,
                "started_at": started_at,
                "finished_at": iso_utc(),
                "timeout_seconds": timeout,
                "returncode": result.returncode,
            }
        )
        return result

    def _run_json(
        self, endpoint: Endpoint, code: str, *, timeout: int
    ) -> dict[str, Any]:
        command = "python3 -c " + shlex.quote(code)
        result = self._execute_performance_command(
            endpoint, command, timeout=timeout, local_command=["python3", "-c", code]
        )
        stdout = (result.stdout or "").strip()
        stderr = (result.stderr or "").strip()
        evidence = {
            "endpoint": endpoint.label,
            "server_id": endpoint.server_id,
            "endpoint_address": endpoint.management_ip,
            "command": command,
            "returncode": result.returncode,
            "stdout": stdout[-16000:],
            "stderr": stderr[-16000:],
        }
        if result.returncode != 0:
            detail = _last_line(stderr or stdout)
            message = f"remote performance command failed on {endpoint.label}: {detail}"
            error_type = (
                SSHExecutionError
                if result.returncode == 255
                and not endpoint.metadata.get("performance_local")
                else MeasurementExecutionError
            )
            raise error_type(message, evidence=evidence)
        lines = [line for line in stdout.splitlines() if line.strip()]
        if not lines:
            raise MeasurementExecutionError(
                f"remote performance command on {endpoint.label} returned no JSON",
                evidence=evidence,
            )
        try:
            value = json.loads(lines[-1])
        except json.JSONDecodeError as exc:
            raise MeasurementExecutionError(
                f"remote performance command on {endpoint.label} returned invalid JSON: "
                f"{_last_line(stdout)}",
                evidence=evidence,
            ) from exc
        if not isinstance(value, dict):
            raise MeasurementExecutionError(
                "performance command JSON result must be an object", evidence=evidence
            )
        options = {}
        for statement in ast.parse(code).body:
            if isinstance(statement, ast.Assign):
                for target in statement.targets:
                    if isinstance(target, ast.Name) and target.id in {
                        "SOURCE",
                        "DESTINATION",
                        "PORT",
                        "DURATION",
                        "STREAMS",
                        "RATE_MBPS",
                        "PACKET_SIZE",
                        "EXPECTED",
                        "FAMILY",
                    }:
                        try:
                            options[target.id.lower()] = ast.literal_eval(
                                statement.value
                            )
                        except (ValueError, TypeError):
                            pass
        execution = {
            **next(
                (
                    item
                    for item in reversed(self._performance_executions)
                    if item["command"] == command
                    and item["server_id"] == endpoint.server_id
                ),
                {},
            ),
            **evidence,
            "location": "runner"
            if endpoint.metadata.get("performance_local")
            else "guest",
            "timeout_seconds": timeout,
            "options": options,
        }
        execution.pop("stdout")
        execution.pop("stderr")
        for item in reversed(self._performance_executions):
            if item["command"] == command and item["server_id"] == endpoint.server_id:
                item["options"] = options
                break
        value["execution_evidence"] = execution
        return value


__all__ = ["PerformanceResultMixin"]
