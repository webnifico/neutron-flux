from __future__ import annotations

import dataclasses
import ipaddress
import math
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .engine import TestEngine
from .errors import RunCancelledError, SuiteError
from .failure_injection import inject_failure
from .models import PlannedGroup, RuntimeGroup, TestSpec
from .network_contract import (
    ONE_ROUTER_PROJECT_NETWORKS,
    PROJECT_NETWORK,
    PROVIDER_NETWORK,
    ROUTING_UNASSIGNED_PROJECT_NETWORK,
    TWO_ROUTER_STATIC_ROUTING,
    canonical_group_kind,
)
from .performance import PerformanceRunner
from .performance_metrics import _jain_fairness
from .result_contract import performance_expectation, performance_observation
from .scheduling import ACTIVITY, timed
from .utils import unique_safe_name


class ConcurrentLoadRunner:
    """Measure VM-observed network behavior under simultaneous pair load."""

    def __init__(self, executor: Any):
        self.executor = executor
        self.config = executor.config
        self.plan = executor.plan
        self.builder = executor.builder
        self.reporter = executor.reporter
        self.cleanup = executor.cleanup_manager
        self.logger = executor.logger
        self.runtimes: list[RuntimeGroup] = []

    def _base_group(self) -> PlannedGroup:
        priorities = {
            PROJECT_NETWORK: 0,
            ROUTING_UNASSIGNED_PROJECT_NETWORK: 1,
            PROVIDER_NETWORK: 2,
            ONE_ROUTER_PROJECT_NETWORKS: 3,
            TWO_ROUTER_STATIC_ROUTING: 4,
        }
        candidates = [
            item
            for item in self.plan.groups
            if item.families and canonical_group_kind(item.kind) in priorities
        ]
        if not candidates:
            raise SuiteError(
                "No endpoint topology is available for concurrent VM-pair load "
                "measurement"
            )
        candidates.sort(
            key=lambda item: (
                priorities.get(canonical_group_kind(item.kind), 99),
                0 if 4 in item.families else 1,
                item.label,
            )
        )
        return candidates[0]

    @staticmethod
    def _address(runtime: RuntimeGroup, side: str, family: int) -> tuple[Any, str]:
        endpoint = runtime.endpoint(side)
        if endpoint is None:
            raise SuiteError(f"Concurrent-load runtime lacks endpoint {side}")
        candidates = []
        for subnet_id, address in endpoint.fixed_ips.items():
            try:
                version = ipaddress.ip_address(address).version
            except ValueError:
                continue
            if version == family:
                candidates.append((subnet_id, address))
        if not candidates:
            raise SuiteError(
                f"{endpoint.label} lacks a usable IPv{family} test address"
            )
        return endpoint, candidates[0][1]

    def _create_pairs(self, count: int) -> list[dict[str, Any]]:
        base = self._base_group()
        family = 4 if 4 in base.families else int(base.families[0])
        pairs: list[dict[str, Any]] = []
        self.logger.section(
            f"Concurrent VM-pair load setup: creating {count} simultaneous pair(s)"
        )
        self._inject_failure(
            "before-concurrent-load-build",
            legacy="before-fabric-build",
        )
        for index in range(1, count + 1):
            clone = dataclasses.replace(
                base,
                id=unique_safe_name(f"concurrent-load-{base.id}-{index}", 72),
                label=f"Concurrent load pair {index} — {base.label}",
                metadata={
                    **base.metadata,
                    "concurrent_path_load": True,
                    "concurrent_load_pair": index,
                    "source_group_id": base.id,
                },
            )
            runtime = self.builder.build_group(
                clone,
                sides=("A", "B"),
            )
            if runtime is None:
                # A topology builder can fail after creating and journaling a
                # subset of the pair. Clean that exact group immediately rather
                # than relying only on the run-wide orphan pass.
                self.builder.stop_group_probes(clone.id)
                self.cleanup.cleanup_group(clone.id)
                raise SuiteError(
                    self.builder.group_failure_reason(clone.id)
                    or f"Could not create concurrent-load VM pair {index}"
                )
            self.runtimes.append(runtime)
            verify = getattr(self.executor, "_verify_runtime", None)
            if callable(verify):
                verify(runtime)
            self.builder.runtime_groups = list(self.runtimes)
            if not hasattr(self.executor, "active"):
                self.executor.active = {}
            self.executor.active[runtime.plan.id] = runtime
            refresh = getattr(self.executor, "_refresh_checkpoint", None)
            if callable(refresh):
                refresh()
            self.executor.peak_endpoints = max(
                int(getattr(self.executor, "peak_endpoints", 0)),
                sum(len(item.endpoints) for item in self.runtimes),
            )
            source, source_ip = self._address(runtime, "A", family)
            destination, destination_ip = self._address(runtime, "B", family)
            source_az = str(source.availability_zone or "").strip() or None
            destination_az = str(destination.availability_zone or "").strip() or None
            availability_zone_placement = (
                "cross-availability-zone"
                if source_az and destination_az and source_az != destination_az
                else "same-availability-zone"
                if source_az and destination_az
                else "availability-zone-unavailable"
            )
            compute_placement = (
                "same-compute"
                if source.host and source.host == destination.host
                else "cross-compute"
                if source.host and destination.host
                else "placement-unavailable"
            )
            pairs.append(
                {
                    "runtime": runtime,
                    "pair_index": index,
                    "family": family,
                    "source": source,
                    "destination": destination,
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    # ``placement`` remains a read alias for legacy consumers.
                    "placement": compute_placement,
                    "compute_placement": compute_placement,
                    "availability_zone_placement": availability_zone_placement,
                    "source_host": source.host,
                    "destination_host": destination.host,
                    "source_availability_zone": source_az,
                    "destination_availability_zone": destination_az,
                }
            )
        # Prefer cross-compute paths for the lowest requested level and the
        # representative loaded-quality sample when they are available. Actual
        # placement is always reported; same-compute measurements remain valid.
        placement_priority = {
            "cross-compute": 0,
            "same-compute": 1,
            "placement-unavailable": 2,
        }
        pairs.sort(
            key=lambda item: (
                placement_priority.get(str(item.get("placement")), 99),
                int(item.get("pair_index") or 0),
            )
        )
        self._inject_failure(
            "after-concurrent-load-build",
            legacy="after-fabric-build",
        )
        return pairs

    def _inject_failure(self, canonical: str, *, legacy: str) -> None:
        """Honor canonical failure points and the legacy aliases."""

        configured = {
            item.strip()
            for item in str(self.config.failure_injection or "").split(",")
            if item.strip()
        }
        inject_failure(
            self.config,
            legacy
            if legacy in configured and canonical not in configured
            else canonical,
        )

    def _cleanup_runtimes(self) -> None:
        remaining: list[RuntimeGroup] = []
        for runtime in reversed(self.runtimes):
            group_id = runtime.plan.id
            cleanup_complete = False
            try:
                self.builder.stop_group_probes(group_id)
            except (SuiteError, OSError, RuntimeError) as exc:
                self.logger.log(
                    f"Could not stop concurrent-load probes for {group_id}: {exc}",
                    "ERROR",
                )
                self.reporter.cleanup_summary["errors"].append(
                    f"concurrent-load probes {group_id}: {exc}"
                )
            try:
                cleanup_complete = bool(self.cleanup.cleanup_group(group_id))
            except (SuiteError, OSError, RuntimeError) as exc:
                self.logger.log(
                    f"Concurrent-load group cleanup failed for {group_id}: {exc}",
                    "ERROR",
                )
                self.reporter.cleanup_summary["errors"].append(
                    f"concurrent-load group {group_id}: {exc}"
                )
            if cleanup_complete:
                self.executor.active.pop(group_id, None)
            else:
                remaining.append(runtime)
        remaining.reverse()
        self.builder.runtime_groups = remaining
        self.runtimes = remaining
        refresh = getattr(self.executor, "_refresh_checkpoint", None)
        if callable(refresh):
            refresh()

    @staticmethod
    def _concurrent_udp_sample(
        measurement: dict[str, Any],
        *,
        pair: dict[str, Any],
        requested_mbps: int,
        packet_size: int,
        sender_threshold_pct: float,
    ) -> dict[str, Any]:
        receiver_goodput = measurement.get("mbps")
        sender_mbps = measurement.get("sender_mbps")
        sender_achievement = (
            float(sender_mbps) / float(requested_mbps) * 100.0
            if sender_mbps is not None and requested_mbps
            else None
        )
        return {
            **measurement,
            "pair_index": pair.get("pair_index"),
            "placement": pair.get("placement"),
            "requested_mbps": requested_mbps,
            "offered_mbps": requested_mbps,
            "packet_size": packet_size,
            "receiver_goodput_mbps": receiver_goodput,
            "achieved_mbps": receiver_goodput,
            "sender_achievement_pct": sender_achievement,
            "sender_achievement_threshold_pct": float(sender_threshold_pct),
            "offered_achievement_pct": (
                float(receiver_goodput) / float(requested_mbps) * 100.0
                if receiver_goodput is not None and requested_mbps
                else None
            ),
            "delivery_pct": (
                float(receiver_goodput) / float(sender_mbps) * 100.0
                if receiver_goodput is not None
                and sender_mbps is not None
                and float(sender_mbps) > 0.0
                else None
            ),
            "load_valid": bool(
                sender_achievement is not None
                and sender_achievement >= sender_threshold_pct
            ),
            "load_validity": (
                "achieved"
                if sender_achievement is not None
                and sender_achievement >= sender_threshold_pct
                else "sender-load-not-achieved"
            ),
        }

    def _traffic_run(
        self,
        runner: PerformanceRunner,
        pairs: list[dict[str, Any]],
    ) -> dict[str, Any]:
        workers = max(1, len(pairs))
        udp_rate = min(self.config.performance_udp_rates_mbps)
        udp_packet_size = min(self.config.performance_udp_packet_sizes)
        sample_duration = max(
            self.config.fabric_scale_duration_seconds,
            math.ceil(
                (
                    self.config.performance_ping_count
                    + self.config.performance_ping_warmup_count
                )
                * 0.2
            )
            + 2,
        )

        with ThreadPoolExecutor(max_workers=workers) as pool:
            idle_latency = [
                future.result()
                for future in [
                    pool.submit(
                        runner._ping,
                        pair["source"],
                        pair["source_ip"],
                        pair["destination_ip"],
                        pair["family"],
                    )
                    for pair in pairs
                ]
            ]

        # Forward and reverse clean samples run as separate simultaneous batches.
        # Their median is representative directional aggregate throughput; they
        # are never added together as if both directions ran concurrently.
        with ThreadPoolExecutor(max_workers=workers) as pool:
            forward = [
                future.result()
                for future in [
                    pool.submit(
                        runner._tcp_upload,
                        pair["source"],
                        pair["source_ip"],
                        pair["destination_ip"],
                        pair["family"],
                        streams=1,
                        duration_seconds=sample_duration,
                    )
                    for pair in pairs
                ]
            ]
        with ThreadPoolExecutor(max_workers=workers) as pool:
            reverse = [
                future.result()
                for future in [
                    pool.submit(
                        runner._tcp_upload,
                        pair["destination"],
                        pair["destination_ip"],
                        pair["source_ip"],
                        pair["family"],
                        streams=1,
                        duration_seconds=sample_duration,
                    )
                    for pair in pairs
                ]
            ]

        # Every active pair gets its own latency and UDP observation while all
        # pairs carry TCP load. No representative pair is used as a proxy.
        with ThreadPoolExecutor(max_workers=max(1, workers * 3)) as pool:
            loaded_tcp_futures = [
                pool.submit(
                    runner._tcp_upload,
                    pair["source"],
                    pair["source_ip"],
                    pair["destination_ip"],
                    pair["family"],
                    streams=1,
                    duration_seconds=sample_duration,
                )
                for pair in pairs
            ]
            loaded_udp_futures = [
                pool.submit(
                    runner._udp_measurement,
                    pair["source"],
                    pair["source_ip"],
                    pair["destination_ip"],
                    pair["family"],
                    udp_rate,
                    udp_packet_size,
                    duration_seconds=sample_duration,
                )
                for pair in pairs
            ]
            time.sleep(0.35)
            loaded_latency_futures = [
                pool.submit(
                    runner._ping,
                    pair["source"],
                    pair["source_ip"],
                    pair["destination_ip"],
                    pair["family"],
                )
                for pair in pairs
            ]
            loaded_tcp = [future.result() for future in loaded_tcp_futures]
            loaded_udp_raw = [future.result() for future in loaded_udp_futures]
            loaded_latency = [future.result() for future in loaded_latency_futures]

        loaded_udp = [
            self._concurrent_udp_sample(
                measurement,
                pair=pair,
                requested_mbps=udp_rate,
                packet_size=udp_packet_size,
                sender_threshold_pct=(
                    self.config.performance_udp_sender_achievement_threshold_pct
                ),
            )
            for pair, measurement in zip(pairs, loaded_udp_raw, strict=True)
        ]
        idle_latency_by_pair = [
            {"pair_index": pair.get("pair_index"), **measurement}
            for pair, measurement in zip(pairs, idle_latency, strict=True)
        ]
        loaded_latency_by_pair = [
            {"pair_index": pair.get("pair_index"), **measurement}
            for pair, measurement in zip(pairs, loaded_latency, strict=True)
        ]

        forward_mbps = [float(item["mbps"]) for item in forward]
        reverse_mbps = [float(item["mbps"]) for item in reverse]
        loaded_tcp_mbps = [float(item["mbps"]) for item in loaded_tcp]
        pair_mbps = [
            statistics.median((forward_value, reverse_value))
            for forward_value, reverse_value in zip(
                forward_mbps, reverse_mbps, strict=True
            )
        ]
        clean_samples = [*forward, *reverse]
        clean_retransmissions = [
            int(item["retransmissions"])
            for item in clean_samples
            if item.get("retransmissions") is not None
        ]
        loaded_retransmissions = [
            int(item["retransmissions"])
            for item in loaded_tcp
            if item.get("retransmissions") is not None
        ]
        clean_bytes = sum(int(item.get("bytes") or 0) for item in clean_samples)
        loaded_bytes = sum(int(item.get("bytes") or 0) for item in loaded_tcp)
        clean_elapsed = sum(
            float(item.get("elapsed_s") or 0.0) for item in clean_samples
        )
        loaded_elapsed = sum(float(item.get("elapsed_s") or 0.0) for item in loaded_tcp)
        clean_retransmission_total = sum(clean_retransmissions)
        loaded_retransmission_total = sum(loaded_retransmissions)
        forward_aggregate = sum(forward_mbps)
        reverse_aggregate = sum(reverse_mbps)
        loaded_ratios: list[dict[str, Any]] = []
        for pair, idle, loaded in zip(pairs, idle_latency, loaded_latency, strict=True):
            idle_p95 = idle.get("p95_ms")
            loaded_p95 = loaded.get("p95_ms")
            ratio = (
                float(loaded_p95) / float(idle_p95)
                if idle_p95 not in {None, 0} and loaded_p95 is not None
                else None
            )
            loaded_ratios.append(
                {
                    "pair_index": pair.get("pair_index"),
                    "idle_p95_ms": idle_p95,
                    "loaded_p95_ms": loaded_p95,
                    "ratio": ratio,
                }
            )
        ratio_values = [
            float(item["ratio"])
            for item in loaded_ratios
            if item.get("ratio") is not None
        ]
        return {
            "forward_aggregate_mbps": forward_aggregate,
            "reverse_aggregate_mbps": reverse_aggregate,
            "aggregate_mbps": statistics.median([forward_aggregate, reverse_aggregate]),
            "aggregate_definition": "median-directional-aggregate-throughput",
            "lowest_directional_aggregate_mbps": min(
                forward_aggregate, reverse_aggregate
            ),
            "forward_pair_mbps": forward_mbps,
            "reverse_pair_mbps": reverse_mbps,
            "pair_median_mbps": pair_mbps,
            "median_pair_mbps": statistics.median(pair_mbps),
            "slowest_pair_mbps": min(pair_mbps),
            "fairness": min(
                _jain_fairness(forward_mbps),
                _jain_fairness(reverse_mbps),
            ),
            "retransmissions": clean_retransmission_total,
            "retransmissions_per_gib": (
                clean_retransmission_total * (1024.0**3) / clean_bytes
                if clean_retransmissions and clean_bytes > 0
                else None
            ),
            "retransmissions_per_second": (
                clean_retransmission_total / clean_elapsed
                if clean_retransmissions and clean_elapsed > 0.0
                else None
            ),
            "loaded_retransmissions": loaded_retransmission_total,
            "loaded_retransmissions_per_gib": (
                loaded_retransmission_total * (1024.0**3) / loaded_bytes
                if loaded_retransmissions and loaded_bytes > 0
                else None
            ),
            "loaded_retransmissions_per_second": (
                loaded_retransmission_total / loaded_elapsed
                if loaded_retransmissions and loaded_elapsed > 0.0
                else None
            ),
            "idle_latency_by_pair": idle_latency_by_pair,
            "loaded_latency_by_pair": loaded_latency_by_pair,
            "loaded_latency_ratios_by_pair": loaded_ratios,
            "loaded_udp_by_pair": loaded_udp,
            # Compatibility aliases for legacy report readers. New summaries
            # consume the explicit by-pair collections above.
            "idle_latency": idle_latency_by_pair[0] if idle_latency_by_pair else {},
            "loaded_latency": (
                loaded_latency_by_pair[0] if loaded_latency_by_pair else {}
            ),
            "loaded_latency_ratio": max(ratio_values) if ratio_values else None,
            "loaded_udp": loaded_udp[0] if loaded_udp else {},
            "loaded_tcp_aggregate_mbps": sum(loaded_tcp_mbps),
            "loaded_tcp_pair_mbps": loaded_tcp_mbps,
            # Retain individual windows as well as the historical totals. A
            # total across pairs/directions cannot identify the largest window.
            "tcp_windows": [
                {
                    **{
                        key: sample[key]
                        for key in (
                            "retransmissions",
                            "stream_retransmissions",
                            "streams",
                            "elapsed_s",
                            "mbps",
                            "bytes",
                        )
                        if key in sample
                    },
                    "pair_index": pair.get("pair_index"),
                    "family": pair.get("family"),
                    "placement": pair.get("placement"),
                    "direction": direction,
                    "condition": condition,
                    "source_label": getattr(
                        pair["source" if direction == "forward" else "destination"],
                        "label",
                        pair[
                            "source_ip" if direction == "forward" else "destination_ip"
                        ],
                    ),
                    "destination_label": getattr(
                        pair["destination" if direction == "forward" else "source"],
                        "label",
                        pair[
                            "destination_ip" if direction == "forward" else "source_ip"
                        ],
                    ),
                }
                for direction, condition, samples in (
                    ("forward", "concurrent VM-pair throughput", forward),
                    ("reverse", "concurrent VM-pair throughput", reverse),
                    ("forward", "concurrent VM-pair latency load", loaded_tcp),
                )
                for pair, sample in zip(pairs, samples, strict=True)
            ],
            "configured_duration_seconds": self.config.fabric_scale_duration_seconds,
            "clean_throughput_sample_duration_seconds": sample_duration,
            "loaded_sample_duration_seconds": sample_duration,
        }

    @staticmethod
    def _summarize_level(
        requested: int,
        pairs: list[dict[str, Any]],
        runs: list[dict[str, Any]],
    ) -> dict[str, Any]:
        aggregate = [float(item["aggregate_mbps"]) for item in runs]
        pair_median = [float(item["median_pair_mbps"]) for item in runs]
        slowest_pair = [float(item["slowest_pair_mbps"]) for item in runs]
        fairness = [float(item["fairness"]) for item in runs]
        idle_rows: list[dict[str, Any]] = []
        loaded_rows: list[dict[str, Any]] = []
        ratio_rows: list[dict[str, Any]] = []
        udp_rows: list[dict[str, Any]] = []
        for run_index, item in enumerate(runs, 1):
            explicit_idle = item.get("idle_latency_by_pair")
            explicit_loaded = item.get("loaded_latency_by_pair")
            explicit_ratios = item.get("loaded_latency_ratios_by_pair")
            explicit_udp = item.get("loaded_udp_by_pair")
            idle_items = (
                explicit_idle
                if isinstance(explicit_idle, list)
                else [item.get("idle_latency") or {}]
            )
            loaded_items = (
                explicit_loaded
                if isinstance(explicit_loaded, list)
                else [item.get("loaded_latency") or {}]
            )
            ratio_items = (
                explicit_ratios
                if isinstance(explicit_ratios, list)
                else [
                    {
                        "pair_index": item.get("representative_pair_index"),
                        "ratio": item.get("loaded_latency_ratio"),
                    }
                ]
            )
            udp_items = (
                explicit_udp
                if isinstance(explicit_udp, list)
                else [item.get("loaded_udp") or {}]
            )
            idle_rows.extend(
                {"run": run_index, **row} for row in idle_items if isinstance(row, dict)
            )
            loaded_rows.extend(
                {"run": run_index, **row}
                for row in loaded_items
                if isinstance(row, dict)
            )
            ratio_rows.extend(
                {"run": run_index, **row}
                for row in ratio_items
                if isinstance(row, dict)
            )
            udp_rows.extend(
                {"run": run_index, **row} for row in udp_items if isinstance(row, dict)
            )
        idle_p95 = [
            float(row["p95_ms"]) for row in idle_rows if row.get("p95_ms") is not None
        ]
        loaded_p95 = [
            float(row["p95_ms"]) for row in loaded_rows if row.get("p95_ms") is not None
        ]
        loaded_ratio = [
            float(row["ratio"]) for row in ratio_rows if row.get("ratio") is not None
        ]
        loaded_tcp_aggregate = [
            float(item["loaded_tcp_aggregate_mbps"])
            for item in runs
            if item.get("loaded_tcp_aggregate_mbps") is not None
        ]
        icmp_loss = [float(row.get("loss_pct") or 0.0) for row in loaded_rows]
        udp_loss = [float(row.get("loss_pct") or 0.0) for row in udp_rows]
        udp_jitter = [float(row.get("jitter_ms") or 0.0) for row in udp_rows]
        limited_udp = [
            row
            for row in udp_rows
            if row.get("load_valid") is False
            or (
                row.get("load_valid") is None
                and row.get("sender_achievement_pct") is not None
                and float(row.get("sender_achievement_pct") or 0.0)
                < float(row.get("sender_achievement_threshold_pct") or 90.0)
            )
        ]
        worst_icmp = max(
            loaded_rows, key=lambda row: float(row.get("loss_pct") or 0.0), default={}
        )
        worst_udp = max(
            udp_rows, key=lambda row: float(row.get("loss_pct") or 0.0), default={}
        )
        worst_jitter = max(
            udp_rows, key=lambda row: float(row.get("jitter_ms") or 0.0), default={}
        )
        placements = []
        for index, pair in enumerate(pairs, 1):
            source_az = str(pair.get("source_availability_zone") or "").strip() or None
            destination_az = (
                str(pair.get("destination_availability_zone") or "").strip() or None
            )
            availability_zone_placement = str(
                pair.get("availability_zone_placement") or ""
            )
            if not availability_zone_placement:
                availability_zone_placement = (
                    "cross-availability-zone"
                    if source_az and destination_az and source_az != destination_az
                    else "same-availability-zone"
                    if source_az and destination_az
                    else "availability-zone-unavailable"
                )
            compute_placement = str(
                pair.get("compute_placement")
                or pair.get("placement")
                or "placement-unavailable"
            )
            placements.append(
                {
                    "pair": int(pair.get("pair_index") or index),
                    "placement": compute_placement,
                    "compute_placement": compute_placement,
                    "availability_zone_placement": availability_zone_placement,
                    "source_host": pair.get("source_host"),
                    "destination_host": pair.get("destination_host"),
                    "source_availability_zone": source_az,
                    "destination_availability_zone": destination_az,
                }
            )
        unique_hosts = sorted(
            {
                str(host)
                for pair in pairs
                for host in (pair.get("source_host"), pair.get("destination_host"))
                if host
            }
        )
        retrans_per_gib = [
            float(item["retransmissions_per_gib"])
            for item in runs
            if item.get("retransmissions_per_gib") is not None
        ]
        loaded_retrans_per_gib = [
            float(item["loaded_retransmissions_per_gib"])
            for item in runs
            if item.get("loaded_retransmissions_per_gib") is not None
        ]
        return {
            "pairs": requested,
            "pairs_used": len(pairs),
            "placements": placements,
            "cross_compute_pairs": sum(
                1 for item in placements if item["placement"] == "cross-compute"
            ),
            "same_compute_pairs": sum(
                1 for item in placements if item["placement"] == "same-compute"
            ),
            "unknown_placement_pairs": sum(
                1 for item in placements if item["placement"] == "placement-unavailable"
            ),
            "cross_availability_zone_pairs": sum(
                1
                for item in placements
                if item["availability_zone_placement"] == "cross-availability-zone"
            ),
            "same_availability_zone_pairs": sum(
                1
                for item in placements
                if item["availability_zone_placement"] == "same-availability-zone"
            ),
            "unknown_availability_zone_pairs": sum(
                1
                for item in placements
                if item["availability_zone_placement"]
                == "availability-zone-unavailable"
            ),
            "unique_compute_hosts": unique_hosts,
            "runs": runs,
            "aggregate_definition": "median-directional-aggregate-throughput",
            "median_aggregate_mbps": statistics.median(aggregate),
            "minimum_aggregate_mbps": min(aggregate),
            "maximum_aggregate_mbps": max(aggregate),
            "median_pair_mbps": statistics.median(pair_median),
            "minimum_pair_mbps": min(slowest_pair),
            "median_fairness": statistics.median(fairness),
            "minimum_fairness": min(fairness),
            "median_idle_p95_ms": statistics.median(idle_p95) if idle_p95 else None,
            "median_loaded_p95_ms": (
                statistics.median(loaded_p95) if loaded_p95 else None
            ),
            "median_loaded_latency_ratio": (
                statistics.median(loaded_ratio) if loaded_ratio else None
            ),
            "median_loaded_tcp_aggregate_mbps": (
                statistics.median(loaded_tcp_aggregate)
                if loaded_tcp_aggregate
                else None
            ),
            "maximum_loaded_icmp_loss_pct": max(icmp_loss, default=0.0),
            "maximum_loaded_udp_application_loss_pct": max(udp_loss, default=0.0),
            # Compatibility alias with explicit UDP meaning.
            "maximum_loaded_udp_loss_pct": max(udp_loss, default=0.0),
            "maximum_loaded_udp_jitter_ms": max(udp_jitter, default=0.0),
            "worst_loaded_icmp_context": {
                key: worst_icmp.get(key) for key in ("run", "pair_index", "loss_pct")
            },
            "worst_loaded_udp_loss_context": {
                key: worst_udp.get(key)
                for key in (
                    "run",
                    "pair_index",
                    "loss_pct",
                    "requested_mbps",
                    "packet_size",
                    "sender_achievement_pct",
                    "receiver_drop_attribution",
                )
            },
            "worst_loaded_udp_jitter_context": {
                key: worst_jitter.get(key)
                for key in (
                    "run",
                    "pair_index",
                    "jitter_ms",
                    "requested_mbps",
                    "packet_size",
                )
            },
            "udp_sender_limited_samples": len(limited_udp),
            "minimum_udp_sender_achievement_pct": min(
                (
                    float(row.get("sender_achievement_pct") or 0.0)
                    for row in udp_rows
                    if row.get("sender_achievement_pct") is not None
                ),
                default=None,
            ),
            "total_retransmissions": sum(
                int(item.get("retransmissions") or 0) for item in runs
            ),
            "total_loaded_retransmissions": sum(
                int(item.get("loaded_retransmissions") or 0) for item in runs
            ),
            "median_retransmissions_per_gib": (
                statistics.median(retrans_per_gib) if retrans_per_gib else None
            ),
            "median_loaded_retransmissions_per_gib": (
                statistics.median(loaded_retrans_per_gib)
                if loaded_retrans_per_gib
                else None
            ),
        }

    @staticmethod
    def _attach_level_comparisons(levels: list[dict[str, Any]]) -> dict[str, Any]:
        """Attach only comparisons supported by the requested concurrency levels.

        A one-pair level enables degradation from a one-pair reference. Multiple
        levels without one pair are compared with the lowest requested level. A
        single requested level is a fixed-concurrency measurement and
        intentionally has no degradation value.
        """
        if not levels:
            return {
                "mode": "unavailable",
                "baseline_pairs": None,
                "one_pair_baseline_present": False,
            }

        baseline_level = min(levels, key=lambda level: int(level.get("pairs") or 0))
        baseline_pairs = int(baseline_level.get("pairs") or 0)
        baseline = float(baseline_level.get("median_pair_mbps") or 0.0)
        one_pair = baseline_pairs == 1
        if len(levels) == 1:
            mode = "fixed-concurrency"
        elif one_pair:
            mode = "one-pair-baseline"
        else:
            mode = "lowest-requested-level"

        for level in levels:
            current = float(level.get("median_pair_mbps") or 0.0)
            comparison_available = len(levels) > 1 and baseline > 0.0
            change_pct = (
                (current - baseline) * 100.0 / baseline
                if comparison_available
                else None
            )
            level["comparison_mode"] = mode
            level["comparison_baseline_pairs"] = (
                baseline_pairs
                if comparison_available and level is not baseline_level
                else None
            )
            level["comparison_baseline_median_pair_mbps"] = (
                baseline
                if comparison_available and level is not baseline_level
                else None
            )
            level["per_pair_change_pct"] = change_pct
            level["per_pair_degradation_pct"] = (
                max(0.0, -change_pct) if change_pct is not None else None
            )

        return {
            "mode": mode,
            "baseline_pairs": baseline_pairs if len(levels) > 1 else None,
            "one_pair_baseline_present": one_pair,
        }

    @staticmethod
    def _placement_assessment(level: dict[str, Any]) -> dict[str, Any]:
        cross_compute = int(level.get("cross_compute_pairs") or 0)
        same_compute = int(level.get("same_compute_pairs") or 0)
        unavailable = int(level.get("unknown_placement_pairs") or 0)
        cross_az = int(level.get("cross_availability_zone_pairs") or 0)
        same_az = int(level.get("same_availability_zone_pairs") or 0)
        unavailable_az = int(level.get("unknown_availability_zone_pairs") or 0)
        known_compute_scopes = int(cross_compute > 0) + int(same_compute > 0)
        known_az_scopes = int(cross_az > 0) + int(same_az > 0)
        if unavailable and not known_compute_scopes:
            compute_scope = "placement-unavailable"
        elif unavailable or known_compute_scopes > 1:
            compute_scope = "mixed"
        elif cross_compute:
            compute_scope = "inter-compute-only"
        elif same_compute:
            compute_scope = "intra-compute-only"
        else:
            compute_scope = "placement-unavailable"

        if unavailable_az and not known_az_scopes:
            availability_zone_scope = "availability-zone-unavailable"
        elif unavailable_az or known_az_scopes > 1:
            availability_zone_scope = "mixed"
        elif cross_az:
            availability_zone_scope = "cross-availability-zone-only"
        elif same_az:
            availability_zone_scope = "same-availability-zone-only"
        else:
            availability_zone_scope = "availability-zone-unavailable"

        if availability_zone_scope == "cross-availability-zone-only":
            scope = availability_zone_scope
        elif cross_az:
            # At least one cross-AZ path occurred, but the observed set was not
            # exclusively and completely cross-AZ.
            scope = "mixed"
        else:
            scope = compute_scope

        scope_authoritative = (
            unavailable_az == 0 and known_az_scopes > 0
            if cross_az
            else unavailable == 0 and known_compute_scopes > 0
        )
        return {
            "scope": scope,
            "status": (
                "confirmed"
                if scope_authoritative
                else "partially-unverified"
                if known_compute_scopes > 0 or known_az_scopes > 0
                else "unverified"
            ),
            "authoritative": scope_authoritative,
            "authority": "Nova-reported server placement",
            "compute_scope": compute_scope,
            "availability_zone_scope": availability_zone_scope,
            "cross_compute_pairs": cross_compute,
            "same_compute_pairs": same_compute,
            "placement_unavailable_pairs": unavailable,
            "cross_availability_zone_pairs": cross_az,
            "same_availability_zone_pairs": same_az,
            "availability_zone_unavailable_pairs": unavailable_az,
            "availability_zone_authoritative": (
                unavailable_az == 0 and known_az_scopes > 0
            ),
            "component_attribution": {
                "status": "not-assessed",
                "reason": (
                    "VM-observed measurements and Nova placement do not identify "
                    "a physical or hidden infrastructure component"
                ),
            },
        }

    def run(self) -> TestSpec | None:
        if not self.config.fabric_scale_enabled:
            return None
        max_pairs = max(self.config.fabric_scale_pairs)
        check_identity = next(
            (
                item.metadata.get("check_bindings", {}).get("load")
                for item in self.executor.plan.tests
                if item.metadata.get("check_bindings", {}).get("load")
            ),
            None,
        )
        spec = TestSpec(
            id=(
                "CONCURRENT-LOAD-"
                + unique_safe_name(
                    getattr(self.executor, "scope", {}).get("pair_scope_id")
                    or getattr(self.reporter, "scope", "")
                    or "RUN",
                    80,
                ).upper()
            ),
            category="network-performance",
            operation="performance-concurrent-path-load",
            family=None,
            expectation=performance_expectation("concurrent-path-load"),
            expectation_reason=(
                "the requested number of disposable VM pairs should transmit "
                "simultaneously and return VM-observed path measurements"
            ),
            authoritative=True,
            dependencies=[],
            phase="concurrent-path-load",
            display_name="Concurrent VM-pair load",
            scenario="VM-observed network behavior under simultaneous path load",
            metadata={
                "supplemental": True,
                "concurrent_path_load": True,
                **({"planned_check_id": check_identity} if check_identity else {}),
            },
        )
        self.executor._append_runtime_specs([spec])
        started = time.monotonic()
        levels: list[dict[str, Any]] = []
        comparison: dict[str, Any] = {
            "mode": "unavailable",
            "baseline_pairs": None,
            "one_pair_baseline_present": False,
        }
        try:
            pairs = self._create_pairs(max_pairs)
            engine = TestEngine(
                self.config,
                self.builder.discovery,
                self.builder,
                self.reporter,
            )
            runner = PerformanceRunner(
                self.config,
                self.builder,
                self.reporter,
                engine,
            )
            with (
                ACTIVITY.scope(
                    exclusive=True,
                    reporter=self.reporter,
                    label="concurrent-load measurement",
                ),
                timed(self.reporter, "concurrent-load", "concurrent-load measurement"),
            ):
                for requested in self.config.fabric_scale_pairs:
                    selected = pairs[:requested]
                    self._inject_failure(
                        f"before-concurrent-load-level:{requested}",
                        legacy=f"before-fabric-level:{requested}",
                    )
                    self.logger.section(
                        f"Concurrent VM-pair load: {requested} simultaneous pair(s), "
                        f"{self.config.fabric_scale_runs} run(s)"
                    )
                    runs = [
                        self._traffic_run(runner, selected)
                        for _ in range(self.config.fabric_scale_runs)
                    ]
                    levels.append(self._summarize_level(requested, selected, runs))
                    self._inject_failure(
                        f"after-concurrent-load-level:{requested}",
                        legacy=f"after-fabric-level:{requested}",
                    )
            comparison = self._attach_level_comparisons(levels)
            warning_reasons: list[str] = []
            unverified_reasons: list[str] = []
            highest = max(levels, key=lambda level: int(level.get("pairs") or 0))
            placement = self._placement_assessment(highest)
            if any(
                float(level.get("maximum_loaded_icmp_loss_pct") or 0.0) > 0.0
                for level in levels
            ):
                warning_reasons.append("loaded ICMP observations recorded packet loss")
            if any(
                float(level.get("maximum_loaded_udp_application_loss_pct") or 0.0)
                > self.config.performance_udp_loss_threshold_pct
                for level in levels
            ):
                warning_reasons.append(
                    "loaded UDP application-delivery loss exceeded the configured "
                    "loss threshold"
                )
            if any(
                int(level.get("udp_sender_limited_samples") or 0) > 0
                for level in levels
            ):
                minimum_achievement = min(
                    (
                        float(level["minimum_udp_sender_achievement_pct"])
                        for level in levels
                        if level.get("minimum_udp_sender_achievement_pct") is not None
                    ),
                    default=0.0,
                )
                unverified_reasons.append(
                    "at least one loaded UDP sample did not generate the requested "
                    f"application rate (minimum sender achievement "
                    f"{minimum_achievement:.1f}%; required "
                    f"{self.config.performance_udp_sender_achievement_threshold_pct:.1f}%)"
                )
            if any(
                float(level.get("minimum_fairness") or 0.0) < 0.75 for level in levels
            ):
                warning_reasons.append("per-pair throughput fairness fell below 0.75")
            functional_failure_reasons = []
            if any(
                float(level.get("minimum_pair_mbps") or 0.0) <= 0.0 for level in levels
            ):
                functional_failure_reasons.append(
                    "at least one requested VM pair returned no usable TCP throughput"
                )
            health = (
                "critical"
                if functional_failure_reasons
                else "unverified"
                if unverified_reasons
                else "warning"
                if warning_reasons
                else "good"
            )
            if functional_failure_reasons:
                status = "FAIL"
                verdict_basis = "network-path-functional-contract"
            elif unverified_reasons:
                status = "UNVERIFIED"
                verdict_basis = "measurement-load-not-achieved"
            elif warning_reasons and self.config.performance_enforce_thresholds:
                status = "FAIL"
                verdict_basis = "operator-threshold-policy"
            else:
                status = "PASS"
                verdict_basis = "measurement-completion"
            if comparison["mode"] == "fixed-concurrency":
                scope_message = (
                    f"Measured the requested fixed concurrency of {highest['pairs']} "
                    "simultaneous VM pairs; no lower-concurrency baseline was requested"
                )
            elif comparison["mode"] == "one-pair-baseline":
                scope_message = (
                    f"Measured scaling from a one-pair baseline up to "
                    f"{highest['pairs']} simultaneous VM pairs"
                )
            else:
                scope_message = (
                    f"Measured requested levels from {comparison['baseline_pairs']} to "
                    f"{highest['pairs']} simultaneous VM pairs; changes use the "
                    f"{comparison['baseline_pairs']}-pair level as the reference because "
                    "a one-pair baseline was not requested"
                )
            message = (
                f"{scope_message}; median directional aggregate "
                f"{highest['median_aggregate_mbps']:.1f} Mbps, median per-pair "
                f"{highest['median_pair_mbps']:.1f} Mbps, minimum fairness "
                f"{highest['minimum_fairness']:.3f}; placement scope "
                f"{placement['scope']}"
            )
            if functional_failure_reasons:
                message += "; " + "; ".join(functional_failure_reasons)
            if unverified_reasons:
                message += "; " + "; ".join(unverified_reasons)
            if warning_reasons:
                message += "; " + "; ".join(warning_reasons)
            observed = performance_observation(
                "concurrent-path-load",
                status=status,
                health=health,
                verdict_basis=verdict_basis,
            )
            self.reporter.result(
                spec.id,
                spec.category,
                status,
                message,
                started=started,
                expected=spec.expectation,
                observed=observed,
                authoritative=status in {"PASS", "FAIL"},
                details={
                    "performance": True,
                    "measurement": "concurrent-path-load",
                    "health": health,
                    "execution_status": "completed",
                    "contract_verdict": (
                        "met"
                        if status == "PASS"
                        else "not-evaluated"
                        if status == "UNVERIFIED"
                        else "violated"
                    ),
                    "verdict_basis": verdict_basis,
                    "path_health": {
                        "status": (
                            "critical"
                            if health == "critical"
                            else "advisory"
                            if health == "warning"
                            else "no-configured-concern-observed"
                        ),
                        "warning_reasons": list(warning_reasons),
                    },
                    "attribution": {"placement": placement},
                    "warning_reasons": list(warning_reasons),
                    "unverified_reasons": list(unverified_reasons),
                    "functional_failure_reasons": functional_failure_reasons,
                    "thresholds_enforced": self.config.performance_enforce_thresholds,
                    "metrics": {"levels": levels},
                    "configuration": {
                        "pairs": list(self.config.fabric_scale_pairs),
                        "runs": self.config.fabric_scale_runs,
                        "duration_seconds": self.config.fabric_scale_duration_seconds,
                        "comparison_mode": comparison.get("mode"),
                        "comparison_baseline_pairs": comparison.get("baseline_pairs"),
                        "one_pair_baseline_present": comparison.get(
                            "one_pair_baseline_present"
                        ),
                    },
                },
                display_name=spec.display_name,
                scenario=spec.scenario,
            )
        except RunCancelledError:
            raise
        except (
            SuiteError,
            KeyError,
            TypeError,
            ValueError,
            OSError,
            RuntimeError,
        ) as exc:
            self.reporter.result(
                spec.id,
                spec.category,
                "ERROR",
                f"Concurrent VM-pair load could not complete: {exc}",
                started=started,
                expected=spec.expectation,
                observed=performance_observation(
                    "concurrent-path-load", status="ERROR"
                ),
                authoritative=False,
                details={
                    "performance": True,
                    "measurement": "concurrent-path-load",
                    "health": "critical",
                    "execution_status": "error",
                    "contract_verdict": "not-evaluated",
                    "verdict_basis": "execution-error",
                    "path_health": {
                        "status": "not-assessed",
                        "warning_reasons": [],
                    },
                    "attribution": {
                        "placement": (
                            self._placement_assessment(levels[-1])
                            if levels
                            else {
                                "scope": "placement-unavailable",
                                "status": "unverified",
                                "authoritative": False,
                            }
                        )
                    },
                    "warning_reasons": [],
                    "metrics": {"levels": levels},
                    "configuration": {
                        "pairs": list(self.config.fabric_scale_pairs),
                        "runs": self.config.fabric_scale_runs,
                        "duration_seconds": self.config.fabric_scale_duration_seconds,
                        "comparison_mode": comparison.get("mode"),
                        "comparison_baseline_pairs": comparison.get("baseline_pairs"),
                        "one_pair_baseline_present": comparison.get(
                            "one_pair_baseline_present"
                        ),
                    },
                },
                display_name=spec.display_name,
                scenario=spec.scenario,
            )
        finally:
            self._cleanup_runtimes()
        return spec


__all__ = ["ConcurrentLoadRunner"]
