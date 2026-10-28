"""Bounded UDP capacity and matched directional measurement orchestration."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .models import Endpoint
from .performance_metrics import udp_sample_assessable

if TYPE_CHECKING:
    from .performance import ResolvedPerformancePath


class UDPMatrixMixin:
    def _udp_profile_blocked_by_size(
        self, rejected: dict[str, Any], rate: int, size: int
    ) -> dict[str, Any]:
        """Record an unattempted rate profile without duplicating old traffic."""
        sample = {
            "packet_size_supported": False,
            "packet_size_status": "not-run-known-local-pmtu",
            "kernel_path_mtu": rejected.get("kernel_path_mtu"),
            "packet_size_error": rejected.get("packet_size_error"),
            "measurement_attempted": False,
            "constraint_reference_rate_mbps": rejected.get("configured_rate_mbps"),
        }
        self._annotate_udp_sample(
            sample,
            configured_rate=rate,
            attempted_rate=rate,
            packet_size=size,
            attempt=0,
        )
        sample["calibration_status"] = "packet-size-rejected"
        return sample

    def _udp_matrix(self, path: ResolvedPerformancePath) -> dict[str, Any]:
        result: dict[str, Any] = {"forward": []}
        # Keep completed profiles available if a later command cannot execute.
        self._partial_udp_samples = result
        selected: dict[tuple[str, int, int], dict[str, Any]] = {}
        directions: list[tuple[str, Endpoint, str, str, str | None]] = [
            (
                "forward",
                path.source,
                path.forward_source_ip,
                path.forward_destination_ip,
                None,
            )
        ]
        if "reverse" in path.plan.directions:
            result["reverse"] = []
            directions.append(
                (
                    "reverse",
                    path.destination,
                    path.reverse_source_ip,
                    path.reverse_destination_ip,
                    path.reverse_expected_peer_ip,
                )
            )
        packet_sizes = list(self.config.performance_udp_packet_sizes)
        near_mtu = max(64, path.expected_mtu - (48 if path.plan.family == 6 else 28))
        if near_mtu not in packet_sizes:
            packet_sizes.append(near_mtu)
        original_packet_sizes = list(packet_sizes)
        rejected_profiles: dict[tuple[int, int], list[str]] = {}
        constraints: list[dict[str, Any]] = []
        for (
            direction,
            endpoint,
            source_ip,
            destination_ip,
            expected_peer_ip,
        ) in directions:
            # Hints are local to this resolved path, direction and packet size.
            # They select a fresh measurement, never substitute an old result.
            sustainable_rates: dict[int, int] = {}
            rejected_sizes: dict[int, dict[str, Any]] = {}
            for configured_rate in self.config.performance_udp_rates_mbps:
                for packet_size in packet_sizes:
                    if packet_size in rejected_sizes:
                        samples = [
                            self._udp_profile_blocked_by_size(
                                rejected_sizes[packet_size],
                                configured_rate,
                                packet_size,
                            )
                        ]
                    else:
                        samples = self._adaptive_udp_samples(
                            endpoint,
                            source_ip,
                            destination_ip,
                            path.plan.family,
                            configured_rate,
                            packet_size,
                            expected_peer_ip=expected_peer_ip,
                            sustainable_rate_hint=sustainable_rates.get(packet_size),
                        )
                    result[direction].extend(samples)
                    for sample in samples:
                        sample["packet_size_origin"] = (
                            "configured"
                            if packet_size in self.config.performance_udp_packet_sizes
                            else "advertised-mtu"
                        )
                        if sample.get("packet_size_supported") is False:
                            rejected_sizes.setdefault(packet_size, sample)
                            rejected_profiles.setdefault(
                                (configured_rate, packet_size), []
                            ).append(direction)
                            if sample.get("measurement_attempted") is not False:
                                constraints.append({"direction": direction, **sample})
                        if (
                            udp_sample_assessable(sample)
                            and sample.get("sender_telemetry_available") is True
                        ):
                            selected[direction, configured_rate, packet_size] = sample
                    selected_rates = [
                        int(item["requested_mbps"])
                        for item in samples
                        if udp_sample_assessable(item)
                        and item.get("sender_telemetry_available") is True
                        and item.get("requested_mbps")
                    ]
                    if selected_rates:
                        sustainable_rates[packet_size] = max(selected_rates)
        if len(directions) == 2:
            result["comparison"] = self._matched_udp_comparison(
                path, directions, packet_sizes, selected, rejected_profiles
            )
            for direction in ("forward", "reverse"):
                for sample in result["comparison"][direction]:
                    if sample.get("packet_size_supported") is False:
                        constraints.append({"direction": direction, **sample})
                        rejected_profiles.setdefault(
                            (
                                int(sample["configured_rate_mbps"]),
                                int(sample["packet_size"]),
                            ),
                            [],
                        ).append(direction)
        # A connected UDP socket can learn a lower route PMTU while an earlier
        # direction still accepts fragmented packets. Preserve every original
        # profile, and verify one common derived payload freshly in both
        # directions. The kernel constraint is not a proven path MTU: successful
        # supplementary traffic supplies its own delivery evidence.
        constrained_mtus = [
            int(item["kernel_path_mtu"])
            for item in constraints
            if isinstance(item.get("kernel_path_mtu"), int)
            and int(item["kernel_path_mtu"]) > 0
        ]
        if constraints:
            result["packet_size_constraints"] = constraints
        supplemental_sizes: list[int] = []
        if constrained_mtus:
            mtu = min(constrained_mtus)
            payload = mtu - (48 if path.plan.family == 6 else 28)
            rejected_sizes_all = {size for _rate, size in rejected_profiles}
            if 64 <= payload < min(rejected_sizes_all) and payload not in packet_sizes:
                supplemental_sizes.append(payload)
                packet_sizes.append(payload)
                for direction, endpoint, source_ip, destination_ip, peer in directions:
                    rejected_supplement: dict[str, Any] | None = None
                    for rate in self.config.performance_udp_rates_mbps:
                        if rejected_supplement is not None:
                            samples = [
                                self._udp_profile_blocked_by_size(
                                    rejected_supplement, rate, payload
                                )
                            ]
                        else:
                            samples = self._adaptive_udp_samples(
                                endpoint,
                                source_ip,
                                destination_ip,
                                path.plan.family,
                                rate,
                                payload,
                                expected_peer_ip=peer,
                            )
                        result[direction].extend(samples)
                        for sample in samples:
                            sample.update(
                                packet_size_origin="kernel-pmtu-supplement",
                                kernel_path_mtu_constraint=mtu,
                                supplements_packet_sizes=sorted(rejected_sizes_all),
                            )
                            if sample.get("packet_size_supported") is False:
                                rejected_supplement = sample
                                rejected_profiles.setdefault(
                                    (rate, payload), []
                                ).append(direction)
                            if (
                                udp_sample_assessable(sample)
                                and sample.get("sender_telemetry_available") is True
                            ):
                                selected[direction, rate, payload] = sample
        if len(directions) == 2:
            if supplemental_sizes:
                self._matched_udp_comparison(
                    path,
                    directions,
                    supplemental_sizes,
                    selected,
                    rejected_profiles,
                    comparison=result["comparison"],
                )
            if constraints:
                result["comparison"].update(
                    original_requested_profiles=(
                        len(original_packet_sizes)
                        * len(self.config.performance_udp_rates_mbps)
                    ),
                    supplemental_profiles=(
                        len(supplemental_sizes)
                        * len(self.config.performance_udp_rates_mbps)
                    ),
                )
        return result

    def _matched_udp_comparison(
        self,
        path: ResolvedPerformancePath,
        directions: list[tuple[str, Endpoint, str, str, str | None]],
        packet_sizes: list[int],
        selected: dict[tuple[str, int, int], dict[str, Any]],
        rejected_profiles: dict[tuple[int, int], list[str]] | None = None,
        *,
        comparison: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Compare the same offered load without replacing capacity measurements.

        Independent calibration can finish at different rates. Additional probes
        therefore back off together and count only pairs with sender telemetry
        and sustainable endpoints in both directions. Every attempt is retained.
        """
        if comparison is None:
            comparison = {
                "forward": [],
                "reverse": [],
                "requested_profiles": 0,
                "incomplete_profiles": 0,
            }
        if isinstance(getattr(self, "_partial_udp_samples", None), dict):
            self._partial_udp_samples["comparison"] = comparison
        adaptive = bool(
            getattr(self.config, "performance_udp_adaptive_calibration", True)
        )
        limit = (
            max(
                1,
                int(
                    getattr(self.config, "performance_udp_calibration_max_attempts", 4)
                ),
            )
            if adaptive
            else 1
        )
        minimum = max(
            1, int(getattr(self.config, "performance_udp_calibration_min_rate_mbps", 1))
        )
        backoff = float(
            getattr(self.config, "performance_udp_calibration_backoff_factor", 0.5)
        )
        for configured_rate in self.config.performance_udp_rates_mbps:
            for size in packet_sizes:
                comparison["requested_profiles"] += 1
                rejected = (rejected_profiles or {}).get((configured_rate, size))
                if rejected:
                    comparison["incomplete_profiles"] += 1
                    comparison["packet_size_rejected_profiles"] = (
                        comparison.get("packet_size_rejected_profiles", 0) + 1
                    )
                    comparison.setdefault("profile_outcomes", []).append(
                        {
                            "configured_rate_mbps": configured_rate,
                            "packet_size": size,
                            "status": "packet-size-rejected",
                            "rejected_directions": rejected,
                        }
                    )
                    continue
                existing = [
                    selected.get((direction, configured_rate, size))
                    for direction, *_ in directions
                ]
                rates = [
                    int(item.get("requested_mbps") or 0) for item in existing if item
                ]
                if len(rates) == 2 and rates[0] == rates[1] and rates[0] > 0:
                    for (direction, *_), sample in zip(
                        directions, existing, strict=True
                    ):
                        comparison[direction].append(
                            {
                                **sample,
                                "comparison_selected": True,
                                "comparison_origin_rate_mbps": configured_rate,
                            }
                        )
                    continue
                rate = min(rates) if rates else int(configured_rate)
                complete = False
                for attempt in range(1, limit + 1):
                    pair = []
                    for (
                        direction,
                        endpoint,
                        source_ip,
                        destination_ip,
                        peer_ip,
                    ) in directions:
                        peer = {"expected_peer_ip": peer_ip} if peer_ip else {}
                        sample = self._udp_measurement(
                            endpoint,
                            source_ip,
                            destination_ip,
                            path.plan.family,
                            rate,
                            size,
                            **peer,
                        )
                        self._annotate_udp_sample(
                            sample,
                            configured_rate=configured_rate,
                            attempted_rate=rate,
                            packet_size=size,
                            attempt=attempt,
                        )
                        sample.update(
                            calibration_selected=True,
                            comparison_selected=False,
                            comparison_origin_rate_mbps=configured_rate,
                        )
                        comparison[direction].append(sample)
                        pair.append(sample)
                    complete = all(
                        udp_sample_assessable(sample)
                        and sample.get("sender_telemetry_available") is True
                        for sample in pair
                    )
                    if complete:
                        for sample in pair:
                            sample["comparison_selected"] = True
                        break
                    if any(
                        sample.get("packet_size_supported") is False for sample in pair
                    ):
                        comparison["packet_size_rejected_profiles"] = (
                            comparison.get("packet_size_rejected_profiles", 0) + 1
                        )
                        break
                    if not adaptive or any(
                        sample.get("sender_telemetry_available") is not True
                        for sample in pair
                    ):
                        break
                    next_rate = max(minimum, int(rate * backoff))
                    if next_rate >= rate:
                        break
                    rate = next_rate
                if not complete:
                    comparison["incomplete_profiles"] += 1
        return comparison
