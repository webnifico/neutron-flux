"""One evidence-based explanation shared by operator-facing report formats.

This module interprets recorded facts for display. It never changes a verdict,
declares an unrecorded root cause, or merges evidence from different endpoints.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from .constants import MIGRATION_DOWNTIME_TOLERANCE_NOTE
from .logical_results import logical_results
from .operator_evidence import evidence_facts, mapping, text
from .performance_analysis import directional_comparison_meaning
from .result_context import normalize_topology_label, result_context
from .terminology import friendly_operator_text


def _details(result: dict[str, Any]) -> dict[str, Any]:
    details = dict(mapping(result.get("reporting_context")))
    details.update(mapping(result.get("details")))
    return details


def is_execution_lane_failure(details: dict[str, Any]) -> bool:
    """Distinguish a stopped execution lane from controller bootstrap failure."""
    if details.get("root_setup_error") is True:
        return False
    phase = str(details.get("failure_phase") or "").lower()
    return "execution" in phase or bool(details.get("root_lane_error"))


def _number(value: Any, unit: str = "", *, places: int = 2) -> str:
    if value is None or isinstance(value, bool):
        return "not recorded"
    try:
        rendered = f"{float(value):,.{places}f}".rstrip("0").rstrip(".")
    except (TypeError, ValueError):
        return "not recorded"
    return rendered + (f" {unit}" if unit else "")


def _udp_profiles(metrics: dict[str, Any], direction: str) -> list[dict[str, Any]]:
    recorded = metrics.get(direction)
    if not isinstance(recorded, list):
        recorded = mapping(metrics.get("comparison")).get(direction)
    if not isinstance(recorded, list):
        return []
    return [
        row
        for row in recorded
        if isinstance(row, dict)
        and row.get("packet_size_supported") is not False
        and row.get("endpoint_limited") is not True
        and row.get("load_valid") is not False
        and row.get("calibration_selected") is not False
    ]


def _udp_profile_line(row: dict[str, Any], direction: str) -> str:
    size = _number(row.get("packet_size"), "bytes")
    offered = row.get("offered_mbps", row.get("requested_mbps"))
    configured = row.get("configured_rate_mbps", offered)
    rate = f"test rate {_number(offered, 'Mbps')}"
    if configured != offered:
        rate += f" (reduced from requested {_number(configured, 'Mbps')})"
    if row.get("receiver_goodput_mbps") is not None:
        delivery = f"receiver delivered {_number(row['receiver_goodput_mbps'], 'Mbps')}"
    elif row.get("achieved_mbps") is not None:
        delivery = f"achieved rate {_number(row['achieved_mbps'], 'Mbps')}"
    elif row.get("mbps") is not None:
        delivery = f"recorded transfer rate {_number(row['mbps'], 'Mbps')}"
    else:
        delivery = "transfer rate not recorded"
    delivery += (
        f" at {_number(row['pps'], 'packets/s')}"
        if row.get("pps") is not None
        else "; packet receive rate not recorded"
    )
    return (
        f"{direction}, UDP payload size {size}, {rate}: "
        f"application loss {_number(row.get('loss_pct'), '%')}; "
        f"{delivery}; "
        f"variation in packet arrival timing {_number(row.get('jitter_ms'), 'ms', places=3)}."
    )


def _udp_origin_rate(row: dict[str, Any]) -> Any:
    for key in (
        "configured_rate_mbps",
        "calibration_origin_rate_mbps",
        "comparison_origin_rate_mbps",
    ):
        if row.get(key) is not None:
            return row[key]
    return None


def _udp_rate_calibrated(metrics: dict[str, Any]) -> bool:
    for direction in ("forward", "reverse"):
        for row in _udp_profiles(metrics, direction):
            rate = row.get("offered_mbps", row.get("requested_mbps"))
            origin = _udp_origin_rate(row)
            try:
                if 0 < float(rate) < float(origin):
                    return True
            except (TypeError, ValueError):
                continue
    return False


def _performance_advisory_story(result: dict[str, Any], story: dict[str, Any]) -> None:
    details = _details(result)
    measurement = details.get("measurement")
    warnings = details.get("warning_reasons") or []
    warnings = warnings if isinstance(warnings, list) else [warnings]
    metrics = mapping(details.get("metrics"))
    if measurement == "udp":
        story["udp_rate_calibrated"] = _udp_rate_calibrated(metrics)
    limited_samples = measurement == "udp" and any(
        isinstance(row, dict) and row.get("endpoint_limited") is True
        for direction in ("forward", "reverse")
        for row in (
            metrics.get(direction) if isinstance(metrics.get(direction), list) else []
        )
    )
    if (
        result.get("status") != "PASS"
        or not measurement
        or not (warnings or details.get("health") == "warning" or limited_samples)
    ):
        return
    rate_notes = []
    receiver_limited = sender_limited = False
    if measurement == "udp":
        for key, direction, sender, receiver in (
            ("forward", "Source → destination", "source VM", "destination VM"),
            ("reverse", "Destination → source", "destination VM", "source VM"),
        ):
            samples = metrics.get(key)
            for row in samples if isinstance(samples, list) else []:
                if not isinstance(row, dict) or row.get("endpoint_limited") is not True:
                    continue
                reason = str(row.get("endpoint_limit_reason") or "")
                offered = row.get("offered_mbps", row.get("configured_rate_mbps"))
                scope = f"{direction}, UDP payload size {_number(row.get('packet_size'), 'bytes')} at {_number(offered, 'Mbps')}"
                if reason == "receiver-overload":
                    receiver_limited = True
                    note = f"{scope}: the {receiver} could not keep up with incoming packets."
                elif reason.startswith("sender"):
                    sender_limited = True
                    note = f"{scope}: the {sender} could not generate the requested traffic rate; it generated {_number(row.get('sender_mbps'), 'Mbps')}."
                else:
                    note = f"{scope}: the measurement was limited by the test VM ({reason.replace('-', ' ') or 'reason not recorded'})."
                origin = _udp_origin_rate(row)
                sustainable = next(
                    (
                        sample.get("offered_mbps", sample.get("requested_mbps"))
                        for sample in _udp_profiles(metrics, key)
                        if sample.get("packet_size") == row.get("packet_size")
                        and origin is not None
                        and _udp_origin_rate(sample) == origin
                    ),
                    None,
                )
                if sustainable is not None:
                    note += f" The usable retry ran at {_number(sustainable, 'Mbps')}."
                note += " This limited attempt was excluded from the network-loss assessment."
                rate_notes.append(note)
    notes = list(dict.fromkeys(rate_notes))
    other_warnings = []
    for warning in warnings:
        value = text(warning)
        if rate_notes and ("endpoint-limited" in value or "endpoint limited" in value):
            continue
        value = re.sub(r"\bforward\b", "source → destination", value, flags=re.I)
        value = re.sub(r"\breverse\b", "destination → source", value, flags=re.I)
        value = value.replace(
            "latency probes observed up to", "Ping replies were missing for up to"
        )
        value = (
            value.replace("packet loss", "of requests")
            if measurement == "latency"
            else value
        )
        other_warnings.append(friendly_operator_text(value).rstrip(".") + ".")
    notes.extend(other_warnings)
    notes = list(dict.fromkeys(notes))
    if not notes:
        notes = [
            "The result records an advisory condition, but its reason was not recorded."
        ]
    story["advisory_summary"] = notes
    story["warnings"] = notes
    story["observed"] += "\nObservation: " + " ".join(notes)
    story["what_happened"] = story["observed"]
    order_warning = any("out of order" in str(value).lower() for value in warnings)
    if measurement == "udp":
        if order_warning:
            story["headline"] = (
                "UDP packets arrived out of order above the advisory tolerance"
            )
            if rate_notes:
                story["headline"] += "; some rates were also limited by the test VMs"
        elif receiver_limited:
            story["headline"] = "UDP receiving VM could not sustain the requested rate"
        elif sender_limited:
            story["headline"] = "UDP sending VM could not generate the requested rate"
        else:
            story["headline"] = "UDP measurement completed with the observations below"
    elif measurement == "latency" and any(
        "packet loss" in str(value).lower() for value in warnings
    ):
        story["headline"] = (
            "Some ping replies were missing during the delay measurements"
        )
    else:
        story["headline"] += "; review the measured advisory below"
    story["kind"] = (
        "measurement-rate-limited" if rate_notes and not other_warnings else "advisory"
    )
    story["why_this_status"] = (
        (
            "The required measurement completed and met the enforced acceptance limits. "
            if details.get("thresholds_enforced") is True
            else "The required measurement completed. "
        )
        + "This observation is advisory under this check's recorded policy, so the result remains PASS."
    )
    if rate_notes:
        story["why_this_status"] += (
            " Only usable-rate measurements were used to assess network loss; the VM-limited attempts are retained separately."
        )
    story["attention"] = True


def _probe_observation(result: dict[str, Any], protocol: str) -> str:
    details = _details(result)
    probe = mapping(details.get("probe"))
    diag = mapping(probe.get("diagnostics"))
    observed = result.get("observed")
    if observed == "blocked":
        if protocol == "TCP" and diag.get("connected") is False:
            observation = "The TCP connection did not open."
        elif protocol == "ICMP":
            observation = "The ping probe received no successful reply."
        else:
            observation = f"The recorded {protocol or 'traffic'} probe could not reach the destination."
    elif observed == "reachable":
        if protocol == "TCP" and diag.get("echo_validated") is True:
            observation = (
                "The TCP connection opened and returned the correct test data."
            )
        elif protocol == "UDP" and (
            diag.get("echo_validated") is True or diag.get("response_validated") is True
        ):
            observation = "The UDP listener returned the correct test data."
        elif protocol == "ICMP":
            match = re.search(
                r"(\d+) packets transmitted,\s*(\d+) (?:packets )?received",
                str(probe.get("stdout") or ""),
            )
            observation = (
                f"The destination replied to {match[2]} of {match[1]} ping requests."
                if match
                else "The recorded ping probe received a successful reply."
            )
        else:
            observation = f"The recorded {protocol or 'traffic'} probe reported successful communication with the destination."
    else:
        return _description(result, "observed")
    if diag.get("converged") is True and diag.get("achieved_consecutive") is not None:
        observation += f" This outcome was confirmed in {diag['achieved_consecutive']} consecutive probes."
    return observation


def _traffic_story(result: dict[str, Any], story: dict[str, Any]) -> None:
    """State the expected flow and actual probe outcome, including negative tests."""
    context = story["context"]
    protocol = str(context.get("protocol") or "").upper()
    flow = f"{protocol} traffic" if protocol else "The tested traffic"
    expected, observed = result.get("expected"), result.get("observed")
    if expected not in {"reachable", "restored", "blocked", "withdrawn", "unreachable"}:
        return
    intended_block = expected in {"blocked", "withdrawn", "unreachable"}
    condition = context.get("action")
    story["expected"] = (
        f"{flow} should be blocked under the stated configuration."
        if intended_block
        else f"{flow} should reach the destination and receive a reply."
    )
    details = _details(result)
    operation = details.get("operation") or result.get("operation")
    reason = {
        "security-deny": "No security-group rule allows this TCP service.",
        "security-allow": "The temporary security-group rule allows this TCP service.",
        "security-restore": "The temporary TCP allow rule has been removed.",
        "server-stop": "The destination VM is stopped, so its service should be unavailable.",
        "server-start": "The destination VM has restarted, so its service should be available again.",
        "static-route-baseline": "The routers do not yet have the static routes required to connect the private networks.",
        "static-route-install": "The required static routes have been added to connect the private networks.",
        "static-route-withdraw": "A required static route has been removed from one router.",
        "static-route-restore": "The removed static route has been restored.",
        "fip-withdraw": "The floating IP has been detached from the destination VM.",
        "fip-return": "The same floating IP has been reattached to the destination VM.",
        "router-interface-remove": "The router interface needed to reach this subnet has been removed.",
        "router-interface-restore": "The router interface needed to reach this subnet has been restored.",
    }.get(str(operation))
    if not reason:
        reason = details.get("expectation_reason")
    if details.get("nat_path") == "self-hairpin":
        reason = "Flux verifies the VM and its own floating-IP mapping."
    if reason:
        reason = friendly_operator_text(reason).rstrip(".")
        story["expected"] += " " + reason[:1].upper() + reason[1:] + "."
    if result.get("status") not in {"PASS", "FAIL", "UNVERIFIED"}:
        return
    story["observed"] = _probe_observation(result, protocol)
    story["what_happened"] = (
        str(condition).rstrip(".") + ". " if condition else ""
    ) + story["observed"]
    status = result.get("status")
    if status == "PASS":
        story["headline"] = (
            f"{protocol or 'Traffic'} blocked as intended"
            if intended_block
            else f"{protocol or 'Traffic'} connectivity restored"
            if expected == "restored"
            else f"{protocol or 'Traffic'} connectivity confirmed"
        )
        story["why_this_status"] = (
            "PASS means the intended block was observed; connectivity was deliberately unavailable for this check."
            if intended_block
            else "PASS means the probe reached the destination and received the required response."
        )
    elif status == "FAIL" and observed in {"reachable", "blocked"}:
        story["headline"] = (
            f"{protocol or 'Traffic'} passed when it should have been blocked"
            if intended_block
            else f"{protocol or 'Traffic'} did not reach the destination as required"
        )
        story["why_this_status"] = (
            "The destination remained reachable when this check required traffic to stop."
            if intended_block
            else "The destination did not return the required successful response."
        )


def _performance_expectation(details: dict[str, Any]) -> str | None:
    measurement = details.get("measurement") or details.get("performance_measurement")
    directions = mapping(details.get("path")).get("directions")
    direction = (
        "in both directions"
        if isinstance(directions, list) and set(directions) == {"forward", "reverse"}
        else "from source to destination"
        if directions == ["forward"]
        else "from destination to source"
        if directions == ["reverse"]
        else "in the selected directions"
    )
    return {
        "tcp-throughput": f"Complete the requested TCP transfers {direction} and record how much data they delivered per second.",
        "latency": f"Measure ping round-trip times {direction} with no test load, then while TCP traffic runs on the same path.",
        "udp": "Send numbered UDP datagrams at the requested packet sizes and rates, then measure delivery and timing variation at the receiver.",
        "mtu-mss": f"Measure the largest packet delivered without fragmentation and record the negotiated TCP segment size {direction}.",
        "asymmetry": "Compare source → destination with destination → source using matching TCP, ping and UDP measurements.",
        "concurrency": "Run one and several TCP connections over the same path and compare their combined transfer rates.",
        "repeatability": "Repeat TCP transfers on the same path and record how much the measured transfer rate varies.",
        "concurrent-path-load": "Run the selected VM-to-VM paths together and record their transfer rates while sharing the network.",
        "fabric-scale": "Run the selected VM-to-VM paths together and record their transfer rates while sharing the network.",
    }.get(measurement)


def _performance_story(result: dict[str, Any], story: dict[str, Any]) -> None:
    details = _details(result)
    measurement = details.get("measurement") or details.get("performance_measurement")
    metrics = mapping(details.get("metrics"))
    if not measurement:
        return
    expectation = _performance_expectation(details)
    if expectation:
        story["expected"] = expectation
    if result.get("status") not in {"PASS", "FAIL", "UNVERIFIED"}:
        return
    summaries = []
    if measurement == "tcp-throughput":
        for key, direction in (
            ("forward", "Source → destination"),
            ("reverse", "Destination → source"),
        ):
            streams = mapping(mapping(metrics.get(key)).get("streams"))
            single = mapping(streams.get("1"))
            if single:
                summaries.append(
                    f"{direction}: median single-connection transfer rate {_number(single.get('median_mbps'), 'Mbps')}"
                )
        bidirectional = mapping(metrics.get("bidirectional"))
        if bidirectional.get("aggregate_mbps") is not None:
            summaries.append(
                f"simultaneous traffic in both directions: combined rate {_number(bidirectional['aggregate_mbps'], 'Mbps')}"
            )
        headline = "TCP transfer rates measured"
    elif measurement == "latency":
        for key, direction in (
            ("forward", "Source → destination"),
            ("reverse", "Destination → source"),
        ):
            idle = mapping(mapping(metrics.get("idle")).get(key))
            loaded = mapping(mapping(metrics.get("loaded")).get(key))
            if idle or loaded:
                summaries.append(
                    f"{direction}: 95th-percentile round-trip time {_number(idle.get('p95_ms'), 'ms')} without test load and {_number(loaded.get('p95_ms'), 'ms')} during TCP load"
                )
        story["limitations"].append(
            "The 95th percentile means 95% of recorded round trips were at or below that time. These are round-trip measurements, not one-way delay."
        )
        headline = "Round-trip delay measured with and without traffic load"
    elif measurement == "udp":
        story["expected"] = (
            "Send numbered UDP datagrams at the requested packet sizes and rates, then measure delivery and timing variation at the receiver."
        )
        for key, direction in (
            ("forward", "Source → destination"),
            ("reverse", "Destination → source"),
        ):
            summaries.extend(
                _udp_profile_line(row, direction) for row in _udp_profiles(metrics, key)
            )
        story["limitations"].append(
            "Measurements limited by the sending or receiving VM are kept as evidence but are excluded from claims about network loss. UDP timing variation is measured at the receiver."
        )
        headline = "UDP delivery and timing measured"
    elif measurement == "asymmetry":
        story["expected"] = (
            "Compare source → destination with destination → source using matching TCP, ping and UDP measurements."
        )
        for key, label, unit in (
            ("throughput_difference_pct", "TCP transfer-rate difference", "%"),
            ("latency_difference_pct", "ping-delay difference", "%"),
            (
                "udp_loss_difference_pct_points",
                "UDP loss difference",
                "percentage points",
            ),
        ):
            if metrics.get(key) is not None:
                summaries.append(f"{label}: {_number(metrics[key], unit)}")
        if metrics.get("udp_compared_profiles") is not None:
            summaries.append(
                f"{metrics['udp_compared_profiles']} UDP packet-size/rate pairs matched for comparison"
            )
        headline = "Traffic directions compared"
    elif measurement == "mtu-mss":
        for key, direction in (
            ("forward", "Source → destination"),
            ("reverse", "Destination → source"),
        ):
            measured = mapping(metrics.get(key))
            mtu = (
                mapping(measured.get("mtu"))
                or mapping(measured.get("mtu_profile"))
                or measured
            )
            if measured:
                summaries.append(
                    f"{direction}: largest tested packet delivered without fragmentation {_number(mtu.get('discovered_mtu'), 'bytes')}; negotiated TCP data-segment sizes {_number(measured.get('client_mss'), 'bytes')} at the client and {_number(measured.get('server_mss'), 'bytes')} at the server"
                )
        story["limitations"].append(
            "MTU is the full IP packet size. TCP segment size is the data carried inside a TCP packet and excludes its IP/TCP headers."
        )
        headline = "Packet size and TCP segment size measured"
    elif measurement == "concurrency":
        story["expected"] = (
            "Run one and several TCP connections over the same path and compare their combined transfer rates."
        )
        for key, direction in (
            ("forward", "Source → destination"),
            ("reverse", "Destination → source"),
        ):
            measured = mapping(metrics.get(key))
            rates = mapping(measured.get("aggregate_mbps_by_stream_count"))
            if rates:
                summaries.append(
                    direction
                    + ": "
                    + ", ".join(
                        f"{count} connection(s) carried {_number(rate, 'Mbps')} combined"
                        for count, rate in rates.items()
                    )
                )
        headline = "Transfer rates compared for one and several TCP connections"
    elif measurement == "repeatability":
        story["expected"] = (
            "Repeat TCP transfers on the same path and record how much the measured transfer rate varies."
        )
        for key, direction in (
            ("forward", "Source → destination"),
            ("reverse", "Destination → source"),
        ):
            value = metrics.get(f"{key}_variation_pct")
            if value is not None:
                summaries.append(
                    f"{direction}: transfer-rate variation {_number(value, '%')}"
                )
        headline = "Variation between repeated TCP transfers measured"
    elif measurement in {"concurrent-path-load", "fabric-scale"}:
        story["expected"] = (
            "Run the selected VM-to-VM paths together and record their transfer rates while sharing the network."
        )
        headline = "Traffic measured across several paths at once"
    else:
        return
    if summaries:
        story["observed"] = (
            "\n".join(summaries) if measurement == "udp" else "; ".join(summaries) + "."
        )
        story["what_happened"] = story["observed"]
    if result.get("status") == "PASS":
        story["headline"] = headline
        story["why_this_status"] = (
            "The required measurement completed and met the enforced limits."
            if details.get("thresholds_enforced") is True
            else "The required measurement completed successfully. The recorded values describe this path, VM placement and test load."
        )


def _packet_size_story(result: dict[str, Any], story: dict[str, Any]) -> None:
    details = _details(result)
    category = result.get("category")
    if category not in {
        "mtu",
        "floating-ip-packet-size",
        "source-nat-packet-size",
        "floating-ip-egress-mtu",
        "floating-ip-egress-fragmentation",
    }:
        return
    mtu = mapping(details.get("mtu_profile"))
    fragmentation = mapping(details.get("fragmentation_profile"))
    story["expected"] = (
        "Check packet delivery at the advertised network MTU, test a larger packet with fragmentation disabled, and record how the path handles that packet."
    )
    if category == "source-nat-packet-size":
        story["expected"] = (
            "Verify connectivity and the translated source address, then measure packet-size limits and delivery when IPv4 fragmentation is permitted through router source NAT."
        )
    elif category == "floating-ip-egress-fragmentation":
        story["expected"] = (
            "Test a packet larger than the no-fragment path limit with IPv4 fragmentation permitted, and record whether it arrives and where fragmentation is supported by evidence."
        )
    if result.get("status") not in {"PASS", "FAIL", "UNVERIFIED"}:
        return
    summaries = []
    if mtu:
        summaries.append(
            f"Advertised packet limit {_number(mtu.get('expected_mtu'), 'bytes')}; largest tested packet delivered without fragmentation {_number(mtu.get('discovered_mtu'), 'bytes')}"
        )
        if mtu.get("pmtud_explanation"):
            summaries.append(
                friendly_operator_text(mtu["pmtud_explanation"]).rstrip(".")
            )
    elif details.get("network_mtu") is not None:
        summaries.append(
            f"Advertised network packet limit {_number(details['network_mtu'], 'bytes')}"
        )
    if category == "floating-ip-egress-fragmentation":
        story["expected"] = (
            "Test a packet larger than the no-fragment path limit with IPv4 fragmentation permitted, and record whether it arrives and where fragmentation is supported by evidence."
        )
    if fragmentation:
        if fragmentation.get("tested_packet_size") is not None:
            summaries.append(
                f"Fragmentation-permitted test packet: {_number(fragmentation['tested_packet_size'], 'bytes')}"
            )
        if fragmentation.get("fragmentation_location_label"):
            summaries.append(
                friendly_operator_text(fragmentation["fragmentation_location_label"])
            )
        if fragmentation.get("capability") == "supported":
            summaries.append(
                "The oversized packet was delivered when fragmentation was permitted"
            )
    if summaries:
        story["observed"] = ". ".join(summaries) + "."
        # Detailed boundary classifications are already readable recorded facts.
        oversized = mapping(mapping(details.get("stages")).get("oversized_rejection"))
        local_rejection = oversized.get("outcome") == "local-mtu-rejected"
        if local_rejection:
            story["observed"] += (
                " The advertised-size packet arrived; the source rejected the larger packet locally before transmission."
            )
            story["limitations"].append(
                "The larger packet did not leave the source VM, so this check does not establish the network's forwarding limit above the advertised MTU or verify network-generated packet-too-big feedback."
            )
        elif not mtu and result.get("message"):
            story["observed"] += " " + friendly_operator_text(result["message"])
        story["what_happened"] = story["observed"]
    if result.get("status") == "PASS":
        story["headline"] = (
            "Packet-size behaviour measured"
            if category != "floating-ip-egress-fragmentation"
            else "IPv4 fragmentation behaviour measured"
        )
        if (
            category == "floating-ip-egress-fragmentation"
            and fragmentation.get("capability") == "supported"
        ):
            story["why_this_status"] = (
                "The fragmentation-permitted probe delivered the test packet and recorded the supported fragmentation behaviour."
            )
        elif category == "floating-ip-egress-fragmentation":
            story["why_this_status"] = (
                "The required fragmentation checks completed and classified the observed behaviour. The recorded capability and test-packet outcome are shown above."
            )
        elif result.get("observed") == "boundary-confirmed":
            story["why_this_status"] = (
                "The advertised-size packet arrived and the larger-packet check completed with the outcome recorded above."
            )
        elif category == "source-nat-packet-size":
            story["why_this_status"] = (
                "The router's translated connection, source-address check and required packet-size measurements completed successfully."
            )
        elif mtu.get("advertised_mtu_contract_status") == "met":
            story["why_this_status"] = (
                "The advertised-size packet arrived with fragmentation disabled, and the required larger-packet checks completed."
            )
        else:
            story["why_this_status"] = (
                "The packet-size assessment completed. The advertised and observed sizes are reported above; a measured MTU difference is recorded as an observation."
            )


def _human_story(result: dict[str, Any], story: dict[str, Any]) -> None:
    """Build full display context from facts without changing the stored contract."""
    context = result_context(result)
    story.update(
        context=context,
        purpose=context.get("purpose"),
        path=context.get("path"),
        action=context.get("action"),
        timing=context.get("timing"),
        placement=context.get("placement"),
        recorded_message=story["what_happened"],
    )
    status = str(result.get("status") or "")
    _traffic_story(result, story)
    _performance_story(result, story)
    _packet_size_story(result, story)
    if status.startswith("BLOCKED") or status == "NOT_RUN_CANCELLED":
        story["observed"] = (
            "This check did not run. It recorded no traffic outcome for this check."
        )
        story["what_happened"] = story["observed"]
        story["why_this_status"] = (
            "The run was cancelled before this check executed."
            if status == "NOT_RUN_CANCELLED"
            else "The required setup or prerequisite was unavailable, so Flux could not execute this check."
        )
    elif status in {"SKIP", "NOT_APPLICABLE"}:
        story["observed"] = "No traffic probe ran for this check."
        story["what_happened"] = story["observed"]
        story["why_this_status"] = (
            "The check was not applicable to the recorded configuration."
            if status == "NOT_APPLICABLE"
            else "The check was skipped under the recorded applicability conditions."
        )
    if result.get("status") not in {"PASS", "FAIL", "UNVERIFIED"}:
        return
    details = _details(result)
    if result.get("category") == "floating-ip-egress-source-address":
        expected = details.get("floating_ip") or mapping(
            mapping(details.get("address_path")).get("source")
        ).get("floating_ip")
        actual = details.get("translated_source_ip_observed_by_provider") or mapping(
            details.get("address_path")
        ).get("observed_source_ip")
        story["expected"] = (
            f"The public-side VM should see the private VM's floating IP as the source address ({expected or 'address not recorded'})."
        )
        story["observed"] = (
            f"The public-side VM recorded source address {actual or 'not recorded'}."
        )
        story["what_happened"] = story["observed"]
        if result.get("status") == "PASS":
            story["headline"] = "Outbound traffic used the assigned floating IP"
            story["why_this_status"] = (
                "The observed source address matched the VM's assigned floating IP."
            )
    if (
        result.get("category") == "router-interface-lifecycle"
        and result.get("expected") == "lifecycle-complete"
    ):
        story["expected"] = (
            "Traffic should work with the router interface attached, stop after its removal, and work again after the same interface is restored. OpenStack must confirm both changes."
        )
        if result.get("status") == "PASS":
            story["headline"] = (
                "Removing the router interface stopped traffic; restoring it recovered traffic"
            )
            stages = mapping(details.get("stages"))
            descriptions = []
            for key, success_text in (
                (
                    "baseline",
                    "TCP reached the destination before the router interface was removed",
                ),
                (
                    "remove_attachment",
                    "OpenStack confirmed that the router interface was removed",
                ),
                (
                    "withdrawn_connectivity",
                    "TCP could no longer reach the destination while the interface was absent",
                ),
                (
                    "restore_attachment",
                    "OpenStack confirmed that the same router interface was restored",
                ),
                (
                    "restored_connectivity",
                    "TCP reached the destination again after the interface was restored",
                ),
            ):
                stage = mapping(stages.get(key))
                if stage.get("status") == "PASS":
                    descriptions.append(success_text + ".")
                elif stage:
                    descriptions.append(
                        f"{success_text.split(' before ')[0]}: this stage was recorded as {stage.get('status', 'unverified')}."
                    )
            story["observed"] = " ".join(descriptions) or friendly_operator_text(
                result.get("message") or "The recorded interface lifecycle completed."
            )
            story["what_happened"] = story["observed"]
            story["why_this_status"] = (
                "All required stages passed: initial reachability, confirmed interface removal, intended traffic block, confirmed restoration and recovered traffic."
            )
    if (
        result.get("category") == "controller-bootstrap"
        and result.get("status") == "PASS"
    ):
        story["headline"] = "Flux controller access confirmed"
        story["expected"] = (
            "The runner must be able to use the controller's OpenStack-provided network connection."
        )
        story["observed"] = friendly_operator_text(
            result.get("message") or "Controller access was recorded as usable."
        )
        story["what_happened"] = story["observed"]
        story["why_this_status"] = (
            "The controller network passed the required runner-access check."
        )


def _migration_story(result: dict[str, Any], story: dict[str, Any]) -> None:
    if result.get("category") != "compute-placement" or result.get("status") not in {
        "PASS",
        "FAIL",
        "UNVERIFIED",
    }:
        return
    details = _details(result)
    if details.get("cloud_operation_outcome") == "NOT_SUBMITTED":
        story.update(
            headline="Migration was not submitted",
            expected="Complete the pre-migration safety checks before requesting the VM move.",
            observed=story["recorded_message"],
            what_happened=story["recorded_message"],
            why_this_status="A required pre-migration safety check could not complete, so Flux did not submit the VM move. This result does not measure traffic during migration.",
            next_check="Restore the recorded API or prerequisite availability, verify the current VM state, then rerun the migration scope.",
        )
        return
    expected = result.get("expected")
    transitions = details.get("transitions") or details.get("related_transitions") or []
    if transitions and all(
        isinstance(transition, dict)
        and transition.get("method") == "endpoint-recreation"
        for transition in transitions
    ):
        story["expected"] = (
            "Recreate one endpoint on the required host and verify the opposite compute placement before network checks continue."
        )
        succeeded = result.get("status") == "PASS"
        story["headline"] = (
            "Recreated endpoint placement verified"
            if succeeded
            else "Endpoint recreation requires review"
        )
        story["observed"] = (
            "One endpoint was recreated on the required host and placement was verified."
            if succeeded
            else friendly_operator_text(
                result.get("message")
                or "The endpoint recreation could not be verified."
            )
        )
        story["what_happened"] = story["observed"]
        story["why_this_status"] = (
            "The required placement was verified after endpoint recreation. This check did not exercise migration or traffic continuity during migration."
            if succeeded
            else "The recorded endpoint-recreation result did not establish the required placement."
        )
        return
    if expected == "fresh-functional-matrix":
        story["expected"] = (
            "The selected VM-to-VM protocol checks and applicable external egress checks must pass again before Flux submits the VM move."
        )
        if result.get("status") == "PASS":
            story["headline"] = (
                "All selected paths were reachable immediately before the VM move"
            )
            story["observed"] = (
                "The selected VM-to-VM protocol checks and applicable external egress checks passed immediately before the VM move."
            )
            story["what_happened"] = story["observed"]
            story["why_this_status"] = (
                "The pre-migration safety checks found the required connectivity before any migration request was submitted."
            )
        return
    moves = details.get("transitions") or details.get("related_transitions")
    moves = moves if isinstance(moves, list) else [details]
    move_sentences = []
    for value in moves:
        move = mapping(value)
        source, target = (
            move.get("source_host"),
            move.get("destination_host") or move.get("target_host"),
        )
        if not source or not target:
            continue
        attempts = move.get("attempts") or details.get("attempts") or []
        attempt = (
            mapping(attempts[-1]) if isinstance(attempts, list) and attempts else {}
        )
        label = move.get("endpoint") or attempt.get("endpoint")
        if not label:
            label = next(
                (
                    item.get("label")
                    for item in story["context"].get("moves", [])
                    if item.get("source_host") == source
                    and item.get("destination_host") == target
                ),
                None,
            )
        label = (
            friendly_operator_text(normalize_topology_label(label))
            if label
            else "The selected VM"
        )
        verb = "moved" if move.get("confirmed") is True else "was requested to move"
        move_sentences.append(f"{label} {verb} from {source} to {target}.")
    if move_sentences:
        story["migration_move"] = " ".join(move_sentences)
        story["what_happened"] = story["migration_move"]
    assessments = _migration_assessments(details)
    if assessments:
        # Context joins can expose the same assessment at two paths. Preserve
        # distinct endpoint records even when their rendered outcomes agree.
        unique_assessments = []
        for assessment in assessments:
            if assessment not in unique_assessments:
                unique_assessments.append(assessment)
        components = []
        phrases = {
            "vm_placement": {
                "PASS": "the VM reached the required host",
                "FAIL": "the VM did not reach the required host",
                "UNVERIFIED": "the VM's final host was not verified",
            },
            "migration_completion": {
                "PASS": "migration completion was verified",
                "FAIL": "the required migration completion checks failed",
                "UNVERIFIED": "migration completion was not verified",
            },
            "tcp_session": {
                "PASS": "the TCP connection stayed established",
                "FAIL": "the TCP connection did not survive",
                "UNVERIFIED": "TCP connection survival was not verified",
            },
            "traffic_recovery": {
                "PASS": "traffic recovered after the move",
                "FAIL": "traffic did not recover",
                "UNVERIFIED": "traffic recovery was not verified",
            },
        }
        descriptions = []
        for assessment in unique_assessments:
            outcomes = mapping(assessment.get("migration_outcomes"))
            description = "; ".join(
                phrases[key].get(
                    outcomes.get(key), f"{key.replace('_', ' ')} was not verified"
                )
                for key in phrases
            )
            icmp = mapping(assessment.get("icmp"))
            window = (
                "from monitor readiness through the post-migration recovery checks"
                if assessment.get("phase_evidence_complete") is True
                else "across the recorded monitoring window"
            )
            if icmp.get("lost") is not None and icmp.get("samples") is not None:
                description += f"; {icmp['lost']} of {icmp['samples']} scheduled ping observations failed {window}"
            udp = mapping(assessment.get("udp"))
            response = mapping(udp.get("response"))
            udp_loss = response.get("loss_pct", assessment.get("udp_loss_pct"))
            if udp_loss is not None:
                description += (
                    f"; UDP datagram loss {_number(udp_loss, '%')} in the same window"
                )
            descriptions.append(description)
        for index, description in enumerate(descriptions, 1):
            components.append(
                (f"Assessment {index}: " if len(descriptions) > 1 else "")
                + (description[:1].upper() + description[1:])
                + "."
            )
        story["observed"] = " ".join(components)
        story["what_happened"] = (
            story.get("migration_move", "") + " " + story["observed"]
        ).strip()
        story["expected"] = (
            "The VM must reach the required host, migration completion must be verified, the established TCP connection must survive, and traffic must recover after the move. Interruption measurements are reported separately."
        )
        if result.get("status") == "PASS":
            story["headline"] = (
                "VM move, TCP connection survival and traffic recovery verified"
            )
            story["why_this_status"] = (
                "The required host placement, migration completion, TCP connection survival and traffic recovery were verified."
            )
    elif expected in {"live-migration-complete", "cold-migration-complete"}:
        story["expected"] = (
            "Verify the VM move through its final compute placement and the required OpenStack completion checks."
        )
        if result.get("status") == "PASS":
            story["headline"] = "VM move completed on the required host"
            story["observed"] = story.get("migration_move") or story["recorded_message"]
            story["why_this_status"] = (
                "The VM move and its required completion checks passed. Traffic-continuity measurements are reported in the associated continuity check."
            )
    elif (
        expected in {"placement-achieved", "requested-placement-verified"}
        and result.get("status") == "PASS"
    ):
        story["headline"] = "Required VM placement achieved"
        story["expected"] = (
            "Verify that the VM reached the requested compute placement and complete the associated migration checks."
        )
        story["observed"] = story["recorded_message"]
        story["why_this_status"] = (
            "The recorded placement check met the required placement. Detailed continuity evidence is available in the associated migration result."
        )


def _description(result: dict[str, Any], key: str) -> str:
    name = "expectation" if key == "expected" else "observation"
    contract = mapping(mapping(result.get("contract")).get(name))
    value = contract.get("description") or result.get(key)
    if key == "expected":
        value = {
            "requested-placement-verified": "Verify that the VM reaches the requested compute host.",
            "lifecycle-complete": "Verify the initial state, the requested change and connectivity recovery after restoration.",
            "profile-complete": "Complete the required connectivity and packet-size measurements for this path.",
            "provider-observes-floating-ip": "Verify that the public-side VM sees the private VM's floating IP as the outbound source address.",
            "fragmentation-behaviour-classified": "Record whether the oversized packet arrives when fragmentation is permitted and where fragmentation is supported by evidence.",
        }.get(str(result.get(key)), value)
    return friendly_operator_text(normalize_topology_label(value or "Not recorded"))


def _migration_port_failure_story(
    result: dict[str, Any], story: dict[str, Any]
) -> None:
    """Explain a failed port contract without turning it into a traffic failure."""
    if result.get("category") != "compute-placement" or result.get("status") != "FAIL":
        return
    details = _details(result)
    continuity = mapping(details.get("continuity"))
    assessment = mapping(details.get("completion_assessment")) or mapping(
        continuity.get("completion_assessment")
    )
    checks = mapping(assessment.get("checks"))
    if checks.get("port_binding_verified") is not False:
        return
    # A mixed failure still needs the complete generic migration explanation.
    if any(
        value is False
        for key, value in checks.items()
        if key != "port_binding_verified"
    ):
        return
    if any(
        any(
            reason != "the migration did not complete successfully"
            for reason in assessment.get("transport_failure_reasons") or []
        )
        or any(
            mapping(assessment.get("migration_outcomes")).get(key) == "FAIL"
            for key in ("vm_placement", "tcp_session", "traffic_recovery")
        )
        for assessment in _migration_assessments(details)
    ):
        return
    nova_completed = checks.get("migration_record_verified") is True
    prefix = "Nova migration completion was verified. " if nova_completed else ""
    explanation = (
        "The required Neutron port binding or ACTIVE-state check failed. "
        "This does not by itself establish a traffic interruption."
    )
    story.update(
        kind="migration-port-validation-failed",
        headline="Migration port binding or state validation failed",
        what_happened=prefix + explanation + " " + story["observed"],
        why_this_status=(
            "The recorded FAIL is retained because the required Neutron port validation failed. "
            + prefix
            + "Read the port-state evidence separately from the recorded TCP, ICMP and UDP continuity measurements."
        ),
        next_check=(
            "Compare each port's recorded binding host and status with the destination compute. "
            "Investigate the failed Neutron port check and correlate it with Nova completion and guest connectivity. "
            "Do not resubmit a VM move solely because a port validation failed."
        ),
    )
    for port_id, value in mapping(details.get("ports")).items():
        port = mapping(value)
        story["facts"].append(
            {
                "label": f"Neutron port {port_id}",
                "value": (
                    f"role={port.get('role', 'not recorded')}; "
                    f"status={port.get('status', 'not recorded')}; "
                    f"binding host={port.get('binding_host_id', 'not recorded')}"
                ),
            }
        )


def needs_attention(result: dict[str, Any]) -> bool:
    return (
        result.get("status") not in {"PASS", "NOT_APPLICABLE", "SKIP"}
        or mapping(result.get("details")).get("health") == "warning"
        or bool(mapping(result.get("details")).get("warning_reasons"))
        or bool(migration_interruption_observations(result))
    )


def _migration_assessments(details: dict[str, Any]) -> list[dict[str, Any]]:
    assessments = []
    if isinstance(details.get("migration_outcomes"), dict):
        assessments.append(details)
    continuity = mapping(details.get("continuity"))
    if isinstance(continuity.get("migration_outcomes"), dict):
        assessments.append(continuity)
    transitions = details.get("transitions") or details.get("related_transitions")
    for transition in transitions if isinstance(transitions, list) else []:
        assessment = mapping(mapping(transition).get("continuity_assessment"))
        if isinstance(assessment.get("migration_outcomes"), dict):
            assessments.append(assessment)
    return assessments


def migration_interruption_observations(result: dict[str, Any]) -> list[str]:
    """Read explicit observation records without reinterpreting historical FAILs."""
    status = str(result.get("status") or "")
    if status.startswith(("BLOCKED", "NOT_RUN")) or status in {
        "SKIP",
        "NOT_APPLICABLE",
    }:
        return []
    details = _details(result)
    reasons = []
    for assessment in [details, *_migration_assessments(details)]:
        values = assessment.get("interruption_observations")
        if isinstance(values, list):
            reasons.extend(_interruption_reason(value) for value in values if value)
        elif (
            mapping(assessment.get("migration_outcomes")).get("interruption_tolerance")
            == "OBSERVATION"
        ):
            reasons.extend(
                _interruption_reason(value)
                for value in assessment.get("tolerance_failure_reasons") or []
            )
    return list(dict.fromkeys(reasons))


def _location(result: dict[str, Any]) -> list[dict[str, str]]:
    details = _details(result)
    path = mapping(details.get("path"))
    rows = []
    for role in ("source", "destination"):
        display = result.get(role)
        if isinstance(display, dict):
            display = display.get("label") or display.get("ip")
        address = path.get(f"{role}_ip") or result.get(f"{role}_ip")
        host = path.get(f"{role}_compute_host") or details.get(f"{role}_compute_host")
        zone = path.get(f"{role}_availability_zone") or details.get(
            f"{role}_availability_zone"
        )
        parts = [
            friendly_operator_text(
                normalize_topology_label(display or address or "Endpoint not recorded")
            )
        ]
        if address and str(address) not in parts[0]:
            parts.append(str(address))
        if host:
            parts.append(f"host {host}")
        if zone:
            parts.append(f"AZ {zone}")
        if display or address or host or zone:
            rows.append({"label": role.title(), "value": " · ".join(parts)})
    scope = mapping(result.get("host_scope"))
    if scope.get("label"):
        rows.append({"label": "Test scope", "value": str(scope["label"])})
    if scope.get("requested_pair"):
        rows.append(
            {"label": "Requested host pair", "value": str(scope["requested_pair"])}
        )
    stage = path.get("stage") or details.get("stage")
    if stage:
        rows.append(
            {"label": "Measurement stage", "value": str(stage).replace("-", " ")}
        )
    return rows


def _probe_story(result: dict[str, Any], story: dict[str, Any]) -> None:
    details = _details(result)
    probe = mapping(details.get("tcp_baseline")) or mapping(details.get("probe"))
    diag = mapping(probe.get("diagnostics"))
    protocol = str(
        details.get("protocol")
        or probe.get("protocol")
        or ("tcp" if details.get("tcp_baseline") else "")
    ).lower()
    phase = diag.get("failure_phase")
    if phase:
        names = {
            "connect": "UDP peer selection" if protocol == "udp" else "TCP connection",
            "send": "Sending application data",
            "send-peer-request": "Sending the peer request",
            "recv": "Waiting for a reply",
            "receive": "Waiting for a reply",
            "receive-peer-response": "Waiting for the peer reply",
            "validate": "Validating the reply",
            "validate-peer-response": "Validating the peer reply",
            "echo-validation": "Validating the echo",
            "socket-create": "Creating the probe socket",
        }
        step = names.get(str(phase), str(phase).replace("-", " ").capitalize())
        timed_out = diag.get("error_type") in {"TimeoutError", "timeout"}
        story["headline"] = f"{step} {'timed out' if timed_out else 'failed'}"
        story["what_happened"] = (
            f"{story['headline']}"
            + (
                f" on port {diag['destination_port']}"
                if diag.get("destination_port")
                else ""
            )
            + (
                f" ({probe['attempts']} recorded attempt(s))"
                if probe.get("attempts")
                else ""
            )
            + "."
        )
        story["observed"] = story["what_happened"]
        story["kind"] = (
            "connection-failed" if phase == "connect" else "probe-step-failed"
        )
        if phase == "connect" and protocol != "udp":
            story["next_check"] = (
                "Repeat the same flow and capture TCP at both VMs. Find whether the SYN leaves the source, reaches the destination, and receives a reply; inspect routing, translation and filtering at the missing step."
            )
        elif phase in {
            "recv",
            "receive",
            "validate",
            "echo-validation",
            "receive-peer-response",
            "validate-peer-response",
        }:
            story["next_check"] = (
                "Check the destination listener and its reply, then the return route and filtering. Capture this flow at both VMs; later listener snapshots alone do not show where the failed request or reply was lost."
            )
        else:
            story["next_check"] = (
                "Check the recorded socket error and source address/interface, then repeat this exact probe."
            )
        if (
            details.get("tcp_baseline")
            and details.get("mtu_profile") is None
            and details.get("fragmentation_profile") is None
        ):
            story["expected"] = (
                "Establish the translated TCP flow to the provider observer, verify its source identity, then measure path MTU and fragmentation."
            )
            story["why_this_status"] = (
                "The baseline connection failed before packet-size testing. MTU and fragmentation were not measured."
            )
            story["observed"] += " MTU and fragmentation were not measured."
        if probe.get("attempts") == 1:
            story["limitations"].append(
                "Only one attempt was recorded; persistence of the failure is not established."
            )
    elif result.get("expected") == "blocked" and result.get("observed") == "reachable":
        story.update(
            kind="isolation-failed",
            headline="Traffic passed when isolation was expected",
            next_check="Check the exact source/destination ports, applied security groups and router state for the isolation step. Compare the allowed and blocked phases of this test.",
        )


def _unverified_story(result: dict[str, Any], story: dict[str, Any]) -> None:
    details = _details(result)
    policy = mapping(details.get("routing_policy"))
    metrics = mapping(details.get("metrics"))
    measurement = details.get("measurement")
    if (
        policy.get("expectation") == "observation"
        or result.get("expected") == "observation"
    ):
        story.update(
            kind="routing-expectation-missing",
            headline="Routing expectation not declared",
            why_this_status="Flux observed the traffic, but has no declared rule saying this path must connect or must be isolated. Neither PASS nor FAIL is justified.",
            next_check="Confirm the intended routing and verify the path manually. Missing routing metadata alone does not establish expected reachability or isolation, so Flux retains this result as an observation.",
        )
        if policy.get("reason"):
            story["facts"].append(
                {
                    "label": "Reason no routing verdict was assigned",
                    "value": text(policy["reason"]),
                }
            )
    elif measurement == "asymmetry":
        story.update(
            kind="comparison-incomplete",
            headline="Forward/reverse comparison is incomplete",
            why_this_status="The recorded evidence does not support every requested direction comparison. Read the individual TCP, latency and UDP results separately; this comparison does not establish packet loss.",
            next_check="Compare the recorded directions at matching packet sizes and eligible send rates. Repeat the unmatched profiles at a rate both endpoints can sustain.",
        )
        for key, label in (
            ("udp_compared_profiles", "Matched UDP profiles"),
            ("udp_unmatched_profiles", "Unmatched UDP profiles"),
        ):
            if key in metrics:
                story["facts"].append({"label": label, "value": str(metrics[key])})
    elif result.get("observed") == "local-mtu-rejected":
        story.update(
            kind="local-mtu-limit",
            headline="The source rejected the packet before transmission",
            why_this_status="A local interface or route/PMTU constraint prevented this probe from measuring the current end-to-end MTU.",
            next_check="Review the source interface MTU and route lookup, including cached PMTU. Repeat after refreshing the route/PMTU state and confirm that the packet actually leaves the VM.",
        )
    elif measurement == "udp":
        story.update(
            kind="measurement-incomplete",
            headline="UDP measurement cannot be fully graded",
            next_check="Review eligible samples separately from endpoint-limited calibration attempts. Resolve the recorded sender/receiver limit or missing telemetry, then repeat the affected profiles.",
        )


def _expected_block_story(result: dict[str, Any], story: dict[str, Any]) -> None:
    expected = result.get("expected")
    if result.get("observed") != "blocked" or expected not in {
        "blocked",
        "withdrawn",
        "unreachable",
    }:
        return
    story["kind"] = (
        "expected-withdrawal" if expected == "withdrawn" else "expected-isolation"
    )
    _traffic_story(result, story)


def _interruption_reason(value: Any) -> str:
    """Clarify legacy display wording without altering saved measurements."""
    return (
        text(value)
        .replace("ICMP loss", "ICMP failed observations")
        .replace("confirmed outage lower bound", "sampled failed-observation span")
    )


def explain_result(result: dict[str, Any]) -> dict[str, Any]:
    details = _details(result)
    status = str(result.get("status") or "UNKNOWN")
    warnings = details.get("warning_reasons") or []
    warnings = warnings if isinstance(warnings, list) else [warnings]
    message = friendly_operator_text(
        normalize_topology_label(
            text(result.get("message") or _description(result, "observed"), 5000)
        )
    )
    if details.get("nat_path") == "self-hairpin":
        message = message.replace(
            "Flux owns and verifies both private endpoints and floating-IP mappings on the same external subnet",
            "Flux verifies the VM and its own floating-IP mapping",
        )
    story: dict[str, Any] = {
        "kind": "passed",
        "headline": "Expected behaviour observed",
        "what_happened": message,
        "expected": _description(result, "expected"),
        "observed": _description(result, "observed"),
        "why_this_status": "The recorded check met its expectation.",
        "next_check": "No follow-up required for this check.",
        "location": _location(result),
        "facts": evidence_facts(result),
        "warnings": [text(value, 1800) for value in warnings],
        "limitations": [],
        "attention": needs_attention(result),
    }
    metrics = mapping(details.get("metrics"))
    if details.get("measurement") == "asymmetry":
        for component, label in (
            ("tcp", "TCP"),
            ("latency", "Latency"),
            ("udp", "UDP"),
        ):
            meaning = directional_comparison_meaning(metrics, component)
            if meaning:
                story["facts"].append(
                    {
                        "label": label + " directional comparison",
                        "value": meaning,
                    }
                )
    if status == "PASS" and warnings:
        story.update(
            kind="passed-with-advisory",
            headline="Passed with an advisory",
            why_this_status="The check met its expectation; the recorded advisory still requires review.",
            next_check="Review the advisory and its supporting evidence before accepting this coverage.",
        )
    if status == "FAIL":
        story.update(
            kind="check-failed",
            headline="Expected behaviour was not observed",
            why_this_status="The recorded observation contradicts this check's expectation.",
            next_check="Repeat the affected check with the same topology and compare its expected and observed state. Start with the endpoint and probe facts below.",
        )
        story["limitations"].append(
            "The cause is not established: this failed check does not identify the faulty network component."
        )
        if details.get("measurement"):
            story["next_check"] = (
                "Compare the measured values with the enforced thresholds below, using eligible samples only. Repeat with the same load and endpoint placement."
            )
        elif result.get("category") == "compute-placement":
            story["next_check"] = (
                "Check requested versus observed hosts, the Nova migration record, port binding, and continuity evidence. A completed migration alone does not prove uninterrupted traffic."
            )
    elif status == "ERROR":
        story.update(
            kind="execution-error",
            headline="Flux could not complete the check",
            why_this_status="The probe, API request or orchestration failed. This result does not establish a network pass or failure.",
            next_check="Resolve the recorded command, API or probe error below, then repeat the affected check.",
        )
        story["limitations"].append(
            "Network behaviour was not fully assessed by this check."
        )
        for key in ("error", "exception", "stderr", "error_message"):
            if details.get(key):
                story["facts"].append(
                    {"label": "Execution error", "value": text(details[key], 4000)}
                )
    elif status == "UNVERIFIED":
        story.update(
            kind="measurement-incomplete",
            headline="Evidence is insufficient for a verdict",
            why_this_status="The check did not record enough authoritative evidence to establish its expectation.",
            next_check="Resolve the measurement gap described below, then repeat the affected check.",
        )
        _unverified_story(result, story)
    elif status.startswith("BLOCKED"):
        prerequisite = (
            details.get("root_setup_result_id")
            or details.get("dependent_on_incident_id")
            or details.get("root_incident_id")
        )
        story.update(
            kind="prerequisite-blocked",
            headline="Check did not run: prerequisite unavailable",
            why_this_status=message,
            next_check="Resolve the named setup/prerequisite failure first, then rerun this scope.",
        )
        if prerequisite:
            story["facts"].append(
                {"label": "Blocking result or incident", "value": str(prerequisite)}
            )
        else:
            story["limitations"].append(
                "No blocking result ID was recorded; the recorded prerequisite message is shown above."
            )
    elif status == "NOT_RUN_CANCELLED":
        story.update(
            kind="cancelled",
            headline="Check did not run: run was cancelled",
            why_this_status=message,
            next_check="Rerun the cancelled scope if this coverage is still required.",
        )
    elif status in {"SKIP", "NOT_APPLICABLE"}:
        story.update(
            kind="not-applicable",
            headline="Check was not applicable or supported",
            why_this_status=message,
            next_check="No repair is implied. Review the stated applicability requirement if this coverage is required.",
        )
    elif status == "PASS" and details.get("mtu_advisory"):
        story.update(
            kind="advisory",
            headline="MTU difference recorded as an observation",
            why_this_status="The MTU observation completed. A difference between advertised and observed packet sizes does not block migration or independent tests.",
            next_check="Compare the advertised, observed and post-migration MTU evidence alongside the connectivity results.",
        )
    elif status == "PASS" and details.get("health") == "warning":
        story.update(
            kind="advisory",
            headline="Check passed with a performance advisory",
            why_this_status="The measurement met its grading contract, but recorded an advisory condition. The warning is not a failed validation.",
            next_check="Review the advisory values and sample eligibility below. Repeat under comparable load if the observed level is unacceptable for this environment.",
        )
    elif status != "PASS":
        story.update(
            kind="unknown-status",
            headline="Result status is not recognized",
            why_this_status="No interpretation is available for this status; the original evidence is retained.",
            next_check="Check the tool/result version and the recorded status before assigning a verdict.",
        )
    _human_story(result, story)
    _performance_advisory_story(result, story)
    if status == "FAIL":
        _probe_story(result, story)
        if result.get("category") == "compute-placement":
            story["next_check"] = (
                "Check requested versus observed hosts, the Nova migration record, port binding, and continuity evidence. A completed migration alone does not prove uninterrupted traffic."
            )
    elif status == "UNVERIFIED":
        _unverified_story(result, story)
    if status == "PASS":
        _expected_block_story(result, story)
    if details.get("thresholds_enforced") is not None:
        story["facts"].append(
            {
                "label": "Performance thresholds enforced",
                "value": "Yes"
                if details["thresholds_enforced"]
                else "No — advisory thresholds",
            }
        )
    if result.get("operator_diagnostic_note"):
        story["limitations"].append(str(result["operator_diagnostic_note"]))
    if status in {"FAIL", "ERROR"} and not (
        details.get("diagnostic_snapshot") or result.get("operator_diagnostics")
    ):
        story["limitations"].append(
            "No guest diagnostic snapshot is embedded for this result; only the recorded probe/API evidence is available."
        )
    assessments = _migration_assessments(details)
    _migration_story(result, story)
    _migration_port_failure_story(result, story)
    observations = migration_interruption_observations(result)
    for assessment in assessments:
        outcomes = assessment["migration_outcomes"]
        icmp = mapping(assessment.get("icmp"))
        samples = icmp.get("raw_samples")
        samples = samples if isinstance(samples, list) else []
        deadline_expirations = sum(
            isinstance(sample, dict)
            and sample.get("ok") is False
            and sample.get("timed_out") is True
            for sample in samples
        )
        if deadline_expirations:
            story["facts"].append(
                {
                    "label": "ICMP probe deadline expirations",
                    "value": str(deadline_expirations),
                }
            )
            deadline = mapping(assessment.get("thresholds")).get("probe_deadline_s")
            if deadline is not None:
                story["facts"].append(
                    {"label": "ICMP probe deadline (seconds)", "value": str(deadline)}
                )
            deadline_note = "An ICMP probe deadline expiry records no reply within the probe budget; it does not distinguish packet loss, a later reply, or guest scheduling delay. "
            deadline_note += (
                "Interruption tolerance levels are observations under this recorded policy."
                if outcomes.get("interruption_tolerance") == "OBSERVATION"
                or assessment.get("packet_loss_is_advisory_after_recovery") is True
                else "The recorded failure limits still apply."
            )
            story["limitations"].append(deadline_note)
        phase_evidence = mapping(assessment.get("phase_evidence"))
        if phase_evidence.get("verified") is True:
            phases = mapping(phase_evidence.get("phases"))
            for key, label in (
                ("migration", "Migration"),
                ("post_migration", "Post-migration"),
            ):
                measured = mapping(mapping(phases.get(key)).get("icmp"))
                if measured.get("samples") is not None:
                    story["facts"].append(
                        {
                            "label": f"{label} ICMP failed observations",
                            "value": f"{measured.get('lost', 'unknown')}/{measured['samples']}",
                        }
                    )
                delivered = mapping(mapping(phases.get(key)).get("udp"))
                if delivered.get("verified") is True:
                    story["facts"].append(
                        {
                            "label": f"{label} UDP datagrams not delivered",
                            "value": f"{delivered.get('lost', 'unknown')}/{delivered.get('sent', 'unknown')}",
                        }
                    )
        for key, label in (
            ("vm_placement", "VM placement"),
            ("migration_completion", "Migration completion"),
            ("tcp_session", "Established TCP session"),
            ("traffic_recovery", "Traffic recovered"),
            ("interruption_tolerance", "Interruption tolerance"),
        ):
            story["facts"].append(
                {"label": label, "value": str(outcomes.get(key, "UNVERIFIED"))}
            )
        story["facts"].append(
            {
                "label": "Interruption observation tolerance levels"
                if outcomes.get("interruption_tolerance") == "OBSERVATION"
                or assessment.get("packet_loss_is_advisory_after_recovery") is True
                else "Enforced interruption limits",
                "value": text(assessment.get("evaluated_thresholds")),
            }
        )
        reasons = [
            _interruption_reason(value)
            for value in assessment.get("tolerance_failure_reasons") or []
        ]
        if reasons:
            story["facts"].append(
                {"label": "Interruption limits exceeded", "value": "; ".join(reasons)}
            )
            story["limitations"].append(
                "Consecutive missed probes define a sampled failed-observation span; they do not prove a continuous physical outage between samples."
            )
        if (
            outcomes.get("migration_completion") == "UNVERIFIED"
            and status == "UNVERIFIED"
        ):
            story.update(
                kind="migration-completion-unverified",
                headline="VM handoff observed; migration completion unverified",
                next_check="Reconcile the exact new Nova migration record and placement evidence. Do not resubmit a VM that already moved.",
            )
    interruption_failures = [
        assessment
        for assessment in assessments
        if assessment["migration_outcomes"].get("interruption_tolerance") == "FAIL"
    ]
    successful_components = bool(assessments) and all(
        all(
            assessment["migration_outcomes"].get(key) == "PASS"
            for key in (
                "vm_placement",
                "migration_completion",
                "tcp_session",
                "traffic_recovery",
            )
        )
        and not assessment.get("transport_failure_reasons")
        for assessment in assessments
    )
    if status == "PASS" and assessments and not successful_components:
        story.update(
            kind="migration-evidence-conflict",
            headline="Migration evidence requires review",
            why_this_status="A recorded migration component failed or remained unverified. The recorded result is retained; this evidence does not establish successful placement, completion, TCP survival and traffic recovery for every assessment.",
            next_check="Review every migration assessment and reconcile its component outcomes with the recorded result.",
            attention=True,
        )
    if status == "FAIL" and interruption_failures and successful_components:
        reasons = list(
            dict.fromkeys(
                _interruption_reason(value)
                for assessment in interruption_failures
                for value in assessment.get("tolerance_failure_reasons") or []
            )
        )
        story.update(
            kind="interruption-tolerance-exceeded",
            headline="Traffic recovered; interruption exceeded tolerance",
            what_happened="Traffic recovered after migration. "
            + (
                "; ".join(reasons) + "."
                if reasons
                else "Interruption exceeded the recorded limits."
            ),
            why_this_status="VM placement, migration completion and the established TCP session passed. This run enforced interruption limits, and the ICMP/UDP measurements exceeded those limits. The recorded FAIL is retained under that run's policy.",
            next_check="Correlate the failed-probe interval with Nova migration and network-side logs. Compare the phase-specific measurements with the recorded acceptance limits; the probe evidence alone does not identify the faulty component.",
        )
    if observations:
        story["interruption_observations"] = observations
        story["interruption_tolerance_note"] = MIGRATION_DOWNTIME_TOLERANCE_NOTE
        story["limitations"].append(MIGRATION_DOWNTIME_TOLERANCE_NOTE)
        if (
            status == "PASS"
            and successful_components
            and all(
                assessment["migration_outcomes"].get("interruption_tolerance")
                in {"PASS", "OBSERVATION"}
                for assessment in assessments
            )
        ):
            story.update(
                kind="migration-interruption-observation",
                headline="Migration passed; interruption exceeded tolerance",
                what_happened=story.get("migration_move", "")
                + (" " if story.get("migration_move") else "")
                + "Migration completed and traffic recovered. [OBSERVATION] Above tolerance: "
                + "; ".join(observations)
                + ".",
                observed=story["observed"]
                + " Interruption above tolerance is recorded as an observation.",
                why_this_status="VM placement, migration completion, the established TCP session and traffic recovery passed. Interruption tolerance is reported as an observation and does not fail the migration.",
                next_check="Review the migration-phase measurements against the goal of zero customer downtime. Correlate the probe interval with Nova and network-side logs if investigating the interruption.",
                attention=True,
            )
    policy = mapping(details.get("migration_policy_interpretation"))
    if (
        status == "FAIL"
        and successful_components
        and policy.get("recorded_status") == "FAIL"
        and policy.get("current_policy_status") == "PASS"
        and policy.get("interruption_tolerance") == "OBSERVATION"
        and policy.get("recorded_verdict_rewritten") is False
        and isinstance(policy.get("interruption_observations"), list)
        and policy["interruption_observations"]
    ):
        current_observations = [
            _interruption_reason(value)
            for value in policy["interruption_observations"]
            if value
        ]
        story["current_policy_interruption_observations"] = current_observations
        story["interruption_tolerance_note"] = MIGRATION_DOWNTIME_TOLERANCE_NOTE
        story["what_happened"] += (
            " Historical FAIL retained. Current migration policy: PASS + [OBSERVATION] above tolerance."
        )
        story["facts"].append(
            {
                "label": "Current migration policy",
                "value": "PASS + OBSERVATION; the recorded historical FAIL is unchanged",
            }
        )
        story["limitations"].append(MIGRATION_DOWNTIME_TOLERANCE_NOTE)
    if details.get("resolution_only") is True and status == "PASS":
        story.update(
            kind="prerequisite-assessment-passed",
            headline="Recorded prerequisite assessment passed",
            observed=message,
            why_this_status="The execution ledger records that this prerequisite was satisfied. No separate probe result was saved for this check; read the recorded assessment and related evidence.",
        )
    story["limitations"] = list(dict.fromkeys(story["limitations"]))
    return story


def explanation_lines(result: dict[str, Any], *, prefix: str = "  ") -> list[str]:
    story = explain_result(result)
    lines = [f"{prefix}{story['headline']}"]
    lines.extend(f"{prefix}{line}" for line in story["context"].get("lines", []))
    lines.extend(
        f"{prefix}{label}: " + str(story[key]).replace("\n", f"\n{prefix}  ")
        for label, key in (
            ("Expected result", "expected"),
            ("Actual result", "observed"),
            (
                "Why this passed"
                if result.get("status") == "PASS"
                else "Why this failed"
                if result.get("status") == "FAIL"
                else "Why this status",
                "why_this_status",
            ),
        )
    )
    if story.get("interruption_observations"):
        lines.extend(
            [
                f"{prefix}[OBSERVATION] Above tolerance: "
                + "; ".join(story["interruption_observations"]),
                f"{prefix}{story['interruption_tolerance_note']}",
            ]
        )
    if story["attention"]:
        lines.extend(
            f"{prefix}{row['label']}: {row['value']}" for row in story["facts"]
        )
        if not story.get("advisory_summary") and story.get("recorded_message") not in {
            story["what_happened"],
            story["observed"],
        }:
            lines.append(f"{prefix}Recorded detail: {story['recorded_message']}")
        lines.extend(
            f"{prefix}Advisory: {value}"
            for value in story["warnings"]
            if value not in story["observed"]
        )
        lines.extend(
            f"{prefix}Evidence limit: {value}" for value in story["limitations"]
        )
        lines.append(f"{prefix}Next check: {story['next_check']}")
    return lines


def operator_overview(payload: dict[str, Any]) -> dict[str, Any]:
    groups: dict[str, dict[str, Any]] = {}
    for result in logical_results(payload):
        story = result.get("operator_explanation") or explain_result(result)
        if not story.get("attention"):
            continue
        keys = [
            "measurement-endpoint-limited"
            if story["kind"] == "measurement-rate-limited"
            and story.get("udp_rate_calibrated") is False
            else story["kind"]
        ]
        if keys == ["check-failed"]:
            # A generic verdict kind can contain different failed contracts.
            # Never assign every check the first result's specific headline.
            keys = [
                "check-failed:"
                + re.sub(r"[^a-z0-9]+", "-", story["headline"].lower()).strip("-")
            ]
        if story.get("udp_rate_calibrated") and "measurement-rate-limited" not in keys:
            keys.append("measurement-rate-limited")
        for key in keys:
            group = groups.setdefault(
                key,
                {
                    "kind": key,
                    "label": {
                        "advisory": "Measurements completed with advisory observations",
                        "measurement-rate-limited": "UDP measurements used lower rates because a test VM could not sustain the requested load",
                        "measurement-endpoint-limited": "UDP measurements were limited by a test VM; a usable lower-rate retry was not recorded",
                    }.get(key, story["headline"]),
                    "count": 0,
                    "result_ids": [],
                    "statuses": Counter(),
                },
            )
            group["count"] += 1
            group["result_ids"].append(result.get("test_id") or result.get("result_id"))
            group["statuses"][str(result.get("status"))] += 1

    def priority(group: dict[str, Any]) -> int:
        statuses = group["statuses"]
        return next(
            (
                index
                for index, status in enumerate(
                    (
                        "ERROR",
                        "FAIL",
                        "BLOCKED_BY_SETUP_ERROR",
                        "BLOCKED_BY_PREREQUISITE",
                        "UNVERIFIED",
                        "NOT_RUN_CANCELLED",
                        "PASS",
                    )
                )
                if statuses.get(status)
            ),
            7,
        )

    return {
        "groups": sorted(groups.values(), key=priority),
        "supporting_evidence_rows": sum(
            bool(mapping(row.get("details")).get("check_sample"))
            for row in payload.get("results") or []
        ),
        "note": "Counts are logical checks, not supporting evidence rows. Categories can overlap when one check records several observations. These categories do not change recorded verdicts or identify a component without evidence.",
    }


def lifecycle_explanations(payload: dict[str, Any]) -> list[dict[str, str]]:
    items = []
    if payload.get("error"):
        items.append(
            {
                "headline": "Run execution stopped",
                "what_happened": text(payload["error"], 8000),
                "next_check": "Resolve the recorded command or API error before rerunning. Checks that never ran do not establish network behaviour.",
            }
        )
    for setup in payload.get("setup_failures") or []:
        setup = mapping(setup)
        execution_failure = is_execution_lane_failure(mapping(setup.get("details")))
        items.append(
            {
                "headline": "Test execution stopped"
                if execution_failure
                else "Setup did not complete",
                "what_happened": text(
                    setup.get("message") or "No failure message was recorded.", 5000
                ),
                "next_check": (
                    "Resolve the recorded execution error and complete cleanup before rerunning this scope. Downstream blocked checks did not run."
                    if execution_failure
                    else "Resolve this setup error first; downstream blocked checks are consequences of this prerequisite failure."
                ),
            }
        )
    cleanup = mapping(payload.get("cleanup"))
    if cleanup.get("complete") is False:
        leftovers = cleanup.get("leftovers") or []
        errors = cleanup.get("errors") or []
        items.append(
            {
                "headline": "Cleanup is incomplete",
                "what_happened": f"{len(leftovers)} unresolved cleanup or verification {'issue' if len(leftovers) == 1 else 'issues'}; {len(errors)} cleanup {'error' if len(errors) == 1 else 'errors'}. "
                + text({"leftovers": leftovers, "errors": errors}, 10000),
                "next_check": "Inspect the named resource/dependency errors, then retry Flux cleanup for this run. Confirm the final inventory scan is clean before considering cleanup complete.",
            }
        )
    return items
