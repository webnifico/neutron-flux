from __future__ import annotations

import copy
import json
import pathlib
from typing import Any

from .junit_report import write_junit
from .mtu_contract import local_mtu_constraint
from .performance_results import _performance_result_summary
from .replay_plan import build_replay_plan, render_replay_plan_text
from .report_diagnostics import with_diagnostic_artifacts
from .report_exports import (
    render_host_qualification_csv,
    render_incident_summary,
)
from .reporting_components.dashboard_model import build_dashboard_model
from .reporting_components.html import _performance_summary, render_html
from .reporting_components.tcp_summary import tcp_retransmission_summary
from .result_contract import normalize_result_record
from .results_io import (
    atomic_write_text,
    load_results,
    output_directory,
    render_results_text,
)


def _udp_sender_limited_samples(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    limited: list[dict[str, Any]] = []
    for direction in ("forward", "reverse"):
        for row in metrics.get(direction) or []:
            if not isinstance(row, dict):
                continue
            requested = row.get("requested_mbps", row.get("offered_mbps"))
            sender = row.get("sender_mbps")
            try:
                requested_value = float(requested)
                sender_value = float(sender)
            except (TypeError, ValueError):
                continue
            if requested_value <= 0:
                continue
            achievement = sender_value / requested_value * 100.0
            if achievement < 90.0:
                limited.append(
                    {
                        "direction": direction,
                        "requested_mbps": requested_value,
                        "sender_mbps": sender_value,
                        "sender_achievement_pct": achievement,
                        "packet_size": row.get("packet_size"),
                    }
                )
    return limited


def _current_offline_interpretation(item: dict[str, Any]) -> tuple[str, str] | None:
    details = item.get("details") or {}
    if isinstance(details.get("routing_policy"), dict):
        # Current results record an explicit decision basis. Historical compatibility
        # heuristics must not replace that decision during report regeneration.
        return None
    measurement = str(details.get("measurement") or "")
    metrics = details.get("metrics") or {}
    message = str(item.get("message") or "")
    if measurement in {"udp", "mtu-mss", "asymmetry"} and isinstance(metrics, dict):
        if measurement == "udp":
            rows = [
                row
                for direction in ("forward", "reverse")
                for row in metrics.get(direction) or []
                if isinstance(row, dict)
            ]
            historical_semantics = (
                any(
                    "sender_achievement_pct" not in row
                    or "receiver_goodput_mbps" not in row
                    for row in rows
                )
                or "worst loss" in message.lower()
            )
            if not historical_semantics:
                return None
        elif measurement == "asymmetry":
            if "UDP loss" not in message or "application-delivery" in message:
                return None
        elif measurement == "mtu-mss":
            historical_semantics = (
                "confirmed no-fragment MTU" in message
                or "Fragmentation not supported" in message
                or any(
                    isinstance(metrics.get(direction), dict)
                    and str(
                        (metrics.get(direction) or {}).get(
                            "expected_probe_classification"
                        )
                        or ""
                    )
                    == "local-mtu-rejected"
                    and str(
                        (metrics.get(direction) or {}).get("discovery_confidence") or ""
                    )
                    == "confirmed-lower-boundary"
                    for direction in ("forward", "reverse")
                )
            )
            if not historical_semantics:
                return None
        summary = _performance_result_summary(measurement, metrics)
        if measurement == "udp":
            limited = _udp_sender_limited_samples(metrics)
            if limited:
                worst = min(
                    limited,
                    key=lambda row: float(row["sender_achievement_pct"]),
                )
                summary += (
                    f"; {len(limited)} stored sample(s) generated less than 90% of "
                    "the requested rate; lowest sender achievement "
                    f"{float(worst['sender_achievement_pct']):.1f}% at "
                    f"{float(worst['requested_mbps']):g} Mbit/s requested, "
                    f"{worst.get('packet_size') or 'unknown'}-byte datagrams"
                )
                return "UNVERIFIED", summary
        if measurement == "mtu-mss":
            local_constraints = [
                local_mtu_constraint(metrics.get(direction) or {})
                for direction in ("forward", "reverse")
                if isinstance(metrics.get(direction), dict)
            ]
            if any(classification for _value, classification in local_constraints):
                return "UNVERIFIED", summary
        return str(item.get("status") or "UNVERIFIED"), summary

    category = str(item.get("category") or "")
    observed = str(item.get("observed") or "")
    if category == "mtu" and observed == "local-mtu-rejected":
        return (
            "UNVERIFIED",
            "The source guest rejected the advertised-size DF packet locally. This "
            "proves a guest interface or cached route-PMTU constraint, not the current "
            "end-to-end path MTU.",
        )
    if (
        category == "floating-ip-packet-size"
        and str(details.get("egress_translation_mode") or "") == "floating-ip-egress"
        and (observed == "snat-runner-baseline-failed" or "runner" in message.lower())
    ):
        return (
            "UNVERIFIED",
            "The historical floating-IP egress probe did not first prove that a "
            "provider control endpoint could reach the exact Flux-runner listener. "
            "Runner firewalling, routing, or ACLs therefore could not be separated "
            "from the OpenStack translation path.",
        )
    probe = details.get("probe") or {}
    if (
        category == "project-provider-connectivity"
        and str(details.get("routing_relationship") or "") == "no-routing-group"
    ):
        return (
            "UNVERIFIED",
            "OpenStack exposed no shared routed address relationship for this "
            "project/provider fixed-IP path. Current reporting records the observed behavior "
            "without asserting that direct reachability or isolation is required.",
        )
    if (
        category == "floating-ip"
        and str(item.get("family") or "") in {"4", "IPv4"}
        and isinstance(probe, dict)
        and int(probe.get("attempts") or 0) == 1
        and str(item.get("status") or "") == "FAIL"
    ):
        return (
            "UNVERIFIED",
            "The historical floating-IP TCP result used one flow and did not "
            "record connect, send, receive, and echo-validation phases. Current reporting "
            "uses controlled fresh-flow confirmation before asserting a persistent "
            "floating-IP TCP failure.",
        )
    if (
        category == "source-nat-setting"
        and isinstance(probe, dict)
        and isinstance(probe.get("diagnostics"), dict)
    ):
        tenant_egress = (probe.get("diagnostics") or {}).get("tenant_egress") or {}
        if (
            isinstance(tenant_egress, dict)
            and tenant_egress.get("target")
            and "restoration_target" not in tenant_egress
        ):
            return (
                "UNVERIFIED",
                "The historical SNAT restoration check reused the same external "
                "destination before, during, and after the cloud operation. Existing "
                "conntrack/NAT state could not be separated from a fresh post-restore "
                "flow. Current probes use new tokenized flows to a provider observer and "
                "requires the restored outcome and observed source identity to match "
                "the pre-operation baseline.",
            )
    if (
        category == "project-provider-connectivity"
        and isinstance(probe, dict)
        and int(probe.get("attempts") or 0) == 1
        and "TimeoutError" in str(probe.get("stderr") or "")
    ):
        return (
            "UNVERIFIED",
            "One historical TCP flow timed out while waiting for the application "
            "echo. The old probe did not record connect/send/receive phases or run "
            "controlled fresh-flow confirmations, so persistence was not established.",
        )
    if category == "compute-placement" and isinstance(details.get("icmp"), dict):
        icmp = details.get("icmp") or {}
        tcp = details.get("tcp") or {}
        udp = details.get("udp") or {}
        response = udp.get("response") if isinstance(udp, dict) else {}
        raw_samples = icmp.get("raw_samples") if isinstance(icmp, dict) else None
        if isinstance(raw_samples, list) and any(
            isinstance(sample, dict) and "sequence" in sample for sample in raw_samples
        ):
            icmp_loss = float(icmp.get("loss_pct") or 0.0)
            udp_loss = float((response or {}).get("loss_pct") or 0.0)
            tcp_connected = bool(tcp.get("connected", tcp.get("survived")))
            tcp_survived = bool(tcp.get("survived"))
            outage = icmp.get("outage") or {}
            outage_lower = float(
                (outage or {}).get(
                    "outage_lower_bound_s", icmp.get("longest_outage_s") or 0.0
                )
                or 0.0
            )
            receiver = tcp.get("server_result") or {}
            delivered = (
                type(tcp.get("bytes_sent")) is int
                and tcp["bytes_sent"] > 0
                and isinstance(receiver, dict)
                and receiver.get("bytes") == tcp["bytes_sent"]
            )
            if tcp_connected and tcp_survived and not delivered:
                return (
                    "UNVERIFIED",
                    "The historical stream survival flag lacks matching receiver delivery acknowledgement. "
                    "The saved verdict is retained, but this is not a verified continuity PASS.",
                )
            if (
                tcp_connected
                and tcp_survived
                and delivered
                and icmp_loss <= 1.0
                and udp_loss <= 1.0
                and outage_lower <= 1.0
            ):
                return (
                    "PASS",
                    f"The established TCP stream survived; ICMP failed observations were "
                    f"{icmp_loss:.2f}%; sequenced UDP application-delivery loss "
                    f"was {udp_loss:.2f}%; and the sampled failed-observation span "
                    f"was {outage_lower:.3f}s. Under current thresholds this is an "
                    "advisory isolated userspace observation, not a material "
                    "live-migration continuity failure.",
                )
            return None
        icmp_loss = float(icmp.get("loss_pct") or 0.0)
        udp_loss = float((response or {}).get("loss_pct") or 0.0)
        tcp_connected = bool(tcp.get("connected", tcp.get("survived")))
        tcp_survived = bool(tcp.get("survived"))
        failure_reasons = []
        if tcp_connected and not tcp_survived:
            failure_reasons.append("the established TCP session did not survive")
        if icmp_loss > 0.0:
            failure_reasons.append(f"ICMP failed observations were {icmp_loss:.2f}%")
        if udp_loss > 1.0:
            failure_reasons.append(
                f"sequenced UDP application-delivery loss was {udp_loss:.2f}%"
            )
        interpretation_status = "FAIL" if failure_reasons else "UNVERIFIED"
        interpretation = (
            f"Historical evidence recorded {int(icmp.get('lost') or 0)} failed "
            f"ICMP observations ({icmp_loss:.2f}%) and {udp_loss:.2f}% "
            "sequenced UDP application-delivery loss. The old blocking ping loop "
            "did not provide fixed-cadence sequence/deadline evidence, and the "
            "stored ICMP duration is a failed-observation span rather than an exact "
            "outage duration."
        )
        if failure_reasons:
            interpretation += " Failure evidence: " + "; ".join(failure_reasons) + "."
        return interpretation_status, interpretation
    return None


def _current_migration_policy_interpretation(
    item: dict[str, Any],
) -> dict[str, Any] | None:
    """Annotate verified tolerance-only history without changing its verdict."""

    if item.get("status") != "FAIL" or item.get("category") != "compute-placement":
        return None
    details = item.get("details") or {}
    if not isinstance(details, dict):
        return None
    assessments: list[dict[str, Any]] = []
    if isinstance(details.get("migration_outcomes"), dict):
        assessments.append(details)
    continuity = details.get("continuity")
    if isinstance(continuity, dict) and isinstance(
        continuity.get("migration_outcomes"), dict
    ):
        assessments.append(continuity)
    transitions = details.get("transitions")
    if isinstance(transitions, list):
        for transition in transitions:
            if (
                not isinstance(transition, dict)
                or transition.get("confirmed") is not True
            ):
                return None
            if any(
                key in transition and transition[key] is not True
                for key in (
                    "task_state_cleared",
                    "port_binding_verified",
                    "endpoint_ready",
                    "guest_marker_verified",
                    "migration_record_verified",
                    "volume_attachment_verified",
                    "placement_verified",
                )
            ):
                return None
            assessment = transition.get("continuity_assessment")
            if not isinstance(assessment, dict):
                return None
            assessments.append(assessment)
    if not assessments:
        return None

    # Re-evaluate saved measurements, rather than trusting a saved survival flag
    # or changing a FAIL because its message happens to mention interruption.
    from .execution.placement_migration import PlacementMigrationMixin

    functional_components = (
        "vm_placement",
        "migration_completion",
        "tcp_session",
        "traffic_recovery",
    )
    observations: list[str] = []
    note = ""
    for assessment in assessments:
        recorded_outcomes = assessment.get("migration_outcomes") or {}
        if not isinstance(recorded_outcomes, dict):
            return None
        if any(recorded_outcomes.get(key) != "PASS" for key in functional_components):
            return None
        if assessment.get("transport_failure_reasons"):
            return None
        recorded_failures = assessment.get("continuity_failure_reasons")
        if recorded_failures and recorded_failures != assessment.get(
            "tolerance_failure_reasons"
        ):
            return None
        try:
            status, _observed, _message, current = (
                PlacementMigrationMixin._live_continuity_verdict(assessment)
            )
        except (TypeError, ValueError, OverflowError):
            return None
        outcomes = current.get("migration_outcomes") or {}
        if status != "PASS" or any(
            outcomes.get(key) != "PASS" for key in functional_components
        ):
            return None
        observations.extend(current.get("interruption_observations") or [])
        note = str(current.get("interruption_tolerance_note") or note)
    if not observations or not any(
        assessment.get("migration_outcomes", {}).get("interruption_tolerance") == "FAIL"
        for assessment in assessments
    ):
        return None
    return {
        "recorded_status": item["status"],
        "current_policy_status": "PASS",
        "interruption_tolerance": "OBSERVATION",
        "interruption_observations": list(dict.fromkeys(observations)),
        "interruption_tolerance_note": note,
        "recorded_verdict_rewritten": False,
    }


def _apply_current_offline_interpretations(payload: dict[str, Any]) -> None:
    migration_interpretations = {
        str(item.get("test_id") or ""): interpretation
        for item in payload.get("results") or []
        if isinstance(item, dict)
        and (interpretation := _current_migration_policy_interpretation(item))
        is not None
    }
    for item in payload.get("results") or []:
        if not isinstance(item, dict):
            continue
        details = dict(item.get("details") or {})
        migration_interpretation = migration_interpretations.get(
            str(item.get("test_id") or "")
        )
        if (
            migration_interpretation is None
            and item.get("status") == "FAIL"
            and item.get("category") == "compute-placement"
            and details.get("check_sample") is True
            and not _has_embedded_continuity(details)
        ):
            migration_interpretation = migration_interpretations.get(
                str(details.get("transition_check_id") or "")
            )
        if migration_interpretation is not None:
            if "migration_policy_interpretation" in details:
                continue
            annotation = copy.deepcopy(migration_interpretation)
            annotation["original_message"] = str(item.get("message") or "")
            details["migration_policy_interpretation"] = annotation
            item["details"] = details
            item["message"] = (
                f"Historical {item['status']} verdict retained. Current migration policy "
                "(PASS + OBSERVATION): migration, placement, TCP survival and recovery "
                "were verified; "
                + "; ".join(annotation["interruption_observations"])
                + ". "
                + annotation["interruption_tolerance_note"]
            )
            item.pop("contract", None)
            normalized = normalize_result_record(item)
            item.clear()
            item.update(normalized)
            continue
        interpretation = _current_offline_interpretation(item)
        if interpretation is None:
            continue
        interpretation_status, message = interpretation
        historical_status = str(item.get("status") or "")
        historical_message = str(item.get("message") or "")
        if message == historical_message and interpretation_status == historical_status:
            continue
        details = dict(item.get("details") or {})
        details["offline_interpretation"] = {
            # Historical wire identifier for this interpretation schema.
            "semantics": "r71",
            "historical_status": historical_status,
            "interpretation_status": interpretation_status,
            "original_message": historical_message,
            "verdict_rewritten": False,
        }
        item["details"] = details
        display_name = str(item.get("display_name") or "")
        if display_name == "UDP loss, jitter, and packet rate":
            item["display_name"] = (
                "UDP application-delivery loss, jitter, and packet rate"
            )
        elif "Measure project-network traffic continuity" in display_name:
            item["display_name"] = display_name.replace(
                "Measure project-network traffic continuity",
                "Measure endpoint traffic continuity",
            )
        item["message"] = (
            f"Historical {historical_status} verdict retained. Current interpretation "
            f"({interpretation_status}): {message}"
        )
        item.pop("contract", None)
        normalized = normalize_result_record(item)
        item.clear()
        item.update(normalized)


def _has_embedded_continuity(details: dict[str, Any]) -> bool:
    fields = {
        "continuity",
        "continuity_assessment",
        "migration_outcomes",
        "transitions",
        "icmp",
        "tcp",
        "udp",
        "transport_failure_reasons",
        "completion_assessment",
        "migration_completion_evidence",
    }
    if fields.intersection(details):
        return True
    assessment = details.get("assessment")
    return isinstance(assessment, dict) and bool(fields.intersection(assessment))


def _refresh_udp_summary(payload: dict[str, Any]) -> None:
    # TCP extrema used to sum repetitions of one single-stream direction and
    # omit loaded/multistream windows. Rebuild only the derived summary fields.
    tcp_summary = tcp_retransmission_summary(payload.get("results") or [])
    summary = payload.setdefault("summary", {})
    for name in ("performance", "performance_summary"):
        if name == "performance_summary" and name not in summary:
            continue
        summary.setdefault(name, {}).update(tcp_summary)
    udp_results = [
        item
        for item in payload.get("results") or []
        if (item.get("details") or {}).get("measurement") == "udp"
    ]
    if udp_results:
        # Rebuild derived display metrics, preserving the source-run verdicts
        # and stored evidence. Old summary extrema included excluded samples.
        udp_summary = _performance_summary(udp_results)
        summary = payload.setdefault("summary", {})
        for name in ("performance", "performance_summary"):
            if name == "performance_summary" and name not in summary:
                continue
            current = summary.setdefault(name, {})
            for key in (
                "worst_udp_loss_pct",
                "worst_endpoint_limited_udp_loss_pct",
                "excluded_udp_samples",
                "worst_udp_jitter_ms",
                "best_udp_mbps",
                "best_udp_pps",
            ):
                current[key] = udp_summary[key]


def regenerate(
    source: str | pathlib.Path,
    *,
    destination: str | pathlib.Path | None = None,
    html: bool = True,
    junit: bool = True,
    evidence: bool | None = None,
) -> dict[str, pathlib.Path]:
    source_path = pathlib.Path(source).expanduser().resolve()
    payload = with_diagnostic_artifacts(
        copy.deepcopy(load_results(source_path)), source_path.parent
    )
    _apply_current_offline_interpretations(payload)
    _refresh_udp_summary(payload)
    if evidence is not None:
        configuration = payload.setdefault("configuration", {})
        configuration["evidence_enabled"] = evidence
    replay_plan = build_replay_plan(payload)
    payload["replay_plan"] = replay_plan
    # Offline regeneration upgrades stale embedded dashboard projections from
    # older result files instead of carrying them into a new report unchanged.
    payload["dashboard"] = build_dashboard_model(payload)
    output = output_directory(destination, default=source_path.parent)
    written: dict[str, pathlib.Path] = {}
    text_path = output / "report.txt"
    atomic_write_text(text_path, render_results_text(payload))
    written["text"] = text_path
    qualification_csv_path = output / "host-qualification.csv"
    atomic_write_text(
        qualification_csv_path,
        render_host_qualification_csv(payload),
    )
    written["host_qualification_csv"] = qualification_csv_path
    incident_path = output / "incident-summary.md"
    atomic_write_text(incident_path, render_incident_summary(payload))
    written["incident_summary"] = incident_path
    replay_json_path = output / "replay-plan.json"
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
    written["replay_plan_json"] = replay_json_path
    replay_text_path = output / "replay-plan.txt"
    atomic_write_text(replay_text_path, render_replay_plan_text(replay_plan))
    written["replay_plan_text"] = replay_text_path
    html_path = output / "report.html"
    if html:
        atomic_write_text(html_path, render_html(payload))
        written["html"] = html_path
    else:
        html_path.unlink(missing_ok=True)
    junit_path = output / "report.junit.xml"
    if junit:
        written["junit"] = write_junit(
            payload,
            junit_path,
            include_evidence=(
                evidence
                if evidence is not None
                else (payload.get("configuration") or {}).get("evidence_enabled", True)
            ),
        )
    else:
        junit_path.unlink(missing_ok=True)
    return written


__all__ = ["regenerate"]
