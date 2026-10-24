from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

from ..operator_explanations import explain_result
from ..performance_metrics import udp_sample_assessable
from .dashboard_mtu_model import mtu_finding_measurements
from .dashboard_vocabulary import STATUS_WEIGHT
from .operator_context import connection_story


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) else None


def finding_measurements(results: list[dict[str, Any]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    worst_udp_loss: float | None = None
    endpoint_limited_loss: list[float] = []
    for result in results:
        details = result.get("details") or {}
        metrics = details.get("metrics") or {}
        if details.get("measurement") == "mtu-mss":
            rows.extend(mtu_finding_measurements(metrics))
        if details.get("measurement") == "udp":
            samples = [
                sample
                for direction in ("forward", "reverse")
                for sample in metrics.get(direction) or []
            ]
            endpoint_limited_loss.extend(
                value
                for sample in samples
                if sample.get("packet_size_supported") is not False
                and (
                    sample.get("endpoint_limited") is True
                    or sample.get("load_valid") is False
                )
                if (value := _number(sample.get("loss_pct"))) is not None
            )
            samples = [sample for sample in samples if udp_sample_assessable(sample)]
            recorded_losses = [
                value
                for sample in samples
                if (value := _number(sample.get("loss_pct"))) is not None
            ]
            if recorded_losses:
                result_worst_loss = max(
                    recorded_losses,
                )
                worst_udp_loss = (
                    result_worst_loss
                    if worst_udp_loss is None
                    else max(worst_udp_loss, result_worst_loss)
                )
        story = connection_story(result)
        if story:
            rows.append(
                {
                    "label": "Failed step",
                    "value": "TCP connection; packet-size tests not run",
                }
            )
        elif result.get("category") == "compute-placement":
            explanation = explain_result(result)
            rows.extend(
                row
                for row in explanation["facts"]
                if row["label"] == "Interruption limits exceeded"
            )
        elif details.get("measurement") == "asymmetry":
            rows.append(
                {
                    "label": "UDP comparison",
                    "value": f"{metrics.get('udp_compared_profiles', 0)} matching profiles; {metrics.get('udp_unmatched_profiles', 0)} unmatched",
                }
            )
        elif result.get("observed"):
            rows.append({"label": "Observed", "value": str(result.get("observed"))})
    if worst_udp_loss is not None:
        rows.insert(
            0,
            {
                "label": "Worst across affected UDP tests",
                "value": f"{worst_udp_loss:.3f}%",
            },
        )
    if endpoint_limited_loss:
        rows.insert(
            1 if worst_udp_loss is not None else 0,
            {
                "label": "Excluded endpoint-limited UDP loss",
                "value": f"{max(endpoint_limited_loss):.3f}%",
            },
        )
    unique: list[dict[str, str]] = []
    seen = set()
    for row in rows:
        key = (row["label"], row["value"])
        if key not in seen:
            seen.add(key)
            unique.append(row)
    return unique[:4]


def _compact_sentence(value: Any, *, limit: int = 260) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip(" ;")
    if not text:
        return ""
    runtime_group = re.search(
        r"Runtime group .*?@([A-Za-z0-9_-]+) lacks endpoint ([A-Za-z0-9_-]+)",
        text,
        flags=re.IGNORECASE,
    )
    if runtime_group:
        return (
            f"A runtime endpoint group in {runtime_group.group(1)} was incomplete: "
            f"endpoint {runtime_group.group(2)} was missing."
        )
    if ": " in text:
        lead, tail = text.split(": ", 1)
        if lead.strip().lower() == tail.strip().lower():
            text = lead.strip()
        elif tail.lower().startswith(lead.lower() + ":"):
            text = tail
    clauses = [clause.strip() for clause in text.split(";") if clause.strip()]
    if len(clauses) > 2:
        text = "; ".join(clauses[:2])
    if len(text) > limit:
        text = text[: limit - 1].rstrip(" ,;:") + "…"
    if text and text[-1] not in ".!?…":
        text += "."
    return text


def finding_summary(
    root: str,
    items: list[dict[str, Any]],
    *,
    path_count: int,
    measurements: list[dict[str, str]],
    status_counts: Counter[str],
) -> str:
    result_count = len(items)
    scope = (
        f"across {path_count} endpoint pair{'s' if path_count != 1 else ''}"
        if path_count
        else "at run scope"
    )
    status_text = " · ".join(
        f"{count} {status.lower().replace('_', ' ')}"
        for status, count in sorted(
            status_counts.items(),
            key=lambda pair: -STATUS_WEIGHT.get(pair[0], 0),
        )
    )
    values = {row["label"]: row["value"] for row in measurements}

    if root == "translated-tcp-connect":
        story = connection_story(items[0])
        return story.get("observed", "The translated TCP connection failed.")
    if root == "migration-interruption":
        return (
            f"{result_count} migration check{'s' if result_count != 1 else ''} exceeded interruption limits. "
            "VM placement and migration completed, the established TCP sessions survived, and traffic recovered. "
            "Review the ICMP failed observations, UDP delivery loss and sampled failed-observation spans below."
        )
    if root == "direction" and all(
        (item.get("details") or {}).get("measurement") == "asymmetry"
        and ((item.get("details") or {}).get("metrics") or {}).get(
            "udp_unmatched_profiles", 0
        )
        > 0
        for item in items
    ):
        return (
            f"{result_count} forward/reverse comparisons {scope} lack matching UDP packet-size/rate samples for every profile. "
            "The directions calibrated to different sustainable rates or lacked an eligible sample. This does not by itself show UDP network loss."
        )

    if root == "udp":
        worst = values.get("Worst across affected UDP tests")
        sentence = (
            f"{result_count} UDP assessment{'s' if result_count != 1 else ''} "
            f"{scope} require review"
        )
        if worst:
            sentence += f"; the worst eligible application-delivery loss was {worst}"
        elif values.get("Excluded endpoint-limited UDP loss"):
            sentence += "; no eligible loss measurement was available"
        if values.get("Excluded endpoint-limited UDP loss"):
            sentence += ". Endpoint-limited samples are shown separately and excluded from network-loss grading"
        return (
            sentence
            + ". Results remain unverified where sender achievement or endpoint "
            "receive counters prevent attributing the observation to the network path alone."
        )

    if root == "mtu":
        advertised = values.get("Advertised MTU")
        local = values.get("Lowest local MTU/PMTU constraint")
        confirmed = values.get("Lowest confirmed no-fragment path MTU")
        facts = [
            f"advertised {advertised}" if advertised else None,
            f"confirmed path {confirmed}" if confirmed else None,
            f"local constraint {local}" if local else None,
        ]
        fact_text = "; ".join(value for value in facts if value)
        suffix = f" The recorded values were {fact_text}." if fact_text else ""
        return (
            f"Packet-size evidence {scope} is not fully conclusive ({status_text})."
            f"{suffix} Local cached PMTU evidence is not presented as an end-to-end path limit."
        )

    if root == "connectivity":
        if status_counts.get("FAIL", 0):
            return (
                f"{status_counts['FAIL']} connectivity test{'s' if status_counts['FAIL'] != 1 else ''} "
                "contradicted the declared expected behaviour; "
                f"{result_count - status_counts['FAIL']} additional check(s) remain unvalidated or require review "
                f"({status_text}). The group spans {path_count} endpoint pair(s); "
                "this does not mean every pair failed. Review individual evidence."
            )
        return (
            f"{result_count} connectivity test{'s' if result_count != 1 else ''} "
            f"{scope} did not produce a conclusive expected-versus-observed result "
            f"({status_text}). Review the affected IP routes and the individual test evidence."
        )

    message = next(
        (
            _compact_sentence(item.get("operator_message") or item.get("message"))
            for item in items
            if item.get("operator_message") or item.get("message")
        ),
        "",
    )
    if root in {
        "execution",
        "neutron-flux-execution",
        "neutron-flux-controller-setup",
    }:
        prefix = (
            f"{result_count} validation operation{'s' if result_count != 1 else ''} "
            f"ended in an execution error ({status_text})."
        )
        return f"{prefix} {message}".strip()

    prefix = (
        f"{result_count} affected test{'s' if result_count != 1 else ''} "
        f"{scope} ({status_text})."
    )
    return f"{prefix} {message}".strip()


__all__ = ["finding_measurements", "finding_summary"]
