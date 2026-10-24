"""Shared test names and evidence-backed execution labels."""

from __future__ import annotations

import re
from typing import Any

from .test_titles import (
    MEASUREMENT_TITLES,
    TITLE_REPLACEMENTS,
    TITLES,
    test_name,
    title_for,
)

__all__ = [
    "MEASUREMENT_TITLES",
    "TITLE_REPLACEMENTS",
    "TITLES",
    "test_name",
    "title_for",
    "packet_path_display_name",
    "execution_name",
    "address_path_lines",
]


def packet_path_display_name(display: str, details: dict[str, Any]) -> str:
    """Do not label a VM-to-itself packet path using its peer topology's hosts."""
    if details.get("packet_path_placement") != "self":
        return display
    display = re.sub(
        r"\b(?:inter-compute|intra-compute)\s*\[[^\]]*\]", "self-hairpin", display
    )
    display = re.sub(r"\b(?:inter-compute|intra-compute)\b", "self-hairpin", display)
    return re.sub(r"\b(?:same-a|same-b|inter|initial|opposite)\b", "self", display)


def execution_name(result: dict[str, Any]) -> str:
    """Name this execution without copying planner codes into the title."""
    from .result_context import result_context

    context = result_context(result)
    parts = [context["test"]]
    if context["action"]:
        parts.append(context["action"])
    parts.append(context["timing"])
    source, destination = context["source"], context["destination"]
    if source.get("probe_address") and destination.get("probe_address"):
        parts.append(
            f"{source['label']} {source['probe_address']} → "
            f"{destination['label']} {destination['probe_address']}"
        )
    else:
        parts.append(context["path"])
    if context["family"] != "IP family was not recorded":
        parts.append(
            f"{context['protocol']} over {context['family']}"
            if context["protocol"]
            else context["family"]
        )
    elif context["protocol"]:
        parts.append(context["protocol"])
    if context["execution_state"] != "Executed":
        parts.append(context["execution_state"])
    return " — ".join(parts)


def address_path_lines(details: dict[str, Any]) -> list[str]:
    """Render declared addresses separately from addresses actually probed."""
    path = details.get("address_path") or {}
    lines = []
    for role in ("source", "destination"):
        endpoint = path.get(role) or {}
        if not endpoint:
            continue
        floating = endpoint.get("floating_ip")
        status = endpoint.get("floating_ip_status") or "unverified"
        fip_text = f"{floating} ({status})" if floating else status
        lines.append(
            f"{role.title()} addresses: fixed {endpoint.get('fixed_ip') or 'unavailable'}; "
            f"floating {fip_text}; probe {endpoint.get('probe_address') or 'unavailable'}"
        )
    if path.get("observed_source_ip"):
        lines.append(f"Source seen by destination: {path['observed_source_ip']}")
    return lines
