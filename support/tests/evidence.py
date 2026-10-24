"""Decode pooled HTML evidence for report assertions."""

from typing import Any

from neutron_flux.reporting_components.evidence_pool import MARKER


def expand_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    transport = payload.get("evidence_pool")
    if (
        not isinstance(transport, dict)
        or transport.get("format") != "neutron-flux-evidence-v1"
    ):
        return payload
    pool = transport["strings"]

    def decode(value: Any) -> Any:
        if isinstance(value, dict):
            if set(value) == {MARKER}:
                ref = value[MARKER]
                return {MARKER: decode(ref[1])} if isinstance(ref, list) else pool[ref]
            return {k: decode(v) for k, v in value.items()}
        if isinstance(value, list):
            return [decode(v) for v in value]
        return value

    original = {k: v for k, v in payload.items() if k != "evidence_pool"}
    if "original" in transport:
        original["evidence_pool"] = transport["original"]
    return decode(original)
