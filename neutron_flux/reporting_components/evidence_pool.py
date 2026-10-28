"""Lossless sharing of repeated HTML evidence, without changing the JSON export."""

from __future__ import annotations

from collections import Counter
from typing import Any

MARKER = "$neutron_flux_evidence"


def pool_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    """Intern repeated long strings; evidence excerpts keep their original contents."""
    counts: Counter[str] = Counter()

    def collect(value: Any) -> None:
        if isinstance(value, str) and len(value) >= 256:
            counts[value] += 1
        elif isinstance(value, dict):
            for item in value.values():
                collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)

    collect(payload)
    shared = [s for s, n in counts.items() if n > 1]
    if not shared and "evidence_pool" not in payload:
        return payload
    indices = {s: i for i, s in enumerate(shared)}

    def encode(value: Any) -> Any:
        if isinstance(value, str) and value in indices:
            return {MARKER: indices[value]}
        if isinstance(value, dict):
            # Escape a literal object that happens to match the reference shape.
            if set(value) == {MARKER}:
                return {MARKER: ["literal", encode(value[MARKER])]}
            return {k: encode(v) for k, v in value.items()}
        if isinstance(value, list):
            return [encode(v) for v in value]
        return value

    encoded = encode(payload)
    transport: dict[str, Any] = {
        "format": "neutron-flux-evidence-v1",
        "strings": shared,
    }
    if "evidence_pool" in encoded:
        transport["original"] = encoded["evidence_pool"]
    encoded["evidence_pool"] = transport
    return encoded
