from __future__ import annotations

from collections.abc import Mapping
from typing import Any

CONTRACT_RESERVED_FIELDS = {
    "schema_version",
    "type",
    "description",
    "source",
    "destination",
    "family",
    "expectation",
    "observation",
    "verdict",
    "authority",
    "execution",
    "path_health",
    "mechanism",
    "attribution",
    "path_signature_key",
    "lifecycle",
    "packet_size",
    "components",
}
PATH_SIGNATURE_RESERVED_FIELDS = {
    "schema_version",
    "key",
    "identity",
    "context",
    "display",
}


def validate_supplied_contract(
    supplied: Mapping[str, Any],
    *,
    generated: Mapping[str, Any],
    expected_verdict: str,
) -> None:
    verdict = supplied.get("verdict")
    if verdict is not None:
        if not isinstance(verdict, Mapping):
            raise ValueError("Result contract.verdict must be an object")
        state = str(verdict.get("state") or "").strip().upper()
        if state and state != expected_verdict:
            raise ValueError(
                "Result status contradicts supplied typed contract verdict"
            )
    supplied_type = supplied.get("type")
    if supplied_type and supplied_type != generated.get("type"):
        raise ValueError(
            "Supplied result contract type contradicts the canonical result type"
        )
    supplied_path_key = supplied.get("path_signature_key")
    if supplied_path_key is not None and supplied_path_key != generated.get(
        "path_signature_key"
    ):
        raise ValueError(
            "Result contract path signature key contradicts the canonical semantic "
            "path identity"
        )
    validate_overlay_consistency(
        supplied,
        generated,
        label="Supplied result contract",
        reserved_root_fields=CONTRACT_RESERVED_FIELDS,
    )


def validate_overlay_consistency(
    supplied: Mapping[str, Any],
    generated: Mapping[str, Any],
    *,
    label: str,
    reserved_root_fields: set[str],
    path: tuple[str, ...] = (),
) -> None:
    """Allow root extensions while protecting every canonical schema field."""

    for key, supplied_value in supplied.items():
        field_path = (*path, str(key))
        if key not in generated:
            if not path and str(key) not in reserved_root_fields:
                continue
            raise ValueError(
                f"{label} {'.'.join(field_path)} contradicts the canonical value"
            )
        generated_value = generated[key]
        if isinstance(supplied_value, Mapping):
            if not isinstance(generated_value, Mapping):
                raise ValueError(
                    f"{label} {'.'.join(field_path)} contradicts the canonical value"
                )
            validate_overlay_consistency(
                supplied_value,
                generated_value,
                label=label,
                reserved_root_fields=reserved_root_fields,
                path=field_path,
            )
            continue
        if supplied_value != generated_value:
            raise ValueError(
                f"{label} {'.'.join(field_path)} contradicts the canonical value"
            )


__all__ = [
    "CONTRACT_RESERVED_FIELDS",
    "PATH_SIGNATURE_RESERVED_FIELDS",
    "validate_overlay_consistency",
    "validate_supplied_contract",
]
