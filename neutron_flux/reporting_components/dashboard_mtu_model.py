from __future__ import annotations

from typing import Any

from ..mtu_contract import confirmed_no_fragment_path_mtu, local_mtu_constraint


def _number(value: Any) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed == parsed else None


def mtu_boundary_values(sample: dict[str, Any], direction: str) -> dict[str, Any]:
    """Return evidence-safe path-boundary and local-constraint dashboard fields."""

    confirmed_mtu = confirmed_no_fragment_path_mtu(sample)
    local_mtu, local_class = local_mtu_constraint(sample)
    return {
        f"{direction}_discovered_mtu": _number(confirmed_mtu),
        f"{direction}_raw_discovered_mtu": _number(sample.get("discovered_mtu")),
        f"{direction}_local_constraint_mtu": _number(local_mtu),
        f"{direction}_local_constraint_class": local_class,
        f"{direction}_path_boundary_confirmed": confirmed_mtu is not None,
    }


def mtu_finding_measurements(metrics: dict[str, Any]) -> list[dict[str, str]]:
    """Summarize confirmed path MTU separately from local PMTU/MTU constraints."""

    rows: list[dict[str, str]] = []
    expected = _number(metrics.get("expected_mtu"))
    directions = [metrics.get(direction) or {} for direction in ("forward", "reverse")]
    confirmed = [
        _number(confirmed_no_fragment_path_mtu(sample)) for sample in directions
    ]
    local = [_number(local_mtu_constraint(sample)[0]) for sample in directions]
    if expected is not None:
        rows.append({"label": "Advertised MTU", "value": f"{expected:.0f} bytes"})
    finite_confirmed = [value for value in confirmed if value is not None]
    if finite_confirmed:
        rows.append(
            {
                "label": "Lowest confirmed no-fragment path MTU",
                "value": f"{min(finite_confirmed):.0f} bytes",
            }
        )
    finite_local = [value for value in local if value is not None]
    if finite_local:
        rows.append(
            {
                "label": "Lowest local MTU/PMTU constraint",
                "value": f"{min(finite_local):.0f} bytes (path unverified)",
            }
        )
    return rows


__all__ = ["mtu_boundary_values", "mtu_finding_measurements"]
