"""Resolve Flux's aggregate restriction without mistaking missing data for absence."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AggregatePolicy:
    requested: str
    resolution: str
    inventory_state: str
    aggregate_count: int | None

    @property
    def requires_shared(self) -> bool:
        return self.resolution == "shared-aggregate"

    @property
    def discovery_blocked(self) -> bool:
        return self.requires_shared and self.inventory_state != "complete"


def resolve_aggregate_policy(
    requirement: bool | None, inventory_state: str, aggregate_count: int | None
) -> AggregatePolicy:
    """Only a complete, globally empty inventory permits automatic fallback.

    A host's empty memberships are not evidence that the cloud has no aggregates.
    Explicit false bypasses only Flux's aggregate restriction, never Nova policy.
    """
    requested = (
        "auto" if requirement is None else "required" if requirement else "ignore"
    )
    resolution = "shared-aggregate"
    if requirement is False:
        resolution = "same-az-explicit"
    elif (
        requirement is None
        and inventory_state == "complete"
        and type(aggregate_count) is int
        and aggregate_count == 0
    ):
        resolution = "same-az-empty-inventory"
    return AggregatePolicy(requested, resolution, inventory_state, aggregate_count)
