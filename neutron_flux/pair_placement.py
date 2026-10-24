"""Resolve one intra/inter transition from verified, bounded endpoint placement."""

from __future__ import annotations

from typing import Any

from .errors import SuiteError
from .executor import AdaptiveExecutor
from .models import Endpoint, RuntimeGroup, TestSpec
from .network_contract import PRIVATE_TRANSLATION_PROJECT_NETWORK
from .scheduling import READ_WORKERS, bounded_map

Member = tuple[str, Endpoint]


def opposite_hosts(
    hosts: tuple[str, str],
    allowed_zones: dict[str, str | None],
    *,
    moving_index: int = 1,
) -> tuple[str, str]:
    """Change one endpoint's host, preserving the selected stationary endpoint."""
    first, second = hosts
    if moving_index not in {0, 1}:
        raise SuiteError("Opposite placement requires one of two moving endpoints")
    if len(allowed_zones) != 2:
        raise SuiteError("Opposite placement requires exactly two selected hosts")
    if (
        not first
        or not second
        or first not in allowed_zones
        or second not in allowed_zones
    ):
        raise SuiteError(
            "Initial endpoint placement is missing or outside the selected host pair"
        )
    stationary = hosts[1 - moving_index]
    if first != second:
        return stationary, stationary
    alternatives = [host for host in allowed_zones if host != stationary]
    if len(alternatives) != 1:
        raise SuiteError("Opposite placement requires exactly two selected hosts")
    targets = list(hosts)
    targets[moving_index] = alternatives[0]
    return targets[0], targets[1]


class PairPlacementMixin:
    """Runtime binding for initial/opposite slots; slot IDs and totals never change."""

    scope: dict[str, Any]
    groups: dict[str, Any]
    active: dict[str, RuntimeGroup]
    builder: Any
    reporter: Any
    plan: Any

    def _selected_pair_zones(self) -> dict[str, str | None]:
        zones = self.scope.get("pair_selected_host_zones")
        requested = {
            self.scope.get("requested_source_host"),
            self.scope.get("requested_destination_host"),
        }
        if not isinstance(zones, dict) or not zones or set(zones) != requested:
            raise SuiteError(
                "Selected host-pair/AZ scope is unavailable or inconsistent"
            )
        return zones

    def _ordered_pair_endpoints(
        self, dependencies: tuple[str, ...], sides: dict[str, Any]
    ) -> list[Member]:
        members = []
        for group_id in dependencies:
            for side in sorted(sides[group_id]):
                endpoint = self.active[group_id].endpoint(side)
                if endpoint is None:
                    raise SuiteError(
                        f"Required endpoint {group_id}:{side} is unavailable"
                    )
                members.append((group_id, endpoint))
        if (
            len(members) != 2
            or len({endpoint.server_id for _, endpoint in members}) != 2
        ):
            raise SuiteError(
                "Placement lifetime requires exactly two distinct endpoint VMs"
            )
        return members

    def _verify_runtime(self, runtime: RuntimeGroup) -> None:
        group = self.groups.get(runtime.plan.id, runtime.plan)
        zones = self._selected_pair_zones()
        initial = self.scope.get("pair_placement") == "initial"
        expected = group.metadata["target_hosts"]
        checks: list[tuple[Endpoint, str, str | None]] = []
        roles: set[str] = set()
        servers: set[str] = set()
        for endpoint in runtime.endpoints:
            if (
                endpoint.side not in {"A", "B"}
                or endpoint.side not in expected
                or endpoint.side in roles
                or not endpoint.server_id
                or endpoint.server_id in servers
            ):
                raise SuiteError(f"Invalid endpoint roles for {group.id}")
            roles.add(endpoint.side)
            servers.add(endpoint.server_id)
            host = endpoint.host
            if (
                not host
                or host not in zones
                or not zones[host]
                or endpoint.availability_zone != zones[host]
            ):
                raise SuiteError(
                    f"Host-pair/AZ placement mismatch for {endpoint.label}: {host or 'unknown'} / {endpoint.availability_zone or 'unknown'}"
                )
            if not initial and expected.get(endpoint.side) != host:
                raise SuiteError(
                    f"Exact placement mismatch for {endpoint.label}: expected {expected.get(endpoint.side)}, observed {host}"
                )
            checks.append((endpoint, host, zones[host]))

        def verify(check: tuple[Endpoint, str, str | None]) -> None:
            endpoint, host, zone = check
            self.builder.verify_server_placement(
                endpoint.server_id,
                [endpoint.management_port_id, endpoint.test_port_id or ""],
                expected_statuses={"active"},
                expected_host=host,
                expected_availability_zone=zone,
                display_name=endpoint.server_name,
                stable_observations=2,
                reuse_fresh=True,
            )

        # Join both verifiers before any stage can publish placement or migrate.
        # Nested port reads keep using OpenStack's process-wide read budget.
        bounded_map(verify, checks, workers=READ_WORKERS)

    def _ensure(
        self,
        required: tuple[str, ...],
        *,
        required_sides: dict[str, tuple[str, ...]] | None = None,
    ) -> None:
        # Retained valid initial endpoints must not be torn down just because the
        # preferred boot hints differ. New endpoints still use scoped host hints.
        sides = required_sides or {group: ("A",) for group in required}
        for index, group_id in enumerate(required):
            hosts = self._hosts_for(
                sides[group_id], index if len(required) == 2 else None
            )
            runtime = self.active.get(group_id)
            if runtime is not None:
                self._verify_runtime(runtime)
                hosts.update(
                    {
                        ep.side: ep.host
                        for ep in runtime.endpoints
                        if ep.side in hosts and ep.host is not None
                    }
                )
            self._set_hosts(group_id, hosts)
        AdaptiveExecutor._ensure(self, required, required_sides=sides)
        for group_id in required:
            runtime = self.active.get(group_id)
            if runtime is not None:
                self._verify_runtime(runtime)

    def _bind_pair_stage(self, specs: list[TestSpec], members: list[Member]) -> None:
        if not specs:
            return
        zones = self._selected_pair_zones()
        hosts = [str(ep.host or "") for _, ep in members]
        if any(host not in zones for host in hosts):
            raise SuiteError("Cannot label a placement outside the selected host pair")
        relation = "intra-compute" if hosts[0] == hosts[1] else "inter-compute"
        metadata = {
            "pair_scope_hosts": hosts,
            "pair_scope_zones": [zones[host] for host in hosts],
            "pair_observed_placement": relation,
            "same_host": hosts[0] == hosts[1],
            "same_availability_zone": zones[hosts[0]] == zones[hosts[1]],
            "compute_placement": relation,
        }
        for spec in specs:
            spec.metadata.update(metadata)
        self.scope.update({**specs[0].metadata, **metadata})
        self.reporter.save_plan()

    def _prepare_opposite_placement(
        self, specs: list[TestSpec], transition: TestSpec, members: list[Member]
    ) -> None:
        zones = self._selected_pair_zones()
        current = tuple(str(ep.host or "") for _, ep in members)
        # Translation belongs to the private VM's port and mapping. Moving only
        # the provider observer would leave the translated owner untested after
        # migration, even though the topology's compute relation changed.
        # Keep the existing endpoint policy across AZs, where recreation cannot
        # move a retained private network/router's placement hints with the VM.
        kinds = [self.groups[group_id].kind for group_id, _ in members]
        prefer_private_owner = (
            kinds.count(PRIVATE_TRANSLATION_PROJECT_NETWORK) == 1
            and kinds.count("provider") == 1
            and len(set(zones.values())) == 1
            and all(zones.values())
            and all(
                endpoint.availability_zone
                and endpoint.availability_zone == zones.get(str(endpoint.host or ""))
                for _, endpoint in members
            )
        )
        moving_index = (
            kinds.index(PRIVATE_TRANSLATION_PROJECT_NETWORK)
            if prefer_private_owner
            else 1
        )
        moving_group, moving_endpoint = members[moving_index]
        targets = opposite_hosts(
            (current[0], current[1]), zones, moving_index=moving_index
        )
        relation = "intra-compute" if targets[0] == targets[1] else "inter-compute"
        metadata = {
            "pair_scope_hosts": list(targets),
            "pair_scope_zones": [zones[host] for host in targets],
            "same_host": targets[0] == targets[1],
            "same_availability_zone": zones[targets[0]] == zones[targets[1]],
            "pair_initial_observed_hosts": list(current),
            "pair_moving_group_id": moving_group,
            "pair_moving_side": moving_endpoint.side,
            "pair_moving_server_id": moving_endpoint.server_id,
            "pair_moving_reason": (
                "private translation owner"
                if prefer_private_owner
                else "second endpoint in the topology"
            ),
            "pair_desired_relation": relation,
            "pair_observed_placement": None,
            "compute_placement": relation,
        }
        for spec in [transition, *specs]:
            spec.metadata.update(metadata)
        transition.display_name = f"Move one endpoint and verify {relation} placement"
        self.scope.update({**transition.metadata, **metadata})
        assigned: dict[str, dict[str, str]] = {}
        for (group_id, endpoint), host in zip(members, targets, strict=True):
            assigned.setdefault(group_id, {})[endpoint.side] = host
        for group_id, hosts in assigned.items():
            self._set_hosts(group_id, hosts)
        self.reporter.save_plan()

    # Supplied by PairScopeExecutor; declarations keep this mixin's contract explicit.
    def _hosts_for(
        self, sides: tuple[str, ...], index: int | None = None
    ) -> dict[str, str]:
        return super()._hosts_for(sides, index)  # type: ignore[misc]

    def _set_hosts(self, group_id: str, hosts: dict[str, str]) -> None:
        super()._set_hosts(group_id, hosts)  # type: ignore[misc]
