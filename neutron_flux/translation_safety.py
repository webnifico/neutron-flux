from __future__ import annotations

from .errors import SuiteError
from .models import Plan, PlannedGroup, RuntimeGroup, TestSpec
from .network_contract import (
    FLOATING_IP_TARGET_CONTRACT,
    NESTED_PUBLIC_PROJECT_NETWORK,
    PRIVATE_TRANSLATION_PROJECT_NETWORK,
    PROJECT_NETWORK_KINDS,
    canonical_group_kind,
)

_FIP_OPERATIONS = frozenset({"fip-baseline", "fip-withdraw", "fip-return"})
_FIP_EGRESS_OPERATIONS = frozenset(
    {
        "fip-egress-source-address",
        "fip-egress-mtu",
        "fip-egress-fragmentation",
    }
)
_TRANSLATION_GROUP_KINDS = frozenset({PRIVATE_TRANSLATION_PROJECT_NETWORK})


def floating_ip_target_sides(spec: TestSpec) -> dict[str, set[str]]:
    if spec.operation == "fip-peer":
        if spec.metadata.get("source_without_floating_ip"):
            return {str(spec.destination_group_id): {spec.destination_side.upper()}}
        targets: dict[str, set[str]] = {}
        for group, side in (
            (spec.source_group_id, spec.source_side),
            (spec.destination_group_id, spec.destination_side),
        ):
            if group:
                targets.setdefault(group, set()).add(side.upper())
        return targets
    group = floating_ip_target_group_id(spec)
    return {group: {"A"}} if group else {}


def floating_ip_target_group_id(spec: TestSpec) -> str | None:
    """Return the group whose private endpoint requires a floating IP."""

    if spec.operation == "fip-peer":
        return str(spec.destination_group_id or "") or None
    if spec.operation in _FIP_OPERATIONS:
        return str(spec.destination_group_id or "") or None
    if spec.operation in _FIP_EGRESS_OPERATIONS:
        return str(spec.source_group_id or "") or None
    if (
        spec.operation == "snat-packet-size-profile"
        and spec.metadata.get("require_floating_ip") is True
    ):
        return str(spec.source_group_id or "") or None
    return None


def _group_error(group: PlannedGroup, detail: str) -> SuiteError:
    return SuiteError(
        f"Unsafe translation topology rejected for {group.label} ({group.id}): {detail}"
    )


def _validate_private_translation_group(group: PlannedGroup) -> None:
    if group.pool_id or group.pool_name:
        raise _group_error(
            group,
            "a disposable private translation fixed subnet must not use a subnet pool",
        )
    if group.families != [4] or not group.synthetic_cidr:
        raise _group_error(
            group,
            "ordinary floating-IP translation requires an explicit synthetic IPv4 subnet",
        )
    if not group.floating_subnet_id:
        raise _group_error(
            group,
            "no explicit network:floatingip-eligible external subnet was selected",
        )
    if group.metadata.get("fixed_address_role") != "disposable-private":
        raise _group_error(group, "the fixed-address role is not disposable-private")
    if group.metadata.get("source_nat_mode") != "cloud-default":
        raise _group_error(
            group,
            "the dedicated translation router must use Neutron's default source NAT setting",
        )
    if group.metadata.get("source_nat_controlled_by_flux") is not False:
        raise _group_error(group, "Flux must not control the router source NAT setting")
    if group.metadata.get("source_nat_default_expected") is not True:
        raise _group_error(group, "the IPv4 topology must require default source NAT")
    if group.metadata.get("floating_ip_target_allowed") is not True:
        raise _group_error(
            group, "the plan does not explicitly allow this floating-IP target"
        )
    if group.metadata.get("floating_ip_target_contract") != FLOATING_IP_TARGET_CONTRACT:
        raise _group_error(
            group, "the floating-IP target contract is absent or invalid"
        )


def validate_plan_translation_safety(plan: Plan) -> None:
    """Reject unsafe planner output and unsafe immutable-plan payloads.

    This validation is deliberately structural.  It never guesses whether an
    address is public or private from its numeric prefix.
    """

    groups = {group.id: group for group in plan.groups}
    for group in groups.values():
        kind = canonical_group_kind(group.kind)
        if kind in PROJECT_NETWORK_KINDS and group.pool_id:
            if group.floating_subnet_id:
                raise _group_error(
                    group,
                    "a subnet-pool-derived fixed network must never receive an upstream floating-IP subnet",
                )
            if (
                group.metadata.get("floating_ip_target_allowed") is not False
                or group.metadata.get("subnet_pool_fixed_ip_only") is not True
            ):
                raise _group_error(
                    group,
                    "a subnet-pool-derived group must carry the fixed-IP-only contract",
                )
            expected_mode = (
                "cloud-default" if group.families == [4] else "not-applicable"
            )
            if group.metadata.get("source_nat_mode") != expected_mode:
                raise _group_error(
                    group,
                    "a subnet-pool-derived group must use the member-visible router default",
                )
            if group.metadata.get("source_nat_controlled_by_flux") is not False:
                raise _group_error(group, "Flux must not control router source NAT")
            if group.metadata.get("source_nat_default_expected") is not (
                group.families == [4]
            ):
                raise _group_error(
                    group, "the default source NAT contract is inconsistent"
                )
        if (
            group.metadata.get("floating_ip_target_allowed") is False
            and group.floating_subnet_id
        ):
            raise _group_error(
                group,
                "the group forbids floating-IP targeting but names a floating subnet",
            )
        if kind == PRIVATE_TRANSLATION_PROJECT_NETWORK:
            _validate_private_translation_group(group)
        elif kind == NESTED_PUBLIC_PROJECT_NETWORK:
            raise _group_error(
                group,
                "nested project-external topology is retired because a project member "
                "cannot mark a project network external or control router source NAT",
            )

    for spec in plan.tests:
        if spec.operation == "fip-peer":
            if (
                not spec.source_group_id
                or not spec.destination_group_id
                or spec.family != 4
            ):
                raise SuiteError(f"Invalid floating-IP peer test: {spec.id}")
            same_group = spec.source_group_id == spec.destination_group_id
            same_side = spec.source_side == spec.destination_side
            mode = spec.metadata.get("nat_path")
            if spec.metadata.get("source_without_floating_ip") and (
                same_group or mode != "snat-to-floating-ip"
            ):
                raise SuiteError(
                    f"A source without a floating IP requires a distinct-router SNAT-to-FIP path: {spec.id}"
                )
            if mode != (
                "snat-to-floating-ip"
                if spec.metadata.get("source_without_floating_ip") and not same_group
                else "self-hairpin"
                if same_group and same_side
                else "same-router"
                if same_group
                else "different-routers"
            ):
                raise SuiteError(f"Invalid floating-IP peer path mode: {spec.id}")
            if (
                spec.protocol not in {"icmp", "tcp", "udp"}
                or spec.expectation != "reachable"
            ):
                raise SuiteError(f"Invalid floating-IP peer probe contract: {spec.id}")
            for group_id, sides in floating_ip_target_sides(spec).items():
                peer_group = groups.get(group_id)
                if (
                    peer_group is None
                    or canonical_group_kind(peer_group.kind)
                    != PRIVATE_TRANSLATION_PROJECT_NETWORK
                ):
                    raise SuiteError(
                        f"Floating-IP peer test {spec.id} requires generated private translation groups"
                    )
                allowed = set(
                    peer_group.metadata.get("floating_ip_endpoint_sides") or ["A"]
                )
                if not sides <= allowed or not sides <= {"A", "B"}:
                    raise _group_error(
                        peer_group,
                        "floating-IP peer endpoint side is not explicitly allowed",
                    )
            source, destination = (
                groups[spec.source_group_id],
                groups[spec.destination_group_id],
            )
            if canonical_group_kind(source.kind) != PRIVATE_TRANSLATION_PROJECT_NETWORK:
                raise SuiteError(
                    f"Floating-IP peer source must use an owned private topology: {spec.id}"
                )
            if (
                source.floating_subnet_id != destination.floating_subnet_id
                or source.external_subnet_id != destination.external_subnet_id
                or source.external_network_id != destination.external_network_id
            ):
                raise SuiteError(
                    f"Floating-IP peer test {spec.id} requires the same external subnet"
                )
            continue
        target_group_id = floating_ip_target_group_id(spec)
        target_group = groups.get(target_group_id) if target_group_id else None
        if target_group_id and target_group is None:
            raise SuiteError(
                f"Unsafe floating-IP test {spec.id} references no planned target group"
            )
        if target_group is not None:
            kind = canonical_group_kind(target_group.kind)
            if kind not in _TRANSLATION_GROUP_KINDS:
                raise _group_error(
                    target_group,
                    f"test {spec.id} attempts floating-IP work on a non-translation group",
                )
            expected_side = "A"
            actual_side = (
                spec.destination_side
                if spec.operation in _FIP_OPERATIONS
                else spec.source_side
            ).upper()
            if actual_side != expected_side:
                raise _group_error(
                    target_group,
                    f"test {spec.id} targets side {actual_side}, not the explicit private side {expected_side}",
                )

        if spec.operation == "snat-packet-size-profile" or spec.operation in (
            _FIP_EGRESS_OPERATIONS
        ):
            source_group = groups.get(str(spec.source_group_id or ""))
            if (
                source_group is None
                or canonical_group_kind(source_group.kind)
                not in _TRANSLATION_GROUP_KINDS
            ):
                label = source_group.label if source_group else spec.source_group_id
                profile_label = (
                    "source-NAT packet-size profile"
                    if spec.operation == "snat-packet-size-profile"
                    else "floating-IP outbound path check"
                )
                raise SuiteError(
                    f"Unsafe {profile_label} rejected for {label}: test {spec.id} "
                    "does not originate from an explicit private translation topology"
                )
        if spec.operation == "source-nat-observe":
            raise SuiteError(
                f"Unsafe router source-NAT cloud operation test rejected: {spec.id}. "
                "Flux only observes Neutron's default setting."
            )


def validate_runtime_floating_ip_target(
    runtime: RuntimeGroup,
    endpoint_side: str = "A",
) -> tuple[str, str]:
    """Return the allowed endpoint side and fixed subnet, or fail pre-operation."""

    group = runtime.plan
    kind = canonical_group_kind(group.kind)
    if kind == PRIVATE_TRANSLATION_PROJECT_NETWORK:
        _validate_private_translation_group(group)
        endpoint_side = str(endpoint_side).upper()
        allowed = set(
            group.metadata.get("floating_ip_endpoint_sides")
            or [group.metadata.get("floating_ip_endpoint_side")]
        )
        if endpoint_side not in {"A", "B"} or endpoint_side not in allowed:
            raise _group_error(
                group,
                "floating IPs must target an explicitly allowed private endpoint side",
            )
        fixed_subnet_id = str(runtime.metadata.get("floating_ip_fixed_subnet_id") or "")
        expected_subnet_id = runtime.subnet_ids[0] if runtime.subnet_ids else ""
        if not fixed_subnet_id or fixed_subnet_id != expected_subnet_id:
            raise _group_error(
                group,
                "the runtime fixed subnet is not the generated private translation subnet",
            )
    else:
        raise _group_error(
            group,
            "floating IPs are prohibited outside explicit private translation topologies",
        )

    floating_subnet_id = str(group.floating_subnet_id or "")
    if not floating_subnet_id:
        raise _group_error(group, "no floating-IP subnet exists at runtime")
    if fixed_subnet_id == floating_subnet_id:
        raise _group_error(
            group,
            "the floating address subnet and target fixed-address subnet are identical",
        )
    if fixed_subnet_id not in runtime.subnet_ids:
        raise _group_error(
            group, "the floating-IP fixed subnet is not in the runtime group"
        )
    return endpoint_side, fixed_subnet_id


def validate_tenant_group_before_build(group: PlannedGroup) -> None:
    """Reject an unsafe group before its first OpenStack cloud operation."""

    kind = canonical_group_kind(group.kind)
    if kind == NESTED_PUBLIC_PROJECT_NETWORK:
        raise _group_error(
            group,
            "legacy nested project-external topology is not executable",
        )
    if kind == PRIVATE_TRANSLATION_PROJECT_NETWORK:
        _validate_private_translation_group(group)
        return
    if group.floating_subnet_id:
        raise _group_error(
            group,
            "only the dedicated private translation group may name a floating subnet",
        )
    if kind in PROJECT_NETWORK_KINDS and group.pool_id:
        if (
            group.metadata.get("floating_ip_target_allowed") is not False
            or group.metadata.get("subnet_pool_fixed_ip_only") is not True
        ):
            raise _group_error(
                group,
                "the subnet-pool-derived group is missing its fixed-IP-only contract",
            )
        expected_mode = "cloud-default" if group.families == [4] else "not-applicable"
        if group.metadata.get("source_nat_mode") != expected_mode:
            raise _group_error(
                group,
                "the subnet-pool-derived group must use the member-visible router default",
            )
        if group.metadata.get("source_nat_controlled_by_flux") is not False:
            raise _group_error(group, "Flux must not control router source NAT")


__all__ = [
    "floating_ip_target_group_id",
    "floating_ip_target_sides",
    "validate_plan_translation_safety",
    "validate_runtime_floating_ip_target",
    "validate_tenant_group_before_build",
]
