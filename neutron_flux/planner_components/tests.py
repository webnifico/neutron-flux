from __future__ import annotations

import copy
import dataclasses
import ipaddress
import itertools

# mypy: disable-error-code="attr-defined"
from ..errors import SuiteError
from ..models import PlannedGroup, TestSpec
from ..network_contract import (
    ONE_ROUTER_KINDS,
    PRIVATE_TRANSLATION_PROJECT_NETWORK,
    PROJECT_NETWORK_KINDS,
    PROJECT_NETWORK_ROUTING,
    PROJECT_PROVIDER_CONNECTIVITY,
    ROUTER_STATIC_ROUTING,
    STATIC_ROUTE_BASELINE,
    STATIC_ROUTE_INSTALL,
    STATIC_ROUTE_RESTORE,
    STATIC_ROUTE_WITHDRAW,
    STATIC_ROUTING_KINDS,
)
from ..policy import RoutingExpectation, TopologyPolicy


class TestSpecPlannerMixin:
    """Compatibility mixin for this planning concern."""

    @staticmethod
    def _routing_contract_names(group: PlannedGroup) -> set[str]:
        # A project group must never inherit its external network's aliases:
        # that would apply a provider contract to unrelated tenant fixed IPs.
        values = [group.id, group.label]
        if group.kind == "provider":
            values.extend([group.network_id, group.network_name])
        return {
            str(value).strip().casefold()
            for value in values
            if str(value or "").strip()
        }

    def _routing_contract(
        self,
        source: PlannedGroup,
        destination: PlannedGroup,
        family: int,
        protocol: str,
    ) -> dict[str, object] | None:
        source_names = self._routing_contract_names(source)
        destination_names = self._routing_contract_names(destination)
        matches = [
            item
            for item in self.config.routing_contracts
            if str(item.get("source") or "").casefold() in source_names
            and str(item.get("destination") or "").casefold() in destination_names
            and str(item.get("protocol") or "").lower() == protocol
            and item.get("family") in {None, family}
        ]
        exact = [item for item in matches if item.get("family") == family]
        selected = exact or [item for item in matches if item.get("family") is None]
        if len(selected) > 1:
            raise SuiteError(
                f"Ambiguous routing contracts for {source.id} to {destination.id}, "
                f"IPv{family} {protocol}; network names and IDs resolve to the same path"
            )
        return dict(selected[0]) if selected else None

    def _routing_protocols(
        self,
        source: PlannedGroup,
        destination: PlannedGroup,
        family: int,
        defaults: tuple[str, ...],
    ) -> tuple[str, ...]:
        configured = {
            str(item["protocol"])
            for item in self.config.routing_contracts
            if str(item["source"]).casefold() in self._routing_contract_names(source)
            and str(item["destination"]).casefold()
            in self._routing_contract_names(destination)
            and item.get("family") in {None, family}
        }
        return tuple(dict.fromkeys((*defaults, *sorted(configured))))

    def _routing_decision(
        self,
        source: PlannedGroup,
        destination: PlannedGroup,
        family: int,
        protocol: str,
        default: RoutingExpectation,
    ) -> tuple[RoutingExpectation, dict[str, object]]:
        contract = self._routing_contract(source, destination, family, protocol)
        decision = (
            default
            if contract is None
            else RoutingExpectation(
                str(contract["expectation"]),
                str(contract["reason"]),
                str(contract["expectation"]) != "observation",
                "operator-routing-contract",
            )
        )
        return decision, {
            "routing_policy": decision.metadata(),
            "routing_contract": contract,
            "routing_contract_configured": bool(contract),
            "routing_contract_provenance": contract.get("provenance")
            if contract
            else None,
        }

    def _validate_routing_contracts(self, providers: list[PlannedGroup]) -> None:
        if not self.config.routing_contracts:
            return
        known_names = set().union(
            *(self._routing_contract_names(group) for group in providers)
        )
        errors: list[str] = []
        for item in self.config.routing_contracts:
            source = str(item.get("source") or "")
            destination = str(item.get("destination") or "")
            source_groups = [
                group
                for group in providers
                if source.casefold() in self._routing_contract_names(group)
            ]
            destination_groups = [
                group
                for group in providers
                if destination.casefold() in self._routing_contract_names(group)
            ]
            if source.casefold() not in known_names:
                errors.append(f"unknown source network {source!r}")
            if destination.casefold() not in known_names:
                errors.append(f"unknown destination network {destination!r}")
            if {group.id for group in source_groups}.intersection(
                group.id for group in destination_groups
            ):
                errors.append(f"{source!r} and {destination!r} select the same group")
            for name, matched in (
                (source, source_groups),
                (destination, destination_groups),
            ):
                if len(matched) > 1 and any(
                    group.kind != "provider" for group in matched
                ):
                    errors.append(
                        f"ambiguous group {name!r}; use the exact planned group ID"
                    )
            family = item.get("family")
            if family is not None:
                if source_groups and not any(
                    family in group.families for group in source_groups
                ):
                    errors.append(f"{source!r} does not provide IPv{family}")
                if destination_groups and not any(
                    family in group.families for group in destination_groups
                ):
                    errors.append(f"{destination!r} does not provide IPv{family}")
        if errors:
            raise SuiteError(
                "network.routing_contracts cannot be applied: "
                + "; ".join(dict.fromkeys(errors))
            )

    def _test_specs(
        self,
        providers: list[PlannedGroup],
        tenants: list[PlannedGroup],
        warnings: list[str],
        skipped: list[dict[str, str]],
    ) -> list[TestSpec]:
        tests: list[TestSpec] = [
            TestSpec(
                id="CONTROL-OBSERVATION-PORTS",
                category="control",
                operation="controller-observation",
                family=None,
                expectation="reachable",
                expectation_reason="provider IPv4 control interface configured",
                authoritative=True,
                dependencies=[],
                phase="bootstrap",
                display_name="Configure the OpenStack probe controller",
                scenario="Controller readiness",
            ),
            TestSpec(
                id="CONTROL-SSH",
                category="control",
                operation="controller-ssh",
                family=4,
                expectation="reachable",
                expectation_reason="runner reaches the probe controller directly or through an isolated management bastion",
                authoritative=True,
                dependencies=[],
                phase="bootstrap",
                display_name="Reach the probe controller over SSH",
                scenario="Controller readiness",
            ),
        ]

        self._validate_routing_contracts([*providers, *tenants])

        attachments: list[tuple[PlannedGroup, str, int]] = []
        for group in [*providers, *tenants]:
            if group.kind in (ONE_ROUTER_KINDS | STATIC_ROUTING_KINDS):
                continue
            subnet_ids = group.subnet_ids if group.kind == "provider" else ["runtime"]
            for subnet_id in subnet_ids:
                family = (
                    self.discovery.subnet(subnet_id).ip_version
                    if subnet_id != "runtime"
                    else group.families[0]
                )
                attachments.append((group, subnet_id, family))
                subnet_name = (
                    self.discovery.subnet(subnet_id).name
                    if subnet_id != "runtime"
                    else "generated project subnet"
                )
                scenario = (
                    "Provider subnet connectivity"
                    if group.kind == "provider"
                    else "Project-network same-subnet connectivity"
                )
                for source_side, destination_side in (("A", "B"), ("B", "A")):
                    for protocol in ("icmp", "tcp", "udp"):
                        tests.append(
                            TestSpec(
                                id=f"SAME-{family}-{self._id_token(group.id, 34)}-{self._id_token(subnet_id, 16)}-{source_side}-{destination_side}-{protocol.upper()}",
                                category="same-subnet",
                                operation="probe",
                                family=family,
                                expectation="reachable",
                                expectation_reason="the source and destination use the same Neutron subnet",
                                authoritative=True,
                                dependencies=[group.id],
                                source_group_id=group.id,
                                destination_group_id=group.id,
                                source_side=source_side,
                                destination_side=destination_side,
                                source_subnet_id=subnet_id,
                                destination_subnet_id=subnet_id,
                                protocol=protocol,
                                phase="intra",
                                display_name=f"{scenario} — IPv{family} {source_side} to {destination_side} {protocol.upper()}",
                                scenario=scenario,
                                metadata={"subnet_name": subnet_name},
                            )
                        )

        # One atomic MTU scenario per family. The valid boundary is the
        # prerequisite; the oversized rejection is retained as stage evidence
        # rather than inflated into a second top-level result.
        for family in (4, 6):
            representative = next(
                (
                    item
                    for item in attachments
                    if item[2] == family and item[0].kind == "provider"
                ),
                None,
            )
            if not representative:
                continue
            group, subnet_id, _ = representative
            tests.append(
                TestSpec(
                    id=f"MTU-BOUNDARY-SCENARIO-{family}-{self._id_token(group.id, 34)}-{self._id_token(subnet_id, 16)}",
                    category="mtu",
                    operation="mtu-scenario",
                    family=family,
                    expectation="mtu-behavior-assessed",
                    expectation_reason=(
                        "record advertised-size delivery, PMTUD feedback and oversized "
                        "packet behavior; measured MTU differences are advisory"
                    ),
                    authoritative=True,
                    dependencies=[group.id],
                    source_group_id=group.id,
                    destination_group_id=group.id,
                    source_side="A",
                    destination_side="B",
                    source_subnet_id=subnet_id,
                    destination_subnet_id=subnet_id,
                    protocol="mtu",
                    phase="intra",
                    metadata={
                        "coverage_scope": "sampled path per address family",
                        "atomic_scenario": True,
                    },
                    display_name=f"Sampled provider MTU boundary — IPv{family}",
                    scenario="Sampled MTU validation",
                )
            )

            # Security-group state is tested as an actual OpenStack lifecycle:
            # blocked -> temporary allow rule -> blocked after rule removal.
            for operation, expectation, suffix, reason in (
                (
                    "security-deny",
                    "blocked",
                    "DENY",
                    "the control TCP port is not allowed by the actual security-group rules",
                ),
                (
                    "security-allow",
                    "reachable",
                    "ALLOW",
                    "a temporary OpenStack security-group rule allows the control TCP port",
                ),
                (
                    "security-restore",
                    "blocked",
                    "RESTORE",
                    "removing the temporary rule restores the original blocked state",
                ),
            ):
                tests.append(
                    TestSpec(
                        id=f"SECURITY-{suffix}-{family}-{self._id_token(group.id, 34)}-{self._id_token(subnet_id, 16)}",
                        category="security-group",
                        operation=operation,
                        family=family,
                        expectation=expectation,
                        expectation_reason=reason,
                        authoritative=True,
                        dependencies=[group.id],
                        source_group_id=group.id,
                        destination_group_id=group.id,
                        source_side="A",
                        destination_side="B",
                        source_subnet_id=subnet_id,
                        destination_subnet_id=subnet_id,
                        protocol="tcp",
                        phase="intra",
                        metadata={
                            "control_port_offset": 2,
                            "coverage_scope": "sampled path per address family",
                        },
                        display_name=f"Sampled security-group {suffix.lower()} test — IPv{family}",
                        scenario="Sampled security-group enforcement",
                    )
                )

        provider_by_subnet = {
            subnet_id: group for group in providers for subnet_id in group.subnet_ids
        }
        route_tenants = [item for item in tenants if item.kind in PROJECT_NETWORK_KINDS]
        for tenant in route_tenants:
            provider = provider_by_subnet.get(str(tenant.external_subnet_id))
            if not provider:
                continue
            for source, destination in ((provider, tenant), (tenant, provider)):
                default = TopologyPolicy.project_expectation(
                    tenant.relationship,
                    tenant.families[0],
                    source_is_project=source.id == tenant.id,
                    synthetic_private=bool(
                        tenant.synthetic_cidr and not tenant.pool_id
                    ),
                )
                protocols = (
                    ("icmp", "tcp", "udp")
                    if tenant.relationship
                    in {TopologyPolicy.DIRECT, TopologyPolicy.ISOLATED}
                    or default.expectation == "reachable"
                    else ("icmp", "tcp")
                )
                for protocol in self._routing_protocols(
                    source, destination, tenant.families[0], protocols
                ):
                    decision, policy_metadata = self._routing_decision(
                        source,
                        destination,
                        tenant.families[0],
                        protocol,
                        default,
                    )
                    if decision.expectation == "not-applicable":
                        tenant.metadata["external_checks_omitted_reason"] = (
                            decision.reason
                        )
                        continue
                    tests.append(
                        TestSpec(
                            id=f"ROUTE-{tenant.families[0]}-{self._id_token(source.id, 28)}-TO-{self._id_token(destination.id, 28)}-{protocol.upper()}",
                            category=PROJECT_PROVIDER_CONNECTIVITY,
                            operation="probe",
                            family=tenant.families[0],
                            expectation=decision.expectation,
                            expectation_reason=decision.reason,
                            authoritative=decision.authoritative,
                            dependencies=[source.id, destination.id],
                            source_group_id=source.id,
                            destination_group_id=destination.id,
                            source_side="A",
                            destination_side="A",
                            source_subnet_id=(
                                tenant.external_subnet_id
                                if source.kind == "provider"
                                else "runtime"
                            ),
                            destination_subnet_id=(
                                tenant.external_subnet_id
                                if destination.kind == "provider"
                                else "runtime"
                            ),
                            protocol=protocol,
                            phase="cross",
                            metadata={
                                **policy_metadata,
                                "routing_relationship": tenant.relationship,
                                "routing_relationship_label": TopologyPolicy.relationship_label(
                                    tenant.relationship
                                ),
                            },
                            display_name=(
                                f"Matching-address-scope project/provider connectivity — IPv{tenant.families[0]} {protocol.upper()}"
                                if tenant.relationship == TopologyPolicy.DIRECT
                                else f"Different-address-scope project/provider connectivity — IPv{tenant.families[0]} {protocol.upper()}"
                                if tenant.relationship == TopologyPolicy.ISOLATED
                                else f"Private fixed-IP egress through router SNAT — IPv{tenant.families[0]} {protocol.upper()}"
                                if decision.basis == "router-default-snat"
                                else f"Project/provider fixed-IP connectivity — IPv{tenant.families[0]} {protocol.upper()}"
                            ),
                            scenario=(
                                "Project/provider connectivity with matching address scopes"
                                if tenant.relationship == TopologyPolicy.DIRECT
                                else "Project/provider connectivity with different address scopes"
                                if tenant.relationship == TopologyPolicy.ISOLATED
                                else "Project/provider fixed-IP observation"
                            ),
                        )
                    )

        # Provider-to-provider coverage is pairwise per family. For routed
        # provider networks this avoids describing an anchor-only spanning graph
        # as complete segment coverage. Selected provider networks carry an
        # explicit bidirectional routing requirement for every shared family.
        for family in (4, 6):
            family_groups = [item for item in providers if family in item.families]
            for first, second in itertools.combinations(
                family_groups,
                2,
            ):
                first_subnet = next(
                    item
                    for item in first.subnet_ids
                    if self.discovery.subnet(item).ip_version == family
                )
                second_subnet = next(
                    item
                    for item in second.subnet_ids
                    if self.discovery.subnet(item).ip_version == family
                )
                same_provider_network = first.network_id == second.network_id
                distinct_segments = first.segment_id != second.segment_id
                routed_segments = same_provider_network and distinct_segments
                default = TopologyPolicy.provider_expectation(
                    routed_segments=routed_segments
                )
                category = (
                    "routed-provider"
                    if routed_segments
                    else "provider-network-connectivity"
                )
                relationship = (
                    "routed-provider" if routed_segments else "separate-provider"
                )
                protocols = ("icmp", "tcp", "udp")

                for source, source_subnet, target, target_subnet in (
                    (first, first_subnet, second, second_subnet),
                    (second, second_subnet, first, first_subnet),
                ):
                    for protocol in self._routing_protocols(
                        source, target, family, protocols
                    ):
                        decision, policy_metadata = self._routing_decision(
                            source,
                            target,
                            family,
                            protocol,
                            default,
                        )
                        tests.append(
                            TestSpec(
                                id=(
                                    f"PROVIDER-ROUTE-{family}-"
                                    f"{self._id_token(source.id, 28)}-TO-"
                                    f"{self._id_token(target.id, 28)}-"
                                    f"{protocol.upper()}"
                                ),
                                category=category,
                                operation="probe",
                                family=family,
                                expectation=decision.expectation,
                                expectation_reason=decision.reason,
                                authoritative=decision.authoritative,
                                dependencies=[source.id, target.id],
                                source_group_id=source.id,
                                destination_group_id=target.id,
                                source_subnet_id=source_subnet,
                                destination_subnet_id=target_subnet,
                                protocol=protocol,
                                phase="cross",
                                metadata={
                                    "routing_relationship": relationship,
                                    "coverage_scope": (
                                        "complete pairwise provider-group "
                                        "matrix for this address family"
                                    ),
                                    **policy_metadata,
                                },
                                display_name=(
                                    f"Routed provider segment connectivity — "
                                    f"IPv{family} {protocol.upper()}"
                                    if category == "routed-provider"
                                    else f"Separate provider network "
                                    f"connectivity — IPv{family} "
                                    f"{protocol.upper()}"
                                ),
                                scenario=(
                                    "Routed provider network segments"
                                    if category == "routed-provider"
                                    else "Separate provider networks"
                                ),
                            )
                        )

        self._append_internal_router_tests(tests, tenants)
        # The router-source-NAT-only profile must run before Flux allocates a
        # floating IP to the same endpoint. Floating-IP ingress and egress
        # profiles are planned immediately afterwards as a distinct NAT path.
        self._append_egress_tests(tests, providers, tenants, skipped)
        self._append_fip_tests(tests, providers, tenants, warnings)
        self._append_lifecycle_tests(tests, providers, tenants)
        self._append_fip_peer_tests(tests, tenants)
        omitted = {spec.id for spec in tests if spec.expectation == "observation"}
        # A lifecycle cannot establish a verdict without its omitted baseline.
        while True:
            dependent = {
                spec.id
                for spec in tests
                if set(spec.requires + spec.requires_pass) & omitted
            }
            if dependent <= omitted:
                break
            omitted.update(dependent)
        skipped.extend(
            [
                {
                    "resource": spec.display_name or spec.id,
                    "reason": "No declared routing expectation for this path; excluded from pass/fail coverage",
                }
                for spec in tests
                if spec.id in omitted
            ]
        )
        tests = [spec for spec in tests if spec.id not in omitted]
        applied = [spec.metadata.get("routing_contract") for spec in tests]
        for contract in self.config.routing_contracts:
            if contract not in applied:
                raise SuiteError(
                    "network.routing_contracts contains a rule with no applicable test: "
                    f"{contract['source']} to {contract['destination']}, "
                    f"IPv{contract.get('family') or 'any'} {contract['protocol']}"
                )
        return tests

    def _append_internal_router_tests(
        self, tests: list[TestSpec], tenants: list[PlannedGroup]
    ) -> None:
        for group in tenants:
            family = group.families[0]
            if group.kind in ONE_ROUTER_KINDS:
                for source_side, destination_side in (("A", "B"), ("B", "A")):
                    for protocol in ("icmp", "tcp", "udp"):
                        tests.append(
                            TestSpec(
                                id=f"PROJECT-ROUTING-{family}-{source_side}-{destination_side}-{protocol.upper()}-{self._id_token(group.id, 28)}",
                                category=PROJECT_NETWORK_ROUTING,
                                operation="probe",
                                family=family,
                                expectation="reachable",
                                expectation_reason="both project networks are attached to the same Neutron router",
                                authoritative=True,
                                dependencies=[group.id],
                                source_group_id=group.id,
                                destination_group_id=group.id,
                                source_side=source_side,
                                destination_side=destination_side,
                                source_subnet_id=f"side-{source_side}",
                                destination_subnet_id=f"side-{destination_side}",
                                protocol=protocol,
                                phase="intra",
                                display_name=f"Routing between project networks through one router — IPv{family} {source_side} to {destination_side} {protocol.upper()}",
                                scenario="Routing between project networks through one Neutron router",
                            )
                        )
                tests.append(
                    TestSpec(
                        id=f"PROJECT-ROUTER-INTERFACE-LIFECYCLE-{family}-{self._id_token(group.id, 28)}",
                        category="router-interface-lifecycle",
                        operation="router-lifecycle-scenario",
                        family=family,
                        expectation="lifecycle-complete",
                        expectation_reason=(
                            "a reachable project-network routing baseline must become blocked after "
                            "API-confirmed attachment removal and recover after restoration"
                        ),
                        authoritative=True,
                        dependencies=[group.id],
                        source_group_id=group.id,
                        destination_group_id=group.id,
                        source_side="A",
                        destination_side="B",
                        source_subnet_id="side-A",
                        destination_subnet_id="side-B",
                        protocol="tcp",
                        phase="intra",
                        metadata={
                            "router_interface_side": "B",
                            "atomic_scenario": True,
                        },
                        display_name=f"Project-network router-interface lifecycle — IPv{family}",
                        scenario="Router-interface lifecycle for every usable project subnet pool",
                    )
                )
            elif group.kind in STATIC_ROUTING_KINDS:
                baseline_id = (
                    f"STATIC-ROUTE-BASELINE-{family}-{self._id_token(group.id, 30)}"
                )
                install_id = (
                    f"STATIC-ROUTE-INSTALL-{family}-{self._id_token(group.id, 30)}"
                )
                tests.append(
                    TestSpec(
                        id=baseline_id,
                        category=ROUTER_STATIC_ROUTING,
                        operation=STATIC_ROUTE_BASELINE,
                        family=family,
                        expectation="blocked",
                        expectation_reason="the two routers have no route to the remote project subnet before router static routes are configured",
                        authoritative=True,
                        dependencies=[group.id],
                        source_group_id=group.id,
                        destination_group_id=group.id,
                        source_side="A",
                        destination_side="B",
                        source_subnet_id="side-A",
                        destination_subnet_id="side-B",
                        protocol="icmp",
                        phase="intra",
                        display_name=f"Two-router baseline without static routes — IPv{family}",
                        scenario="Routing between two Neutron routers using static routes",
                    )
                )
                tests.append(
                    TestSpec(
                        id=install_id,
                        requires=[baseline_id],
                        category=ROUTER_STATIC_ROUTING,
                        operation=STATIC_ROUTE_INSTALL,
                        family=family,
                        expectation="reachable",
                        expectation_reason="Neutron router static routes on both routers provide a path to the remote project subnet",
                        authoritative=True,
                        dependencies=[group.id],
                        source_group_id=group.id,
                        destination_group_id=group.id,
                        source_side="A",
                        destination_side="B",
                        source_subnet_id="side-A",
                        destination_subnet_id="side-B",
                        protocol="icmp",
                        phase="intra",
                        display_name=f"Add routes between two Neutron routers — IPv{family}",
                        scenario="Routing between two Neutron routers using static routes",
                    )
                )
                for source_side, destination_side in (("A", "B"), ("B", "A")):
                    for protocol in ("icmp", "tcp", "udp"):
                        if (
                            source_side == "A"
                            and destination_side == "B"
                            and protocol == "icmp"
                        ):
                            continue
                        tests.append(
                            TestSpec(
                                id=f"STATIC-ROUTE-PROBE-{family}-{source_side}-{destination_side}-{protocol.upper()}-{self._id_token(group.id, 24)}",
                                category=ROUTER_STATIC_ROUTING,
                                operation="probe",
                                requires=[install_id],
                                family=family,
                                expectation="reachable",
                                expectation_reason="the configured Neutron router static routes provide bidirectional project-network routing",
                                authoritative=True,
                                dependencies=[group.id],
                                source_group_id=group.id,
                                destination_group_id=group.id,
                                source_side=source_side,
                                destination_side=destination_side,
                                source_subnet_id=f"side-{source_side}",
                                destination_subnet_id=f"side-{destination_side}",
                                protocol=protocol,
                                phase="intra",
                                display_name=f"Two-router static-route connectivity — IPv{family} {source_side} to {destination_side} {protocol.upper()}",
                                scenario="Routing between two Neutron routers using static routes",
                            )
                        )
                for operation, expectation, suffix in (
                    (STATIC_ROUTE_WITHDRAW, "withdrawn", "WITHDRAW"),
                    (STATIC_ROUTE_RESTORE, "restored", "RESTORE"),
                ):
                    tests.append(
                        TestSpec(
                            id=f"STATIC-ROUTE-{suffix}-{family}-{self._id_token(group.id, 30)}",
                            category=ROUTER_STATIC_ROUTING,
                            operation=operation,
                            requires=[
                                install_id
                                if operation == STATIC_ROUTE_WITHDRAW
                                else f"STATIC-ROUTE-WITHDRAW-{family}-{self._id_token(group.id, 30)}"
                            ],
                            family=family,
                            expectation=expectation,
                            expectation_reason="removing one configured route should interrupt one direction and restoring it should return connectivity",
                            authoritative=True,
                            dependencies=[group.id],
                            source_group_id=group.id,
                            destination_group_id=group.id,
                            source_side="A",
                            destination_side="B",
                            source_subnet_id="side-A",
                            destination_subnet_id="side-B",
                            protocol="tcp",
                            phase="intra",
                            metadata={"route_side": "A"},
                            display_name=(
                                f"Withdraw one router static route — IPv{family}"
                                if operation == STATIC_ROUTE_WITHDRAW
                                else f"Restore removed router static route — IPv{family}"
                            ),
                            scenario="Routing between two Neutron routers using static routes",
                        )
                    )

    def _append_fip_tests(
        self,
        tests: list[TestSpec],
        providers: list[PlannedGroup],
        tenants: list[PlannedGroup],
        warnings: list[str],
    ) -> None:
        ipv4_tenants = [
            item
            for item in tenants
            if item.families == [4] and item.kind == PRIVATE_TRANSLATION_PROJECT_NETWORK
        ]
        fip_capable = [item for item in ipv4_tenants if item.floating_subnet_id]
        if not fip_capable:
            if ipv4_tenants:
                warnings.append(
                    "No selected external IPv4 subnet is eligible for "
                    "network:floatingip allocation; floating-IP tests are omitted"
                )
            return

        reason = (
            "a controlled provider endpoint on the floating-IP subnet must reach the "
            "associated private endpoint; this validates translation, not upstream routing"
        )
        for tenant in fip_capable:
            target_subnet = self.discovery.subnet(str(tenant.floating_subnet_id))
            observer = next(
                (group for group in providers if target_subnet.id in group.subnet_ids),
                None,
            )
            observer_subnet_id = target_subnet.id if observer else None
            observer_reason = (
                "controlled provider endpoint on the floating-IP subnet"
                if observer
                else "no controlled provider endpoint on the floating-IP subnet"
            )
            dependencies = [tenant.id] + ([observer.id] if observer else [])
            if not observer:
                warnings.append(
                    f"No controlled provider endpoint exists on {target_subnet.cidr}; "
                    f"floating-IP ingress for {tenant.label} is excluded from pass/fail coverage "
                    "without asserting an upstream routing policy"
                )
            metadata = {
                "coverage_scope": (
                    "every eligible disposable private IPv4 translation topology"
                ),
                "router_gateway_subnet_id": tenant.external_subnet_id,
                "floating_ip_subnet_id": tenant.floating_subnet_id,
                "observer_group_id": observer.id if observer else None,
                "observer_mode": "controlled-provider"
                if observer
                else "runner-observation",
                "observer_path_contract": "same-provider-subnet" if observer else None,
                "claim_boundary": "floating-IP translation on the external subnet; upstream routing is observed separately",
                "authority_required": True,
                "observer_authoritative": False,
                "observer_reason": observer_reason,
                "target_external_cidr": target_subnet.cidr,
            }
            token = self._id_token(tenant.id, 36)
            baseline_ids: dict[str, str] = {}
            for protocol in ("icmp", "tcp", "udp"):
                baseline_id = f"FIP-BASELINE-{protocol.upper()}-{token}"
                baseline_ids[protocol] = baseline_id
                tests.append(
                    TestSpec(
                        id=baseline_id,
                        category="floating-ip",
                        operation="fip-baseline",
                        family=4,
                        expectation="reachable" if observer else "observation",
                        expectation_reason=reason,
                        authoritative=observer is not None,
                        dependencies=list(dict.fromkeys(dependencies)),
                        source_group_id=observer.id if observer else None,
                        destination_group_id=tenant.id,
                        source_side="A",
                        destination_side="A",
                        source_subnet_id=observer_subnet_id,
                        destination_subnet_id="runtime",
                        protocol=protocol,
                        phase="cross",
                        metadata=dict(metadata),
                        display_name=(
                            f"Floating IPv4 ingress for {tenant.label} — "
                            f"{protocol.upper()} probe"
                        ),
                        scenario="Floating IPv4 ingress",
                    )
                )
            provider_for_gateway = next(
                (
                    item
                    for item in providers
                    if str(tenant.external_subnet_id or "") in item.subnet_ids
                ),
                None,
            )
            if provider_for_gateway is not None:
                external_label = str(
                    tenant.external_network_name
                    or tenant.external_network_id
                    or "selected external network"
                )
                outbound_token = self._id_token(
                    (
                        "private-translation-"
                        f"{external_label}-{tenant.external_subnet_id}"
                    ),
                    48,
                )
                source_address_id = f"FIP-EGRESS-SOURCE-ADDRESS-{outbound_token}"
                mtu_id = f"FIP-EGRESS-MTU-{outbound_token}"
                fragmentation_id = f"FIP-EGRESS-FRAGMENTATION-{outbound_token}"
                fip_egress_metadata = {
                    "coverage_scope": "every eligible IPv4 floating-IP topology",
                    "egress_translation_mode": "floating-ip-egress",
                    "require_floating_ip": True,
                    "external_network_name": tenant.external_network_name,
                    "floating_ip_subnet_id": tenant.floating_subnet_id,
                    "fixed_address_role": "disposable-private",
                }
                tests.extend(
                    [
                        TestSpec(
                            id=source_address_id,
                            category="floating-ip-egress-source-address",
                            operation="fip-egress-source-address",
                            family=4,
                            expectation="provider-observes-floating-ip",
                            expectation_reason=(
                                "the private endpoint must establish one outbound TCP "
                                "connection and the provider observer must see the "
                                "endpoint's floating IP as the translated source address"
                            ),
                            authoritative=True,
                            dependencies=[tenant.id, provider_for_gateway.id],
                            source_group_id=tenant.id,
                            destination_group_id=provider_for_gateway.id,
                            source_side="A",
                            destination_side="A",
                            source_subnet_id="runtime",
                            destination_subnet_id=tenant.external_subnet_id,
                            protocol="tcp",
                            phase="cross",
                            metadata={
                                **fip_egress_metadata,
                                "claim_boundary": (
                                    "the project endpoint initiates one TCP connection; "
                                    "the provider endpoint reports only the source address "
                                    "it observed"
                                ),
                            },
                            display_name=(
                                "Floating-IP outbound source-address verification "
                                f"through {external_label}"
                            ),
                            scenario=(
                                f"Floating IPv4 outbound path through {external_label}"
                            ),
                        ),
                        TestSpec(
                            id=mtu_id,
                            category="floating-ip-egress-mtu",
                            operation="fip-egress-mtu",
                            family=4,
                            expectation="mtu-behavior-assessed",
                            expectation_reason=(
                                "after the outbound floating-IP source-address check "
                                "passes, measure the no-fragment path MTU and record "
                                "differences from the advertised MTU as advisory"
                            ),
                            authoritative=True,
                            dependencies=[tenant.id, provider_for_gateway.id],
                            source_group_id=tenant.id,
                            destination_group_id=provider_for_gateway.id,
                            source_side="A",
                            destination_side="A",
                            source_subnet_id="runtime",
                            destination_subnet_id=tenant.external_subnet_id,
                            protocol="icmp",
                            phase="cross",
                            metadata={
                                **fip_egress_metadata,
                                "claim_boundary": (
                                    "DF/PMTUD probes measure only the outbound "
                                    "floating-IP path's no-fragment packet-size boundary"
                                ),
                                "source_address_test_id": source_address_id,
                            },
                            display_name=(
                                "Floating-IP outbound no-fragment path MTU "
                                f"through {external_label}"
                            ),
                            scenario=(
                                f"Floating IPv4 outbound path through {external_label}"
                            ),
                            requires_pass=[source_address_id],
                        ),
                        TestSpec(
                            id=fragmentation_id,
                            category="floating-ip-egress-fragmentation",
                            operation="fip-egress-fragmentation",
                            family=4,
                            expectation="fragmentation-behaviour-classified",
                            expectation_reason=(
                                "after the outbound path MTU check passes, Flux must "
                                "separately determine whether a source-sized IPv4 packet "
                                "can cross when fragmentation is permitted"
                            ),
                            authoritative=True,
                            dependencies=[tenant.id, provider_for_gateway.id],
                            source_group_id=tenant.id,
                            destination_group_id=provider_for_gateway.id,
                            source_side="A",
                            destination_side="A",
                            source_subnet_id="runtime",
                            destination_subnet_id=tenant.external_subnet_id,
                            protocol="icmp",
                            phase="cross",
                            metadata={
                                **fip_egress_metadata,
                                "claim_boundary": (
                                    "the fragmentation check runs independently from "
                                    "the path-MTU verdict and attributes location only "
                                    "when endpoint counters support it"
                                ),
                                "source_address_test_id": source_address_id,
                                "mtu_test_id": mtu_id,
                            },
                            display_name=(
                                "Floating-IP outbound IPv4 fragmentation "
                                f"through {external_label}"
                            ),
                            scenario=(
                                f"Floating IPv4 outbound path through {external_label}"
                            ),
                            requires_pass=[mtu_id],
                        ),
                    ]
                )
            else:
                warnings.append(
                    f"No provider endpoint matched the router external subnet for "
                    f"{tenant.label}; floating-IP outbound source-address, path-MTU, "
                    "and fragmentation checks are omitted"
                )

            withdraw_id = f"FIP-WITHDRAW-{self._id_token(tenant.id, 40)}"
            for operation, expectation, display_name in (
                ("fip-withdraw", "withdrawn", "Detach floating IPv4 address"),
                ("fip-return", "restored", "Reassociate floating IPv4 address"),
            ):
                tests.append(
                    TestSpec(
                        id=(
                            f"FIP-{operation.split('-')[-1].upper()}-"
                            f"{self._id_token(tenant.id, 40)}"
                        ),
                        category="floating-ip-lifecycle",
                        operation=operation,
                        family=4,
                        expectation=expectation,
                        expectation_reason=reason,
                        authoritative=False,
                        dependencies=list(dict.fromkeys(dependencies)),
                        source_group_id=observer.id if observer else None,
                        destination_group_id=tenant.id,
                        source_side="A",
                        destination_side="A",
                        source_subnet_id=observer_subnet_id,
                        destination_subnet_id="runtime",
                        protocol="tcp",
                        phase="cross",
                        metadata=dict(metadata),
                        display_name=f"{display_name} for {tenant.label}",
                        scenario="Floating IPv4 lifecycle",
                        requires=(
                            [baseline_ids["tcp"]]
                            if operation == "fip-withdraw"
                            else [withdraw_id]
                        ),
                        # Restore still runs after an uncertain/failed detach,
                        # but cannot run without a successful original baseline.
                        requires_pass=[baseline_ids["tcp"]],
                    )
                )

    def _append_fip_peer_tests(
        self, tests: list[TestSpec], tenants: list[PlannedGroup]
    ) -> None:
        """Bounded NAT coverage: two endpoints and at most two routers per batch."""
        cidrs = iter(self._private_translation_ipv4_cidrs())
        for group in list(tenants):
            if (
                group.kind != PRIVATE_TRANSLATION_PROJECT_NETWORK
                or not group.floating_subnet_id
            ):
                continue
            group.metadata["floating_ip_endpoint_sides"] = ["A", "B"]
            peer_metadata = copy.deepcopy(group.metadata)
            peer_metadata.update(
                floating_ip_endpoint_sides=["A"], fip_peer_for=group.id
            )
            peer = dataclasses.replace(
                group,
                id=group.id + "-fip-peer",
                label=group.label + " / second router",
                synthetic_cidr=next(cidrs),
                metadata=peer_metadata,
            )
            tenants.append(peer)
            snat_source = dataclasses.replace(
                group,
                id=group.id + "-snat-source",
                label=group.label + " / source without floating IP",
                synthetic_cidr=next(cidrs),
                metadata={**copy.deepcopy(peer_metadata), "snat_source_for": group.id},
            )
            tenants.append(snat_source)
            # Both routers use the same external subnet; no undeclared upstream
            # route or routing relationship between provider networks is assumed.
            paths = [
                (group, "A", group, "B", "same-router"),
                (group, "B", group, "A", "same-router"),
                (group, "A", group, "A", "self-hairpin"),
                (group, "B", group, "B", "self-hairpin"),
                (group, "A", peer, "A", "different-routers"),
                (peer, "A", group, "A", "different-routers"),
                (peer, "A", peer, "A", "self-hairpin"),
                (snat_source, "A", peer, "A", "snat-to-floating-ip"),
            ]
            for source, source_side, destination, destination_side, mode in paths:
                for protocol in ("icmp", "tcp", "udp"):
                    identity = f"{source.id}:{source_side}:{destination.id}:{destination_side}:{mode}"
                    tests.append(
                        TestSpec(
                            id=f"FIP-PEER-{protocol.upper()}-{self._id_token(identity, 55)}",
                            category="floating-ip-peer",
                            operation="fip-peer",
                            family=4,
                            expectation="reachable",
                            authoritative=True,
                            expectation_reason=(
                                "The source has no floating IP and uses verified router SNAT to reach the destination's verified floating-IP mapping"
                                if mode == "snat-to-floating-ip"
                                else "Flux verifies the VM and its own floating-IP mapping"
                                if mode == "self-hairpin"
                                else "Flux owns and verifies both private endpoints and floating-IP mappings on the same external subnet"
                            ),
                            # Reuse the two-router A/A batch for the peer's
                            # own-FIP check; do not boot an unused second peer.
                            dependencies=sorted(
                                {group.id, peer.id}
                                if source.id == peer.id and mode == "self-hairpin"
                                else {source.id, destination.id}
                            ),
                            source_group_id=source.id,
                            destination_group_id=destination.id,
                            source_side=source_side,
                            destination_side=destination_side,
                            source_subnet_id="runtime",
                            destination_subnet_id="runtime",
                            protocol=protocol,
                            phase="cross",
                            metadata={
                                "nat_path": mode,
                                "source_without_floating_ip": mode
                                == "snat-to-floating-ip",
                                "floating_ip_subnet_id": group.floating_subnet_id,
                                "coverage_scope": "bounded floating-IP and hairpin connectivity matrix",
                            },
                            display_name=(
                                f"{'Own floating-IP hairpin' if mode == 'self-hairpin' else 'Private fixed IP without floating IP to floating IP' if mode == 'snat-to-floating-ip' else 'VM with floating IP to peer floating IP'} "
                                f"— {mode}, {source_side} to {destination_side}, {protocol.upper()} / {group.external_network_name}"
                            ),
                            scenario={
                                "same-router": "Floating IPs behind the same router",
                                "self-hairpin": "VM reaching its own floating IP",
                                "different-routers": "Floating IPs behind separate routers",
                                "snat-to-floating-ip": "Router SNAT to destination floating-IP DNAT",
                            }[mode],
                        )
                    )
            # Both router owners already exist in the separate-router batch.
            # Test each one's own mapping there so whichever owner moves has
            # hairpin coverage before and after the single transition.
            tests.extend(
                dataclasses.replace(
                    spec,
                    id=f"{spec.id}-TWO-ROUTERS",
                    dependencies=sorted({group.id, peer.id}),
                    metadata={**spec.metadata, "hairpin_topology": "different-routers"},
                )
                for spec in list(tests)
                if spec.operation == "fip-peer"
                and spec.source_group_id == group.id
                and spec.destination_group_id == group.id
                and spec.source_side == spec.destination_side == "A"
                and spec.metadata.get("nat_path") == "self-hairpin"
                and len(spec.dependencies) == 1
            )

    def _append_egress_tests(
        self,
        tests: list[TestSpec],
        providers: list[PlannedGroup],
        tenants: list[PlannedGroup],
        skipped: list[dict[str, str]] | None = None,
    ) -> None:
        for family in (4, 6):
            targets = (
                self.config.ipv4_targets if family == 4 else self.config.ipv6_targets
            )
            representatives: list[PlannedGroup] = []
            provider = next(
                (item for item in providers if family in item.families), None
            )
            tenant = next(
                (
                    item
                    for item in tenants
                    if family in item.families
                    and (
                        item.kind == PRIVATE_TRANSLATION_PROJECT_NETWORK
                        if family == 4
                        else item.kind in PROJECT_NETWORK_KINDS
                    )
                    and self._egress_policy(item, family, targets)[0]
                    != "not-applicable"
                ),
                None,
            )
            if provider:
                representatives.append(provider)
            if tenant:
                representatives.append(tenant)
            if targets and not representatives and skipped is not None:
                skipped.append(
                    {
                        "resource": f"External IPv{family} reachability",
                        "reason": (
                            f"No eligible selected provider or project-network path "
                            f"supports external IPv{family} reachability; the selected "
                            "external targets were skipped"
                        ),
                    }
                )
            for group in representatives:
                subnet_id = (
                    next(
                        item
                        for item in group.subnet_ids
                        if self.discovery.subnet(item).ip_version == family
                    )
                    if group.kind == "provider"
                    else "runtime"
                )
                for target in targets:
                    try:
                        if ipaddress.ip_address(target).version != family:
                            continue
                    except ValueError:
                        continue
                    expectation, reason, authoritative = self._egress_policy(
                        group, family, [target]
                    )
                    tests.append(
                        TestSpec(
                            id=f"EGRESS-{family}-{self._id_token(group.id + '-' + target, 42)}",
                            category="egress",
                            operation="egress",
                            family=family,
                            expectation=expectation,
                            expectation_reason=reason,
                            authoritative=authoritative,
                            dependencies=[group.id],
                            source_group_id=group.id,
                            source_subnet_id=subnet_id,
                            source_side="B",
                            protocol="icmp",
                            phase="intra",
                            metadata={
                                "target": target,
                                "coverage_scope": "sampled provider and project-network path per family",
                            },
                            display_name=f"Sampled external IPv{family} reachability to {target}",
                            scenario="Sampled external egress",
                        )
                    )

        # Profile the actual project-network -> runner router SNAT path.  The
        # project endpoint initiates the connection: a runner cannot originate
        # a new flow to a fixed IP hidden behind source NAT without a floating
        # IP or port-forwarding rule.
        provider_by_subnet = {
            str(subnet_id): group
            for group in providers
            for subnet_id in group.subnet_ids
        }
        for project_group in tenants:
            if (
                4 not in project_group.families
                or project_group.kind != PRIVATE_TRANSLATION_PROJECT_NETWORK
                or project_group.metadata.get("source_nat_mode") != "cloud-default"
            ):
                continue
            provider_group = provider_by_subnet.get(
                str(project_group.external_subnet_id or "")
            )
            if provider_group is None:
                continue
            profile = TestSpec(
                id=f"SNAT-PACKET-SIZE-{self._id_token(project_group.id, 44)}",
                category="source-nat-packet-size",
                operation="snat-packet-size-profile",
                family=4,
                expectation="profile-complete",
                expectation_reason=(
                    "the project endpoint must be able to initiate a returnable "
                    "flow to a disposable provider endpoint through the router's SNAT "
                    "egress path; Flux then verifies translated source identity and "
                    "measures no-fragment path MTU and fragmentation capability"
                ),
                authoritative=True,
                dependencies=[project_group.id, provider_group.id],
                source_group_id=project_group.id,
                destination_group_id=provider_group.id,
                source_side="A",
                destination_side="A",
                source_subnet_id="runtime",
                destination_subnet_id=project_group.external_subnet_id,
                protocol="mtu",
                phase="cross",
                metadata={
                    "coverage_scope": (
                        "every eligible disposable private IPv4 translation topology"
                    ),
                    "claim_boundary": (
                        "project endpoint initiates the flow; the runner only replies "
                        "through established router SNAT state"
                    ),
                    "external_network_name": project_group.external_network_name,
                    "fixed_address_role": "disposable-private",
                    "egress_translation_mode": "router-source-nat",
                    "require_no_floating_ip": True,
                },
                display_name=("Router SNAT packet-size and fragmentation profile"),
                scenario="Project-network external egress through router source NAT",
            )
            tests.extend(
                dataclasses.replace(
                    profile,
                    id=f"SNAT-BASELINE-{protocol.upper()}-{self._id_token(project_group.id, 44)}",
                    category="source-nat-connectivity",
                    operation="probe",
                    protocol=protocol,
                    expectation="reachable",
                    expectation_reason=(
                        "the owned private endpoint must reach the controlled provider "
                        "endpoint through its router's source NAT, without a floating IP"
                    ),
                    metadata=dict(profile.metadata),
                    display_name=f"Router SNAT connectivity — {protocol.upper()}",
                )
                for protocol in ("icmp", "tcp", "udp")
            )
            tests.append(profile)

    def _egress_policy(
        self,
        group: PlannedGroup,
        family: int,
        targets: list[str],
    ) -> tuple[str, str, bool]:
        if not targets:
            return (
                "not-applicable",
                "no external target configured for this IP family",
                False,
            )

        omitted_reason = group.metadata.get("external_checks_omitted_reason")
        if group.expected_routing == "not-applicable" or omitted_reason:
            return (
                "not-applicable",
                str(omitted_reason)
                if omitted_reason
                else "this topology supplies internal coverage only; no external route was declared",
                False,
            )

        explicitly_configured = (
            self.config.ipv4_targets_configured
            if family == 4
            else self.config.ipv6_targets_configured
        )
        if not explicitly_configured:
            return (
                "reachable",
                "automatic public targets are treated as required external reachability checks",
                True,
            )

        return (
            "reachable",
            f"operator-configured IPv{family} targets are required reachability checks",
            True,
        )

    def _append_lifecycle_tests(
        self,
        tests: list[TestSpec],
        providers: list[PlannedGroup],
        tenants: list[PlannedGroup],
    ) -> None:
        # One sampled server lifecycle path per family.
        recovery_tests: list[TestSpec] = []
        for family in (4, 6):
            group = next(
                (item for item in providers if family in item.families), None
            ) or next((item for item in tenants if family in item.families), None)
            if group:
                subnet_id = (
                    next(
                        item
                        for item in group.subnet_ids
                        if self.discovery.subnet(item).ip_version == family
                    )
                    if group.kind == "provider"
                    else "runtime"
                )
                for operation, expectation in (
                    ("server-stop", "withdrawn"),
                    ("server-start", "restored"),
                ):
                    tests.append(
                        TestSpec(
                            id=f"SERVER-{operation.split('-')[-1].upper()}-{family}-{self._id_token(group.id, 36)}",
                            category="server-lifecycle",
                            operation=operation,
                            family=family,
                            expectation=expectation,
                            expectation_reason="endpoint service reachability follows the Nova server state",
                            authoritative=True,
                            dependencies=[group.id],
                            source_group_id=group.id,
                            destination_group_id=group.id,
                            source_side="A",
                            destination_side="B",
                            source_subnet_id=subnet_id,
                            destination_subnet_id=subnet_id,
                            protocol="tcp",
                            phase="intra",
                            metadata={
                                "coverage_scope": "sampled endpoint group per address family"
                            },
                            display_name=(
                                f"Sampled stop test VM and verify service loss — IPv{family}"
                                if operation == "server-stop"
                                else f"Sampled start test VM and verify service recovery — IPv{family}"
                            ),
                            scenario="Sampled VM stop/start recovery",
                        )
                    )
                    if operation == "server-start":
                        start_id = tests[-1].id
                        external_paths = [
                            spec
                            for spec in tests
                            if spec.operation == "egress"
                            and spec.source_group_id == group.id
                            and spec.family == family
                            and not spec.metadata.get("server_start_recovery")
                        ]
                        recovery_tests.extend(
                            dataclasses.replace(
                                spec,
                                id=f"{spec.id}-AFTER-SERVER-START",
                                source_side="B",
                                requires=[spec.id],
                                requires_pass=[start_id],
                                metadata={
                                    **spec.metadata,
                                    "server_start_recovery": True,
                                    "server_start_check_id": start_id,
                                },
                                display_name=(
                                    f"Sampled external IPv{family} reachability after starting "
                                    f"the test VM — {spec.metadata['target']}"
                                ),
                                scenario="External reachability after VM stop/start",
                            )
                            for spec in external_paths
                        )
        # Keep stop/start family checks adjacent so the engine can share one
        # cloud lifecycle operation across the endpoint's IPv4 and IPv6 paths.
        tests.extend(recovery_tests)
