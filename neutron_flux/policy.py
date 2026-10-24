from __future__ import annotations

from dataclasses import dataclass

from .models import PolicyDecision, ProbeResult, TestSpec


@dataclass(frozen=True)
class RoutingExpectation:
    """A routing requirement derived without looking at probe success."""

    expectation: str
    reason: str
    authoritative: bool
    basis: str

    def metadata(self) -> dict[str, object]:
        return {
            "expectation": self.expectation,
            "reason": self.reason,
            "authoritative": self.authoritative,
            "basis": self.basis,
        }


class PolicyEvaluator:
    """Translate a raw VM/network observation into an operator-facing result."""

    def evaluate(self, spec: TestSpec, probe: ProbeResult) -> PolicyDecision:
        observed = probe.outcome
        expected = spec.expectation
        authoritative = spec.authoritative

        if observed == "error":
            return PolicyDecision(
                status="ERROR",
                message="The probe could not execute correctly",
                expected=expected,
                observed=observed,
                authoritative=authoritative,
            )
        if observed == "inconclusive":
            return PolicyDecision(
                status="UNVERIFIED",
                message=spec.expectation_reason,
                expected=expected,
                observed=observed,
                authoritative=False,
            )
        if not authoritative and bool(spec.metadata.get("authority_required")):
            return PolicyDecision(
                status="UNVERIFIED",
                message=f"No authoritative observation path was available: {spec.expectation_reason}",
                expected=expected,
                observed=observed,
                authoritative=False,
            )
        if expected == "not-applicable":
            return PolicyDecision(
                status="NOT_APPLICABLE",
                message=spec.expectation_reason,
                expected=expected,
                observed=observed,
                authoritative=authoritative,
            )
        if expected == "observation" or not authoritative:
            return PolicyDecision(
                status="UNVERIFIED",
                message=(
                    "Observed behavior without asserting a routing contract: "
                    + spec.expectation_reason
                ),
                expected=expected,
                observed=observed,
                authoritative=False,
            )
        if expected == "reachable":
            status = "PASS" if observed == "reachable" else "FAIL"
        elif expected == "blocked":
            status = "PASS" if observed in {"blocked", "local-mtu-rejected"} else "FAIL"
        elif expected == "restored":
            status = "PASS" if observed == "reachable" else "FAIL"
        elif expected == "withdrawn":
            status = "PASS" if observed == "blocked" else "FAIL"
        else:
            status = "UNVERIFIED"
        return PolicyDecision(
            status=status,
            message=spec.expectation_reason,
            expected=expected,
            observed=observed,
            authoritative=authoritative,
        )


class TopologyPolicy:
    """OpenStack-visible routing relationship policy.

    OpenStack calls the underlying API object an ``address scope``. Internal
    canonical values preserve the long-standing plan contract:

    * direct-routing-compatible: both explicit address-scope IDs match;
    * routing-isolated: both IDs exist and differ;
    * routing-metadata-unassigned: one or both sides have no declared routed
      relationship. User-facing output presents these as matching, different,
      or unassigned facts and does not infer an L2/L3 implementation.
    """

    DIRECT = "direct-routing-compatible"
    ISOLATED = "routing-isolated"
    UNASSIGNED = "no-routing-group"

    @classmethod
    def routing_relationship(
        cls, source_routing_group: str | None, destination_routing_group: str | None
    ) -> str:
        if source_routing_group and destination_routing_group:
            return (
                cls.DIRECT
                if source_routing_group == destination_routing_group
                else cls.ISOLATED
            )
        return cls.UNASSIGNED

    @classmethod
    def project_expectation(
        cls,
        relationship: str,
        family: int,
        *,
        source_is_project: bool = False,
        synthetic_private: bool = False,
    ) -> RoutingExpectation:
        """Resolve a project/external path with a planned Neutron router.

        Pool allocation and a guest default route are not routing contracts.
        IPv4 outbound SNAT is a conditional requirement: runtime provisioning
        must verify the router's SNAT setting. It proves no reverse fixed-IP
        isolation when scopes are missing. Synthetic IPv6 is for local coverage.
        """
        if synthetic_private and family == 6:
            return RoutingExpectation(
                "not-applicable",
                "the generated private IPv6 subnet supplies internal coverage; no external route was declared for its prefix",
                False,
                "synthetic-private-ipv6",
            )
        if relationship == cls.DIRECT:
            return RoutingExpectation(
                "reachable",
                "the project and external subnets have matching explicit address scopes and a configured Neutron router",
                True,
                "matching-address-scopes",
            )
        if (
            family == 4
            and source_is_project
            and relationship in {cls.UNASSIGNED, cls.ISOLATED}
        ):
            return RoutingExpectation(
                "reachable",
                "outbound IPv4 connectivity is required through the configured router after its default source NAT setting is verified",
                True,
                "router-default-snat",
            )
        if relationship == cls.ISOLATED:
            return RoutingExpectation(
                "blocked",
                "the project and external subnets have different explicit address scopes and this direction has no applicable address translation",
                True,
                "different-address-scopes",
            )
        return RoutingExpectation(
            "observation",
            "OpenStack exposed no shared routed address relationship; missing metadata proves neither fixed-IP reachability nor isolation",
            False,
            "routing-relationship-unknown",
        )

    @staticmethod
    def provider_expectation(*, routed_segments: bool) -> RoutingExpectation:
        if routed_segments:
            return RoutingExpectation(
                "reachable",
                "the subnets are different segments of the same routed provider network",
                True,
                "routed-provider-network",
            )
        return RoutingExpectation(
            "reachable",
            "the selected provider networks are required to route between each other",
            True,
            "selected-provider-routing-contract",
        )

    @classmethod
    def relationship_label(cls, relationship: str) -> str:
        return {
            cls.DIRECT: "Matching address scopes",
            cls.ISOLATED: "Different address scopes",
            cls.UNASSIGNED: "Routing metadata unassigned",
            "provider": "Provider network",
            "routed-provider": "Routed provider network",
            "separate-provider": "Separate provider networks",
        }.get(relationship, relationship.replace("-", " ").title())
