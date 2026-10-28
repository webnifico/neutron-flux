from __future__ import annotations

from collections.abc import Iterable
from typing import Any


def positive_mtu(value: Any) -> int | None:
    """Return a usable MTU without accepting booleans, nulls, or zero."""
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def route_mtu_from_evidence(evidence: dict[str, Any] | None) -> int | None:
    """Read route PMTU from current and legacy ``ip -j route get`` shapes."""
    evidence = evidence or {}
    direct = positive_mtu(evidence.get("route_mtu"))
    if direct is not None:
        return direct
    route = evidence.get("route")
    if not isinstance(route, dict):
        return None
    direct = positive_mtu(route.get("mtu"))
    if direct is not None:
        return direct
    metrics = route.get("metrics")
    rows = metrics if isinstance(metrics, list) else [metrics]
    for row in rows:
        if isinstance(row, dict):
            parsed = positive_mtu(row.get("mtu"))
            if parsed is not None:
                return parsed
    return None


def make_mtu_observation(
    *,
    label: str,
    reported_mtu: Any,
    authority: str,
    authoritative: bool,
    resource_type: str,
    resource_id: str | None = None,
    resource_name: str | None = None,
    observed_at: str | None = None,
    fallback_mtu: int = 1500,
    network_type: Any = None,
    physical_network: Any = None,
    segmentation_id: Any = None,
    source: str | None = None,
) -> dict[str, Any]:
    """Build a JSON-safe MTU observation with explicit provenance.

    A fallback remains useful for bounded diagnostics, but it is never silently
    promoted to an operator contract.  Callers can therefore keep probing while
    reporting an UNVERIFIED contract when Neutron did not expose ``network.mtu``.
    """
    reported = positive_mtu(reported_mtu)
    fallback = positive_mtu(fallback_mtu) or 1500
    effective = reported if reported is not None else fallback
    verified = bool(authoritative and reported is not None)
    overlay = str(network_type or "").strip().lower()
    note = None
    if overlay in {"geneve", "vxlan", "gre"}:
        note = (
            "Neutron network.mtu is the project-visible effective L2 MTU; "
            "Neutron's network MTU calculation already accounts for overlay "
            "encapsulation overhead."
        )
    elif resource_type == "network":
        note = (
            "This is the MTU reported for the Neutron network resource; Flux "
            "does not subtract an assumed encapsulation overhead a second time."
        )
    if reported is None:
        note = (
            f"Neutron did not expose a usable MTU. Flux used {fallback} bytes "
            "only to bound diagnostics; that fallback is not an authoritative "
            "network contract."
        )
    return {
        "label": str(label),
        "reported_mtu": reported,
        "effective_mtu": effective,
        "authority": str(authority),
        "authoritative": verified,
        "fallback_used": reported is None,
        "fallback_mtu": fallback if reported is None else None,
        "resource_type": str(resource_type),
        "resource_id": str(resource_id) if resource_id else None,
        "resource_name": str(resource_name) if resource_name else None,
        "observed_at": observed_at,
        "source": str(source or authority),
        "network_type": str(network_type) if network_type not in (None, "") else None,
        "physical_network": (
            str(physical_network) if physical_network not in (None, "") else None
        ),
        "segmentation_id": (
            str(segmentation_id) if segmentation_id not in (None, "") else None
        ),
        "derivation_note": note,
    }


def resolve_mtu_contract(
    observations: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    constraints = [dict(item) for item in observations if isinstance(item, dict)]
    usable = [
        item
        for item in constraints
        if positive_mtu(item.get("effective_mtu")) is not None
    ]
    if not usable:
        return {
            "expected_mtu": None,
            "authoritative": False,
            "fallback_used": True,
            "constraints": constraints,
            "limiting_constraints": [],
            "formula": "No usable MTU constraints were available",
            "authority_summary": "unverified",
        }
    expected = min(int(item["effective_mtu"]) for item in usable)
    limiting = [
        {
            "label": item.get("label"),
            "effective_mtu": int(item["effective_mtu"]),
            "authority": item.get("authority"),
            "resource_id": item.get("resource_id"),
            "authoritative": bool(item.get("authoritative")),
        }
        for item in usable
        if int(item["effective_mtu"]) == expected
    ]
    authoritative = all(bool(item.get("authoritative")) for item in usable)
    labels = ", ".join(
        f"{item.get('label') or 'constraint'}={int(item['effective_mtu'])}"
        for item in usable
    )
    return {
        "expected_mtu": expected,
        "authoritative": authoritative,
        "fallback_used": any(bool(item.get("fallback_used")) for item in usable),
        "constraints": usable,
        "limiting_constraints": limiting,
        "formula": f"minimum({labels}) = {expected} bytes",
        "authority_summary": (
            "authoritative Neutron/kernel evidence"
            if authoritative
            else "diagnostic fallback present; contract is unverified"
        ),
    }


def fragment_counter_delta(
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
) -> dict[str, int]:
    before = before or {}
    after = after or {}
    if not before.get("available") or not after.get("available"):
        return {}
    start = before.get("counters") or {}
    end = after.get("counters") or {}
    keys = set(start) | set(end)
    return {
        key: max(0, int(end.get(key) or 0) - int(start.get(key) or 0))
        for key in sorted(keys)
    }


def confirmed_fragmentation_path_mtu(
    probe: dict[str, Any] | None,
    expected_mtu: int,
) -> int | None:
    """Use a confirmed measured boundary for follow-up fragmentation probes."""
    # Keep expected_mtu as a compatibility argument, never as measured evidence.
    return confirmed_no_fragment_path_mtu(probe)


def confirmed_no_fragment_path_mtu(
    probe: dict[str, Any] | None,
) -> int | None:
    """Return only an end-to-end no-fragment boundary Flux actually measured.

    A local interface rejection or cached per-destination route PMTU can explain
    why a packet was not transmitted, but it is not an independent measurement
    of the current path. Historical results did not always carry the explicit
    ``path_boundary_confirmed`` flag, so the local-rejection classification is
    also used to reject false path-boundary claims during offline reporting.
    """

    probe = probe or {}
    discovered = positive_mtu(probe.get("discovered_mtu"))
    if discovered is None:
        return None
    confidence = str(probe.get("discovery_confidence") or "legacy")
    expected_class = str(probe.get("expected_probe_classification") or "")
    local_class = str(probe.get("local_constraint_classification") or "")
    path_confirmed = probe.get("path_boundary_confirmed")
    if expected_class == "local-mtu-rejected" or local_class in {
        "cached-route-pmtu",
        "interface-mtu-constraint",
        "local-mtu-constraint-unverified",
    }:
        return None
    if path_confirmed is False:
        return None
    if confidence in {"expected-confirmed", "confirmed-lower-boundary", "legacy"}:
        return discovered
    return None


def local_mtu_constraint(
    probe: dict[str, Any] | None,
) -> tuple[int | None, str | None]:
    """Return a local MTU/PMTU constraint without presenting it as path MTU."""

    probe = probe or {}
    expected_class = str(probe.get("expected_probe_classification") or "")
    local_class = str(probe.get("local_constraint_classification") or "") or None
    if expected_class != "local-mtu-rejected" and local_class not in {
        "cached-route-pmtu",
        "interface-mtu-constraint",
        "local-mtu-constraint-unverified",
    }:
        return None, None
    evidence = probe.get("local_mtu_evidence")
    evidence = evidence if isinstance(evidence, dict) else {}
    route_mtu = route_mtu_from_evidence(evidence)
    interface_mtu = positive_mtu(evidence.get("source_interface_mtu"))
    discovered = positive_mtu(probe.get("discovered_mtu"))
    if not local_class:
        if route_mtu is not None and (
            interface_mtu is None or route_mtu < interface_mtu
        ):
            local_class = "cached-route-pmtu"
        elif interface_mtu is not None:
            local_class = "interface-mtu-constraint"
        else:
            local_class = "local-mtu-constraint-unverified"
    if local_class == "cached-route-pmtu":
        return route_mtu or discovered, local_class
    if local_class == "interface-mtu-constraint":
        return interface_mtu or discovered, local_class
    return route_mtu or interface_mtu or discovered, local_class


def classify_fragmentation_location(
    profile: dict[str, Any],
    *,
    destination_before: dict[str, Any] | None = None,
    destination_after: dict[str, Any] | None = None,
    router_ids: Iterable[str] = (),
    router_backend_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Separate endpoint observations from path and component attribution.

    Guest fragment/reassembly counters can directly show that the source
    fragmented a packet or, by correlation, that fragmentation happened
    somewhere between the source and destination. Neutron router membership and
    backend inventory are path context, not component-local evidence. They may
    identify candidate components, but must never be presented as direct proof
    that an OVN or Neutron router performed the fragmentation.
    """
    result = dict(profile)
    family = int(result.get("family") or 0)
    capability = str(result.get("capability") or "unverified")
    routers = tuple(dict.fromkeys(str(item) for item in router_ids if item))
    backend_evidence = dict(router_backend_evidence or {})
    router_backend = str(backend_evidence.get("backend") or "unknown").lower()
    router_backend_confirmed = bool(backend_evidence.get("confirmed"))
    source_counter_set = result.get("source_fragment_counters") or {}
    source_before = source_counter_set.get("before") or {}
    source_after = source_counter_set.get("after_permitted") or {}
    source_delta = fragment_counter_delta(source_before, source_after)
    destination_delta = fragment_counter_delta(destination_before, destination_after)
    source_available = bool(source_before.get("available")) and bool(
        source_after.get("available")
    )
    destination_available = bool((destination_before or {}).get("available")) and bool(
        (destination_after or {}).get("available")
    )
    source_fragment_key = "FragCreates" if family == 4 else "Ip6FragCreates"
    destination_reassembly_key = "ReasmOKs" if family == 4 else "Ip6ReasmOKs"
    source_fragment_count = int(source_delta.get(source_fragment_key) or 0)
    destination_reassembly_count = int(
        destination_delta.get(destination_reassembly_key) or 0
    )
    successful_trials = max(
        1,
        int(
            ((result.get("fragmentation_permitted") or {}).get("counts") or {}).get(
                "success"
            )
            or 1
        ),
    )

    source_observation = {
        "status": (
            "observed"
            if source_available and source_fragment_count >= successful_trials
            else "not-observed"
            if source_available
            else "unavailable"
        ),
        "directly_observed": bool(
            source_available and source_fragment_count >= successful_trials
        ),
        "counter": source_fragment_key,
        "delta": source_fragment_count if source_available else None,
        "threshold": successful_trials,
        "authority": "source guest network-namespace IP counters",
    }
    destination_observation = {
        "status": (
            "observed"
            if destination_available
            and destination_reassembly_count >= successful_trials
            else "not-observed"
            if destination_available
            else "unavailable"
        ),
        "directly_observed": bool(
            destination_available and destination_reassembly_count >= successful_trials
        ),
        "counter": destination_reassembly_key,
        "delta": destination_reassembly_count if destination_available else None,
        "threshold": successful_trials,
        "authority": "destination guest network-namespace IP counters",
    }
    component_inference: dict[str, Any] = {
        "status": "not-assessed",
        "component": None,
        "label": "No network component attributed",
        "directly_observed": False,
        "confidence": "none",
        "basis": [],
        "limitation": (
            "Endpoint counters do not expose the identity of an in-path "
            "fragmenting component."
        ),
    }
    location = "not-observed"
    label = "No fragmentation observed"
    confidence = "not-applicable"
    in_path_fragmentation_observed: bool | None = None
    in_path_fragmentation_inferred: bool | None = None
    if capability == "not-required":
        component_inference["status"] = "not-applicable"
        reason = (
            "The tested source packet did not exceed the confirmed no-fragment "
            "path MTU, so fragmentation was not required."
        )
    elif capability == "path-supports-source-mtu":
        component_inference["status"] = "not-applicable"
        location = "not-required-at-tested-size"
        label = "No narrower path observed"
        confidence = "confirmed-by-probe"
        reason = (
            "The source-sized packet crossed with fragmentation disabled, so the "
            "probe did not require fragmentation."
        )
    elif capability != "supported":
        component_inference["status"] = (
            "not-applicable" if capability == "not-supported" else "not-assessed"
        )
        location = (
            "fragmented-delivery-not-observed"
            if capability == "not-supported"
            else "unverified"
        )
        label = (
            "Fragmented delivery not observed at the tested size"
            if capability == "not-supported"
            else "Fragmentation location unverified"
        )
        confidence = "confirmed-by-probe" if capability == "not-supported" else "none"
        reason = str(
            result.get("reason")
            or (
                "The source permitted fragmentation, but successful destination "
                "reassembly and delivery were not observed at the tested size."
                if capability == "not-supported"
                else "Fragmentation could not be classified."
            )
        )
    elif source_available and source_fragment_count >= successful_trials:
        location = "source"
        label = "Source guest fragmented the packet"
        confidence = "endpoint-counter-corroborated"
        in_path_fragmentation_observed = False
        in_path_fragmentation_inferred = False
        component_inference.update(
            {
                "status": "not-needed",
                "label": "Source endpoint directly observed",
                "confidence": "not-applicable",
                "basis": [
                    (f"{source_fragment_key} increased by {source_fragment_count}")
                ],
                "limitation": (
                    "The source observation identifies endpoint fragmentation; "
                    "it does not prove or disprove additional in-path behavior."
                ),
            }
        )
        reason = (
            f"The source network namespace created {source_fragment_count} IP "
            "fragments during the fragmentation-permitted probe."
        )
    elif (
        family == 4
        and source_available
        and destination_available
        and source_fragment_count == 0
        and destination_reassembly_count >= successful_trials
    ):
        location = "in-path"
        label = "In-path IPv4 fragmentation inferred from endpoint counters"
        confidence = "endpoint-counter-inference"
        in_path_fragmentation_observed = False
        in_path_fragmentation_inferred = True
        component_basis = [
            f"source {source_fragment_key} delta was 0",
            (
                f"destination {destination_reassembly_key} increased by "
                f"{destination_reassembly_count}"
            ),
            f"recorded Neutron router count was {len(routers)}",
        ]
        if len(routers) == 1:
            if router_backend == "ovn" and router_backend_confirmed:
                component_inference.update(
                    {
                        "status": "candidate-consistent-with-evidence",
                        "component": "ovn-backed-neutron-router-path",
                        "label": (
                            "One OVN-backed Neutron router is present on the "
                            "recorded path"
                        ),
                        "confidence": "path-context-only",
                        "basis": [
                            *component_basis,
                            "Neutron agent inventory reported an OVN backend",
                        ],
                        "limitation": (
                            "No router-local or OVN component evidence identifies "
                            "the component that fragmented the packet."
                        ),
                    }
                )
                reason = (
                    "Endpoint counter correlation infers fragmentation after the "
                    "source and before destination reassembly. The recorded path "
                    "contains one Neutron router and inventory reports OVN, making "
                    "that routed segment a candidate; no component-local evidence "
                    "proves that the OVN logical router fragmented the packet."
                )
            else:
                component_inference.update(
                    {
                        "status": "candidate-consistent-with-evidence",
                        "component": "neutron-router-path",
                        "label": ("One Neutron router is present on the recorded path"),
                        "confidence": "path-context-only",
                        "basis": [
                            *component_basis,
                            (
                                f"visible backend inventory reported {router_backend}"
                                if router_backend_confirmed
                                else "router backend was not independently confirmed"
                            ),
                        ],
                        "limitation": (
                            "No router-local component evidence identifies the "
                            "component that fragmented the packet."
                        ),
                    }
                )
                reason = (
                    "Endpoint counter correlation infers fragmentation after the "
                    "source and before destination reassembly. The recorded path "
                    "contains one Neutron router, but no component-local evidence "
                    "proves that the router performed the fragmentation."
                )
        elif len(routers) > 1:
            component_inference.update(
                {
                    "status": "multiple-candidates",
                    "component": (
                        "ovn-backed-neutron-router-path"
                        if router_backend == "ovn" and router_backend_confirmed
                        else "neutron-router-path"
                    ),
                    "label": (
                        "Multiple Neutron routers are present on the recorded path"
                    ),
                    "confidence": "path-context-only",
                    "basis": [
                        *component_basis,
                        (
                            "Neutron agent inventory reported an OVN backend"
                            if router_backend == "ovn" and router_backend_confirmed
                            else "router backend does not identify a fragmenting component"
                        ),
                    ],
                    "limitation": (
                        "Endpoint evidence cannot identify which routed segment or "
                        "other in-path component fragmented the packet."
                    ),
                }
            )
            reason = (
                "Endpoint counter correlation infers in-path IPv4 fragmentation, "
                "but the path "
                "contains multiple Neutron routers and possibly other components; "
                "no component-local evidence identifies the fragmentation point."
            )
        else:
            component_inference.update(
                {
                    "status": "unresolved",
                    "label": "In-path component unresolved",
                    "confidence": "none",
                    "basis": component_basis,
                    "limitation": (
                        "No recorded component identity can be correlated with the "
                        "endpoint counter observation."
                    ),
                }
            )
            reason = (
                "Endpoint counter correlation infers in-path IPv4 fragmentation, but no "
                "component-local evidence identifies where it occurred."
            )
    else:
        location = "unverified"
        label = "Fragmentation supported; location unverified"
        confidence = "capability-only"
        component_inference["status"] = "not-assessed"
        reason = (
            "The source-sized packet crossed when fragmentation was permitted, "
            "but counter evidence did not safely distinguish source fragmentation "
            "from in-path fragmentation."
        )

    result.update(
        {
            "fragmentation_location": location,
            "fragmentation_location_label": label,
            "attribution_confidence": confidence,
            "attribution_reason": reason,
            "endpoint_observations": {
                "source_fragment_creation": source_observation,
                "destination_reassembly": destination_observation,
            },
            "in_path_fragmentation_observed": in_path_fragmentation_observed,
            "in_path_fragmentation_inferred": in_path_fragmentation_inferred,
            "component_inference": component_inference,
            "component_attribution_directly_observed": False,
            "router_ids": list(routers),
            # Legacy compatibility fields deliberately never report True from
            # endpoint-only evidence. Component attribution requires
            # component-local evidence that this probe does not collect.
            "router_fragmentation_observed": None,
            "ovn_router_fragmentation_observed": None,
            "router_backend_evidence": backend_evidence,
            "source_fragment_counter_delta": source_delta,
            "destination_reassembly_counter_delta": destination_delta,
            "source_fragment_counters_available": source_available,
            "destination_fragment_counters_available": destination_available,
            "counter_correlation_threshold": successful_trials,
            "destination_fragment_counters": {
                "before": destination_before or {},
                "after": destination_after or {},
            },
        }
    )
    return result


def classify_mtu_contract_probe(
    probe: dict[str, Any],
    *,
    expected_mtu: int,
    contract_authoritative: bool,
) -> dict[str, Any]:
    """Annotate a boundary probe without conflating PMTUD with the contract."""
    result = dict(probe)
    confidence = str(result.get("discovery_confidence") or "")
    discovered = positive_mtu(result.get("discovered_mtu"))
    expected_class = str(result.get("expected_probe_classification") or "")
    evidence = result.get("local_mtu_evidence")
    if not isinstance(evidence, dict):
        evidence = {}
    route_mtu = route_mtu_from_evidence(evidence)
    interface_mtu = positive_mtu(evidence.get("source_interface_mtu"))
    local_class = str(result.get("local_constraint_classification") or "")
    if expected_class == "local-mtu-rejected" and not local_class:
        if (
            route_mtu is not None
            and route_mtu < int(expected_mtu)
            and (interface_mtu is None or route_mtu < interface_mtu)
        ):
            local_class = "cached-route-pmtu"
        elif interface_mtu is not None and interface_mtu < int(expected_mtu):
            local_class = "interface-mtu-constraint"
        else:
            local_class = "local-mtu-constraint-unverified"
    if route_mtu is not None and evidence.get("route_mtu") is None:
        evidence = {**evidence, "route_mtu": route_mtu}
        result["local_mtu_evidence"] = evidence
    if local_class:
        result["local_constraint_classification"] = local_class
    if expected_class == "local-mtu-rejected" and local_class:
        # Preserve what the binary-search probe originally called the result,
        # but do not let a local rejection retain end-to-end boundary confidence.
        result.setdefault("boundary_probe_confidence", confidence or None)
        confidence = local_class
        result["discovery_confidence"] = confidence
        result["path_boundary_confirmed"] = False
    if not contract_authoritative:
        contract_status = "unverified"
    elif confidence == "expected-confirmed" and discovered == int(expected_mtu):
        contract_status = "met"
    elif expected_class == "packet-too-big":
        contract_status = "failed"
    elif local_class == "interface-mtu-constraint":
        contract_status = "failed"
    elif expected_class == "local-mtu-rejected":
        contract_status = "unverified"
    elif (
        confidence == "confirmed-lower-boundary"
        and discovered is not None
        and discovered < int(expected_mtu)
    ):
        contract_status = "failed" if contract_authoritative else "unverified"
    else:
        contract_status = "unverified"

    if expected_class == "packet-too-big":
        reported = positive_mtu(result.get("reported_path_mtu"))
        pmtud_status = "packet-too-big-received"
        pmtud_explanation = (
            f"The advertised {expected_mtu}-byte packet received fresh ICMP "
            f"Packet Too Big / fragmentation-needed feedback reporting MTU "
            f"{reported or 'unknown'} bytes. "
            + (
                f"Repeated probes confirmed a no-fragment path MTU of {discovered} bytes."
                if confirmed_no_fragment_path_mtu(result) is not None
                else "The exact no-fragment path boundary remains unverified."
            )
        )
    elif local_class == "cached-route-pmtu":
        pmtud_status = "cached-route-pmtu-observed"
        pmtud_explanation = (
            f"The source guest had a per-destination route PMTU of "
            f"{route_mtu or discovered or 'unknown'} bytes. Packets above that "
            "cached PMTU were rejected before transmission, so Flux did not "
            "independently measure the current end-to-end path boundary."
        )
    elif local_class == "interface-mtu-constraint":
        pmtud_status = "source-interface-mtu-constraint"
        pmtud_explanation = (
            "The source interface MTU was below the advertised network MTU, so "
            "the packet was rejected before transmission."
        )
    elif expected_class == "local-mtu-rejected":
        pmtud_status = "local-mtu-constraint-unverified"
        pmtud_explanation = (
            "The source guest rejected the packet before transmission, but Flux "
            "could not safely distinguish cached PMTU state from another local "
            "constraint."
        )
    elif (
        expected_class == "no-reply"
        and confidence == "confirmed-lower-boundary"
        and discovered is not None
    ):
        pmtud_status = "df-path-boundary-observed"
        pmtud_explanation = (
            "The advertised DF packet was transmitted but did not cross, while "
            "the adjacent lower boundary succeeded repeatedly. Flux confirmed "
            "the no-fragment path boundary, but this evidence alone does not "
            "prove that an ICMP Packet Too Big response reached the sender."
        )
    elif confidence == "expected-confirmed":
        pmtud_status = "expected-size-confirmed"
        pmtud_explanation = (
            "The advertised packet size crossed with fragmentation disabled; no "
            "lower PMTU enforcement was required at that size."
        )
    else:
        pmtud_status = "unverified"
        pmtud_explanation = (
            "Flux did not obtain stable evidence for PMTUD or route-MTU behavior."
        )
    result.update(
        {
            "advertised_mtu_contract_status": contract_status,
            "advertised_mtu_contract_authoritative": bool(contract_authoritative),
            "pmtud_status": pmtud_status,
            "pmtud_explanation": pmtud_explanation,
        }
    )
    return result


__all__ = [
    "classify_fragmentation_location",
    "classify_mtu_contract_probe",
    "confirmed_fragmentation_path_mtu",
    "confirmed_no_fragment_path_mtu",
    "fragment_counter_delta",
    "local_mtu_constraint",
    "make_mtu_observation",
    "positive_mtu",
    "route_mtu_from_evidence",
    "resolve_mtu_contract",
]
