from __future__ import annotations

from collections import Counter
from typing import Any

from ..result_context import recorded_execution_stage

PERFORMANCE_FINDINGS = {
    "tcp-throughput": ("throughput", "TCP throughput requires review"),
    "latency": ("latency", "Latency measurements require review"),
    "udp": ("udp", "UDP packet quality requires review"),
    "mtu-mss": ("mtu", "Packet-size validation requires review"),
    "repeatability": ("repeatability", "Repeated measurements require review"),
    "concurrency": ("concurrency", "Concurrent-flow measurements require review"),
    "concurrent-path-load": ("concurrency", "Concurrent VM-pair load requires review"),
    "fabric-scale": ("concurrency", "Concurrent VM-pair load requires review"),
}


def _binding_stages(specs: dict[str, dict[str, Any]]) -> dict[str, str]:
    """Index exact reserved control identities, without parsing their names."""
    controls = {
        "HOST-DISCOVERY": "placement-discovery",
        "MIGRATION-BASELINE": "pre-migration",
        "MIGRATION-FUNCTIONAL-BASELINE": "pre-migration",
        "MIGRATION": "during-migration",
        "LIVE-MIGRATION": "during-migration",
        "LIVE-CONTINUITY": "during-migration",
        "PORT-BINDING": "post-migration",
        "ENDPOINT-READY": "post-migration",
    }
    stages = {}
    for spec in specs.values():
        binding = (spec.get("metadata") or {}).get("check_bindings") or {}
        for key, identity in (binding.get("placement") or {}).items():
            if key in controls:
                stages[str(identity)] = controls[key]
        if binding.get("post-migration"):
            stages[str(binding["post-migration"])] = "post-migration"
    return stages


def _historical_stage(
    raw: dict[str, Any],
    source_spec: dict[str, Any],
    specs: dict[str, dict[str, Any]],
    checks: dict[str, dict[str, Any]],
    binding_stages: dict[str, str],
    transition_workflows: set[tuple[Any, ...]],
) -> str | None:
    """Recover old execution context only through saved planner relationships."""
    details = raw.get("details") or {}
    explicit = recorded_execution_stage(
        {**(source_spec.get("metadata") or {}), **details}
    )
    if details.get("execution_stage") or details.get(
        "pre_migration_functional_barrier"
    ):
        return explicit
    transitions = details.get("transitions") or []
    if raw.get("category") == "compute-placement" and transitions:
        return (
            "during-endpoint-recreation"
            if all(item.get("method") == "endpoint-recreation" for item in transitions)
            else "during-migration"
        )
    identity = str(details.get("planned_check_id") or raw.get("test_id") or "")
    if identity in binding_stages:
        return binding_stages[identity]
    check = checks.get(identity) or {}
    stage = (
        (details.get("path") or {}).get("stage")
        or details.get("stage")
        or check.get("stage")
    )
    if stage in {
        "pre-migration",
        "post-migration",
        "post-live-migration",
        "post-cold-migration",
    }:
        return str(stage)
    metadata = source_spec.get("metadata") or {}
    workflow = (
        metadata.get("workflow_batch"),
        metadata.get("host_qualification_pair_id"),
        metadata.get("host_qualification_cycle"),
    )
    if (
        metadata.get("coordinated_pair") is True
        and metadata.get("pair_placement_policy") == "initial-opposite-v1"
        and metadata.get("pair_placement") == "initial"
        and all(workflow)
        and workflow not in transition_workflows
    ):
        return "initial-testing"
    if explicit:
        return explicit
    if check.get("kind") == "performance" and check.get("prerequisites"):
        parents = [specs.get(str(key)) or {} for key in check["prerequisites"]]
        if all(
            recorded_execution_stage(parent.get("metadata") or {}) == "pre-migration"
            for parent in parents
        ):
            return "pre-migration"
    if source_spec and source_spec.get("phase") in {"intra", "cross"}:
        return "initial-testing"
    return None


def endpoint_zones(details: dict[str, Any]) -> tuple[str, str]:
    path = details.get("path") or {}
    return (
        str(
            path.get("source_availability_zone")
            or details.get("source_availability_zone")
            or ""
        ).strip(),
        ""
        if details.get("operation") == "egress"
        else str(
            path.get("destination_availability_zone")
            or details.get("destination_availability_zone")
            or ""
        ).strip(),
    )


def connection_story(result: dict[str, Any]) -> dict[str, str]:
    """Describe the failed prerequisite, without guessing a fault location."""
    details = result.get("details") or {}
    baseline = details.get("tcp_baseline") or {}
    diagnostics = baseline.get("diagnostics") or {}
    if (
        result.get("status") != "FAIL"
        or result.get("observed")
        not in {
            "source-nat-provider-observer-failed",
            "floating-ip-provider-observer-failed",
        }
        or baseline.get("success") is not False
        or diagnostics.get("failure_phase") != "connect"
    ):
        return {}
    mode = (
        "Router SNAT"
        if details.get("egress_translation_mode") == "router-source-nat"
        else "Floating-IP egress"
    )
    timed_out = diagnostics.get("error_type") == "TimeoutError"
    symptom = "timed out" if timed_out else "failed"
    port = diagnostics.get("destination_port")
    attempt_count = baseline.get("attempts")
    attempts = (
        f" in {attempt_count} attempt{'s' if attempt_count != 1 else ''}"
        if attempt_count
        else ""
    )
    destination = str(result.get("destination") or "the provider VM")
    source = str(result.get("source") or "the private VM")
    observation = (
        f"TCP from {source} to {destination}"
        + (f" on port {port}" if port else "")
        + f" {symptom} before connecting{attempts}."
    )
    return {
        "title": f"{mode} TCP connection {symptom}",
        "observed": observation,
        "impact": "The initial TCP connection failed. MTU and fragmentation were not measured.",
        "evidence_summary": "The probe recorded a connection failure. The cause is not established; this does not locate a fault in the router, firewall, or destination VM.",
        "next_check": (
            "Repeat this connection with the same address-translation setup and capture TCP on the source and provider VM. "
            "Check whether the SYN leaves, arrives, and receives a reply; then inspect the router translation and security-group rules at the missing step."
        ),
    }


def _endpoint_transitions(records: dict[str, dict[str, Any]]) -> dict[str, dict]:
    """Index confirmed moves by VM identity, never by host-pair labels alone."""
    candidates: dict[str, dict[tuple[str, str, str], dict]] = {}
    labels: dict[str, Any] = {}
    for row in records.values():
        addresses = (row.get("details") or {}).get("address_path") or {}
        for role in ("source", "destination"):
            server_id = (addresses.get(role) or {}).get("server_id")
            if server_id and row.get(role):
                labels.setdefault(str(server_id), row[role])
    for row in records.values():
        if row.get("category") != "compute-placement":
            continue
        details = row.get("details") or {}
        transitions = details.get("transitions") or (
            [details] if details.get("server_id") else []
        )
        for transition in transitions:
            if (
                not isinstance(transition, dict)
                or transition.get("confirmed") is not True
            ):
                continue
            moving = transition.get("server_id")
            origin, target = (
                transition.get("source_host"),
                transition.get("destination_host"),
            )
            if not moving or not origin or not target or origin == target:
                continue
            monitor = (
                transition.get("continuity_assessment")
                or (transition.get("details") or {}).get("continuity")
                or {}
            )
            identity = (str(moving), str(origin), str(target))
            roles = {str(moving): "moving"}
            stationary = monitor.get("stationary_server_id")
            if stationary and stationary != moving:
                roles[str(stationary)] = "stationary"
            for server_id, role in roles.items():
                candidates.setdefault(server_id, {})[identity] = {
                    "role": role,
                    "moving_server_id": moving,
                    "moving_label": labels.get(str(moving)),
                    "source_host": origin,
                    "destination_host": target,
                    "confirmed": True,
                }
    # Multiple moves of the same VM are ambiguous without a direct reference.
    return {
        server_id: next(iter(moves.values()))
        for server_id, moves in candidates.items()
        if len(moves) == 1
    }


def contextual_results(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Join exact planner references for display; leave stored evidence untouched."""
    plan = payload.get("plan") or {}
    specs = {
        str(spec.get("id")): spec
        for spec in plan.get("tests") or []
        if isinstance(spec, dict) and spec.get("id")
    }
    checks = {
        str(check.get("id")): check
        for check in plan.get("checks") or []
        if isinstance(check, dict) and check.get("id")
    }
    binding_stages = _binding_stages(specs)
    base_specs: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for spec in specs.values():
        metadata = spec.get("metadata") or {}
        base = metadata.get("base_test_id")
        if base:
            key = (str(base), str(metadata.get("availability_zone") or ""))
            base_specs.setdefault(key, []).append(spec)
    qualification = plan.get("host_qualification") or {}
    records = {
        str(row.get("test_id")): row
        for row in payload.get("results") or []
        if isinstance(row, dict) and row.get("test_id")
    }
    resources = {
        str(resource.get("id")): resource
        for resource in payload.get("resources") or []
        if isinstance(resource, dict) and resource.get("id")
    }
    endpoint_transitions = _endpoint_transitions(records)
    transition_methods = {}
    transition_workflows = set()
    for spec in specs.values():
        if spec.get("operation") != "pair-transition":
            continue
        scope = spec.get("metadata") or {}
        identity = (
            scope.get("workflow_batch"),
            scope.get("host_qualification_pair_id"),
            scope.get("host_qualification_cycle"),
        )
        if all(identity):
            transition_workflows.add(identity)
        record = records.get(str(spec.get("id"))) or {}
        transitions = (record.get("details") or {}).get("transitions") or []
        if (
            all(identity)
            and transitions
            and all(
                isinstance(transition, dict)
                and transition.get("method") == "endpoint-recreation"
                for transition in transitions
            )
        ):
            transition_methods[identity] = "endpoint-recreation"
        elif (
            all(identity)
            and transitions
            and record.get("status") == "PASS"
            and all(
                isinstance(transition, dict)
                and transition.get("confirmed") is True
                and transition.get("server_id")
                and transition.get("source_host")
                and transition.get("destination_host")
                and transition.get("source_host") != transition.get("destination_host")
                for transition in transitions
            )
        ):
            transition_methods[identity] = "migration"
    output = []
    for raw in payload.get("results") or []:
        details = dict(raw.get("details") or {})
        path = details.get("path") or {}
        source_spec = (
            specs.get(str(raw.get("test_id") or ""))
            or specs.get(str(path.get("source_spec_id") or ""))
            or specs.get(str(details.get("source_spec_id") or ""))
            or {}
        )
        if not source_spec:
            base = str(
                path.get("source_spec_id") or details.get("source_spec_id") or ""
            )
            zone = str(details.get("availability_zone") or "")
            matches = base_specs.get((base, zone)) or []
            if len(matches) == 1:
                source_spec = matches[0]
        metadata = source_spec.get("metadata") or {}
        presentation_metadata = {
            **metadata,
            **{
                key: source_spec[key]
                for key in (
                    "operation",
                    "protocol",
                    "family",
                    "source_side",
                    "destination_side",
                )
                if source_spec.get(key) is not None
            },
        }
        for key, value in presentation_metadata.items():
            if key.startswith(("host_qualification", "pair_")) or key in {
                "requested_source_host",
                "requested_destination_host",
                "qualification_profile",
                "qualification_strategy",
                "placement_origin",
                "operation",
                "protocol",
                "family",
                "source_side",
                "destination_side",
                "execution_stage",
            }:
                details.setdefault(key, value)
        stage = str(path.get("stage") or "")
        targeted = (
            bool(details.get("host_qualification_pair_id"))
            or stage in {"host-qualification", "post-live-migration"}
            or (
                raw.get("category") == "compute-placement"
                and qualification.get("enabled")
            )
        )
        if raw.get("category") == "controller-bootstrap":
            code, label = "control", "Runner and controller checks"
        elif stage == "post-live-migration":
            code, label = "post-migration", "Targeted pair after migration"
        elif targeted:
            code, label = "targeted", "Targeted host-pair checks"
        else:
            code, label = "general", "Unscoped topology · observed placement"
        requested = [
            str(details.get(key) or "")
            for key in ("requested_source_host", "requested_destination_host")
        ]
        observed = [
            str(path.get(key) or details.get(key) or "")
            for key in ("source_compute_host", "destination_compute_host")
        ]
        reporting_context = {
            key: value
            for key, value in details.items()
            if key.startswith(("host_qualification", "pair_"))
            or key
            in {
                "requested_source_host",
                "requested_destination_host",
                "placement_origin",
                "operation",
                "protocol",
                "family",
                "source_side",
                "destination_side",
                "execution_stage",
            }
        }
        workflow_identity = (
            metadata.get("workflow_batch"),
            details.get("host_qualification_pair_id"),
            details.get("host_qualification_cycle"),
        )
        if workflow_identity in transition_methods:
            reporting_context["placement_transition_method"] = transition_methods[
                workflow_identity
            ]
        historical_stage = _historical_stage(
            {**raw, "details": {**reporting_context, **details}},
            source_spec,
            specs,
            checks,
            binding_stages,
            transition_workflows,
        )
        if historical_stage:
            reporting_context["execution_stage"] = historical_stage
        transition_record = (
            records.get(str(details.get("transition_check_id") or "")) or {}
        )
        related = (transition_record.get("details") or {}).get("transitions") or []
        if related:
            reporting_context["related_transitions"] = related
        self_path = (
            details.get("nat_path") == "self-hairpin"
            or details.get("packet_path_placement") == "self"
        )
        if self_path or raw.get("category") == "egress":
            addresses = details.get("address_path") or {}
            source_id = (addresses.get("source") or {}).get("server_id") or details.get(
                "source_server_id"
            )
            destination_id = (addresses.get("destination") or {}).get(
                "server_id"
            ) or details.get("destination_server_id")
            if (
                source_id
                and (not self_path or source_id == destination_id)
                and str(source_id) in endpoint_transitions
            ):
                reporting_context["topology_endpoint_transition"] = (
                    endpoint_transitions[str(source_id)]
                )
        supporting = []
        for round_ in details.get("rounds") or []:
            if not isinstance(round_, dict):
                continue
            for reference in round_.get("test_ids") or []:
                if reference in records and records[reference] is not raw:
                    record = records[reference]
                    evidence = record.get("details") or {}
                    supporting.append(
                        {
                            key: record.get(key)
                            for key in (
                                "source",
                                "destination",
                                "family",
                                "status",
                                "category",
                                "display_name",
                            )
                        }
                        | {
                            "details": {
                                key: evidence[key]
                                for key in (
                                    "address_path",
                                    "source_compute_host",
                                    "destination_compute_host",
                                    "source_availability_zone",
                                    "destination_availability_zone",
                                    "protocol",
                                )
                                if key in evidence
                            }
                        }
                    )
        if supporting:
            reporting_context["supporting_paths"] = supporting
        moving = []
        direct_transition = (
            [details]
            if details.get("source_host")
            and details.get("destination_host")
            and details.get("server_id")
            else []
        )
        for transition in details.get("transitions") or related or direct_transition:
            if not isinstance(transition, dict):
                continue
            server_id = str(transition.get("server_id") or "")
            resource = resources.get(server_id) or {}
            endpoint_label = None
            for row in payload.get("results") or []:
                addresses = (row.get("details") or {}).get("address_path") or {}
                for role in ("source", "destination"):
                    if (
                        server_id
                        and (addresses.get(role) or {}).get("server_id") == server_id
                    ):
                        endpoint_label = row.get(role)
                        break
                if endpoint_label:
                    break
            if endpoint_label or resource:
                moving.append(
                    {
                        "server_id": server_id,
                        "label": endpoint_label,
                        "side": (resource.get("metadata") or {}).get("endpoint_side"),
                        "vm_name": resource.get("name"),
                    }
                )
        if moving:
            reporting_context["moving_endpoints"] = moving
        monitor = (
            details.get("continuity_assessment")
            or details.get("continuity")
            or (details.get("details") or {}).get("continuity")
            or {}
        )
        transitions = details.get("transitions") or related
        if not monitor and transitions:
            monitor = (
                transitions[0].get("continuity_assessment")
                or (transitions[0].get("details") or {}).get("continuity")
                or {}
            )
        if (
            isinstance(monitor, dict)
            and monitor.get("observer_server_id")
            and monitor.get("target_server_id")
        ):
            for row in payload.get("results") or []:
                evidence = row.get("details") or {}
                addresses = evidence.get("address_path") or {}
                source_address, destination_address = (
                    addresses.get("source") or {},
                    addresses.get("destination") or {},
                )
                if (
                    source_address.get("server_id") == monitor["observer_server_id"]
                    and destination_address.get("server_id")
                    == monitor["target_server_id"]
                    and source_address.get("probe_address") == monitor.get("source_ip")
                    and destination_address.get("probe_address")
                    == monitor.get("destination_ip")
                ):
                    reporting_context["monitored_path"] = {
                        key: row.get(key)
                        for key in (
                            "source",
                            "destination",
                            "family",
                            "category",
                            "status",
                        )
                    } | {
                        "details": {
                            key: evidence[key]
                            for key in (
                                "address_path",
                                "source_compute_host",
                                "destination_compute_host",
                                "source_availability_zone",
                                "destination_availability_zone",
                                "nat_path",
                                "path_kind",
                                "egress_translation_mode",
                            )
                            if key in evidence
                        }
                    }
                    break
        output.append(
            {
                **raw,
                # Enrichment is presentation context, not a rewrite of signed
                # semantic-path/contract evidence from the historical result.
                "reporting_context": reporting_context,
                "host_scope": {
                    "code": code,
                    "label": label,
                    "requested_pair": " ↔ ".join(requested) if all(requested) else None,
                    "observed_pair": " → ".join(observed) if all(observed) else None,
                    **(
                        {
                            "requested_placement": (
                                details.get("topology_placement_context") or {}
                            ).get("pair_placement", details["pair_placement"]),
                            "placement": (
                                "same-host"
                                if observed[0] == observed[1]
                                else "inter-host"
                            )
                            if all(observed)
                            else "unknown",
                            "cycle": details.get("host_qualification_cycle"),
                        }
                        if details.get("pair_placement")
                        else {}
                    ),
                },
            }
        )
    return output


def host_scope_summary(payload: dict[str, Any]) -> dict[str, Any]:
    plan = payload.get("plan") or {}
    qualification = plan.get("host_qualification") or {}
    results = contextual_results(payload)
    counts = Counter(row["host_scope"]["code"] for row in results)
    pair_scoped = any(
        (spec.get("metadata") or {}).get("pair_scope_id")
        for spec in plan.get("tests", [])
        if isinstance(spec, dict)
    )
    observed_requested_pairs = sorted(
        {
            row["host_scope"]["observed_pair"]
            for row in results
            if row["host_scope"]["code"] in {"targeted", "post-migration"}
            and row["host_scope"]["observed_pair"]
        }
    )
    unscoped_observed_pairs = sorted(
        {
            row["host_scope"]["observed_pair"]
            for row in results
            if row["host_scope"]["code"] == "general"
            and row["host_scope"]["observed_pair"]
        }
    )
    return {
        "enabled": bool(qualification.get("enabled")),
        "pair_scoped": pair_scoped,
        "requested_pairs": [
            f"{pair.get('source_host')} ↔ {pair.get('destination_host')}"
            for pair in qualification.get("pairs") or []
        ],
        "counts": dict(counts),
        "observed_requested_pairs": observed_requested_pairs,
        # Preserve the old field for consumers of the report JSON while giving it
        # an accurate meaning. These are results lacking requested-pair context.
        "general_observed_pairs": unscoped_observed_pairs,
        "unscoped_observed_pairs": unscoped_observed_pairs,
        "placement_policy": (
            "initial-opposite-v1"
            if any(
                (spec.get("metadata") or {}).get("pair_placement_policy")
                == "initial-opposite-v1"
                for spec in plan.get("tests", [])
                if isinstance(spec, dict)
            )
            else "historical"
        ),
        "note": (
            "Each eligible topology starts at its verified placement, tests once, moves one endpoint to the opposite relation and tests once more. One intra-compute and one inter-compute placement; no third stage or return trip. Explicit single-host scopes have only intra coverage. The probe controller is shared."
            if pair_scoped
            and any(
                (spec.get("metadata") or {}).get("pair_placement_policy")
                == "initial-opposite-v1"
                for spec in plan.get("tests", [])
                if isinstance(spec, dict)
            )
            else "Every network-test VM is constrained to its requested pair. Each ordinary pair runs same-host A, inter-host A:B, then same-host B; migration adds pair-local post-migration evidence. The probe controller is shared."
            if pair_scoped
            else "Requested-pair results are shown separately from results that do not carry pair context. Unscoped results are labelled from observed evidence only; the report does not state how their placement was selected."
        ),
    }
