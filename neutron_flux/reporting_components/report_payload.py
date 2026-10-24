from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from typing import Any

from ..logical_results import unrecorded_check_result
from ..operator_explanations import (
    explain_result,
    lifecycle_explanations,
    operator_overview,
)
from ..replay_plan import RerunResolver
from ..result_context import context_lines, normalize_topology_label, result_context
from ..terminology import category_label
from ..test_names import address_path_lines
from .manual_reproduction import manual_reproduction
from .operator_context import (
    connection_story,
    contextual_results,
    endpoint_zones,
    host_scope_summary,
)

REPORT_MODEL_VERSION = 13
DASHBOARD_MODEL_VERSION = 15


_SUITE_LABELS = {
    "controller-bootstrap": "Controller readiness",
    "same-subnet": "Same-subnet connectivity",
    "project-network-routing": "Routed project networks",
    "router-static-routing": "Router static routes",
    "project-provider-connectivity": "Project/provider connectivity",
    "floating-ip": category_label("floating-ip"),
    "floating-ip-lifecycle": category_label("floating-ip-lifecycle"),
    "egress": "External egress",
    "source-nat-setting": category_label("source-nat-setting"),
    "source-nat-packet-size": category_label("source-nat-packet-size"),
    "floating-ip-packet-size": "Floating-IP packet size",
    "floating-ip-egress-source-address": "Floating-IP outbound source address",
    "floating-ip-egress-mtu": "Floating-IP outbound path MTU",
    "floating-ip-egress-fragmentation": "Floating-IP outbound fragmentation",
    "mtu": "Packet-size validation",
    "security-group": "Security groups",
    "server-lifecycle": "Server lifecycle",
    "router-interface-lifecycle": "Router-interface lifecycle",
    "compute-placement": "Migration and placement",
    "network-performance": "Path performance",
}


_PURPOSE_BY_CATEGORY = {
    "controller-bootstrap": "Confirms that the guest probe controller is ready before network tests begin.",
    "same-subnet": "Checks whether two endpoints on the same Neutron subnet communicate as expected.",
    "project-network-routing": "Checks traffic between project networks through one Neutron router.",
    "router-static-routing": "Checks traffic between two Neutron routers using explicit static routes.",
    "project-provider-connectivity": "Observes fixed-IP traffic between a project network and a provider network.",
    "provider-network-connectivity": "Checks fixed-IP traffic between the recorded provider networks against the configured routing expectation.",
    "floating-ip": "Checks inbound connectivity through a Neutron floating IPv4 address.",
    "floating-ip-lifecycle": "Checks traffic withdrawal and recovery while a floating IP is detached and reassociated.",
    "floating-ip-peer": "Checks traffic to a peer's floating IP or the VM's own floating IP, according to the recorded path.",
    "egress": "Checks outbound connectivity and the translated source identity seen outside the project network.",
    "source-nat-setting": "Checks traffic behaviour while router source NAT is disabled and restored.",
    "source-nat-connectivity": "Checks outbound connectivity through router source NAT and the source identity observed by the destination.",
    "source-nat-packet-size": "Checks routed MTU and source-NAT packet-size behaviour toward the provider observer.",
    "floating-ip-packet-size": "Checks routed MTU and packet-size behaviour for floating-IP egress.",
    "floating-ip-egress-source-address": "Checks the translated source address seen by a provider observer for one outbound floating-IP TCP flow.",
    "floating-ip-egress-mtu": "Checks the outbound floating-IP path's advertised no-fragment MTU contract.",
    "floating-ip-egress-fragmentation": "Separately checks outbound IPv4 fragmentation behaviour after the path-MTU prerequisite passes.",
    "mtu": "Checks advertised MTU, no-fragment path limits, PMTUD evidence, and TCP MSS where available.",
    "security-group": "Checks that security-group deny, allow, and restore states affect traffic as expected.",
    "server-lifecycle": "Checks traffic loss and recovery across a sampled server stop/start cycle.",
    "router-interface-lifecycle": "Checks traffic withdrawal and recovery while a router interface is removed and restored.",
    "compute-placement": "Checks placement, migration completion, port rebinding, guest continuity, and endpoint recovery.",
    "network-performance": "Measures traffic between the recorded endpoints; the test title identifies the exact metric.",
}


def _bounded_text(value: Any, *, limit: int = 600) -> str:
    text = re.sub(r"[ \t]+", " ", str(value or "")).strip()
    text = re.sub(r"\n{3,}", "\n\n", text)
    if len(text) <= limit:
        return text
    head = max(1, int(limit * 0.62))
    tail = max(1, limit - head - 28)
    return f"{text[:head].rstrip()}\n… evidence omitted …\n{text[-tail:].lstrip()}"


def _summary_text(value: Any, *, limit: int = 360) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip(" ;")
    if not text:
        return ""
    clauses = [clause.strip() for clause in text.split(";") if clause.strip()]
    if len(clauses) > 2:
        text = "; ".join(clauses[:2])
    if len(text) > limit:
        text = text[: limit - 1].rstrip(" ,;:") + "…"
    return text


def _json_excerpt(value: Any, *, limit: int) -> str:
    if value in (None, {}, []):
        return ""
    try:
        rendered = json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError):
        rendered = repr(value)
    return _bounded_text(rendered, limit=limit)


def _first(*values: Any) -> Any:
    return next((value for value in values if value not in (None, "", [], {})), None)


def _without_inferred_labels(value: Any) -> Any:
    """Remove presentation-only interpretations from compact HTML evidence."""

    blocked_keys = (
        "inference",
        "likely_failure",
        "topology_label",
        "topology_description",
        "placement_description",
        "fragmentation_location",
        "attribution_reason",
        "failure_attribution",
    )
    if isinstance(value, dict):
        output = {}
        for key, item in value.items():
            normalized = str(key).lower()
            if any(token in normalized for token in blocked_keys):
                continue
            cleaned = _without_inferred_labels(item)
            if cleaned not in (None, "", [], {}):
                output[str(key)] = cleaned
        return output
    if isinstance(value, list):
        return [
            cleaned
            for item in value
            if (cleaned := _without_inferred_labels(item)) not in (None, "", [], {})
        ]
    if isinstance(value, str) and re.search(
        r"\b(?:infer(?:red|ence)?|likely|suspected|appears?|suggests?|probably|presumably|reconstructed)\b"
        r"|\b(?:direct\s+l[23]|same[- ]subnet\s+path|routed\s+(?:ip\s+)?path|nat(?:ted)?\s+path|translated\s+path)\b",
        value,
        flags=re.IGNORECASE,
    ):
        return None
    return value


def _presentation_text(value: Any, *, fallback: str = "") -> str:
    """Return factual presentation text or a neutral fallback.

    Raw commands, stdout/stderr, and route lookups do not pass through this
    helper: they remain evidence. It is only for report titles, summaries, and
    explanatory labels.
    """

    text = normalize_topology_label(value)
    if not text:
        return fallback
    cleaned = _without_inferred_labels(text)
    return str(cleaned) if cleaned is not None else fallback


def _route_output(value: Any) -> str:
    if isinstance(value, str):
        return _bounded_text(value, limit=4_000)
    if isinstance(value, dict):
        return _bounded_text(
            json.dumps(
                value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
            ),
            limit=4_000,
        )
    return ""


def _recorded_route_observations(result: dict[str, Any]) -> list[dict[str, str]]:
    """Return raw route lookups that were actually persisted by a test."""

    details = result.get("details") or {}
    observations: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(observer: str, value: Any, returncode: Any = 0) -> None:
        try:
            successful = int(returncode) == 0
        except (TypeError, ValueError):
            successful = False
        output = _route_output(value)
        if not successful or not output or output in seen:
            return
        seen.add(output)
        observations.append({"observer": observer, "output": output})

    diagnostics = (details.get("probe") or {}).get("diagnostics") or {}
    add(
        "Flux runner",
        diagnostics.get("runner_route"),
        diagnostics.get("runner_route_returncode", 0),
    )
    add(
        "Provider observer",
        diagnostics.get("observer_route"),
        diagnostics.get("observer_route_returncode", 0),
    )
    endpoint_route = diagnostics.get("endpoint_route")
    if (
        isinstance(endpoint_route, dict)
        and str(endpoint_route.get("stdout") or "").strip()
    ):
        route_text = "\n".join(
            str(value).strip()
            for value in (
                endpoint_route.get("command"),
                endpoint_route.get("stdout"),
            )
            if str(value or "").strip()
        )
        add(
            "Source endpoint",
            route_text,
            endpoint_route.get("returncode"),
        )

    def visit(value: Any, path: tuple[str, ...] = ()) -> None:
        if len(observations) >= 4:
            return
        if isinstance(value, list):
            for item in value:
                visit(item, path)
            return
        if not isinstance(value, dict):
            return
        route = value.get("route")
        if isinstance(route, dict) and str(route.get("stdout") or "").strip():
            add(
                "Destination endpoint" if "reverse" in path else "Source endpoint",
                "\n".join(
                    str(item).strip()
                    for item in (route.get("command"), route.get("stdout"))
                    if str(item or "").strip()
                ),
                route.get("returncode", 0),
            )
        if (
            isinstance(route, dict)
            and route.get("dev")
            and (route.get("dst") or route.get("from") or route.get("gateway"))
        ):
            direction = " ".join(path).lower()
            observer = (
                "Source endpoint"
                if "forward" in direction
                else "Destination endpoint"
                if "reverse" in direction
                else "Recorded endpoint"
            )
            add(observer, route)
        for key, item in value.items():
            visit(item, path + (str(key),))

    visit(details)
    return observations[:4]


def _suite_label(category: Any) -> str:
    key = str(category or "uncategorized")
    return _SUITE_LABELS.get(key, category_label(key))


def _purpose(result: dict[str, Any]) -> str:
    details = result.get("details") or {}
    measurement = str(details.get("measurement") or "")
    measurement_purpose = {
        "tcp-throughput": "Measures forward and reverse TCP throughput for this endpoint pair.",
        "latency": "Measures idle latency and latency while the path is carrying load.",
        "udp": "Measures UDP application delivery, jitter, packet ordering, and sender achievement.",
        "mtu-mss": "Measures the effective no-fragment path MTU and TCP MSS against the advertised contract.",
        "concurrency": "Measures aggregate TCP throughput and fairness as parallel flows increase.",
        "asymmetry": "Compares forward and reverse performance on the same path.",
        "repeatability": "Checks variation across repeated measurements of the same path.",
        "concurrent-path-load": "Measures aggregate and per-pair behaviour while multiple VM pairs run simultaneously.",
        "fabric-scale": "Measures aggregate and per-pair behaviour while multiple VM pairs run simultaneously.",
    }.get(measurement)
    if measurement_purpose:
        return measurement_purpose
    contract = _first(
        result.get("contract_description"),
        ((result.get("contract") or {}).get("description")),
    )
    if contract:
        return _summary_text(contract, limit=240)
    return _PURPOSE_BY_CATEGORY.get(
        str(result.get("category") or ""),
        "Checks the expected OpenStack networking behaviour named by this test.",
    )


def _compact_evidence(result: dict[str, Any]) -> dict[str, Any]:
    details = result.get("details") or {}
    probe = details.get("tcp_baseline") or details.get("probe") or {}
    execution = details.get("execution_error") or {}
    attention = str(result.get("severity") or "") not in {"good", "neutral"}
    output_limit = 8_000 if attention else 1_200
    parsed_limit = 14_000 if attention else 2_800
    command = _first(
        probe.get("command"), execution.get("command"), details.get("command")
    )
    parsed = _without_inferred_labels(
        _first(
            details.get("execution_diagnostics"),
            details.get("metrics"),
            probe.get("diagnostics"),
            details.get("diagnostics"),
            details.get("assessment"),
        )
    )
    return {
        "command": _bounded_text(command, limit=4_000) if command else "",
        "stdout": _bounded_text(
            _first(probe.get("stdout"), execution.get("stdout"), details.get("stdout")),
            limit=output_limit,
        ),
        "stderr": _bounded_text(
            _first(probe.get("stderr"), execution.get("stderr"), details.get("stderr")),
            limit=output_limit,
        ),
        "parsed": _json_excerpt(parsed, limit=parsed_limit),
        "diagnostic_snapshot": result.get("operator_diagnostics")
        or details.get("diagnostic_snapshot")
        or {},
        "note": "Bounded excerpts are embedded here. The complete machine-readable record remains in results.json.",
    }


def _compact_result(
    index: int,
    result: dict[str, Any],
    *,
    rerun: dict[str, Any] | None = None,
    manual_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    details = result.get("details") or {}
    source = result.get("source_display") or {}
    destination = result.get("destination_display") or {}
    category = str(result.get("category") or "uncategorized")
    zones = sorted(
        {
            str(zone)
            for zone in (
                source.get("zone"),
                destination.get("zone"),
                details.get("availability_zone"),
                (details.get("path") or {}).get("availability_zone"),
                *endpoint_zones(details),
            )
            if zone
        }
    )
    expected = _first(
        result.get("expectation_description"),
        ((result.get("contract") or {}).get("expectation") or {}).get("description"),
        result.get("expected"),
    )
    observed = _first(
        result.get("observation_description"),
        ((result.get("contract") or {}).get("observation") or {}).get("description"),
        result.get("observed"),
        result.get("actual"),
    )
    result_id = str(
        result.get("result_id") or result.get("test_id") or f"result-{index:04d}"
    )
    title = _presentation_text(
        _first(result.get("title"), result.get("display_name")),
        fallback=f"Validation test {index:04d}",
    )
    suite = _presentation_text(_suite_label(category), fallback="Validation")
    purpose = _presentation_text(
        _purpose(result),
        fallback="Checks the expected behaviour named by this test.",
    )
    scenario = _presentation_text(
        _first(result.get("scenario_label"), result.get("scenario")),
        fallback=suite,
    )
    message = _presentation_text(
        _summary_text(
            _first(result.get("operator_message"), result.get("message")),
            limit=420,
        )
    )
    expected_text = _presentation_text(_summary_text(expected, limit=500))
    observed_text = _presentation_text(_summary_text(observed, limit=500))
    story = connection_story(result)
    if story:
        title = story["title"]
        purpose = "Connect to the provider VM through address translation before measuring packet sizes."
        observed_text = story["observed"]
        message = story["impact"]
    explanation = explain_result(result)
    if not story and explanation.get("recorded_message"):
        message = _presentation_text(
            _bounded_text(explanation["recorded_message"], limit=420)
        )
    context = result.get("human_context") or result_context(result)
    readable_context = result.get("context_lines") or context_lines(result)
    purpose = context.get("purpose") or purpose
    for key in ("expected", "observed", "what_happened"):
        explanation[key] = _presentation_text(explanation[key])
    expected_text = explanation["expected"]
    observed_text = story["observed"] if story else explanation["observed"]
    if explanation["kind"] in {
        "expected-isolation",
        "expected-withdrawal",
        "interruption-tolerance-exceeded",
        "migration-interruption-observation",
    }:
        message = _bounded_text(explanation["what_happened"], limit=420)
        observed_text = explanation["observed"]
    search_text = " ".join(
        str(value or "")
        for value in (
            result_id,
            result.get("test_name"),
            title,
            suite,
            scenario,
            result.get("phase"),
            result.get("family_label"),
            result.get("path_id"),
            source.get("label"),
            source.get("ip"),
            destination.get("label"),
            destination.get("ip"),
            " ".join(zones),
            explanation.get("headline"),
            explanation.get("kind"),
            " ".join(readable_context),
            context.get("path"),
            context.get("placement"),
            context.get("timing"),
            context.get("action"),
        )
    ).lower()
    return {
        "sequence": index,
        "reference": f"Test {index:04d}",
        "result_id": result_id,
        "title": title,
        "test_name": _presentation_text(result.get("test_name"), fallback=title),
        "execution_name": _presentation_text(
            result.get("execution_name"), fallback=title
        ),
        "address_path": details.get("address_path") or {},
        "address_summary": " | ".join(address_path_lines(details)),
        "purpose": purpose,
        "human_context": context,
        "context_lines": readable_context,
        "status": result.get("status") or "UNKNOWN",
        "severity": result.get("severity") or "neutral",
        "category": category,
        "suite": suite,
        "scenario": scenario,
        "phase": context.get("timing"),
        "timing": context.get("timing"),
        "action": context.get("action"),
        "family": result.get("family_label"),
        "path_id": result.get("path_id"),
        "source": {
            "label": _presentation_text(source.get("label")),
            "ip": source.get("ip") or result.get("source_ip"),
        },
        "destination": {
            "label": _presentation_text(destination.get("label")),
            "ip": destination.get("ip") or result.get("destination_ip"),
        },
        "zones": zones,
        "expected": expected_text,
        "observed": observed_text,
        "message": _presentation_text(message),
        "operator_explanation": explanation,
        "host_scope": result.get("host_scope") or {},
        "started_at": result.get("started_at"),
        "finished_at": result.get("finished_at"),
        "duration_ms": _first(result.get("duration_ms"), details.get("duration_ms")),
        "route_observations": _recorded_route_observations(result),
        "technical": {
            "address_mappings": json.dumps(
                details["address_path"], sort_keys=True, indent=2
            )
            if details.get("address_path")
            else None,
            "canonical_name": _presentation_text(
                result.get("canonical_name") or result.get("display_name"),
                fallback=result_id,
            ),
            "contract_type": result.get("contract_type"),
            "contract_verdict": result.get("contract_verdict"),
            "semantic_path": result.get("semantic_path_key"),
        },
        "evidence": _compact_evidence(result),
        "manual_reproduction": manual_reproduction(result, context=manual_context),
        "rerun": rerun or {},
        "search_text": search_text,
    }


def _compact_measurement(measurement: dict[str, Any]) -> dict[str, Any]:
    values = measurement.get("values") or {}
    primitive_values = {
        str(key): value
        for key, value in values.items()
        if isinstance(value, (int, float, bool)) or value is None
    }
    return {
        "kind": measurement.get("kind"),
        "title": measurement.get("title"),
        "status": measurement.get("status"),
        "health": measurement.get("health"),
        "values": primitive_values,
        "result_id": measurement.get("result_id"),
    }


def _addressing(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    source = str(value.get("gateway_ip_source") or "")
    recorded_gateway = not source.lower().startswith("inferred")
    output = {
        key: value.get(key)
        for key in (
            "cidr",
            "network_name",
            "network_label",
            "allocation_method",
            "subnet_pool_name",
        )
    }
    output["gateway_ip"] = value.get("gateway_ip") if recorded_gateway else None
    output["gateway_ip_source"] = source if recorded_gateway else None
    return output


def _compact_path(
    path: dict[str, Any],
    route_observations: list[dict[str, str]],
    contexts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    contexts = contexts or []
    measurements = {
        str(kind): _compact_measurement(measurement)
        for kind, measurement in (path.get("measurements") or {}).items()
    }
    return {
        "path_id": path.get("path_id"),
        "reference": (
            f"Pair {int(path['path_number']):02d}"
            if path.get("path_number") is not None
            else path.get("path_reference") or path.get("path_id")
        ),
        "title": "Recorded endpoint pair",
        "endpoint_pair": path.get("endpoint_pair") or path.get("address_route"),
        "route_observations": route_observations,
        "source": {
            "label": _presentation_text(
                (path.get("source") or {}).get("label"), fallback="Source endpoint"
            ),
            "ip": path.get("source_ip") or (path.get("source") or {}).get("ip"),
        },
        "destination": {
            "label": _presentation_text(
                (path.get("destination") or {}).get("label"),
                fallback="Destination endpoint",
            ),
            "ip": path.get("destination_ip")
            or (path.get("destination") or {}).get("ip"),
        },
        "source_addressing": _addressing(path.get("source_addressing")),
        "destination_addressing": _addressing(path.get("destination_addressing")),
        "family": path.get("family_label"),
        "phase": path.get("phase"),
        "packet_paths": sorted(
            {str(context["path"]) for context in contexts if context.get("path")}
        ),
        "timing_labels": sorted(
            {str(context["timing"]) for context in contexts if context.get("timing")}
        ),
        "placement_labels": sorted(
            {
                str(context["placement"])
                for context in contexts
                if context.get("placement")
            }
        ),
        "source_host": path.get("source_host_alias"),
        "destination_host": path.get("destination_host_alias"),
        "availability_zone": path.get("availability_zone"),
        "source_availability_zone": path.get("source_availability_zone"),
        "destination_availability_zone": path.get("destination_availability_zone"),
        "health": path.get("health"),
        "connectivity": path.get("connectivity"),
        "measurements": measurements,
        "finding_ids": list(path.get("finding_ids") or []),
        "result_ids": list(path.get("result_ids") or []),
        "comparison": path.get("comparison"),
    }


def _compact_network(network: dict[str, Any]) -> dict[str, Any]:
    compact = {
        key: network.get(key)
        for key in (
            "id",
            "name",
            "label",
            "subnet_summary",
            "external",
            "shared",
            "network_type",
            "physical_network",
            "segmentation_id",
            "mtu",
            "availability_zone_hints",
        )
    }
    compact["label"] = _presentation_text(
        compact.get("label"),
        fallback=str(compact.get("name") or compact.get("id") or "Network"),
    )
    return compact


def _suite_summary(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, Counter[str]] = defaultdict(Counter)
    for result in results:
        grouped[str(result["suite"])][str(result["status"])] += 1
    rows = []
    for suite, counts in grouped.items():
        total = sum(counts.values())
        rows.append(
            {
                "suite": suite,
                "total": total,
                "counts": dict(counts),
                "attention": total
                - counts.get("PASS", 0)
                - counts.get("NOT_APPLICABLE", 0),
            }
        )
    return sorted(rows, key=lambda row: (-row["attention"], row["suite"]))


def _finding_workflow(
    finding: dict[str, Any],
    tests_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Add a short, evidence-bound investigation handoff to one finding."""

    finding = {
        **finding,
        "title": _presentation_text(
            finding.get("title"), fallback="Recorded condition requiring review"
        ),
        "summary": _presentation_text(
            finding.get("summary"),
            fallback="Review the contributing tests and recorded evidence.",
        ),
    }

    result_ids = [str(value) for value in finding.get("result_ids") or []]
    tests = [tests_by_id[value] for value in result_ids if value in tests_by_id]
    total = int(finding.get("result_count") or len(tests))
    path_count = len(finding.get("path_ids") or [])
    status_counts = Counter(
        {
            str(key).upper(): int(value or 0)
            for key, value in (finding.get("status_counts") or {}).items()
        }
    )
    paired_evidence = sum(
        1 for test in tests if test.get("expected") and test.get("observed")
    )
    path_evidence = sum(1 for test in tests if test.get("path_id"))
    root = str(finding.get("root_key") or "")
    failures = status_counts.get("FAIL", 0)
    errors = status_counts.get("ERROR", 0)
    inconclusive = status_counts.get("UNVERIFIED", 0)

    scope = (
        f"{path_count} endpoint pair{'s' if path_count != 1 else ''}"
        if path_count
        else "run scope"
    )
    incomplete_count = (
        errors
        + inconclusive
        + sum(
            count
            for status, count in status_counts.items()
            if status.startswith("BLOCKED") or status == "NOT_RUN_CANCELLED"
        )
    )
    mixed_failure_and_error = bool(failures and incomplete_count)

    if mixed_failure_and_error:
        impact = (
            f"{failures} completed validation{'s' if failures != 1 else ''} "
            f"contradict{'s' if failures == 1 else ''} expected behaviour; "
            + (
                f"{errors} additional operation{'s' if errors != 1 else ''} did not complete; "
                if errors
                else ""
            )
            + f"{incomplete_count} additional check(s) remain unvalidated. "
            f"The grouped evidence spans {scope}; it does not establish a failure on every pair."
        )
        next_check = (
            "Inspect the first failing command and standard error for each ERROR; "
            "correct the execution problem and rerun the recorded selectable "
            "validation. Separately investigate completed FAIL results by comparing "
            "expected and observed evidence. Correcting an ERROR does not clear a "
            "confirmed contradiction."
        )
    elif errors:
        impact = (
            "The affected network behaviour remains unvalidated because Flux did "
            "not complete the operation."
        )
        next_check = (
            "Open the affected test, inspect the first failing command and standard "
            "error, correct the execution error, then rerun only a recorded "
            "planner-selectable validation."
        )
    elif root == "connectivity":
        impact = (
            f"Expected connectivity is contradicted on {scope}."
            if failures
            else f"Connectivity remains unvalidated across {scope}."
        )
        next_check = (
            "Open an affected endpoint pair, review its endpoint and subnet facts, "
            "and raw route lookup output, then compare expected with observed evidence."
        )
    elif root in {
        "execution",
        "neutron-flux-execution",
        "neutron-flux-controller-setup",
    }:
        impact = (
            "The affected network behaviour remains unvalidated because Flux did "
            "not complete the operation."
        )
        next_check = (
            "Open the affected test, inspect the first failing command or standard "
            "error, then rerun only that validation."
        )
    elif root == "migration-interruption":
        impact = "Migration completed and TCP survived, but the sampled ICMP/UDP interruption exceeded the recorded limits."
        next_check = "Correlate the failed-probe interval with Nova migration and network-side logs. Review the exact limits and phase measurements in each affected check."
    elif root == "udp":
        impact = (
            f"UDP delivery quality across {scope} cannot be attributed to the "
            "network alone from the current evidence."
        )
        next_check = (
            "Check sender achievement and endpoint receive counters before treating "
            "the recorded loss as a network-path fault."
        )
    elif root == "mtu":
        impact = (
            f"The usable no-fragment packet size across {scope} is not fully "
            "confirmed against the advertised MTU."
        )
        next_check = (
            "Compare advertised MTU with the confirmed no-fragment value in both "
            "directions, then open the contributing MTU test."
        )
    elif "packet-size" in root:
        impact = (
            f"The recorded packet-size result contradicts the expected behaviour on {scope}."
            if failures
            else f"Packet-size behaviour across {scope} requires confirmation."
        )
        next_check = (
            "Compare the advertised MTU, confirmed no-fragment size, and translated "
            "source on the affected route before changing the cloud."
        )
    else:
        impact = (
            f"{total} test{'s' if total != 1 else ''} at {scope} require review "
            "before the affected behaviour can be accepted."
        )
        next_check = (
            "Compare the affected tests' expected behaviour with their parsed "
            "observations before changing the cloud."
        )

    if mixed_failure_and_error:
        completeness = "Conclusive with gaps"
        evidence_summary = (
            f"{failures} completed result{'s' if failures != 1 else ''} record"
            f"{'s' if failures == 1 else ''} FAIL"
            + (
                f"; {paired_evidence} include{'s' if paired_evidence == 1 else ''} "
                "paired expectation and observation"
                if paired_evidence
                else ""
            )
            + f". {incomplete_count} additional check(s) lack conclusive execution evidence and remain unvalidated."
        )
        # A completed contradiction must remain a confirmed finding even when a
        # sibling result in the same root group ended in an execution error.
        finding["severity"] = "critical"
        finding["group"] = "confirmed"
    elif errors:
        completeness = "Limited"
        remaining = max(0, total - errors)
        evidence_summary = (
            f"{errors} operation{'s' if errors != 1 else ''} did not complete"
            + (
                f"; {remaining} additional result{'s' if remaining != 1 else ''} retain partial evidence."
                if remaining
                else "; network behaviour was not fully observed."
            )
        )
    elif failures and paired_evidence:
        completeness = "Conclusive"
        evidence_summary = (
            f"{paired_evidence} of {total} affected tests record both expectation and "
            "observation; a contradiction is present."
        )
    else:
        completeness = "Partial"
        evidence_summary = (
            f"{paired_evidence} of {total} affected tests record both expectation and "
            f"observation; {path_evidence} are tied to an exact endpoint pair."
        )
    if inconclusive and not failures and not errors:
        evidence_summary = (
            f"{inconclusive} result{'s' if inconclusive != 1 else ''} remain "
            "inconclusive; additional endpoint evidence is required."
        )

    if root == "translated-tcp-connect":
        stories = [
            test.get("operator_explanation") or connection_story(test) for test in tests
        ]
        story: dict[str, str] = next((item for item in stories if item), {})
        if story:
            impact = story.get("why_this_status") or story.get("impact") or impact
            next_check = story["next_check"]
            completeness = "Connection failure recorded"
            evidence_summary = (
                " ".join(story.get("limitations") or [])
                or story.get("evidence_summary")
                or "The failed step is recorded; the component cause is not established."
            )
    elif root == "direction" and inconclusive and not failures and not errors:
        impact = "The forward/reverse comparison is incomplete. Read the individual TCP, latency, and UDP measurements separately."
        next_check = "Compare UDP only at the same packet size and sustainable send rate in both directions. Use the recorded unmatched-profile count to identify the measurement gap."
        evidence_summary = "Different calibrated rates or missing eligible samples prevent a complete UDP comparison. An incomplete comparison is not evidence of packet loss."

    test_reruns = []
    seen_reruns: set[tuple[Any, ...]] = set()
    for result_id in result_ids:
        test = tests_by_id.get(result_id) or {}
        rerun = test.get("rerun") or {}
        identity = (
            rerun.get("command"),
            rerun.get("exact_fragment"),
            rerun.get("parent_fragment"),
            rerun.get("phase_fragment"),
            rerun.get("guidance"),
        )
        if identity in seen_reruns:
            continue
        seen_reruns.add(identity)
        test_reruns.append(
            {
                "result_id": result_id,
                "kind": rerun.get("kind") or "unavailable",
                "selectable_test_id": rerun.get("selectable_test_id"),
                "exact_fragment": rerun.get("exact_fragment"),
                "parent_fragment": rerun.get("parent_fragment"),
                "phase_fragment": rerun.get("phase_fragment"),
                "command": rerun.get("command"),
                "guidance": rerun.get("guidance")
                or "No corresponding result record was available for rerun guidance.",
            }
        )

    return {
        **finding,
        "test_ids": result_ids,
        "operator_cases": [
            {
                "result_id": test.get("result_id"),
                "explanation": test.get("operator_explanation") or explain_result(test),
            }
            for test in tests
        ],
        "test_reruns": test_reruns,
        "impact": _presentation_text(_summary_text(impact, limit=260)),
        "evidence_completeness": completeness,
        "evidence_summary": _presentation_text(
            _summary_text(evidence_summary, limit=260)
        ),
        "next_check": _presentation_text(_summary_text(next_check, limit=300)),
    }


def enrich_findings(
    payload: dict[str, Any],
    findings: list[dict[str, Any]],
    results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Apply one operator workflow to HTML and incident-summary findings."""

    tests_by_id: dict[str, dict[str, Any]] = {}
    reruns: RerunResolver | None = None
    for index, result in enumerate(results, start=1):
        result_id = str(
            result.get("result_id") or result.get("test_id") or f"result-{index:04d}"
        )
        details = result.get("details") or {}
        path = details.get("path") or {}
        rerun = result.get("rerun")
        if not rerun:
            if reruns is None:
                reruns = RerunResolver(payload)
            rerun = reruns.for_result(result)
        tests_by_id[result_id] = {
            **result,
            "result_id": result_id,
            "path_id": result.get("path_id") or path.get("path_id"),
            "expected": _first(
                result.get("expected"),
                result.get("expectation_description"),
                ((result.get("contract") or {}).get("expectation") or {}).get(
                    "description"
                ),
            ),
            "observed": _first(
                result.get("observed"),
                result.get("observation_description"),
                ((result.get("contract") or {}).get("observation") or {}).get(
                    "description"
                ),
            ),
            "rerun": rerun,
        }
    return [_finding_workflow(finding, tests_by_id) for finding in findings]


def _path_evidence_scope(
    payload: dict[str, Any],
    results: list[dict[str, Any]],
    paths: list[dict[str, Any]],
) -> dict[str, Any]:
    """Keep guest-path diagnostics separate from control and measurement records."""

    by_id = {str(row.get("result_id")): row for row in results}
    controller_paths = []
    traffic_paths = []
    guest_paths = []
    performance_paths = []
    for path in paths:
        rows = [
            by_id[str(identity)]
            for identity in path.get("result_ids") or []
            if str(identity) in by_id
        ]
        categories = {row.get("category") for row in rows}
        controller_only = bool(rows) and (
            categories == {"controller-bootstrap"}
            or all(
                (row.get("host_scope") or {}).get("code") == "control" for row in rows
            )
        )
        if controller_only:
            controller_paths.append(path)
            continue
        traffic_paths.append(path)
        if categories == {"network-performance"}:
            performance_paths.append(path)
        else:
            # Unknown or incomplete classifications remain applicable: absence
            # of captured output must not itself turn a real gap into N/A.
            guest_paths.append(path)
    performance = (payload.get("summary") or {}).get("performance_coverage") or {}
    return {
        "traffic_paths": len(traffic_paths),
        "traffic_paths_with_endpoint_ips": sum(
            bool((path.get("source") or {}).get("ip"))
            and bool((path.get("destination") or {}).get("ip"))
            for path in traffic_paths
        ),
        "functional_guest_paths": len(guest_paths),
        "functional_guest_paths_with_route_output": sum(
            bool(path.get("route_observations")) for path in guest_paths
        ),
        "controller_access_paths": len(controller_paths),
        "controller_paths_without_runner_ip": sum(
            not (path.get("source") or {}).get("ip") for path in controller_paths
        ),
        "standalone_performance_paths": len(performance_paths),
        "performance_paths_selected": performance.get("selected"),
        "performance_paths_completed": performance.get("completed"),
        "performance_paths_omitted": performance.get("omitted"),
    }


def _coverage_summary(
    payload: dict[str, Any],
    results: list[dict[str, Any]],
    paths: list[dict[str, Any]],
) -> dict[str, Any]:
    ledger = payload.get("planned_check_ledger") or [
        row
        for row in (payload.get("coverage_ledger") or [])
        if row.get("kind") in (None, "test")
    ]
    outcomes = Counter(str(row.get("outcome") or "UNKNOWN") for row in ledger)
    planned = len(ledger) or len(results)
    never_ran = sum(
        outcomes.get(key, 0) for key in ("BLOCKED", "NEVER_RAN", "CANCELLED", "PENDING")
    )
    accounted = planned - outcomes.get("UNKNOWN", 0) - outcomes.get("PENDING", 0)
    routes_with_addresses = sum(
        1
        for path in paths
        if (path.get("source") or {}).get("ip")
        and (path.get("destination") or {}).get("ip")
    )
    routes_with_observations = sum(
        1 for path in paths if path.get("route_observations")
    )
    tests_with_endpoint_pairs = sum(
        1
        for result in results
        if result.get("path_id")
        or (
            (result.get("source") or {}).get("ip")
            and (result.get("destination") or {}).get("ip")
        )
    )
    measured_paths = sum(
        1 for path in paths if any((path.get("measurements") or {}).values())
    )
    return {
        "planned_tests": planned,
        "accounted_tests": accounted,
        "never_ran_tests": never_ran,
        "outcomes": dict(sorted(outcomes.items())),
        "tests_with_endpoint_pairs": tests_with_endpoint_pairs,
        "path_count": len(paths),
        "paths_with_endpoint_ips": routes_with_addresses,
        "paths_with_route_observations": routes_with_observations,
        "measured_paths": measured_paths,
        "evidence_scope": _path_evidence_scope(payload, results, paths),
    }


def _concurrent_load(payload: dict[str, Any]) -> list[dict[str, Any]]:
    scalar_keys = (
        "pairs",
        "pairs_used",
        "cross_compute_pairs",
        "same_compute_pairs",
        "median_aggregate_mbps",
        "minimum_aggregate_mbps",
        "maximum_aggregate_mbps",
        "median_pair_mbps",
        "minimum_pair_mbps",
        "minimum_fairness",
        "median_idle_p95_ms",
        "median_loaded_p95_ms",
        "median_loaded_latency_ratio",
        "median_loaded_tcp_aggregate_mbps",
        "maximum_loaded_icmp_loss_pct",
        "maximum_loaded_udp_application_loss_pct",
        "maximum_loaded_udp_jitter_ms",
        "minimum_udp_sender_achievement_pct",
        "total_retransmissions",
        "total_loaded_retransmissions",
        "per_pair_degradation_pct",
    )
    rows = []
    for result in payload.get("results") or []:
        details = result.get("details") or {}
        if details.get("measurement") not in {"concurrent-path-load", "fabric-scale"}:
            continue
        execution_scope = details.get("execution_scope")
        execution_scope_zone = (
            execution_scope.get("availability_zone")
            if isinstance(execution_scope, dict)
            else None
        )
        zone = _first(
            details.get("availability_zone"),
            (details.get("path") or {}).get("availability_zone"),
            execution_scope_zone,
        )
        rows.append(
            {
                "result_id": result.get("test_id"),
                "status": result.get("status"),
                "zone": zone or "Availability zone unavailable",
                "levels": [
                    {key: level.get(key) for key in scalar_keys}
                    for level in ((details.get("metrics") or {}).get("levels") or [])
                ],
            }
        )
    return rows


def _resource_summary(resources: list[dict[str, Any]]) -> dict[str, Any]:
    by_type = Counter(str(item.get("resource_type") or "unknown") for item in resources)
    by_state = Counter(
        str(item.get("cleanup_state") or "unknown") for item in resources
    )
    return {
        "total": len(resources),
        "by_type": dict(sorted(by_type.items())),
        "by_cleanup_state": dict(sorted(by_state.items())),
    }


def _compact_summary(value: Any) -> dict[str, Any]:
    summary = value if isinstance(value, dict) else {}
    return {
        key: summary.get(key)
        for key in (
            "counts",
            "total_results",
            "performance_results",
            "performance",
            "setup_failed",
            "interrupted",
            "cleanup_complete",
            "unresolved_cloud_operations",
            "quarantined_hosts",
        )
    }


def _compact_run(value: Any) -> dict[str, Any]:
    run = value if isinstance(value, dict) else {}
    return {
        "run_id": run.get("run_id"),
        "action": run.get("action"),
        "started_at": run.get("started_at"),
        "finished_at": run.get("finished_at"),
        "final_status": run.get("final_status"),
        "example_notice": _presentation_text(run.get("example_notice")),
    }


def _compact_dashboard_summary(value: Any) -> dict[str, Any]:
    summary = value if isinstance(value, dict) else {}
    return {
        key: summary.get(key)
        for key in (
            "result_counts",
            "path_health_counts",
            "finding_count",
            "executed_count",
            "cleanup_present",
            "cleanup_unresolved_resources",
            "cleanup_verification_issues",
            "cleanup_complete",
            "final_status",
            "performance",
        )
    }


def _compact_configuration(value: Any) -> dict[str, Any]:
    config = value if isinstance(value, dict) else {}
    migration = dict(config.get("migration") or {})
    if str(migration.get("mode") or "").lower() == "cold-only":
        migration["transport"] = "not used"
        migration["effective_storage"] = "not used"
    return {
        "test_selection": {
            **(
                {
                    "include_derived_tests": bool(
                        config["test_selection"]["include_derived_tests"]
                    )
                }
                if "include_derived_tests" in (config.get("test_selection") or {})
                else {}
            ),
            "mode": (config.get("test_selection") or {}).get("mode") or "all",
            "requested_test_ids": (
                (config.get("test_selection") or {}).get("requested_test_ids") or []
            ),
            "automatically_included_test_ids": (
                (config.get("test_selection") or {}).get(
                    "automatically_included_test_ids"
                )
                or []
            ),
        },
        "image": config.get("image"),
        "flavor": config.get("flavor"),
        "storage": config.get("storage"),
        "performance_profile": config.get("performance_profile") or "unrecorded",
        "availability_zones": config.get("availability_zones") or [],
        "allow_cross_az_volumes": config.get("allow_cross_az_volumes", False),
        "volume_az_policy": config.get("volume_az_policy"),
        "allow_cross_az_networking": config.get("allow_cross_az_networking", False),
        "network_az": config.get("network_az"),
        "router_az": config.get("router_az"),
        "migration": {
            key: migration.get(key)
            for key in (
                "enabled",
                "mode",
                "transport",
                "storage",
                "effective_storage",
            )
        },
        "network_paths": {
            key: (config.get("network_paths") or {}).get(key)
            for key in (
                "runner_control_family",
                "ipv6_test_origin",
                "runner_ipv6_required",
            )
        },
        "performance_enabled": config.get("performance_enabled"),
        "performance_duration_seconds": config.get("performance_duration_seconds"),
        "performance_repeats": config.get("performance_repeats"),
        "concurrent_vm_pair_load": {
            key: (config.get("concurrent_vm_pair_load") or {}).get(key)
            for key in ("enabled", "pairs", "runs")
        },
        "evidence_enabled": config.get("evidence_enabled"),
    }


def _compact_cleanup(value: Any) -> dict[str, Any]:
    cleanup = value if isinstance(value, dict) else {}
    sweep = cleanup.get("orphan_sweep") or {}
    return {
        "attempted": cleanup.get("attempted"),
        "complete": cleanup.get("complete"),
        "interrupted": cleanup.get("interrupted"),
        "interruption_reason": _summary_text(
            cleanup.get("interruption_reason"), limit=320
        ),
        "scope_verification": cleanup.get("scope_verification"),
        "unverified_resource_count": cleanup.get("unverified_resource_count"),
        "deleted": cleanup.get("deleted"),
        "cleanup_issue_count": len(cleanup.get("leftovers") or []),
        "verification_issue_count": sum(
            "verification-error" in str(issue)
            for issue in cleanup.get("leftovers") or []
        ),
        "confirmed_deleted_count": cleanup.get("confirmed_deleted_count"),
        "failed": cleanup.get("failed"),
        "orphan_sweep": {
            key: sweep.get(key)
            for key in (
                "stale_resources_remaining",
                "protected_resources_remaining",
                "unknown_resources_remaining",
                "project_resources_remaining",
                "candidate_runs",
            )
        },
    }


def _blocking_check_ids(identity: str, checks: dict[str, Any]) -> list[str]:
    """Follow recorded unmet dependencies, preserving distinct causes and cycles."""
    pending = list(reversed(checks[identity].get("prerequisites", [])))
    seen = {identity}
    roots = []
    while pending:
        current = pending.pop()
        if current in seen or current not in checks:
            continue
        seen.add(current)
        row = checks[current]
        if row["outcome"] in {"PASSED", "PENDING", "INAPPLICABLE"}:
            continue
        unmet = [
            item
            for item in row.get("prerequisites", [])
            if item in checks
            and checks[item]["outcome"] not in {"PASSED", "PENDING", "INAPPLICABLE"}
        ]
        if row["outcome"] in {"FAILED", "ERROR"} or not unmet:
            roots.append(current)
        else:
            pending.extend(reversed(unmet))
    return roots


def build_report_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Build the small, operator-facing payload embedded in report.html.

    results.json remains the complete evidence record. The HTML report embeds
    one concise copy of the fields it renders, plus bounded evidence excerpts.
    """

    dashboard = payload.get("dashboard") or {}
    raw_results_by_id = {
        str(
            result.get("result_id") or result.get("test_id") or f"result-{index:04d}"
        ): result
        for index, result in enumerate(contextual_results(payload), start=1)
    }
    reruns = RerunResolver(payload)
    result_rows = []
    full_results_by_id = {}
    for index, dashboard_result in enumerate(dashboard.get("results") or [], start=1):
        result_id = str(dashboard_result.get("result_id") or f"result-{index:04d}")
        result = dict(raw_results_by_id.get(result_id) or {})
        result.update(dashboard_result)
        full_results_by_id[result_id] = result
        result_rows.append(
            _compact_result(
                index,
                result,
                rerun=reruns.for_result(result),
                manual_context=payload,
            )
        )
    evidence_entries = {}
    result_aliases = {}
    # Supporting probes carry route and endpoint context even when the ledger
    # selects an aggregate migration or lifecycle record as its canonical row.
    # Preserve those facts before reducing the visible test list.
    path_evidence_rows = list(result_rows)
    ledger = payload.get("planned_check_ledger") or []
    if ledger:
        by_id = {row["result_id"]: row for row in result_rows}
        canonical_rows: list[dict[str, Any]] = []
        for check in ledger:
            selected = by_id.get(check.get("result_id"))
            if selected is None:
                synthesized = contextual_results(
                    {
                        "plan": payload.get("plan") or {},
                        "results": [unrecorded_check_result(check)],
                    }
                )[0]
                selected = _compact_result(
                    len(canonical_rows) + 1,
                    {
                        **synthesized,
                        "test_name": check["title"],
                    },
                    rerun={},
                    manual_context=payload,
                )
                if check.get("requested_source_host"):
                    selected["host_scope"] = {
                        "code": "targeted",
                        "requested_pair": check["requested_source_host"]
                        + " ↔ "
                        + check["requested_destination_host"],
                        "requested_placement": check.get("pair_placement"),
                        "placement": "unknown",
                        "cycle": check.get("host_qualification_cycle"),
                    }
            else:
                selected = dict(selected)
                if check["outcome"] == "BLOCKED" and not selected["status"].startswith(
                    "BLOCKED"
                ):
                    recorded_status = selected["status"]
                    selected = _compact_result(
                        len(canonical_rows) + 1,
                        {
                            **full_results_by_id[selected["result_id"]],
                            "status": "BLOCKED_BY_PREREQUISITE",
                        },
                        rerun=selected.get("rerun"),
                        manual_context=payload,
                    )
                    selected["recorded_status"] = recorded_status
            if check["outcome"] == "BLOCKED":
                selected["blocked_reason"] = _presentation_text(
                    _summary_text(check["reason"], limit=800)
                )
            selected["sequence"] = len(canonical_rows) + 1
            selected["reference"] = f"T{len(canonical_rows) + 1:04d}"
            for identity in [check["id"], *check.get("evidence_ids", [])]:
                result_aliases[identity] = selected["result_id"]
            selected["related_evidence_ids"] = [
                identity
                for identity in check.get("evidence_ids", [])
                if identity != selected["result_id"] and identity in by_id
            ]
            for identity in selected["related_evidence_ids"]:
                row = by_id[identity]
                evidence_entries[identity] = {
                    k: row.get(k)
                    for k in (
                        "title",
                        "status",
                        "observed",
                        "message",
                        "evidence",
                        "manual_reproduction",
                        "host_scope",
                        "human_context",
                        "context_lines",
                        "purpose",
                        "expected",
                        "operator_explanation",
                        "family",
                        "timing",
                        "action",
                    )
                }
            canonical_rows.append(selected)
        result_rows = canonical_rows
        checks = {check["id"]: check for check in ledger}
        rows_by_id = {row["result_id"]: row for row in result_rows}
        for check, row in zip(ledger, result_rows, strict=True):
            if check["outcome"] != "BLOCKED":
                continue
            row["blocking_checks"] = [
                {
                    "result_id": target["result_id"],
                    "sequence": target["sequence"],
                    "reference": target["reference"],
                    "title": target["test_name"],
                    "reason": _presentation_text(
                        _summary_text(checks[identity]["reason"], limit=500)
                    ),
                }
                for identity in _blocking_check_ids(check["id"], checks)
                if (target := rows_by_id.get(result_aliases.get(identity))) is not None
            ]
    route_observations_by_path: dict[str, list[dict[str, str]]] = defaultdict(list)
    contexts_by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for result in path_evidence_rows:
        path_id = str(result.get("path_id") or "")
        if not path_id:
            continue
        contexts_by_path[path_id].append(result["human_context"])
        existing = {row.get("output") for row in route_observations_by_path[path_id]}
        for observation in result.get("route_observations") or []:
            if observation.get("output") not in existing:
                route_observations_by_path[path_id].append(observation)
                existing.add(observation.get("output"))
    paths = [
        _compact_path(
            path,
            route_observations_by_path.get(str(path.get("path_id") or ""), [])[:4],
            contexts_by_path.get(str(path.get("path_id") or ""), []),
        )
        for path in dashboard.get("paths") or []
    ]
    tests_by_id = {row["result_id"]: row for row in result_rows}

    def linked_ids(identities: list[str]) -> list[str]:
        return list(
            dict.fromkeys(
                result_aliases.get(identity, identity) for identity in identities
            )
        )

    for path in paths:
        path["evidence_ids"] = list(path.get("result_ids") or [])
        path["result_ids"] = linked_ids(path["evidence_ids"])
        scopes = [
            tests_by_id[result_id].get("host_scope") or {}
            for result_id in path.get("result_ids") or []
            if result_id in tests_by_id
        ]
        path["host_scopes"] = list(
            {scope.get("code"): scope for scope in scopes}.values()
        )
    findings = enrich_findings(
        payload,
        [
            {
                **finding,
                "evidence_ids": list(finding.get("result_ids") or []),
                "result_ids": linked_ids(list(finding.get("result_ids") or [])),
                "result_count": len(linked_ids(list(finding.get("result_ids") or [])))
                if ledger
                else finding.get("result_count", 0),
            }
            for finding in dashboard.get("findings") or []
        ],
        result_rows,
    )
    environment = dashboard.get("environment") or {}
    events = [
        {
            "timestamp": event.get("timestamp"),
            "type": event.get("type"),
            "title": event.get("title"),
            "message": _summary_text(event.get("message"), limit=320),
            "source_host": event.get("source_host"),
            "destination_host": event.get("destination_host"),
        }
        for event in (dashboard.get("events") or [])[-120:]
    ]
    resources = list(payload.get("resources") or [])
    return {
        "report_model_version": REPORT_MODEL_VERSION,
        "check_inventory_complete": bool(ledger),
        "schema_version": payload.get("schema_version"),
        "tool": payload.get("tool"),
        "tool_version": payload.get("tool_version"),
        "release": payload.get("release") or {},
        "run": _compact_run(payload.get("run")),
        "timing": payload.get("timing") or {},
        "configuration": _compact_configuration(payload.get("configuration")),
        "summary": _compact_summary(payload.get("summary")),
        "cleanup": _compact_cleanup(payload.get("cleanup")),
        "cloud_operations": {
            "unresolved_count": (payload.get("cloud_operations") or {}).get(
                "unresolved_count", 0
            ),
            "unresolved_operation_ids": (payload.get("cloud_operations") or {}).get(
                "unresolved_operation_ids"
            )
            or [],
            "quarantined_hosts": (payload.get("cloud_operations") or {}).get(
                "quarantined_hosts"
            )
            or [],
        },
        "resources": _resource_summary(resources),
        "dashboard": {
            "model_version": dashboard.get("model_version") or DASHBOARD_MODEL_VERSION,
            "report_shape_version": dashboard.get("report_shape_version")
            or REPORT_MODEL_VERSION,
            "summary": {
                **_compact_dashboard_summary(dashboard.get("summary")),
                "result_counts": dict(Counter(row["status"] for row in result_rows)),
            },
            "evidence_entries": evidence_entries,
            "environment": {
                "cloud": environment.get("cloud"),
                "region_name": environment.get("region_name"),
                "project_name": environment.get("project_name"),
                "zones": environment.get("zones") or [],
                "host_count": environment.get("host_count", 0),
                "networks": [
                    _compact_network(network)
                    for network in (environment.get("networks") or [])
                ],
                "network_count": environment.get("network_count", 0),
                "subnet_count": environment.get("subnet_count", 0),
                "discovered_subnet_count": environment.get(
                    "discovered_subnet_count", 0
                ),
                "created_subnet_count": environment.get("created_subnet_count", 0),
                "endpoint_count": environment.get("endpoint_count", 0),
                "path_count": environment.get("path_count", len(paths)),
                "measured_path_count": environment.get("measured_path_count", 0),
                "address_families": environment.get("address_families") or [],
            },
            "findings": findings,
            "paths": paths,
            "results": result_rows,
            "suites": _suite_summary(result_rows),
            "coverage": _coverage_summary(payload, result_rows, paths),
            "host_scope": host_scope_summary(payload),
            "operator_overview": operator_overview({"results": result_rows}),
            "lifecycle_issues": lifecycle_explanations(payload),
            "events": [
                {
                    **event,
                    "title": _presentation_text(
                        event.get("title"), fallback="Recorded lifecycle event"
                    ),
                    "message": _presentation_text(event.get("message")),
                }
                for event in events
            ],
            "concurrent_load": _concurrent_load(payload),
        },
    }


__all__ = [
    "DASHBOARD_MODEL_VERSION",
    "REPORT_MODEL_VERSION",
    "build_report_payload",
    "enrich_findings",
]
