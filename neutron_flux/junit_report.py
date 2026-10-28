from __future__ import annotations

import json
import pathlib
import re
import xml.etree.ElementTree as ET
from typing import Any

from .logical_results import logical_results
from .network_contract import canonical_category
from .operator_explanations import explain_result, explanation_lines
from .result_context import normalize_topology_label
from .result_contract import normalize_result_record, typed_verdict
from .results_io import atomic_write_text
from .terminology import (
    friendly_operator_text,
    friendly_scenario,
    friendly_title,
)

_INVALID_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")


def _clean(value: Any) -> str:
    return _INVALID_XML.sub("", str(value if value is not None else ""))


def _bounded(value: Any, limit: int = 2000) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _display_message(result: dict[str, Any]) -> str:
    if not result.get("message"):
        return ""
    return str(explain_result(result).get("recorded_message") or "")


def _compact_evidence(result: dict[str, Any]) -> dict[str, Any]:
    """Return a small pointer/excerpt; results.json owns complete evidence."""

    details = result.get("details") or {}
    probe = details.get("probe") or {}
    warning_reasons = details.get("warning_reasons") or []
    if not isinstance(warning_reasons, list):
        warning_reasons = [warning_reasons]
    output = {
        "operator_explanation": explain_result(result),
        "canonical_evidence": "results.json",
        "result_id": result.get("test_id") or result.get("result_id"),
        "message": _bounded(_display_message(result), 1000),
        "likely_failure": _bounded(result.get("likely_failure"), 500),
        "measurement": details.get("measurement"),
        "address_path": details.get("address_path"),
        "health": details.get("health"),
        "root_incident_id": details.get("root_incident_id"),
        "dependent_on_incident_id": details.get("dependent_on_incident_id"),
        "command": _bounded(probe.get("command") or details.get("command"), 1200),
        "stderr_excerpt": _bounded(probe.get("stderr") or details.get("stderr"), 1800),
        "warning_reasons": [
            text for value in warning_reasons[:4] if (text := _bounded(value, 500))
        ],
    }
    return {key: value for key, value in output.items() if value not in (None, "", [])}


def _property(parent: ET.Element, name: str, value: Any) -> None:
    if value is None:
        return
    ET.SubElement(parent, "property", name=_clean(name), value=_clean(value))


def build_junit(payload: dict[str, Any], *, include_evidence: bool = True) -> str:
    results = [
        normalize_result_record(item, share_evidence=True)
        for item in logical_results(payload)
    ]
    run = payload.get("run") or {}
    final_status = str(run.get("final_status") or "").upper()
    failures = sum(1 for item in results if typed_verdict(item) == "FAIL")
    errors = sum(1 for item in results if typed_verdict(item) == "ERROR")
    skipped = sum(
        1
        for item in results
        if typed_verdict(item) in {"UNVERIFIED", "BLOCKED", "INAPPLICABLE", "NOT_RUN"}
    )
    lifecycle_kind: str | None = None
    if final_status in {
        "SETUP FAILED",
        "PARTIAL",
        "INCOMPLETE",
        "CLEANUP INCOMPLETE",
        "INTERRUPTED",
    }:
        lifecycle_kind = "error"
    elif final_status == "CANCELLED":
        lifecycle_kind = "skipped"
    elif final_status == "ERROR" and errors == 0:
        lifecycle_kind = "error"
    elif final_status == "FAIL" and failures == 0:
        lifecycle_kind = "failure"
    if lifecycle_kind == "error":
        errors += 1
    elif lifecycle_kind == "failure":
        failures += 1
    elif lifecycle_kind == "skipped":
        skipped += 1
    total_time = sum(float(item.get("duration_ms") or 0) for item in results) / 1000.0
    suite = ET.Element(
        "testsuite",
        name="neutron-flux",
        tests=str(len(results) + (1 if lifecycle_kind else 0)),
        failures=str(failures),
        errors=str(errors),
        skipped=str(skipped),
        time=f"{total_time:.6f}",
        timestamp=_clean(run.get("started_at") or ""),
        hostname=_clean(run.get("run_id") or "neutron-flux"),
    )
    suite_properties = ET.SubElement(suite, "properties")
    _property(suite_properties, "run_id", run.get("run_id"))
    _property(suite_properties, "final_status", run.get("final_status"))
    _property(suite_properties, "tool_version", payload.get("tool_version"))
    _property(suite_properties, "canonical_evidence_file", "results.json")
    _property(
        suite_properties,
        "cleanup_complete",
        (payload.get("cleanup") or {}).get("complete"),
    )
    cloud_operations = payload.get("cloud_operations") or {}
    _property(
        suite_properties,
        "unresolved_cloud_operations",
        cloud_operations.get("unresolved_count", 0),
    )
    _property(
        suite_properties,
        "quarantined_hosts",
        ",".join(cloud_operations.get("quarantined_hosts") or []),
    )

    for result in results:
        details = result.get("details") or {}
        contract = result.get("contract") or {}
        path_signature = result.get("path_signature") or {}
        expectation = contract.get("expectation") or {}
        authority = contract.get("authority") or {}
        migration_attempts = (
            details.get("migration_attempts") or details.get("attempts") or []
        )
        if not isinstance(migration_attempts, list):
            migration_attempts = []
        last_attempt = (
            migration_attempts[-1]
            if migration_attempts and isinstance(migration_attempts[-1], dict)
            else {}
        )
        execution_scope = details.get("execution_scope") or details.get(
            "availability_zone"
        )
        class_name = canonical_category(result.get("category") or "neutron-flux")
        if execution_scope:
            class_name = f"{class_name}.{execution_scope}"
        case = ET.SubElement(
            suite,
            "testcase",
            classname=_clean(class_name),
            # Test IDs are globally unique, including scoped multi-AZ runs.
            # Keep the friendly display name as a property instead of using it
            # as the JUnit identity where CI dashboards may collapse duplicates.
            name=_clean(
                result.get("test_id") or result.get("display_name") or "unnamed"
            ),
            time=f"{float(result.get('duration_ms') or 0) / 1000.0:.6f}",
        )
        properties = ET.SubElement(case, "properties")
        for name in (
            "test_id",
            "family",
            "source",
            "destination",
            "expected",
            "observed",
            "authoritative",
            "scenario",
        ):
            value = result.get(name)
            if name == "scenario":
                value = friendly_scenario(value)
            elif name in {"source", "destination"}:
                value = friendly_operator_text(normalize_topology_label(value))
            _property(properties, name, value)
        _property(properties, "contract_type", contract.get("type"))
        _property(properties, "contract_verdict", typed_verdict(result))
        _property(
            properties,
            "expectation_source",
            (expectation.get("source") or {}).get("classification"),
        )
        _property(
            properties,
            "authority_classification",
            authority.get("classification"),
        )
        _property(properties, "semantic_path_key", path_signature.get("key"))
        _property(
            properties,
            "display_name",
            friendly_title(normalize_topology_label(result.get("display_name"))),
        )
        _property(properties, "execution_scope", execution_scope)
        _property(properties, "health", details.get("health"))
        _property(properties, "performance", details.get("performance"))
        _property(
            properties,
            "cloud_operation_outcome",
            details.get("cloud_operation_outcome")
            or last_attempt.get("cloud_operation_outcome"),
        )
        _property(
            properties,
            "retry_performed_after_proven_failure",
            any(
                isinstance(item, dict)
                and item.get("retry_performed_after_proven_failure") is True
                for item in migration_attempts
            ),
        )
        _property(
            properties,
            "host_quarantined",
            details.get("host_quarantined"),
        )

        status = str(result.get("status") or "ERROR")
        verdict = typed_verdict(result)
        message = _clean(_display_message(result) or status)
        if verdict == "FAIL":
            node = ET.SubElement(
                case, "failure", message=message, type="contract-violation"
            )
            node.text = _clean("\n".join(explanation_lines(result, prefix="")))
        elif verdict == "ERROR":
            node = ET.SubElement(case, "error", message=message, type="execution-error")
            node.text = _clean("\n".join(explanation_lines(result, prefix="")))
        elif verdict in {"UNVERIFIED", "BLOCKED", "INAPPLICABLE", "NOT_RUN"}:
            node = ET.SubElement(case, "skipped", message=message)
            node.text = _clean("\n".join(explanation_lines(result, prefix="")))

        if include_evidence:
            output = ET.SubElement(case, "system-out")
            output.text = _clean(
                json.dumps(
                    _compact_evidence(result),
                    separators=(",", ":"),
                    sort_keys=True,
                    allow_nan=False,
                )
            )

    if lifecycle_kind:
        cleanup = payload.get("cleanup") or {}
        setup_failures = payload.get("setup_failures") or []
        reasons: list[str] = []
        if payload.get("error"):
            reasons.append(str(payload.get("error")))
        for item in setup_failures:
            if isinstance(item, dict) and item.get("message"):
                reasons.append(str(item.get("message")))
        for item in cleanup.get("leftovers") or []:
            reasons.append(f"cleanup leftover: {item}")
        for item in cleanup.get("errors") or []:
            reasons.append(f"cleanup error: {item}")
        for operation_id in cloud_operations.get("unresolved_operation_ids") or []:
            reasons.append(f"unresolved cloud operation: {operation_id}")
        message = "; ".join(dict.fromkeys(reasons)) or f"Run ended with {final_status}"
        case = ET.SubElement(
            suite,
            "testcase",
            classname="neutron-flux.lifecycle",
            name="RUN-FINAL-STATUS",
            time="0.000000",
        )
        properties = ET.SubElement(case, "properties")
        _property(properties, "final_status", final_status)
        lifecycle_type = (
            "run-lifecycle-error"
            if lifecycle_kind == "error"
            else "run-cancelled"
            if lifecycle_kind == "skipped"
            else "run-failure"
        )
        node = ET.SubElement(
            case,
            lifecycle_kind,
            message=_clean(message),
            type=lifecycle_type,
        )
        node.text = _clean(message)

    if payload.get("error"):
        error_output = ET.SubElement(suite, "system-err")
        error_output.text = _clean(payload.get("error"))
    ET.indent(suite, space="  ")
    return ET.tostring(suite, encoding="unicode", xml_declaration=True) + "\n"


def write_junit(
    payload: dict[str, Any],
    path: pathlib.Path,
    *,
    include_evidence: bool = True,
) -> pathlib.Path:
    atomic_write_text(path, build_junit(payload, include_evidence=include_evidence))
    return path


__all__ = ["build_junit", "write_junit"]
