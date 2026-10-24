from __future__ import annotations

import csv
import io
import json
import re
from collections import Counter
from typing import Any

from .logical_results import logical_results
from .operator_explanations import (
    explain_result,
    explanation_lines,
    lifecycle_explanations,
    needs_attention,
    operator_overview,
)
from .replay_plan import RerunResolver, build_replay_plan
from .reporting_components.operator_context import contextual_results
from .reporting_components.report_payload import enrich_findings
from .result_context import normalize_topology_label
from .result_contract import typed_verdict
from .terminology import friendly_operator_text
from .test_names import test_name

_HOST_QUALIFICATION_FIELDS = (
    "pair_id",
    "cycle",
    "total_cycles",
    "source_host",
    "destination_host",
    "source_availability_zone",
    "destination_availability_zone",
    "relationship",
    "strategy",
    "profile",
    "test_id",
    "category",
    "status",
    "family",
    "source",
    "destination",
    "measurement",
    "confidence",
    "message",
    "metrics_json",
)


def _counted(count: int, singular: str, plural: str | None = None) -> str:
    return f"{count} {singular if count == 1 else plural or singular + 's'}"


def _qualification_confidence(result: dict[str, Any]) -> str:
    status = str(result.get("status") or "").upper()
    details = result.get("details") or {}
    if status in {"BLOCKED_BY_PREREQUISITE", "BLOCKED_BY_SETUP_ERROR"}:
        return "blocked"
    if status in {"UNVERIFIED", "NOT_RUN_CANCELLED"}:
        return "unverified"
    if status in {"SKIP", "NOT_APPLICABLE"}:
        return "not-measured"
    if (
        details.get("placement_method") == "nova-availability-zone-host"
        or details.get("host_qualification")
    ) and status in {"PASS", "FAIL", "ERROR"}:
        return "exact-placement-evidence"
    return "result-only"


def render_host_qualification_csv(payload: dict[str, Any]) -> str:
    """Render one stable, machine-readable row per host qualification result."""
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=_HOST_QUALIFICATION_FIELDS)
    writer.writeheader()
    for result in payload.get("results") or []:
        details = result.get("details") or {}
        pair_id = details.get("host_qualification_pair_id")
        if not pair_id:
            continue
        relationship = (
            "same-host"
            if details.get("same_host")
            else "same-az"
            if details.get("same_availability_zone")
            else "cross-az"
        )
        metrics = details.get("metrics")
        writer.writerow(
            {
                "pair_id": pair_id,
                "cycle": details.get("host_qualification_cycle"),
                "total_cycles": details.get("host_qualification_total_cycles"),
                "source_host": details.get("requested_source_host"),
                "destination_host": details.get("requested_destination_host"),
                "source_availability_zone": details.get("source_availability_zone"),
                "destination_availability_zone": details.get(
                    "destination_availability_zone"
                ),
                "relationship": relationship,
                "strategy": details.get("qualification_strategy"),
                "profile": details.get("qualification_profile"),
                "test_id": result.get("test_id"),
                "category": result.get("category"),
                "status": result.get("status"),
                "family": result.get("family"),
                "source": friendly_operator_text(
                    normalize_topology_label(result.get("source"))
                ),
                "destination": friendly_operator_text(
                    normalize_topology_label(result.get("destination"))
                ),
                "measurement": details.get("measurement"),
                "confidence": _qualification_confidence(result),
                "message": explain_result(result).get("recorded_message"),
                "metrics_json": (
                    json.dumps(
                        metrics,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    )
                    if isinstance(metrics, dict)
                    else ""
                ),
            }
        )
    return output.getvalue()


def _result_availability_zone(result: dict[str, Any]) -> str:
    details = result.get("details") or {}
    path = details.get("path") or {}
    source_zone = path.get("source_availability_zone") or details.get(
        "source_availability_zone"
    )
    destination_zone = path.get("destination_availability_zone") or details.get(
        "destination_availability_zone"
    )
    if source_zone and destination_zone and source_zone != destination_zone:
        return f"{source_zone} → {destination_zone}"
    if source_zone or destination_zone:
        return str(source_zone or destination_zone)
    for key in (
        "availability_zone",
        "source_availability_zone",
        "destination_availability_zone",
    ):
        value = str(details.get(key) or "").strip()
        if value:
            return value
    scope = str(details.get("execution_scope") or "").strip()
    if scope.startswith("az-") and len(scope) > 3:
        return scope[3:]
    match = re.match(
        r"^AZ-(.+?)-(?:CONTROL|SAME|PROJECT|STATIC|PERF|EGRESS|FIP|MTU|ROUTE|SECURITY|SERVER|SNAT|SOURCE|PLACEMENT|CONCURRENT)(?:-|$)",
        str(result.get("test_id") or ""),
        re.IGNORECASE,
    )
    return match.group(1).lower() if match else "run scope"


def _cleanup_scope_accounting_note(cleanup: dict[str, Any]) -> str | None:
    zones = cleanup.get("zones") or {}
    scoped = {
        str(scope): int((summary or {}).get("adopted_orphans") or 0)
        for scope, summary in zones.items()
        if int((summary or {}).get("adopted_orphans") or 0) > 0
    }
    if not scoped:
        return None
    scoped_total = sum(scoped.values())
    run_total = int(cleanup.get("adopted_orphans") or 0)
    scopes = ", ".join(f"{scope}={count}" for scope, count in sorted(scoped.items()))
    return (
        "Cleanup ownership/accounting anomaly: scoped cleanup summaries report "
        f"{_counted(scoped_total, 'adopted orphan record')} ({scopes}), while the run-level "
        f"adopted_orphans value is {run_total}. Treat this as historical tool cleanup "
        "evidence, not as a cloud-network failure."
    )


def _incident_actionable(result: dict[str, Any]) -> bool:
    details = result.get("details") or {}
    if details.get("tool_failure"):
        return False
    verdict = typed_verdict(result)
    if verdict in {"FAIL", "ERROR"}:
        return True
    if verdict != "UNVERIFIED":
        return False
    if details.get("dependent_on_incident_id"):
        return True
    expectation = str(result.get("expected") or "").lower()
    return (
        "observation" not in expectation and details.get("observation_only") is not True
    )


def _render_test_id_list(test_ids: list[str], *, limit: int = 12) -> str:
    if not test_ids:
        return "unavailable"
    displayed = ", ".join(f"`{test_id}`" for test_id in test_ids[:limit])
    remaining = len(test_ids) - limit
    if remaining > 0:
        displayed += (
            f", … (+{remaining} more; see the finding result_ids in results.json)"
        )
    return displayed


def _rerun_value(rerun: dict[str, Any]) -> tuple[str | None, str]:
    command = str(rerun.get("command") or "").strip()
    if command:
        return command, "Full-suite rerun command"
    for key, label in (
        ("exact_fragment", "Exact selection fragment"),
        ("parent_fragment", "Selectable parent fragment"),
        ("phase_fragment", "Phase selection fragment"),
    ):
        value = str(rerun.get(key) or "").strip()
        if value:
            return value, label
    return None, "Rerun limitation"


def render_incident_summary(payload: dict[str, Any]) -> str:
    """Render a concise hand-off note without embedding raw command evidence."""
    run = payload.get("run") or {}
    dashboard = payload.get("dashboard") or {}
    qualification = dashboard.get("host_qualification") or {}
    results = contextual_results(payload)
    checks = logical_results({**payload, "results": results})
    findings = [
        finding
        for finding in enrich_findings(
            payload,
            list(dashboard.get("findings") or []),
            list(results),
        )
        if str(finding.get("root_key") or "")
        not in {"neutron-flux-execution", "neutron-flux-controller-setup"}
    ]
    setup_failures = payload.get("setup_failures") or []
    adverse = [result for result in checks if _incident_actionable(result)]
    blocked = [
        result
        for result in checks
        if str(result.get("status") or "").upper()
        in {"BLOCKED_BY_SETUP_ERROR", "BLOCKED_BY_PREREQUISITE"}
    ]
    healthy_controller_zones = {
        _result_availability_zone(result)
        for result in results
        if str(result.get("status") or "").upper() == "PASS"
        and (
            str(result.get("scenario") or "").lower() == "controller readiness"
            or str(result.get("category") or "").lower()
            in {"control", "controller-bootstrap"}
        )
    }
    counts = Counter(str(result.get("status") or "UNKNOWN") for result in results)
    verdict_counts = Counter(typed_verdict(result) for result in results)
    cleanup = payload.get("cleanup") or {}
    replay_plan = build_replay_plan(payload)
    ledger = payload.get("planned_check_ledger") or []
    planned_counts = Counter(str(row.get("outcome") or "PENDING") for row in ledger)
    cleanup_only = str(run.get("action") or "").lower() == "cleanup"
    lines = [
        f"# Neutron Flux incident summary — {run.get('run_id') or 'unknown run'}",
        "",
        f"- Final status: **{run.get('final_status') or 'UNKNOWN'}**",
        f"- Finished: {run.get('finished_at') or 'not recorded'}",
        (
            f"- Planned checks: {len(ledger)} total; "
            + ", ".join(
                f"{status}={count}" for status, count in sorted(planned_counts.items())
            )
        )
        if ledger
        else "- Planned-check inventory: unavailable",
        (
            f"- Evidence records: {len(results)} total; "
            + ", ".join(f"{status}={count}" for status, count in sorted(counts.items()))
            if results
            else "- Network-test evidence: none recorded"
        ),
        (
            "- Evidence verdicts: "
            + ", ".join(
                f"{verdict}={count}"
                for verdict, count in sorted(verdict_counts.items())
            )
            if results
            else "- Network-test verdicts: not applicable to this cleanup action"
            if cleanup_only
            else "- Network-test verdicts: none recorded"
        ),
        (
            "- Cleanup: complete"
            if cleanup.get("complete") is True
            else "- Cleanup: requires review"
        ),
        f"- Replay plan: {replay_plan.get('status') or 'not generated'}; "
        f"{_counted(len(replay_plan.get('cases') or []), 'review case')}; "
        f"{_counted(replay_plan.get('command_count', 0), 'distinct suite command')}; "
        f"`{replay_plan.get('fingerprint') or 'no fingerprint'}`",
    ]
    if qualification.get("enabled"):
        pairs = qualification.get("pairs") or []
        completed = sum(
            1
            for pair in pairs
            if (pair.get("completed_cycles") or [])
            and pair.get("severity") not in {"blocked", "unverified"}
        )
        lines.extend(
            [
                (
                    f"- Host qualification: {completed}/{len(pairs)} pair rows "
                    f"produced measured evidence across "
                    f"{_counted(int(qualification.get('cycles') or 1), 'cycle')}"
                ),
                (
                    "- Inventory fingerprint: `"
                    + str(qualification.get("inventory_fingerprint") or "unavailable")
                    + "`"
                ),
            ]
        )
    if setup_failures:
        lines.extend(["", "## Tool or setup failures", ""])
        for item in setup_failures[:20]:
            lines.append("- " + str(item.get("message") or "Unknown setup failure"))
    cleanup_accounting_note = _cleanup_scope_accounting_note(cleanup)
    if cleanup_accounting_note:
        if not setup_failures:
            lines.extend(["", "## Tool or setup failures", ""])
        lines.append("- " + cleanup_accounting_note)

    lines.extend(["", "## What needs attention", ""])
    for group in operator_overview(payload)["groups"]:
        lines.append(f"- {group['count']}: {group['label']}")
    for issue in lifecycle_explanations(payload):
        lines.extend(
            [
                "",
                f"**{issue['headline']}**",
                issue["what_happened"],
                "Next check: " + issue["next_check"],
            ]
        )
    emitted_reruns: set[str] = set()
    lines.extend(["", "## Conditions requiring review", ""])
    if not findings and not adverse:
        lines.append(
            "This cleanup action did not run network tests. Its final status describes "
            "resource cleanup only; it does not establish network health."
            if cleanup_only
            else "No executed network contract produced a failed, errored, or unverified verdict."
        )
    else:
        for finding in findings[:20]:
            test_ids = [str(value) for value in finding.get("test_ids") or []]
            lines.extend(
                [
                    f"- **{finding.get('title') or 'Finding'}** — "
                    f"{finding.get('summary') or finding.get('message') or 'See report evidence.'}",
                    "  - Test IDs: " + _render_test_id_list(test_ids),
                    f"  - Impact: {finding.get('impact') or 'Review required.'}",
                    "  - Evidence: "
                    f"{finding.get('evidence_completeness') or 'Partial'} — "
                    f"{finding.get('evidence_summary') or 'See report evidence.'}",
                    f"  - Next check: {finding.get('next_check') or 'Review the affected tests.'}",
                ]
            )
            for rerun in finding.get("test_reruns") or []:
                result_id = str(rerun.get("result_id") or "unknown result")
                value, label = _rerun_value(rerun)
                if value and value not in emitted_reruns:
                    emitted_reruns.add(value)
                    lines.append(f"  - {label} for `{result_id}`: `{value}`")
                elif not value:
                    guidance = str(rerun.get("guidance") or "Exact rerun unavailable.")
                    key = f"guidance:{guidance}"
                    if key not in emitted_reruns:
                        emitted_reruns.add(key)
                        lines.append(
                            f"  - Rerun limitation for `{result_id}`: {guidance}"
                        )
        finding_result_ids = {
            str(result_id)
            for finding in findings
            for result_id in finding.get("result_ids") or []
        }
        reruns = RerunResolver(payload)
        for result in adverse[:50]:
            if (
                str(result.get("result_id") or result.get("test_id"))
                in finding_result_ids
            ):
                continue
            contract = result.get("contract") or {}
            signature = result.get("path_signature") or {}
            rerun = reruns.for_result(result)
            lines.append(
                f"- **{typed_verdict(result)} · "
                f"{contract.get('type') or 'untyped'} · "
                f"{test_name(result)}** — "
                f"{result.get('message') or 'No summary recorded.'} "
                f"Test ID: `{result.get('test_id') or 'unavailable'}`. "
                f"Path: `{signature.get('key') or 'unavailable'}`"
            )
            value, label = _rerun_value(rerun)
            if value and value not in emitted_reruns:
                emitted_reruns.add(value)
                lines.append(f"  - {label}: `{value}`")
            elif not value:
                guidance = str(rerun.get("guidance") or "Unavailable.")
                key = f"guidance:{guidance}"
                if key not in emitted_reruns:
                    emitted_reruns.add(key)
                    lines.append(f"  - Rerun limitation: {guidance}")
    attention = [result for result in results if needs_attention(result)]
    if attention:
        lines.extend(["", "## Per-check explanations", ""])
        for result in attention:
            lines.extend(
                ["", f"### {result.get('test_id')} · {result.get('status')}", ""]
            )
            lines.extend(explanation_lines(result, prefix=""))
    if blocked:
        lines.extend(["", "## Coverage blocked by setup or prerequisite", ""])
        grouped = Counter(
            (
                _result_availability_zone(result),
                str(result.get("status") or "UNKNOWN").upper(),
            )
            for result in blocked
        )
        for (zone, status), count in sorted(grouped.items()):
            if status == "BLOCKED_BY_SETUP_ERROR" and zone in healthy_controller_zones:
                label = "run-wide orchestration stopped after this zone's controller was already healthy"
            elif status == "BLOCKED_BY_SETUP_ERROR":
                label = "setup did not complete"
            else:
                label = "a prerequisite did not complete"
            lines.append(
                f"- **{zone}** — {_counted(count, 'downstream validation')} "
                f"did not run because {label}."
            )
    replay_cases = replay_plan.get("cases") or []
    if replay_cases:
        lines.extend(["", "## Selected review cases", ""])
        for case in replay_cases[:50]:
            rerun = case.get("rerun") or {}
            lines.append(
                f"- `{case.get('target_result_id')}` — "
                f"{case.get('contract_type') or 'untyped'}; "
                f"healthy control `{case.get('healthy_control_result_id') or 'unavailable'}`; "
                "host/AZ variations "
                + (
                    ", ".join(
                        f"`{value}`" for value in case.get("variation_result_ids") or []
                    )
                    or "unavailable"
                )
            )
            value, label = _rerun_value(rerun)
            if value and value not in emitted_reruns:
                emitted_reruns.add(value)
                lines.append(f"  - {label}: `{value}`")
            elif not value:
                guidance = str(rerun.get("guidance") or "Unavailable.")
                key = f"guidance:{guidance}"
                if key not in emitted_reruns:
                    emitted_reruns.add(key)
                    lines.append(f"  - Rerun limitation: {guidance}")
    qualification_reruns = {
        str(pair.get("rerun_fragment"))
        for pair in qualification.get("pairs") or []
        if pair.get("rerun_fragment")
        and pair.get("severity")
        in {"critical", "error", "blocked", "unverified", "warning"}
    }
    remaining_reruns = sorted(qualification_reruns - emitted_reruns)
    if remaining_reruns:
        lines.extend(["", "## Additional focused selectors", ""])
        lines.extend(f"- `{fragment}`" for fragment in remaining_reruns[:20])
    lines.extend(
        [
            "",
            "## Evidence files",
            "",
            "- `results.json` — canonical structured evidence",
            "- `report.html` — interactive dashboard",
            "- `host-qualification.csv` — normalized host/pair/cycle rows",
            "- `report.junit.xml` — CI result mapping when enabled",
            "- `replay-plan.json` — selected review cases and full-suite rerun commands",
            "- `replay-plan.txt` — human-readable review cases and rerun guidance",
            "",
        ]
    )
    return "\n".join(lines)


__all__ = [
    "render_host_qualification_csv",
    "render_incident_summary",
]
