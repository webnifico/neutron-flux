from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, fields, is_dataclass
from typing import Any

# mypy: disable-error-code="attr-defined"
from ..check_ledger import check_ledger
from ..constants import DISPLAY_VERSION
from ..logical_results import logical_results
from ..models import TestResult
from ..operator_explanations import (
    explain_result,
    explanation_lines,
    migration_interruption_observations,
    needs_attention,
    operator_overview,
)
from ..progress import reporter_progress
from ..scheduling import timing_summary
from ..terminology import (
    category_label,
    friendly_operator_text,
)
from ..test_names import execution_name
from .attention_summary import (
    attention_summary,
    attention_summary_lines,
    attention_summary_parts,
)
from .operator_context import contextual_results, endpoint_zones


class SummaryRendererMixin:
    """Human-readable summary rendering without manifest changes."""

    def _presentation_results(self) -> dict[str, dict[str, Any]]:
        """Join plan and sibling evidence once for this summary snapshot."""
        plan = getattr(self, "plan", None)
        qualification = getattr(plan, "host_qualification", {}) or {}
        if is_dataclass(qualification) and not isinstance(qualification, type):
            qualification = asdict(qualification)
        specs = [
            asdict(spec) if is_dataclass(spec) else dict(spec)
            for spec in getattr(plan, "tests", []) or []
            if isinstance(spec, dict)
            or (is_dataclass(spec) and not isinstance(spec, type))
        ]
        rows = contextual_results(
            {
                "results": [
                    {field.name: getattr(item, field.name) for field in fields(item)}
                    for item in self.results
                ],
                "resources": [
                    asdict(item) if is_dataclass(item) else dict(item)
                    for item in getattr(self, "resources", []) or []
                    if isinstance(item, dict)
                    or (is_dataclass(item) and not isinstance(item, type))
                ],
                "plan": {
                    "tests": specs,
                    "checks": [
                        asdict(check) if is_dataclass(check) else dict(check)
                        for check in getattr(plan, "checks", []) or []
                        if isinstance(check, dict)
                        or (is_dataclass(check) and not isinstance(check, type))
                    ],
                    "host_qualification": qualification,
                },
            }
        )
        return {row["test_id"]: row for row in rows}

    def _presentation_result(self, item: TestResult) -> dict[str, Any]:
        """Project one live row without serializing unrelated saved evidence."""
        plan = getattr(self, "plan", None)
        references = {
            item.test_id,
            (item.details.get("path") or {}).get("source_spec_id"),
            item.details.get("transition_check_id"),
            item.details.get("planned_check_id"),
        } - {None, ""}
        plan_specs = getattr(plan, "tests", []) or []
        selected_specs = []
        for spec in plan_specs:
            if not is_dataclass(spec) or isinstance(spec, type):
                continue
            binding = (getattr(spec, "metadata", {}) or {}).get("check_bindings") or {}
            linked = {
                *(binding.get("placement") or {}).values(),
                binding.get("post-migration"),
            }
            if getattr(spec, "id", None) in references or references.intersection(
                linked
            ):
                selected_specs.append(spec)
        source_spec = next(
            (spec for spec in selected_specs if spec.id == item.test_id),
            next(
                (
                    spec
                    for spec in selected_specs
                    if spec.id == (item.details.get("path") or {}).get("source_spec_id")
                ),
                None,
            ),
        )
        metadata = getattr(source_spec, "metadata", {}) or {}
        scope = (
            metadata.get("workflow_batch"),
            metadata.get("host_qualification_pair_id"),
            metadata.get("host_qualification_cycle"),
        )
        if all(scope):
            for spec in plan_specs:
                context = getattr(spec, "metadata", {}) or {}
                if getattr(spec, "operation", None) == "pair-transition" and scope == (
                    context.get("workflow_batch"),
                    context.get("host_qualification_pair_id"),
                    context.get("host_qualification_cycle"),
                ):
                    references.add(spec.id)
                    if spec not in selected_specs:
                        selected_specs.append(spec)
        selected = {item.test_id: item}
        records = getattr(self, "results_by_id", None)
        if (
            not isinstance(records, dict)
            or len(records) != len(self.results)
            or records.get(item.test_id) is not item
        ):
            # Compatibility callers can install a captured list directly or
            # provide a minimal reporter without the live journal index.
            records = {row.test_id: row for row in self.results}
        for identity in references:
            if identity in records:
                selected[identity] = records[identity]
        endpoint_ids = {
            item.details.get(f"{role}_server_id")
            or ((item.details.get("address_path") or {}).get(role) or {}).get(
                "server_id"
            )
            for role in ("source", "destination")
        } - {None}
        owner_context = (
            item.category == "egress"
            or item.details.get("nat_path") == "self-hairpin"
            or item.details.get("packet_path_placement") == "self"
        )
        if owner_context:
            for row in self.results:
                if row.category != "compute-placement":
                    continue
                for transition in row.details.get("transitions") or []:
                    monitor = (
                        transition.get("continuity_assessment")
                        or (transition.get("details") or {}).get("continuity")
                        or {}
                    )
                    if endpoint_ids.intersection(
                        {
                            transition.get("server_id"),
                            monitor.get("stationary_server_id"),
                        }
                    ):
                        selected[row.test_id] = row
        monitors = []
        moving_ids = set()
        for row in list(selected.values()):
            for round_ in row.details.get("rounds") or []:
                references.update(round_.get("test_ids") or [])
            if (
                row is not item
                and not owner_context
                and item.category != "compute-placement"
            ):
                # An ordinary row needs the transition method, not its sibling
                # transition's monitored-path or VM-label presentation.
                continue
            transitions = row.details.get("transitions") or (
                [row.details] if row.details.get("server_id") else []
            )
            for transition in transitions:
                if transition.get("server_id"):
                    moving_ids.add(transition["server_id"])
                monitor = (
                    transition.get("continuity_assessment")
                    or (transition.get("details") or {}).get("continuity")
                    or {}
                )
                if monitor.get("observer_server_id") and monitor.get(
                    "target_server_id"
                ):
                    monitors.append(monitor)
        found_monitors = set()
        found_labels = set()
        for identity in references:
            if identity in records:
                selected[identity] = records[identity]
        for row in self.results if monitors or moving_ids else []:
            addresses = row.details.get("address_path") or {}
            source, destination = (
                addresses.get("source") or {},
                addresses.get("destination") or {},
            )
            for index, monitor in enumerate(monitors):
                if index not in found_monitors and (
                    source.get("server_id") == monitor["observer_server_id"]
                    and destination.get("server_id") == monitor["target_server_id"]
                    and source.get("probe_address") == monitor.get("source_ip")
                    and destination.get("probe_address")
                    == monitor.get("destination_ip")
                ):
                    selected[row.test_id] = row
                    found_monitors.add(index)
            for server_id in moving_ids - found_labels:
                if server_id in {source.get("server_id"), destination.get("server_id")}:
                    selected[row.test_id] = row
                    found_labels.add(server_id)
        qualification = getattr(plan, "host_qualification", {}) or {}
        if is_dataclass(qualification) and not isinstance(qualification, type):
            qualification = asdict(qualification)
        projected = contextual_results(
            {
                # These dictionaries are consumed synchronously by read-only
                # presentation joins; copying continuity sample trees would make
                # each emitted line repeat the cost of previous measurements.
                "results": [
                    {field.name: getattr(row, field.name) for field in fields(row)}
                    for row in selected.values()
                ],
                "plan": {
                    "tests": [asdict(spec) for spec in selected_specs],
                    "checks": [
                        asdict(check) if is_dataclass(check) else dict(check)
                        for check in getattr(plan, "checks", []) or []
                        if isinstance(check, dict)
                        or (is_dataclass(check) and not isinstance(check, type))
                    ],
                    "host_qualification": qualification,
                },
                "resources": [
                    asdict(resource)
                    for resource in getattr(self, "resources", []) or []
                    if getattr(resource, "id", None) in moving_ids
                ],
            }
        )
        return next(row for row in projected if row["test_id"] == item.test_id)

    def _primary_summary_results(self) -> list[TestResult]:
        if not getattr(getattr(self, "plan", None), "checks", None):
            return list(self.results)
        if (
            not hasattr(self, "_lock")
            or not hasattr(self.plan, "tests")
            or any(not isinstance(item, TestResult) for item in self.results)
        ):
            # Minimal category-only callers have no journal/complete ledger to
            # join. Preserve their supported duck-typed result-count interface.
            return [
                item
                for item in self.results
                if not (item.details or {}).get("check_sample")
            ]
        rows = logical_results(
            {
                "results": [
                    {field.name: getattr(item, field.name) for field in fields(item)}
                    for item in self.results
                ],
                "planned_check_ledger": check_ledger(self),
            }
        )
        names = {field.name for field in fields(TestResult)}
        return [
            TestResult(
                **{
                    "family": None,
                    "source": None,
                    "destination": None,
                    "started_at": "",
                    "duration_ms": 0,
                    **{key: value for key, value in row.items() if key in names},
                }
            )
            for row in rows
        ]

    def _category_summary(self) -> dict[str, Counter[str]]:
        grouped: dict[str, Counter[str]] = defaultdict(Counter)
        for result in self._primary_summary_results():
            grouped[result.category][result.status] += 1
            if self._is_performance_warning(result):
                grouped[result.category]["HEALTH_WARNING"] += 1
        return dict(sorted(grouped.items()))

    @staticmethod
    def _is_performance_warning(result: TestResult) -> bool:
        return result.status == "PASS" and needs_attention(
            {"status": result.status, "details": result.details or {}}
        )

    def _performance_warning_count(self) -> int:
        return sum(
            1
            for item in self._primary_summary_results()
            if self._is_performance_warning(item)
        )

    def _attention_summary_counts(self) -> Counter[str]:
        return attention_summary(
            {
                "results": [
                    {field.name: getattr(item, field.name) for field in fields(item)}
                    for item in self._primary_summary_results()
                ]
            }
        )

    @staticmethod
    def _category_verdict(counts: Counter[str]) -> str:
        failed = counts.get("FAIL", 0)
        errors = counts.get("ERROR", 0)
        passed = counts.get("PASS", 0)
        unverified = counts.get("UNVERIFIED", 0)
        not_run = (
            counts.get("SKIP", 0)
            + counts.get("BLOCKED_BY_SETUP_ERROR", 0)
            + counts.get("BLOCKED_BY_PREREQUISITE", 0)
            + counts.get("NOT_RUN_CANCELLED", 0)
        )
        if failed and errors:
            return "FAILED / ERROR"
        if failed:
            return "FAILED"
        if errors:
            return "ERROR"
        if unverified:
            return "PASS WITH WARNINGS" if passed else "UNVERIFIED"
        if counts.get("HEALTH_WARNING", 0) and passed:
            return "PASS WITH WARNINGS"
        if passed and not_run:
            return "PASS WITH GAPS"
        if passed:
            return "PASS"
        if not_run:
            return "NOT RUN"
        if counts.get("NOT_APPLICABLE", 0):
            return "NOT APPLICABLE"
        return "NO RESULTS"

    @staticmethod
    def _category_label(category: str) -> str:
        return category_label(category)

    def _known_availability_zones(self) -> list[str]:
        zones = {
            str(zone).strip()
            for zone in getattr(self.config, "availability_zones", []) or []
            if str(zone).strip()
        }
        if self.plan is not None:
            for spec in self.plan.tests:
                metadata = getattr(spec, "metadata", {}) or {}
                zone = str(metadata.get("availability_zone") or "").strip()
                if zone:
                    zones.add(zone)
                for key in (
                    "source_availability_zone",
                    "destination_availability_zone",
                ):
                    value = str(metadata.get(key) or "").strip()
                    if value:
                        zones.add(value)
        for result in self._primary_summary_results():
            details = result.details or {}
            for key in (
                "availability_zone",
                "source_availability_zone",
                "destination_availability_zone",
            ):
                value = str(details.get(key) or "").strip()
                if value:
                    zones.add(value)
        return sorted(zones, key=lambda value: (-len(value), value))

    def _result_availability_zone(self, result: TestResult) -> str | None:
        details = result.details or {}
        zone = str(details.get("availability_zone") or "").strip()
        if zone:
            return zone
        source_zone, destination_zone = endpoint_zones(details)
        if source_zone and source_zone == destination_zone:
            return source_zone
        if bool(source_zone) != bool(destination_zone):
            return source_zone or destination_zone
        execution_scope = str(details.get("execution_scope") or "").strip()
        for candidate in self._known_availability_zones():
            if execution_scope == f"az-{candidate}":
                return candidate
            if result.test_id.upper().startswith(f"AZ-{candidate.upper()}-"):
                return candidate
        if self.plan is not None:
            spec = next(
                (
                    item
                    for item in self.plan.tests
                    if getattr(item, "id", None) == result.test_id
                ),
                None,
            )
            metadata = getattr(spec, "metadata", {}) or {}
            zone = str(metadata.get("availability_zone") or "").strip()
            if zone:
                return zone
        return None

    def _append_zone_summary(self, lines: list[str], width: int) -> None:
        per_zone: dict[str, Counter[str]] = defaultdict(Counter)
        cross_pairs: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
        for result in self._primary_summary_results():
            details = result.details or {}
            source_zone, destination_zone = endpoint_zones(details)
            if source_zone and destination_zone and source_zone != destination_zone:
                counts = cross_pairs[(str(source_zone), str(destination_zone))]
                counts[result.status] += 1
                if self._is_performance_warning(result):
                    counts["HEALTH_WARNING"] += 1
                continue
            zone = self._result_availability_zone(result)
            counts = per_zone[zone or "Run scope / AZ not recorded"]
            counts[result.status] += 1
            if self._is_performance_warning(result):
                counts["HEALTH_WARNING"] += 1
        if per_zone:
            lines.extend(
                [
                    "",
                    "AVAILABILITY-ZONE RESULTS",
                    "-" * width,
                    f"{'Availability zone':<34} {'Verdict':<22} {'Pass':>6} {'Fail':>6} {'Unverified':>11} {'Errors':>7} {'N/A':>5} {'Not run':>8} {'Total':>7}",
                    "-" * width,
                ]
            )
            for zone in sorted(per_zone):
                counts = per_zone[zone]
                not_run = (
                    counts.get("SKIP", 0)
                    + counts.get("BLOCKED_BY_SETUP_ERROR", 0)
                    + counts.get("BLOCKED_BY_PREREQUISITE", 0)
                    + counts.get("NOT_RUN_CANCELLED", 0)
                )
                execution_errors = counts.get("ERROR", 0)
                lines.append(
                    f"{zone:<34.34} {self._category_verdict(counts):<22.22} "
                    f"{counts.get('PASS', 0):>6} {counts.get('FAIL', 0):>6} "
                    f"{counts.get('UNVERIFIED', 0):>11} {execution_errors:>7} "
                    f"{counts.get('NOT_APPLICABLE', 0):>5} {not_run:>8} "
                    f"{sum(value for status, value in counts.items() if status != 'HEALTH_WARNING'):>7}"
                )
        if cross_pairs:
            lines.extend(
                [
                    "",
                    "CROSS-ZONE RESULTS",
                    "-" * width,
                    f"{'Source AZ':<24} {'Destination AZ':<24} {'Verdict':<22} {'Pass':>6} {'Fail':>6} {'Unverified':>11} {'Errors':>7} {'N/A':>5} {'Total':>7}",
                    "-" * width,
                ]
            )
            for (source_zone, destination_zone), counts in sorted(cross_pairs.items()):
                execution_errors = counts.get("ERROR", 0)
                lines.append(
                    f"{source_zone:<24.24} {destination_zone:<24.24} "
                    f"{self._category_verdict(counts):<22.22} "
                    f"{counts.get('PASS', 0):>6} {counts.get('FAIL', 0):>6} "
                    f"{counts.get('UNVERIFIED', 0):>11} {execution_errors:>7} "
                    f"{counts.get('NOT_APPLICABLE', 0):>5} "
                    f"{sum(value for status, value in counts.items() if status != 'HEALTH_WARNING'):>7}"
                )

    def _append_category_summary(self, lines: list[str], width: int) -> None:
        categories = self._category_summary()
        if not categories:
            return
        lines.extend(
            [
                "",
                "CATEGORY RESULTS",
                "-" * width,
                (
                    f"{'Category':<42} {'Verdict':<22} {'Pass':>5} {'Fail':>5} "
                    f"{'Unverified':>10} {'Errors':>6} {'N/A':>5} {'Not run':>7} {'Total':>6}"
                ),
                "-" * width,
            ]
        )
        for category, category_counts in categories.items():
            not_run = (
                category_counts.get("SKIP", 0)
                + category_counts.get("BLOCKED_BY_SETUP_ERROR", 0)
                + category_counts.get("BLOCKED_BY_PREREQUISITE", 0)
                + category_counts.get("NOT_RUN_CANCELLED", 0)
            )
            execution_errors = category_counts.get("ERROR", 0)
            total = sum(
                value
                for status, value in category_counts.items()
                if status != "HEALTH_WARNING"
            )
            lines.append(
                f"{self._category_label(category):<42.42} "
                f"{self._category_verdict(category_counts):<22.22} "
                f"{category_counts.get('PASS', 0):>5} "
                f"{category_counts.get('FAIL', 0):>5} "
                f"{category_counts.get('UNVERIFIED', 0):>10} "
                f"{execution_errors:>6} "
                f"{category_counts.get('NOT_APPLICABLE', 0):>5} "
                f"{not_run:>7} "
                f"{total:>6}"
            )
        lines.append(
            "Executed tests receive PASS, FAIL, UNVERIFIED or ERROR verdicts. N/A means the check does not apply; tests prevented from running are shown separately."
        )

    def _append_detailed_category_results(
        self,
        lines: list[str],
        width: int,
        presentations: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        primary_results = self._primary_summary_results()
        if not self.results and not primary_results:
            return
        if presentations is None:
            presentations = self._presentation_results()
        compact_blocked = (
            sum(
                1
                for item in primary_results
                if item.status in {"BLOCKED_BY_SETUP_ERROR", "BLOCKED_BY_PREREQUISITE"}
            )
            > 20
        )
        compact_cancelled = (
            sum(1 for item in primary_results if item.status == "NOT_RUN_CANCELLED")
            > 20
        )
        grouped: dict[str, list[TestResult]] = defaultdict(list)
        primary_by_id = {item.test_id: item for item in primary_results}
        for result in self.results:
            grouped[result.category].append(primary_by_id.get(result.test_id, result))
        recorded_ids = {item.test_id for item in self.results}
        for result in primary_results:
            if result.test_id not in recorded_ids:
                grouped[result.category].append(result)
        primary_ids = set(primary_by_id)
        lines.extend(["", "DETAILED RESULTS BY CATEGORY", "-" * width])
        if compact_blocked:
            blocked_groups: Counter[tuple[str, str, str, str]] = Counter()
            for item in self.results:
                if item.status not in {
                    "BLOCKED_BY_SETUP_ERROR",
                    "BLOCKED_BY_PREREQUISITE",
                }:
                    continue
                details = item.details or {}
                blocked_groups[
                    (
                        item.status,
                        self._result_availability_zone(item)
                        or str(details.get("execution_scope") or "run scope"),
                        str(details.get("root_setup_result_id") or "").strip(),
                        friendly_operator_text(item.message),
                    )
                ] += 1
            for (status, scope, root_result_id, reason), count in sorted(
                blocked_groups.items(),
                key=lambda row: (row[0][1], row[0][0], row[0][2], row[0][3]),
            ):
                root = f"; root {root_result_id}" if root_result_id else ""
                lines.append(
                    f"  {self._display_status(status)} | "
                    f"{self._human_count(count, 'validation')} in {scope}{root} | "
                    f"{reason}"
                )
            lines.append(
                "  Individual blocked rows remain available in results.json and "
                "the visual report."
            )
        if compact_cancelled:
            cancelled_reasons = Counter(
                friendly_operator_text(item.message)
                for item in self.results
                if item.status == "NOT_RUN_CANCELLED"
            )
            for reason, count in cancelled_reasons.most_common():
                lines.append(
                    f"  NOT RUN — CANCELLED | "
                    f"{self._human_count(count, 'validation')} | {reason}"
                )
            lines.append(
                "  Individual cancellation rows remain available in results.json "
                "and the visual report."
            )
        for category in sorted(grouped):
            results = grouped[category]
            tests = [item for item in results if item.test_id in primary_ids]
            supporting_count = len(results) - len(tests)
            category_counts = Counter(item.status for item in tests)
            category_counts["HEALTH_WARNING"] = sum(
                1 for item in tests if self._is_performance_warning(item)
            )
            lines.extend(
                [
                    "",
                    (
                        f"{self._category_label(category)} — "
                        f"{self._category_verdict(category_counts)} — "
                        f"{self._human_count(len(tests), 'test')}"
                        + (
                            f"; {self._human_count(supporting_count, 'supporting record')}"
                            if supporting_count
                            else ""
                        )
                    ),
                    "." * width,
                ]
            )
            visible_results = [
                item
                for item in results
                if not (
                    (
                        compact_blocked
                        and item.status
                        in {"BLOCKED_BY_SETUP_ERROR", "BLOCKED_BY_PREREQUISITE"}
                    )
                    or (compact_cancelled and item.status == "NOT_RUN_CANCELLED")
                )
            ]
            for item in visible_results:
                lines.append("")
                lines.extend(
                    "  " + line
                    for line in self._summary_result_lines(
                        item, presentation=presentations.get(item.test_id)
                    )
                )

    @staticmethod
    def _human_count(count: int, singular: str, plural: str | None = None) -> str:
        return f"{count} {singular if count == 1 else (plural or singular + 's')}"

    @staticmethod
    def _display_status(status: str) -> str:
        return {
            "BLOCKED_BY_SETUP_ERROR": "NOT RUN — SETUP ERROR",
            "BLOCKED_BY_PREREQUISITE": "NOT RUN — PREREQUISITE",
            "NOT_RUN_CANCELLED": "NOT RUN — CANCELLED",
            "NOT_APPLICABLE": "NOT APPLICABLE",
            "SKIP": "NOT RUN — UNSUPPORTED",
        }.get(status, status.replace("_", " "))

    @staticmethod
    def _display_expectation(expectation: str) -> str:
        return {
            "observation": "measured behavior",
            "reachable": "reachable",
            "blocked": "blocked",
            "withdrawn": "blocked after removal",
            "restored": "reachable after restoration",
            "not-applicable": "not applicable",
            "placement-known": "compute placement visible",
            "placement-achieved": "requested compute placement achieved",
            "bound-to-destination": "ports bound to the destination compute host",
            "endpoint-ready": "migrated endpoint networking restored",
        }.get(expectation, expectation.replace("-", " "))

    @staticmethod
    def _display_observation(observed: str) -> str:
        return {
            "inconclusive": "could not verify",
            "not-run": "not run",
            "setup-error": "not run because setup failed",
            "placement-hidden": "compute placement was not visible",
            "placement-unavailable": "requested placement could not be created",
            "migration-failed": "migration failed",
            "wrong-placement": "migration completed on the wrong placement",
            "migrated-and-confirmed": "migrated and confirmed",
            "bound-to-destination": "bound to the destination compute host",
            "binding-invalid": "destination port binding invalid",
            "endpoint-ready": "endpoint networking restored",
            "endpoint-unavailable": "endpoint networking unavailable",
            "binding-host-hidden": "destination binding host was hidden",
        }.get(observed, observed.replace("-", " "))

    def _overall_result_line(self, final_status: str, counts: Counter[str]) -> str:
        if self.plan and self.plan.checks and self.action == "run":
            outcomes = reporter_progress(self)["outcomes"]
            counts = Counter(
                {
                    "PASS": outcomes.get("PASSED", 0),
                    "FAIL": outcomes.get("FAILED", 0),
                    "ERROR": outcomes.get("ERROR", 0),
                    "UNVERIFIED": outcomes.get("UNVERIFIED", 0),
                }
            )
        parts = [
            f"{counts.get('PASS', 0)} passed",
            f"{counts.get('FAIL', 0)} failed",
            f"{counts.get('UNVERIFIED', 0)} unverified",
        ]
        tool_errors = sum(
            1
            for item in self.results
            if item.status == "ERROR" and bool((item.details or {}).get("tool_failure"))
        )
        validation_errors = max(0, counts.get("ERROR", 0) - tool_errors)
        if validation_errors:
            parts.append(f"{validation_errors} validation execution errors")
        if tool_errors:
            parts.append(f"{tool_errors} tool/setup error records")
        parts.extend(attention_summary_parts(self._attention_summary_counts()))
        return f"{final_status} — {', '.join(parts)}"

    def _summary(self, final_status: str, finished: Any, counts: Counter[str]) -> str:
        presentations = self._presentation_results()
        width = self.SUMMARY_WIDTH
        rule = "=" * width
        duration = max(0.0, (finished - self.started).total_seconds())
        cleanup_complete = self.cleanup_summary.get("complete")
        if self.action == "plan":
            cleanup_text = "not required; planning created no cloud resources"
        elif cleanup_complete is True:
            delayed_count = len(self.cleanup_summary.get("delayed_groups") or [])
            sweep = self.cleanup_summary.get("orphan_sweep") or {}
            protected = int(sweep.get("protected_resources_remaining") or 0)
            cleanup_text = (
                f"complete for eligible scope; {self.cleanup_summary.get('deleted', 0)} explicit delete operations completed"
                + (
                    f"; {protected} active-run resource(s) protected"
                    if protected
                    else ""
                )
                + (
                    f"; {delayed_count} delayed group cleanup(s) recovered"
                    if delayed_count
                    else ""
                )
            )
        elif cleanup_complete is False:
            leftovers = len(self.cleanup_summary.get("leftovers", []))
            cleanup_text = (
                f"INCOMPLETE; {leftovers} unresolved cleanup or verification issues"
            )
        elif self.cleanup_summary.get("interrupted"):
            deleted = int(
                self.cleanup_summary.get(
                    "confirmed_deleted_count", self.cleanup_summary.get("deleted")
                )
                or 0
            )
            unverified = int(self.cleanup_summary.get("unverified_resource_count") or 0)
            cleanup_text = (
                f"INTERRUPTED; {deleted} resource(s) confirmed absent; {unverified} "
                "tracked resource(s) unverified; rerun cleanup for this run"
            )
        elif self.cleanup_summary.get("attempted"):
            cleanup_text = "attempted; final state unknown"
        else:
            cleanup_text = "not required for this action"

        selection_mode = (
            self.plan.selection_mode
            if self.plan is not None
            else "exact"
            if self.config.test_ids
            else "all"
        )
        if selection_mode == "exact":
            requested_count = (
                len(self.plan.requested_test_ids)
                if self.plan is not None
                else len(self.config.test_ids)
            )
            automatic_count = (
                len(self.plan.automatically_included_test_ids)
                if self.plan is not None
                else 0
            )
            test_scope = f"exact selection; {requested_count} requested" + (
                f", {automatic_count} prerequisite/control" if automatic_count else ""
            )
        else:
            test_scope = "full planned selection"

        summary_title = (
            "NEUTRON FLUX PLAN SUMMARY"
            if self.action == "plan"
            else "NEUTRON FLUX FINAL SUMMARY"
        )
        status_line = (
            f"Plan status:     {'COMPLETE' if final_status == 'PASS' else final_status}"
            if self.action == "plan"
            else f"Final status:    {final_status}"
        )
        lines = [
            "",
            rule,
            summary_title.center(width),
            rule,
            f"Run ID:          {self.run_id}",
            f"Action:          {self.action}",
            f"Version:         {DISPLAY_VERSION}",
            status_line,
            f"Duration:        {duration:.1f} seconds",
            f"Cleanup:         {cleanup_text}",
            f"Text report:     {self.report_path}",
            f"Visual report:   {self.html_report_path if self.config.html_report_enabled else 'disabled'}",
            f"Results JSON:    {self.results_path}",
        ]
        if self.action in {"plan", "run"}:
            lines[6:6] = [
                f"Test scope:      {test_scope}",
                f"Image:           {self.config.image}",
                f"Flavor:          {self.config.flavor}",
                f"Storage:         {self.config.storage}",
                f"Migration:       {self.config.migration_mode}",
                f"Live transport:  {'not used' if self.config.migration_mode == 'cold-only' else 'block live migration' if self.config.effective_migration_storage == 'host' else 'shared/volume-backed live migration'}",
                f"Networks:        {', '.join(self.config.external_networks)}",
                f"Zone mode:       {self.config.zone_mode}",
                f"Zones requested: {'all' if self.config.availability_zones_all else ', '.join(self.config.availability_zones) or 'automatic single zone'}",
            ]
            if self.config.storage == "volume":
                lines[9:9] = [
                    f"Volume size:     {self.config.volume_size} GiB",
                    f"Volume type:     {self.config.volume_type or 'Cinder default'}",
                ]

        validation_statuses = {"PASS", "FAIL", "UNVERIFIED", "ERROR"}
        not_run_statuses = {
            "SKIP",
            "NOT_APPLICABLE",
            "BLOCKED_BY_SETUP_ERROR",
            "BLOCKED_BY_PREREQUISITE",
            "NOT_RUN_CANCELLED",
        }
        validation_count = sum(counts.get(status, 0) for status in validation_statuses)
        not_run_count = sum(counts.get(status, 0) for status in not_run_statuses)
        completed_count = validation_count
        planned_count = len(self.plan.tests) if self.plan else len(self.results)

        if self.action == "run":
            lines.extend(
                [
                    "",
                    "OVERALL RESULT",
                    "-" * width,
                    self._overall_result_line(final_status, counts),
                ]
            )
            if final_status in {"PASS", "PASS WITH WARNINGS"}:
                lines.append("No validation failed.")
            lines.extend(attention_summary_lines(self._attention_summary_counts()))
            if counts.get("UNVERIFIED", 0):
                lines.append(
                    f"{self._human_count(counts.get('UNVERIFIED', 0), 'validation')} could not be independently verified."
                )

            if self.plan and self.plan.checks:
                progress = reporter_progress(self)
                outcomes = progress["outcomes"]
                lines.extend(
                    [
                        "",
                        "CHECK RESULTS",
                        "-" * width,
                        f"Checks planned (fixed):                {progress['planned']}",
                        f"Checks accounted for:                 {progress['planned_recorded']}",
                        f"  Passed:                             {outcomes.get('PASSED', 0)}",
                        f"  Failed:                             {outcomes.get('FAILED', 0)}",
                        f"  Unverified:                         {outcomes.get('UNVERIFIED', 0)}",
                        f"  Blocked:                            {outcomes.get('BLOCKED', 0)}",
                        f"  Not applicable:                     {outcomes.get('INAPPLICABLE', 0)}",
                        f"  Cancelled:                          {outcomes.get('CANCELLED', 0)}",
                        f"Evidence records including retries and samples: {len(self.results)}",
                    ]
                )
            else:
                lines.extend(
                    [
                        "",
                        "CHECK RESULTS",
                        "-" * width,
                        f"Checks planned:                       {planned_count}",
                        f"Checks completed:                     {completed_count}",
                        "",
                        f"Validations:                          {validation_count}",
                        f"  Passed:                             {counts.get('PASS', 0)}",
                        f"  Failed:                             {counts.get('FAIL', 0)}",
                        f"  Unverified:                         {counts.get('UNVERIFIED', 0)}",
                        f"  Execution errors:                   {counts.get('ERROR', 0)}",
                        "",
                        f"Checks not run:                       {not_run_count}",
                        f"  Unsupported/skipped:                {counts.get('SKIP', 0)}",
                        f"  Not applicable:                     {counts.get('NOT_APPLICABLE', 0)}",
                        f"  Blocked by setup error:             {counts.get('BLOCKED_BY_SETUP_ERROR', 0)}",
                        f"  Blocked by prerequisite:            {counts.get('BLOCKED_BY_PREREQUISITE', 0)}",
                        f"  Cancelled before execution:         {counts.get('NOT_RUN_CANCELLED', 0)}",
                    ]
                )
            network_results = [
                item
                for item in self.results
                if item.scenario != "Controller readiness"
                and not bool((item.details or {}).get("tool_failure"))
            ]
            completed_network_results = [
                item for item in network_results if item.status not in not_run_statuses
            ]
            if network_results and not completed_network_results:
                lines.append("No network connectivity validations were completed.")
        elif self.action == "plan":
            selectable_count = sum(
                1
                for item in (self.plan.tests if self.plan else [])
                if item.scenario != "Controller readiness"
            )
            automatic_count = (
                len(self.plan.tests) - selectable_count if self.plan else 0
            )
            lines.extend(
                [
                    "",
                    "PLAN RESULT",
                    "-" * width,
                    "Plan created successfully.",
                    (
                        f"Tests available: {selectable_count} selectable; "
                        f"{automatic_count} automatic readiness checks."
                    ),
                    "No cloud resources were created and no tests were executed.",
                ]
            )
        else:
            lines.extend(
                [
                    "",
                    "ACTION RESULTS",
                    "-" * width,
                    f"Results recorded: {len(self.results)}",
                ]
            )

        if not self.results and self.action != "plan":
            lines.append("No checks were recorded by this action.")

        self._append_zone_summary(lines, width)
        self._append_category_summary(lines, width)
        self._append_detailed_category_results(lines, width, presentations)

        tool_errors = [
            item
            for item in self.results
            if item.status == "ERROR" and bool((item.details or {}).get("tool_failure"))
        ]
        failures = [
            item
            for item in self.results
            if item.status in {"FAIL", "ERROR"}
            and item not in tool_errors
            and not (
                self.plan and self.plan.checks and item.details.get("check_sample")
            )
        ]
        blocked_setup = [
            item for item in self.results if item.status == "BLOCKED_BY_SETUP_ERROR"
        ]
        blocked_prerequisite = [
            item for item in self.results if item.status == "BLOCKED_BY_PREREQUISITE"
        ]
        unverified = [item for item in self.results if item.status == "UNVERIFIED"]
        cancelled = [
            item for item in self.results if item.status == "NOT_RUN_CANCELLED"
        ]
        skipped = [
            item for item in self.results if item.status in {"SKIP", "NOT_APPLICABLE"}
        ]

        groups = operator_overview(
            {
                "results": [
                    presentations.get(item.test_id)
                    or {field.name: getattr(item, field.name) for field in fields(item)}
                    for item in self._primary_summary_results()
                ]
            }
        )["groups"]
        if groups:
            lines.extend(["", "WHY RESULTS NEED ATTENTION", "-" * width])
            lines.extend(f"- {group['count']}: {group['label']}" for group in groups)
        if self.setup_failures:
            lines.extend(["", "SETUP FAILURE", "-" * width])
            for item in self.setup_failures:
                lines.append(
                    "- "
                    + friendly_operator_text(
                        item.get("message", "unknown setup failure")
                    )
                )
        if failures:
            lines.extend(["", "FAILED OR ERRORED VALIDATIONS", "-" * width])
            for item in failures:
                lines.extend(
                    self._summary_result_lines(
                        item, presentation=presentations.get(item.test_id)
                    )
                )
        if tool_errors:
            lines.extend(["", "TOOL OR LANE EXECUTION ERRORS", "-" * width])
            for item in tool_errors:
                lines.extend(
                    self._summary_result_lines(
                        item, presentation=presentations.get(item.test_id)
                    )
                )
        if blocked_setup:
            lines.extend(["", "VALIDATIONS BLOCKED BY SETUP ERROR", "-" * width])
            reasons = Counter(
                friendly_operator_text(item.message) for item in blocked_setup
            )
            for reason, count in reasons.most_common():
                lines.append(f"- {self._human_count(count, 'validation')}: {reason}")
        if blocked_prerequisite:
            lines.extend(["", "VALIDATIONS BLOCKED BY PREREQUISITE", "-" * width])
            reasons = Counter(
                friendly_operator_text(item.message) for item in blocked_prerequisite
            )
            for reason, count in reasons.most_common():
                lines.append(f"- {self._human_count(count, 'validation')}: {reason}")
        if cancelled:
            lines.extend(["", "VALIDATIONS NOT RUN — OPERATOR CANCELLED", "-" * width])
            reasons = Counter(
                friendly_operator_text(item.message) for item in cancelled
            )
            for reason, count in reasons.most_common():
                lines.append(f"- {self._human_count(count, 'validation')}: {reason}")
        if unverified and not self.setup_failed:
            lines.extend(["", "UNVERIFIED COVERAGE", "-" * width])
            reasons = Counter(
                explain_result(
                    presentations.get(item.test_id)
                    or {field.name: getattr(item, field.name) for field in fields(item)}
                )["headline"]
                + ": "
                + friendly_operator_text(item.message)
                for item in unverified
            )
            for reason, count in reasons.most_common():
                lines.append(f"- {self._human_count(count, 'validation')}: {reason}")
            lines.append(
                "No failure was detected by these checks, but their expected behavior was not independently proven."
            )
        if skipped and not self.setup_failed:
            lines.extend(["", "UNSUPPORTED OR NOT-APPLICABLE COVERAGE", "-" * width])
            reasons = Counter(friendly_operator_text(item.message) for item in skipped)
            for reason, count in reasons.most_common():
                lines.append(f"- {self._human_count(count, 'check')}: {reason}")

        sweep = self.cleanup_summary.get("orphan_sweep") or {}
        if sweep:
            lines.extend(["", "ORPHAN CLEANUP VERIFICATION", "-" * width])
            lines.extend(
                [
                    f"Fixed-point passes:                  {len(sweep.get('passes') or [])}",
                    f"Orphaned resources remaining:       {int(sweep.get('stale_resources_remaining') or 0)}",
                    f"Protected active resources:         {int(sweep.get('protected_resources_remaining') or 0)}",
                    f"Unknown Flux-like resources:        {int(sweep.get('unknown_resources_remaining') or 0)}",
                    f"Recognized Flux resources still in project:{int(sweep.get('project_resources_remaining') or 0):>9}",
                ]
            )
            protected_runs = list(sweep.get("protected_runs") or [])
            if protected_runs:
                lines.append("Protected runs: " + ", ".join(protected_runs))
            candidate_runs = list(sweep.get("candidate_runs") or [])
            if candidate_runs:
                lines.append("Orphan candidate runs: " + ", ".join(candidate_runs))

        cancellation_reason = getattr(self, "cancellation_reason", None)
        if self.interrupted and cancellation_reason:
            lines.extend(
                [
                    "",
                    "OPERATOR CANCELLATION",
                    "-" * width,
                    friendly_operator_text(cancellation_reason),
                ]
            )
        if self.error:
            lines.extend(
                [
                    "",
                    "EXECUTION ERROR",
                    "-" * width,
                    friendly_operator_text(self.error),
                ]
            )
        cleanup_errors = self.cleanup_summary.get("errors", [])
        recovered_errors = self.cleanup_summary.get("recovered_errors", [])
        if cleanup_complete is True and cleanup_errors:
            recovered_errors = list(dict.fromkeys([*recovered_errors, *cleanup_errors]))
            cleanup_errors = []
        if recovered_errors:
            lines.extend(["", "RECOVERED CLEANUP DELAYS", "-" * width])
            lines.extend(
                f"- {friendly_operator_text(error)}" for error in recovered_errors
            )
            sweep = self.cleanup_summary.get("orphan_sweep") or {}
            protected = int(sweep.get("protected_resources_remaining") or 0)
            if protected:
                lines.append(
                    "Final orphan cleanup verification succeeded; "
                    f"{protected} protected active resource(s) remain."
                )
            else:
                lines.append(
                    "Final cleanup verification succeeded for the eligible resource scope."
                )
        if cleanup_errors:
            lines.extend(["", "CLEANUP ERRORS", "-" * width])
            lines.extend(
                f"- {friendly_operator_text(error)}" for error in cleanup_errors
            )
        leftovers = self.cleanup_summary.get("leftovers", [])
        if leftovers:
            lines.extend(["", "UNRESOLVED CLEANUP OR VERIFICATION ISSUES", "-" * width])
            lines.extend(f"- {friendly_operator_text(item)}" for item in leftovers)
        if self.cleanup_summary.get("recovery_markdown"):
            lines.append(f"Recovery guide: {self.cleanup_summary['recovery_markdown']}")

        timings = timing_summary(getattr(self, "events", []))
        if timings["categories"]:
            lines.extend(["", "RUNTIME TIMING", "-" * width])
            lines.append(
                "Concurrent spans overlap; component totals are not run wall time."
            )
            lines.append(
                f"{'Component':<28} {'Count':>8} {'Elapsed seconds':>18} {'Self seconds':>16}"
            )
            for category, row in sorted(timings["categories"].items()):
                lines.append(
                    f"{category:<28} {row['count']:>8} {row['elapsed_seconds']:>18.2f} {row['self_seconds']:>16.2f}"
                )
        lines.extend([rule, ""])
        return "\n".join(lines)

    @classmethod
    def _summary_result_lines(
        cls, item: TestResult, *, presentation: dict[str, Any] | None = None
    ) -> list[str]:
        record = presentation if presentation is not None else asdict(item)
        title = execution_name(record)
        sample = "Supporting sample " if item.details.get("check_sample") else ""
        status = cls._display_status(item.status)
        if (
            item.status == "PASS"
            and (item.details or {}).get("health") == "warning"
            and not migration_interruption_observations(record)
        ):
            status = "PASS WITH WARNING"
        lines = [f"{sample}[{status}] {title}"]
        lines.extend(explanation_lines(record))
        lines.append(f"  Technical reference: {item.test_id}")
        return lines
