from __future__ import annotations

import dataclasses
import datetime as dt
import json
import pathlib
import threading
import time
import traceback
from collections import Counter
from typing import Any

from .check_ledger import finalize_checks, result_binding, validate_check_bindings
from .config import Config
from .constants import (
    EXIT_CLEANUP_INCOMPLETE,
    EXIT_EXECUTION_ERROR,
    EXIT_SUCCESS,
    EXIT_TEST_FAILURE,
    RESULT_STATUSES,
)
from .contract_assessment import with_contract_assessment
from .coverage_ledger import build_coverage_ledger, materialize_missing_results
from .errors import SetupFailureError, SuiteError
from .log import Logger
from .models import Discovery, Plan, ResourceRecord, TestResult
from .operation_compat import canonical_operation_fields
from .plan_contract import attach_runtime_plan, plan_dict
from .progress import progress_text, reporter_progress
from .reporting_components.html import (
    _atomic_write,
    build_run_payload,
    write_structured_reports,
)
from .reporting_components.summary import SummaryRendererMixin
from .result_contract import normalize_result_record, typed_verdict
from .results_io import append_text, atomic_write_text
from .utils import iso_utc, safe_name, unique_safe_name, utc_now, validate_run_id


class Reporter(SummaryRendererMixin):
    """Record run state and render text, structured JSON, and visual HTML reports."""

    SUMMARY_WIDTH = 120

    def __init__(
        self,
        config: Config,
        run_id: str,
        *,
        load_existing: bool = False,
        identity: dict[str, Any] | None = None,
    ):
        self.config = config
        self.run_id = validate_run_id(run_id)
        if config.report_dir.is_symlink():
            raise SuiteError(
                f"Report directory must not be a symbolic link: {config.report_dir}"
            )
        runs_dir = config.report_dir / "runs"
        if runs_dir.is_symlink():
            raise SuiteError(f"Runs directory must not be a symbolic link: {runs_dir}")
        self.run_dir = runs_dir / self.run_id
        if self.run_dir.is_symlink():
            raise SuiteError(
                f"Run directory must not be a symbolic link: {self.run_dir}"
            )
        try:
            self.run_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise SuiteError(
                f"Could not prepare run report directory {self.run_dir}: {exc}"
            ) from exc
        self.started = utc_now()
        self._lock = threading.RLock()
        # API workers publish timing events before releasing their admission
        # slots. Result logging can request a heartbeat while holding _lock,
        # so event appends must never wait for that result/publication lock.
        self._event_lock = threading.Lock()

        # Live text transcript and final human-readable summary.
        self.report_path = self.run_dir / "report.txt"
        self.log_path = self.report_path  # Compatibility alias for internal callers.

        # Runtime state plus structured and visual report paths.
        self.manifest_path = self.run_dir / "manifest.jsonl"
        self.result_journal_path = self.run_dir / "results.jsonl"
        self.active_path = self.run_dir / "active.json"
        self.plan_path = self.run_dir / "plan.json"
        self.plan_drift_path = self.run_dir / "plan-drift.json"
        self.results_path = self.run_dir / "results.json"
        self.html_report_path = self.run_dir / "report.html"
        self.junit_report_path = self.run_dir / "report.junit.xml"
        self.replay_plan_path = self.run_dir / "replay-plan.json"
        self.replay_plan_text_path = self.run_dir / "replay-plan.txt"

        for path in (
            self.report_path,
            self.manifest_path,
            self.result_journal_path,
            self.active_path,
            self.plan_path,
            self.plan_drift_path,
            self.results_path,
            self.html_report_path,
            self.junit_report_path,
            self.replay_plan_path,
            self.replay_plan_text_path,
        ):
            if path.is_symlink():
                raise SuiteError(
                    f"Managed run artifact must not be a symbolic link: {path}"
                )

        self.run_tag = safe_name(f"neutron-flux-{run_id}", 80)
        self.name_prefix = (
            safe_name(run_id, 36) if load_existing else unique_safe_name(run_id, 36)
        )
        if load_existing:
            if self.active_path.is_file():
                self._restore_existing_identity()
            elif identity:
                self._restore_checkpoint_identity(identity)
        try:
            self.logger = Logger(self.report_path)
        except OSError as exc:
            raise SuiteError(
                f"Could not open run report transcript {self.report_path}: {exc}"
            ) from exc
        self.results: list[TestResult] = []
        self.results_by_id: dict[str, TestResult] = {}
        self._reopened_result_ids: set[str] = set()
        self.events: list[dict[str, Any]] = []
        self.setup_failures: list[dict[str, Any]] = []
        self.setup_failed = False
        self.discovery: Discovery | None = None
        self.plan: Plan | None = None
        self._progress_plan_ids: frozenset[str] | None = None
        self.plan_contract: dict[str, Any] | None = None
        self.plan_approval: dict[str, Any] = {
            "verified": False,
            "source": None,
            "fingerprint": None,
            "mode": "unavailable",
        }
        self.plan_drift: list[dict[str, Any]] = []
        self.capabilities: dict[str, Any] | None = None
        self.coverage_ledger: list[dict[str, Any]] = []
        self.resources: list[ResourceRecord] = []
        self._resource_sequence = 0
        self.manifest_errors: list[str] = []
        self.cleanup_summary: dict[str, Any] = {
            "attempted": False,
            "complete": None,
            "deleted": 0,
            "adopted_orphans": 0,
            "leftovers": [],
            "errors": [],
        }
        self.error: str | None = None
        self.traceback: str | None = None
        self.interrupted = False
        self.cancellation_reason: str | None = None
        self.action = config.action
        self.finalized = False
        if load_existing:
            self._load_previous()
        try:
            append_text(self.manifest_path, "")
            append_text(self.result_journal_path, "")
            atomic_write_text(
                self.active_path,
                json.dumps(
                    {
                        "schema_version": 3,
                        "manifest": str(self.manifest_path),
                        "report": str(self.report_path),
                        "results": str(self.results_path),
                        "result_journal": str(self.result_journal_path),
                        "html_report": (
                            str(self.html_report_path)
                            if self.config.html_report_enabled
                            else None
                        ),
                        "junit_report": (
                            str(self.junit_report_path)
                            if self.config.junit_report_enabled
                            else None
                        ),
                        "replay_plan": str(self.replay_plan_path),
                        "run_id": self.run_id,
                        "run_tag": self.run_tag,
                        "name_prefix": self.name_prefix,
                        "action": self.action,
                    },
                    sort_keys=True,
                )
                + "\n",
            )
        except (OSError, SuiteError) as exc:
            self.logger.close()
            raise SuiteError(
                f"Could not initialize run journal under {self.run_dir}: {exc}"
            ) from exc

    def _restore_existing_identity(self) -> None:
        try:
            payload = json.loads(self.active_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SuiteError(
                f"Could not read existing run identity {self.active_path}: {exc}"
            ) from exc
        if not isinstance(payload, dict) or payload.get("run_id") != self.run_id:
            raise SuiteError(
                f"Existing run identity does not match {self.run_id}: {self.active_path}"
            )
        for field, limit in (("run_tag", 80), ("name_prefix", 36)):
            value = payload.get(field)
            if (
                not isinstance(value, str)
                or not value
                or safe_name(value, limit) != value
            ):
                raise SuiteError(
                    f"Existing run identity field {field} is invalid: {self.active_path}"
                )
            setattr(self, field, value)

    def _restore_checkpoint_identity(self, identity: dict[str, Any]) -> None:
        for field, limit in (("run_tag", 80), ("name_prefix", 36)):
            value = identity.get(field)
            if (
                not isinstance(value, str)
                or not value
                or safe_name(value, limit) != value
            ):
                raise SuiteError(
                    f"Checkpoint identity field {field} is missing or invalid"
                )
            setattr(self, field, value)

    def _load_previous(self) -> None:
        if self.manifest_path.is_file():
            self.resources = ResourceTracker.load_manifest(
                self.manifest_path, errors=self.manifest_errors
            )
            self._resource_sequence = max(
                (item.sequence for item in self.resources), default=0
            )
            if self.manifest_errors:
                self.cleanup_summary["manifest_errors"] = list(self.manifest_errors)
                self.cleanup_summary["errors"].extend(self.manifest_errors)
                for error in self.manifest_errors:
                    self.logger.log(error, "ERROR")
        if self.action != "run":
            return
        if self.results_path.is_file():
            self._load_previous_results_file()
        if self.result_journal_path.is_file():
            self._load_result_journal()
        self._discard_restartable_results()
        if self.results:
            self.logger.log(
                f"Recovered {len(self.results)} durable result(s) for resume"
            )
            self.event(
                "run-resumed",
                "Recovered durable execution progress",
                recovered_results=len(self.results),
            )

    def _discard_restartable_results(self) -> None:
        restartable = [
            item
            for item in self.results
            if item.status == "NOT_RUN_CANCELLED"
            or (item.details or {}).get("coverage_outcome") == "NEVER_RAN"
        ]
        restartable_ids = {
            item.test_id for item in restartable
        } | self._reopened_result_ids
        if not restartable_ids:
            return
        self.results = [
            item
            for item in self.results
            if item.status != "NOT_RUN_CANCELLED"
            and (item.details or {}).get("coverage_outcome") != "NEVER_RAN"
        ]
        self.results_by_id = {item.test_id: item for item in self.results}
        journal = "".join(
            json.dumps(dataclasses.asdict(item), sort_keys=True, allow_nan=False) + "\n"
            for item in self.results
        )
        atomic_write_text(self.result_journal_path, journal)
        self.logger.log(f"Resume reopened {len(restartable_ids)} unfinished result(s)")
        self.event(
            "resume-results-reopened",
            "Cancelled or synthetic never-run results were reopened",
            result_ids=sorted(restartable_ids),
        )

    def _load_previous_results_file(self) -> None:
        try:
            payload = json.loads(self.results_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SuiteError(
                f"Could not read prior structured results {self.results_path}: {exc}"
            ) from exc
        if not isinstance(payload, dict):
            raise SuiteError(
                f"Prior structured results must contain an object: {self.results_path}"
            )
        payload = canonical_operation_fields(payload)
        run = payload.get("run") or {}
        started_at = run.get("started_at") if isinstance(run, dict) else None
        if isinstance(started_at, str):
            try:
                parsed = dt.datetime.fromisoformat(started_at.replace("Z", "+00:00"))
                self.started = parsed
            except ValueError:
                pass
        for raw in payload.get("results") or []:
            self._load_result_record(raw, source=str(self.results_path))
        prior_events = payload.get("events")
        if isinstance(prior_events, list):
            self.events = [item for item in prior_events if isinstance(item, dict)]
        prior_setup = payload.get("setup_failures")
        if isinstance(prior_setup, list):
            self.setup_failures = [
                item for item in prior_setup if isinstance(item, dict)
            ]
            self.setup_failed = bool(self.setup_failures)

    def _load_result_journal(self) -> None:
        try:
            lines = self.result_journal_path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise SuiteError(
                f"Could not read result journal {self.result_journal_path}: {exc}"
            ) from exc
        for line_number, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SuiteError(
                    f"Invalid result journal record at "
                    f"{self.result_journal_path}:{line_number}: {exc}"
                ) from exc
            self._load_result_record(
                raw,
                source=f"{self.result_journal_path}:{line_number}",
            )

    def _load_result_record(self, raw: Any, *, source: str) -> None:
        if not isinstance(raw, dict):
            raise SuiteError(f"Result journal record is not an object: {source}")
        field_names = {field.name for field in dataclasses.fields(TestResult)}
        try:
            normalized = normalize_result_record(raw)
            item = TestResult(
                **{key: normalized[key] for key in field_names if key in normalized}
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise SuiteError(
                f"Invalid result journal record at {source}: {exc}"
            ) from exc
        if item.status not in RESULT_STATUSES:
            raise SuiteError(
                f"Invalid result status {item.status!r} in recovered record {source}"
            )
        if (
            item.status == "NOT_RUN_CANCELLED"
            or (item.details or {}).get("coverage_outcome") == "NEVER_RAN"
        ):
            self._reopened_result_ids.add(item.test_id)
            return
        existing = self.results_by_id.get(item.test_id)
        if existing is not None:
            if dataclasses.asdict(existing) != dataclasses.asdict(item):
                raise SuiteError(
                    f"Conflicting recovered result ID {item.test_id} at {source}"
                )
            return
        self.results.append(item)
        self.results_by_id[item.test_id] = item

    def event(self, event_type: str, message: str, **details: Any) -> None:
        try:
            json.dumps(details, sort_keys=True, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise SuiteError(
                f"Event {event_type!r} contains non-JSON details: {exc}"
            ) from exc
        with self._event_lock:
            self.events.append(
                {
                    "timestamp": iso_utc(),
                    "type": event_type,
                    "message": message,
                    "details": details,
                }
            )

    def record_setup_failure(
        self,
        message: str,
        *,
        emit_console: bool = True,
        **details: Any,
    ) -> None:
        with self._lock:
            item = {
                "timestamp": iso_utc(),
                "message": message,
                "details": details,
            }
            if not any(
                existing.get("message") == message for existing in self.setup_failures
            ):
                self.setup_failures.append(item)
            self.setup_failed = True
            self.event("setup-failed", message, **details)
            if emit_console:
                self.logger.log(message, "ERROR")

    def result(
        self,
        test_id: str,
        category: str,
        status: str,
        message: str,
        *,
        family: int | None = None,
        source: str | None = None,
        destination: str | None = None,
        started: float | None = None,
        started_at: str | None = None,
        duration_ms: int | None = None,
        details: dict[str, Any] | None = None,
        expected: str | None = None,
        observed: str | None = None,
        authoritative: bool | None = None,
        likely_failure: str | None = None,
        display_name: str | None = None,
        scenario: str | None = None,
        contract: dict[str, Any] | None = None,
        path_signature: dict[str, Any] | None = None,
        emit_console: bool | None = None,
    ) -> TestResult:
        with self._lock:
            if status not in RESULT_STATUSES:
                raise ValueError(f"Unknown result status: {status}")
            if emit_console is None:
                emit_console = status not in {
                    "BLOCKED_BY_SETUP_ERROR",
                    "BLOCKED_BY_PREREQUISITE",
                    "NOT_RUN_CANCELLED",
                }
            if status in {
                "BLOCKED_BY_SETUP_ERROR",
                "BLOCKED_BY_PREREQUISITE",
                "NOT_RUN_CANCELLED",
            }:
                # These records explain why an approved validation did not run.
                # They are authoritative execution-ledger entries, but they are
                # never authoritative observations of the network contract.
                authoritative = False
            binding = result_binding(self, test_id, details)
            enriched_details = with_contract_assessment(
                {**(details or {}), **binding} if binding else details,
                status=status,
                expected=expected,
                observed=observed,
                authoritative=authoritative,
            )
            if enriched_details.get("address_path") and enriched_details.get(
                "translated_source_ip_observed_by_provider"
            ):
                enriched_details["address_path"] = {
                    **enriched_details["address_path"],
                    "observed_source_ip": enriched_details[
                        "translated_source_ip_observed_by_provider"
                    ],
                }
            if likely_failure and "diagnostic_classification" not in enriched_details:
                enriched_details["diagnostic_classification"] = {
                    "code": likely_failure,
                    "basis": "observed probe symptom pattern",
                    "causal_claim": False,
                    "interpretation": (
                        "Diagnostic classification only; this is not a proven "
                        "root cause."
                    ),
                }
            try:
                normalized = normalize_result_record(
                    {
                        "test_id": test_id,
                        "category": category,
                        "status": status,
                        "family": family,
                        "source": source,
                        "destination": destination,
                        "message": message,
                        "details": enriched_details,
                        "expected": expected,
                        "observed": observed,
                        "authoritative": authoritative,
                        "likely_failure": likely_failure,
                        "display_name": display_name,
                        "scenario": scenario,
                        "contract": contract,
                        "path_signature": path_signature,
                    }
                )
            except (TypeError, ValueError) as exc:
                raise SuiteError(
                    f"Result {test_id!r} has an invalid typed network contract: {exc}"
                ) from exc
            expected = normalized.get("expected")
            observed = normalized.get("observed")
            contract = normalized["contract"]
            path_signature = normalized["path_signature"]
            existing = self.results_by_id.get(test_id)
            material = {
                "category": category,
                "status": status,
                "family": family,
                "source": source,
                "destination": destination,
                "message": message,
                "details": enriched_details,
                "expected": expected,
                "observed": observed,
                "authoritative": authoritative,
                "likely_failure": likely_failure,
                "display_name": display_name,
                "scenario": scenario,
                "contract": contract,
                "path_signature": path_signature,
            }
            if existing is not None:
                existing_material = {key: getattr(existing, key) for key in material}
                if existing_material == material:
                    return existing
                differences = [
                    key
                    for key in material
                    if existing_material.get(key) != material.get(key)
                ]
                raise SuiteError(
                    f"Conflicting duplicate test result ID {test_id}: "
                    + ", ".join(differences)
                )
            calculated_duration = (
                duration_ms
                if duration_ms is not None
                else int((time.monotonic() - started) * 1000)
                if started is not None
                else 0
            )
            item = TestResult(
                test_id=test_id,
                category=category,
                status=status,
                family=family,
                source=source,
                destination=destination,
                message=message,
                started_at=started_at
                or (
                    utc_now()
                    - dt.timedelta(
                        seconds=max(0.0, time.monotonic() - started)
                        if started is not None
                        else max(0, calculated_duration) / 1000
                    )
                ).isoformat(),
                duration_ms=calculated_duration,
                details=enriched_details,
                expected=expected,
                observed=observed,
                authoritative=authoritative,
                likely_failure=likely_failure,
                display_name=display_name,
                scenario=scenario,
                contract=contract,
                path_signature=path_signature,
            )
            try:
                encoded = (
                    json.dumps(
                        dataclasses.asdict(item),
                        sort_keys=True,
                        allow_nan=False,
                    )
                    + "\n"
                )
            except (TypeError, ValueError) as exc:
                raise SuiteError(
                    f"Result {test_id!r} contains non-JSON evidence: {exc}"
                ) from exc
            append_text(
                self.result_journal_path,
                encoded,
            )
            # Publish the in-memory record only after its durable JSON journal
            # append succeeds. Failed serialization or I/O must not create a
            # phantom completed result that resume cannot recover.
            self.results.append(item)
            self.results_by_id[test_id] = item
            if not emit_console:
                return item
            presentation_lines = self._summary_result_lines(
                item, presentation=self._presentation_result(item)
            )
            self.logger.log(presentation_lines[0])
            progress_line = progress_text(reporter_progress(self))
            if enriched_details.get("check_sample"):
                sample_index = enriched_details.get("sample_index")
                sample_total = enriched_details.get("sample_total")
                sample_text = (
                    f"{sample_index}/{sample_total}"
                    if sample_index and sample_total
                    else str(
                        sum(
                            bool(row.details.get("check_sample"))
                            for row in self.results
                        )
                    )
                )
                progress_line = (
                    f"Supporting sample {sample_text} recorded | {progress_line}"
                )
            self.logger.log(progress_line)
            for line in presentation_lines[1:]:
                self.logger.log(line)
            return item

    def has_result(self, test_id: str) -> bool:
        with self._lock:
            return test_id in self.results_by_id

    def get_result(self, test_id: str) -> TestResult | None:
        with self._lock:
            return self.results_by_id.get(test_id)

    def next_resource_sequence(self) -> int:
        with self._lock:
            self._resource_sequence += 1
            return self._resource_sequence

    def add_resource(self, resource: ResourceRecord) -> None:
        with self._lock:
            self.update_resource(resource)
            self.resources.append(resource)

    def update_resource(self, resource: ResourceRecord) -> None:
        with self._lock:
            append_text(
                self.manifest_path,
                json.dumps(dataclasses.asdict(resource), sort_keys=True) + "\n",
            )

    def set_error(self, exc: BaseException) -> None:
        self.error = str(exc)
        if isinstance(exc, SetupFailureError):
            self.setup_failed = True
            if self.error and not any(
                item.get("message") == self.error for item in self.setup_failures
            ):
                self.setup_failures.append(
                    {"timestamp": iso_utc(), "message": self.error, "details": {}}
                )
        self.traceback = "".join(
            traceback.format_exception(type(exc), exc, exc.__traceback__)
        )

    def save_plan(self) -> None:
        with self._lock:
            if self.plan:
                original_checks = (
                    (self.plan_contract or {}).get("plan", {}).get("checks")
                )
                if original_checks is not None and self.plan.checks != original_checks:
                    raise SuiteError(
                        "The complete approved check inventory changed during execution"
                    )
                validate_check_bindings(self.plan)
                self._check_binding_cache = None
                reporter_progress(self)
                self.plan.estimated["test_results"] = len(self.plan.tests)
                self.plan.estimated["estimated_result_rows"] = len(self.plan.tests)
                payload: dict[str, Any]
                if self.plan_contract is not None:
                    payload = attach_runtime_plan(self.plan_contract, self.plan)
                else:
                    payload = plan_dict(self.plan)
                atomic_write_text(
                    self.plan_path,
                    json.dumps(
                        payload, separators=(",", ":"), sort_keys=True, allow_nan=False
                    )
                    + "\n",
                )

    def save_plan_drift(self, diff: list[dict[str, Any]]) -> None:
        with self._lock:
            self.plan_drift = list(diff)
            atomic_write_text(
                self.plan_drift_path,
                json.dumps(
                    {
                        "schema_version": 1,
                        "run_id": self.run_id,
                        "generated_at": iso_utc(),
                        "changes": self.plan_drift,
                    },
                    indent=2,
                    sort_keys=True,
                    allow_nan=False,
                )
                + "\n",
            )

    def finalize(self, requested_exit_code: int) -> int:
        if self.finalized:
            return requested_exit_code
        self.finalized = True
        materialize_missing_results(self, self.plan)
        finalize_checks(self)
        completed_pair_cycles = set(
            getattr(self, "completed_pair_cycles", set()) or set()
        )
        self.coverage_ledger = build_coverage_ledger(
            self.plan,
            self.results,
            completed_pair_cycles=completed_pair_cycles,
        )
        finished = utc_now()
        counts = Counter(item.status for item in self.results)
        verdict_counts = Counter(typed_verdict(item) for item in self.results)
        cleanup_complete = self.cleanup_summary.get("complete")
        test_failures = verdict_counts.get("FAIL", 0)
        execution_errors = verdict_counts.get("ERROR", 0)
        blocked_checks = verdict_counts.get("BLOCKED", 0)
        if self.plan and self.plan.checks and self.action == "run":
            outcomes = reporter_progress(self)["outcomes"]
            test_failures = outcomes.get("FAILED", 0)
            execution_errors = outcomes.get("ERROR", 0) + sum(
                typed_verdict(item) == "ERROR"
                and bool((item.details or {}).get("tool_failure"))
                for item in self.results
            )
            blocked_checks = outcomes.get("BLOCKED", 0)
            # Intermediate samples and retries do not replace their parent check's
            # terminal assessment. Explicit tool failures remain fatal.
            verdict_counts = Counter(
                {
                    "PASS": outcomes.get("PASSED", 0),
                    "FAIL": test_failures,
                    "ERROR": execution_errors,
                    "BLOCKED": blocked_checks,
                    "UNVERIFIED": outcomes.get("UNVERIFIED", 0),
                    "INAPPLICABLE": outcomes.get("INAPPLICABLE", 0),
                    "NOT_RUN": outcomes.get("CANCELLED", 0),
                }
            )
        prerequisite_blocks = sum(
            1
            for item in self.results
            if item.status == "BLOCKED_BY_PREREQUISITE"
            and not (item.details or {}).get("check_sample")
        )
        # Grade the terminal logical checks, using the same observation policy
        # as report presentation. Nested migration evidence must not disappear,
        # and an earlier supporting sample must not replace its parent verdict.
        passing_warnings = self._performance_warning_count()
        network_results = [
            item
            for item in self.results
            if item.scenario != "Controller readiness"
            and not bool((item.details or {}).get("tool_failure"))
            and not bool((item.details or {}).get("check_sample"))
        ]
        executed_network_results = [
            item
            for item in network_results
            if item.status
            not in {
                "SKIP",
                "NOT_APPLICABLE",
                "BLOCKED_BY_SETUP_ERROR",
                "BLOCKED_BY_PREREQUISITE",
                "NOT_RUN_CANCELLED",
            }
        ]
        no_network_tests = bool(
            self.action == "run"
            and not self.interrupted
            and self.plan is not None
            and network_results
            and not executed_network_results
        )
        if no_network_tests:
            self.setup_failed = True
            message = (
                "No network connectivity validation executed; every non-controller "
                "test was skipped during endpoint or topology setup"
            )
            if not any(item.get("message") == message for item in self.setup_failures):
                self.setup_failures.append(
                    {"timestamp": iso_utc(), "message": message, "details": {}}
                )

        if cleanup_complete is False:
            final_status = "CLEANUP INCOMPLETE"
        elif self.interrupted:
            final_status = "CANCELLED"
        elif self.setup_failed and executed_network_results:
            final_status = "PARTIAL"
        elif self.setup_failed:
            final_status = "SETUP FAILED"
        elif self.error or execution_errors:
            final_status = "ERROR"
        elif test_failures:
            final_status = "FAIL"
        elif blocked_checks:
            final_status = "INCOMPLETE"
        elif (
            verdict_counts.get("UNVERIFIED", 0)
            or verdict_counts.get("INAPPLICABLE", 0)
            or verdict_counts.get("NOT_RUN", 0)
            or prerequisite_blocks
            or passing_warnings
        ):
            final_status = "PASS WITH WARNINGS"
        else:
            final_status = "PASS"

        if cleanup_complete is True:
            self.active_path.unlink(missing_ok=True)

        try:
            results_path, html_path = write_structured_reports(
                self,
                final_status=final_status,
                finished=finished,
                counts=counts,
            )
            self.logger.log(f"Structured results: {results_path}")
            if html_path is not None:
                self.logger.log(f"Visual HTML report: {html_path}")
        except (
            AttributeError,
            IndexError,
            KeyError,
            OSError,
            SuiteError,
            TypeError,
            ValueError,
            RuntimeError,
        ) as exc:
            self.error = f"Could not generate structured visual report: {exc}"
            if final_status not in {"CLEANUP INCOMPLETE", "CANCELLED"}:
                final_status = "ERROR"
            self.logger.log(self.error, "ERROR")
            # Keep the canonical JSON aligned with the exit code and text
            # summary even when an optional renderer or write fails. Remove
            # optional artifacts because they may describe an earlier attempt.
            self.html_report_path.unlink(missing_ok=True)
            self.junit_report_path.unlink(missing_ok=True)
            try:
                corrected = build_run_payload(
                    self,
                    final_status=final_status,
                    finished=finished,
                    counts=counts,
                    include_dashboard=False,
                )
                corrected["dashboard"] = {
                    "available": False,
                    "error": self.error,
                }
                _atomic_write(
                    self.results_path,
                    json.dumps(
                        corrected,
                        indent=2,
                        sort_keys=True,
                        allow_nan=False,
                    )
                    + "\n",
                )
            except (
                AttributeError,
                IndexError,
                KeyError,
                OSError,
                SuiteError,
                TypeError,
                ValueError,
                RuntimeError,
            ) as recovery_exc:
                self.logger.log(
                    f"Could not repair results.json after report failure: {recovery_exc}",
                    "ERROR",
                )

        summary = self._summary(final_status, finished, counts)
        # Keep the live chronological log intact as technical history, while
        # placing the finished report's human-readable outcome first.
        transcript = self.report_path.read_text(encoding="utf-8")
        self.logger.raw(summary)
        self.logger.close()
        atomic_write_text(
            self.report_path,
            summary
            + "\nRUNTIME HISTORY — TIMESTAMPED TECHNICAL LOG\n"
            + "=" * self.SUMMARY_WIDTH
            + "\nThe final results above are the report summary. The following "
            "log records events as they occurred, including retries and setup.\n\n"
            + transcript,
        )

        if cleanup_complete is False:
            return EXIT_CLEANUP_INCOMPLETE
        if self.interrupted:
            return requested_exit_code or 130
        if self.setup_failed:
            return max(requested_exit_code, EXIT_EXECUTION_ERROR)
        if self.error or execution_errors:
            return max(requested_exit_code, EXIT_EXECUTION_ERROR)
        if test_failures:
            return max(requested_exit_code, EXIT_TEST_FAILURE)
        if blocked_checks:
            return max(requested_exit_code, EXIT_EXECUTION_ERROR)
        return requested_exit_code or EXIT_SUCCESS


class ScopedLogger:
    """Prefix one parallel execution lane while writing to the parent report."""

    def __init__(self, parent: Logger, label: str):
        self.parent = parent
        self.label = label
        self.heartbeat = None

    @property
    def path(self) -> pathlib.Path:
        return self.parent.path

    def close(self) -> None:
        return None

    def _render(self, message: str) -> str:
        return f"[{self.label}] {message}" if message else f"[{self.label}]"

    def log(self, message: str = "", level: str = "INFO") -> None:
        self.parent.log(self._render(message), level)

    def raw(self, message: str = "") -> None:
        self.parent.raw(self._render(message))

    def section(self, message: str) -> None:
        self.log()
        self.log(f"==> {message}")


class ScopedReporter:
    """Thread-safe view of one AZ lane backed by the parent run journal."""

    def __init__(self, parent: Reporter, scope: str, *, availability_zone: str | None):
        self.parent = parent
        self.config = parent.config
        self.run_id = parent.run_id
        self.scope = unique_safe_name(scope, 32)
        self.availability_zone = availability_zone
        zones_dir = parent.run_dir / "zones"
        if zones_dir.is_symlink():
            raise SuiteError(
                f"Availability-zone report directory must not be a symbolic link: {zones_dir}"
            )
        self.run_dir = zones_dir / self.scope
        if self.run_dir.is_symlink():
            raise SuiteError(
                f"Scoped report directory must not be a symbolic link: {self.run_dir}"
            )
        try:
            self.run_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise SuiteError(
                f"Could not prepare scoped report directory {self.run_dir}: {exc}"
            ) from exc
        self.report_path = parent.report_path
        self.log_path = parent.log_path
        self.manifest_path = parent.manifest_path
        self.active_path = parent.active_path
        self.plan_path = self.run_dir / "plan.json"
        if self.plan_path.is_symlink():
            raise SuiteError(
                f"Scoped plan artifact must not be a symbolic link: {self.plan_path}"
            )
        self.results_path = parent.results_path
        self.html_report_path = parent.html_report_path
        self.junit_report_path = parent.junit_report_path
        self.replay_plan_path = parent.replay_plan_path
        self.replay_plan_text_path = parent.replay_plan_text_path
        self.run_tag = unique_safe_name(f"{parent.run_tag}-{self.scope}", 80)
        self.name_prefix = unique_safe_name(f"{parent.name_prefix}-{self.scope}", 36)
        self.logger = ScopedLogger(parent.logger, scope)
        self.cleanup_summary: dict[str, Any] = {
            "attempted": False,
            "complete": None,
            "deleted": 0,
            "adopted_orphans": 0,
            "leftovers": [],
            "errors": [],
        }
        # All AZ lanes append to the same manifest journal. Cleanup reads the
        # parent parser diagnostics through this shared view.
        self.manifest_errors = parent.manifest_errors
        self.plan: Plan | None = None
        self.discovery = parent.discovery
        self.setup_failures: list[dict[str, Any]] = []
        self.setup_failed = False
        self.error: str | None = None
        self.events: list[dict[str, Any]] = []
        self._result_ids: set[str] = set()
        self._local_result_ids: dict[str, str] = {}
        self._lock = threading.RLock()
        self._event_lock = threading.Lock()

    def _id(self, test_id: str) -> str:
        prefix = f"{self.scope.upper()}-"
        return test_id if test_id.startswith(prefix) else f"{prefix}{test_id}"

    def scoped_test_id(self, test_id: str) -> str:
        """Return the canonical parent-journal ID for one lane-local result."""

        return self._id(test_id)

    def _unscoped_result(self, item: TestResult) -> TestResult:
        with self._lock:
            test_id = self._local_result_ids.get(item.test_id, item.test_id)
        return dataclasses.replace(item, test_id=test_id)

    @property
    def results(self) -> list[TestResult]:
        with self._lock:
            result_ids = set(self._result_ids)
        with self.parent._lock:
            return [
                self._unscoped_result(item)
                for item in self.parent.results
                if item.test_id in result_ids
            ]

    @property
    def results_by_id(self) -> dict[str, TestResult]:
        return {item.test_id: item for item in self.results}

    @property
    def resources(self) -> list[ResourceRecord]:
        return [
            item
            for item in self.parent.resources
            if item.metadata.get("execution_scope") == self.scope
        ]

    def event(self, event_type: str, message: str, **details: Any) -> None:
        payload = {
            **details,
            "execution_scope": self.scope,
            "availability_zone": self.availability_zone,
        }
        with self._event_lock:
            self.events.append(
                {
                    "timestamp": iso_utc(),
                    "type": event_type,
                    "message": message,
                    "details": payload,
                }
            )
        self.parent.event(event_type, message, **payload)

    def record_setup_failure(
        self,
        message: str,
        *,
        emit_console: bool = True,
        **details: Any,
    ) -> None:
        payload = {
            **details,
            "execution_scope": self.scope,
            "availability_zone": self.availability_zone,
        }
        with self._lock:
            self.setup_failed = True
            self.setup_failures.append(
                {"timestamp": iso_utc(), "message": message, "details": payload}
            )
        self.parent.record_setup_failure(
            f"[{self.scope}] {message}",
            emit_console=emit_console,
            **payload,
        )

    def result(
        self, test_id: str, category: str, status: str, message: str, **kwargs: Any
    ) -> TestResult:
        scoped_id = self._id(test_id)
        details = {
            **(kwargs.pop("details", None) or {}),
            "execution_scope": self.scope,
            "availability_zone": self.availability_zone,
        }
        source = kwargs.pop("source", None)
        destination = kwargs.pop("destination", None)
        if self.availability_zone:
            source = f"{self.availability_zone}/{source}" if source else None
            destination = (
                f"{self.availability_zone}/{destination}" if destination else None
            )
        item = self.parent.result(
            scoped_id,
            category,
            status,
            message,
            source=source,
            destination=destination,
            details=details,
            **kwargs,
        )
        with self._lock:
            self._result_ids.add(scoped_id)
            self._local_result_ids[scoped_id] = test_id
        return item

    def has_result(self, test_id: str) -> bool:
        return self.parent.has_result(self._id(test_id))

    def get_result(self, test_id: str) -> TestResult | None:
        item = self.parent.get_result(self._id(test_id))
        return self._unscoped_result(item) if item is not None else None

    def next_resource_sequence(self) -> int:
        return self.parent.next_resource_sequence()

    def add_resource(self, resource: ResourceRecord) -> None:
        resource.metadata.setdefault("execution_scope", self.scope)
        resource.metadata.setdefault("availability_zone", self.availability_zone)
        self.parent.add_resource(resource)

    def update_resource(self, resource: ResourceRecord) -> None:
        resource.metadata.setdefault("execution_scope", self.scope)
        resource.metadata.setdefault("availability_zone", self.availability_zone)
        self.parent.update_resource(resource)

    def save_plan(self) -> None:
        if not self.plan:
            return
        with self._lock:
            atomic_write_text(
                self.plan_path,
                json.dumps(plan_dict(self.plan), indent=2, sort_keys=True) + "\n",
            )
            lane_tests = list(self.plan.tests)
        # AdaptiveExecutor appends runtime placement/readiness specifications to
        # the lane plan. Merge those scoped IDs into the parent aggregate plan so
        # final planned/completed counts remain accurate under concurrent AZs.
        with self.parent._lock:
            if self.parent.plan is not None:
                existing = {item.id for item in self.parent.plan.tests}
                for spec in lane_tests:
                    scoped_id = self._id(spec.id)
                    if scoped_id in existing:
                        continue
                    self.parent.plan.tests.append(
                        dataclasses.replace(spec, id=scoped_id)
                    )
                    existing.add(scoped_id)
        self.parent.save_plan()

    def set_error(self, exc: BaseException) -> None:
        self.error = str(exc)
        self.parent.set_error(exc)


_MANAGED_RESOURCE_TYPES = frozenset(
    {
        "floating_ip",
        "server",
        "router",
        "port",
        "subnet",
        "network",
        "volume",
        "security_group",
        "server_group",
        "keypair",
    }
)


def _validated_manifest_record(
    raw: dict[str, Any],
    *,
    path: pathlib.Path,
    line_number: int,
    existing: ResourceRecord | None,
) -> ResourceRecord:
    item = ResourceRecord(**raw)
    if (
        isinstance(item.sequence, bool)
        or not isinstance(item.sequence, int)
        or item.sequence < 1
    ):
        raise ValueError("resource sequence must be a positive integer")
    if item.resource_type not in _MANAGED_RESOURCE_TYPES:
        raise ValueError(f"unsupported managed resource type {item.resource_type!r}")
    if not isinstance(item.id, str) or not item.id.strip():
        raise ValueError("resource ID must be a non-empty string")
    if not isinstance(item.name, str) or not item.name.strip():
        raise ValueError("resource name must be a non-empty string")
    if item.parent_id is not None and not isinstance(item.parent_id, str):
        raise ValueError("resource parent_id must be a string or null")
    if not isinstance(item.metadata, dict):
        raise ValueError("resource metadata must be an object")
    if existing is not None and (
        existing.resource_type != item.resource_type or existing.id != item.id
    ):
        raise ValueError(
            "resource identity changed for sequence "
            f"{item.sequence}: {existing.resource_type}:{existing.id} -> "
            f"{item.resource_type}:{item.id}"
        )
    return item


class ResourceTracker:
    def __init__(self, reporter: Reporter):
        self.reporter = reporter
        self.deletion_callbacks: list[Any] = []
        self.sequence = max((item.sequence for item in reporter.resources), default=0)

    def add(
        self,
        resource_type: str,
        resource_id: str,
        name: str,
        *,
        parent_id: str | None = None,
        **metadata: Any,
    ) -> ResourceRecord:
        if hasattr(self.reporter, "next_resource_sequence"):
            sequence = self.reporter.next_resource_sequence()
            self.sequence = max(self.sequence, sequence)
        else:
            self.sequence += 1
            sequence = self.sequence
        metadata.setdefault("run_id", self.reporter.run_id)
        metadata.setdefault("run_tag", self.reporter.run_tag)
        metadata.setdefault("name_prefix", self.reporter.name_prefix)
        item = ResourceRecord(
            sequence=sequence,
            resource_type=resource_type,
            id=resource_id,
            name=name,
            parent_id=parent_id,
            metadata=metadata,
            created_at=iso_utc(),
        )
        self.reporter.add_resource(item)
        return item

    def mark_deleted(self, item: ResourceRecord, status: str = "deleted") -> None:
        item.deleted_at = iso_utc()
        item.delete_status = status
        item.cleanup_state = "DELETED"
        item.cleanup_error = None
        self.reporter.update_resource(item)
        for callback in getattr(self, "deletion_callbacks", ()):
            callback(item)

    def mark_present(
        self,
        item: ResourceRecord,
        *,
        reason: str = "rediscovered-during-cleanup",
    ) -> None:
        """Reopen a record when authoritative inventory sees its UUID again."""
        item.deleted_at = None
        item.delete_status = None
        item.cleanup_state = "PRESENT"
        item.cleanup_error = None
        item.metadata["cleanup_rediscovery_reason"] = reason
        item.metadata["cleanup_rediscovered_at"] = iso_utc()
        self.reporter.update_resource(item)

    @staticmethod
    def load_manifest(
        path: pathlib.Path, *, errors: list[str] | None = None
    ) -> list[ResourceRecord]:
        latest: dict[int, ResourceRecord] = {}
        identities: dict[tuple[str, str], int] = {}
        if not path.is_file():
            return []
        error_sink = errors if errors is not None else []
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    raw = json.loads(line)
                    if not isinstance(raw, dict):
                        raise TypeError("manifest record is not a JSON object")
                    sequence = raw.get("sequence")
                    existing = (
                        latest.get(sequence) if isinstance(sequence, int) else None
                    )
                    item = _validated_manifest_record(
                        raw,
                        path=path,
                        line_number=line_number,
                        existing=existing,
                    )
                    identity = (item.resource_type, item.id)
                    prior_sequence = identities.get(identity)
                    if prior_sequence is not None and prior_sequence != item.sequence:
                        raise ValueError(
                            f"resource identity {item.resource_type}:{item.id} is "
                            f"duplicated across sequences {prior_sequence} and {item.sequence}"
                        )
                except (json.JSONDecodeError, TypeError, ValueError) as exc:
                    error_sink.append(
                        f"Manifest corruption at {path}:{line_number}: {exc}; "
                        "valid earlier records were recovered, but cleanup verification is uncertain"
                    )
                    continue
                latest[item.sequence] = item
                identities[identity] = item.sequence
        return [latest[key] for key in sorted(latest)]
