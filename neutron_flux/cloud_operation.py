from __future__ import annotations

import json
import pathlib
import shlex
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, TypeVar

from .cancellation import cancellation_active, raise_if_cancelled
from .cloud_operation_command import OpenStackCloudOperationCommand
from .cloud_operation_reconciliation import (
    append_operation_resolution,
    cloud_operation_scope,
    cloud_operation_scope_fingerprint,
)
from .configuration.values import pacing_scale
from .errors import (
    CloudOperationBlockedError,
    CommandTimeoutError,
    RunCancelledError,
    SuiteError,
)
from .operation_compat import (
    normalize_operation_record,
    operation_journal_path,
    operation_journal_paths,
)
from .results_io import append_text
from .scheduling import ACTIVITY, timed
from .utils import iso_utc

T = TypeVar("T")


class CloudOperationOutcome(str, Enum):
    """Durable outcome of one disruptive command submission."""

    PREPARED = "PREPARED"
    SUBMITTING = "SUBMITTING"
    SUCCEEDED = "SUCCEEDED"
    IN_PROGRESS = "IN_PROGRESS"
    FAILED_RETRYABLE = "FAILED_RETRYABLE"
    FAILED_FINAL = "FAILED_FINAL"
    COMMAND_REJECTED = "COMMAND_REJECTED"
    AMBIGUOUS = "AMBIGUOUS"


TERMINAL_CLOUD_OPERATION_OUTCOMES = frozenset(
    {
        CloudOperationOutcome.SUCCEEDED.value,
        CloudOperationOutcome.FAILED_RETRYABLE.value,
        CloudOperationOutcome.FAILED_FINAL.value,
        CloudOperationOutcome.COMMAND_REJECTED.value,
    }
)
UNRESOLVED_CLOUD_OPERATION_OUTCOMES = frozenset(
    {
        CloudOperationOutcome.PREPARED.value,
        CloudOperationOutcome.SUBMITTING.value,
        CloudOperationOutcome.IN_PROGRESS.value,
        CloudOperationOutcome.AMBIGUOUS.value,
    }
)


@dataclass(frozen=True)
class CloudOperationPolicy:
    minimum_gap: float
    quiet_after: float


@dataclass(frozen=True)
class CloudOperationIntent:
    """Structured intent which is fsynced before its command is invoked."""

    operation_id: str
    transaction_id: str | None
    kind: str
    resource_ids: tuple[str, ...] = ()
    source_host: str | None = None
    destination_host: str | None = None
    availability_zone: str | None = None
    attempt: int = 1
    max_attempts: int = 1
    pre_state: Mapping[str, Any] = field(default_factory=dict)
    conflicts: tuple[str, ...] = ()


@dataclass
class CloudOperationTransaction:
    transaction_id: str
    kind: str
    description: str
    resource_ids: tuple[str, ...]
    source_host: str | None
    destination_host: str | None
    availability_zone: str | None
    attempt: int
    max_attempts: int
    pre_state: dict[str, Any]
    conflicts: tuple[str, ...]
    operation_ids: list[str] = field(default_factory=list)
    command_sequence: int = 0
    resolve_ambiguous_on_success: bool = True
    ambiguity_reason: str | None = None


@dataclass
class HostCloudOperationState:
    host: str
    last_server_boot: str | None = None
    last_server_delete: str | None = None
    last_migration_source: str | None = None
    last_migration_destination: str | None = None
    last_port_attachment: str | None = None
    last_port_detachment: str | None = None
    backoff_level: int = 0
    health: str = "healthy"
    quarantined: bool = False
    quarantine_reason: str | None = None
    quarantine_operation_id: str | None = None


class CloudOperationJournal:
    """Append-only journal with strict replay and fsync on every transition."""

    SCHEMA_VERSION = 1

    def __init__(self, reporter: Any):
        self.path: pathlib.Path | None = None
        self._lock = threading.RLock()
        self.latest: dict[str, dict[str, Any]] = {}
        self.host_states: dict[str, HostCloudOperationState] = {}
        self.scope = cloud_operation_scope()
        self.scope_fingerprint = cloud_operation_scope_fingerprint(self.scope)
        run_dir = getattr(reporter, "run_dir", None)
        if run_dir is None:
            return
        path = operation_journal_path(pathlib.Path(run_dir))
        if path.parent.is_symlink() or path.is_symlink():
            raise SuiteError(
                f"Cloud operation journal must not be a symbolic link: {path}"
            )
        self.path = path
        self._load()
        append_text(path, "")

    def _load(self) -> None:
        if self.path is None or not self.path.is_file():
            return
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise SuiteError(
                f"Could not read cloud operation journal {self.path}: {exc}"
            ) from exc
        for line_number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SuiteError(
                    f"Cloud operation journal {self.path} has invalid JSON on line "
                    f"{line_number}: {exc}"
                ) from exc
            if not isinstance(item, dict) or item.get("schema_version") != 1:
                raise SuiteError(
                    f"Cloud operation journal {self.path} line {line_number} is invalid"
                )
            if item.get("record_type") == "operation":
                operation_id = str(item.get("operation_id") or "")
                outcome = str(item.get("outcome") or "")
                if not operation_id or outcome not in {
                    member.value for member in CloudOperationOutcome
                }:
                    raise SuiteError(
                        f"Cloud operation journal {self.path} line {line_number} "
                        "contains an invalid operation"
                    )
                self.latest[operation_id] = normalize_operation_record(item)
            elif item.get("record_type") == "host-state":
                raw = item.get("state")
                try:
                    state = HostCloudOperationState(**raw)
                except (TypeError, AttributeError) as exc:
                    raise SuiteError(
                        f"Cloud operation journal {self.path} line {line_number} "
                        f"contains an invalid host state: {exc}"
                    ) from exc
                self.host_states[state.host] = state

    def append(self, item: dict[str, Any]) -> None:
        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "timestamp": iso_utc(),
            "scope": dict(self.scope),
            "scope_fingerprint": self.scope_fingerprint,
            **item,
        }
        encoded = (
            json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
            + "\n"
        )
        with self._lock:
            if self.path is not None:
                append_text(self.path, encoded)
            if payload.get("record_type") == "operation":
                self.latest[str(payload["operation_id"])] = payload
            elif payload.get("record_type") == "host-state":
                state = HostCloudOperationState(**payload["state"])
                self.host_states[state.host] = state

    def operation(
        self,
        intent: CloudOperationIntent,
        outcome: CloudOperationOutcome,
        *,
        command: Sequence[str],
        fingerprint: str,
        submitted: bool,
        accepted: bool | None,
        message: str,
        evidence: Mapping[str, Any] | None = None,
        duration_seconds: float | None = None,
    ) -> None:
        self.append(
            {
                "record_type": "operation",
                **asdict(intent),
                "outcome": outcome.value,
                "submitted": submitted,
                "accepted": accepted,
                "command": list(command),
                "command_fingerprint": fingerprint,
                "message": message,
                "evidence": dict(evidence or {}),
                "duration_seconds": duration_seconds,
            }
        )

    def host_state(self, state: HostCloudOperationState) -> None:
        self.append({"record_type": "host-state", "state": asdict(state)})


class CloudOperationCoordinator:
    """Global single-flight and at-most-once safety for disruptive operations."""

    # All coordinators in one Flux process share these locks.  This matters
    # when the top-level Suite and a multi-zone orchestrator coexist.
    _PROCESS_LOCK = threading.RLock()

    DEFAULT_POLICY = CloudOperationPolicy(minimum_gap=2.0, quiet_after=3.0)
    POLICIES: dict[str, CloudOperationPolicy] = {
        "port-create": CloudOperationPolicy(3.0, 3.0),
        "port-delete": CloudOperationPolicy(5.0, 8.0),
        "server-create": CloudOperationPolicy(5.0, 5.0),
        "server-delete": CloudOperationPolicy(5.0, 8.0),
        "server-lifecycle": CloudOperationPolicy(5.0, 5.0),
        "migration": CloudOperationPolicy(5.0, 5.0),
        "router-interface": CloudOperationPolicy(5.0, 5.0),
        "router-gateway": CloudOperationPolicy(5.0, 5.0),
        "router-cloud-operation": CloudOperationPolicy(5.0, 5.0),
        "floating-ip": CloudOperationPolicy(5.0, 5.0),
        "security-group-rule": CloudOperationPolicy(2.0, 3.0),
        "security-group": CloudOperationPolicy(3.0, 5.0),
        "network-topology": CloudOperationPolicy(3.0, 5.0),
        "volume": CloudOperationPolicy(3.0, 5.0),
        "keypair": CloudOperationPolicy(1.0, 1.0),
        "generic": DEFAULT_POLICY,
    }
    TRANSIENT_MARKERS = (
        "http 429",
        "http 500",
        "http 502",
        "http 503",
        "http 504",
        "service unavailable",
        "gateway timeout",
        "bad gateway",
        "temporarily unavailable",
        "connection reset",
        "connection timed out",
        "read timed out",
        "connect timeout",
        "connection refused",
        "remote end closed connection",
        "remote disconnected",
        "unexpected eof",
        "broken pipe",
        "network is unreachable",
        "no route to host",
    )

    def __init__(self, reporter: Any):
        self.reporter = reporter
        self.logger = reporter.logger
        config = getattr(reporter, "config", None)
        self.quiet_period_scale = pacing_scale(
            getattr(config, "quiet_period_scale", 1.0), "pacing.quiet_period_scale"
        )
        self.operation_gap_scale = pacing_scale(
            getattr(config, "operation_gap_scale", 1.0), "pacing.operation_gap_scale"
        )
        self.lock = self._PROCESS_LOCK
        self._cleanup_condition = threading.Condition(self.lock)
        self._local = threading.local()
        self._active_transactions: dict[str, CloudOperationTransaction] = {}
        self._sequence = 0
        self.placement_evidence: dict[
            tuple[Any, ...], tuple[int, float, dict[str, Any]]
        ] = {}
        self._last_completed_at = 0.0
        self._host_last_activity_at: dict[str, float] = {}
        self._adaptive_level = 0
        self._fast_successes = 0
        self.journal = CloudOperationJournal(reporter)
        self._latest = self.journal.latest
        self._host_states = self.journal.host_states
        self._quarantined_resources: dict[str, str] = {}
        self._external_unresolved: list[dict[str, Any]] = []
        self._external_replay_warnings: list[str] = []
        self._load_external_unresolved()
        self._reconcile_unsubmitted_prepared()
        self._restore_quarantine()
        reporter.cloud_operation_coordinator = self
        if self.quiet_period_scale != 1.0 or self.operation_gap_scale != 1.0:
            self.logger.log(
                f"Cloud operation pacing overrides: quiet-period scale={self.quiet_period_scale:g}, "
                f"operation-gap scale={self.operation_gap_scale:g}; "
                "error-backoff and final cleanup inventory-window floors are retained"
            )
            self._record(
                "cloud-operation-pacing",
                "Operator pacing overrides applied",
                quiet_period_scale=self.quiet_period_scale,
                operation_gap_scale=self.operation_gap_scale,
            )

    def _load_external_unresolved(self) -> None:
        config = getattr(self.reporter, "config", None)
        report_dir = getattr(config, "report_dir", None)
        if report_dir is None:
            return
        runs_dir = pathlib.Path(report_dir) / "runs"
        if not runs_dir.is_dir() or runs_dir.is_symlink():
            return
        current = self.journal.path
        current_scope = self.journal.scope_fingerprint
        valid_outcomes = {member.value for member in CloudOperationOutcome}
        for path in operation_journal_paths(runs_dir):
            if path == current or path.is_symlink() or path.parent.is_symlink():
                continue
            latest: dict[str, dict[str, Any]] = {}
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except OSError as exc:
                warning = (
                    f"could not replay historical cloud operation journal {path}: {exc}"
                )
                self._external_replay_warnings.append(warning)
                self.logger.log(warning, "WARNING")
                continue
            for line_number, line in enumerate(lines, 1):
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError as exc:
                    warning = (
                        f"ignored invalid historical cloud operation journal line "
                        f"{path}:{line_number}: {exc}"
                    )
                    self._external_replay_warnings.append(warning)
                    self.logger.log(warning, "WARNING")
                    continue
                if not isinstance(item, dict) or item.get("record_type") != "operation":
                    continue
                operation_id = str(item.get("operation_id") or "")
                outcome = str(item.get("outcome") or "")
                if not operation_id or outcome not in valid_outcomes:
                    warning = (
                        f"ignored invalid historical cloud operation at "
                        f"{path}:{line_number}"
                    )
                    self._external_replay_warnings.append(warning)
                    self.logger.log(warning, "WARNING")
                    continue
                record_scope = str(item.get("scope_fingerprint") or "")
                if record_scope and record_scope != current_scope:
                    continue
                latest[operation_id] = {
                    **normalize_operation_record(item),
                    "journal_path": str(path),
                }
            self._external_unresolved.extend(
                item
                for item in latest.values()
                if str(item.get("outcome")) in UNRESOLVED_CLOUD_OPERATION_OUTCOMES
                and not (
                    str(item.get("outcome")) == CloudOperationOutcome.PREPARED.value
                    and item.get("submitted") is False
                )
            )

    def _reconcile_unsubmitted_prepared(self) -> None:
        """Classify replayed PREPARED records that never reached submission."""
        for record in list(self._latest.values()):
            if (
                str(record.get("outcome")) != CloudOperationOutcome.PREPARED.value
                or record.get("submitted") is not False
            ):
                continue
            intent = self._intent_from_record(record)
            self._set_outcome(
                intent,
                CloudOperationOutcome.FAILED_RETRYABLE,
                command=tuple(record.get("command") or ()),
                fingerprint=str(record.get("command_fingerprint") or ""),
                submitted=False,
                accepted=False,
                message=(
                    "Journal replay proved the process stopped before command "
                    "submission began"
                ),
                evidence={"journal_replay": True, "callback_started": False},
            )

    def _restore_quarantine(self) -> None:
        records = [
            (operation_id, record) for operation_id, record in self._latest.items()
        ] + [
            (str(record.get("operation_id")), record)
            for record in self._external_unresolved
        ]
        for operation_id, record in records:
            if str(record.get("outcome")) not in UNRESOLVED_CLOUD_OPERATION_OUTCOMES:
                continue
            for resource_id in record.get("resource_ids") or ():
                self._quarantined_resources[str(resource_id)] = operation_id
            for host in (record.get("source_host"), record.get("destination_host")):
                if host:
                    self._quarantine_host(
                        str(host),
                        f"unresolved cloud operation {operation_id}",
                        operation_id,
                        persist=False,
                    )

    COMMAND_PHRASES = OpenStackCloudOperationCommand.COMMAND_PHRASES

    @staticmethod
    def classify_openstack_command(args: tuple[str, ...]) -> str | None:
        return OpenStackCloudOperationCommand.classify(args)

    @staticmethod
    def command_fingerprint(command: Sequence[str]) -> str:
        return OpenStackCloudOperationCommand.fingerprint(command)

    @staticmethod
    def _resource_ids_from_command(command: Sequence[str]) -> tuple[str, ...]:
        return OpenStackCloudOperationCommand.resource_ids(command)

    @classmethod
    def _transient_result(cls, result: Any) -> bool:
        text = "\n".join(
            str(item or "")
            for item in (
                getattr(result, "stderr", ""),
                getattr(result, "stdout", ""),
            )
        ).lower()
        return any(marker in text for marker in cls.TRANSIENT_MARKERS)

    @property
    def adaptive_factor(self) -> float:
        return (1.0, 1.5, 2.0, 4.0)[min(self._adaptive_level, 3)]

    @property
    def current_transaction(self) -> CloudOperationTransaction | None:
        return getattr(self._local, "transaction", None)

    def _policy(self, kind: str) -> CloudOperationPolicy:
        return self.POLICIES.get(kind, self.DEFAULT_POLICY)

    def _scaled_delay(
        self, seconds: float, scale: float, *, fresh: bool = False
    ) -> float:
        # Operator reductions apply to healthy routine pacing. Error recovery
        # and fresh inventory visibility windows retain their original floor.
        effective_scale = max(1.0, scale) if fresh or self._adaptive_level else scale
        return max(0.0, seconds) * effective_scale * self.adaptive_factor

    def _sleep(self, seconds: float, reason: str) -> None:
        remaining = max(0.0, seconds)
        if not remaining:
            return
        self.logger.log(f"Dataplane quiet period: {remaining:.1f}s — {reason}")
        with timed(self.reporter, "quiet-wait", reason):
            deadline = time.monotonic() + remaining
            while True:
                if cancellation_active():
                    raise_if_cancelled()
                left = deadline - time.monotonic()
                if left <= 0:
                    return
                time.sleep(min(0.25, left))

    def _record(self, event_type: str, message: str, **details: Any) -> None:
        event = getattr(self.reporter, "event", None)
        if callable(event):
            event(event_type, message, **details)

    def _next_operation_id(self, transaction: CloudOperationTransaction | None) -> str:
        if transaction is None:
            return f"cloud-operation-{uuid.uuid4().hex}"
        transaction.command_sequence += 1
        return (
            f"{transaction.transaction_id}-command-{transaction.command_sequence:02d}"
        )

    def _intent_for(self, kind: str, command: Sequence[str]) -> CloudOperationIntent:
        explicit = getattr(self._local, "intent", None)
        if explicit is not None:
            return explicit
        transaction = self.current_transaction
        operation_id = self._next_operation_id(transaction)
        if transaction is None:
            return CloudOperationIntent(
                operation_id,
                None,
                kind,
                resource_ids=self._resource_ids_from_command(command),
                conflicts=(kind,),
            )
        transaction.operation_ids.append(operation_id)
        return CloudOperationIntent(
            operation_id,
            transaction.transaction_id,
            kind,
            resource_ids=transaction.resource_ids
            or self._resource_ids_from_command(command),
            source_host=transaction.source_host,
            destination_host=transaction.destination_host,
            availability_zone=transaction.availability_zone,
            attempt=transaction.attempt,
            max_attempts=transaction.max_attempts,
            pre_state=transaction.pre_state,
            conflicts=transaction.conflicts,
        )

    def _unresolved_records(self) -> list[dict[str, Any]]:
        return [
            item
            for item in self._latest.values()
            if str(item.get("outcome")) in UNRESOLVED_CLOUD_OPERATION_OUTCOMES
        ] + list(self._external_unresolved)

    def unresolved_records(
        self, *, include_historical: bool = True
    ) -> list[dict[str, Any]]:
        with self.lock:
            records = (
                self._unresolved_records()
                if include_historical
                else [
                    item
                    for item in self._latest.values()
                    if str(item.get("outcome")) in UNRESOLVED_CLOUD_OPERATION_OUTCOMES
                ]
            )
            return [dict(item) for item in records]

    def current_transaction_records(self) -> list[dict[str, Any]]:
        transaction = self.current_transaction
        if transaction is None:
            return []
        with self.lock:
            return [
                dict(self._latest[operation_id])
                for operation_id in transaction.operation_ids
                if operation_id in self._latest
            ]

    def _assert_submission_allowed(
        self, intent: CloudOperationIntent, fingerprint: str, *, creating: bool = False
    ) -> None:
        previous = self._latest.get(intent.operation_id)
        if previous and previous.get("submitted"):
            raise CloudOperationBlockedError(
                f"Cloud operation {intent.operation_id} was already submitted; duplicate "
                "submission refused"
            )
        for record in self._unresolved_records():
            if record.get("operation_id") == intent.operation_id:
                continue
            same_transaction = (
                intent.transaction_id
                and record.get("transaction_id") == intent.transaction_id
            )
            same_command = record.get("command_fingerprint") == fingerprint
            globally_unsafe = record.get("outcome") in {
                CloudOperationOutcome.PREPARED.value,
                CloudOperationOutcome.SUBMITTING.value,
                CloudOperationOutcome.AMBIGUOUS.value,
            }
            if same_transaction:
                # A transaction may issue a distinct confirm/revert while it
                # reconciles an accepted operation, but never resubmit the same
                # ambiguous command.
                if same_command or (creating and globally_unsafe):
                    raise CloudOperationBlockedError(
                        "At-most-once protection refused a duplicate command or new create "
                        f"while cloud operation {record.get('operation_id')} remains "
                        f"{record.get('outcome')}"
                    )
                continue
            unresolved_migration = record.get("kind") == "migration"
            if same_command or globally_unsafe or unresolved_migration:
                raise CloudOperationBlockedError(
                    "A disruptive command cannot be submitted while cloud operation "
                    f"{record.get('operation_id')} remains "
                    f"{record.get('outcome')}"
                )
        for resource_id in intent.resource_ids:
            blocking = self._quarantined_resources.get(resource_id)
            blocking_record = self._latest.get(blocking or "", {})
            same_transaction = bool(
                intent.transaction_id
                and blocking_record.get("transaction_id") == intent.transaction_id
            )
            if blocking and blocking != intent.operation_id and not same_transaction:
                raise CloudOperationBlockedError(
                    f"Resource {resource_id} is quarantined by cloud operation {blocking}"
                )
        for host in (intent.source_host, intent.destination_host):
            state = self._host_states.get(str(host)) if host else None
            quarantine_record = (
                self._latest.get(state.quarantine_operation_id or "", {})
                if state is not None
                else {}
            )
            same_transaction = bool(
                intent.transaction_id
                and quarantine_record.get("transaction_id") == intent.transaction_id
            )
            if state is not None and state.quarantined and not same_transaction:
                raise CloudOperationBlockedError(
                    f"Host {host} is quarantined: "
                    f"{state.quarantine_reason or 'state unresolved'}"
                )
            if host:
                last_activity = self._host_last_activity_at.get(str(host), 0.0)
                required_gap = self._scaled_delay(
                    self._policy(intent.kind).minimum_gap, self.operation_gap_scale
                )
                elapsed = (
                    time.monotonic() - last_activity if last_activity else required_gap
                )
                if elapsed < required_gap:
                    self._sleep(
                        required_gap - elapsed,
                        f"per-host cooldown for {host} before {intent.kind}",
                    )

    def _set_outcome(
        self,
        intent: CloudOperationIntent,
        outcome: CloudOperationOutcome,
        *,
        command: Sequence[str],
        fingerprint: str,
        submitted: bool,
        accepted: bool | None,
        message: str,
        evidence: Mapping[str, Any] | None = None,
        duration_seconds: float | None = None,
    ) -> None:
        self.journal.operation(
            intent,
            outcome,
            command=command,
            fingerprint=fingerprint,
            submitted=submitted,
            accepted=accepted,
            message=message,
            evidence=evidence,
            duration_seconds=duration_seconds,
        )
        self._record(
            "cloud-operation-outcome",
            message,
            operation_id=intent.operation_id,
            transaction_id=intent.transaction_id,
            kind=intent.kind,
            outcome=outcome.value,
            accepted=accepted,
            resource_ids=list(intent.resource_ids),
            source_host=intent.source_host,
            destination_host=intent.destination_host,
            attempt=intent.attempt,
            max_attempts=intent.max_attempts,
            evidence=dict(evidence or {}),
        )
        if outcome == CloudOperationOutcome.AMBIGUOUS:
            for resource_id in intent.resource_ids:
                self._quarantined_resources[resource_id] = intent.operation_id
            for host in (intent.source_host, intent.destination_host):
                if host:
                    self._quarantine_host(
                        host,
                        f"cloud operation {intent.operation_id} outcome is ambiguous",
                        intent.operation_id,
                    )

    def _host_state(self, host: str) -> HostCloudOperationState:
        state = self._host_states.get(host)
        if state is None:
            state = HostCloudOperationState(host)
            self._host_states[host] = state
        return state

    def _quarantine_host(
        self,
        host: str,
        reason: str,
        operation_id: str,
        *,
        persist: bool = True,
    ) -> None:
        state = self._host_state(host)
        state.quarantined = True
        state.health = "quarantined"
        state.quarantine_reason = reason
        state.quarantine_operation_id = operation_id
        state.backoff_level = max(3, state.backoff_level)
        if persist:
            self.journal.host_state(state)
            self._record(
                "host-quarantined",
                f"Host {host} quarantined: {reason}",
                host=host,
                operation_id=operation_id,
                cloud_operation_outcome="HOST_QUARANTINED",
            )

    def _release_resolved_quarantine(self, intent: CloudOperationIntent) -> None:
        for resource_id in intent.resource_ids:
            if self._quarantined_resources.get(resource_id) == intent.operation_id:
                self._quarantined_resources.pop(resource_id, None)
        unresolved = self._unresolved_records()
        for host in (intent.source_host, intent.destination_host):
            if not host:
                continue
            still_blocked = any(
                host in {item.get("source_host"), item.get("destination_host")}
                for item in unresolved
            )
            state = self._host_states.get(host)
            if (
                not still_blocked
                and state
                and state.quarantine_operation_id == intent.operation_id
            ):
                state.quarantined = False
                state.health = "recovering"
                state.quarantine_reason = None
                state.quarantine_operation_id = None
                self.journal.host_state(state)

    def record_host_activity(self, kind: str, *hosts: str | None) -> None:
        field_by_kind = {
            "server-create": "last_server_boot",
            "server-delete": "last_server_delete",
            "port-create": "last_port_attachment",
            "port-delete": "last_port_detachment",
        }
        now = iso_utc()
        for index, host in enumerate(hosts):
            if not host:
                continue
            state = self._host_state(host)
            field_name = (
                "last_migration_source"
                if kind == "migration" and index == 0
                else "last_migration_destination"
                if kind == "migration"
                else field_by_kind.get(kind)
            )
            if field_name:
                setattr(state, field_name, now)
            self._host_last_activity_at[host] = time.monotonic()
            state.backoff_level = max(state.backoff_level, self._adaptive_level)
            self.journal.host_state(state)

    def cloud_operation_summary(self) -> dict[str, Any]:
        with self.lock:
            operations = [dict(item) for item in self._latest.values()]
            unresolved = [
                item
                for item in operations
                if str(item.get("outcome")) in UNRESOLVED_CLOUD_OPERATION_OUTCOMES
            ]
            external = [dict(item) for item in self._external_unresolved]
            quarantined_hosts = sorted(
                host for host, state in self._host_states.items() if state.quarantined
            )
            return {
                "journal": str(self.journal.path) if self.journal.path else None,
                "operations": operations,
                "unresolved_operation_ids": sorted(
                    str(item.get("operation_id")) for item in [*unresolved, *external]
                ),
                "unresolved_count": len(unresolved) + len(external),
                "quarantined_resources": dict(
                    sorted(self._quarantined_resources.items())
                ),
                "quarantined_hosts": quarantined_hosts,
                "external_unresolved_operations": external,
                "external_replay_warnings": list(self._external_replay_warnings),
                "scope_fingerprint": self.journal.scope_fingerprint,
                "hosts": {
                    host: asdict(state)
                    for host, state in sorted(self._host_states.items())
                },
            }

    def annotate_current_transaction(
        self,
        *,
        resource_ids: Sequence[str] | None = None,
        source_host: str | None = None,
        destination_host: str | None = None,
        availability_zone: str | None = None,
        attempt: int | None = None,
        pre_state: Mapping[str, Any] | None = None,
    ) -> None:
        """Attach resolved placement and baseline data before submission."""
        transaction = self.current_transaction
        if transaction is None:
            return
        if resource_ids is not None:
            transaction.resource_ids = tuple(str(item) for item in resource_ids if item)
        if source_host is not None:
            transaction.source_host = source_host
        if destination_host is not None:
            transaction.destination_host = destination_host
        if availability_zone is not None:
            transaction.availability_zone = availability_zone
        if attempt is not None:
            transaction.attempt = max(1, int(attempt))
        if pre_state is not None:
            transaction.pre_state.update(dict(pre_state))

    def keep_current_ambiguity(self, reason: str) -> None:
        """Keep a handled UNVERIFIED transaction from resolving as success."""
        transaction = self.current_transaction
        if transaction is None:
            return
        transaction.resolve_ambiguous_on_success = False
        transaction.ambiguity_reason = reason
        self._record(
            "cloud-operation-transaction-unverified",
            reason,
            transaction_id=transaction.transaction_id,
            kind=transaction.kind,
        )

    @contextmanager
    def operation(self, intent: CloudOperationIntent) -> Iterator[None]:
        if getattr(self._local, "intent", None) is not None:
            raise CloudOperationBlockedError(
                "Nested explicit cloud operation intents are invalid"
            )
        self._local.intent = intent
        try:
            yield
        finally:
            self._local.intent = None

    @contextmanager
    def transaction(
        self,
        kind: str,
        description: str,
        *,
        resource_ids: Sequence[str] = (),
        source_host: str | None = None,
        destination_host: str | None = None,
        availability_zone: str | None = None,
        attempt: int = 1,
        max_attempts: int = 1,
        pre_state: Mapping[str, Any] | None = None,
        conflicts: Sequence[str] = (),
        transaction_id: str | None = None,
        final_cooldown: float | None = None,
    ) -> Iterator[CloudOperationTransaction]:
        parent = self.current_transaction
        if parent is not None:
            yield parent
            return
        independent = kind in {"server-delete", "port-delete", "cleanup"}
        with (
            ACTIVITY.scope(
                exclusive=not independent, reporter=self.reporter, label=description
            ),
            ACTIVITY.resources(resource_ids),
        ):
            transaction = CloudOperationTransaction(
                transaction_id or f"{kind}-{uuid.uuid4().hex}",
                kind,
                description,
                tuple(str(item) for item in resource_ids if item),
                source_host,
                destination_host,
                availability_zone,
                max(1, int(attempt)),
                max(1, int(max_attempts)),
                dict(pre_state or {}),
                tuple(conflicts or (kind,)),
            )
            self._local.transaction = transaction
            started = time.monotonic()
            self._record(
                "cloud-operation-transaction-start",
                description,
                transaction_id=transaction.transaction_id,
                kind=kind,
                resource_ids=list(transaction.resource_ids),
                source_host=source_host,
                destination_host=destination_host,
                attempt=transaction.attempt,
                max_attempts=transaction.max_attempts,
            )
            try:
                with self.lock:
                    self._active_transactions[transaction.transaction_id] = transaction
                yield transaction
            except BaseException:
                with self.lock:
                    self._finalize_transaction(transaction, success=False)
                raise
            else:
                with self.lock:
                    self._finalize_transaction(transaction, success=True)
                if final_cooldown is not None and transaction.operation_ids:
                    self.settle(
                        kind,
                        f"verified final cooldown after {description}",
                        seconds=final_cooldown,
                    )
            finally:
                with self.lock:
                    self._active_transactions.pop(transaction.transaction_id, None)
                    self._cleanup_condition.notify_all()
                self._record(
                    "cloud-operation-transaction-finish",
                    description,
                    transaction_id=transaction.transaction_id,
                    kind=kind,
                    duration_seconds=round(time.monotonic() - started, 3),
                    unresolved_operation_ids=[
                        operation_id
                        for operation_id in transaction.operation_ids
                        if str(self._latest.get(operation_id, {}).get("outcome"))
                        in UNRESOLVED_CLOUD_OPERATION_OUTCOMES
                    ],
                    ambiguity_reason=transaction.ambiguity_reason,
                )
                self._local.transaction = None

    def _intent_from_record(self, record: Mapping[str, Any]) -> CloudOperationIntent:
        return CloudOperationIntent(
            str(record.get("operation_id")),
            record.get("transaction_id"),
            str(record.get("kind") or "generic"),
            tuple(record.get("resource_ids") or ()),
            record.get("source_host"),
            record.get("destination_host"),
            record.get("availability_zone"),
            int(record.get("attempt") or 1),
            int(record.get("max_attempts") or 1),
            record.get("pre_state") or {},
            tuple(record.get("conflicts") or ()),
        )

    def _finalize_transaction(
        self, transaction: CloudOperationTransaction, *, success: bool
    ) -> None:
        for operation_id in transaction.operation_ids:
            record = self._latest.get(operation_id)
            if not record:
                continue
            prior = str(record.get("outcome"))
            resolvable = prior == CloudOperationOutcome.IN_PROGRESS.value
            if (
                success
                and transaction.resolve_ambiguous_on_success
                and prior == CloudOperationOutcome.AMBIGUOUS.value
            ):
                resolvable = True
            if not resolvable:
                continue
            intent = self._intent_from_record(record)
            authoritative_success = success and transaction.resolve_ambiguous_on_success
            outcome = (
                CloudOperationOutcome.SUCCEEDED
                if authoritative_success
                else CloudOperationOutcome.AMBIGUOUS
            )
            self._set_outcome(
                intent,
                outcome,
                command=tuple(record.get("command") or ()),
                fingerprint=str(record.get("command_fingerprint") or ""),
                submitted=True,
                accepted=True,
                message=(
                    "Authoritative transaction validation completed"
                    if success
                    else (
                        "Transaction ended without authoritative completion "
                        "evidence after command acceptance"
                    )
                ),
                evidence={"transaction_id": transaction.transaction_id},
            )
            if outcome.value in TERMINAL_CLOUD_OPERATION_OUTCOMES:
                self._release_resolved_quarantine(intent)
        if success and transaction.resolve_ambiguous_on_success:
            self.record_host_activity(
                transaction.kind,
                transaction.source_host,
                transaction.destination_host,
            )

    @contextmanager
    def freeze(self, kind: str, description: str) -> Iterator[None]:
        """Protect measurement windows while independent creations converge."""
        exclusive = kind not in {"server-create", "port-create"}
        with ACTIVITY.scope(
            exclusive=exclusive, reporter=self.reporter, label=description
        ):
            depth = int(getattr(self._local, "freeze_depth", 0))
            self._local.freeze_depth = depth + 1
            if depth == 0:
                self._record(
                    "cloud-operation-freeze-start",
                    description,
                    kind=kind,
                    adaptive_level=self._adaptive_level,
                )
            try:
                yield
            finally:
                self._local.freeze_depth = depth
                if depth == 0:
                    self._record(
                        "cloud-operation-freeze-end",
                        description,
                        kind=kind,
                        adaptive_level=self._adaptive_level,
                    )

    @contextmanager
    def _submission_slot(self) -> Iterator[None]:
        with timed(
            self.reporter, "cloud-operation-queue", "cloud operation submission lock"
        ):
            while not self.lock.acquire(timeout=0.1):
                raise_if_cancelled()
        try:
            yield
        finally:
            self.lock.release()

    def execute(
        self,
        kind: str,
        command: tuple[str, ...],
        callback: Callable[[], T],
    ) -> T:
        policy = self._policy(kind)
        with (
            ACTIVITY.scope(reporter=self.reporter, label="cloud operation submission"),
            self._submission_slot(),
        ):
            intent = self._intent_for(kind, command)
            fingerprint = self.command_fingerprint(command)
            matched = OpenStackCloudOperationCommand._matched_command(command)
            self._assert_submission_allowed(
                intent,
                fingerprint,
                creating=bool(matched and matched[0][-1] == "create"),
            )
            self._set_outcome(
                intent,
                CloudOperationOutcome.PREPARED,
                command=command,
                fingerprint=fingerprint,
                submitted=False,
                accepted=False,
                message="Cloud operation intent durably recorded before submission",
            )
            elapsed = (
                time.monotonic() - self._last_completed_at
                if self._last_completed_at
                else 9999.0
            )
            required_gap = self._scaled_delay(
                policy.minimum_gap, self.operation_gap_scale
            )
            if elapsed < required_gap:
                self._sleep(required_gap - elapsed, f"spacing before {kind}")

            self._sequence += 1
            sequence = self._sequence
            command_text = "openstack " + shlex.join(command)
            started = time.monotonic()
            self.logger.log(
                f"Cloud operation {sequence} starting: operation_id="
                f"{intent.operation_id}, kind={kind}, command={command_text}"
            )
            self._record(
                "cloud-operation-start",
                command_text,
                sequence=sequence,
                operation_id=intent.operation_id,
                transaction_id=intent.transaction_id,
                kind=kind,
                adaptive_level=self._adaptive_level,
                minimum_gap_seconds=required_gap,
            )
            self._set_outcome(
                intent,
                CloudOperationOutcome.SUBMITTING,
                command=command,
                fingerprint=fingerprint,
                submitted=True,
                accepted=None,
                message="Command submission started",
            )
            success = False
            outcome = CloudOperationOutcome.AMBIGUOUS
            accepted: bool | None = None
            message = "Command returned no usable result"
            result_value: T | None = None
            try:
                result_value = callback()
                returncode = int(getattr(result_value, "returncode", 0) or 0)
                if returncode == 0:
                    success = True
                    accepted = True
                    outcome = (
                        CloudOperationOutcome.IN_PROGRESS
                        if self.current_transaction is not None
                        else CloudOperationOutcome.SUCCEEDED
                    )
                    message = (
                        "Command accepted; authoritative validation is in progress"
                        if outcome == CloudOperationOutcome.IN_PROGRESS
                        else "Command completed successfully"
                    )
                elif self._transient_result(result_value):
                    message = (
                        "Transient API/client failure left command acceptance unknown"
                    )
                else:
                    outcome = CloudOperationOutcome.COMMAND_REJECTED
                    accepted = False
                    message = str(
                        getattr(result_value, "stderr", "")
                        or getattr(result_value, "stdout", "")
                        or "command rejected"
                    ).strip()
                return result_value
            except (CommandTimeoutError, RunCancelledError) as exc:
                message = str(exc)
                raise
            except BaseException as exc:
                message = f"{type(exc).__name__}: {exc}"
                raise
            finally:
                duration = time.monotonic() - started
                previous_level = self._adaptive_level
                if outcome == CloudOperationOutcome.AMBIGUOUS or (
                    outcome == CloudOperationOutcome.COMMAND_REJECTED
                    and self._transient_result(result_value)
                ):
                    self._adaptive_level = min(3, self._adaptive_level + 1)
                    self._fast_successes = 0
                elif success and duration <= 10:
                    self._fast_successes += 1
                    if self._fast_successes >= 3 and self._adaptive_level > 0:
                        self._adaptive_level -= 1
                        self._fast_successes = 0
                else:
                    self._fast_successes = 0
                self._set_outcome(
                    intent,
                    outcome,
                    command=command,
                    fingerprint=fingerprint,
                    submitted=True,
                    accepted=accepted,
                    message=message,
                    evidence={
                        "returncode": (
                            int(getattr(result_value, "returncode", 0) or 0)
                            if result_value is not None
                            else None
                        )
                    },
                    duration_seconds=round(duration, 3),
                )
                quiet = self._scaled_delay(policy.quiet_after, self.quiet_period_scale)
                self._last_completed_at = time.monotonic()
                self._record(
                    "cloud-operation-finish",
                    command_text,
                    sequence=sequence,
                    operation_id=intent.operation_id,
                    transaction_id=intent.transaction_id,
                    kind=kind,
                    success=success,
                    outcome=outcome.value,
                    duration_seconds=round(duration, 3),
                    quiet_period_seconds=(
                        quiet if success and self.current_transaction is None else 0.0
                    ),
                    adaptive_level_before=previous_level,
                    adaptive_level_after=self._adaptive_level,
                )
                level = "INFO" if success else "WARNING"
                self.logger.log(
                    f"Cloud operation {sequence} finished: operation_id="
                    f"{intent.operation_id}, kind={kind}, outcome={outcome.value}, "
                    f"duration={duration:.1f}s, "
                    f"adaptive_level={self._adaptive_level}",
                    level,
                )
                if success and self.current_transaction is None:
                    self._sleep(quiet, f"after {kind} cloud operation {sequence}")

    def resolve(
        self,
        operation_id: str,
        outcome: CloudOperationOutcome,
        *,
        evidence: Mapping[str, Any],
        message: str,
    ) -> None:
        if outcome in {
            CloudOperationOutcome.PREPARED,
            CloudOperationOutcome.SUBMITTING,
        }:
            raise ValueError(f"{outcome.value} is not an authoritative resolution")
        with self.lock:
            record = self._latest.get(operation_id)
            external = False
            if record is None:
                record = next(
                    (
                        item
                        for item in self._external_unresolved
                        if str(item.get("operation_id")) == operation_id
                    ),
                    None,
                )
                external = record is not None
            if record is None:
                raise CloudOperationBlockedError(
                    f"Unknown cloud operation ID: {operation_id}"
                )
            intent = self._intent_from_record(record)
            if external:
                if outcome.value not in TERMINAL_CLOUD_OPERATION_OUTCOMES:
                    raise CloudOperationBlockedError(
                        "Historical cloud operation reconciliation requires a terminal outcome"
                    )
                journal_path = pathlib.Path(str(record.get("journal_path") or ""))
                if not journal_path.name:
                    raise CloudOperationBlockedError(
                        f"Historical cloud operation {operation_id} has no journal path"
                    )
                append_operation_resolution(
                    journal_path,
                    record,
                    outcome=outcome.value,
                    evidence=evidence,
                    message=message,
                )
                self._external_unresolved = [
                    item
                    for item in self._external_unresolved
                    if str(item.get("operation_id")) != operation_id
                ]
            else:
                self._set_outcome(
                    intent,
                    outcome,
                    command=tuple(record.get("command") or ()),
                    fingerprint=str(record.get("command_fingerprint") or ""),
                    submitted=bool(record.get("submitted")),
                    accepted=(
                        True
                        if outcome
                        in {
                            CloudOperationOutcome.SUCCEEDED,
                            CloudOperationOutcome.IN_PROGRESS,
                        }
                        else record.get("accepted")
                    ),
                    message=message,
                    evidence=evidence,
                )
            if outcome.value in TERMINAL_CLOUD_OPERATION_OUTCOMES:
                self._release_resolved_quarantine(intent)

    def cleanup_blocker(
        self,
        resource_id: str | None = None,
        *,
        wait_for_active: bool = False,
        timeout: float = 0.0,
    ) -> str | None:
        """Wait for owned cleanup work, preserving barriers for uncertain outcomes."""
        deadline = time.monotonic() + max(0.0, timeout)
        waiting_for = None
        with self._cleanup_condition:
            while True:
                blocked = self._cleanup_blocker_locked(resource_id)
                if blocked is None:
                    return None
                reason, record = blocked
                transaction = self._active_transactions.get(
                    str(record.get("transaction_id") or "")
                )
                affected = record.get("resource_ids") or ()
                can_wait = (
                    wait_for_active
                    and resource_id
                    and affected
                    and resource_id not in affected
                    and record.get("outcome") == CloudOperationOutcome.IN_PROGRESS.value
                    and record.get("accepted") is True
                    and transaction is not None
                    and transaction is not self.current_transaction
                    and transaction.kind in {"server-delete", "port-delete", "cleanup"}
                    and record.get("operation_id") in transaction.operation_ids
                    and transaction.resolve_ambiguous_on_success
                )
                if not can_wait:
                    return reason
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return f"cleanup wait expired; {reason}"
                if waiting_for != record.get("operation_id"):
                    waiting_for = record.get("operation_id")
                    self._record(
                        "cleanup-waiting-for-operation",
                        "Waiting for active cleanup in another worker before continuing resource deletion",
                        resource_id=resource_id,
                        operation_id=waiting_for,
                        outcome=record.get("outcome"),
                    )
                raise_if_cancelled()
                # Release the submission lock so the owning worker can finish
                # its remaining commands and authoritative absence checks.
                self._cleanup_condition.wait(min(0.1, remaining))

    def _cleanup_blocker_locked(
        self, resource_id: str | None
    ) -> tuple[str, dict[str, Any]] | None:
        with self.lock:
            if resource_id:
                operation_id = self._quarantined_resources.get(resource_id)
                if operation_id:
                    return (
                        f"resource is quarantined by unresolved cloud operation {operation_id}",
                        self._latest.get(operation_id, {}),
                    )
            for item in self._unresolved_records():
                kind = str(item.get("kind") or "")
                affected = tuple(
                    str(value) for value in (item.get("resource_ids") or ()) if value
                )
                transaction = self._active_transactions.get(
                    str(item.get("transaction_id") or "")
                )
                independent_delete = kind in {"server-delete", "port-delete"} or (
                    kind == "cleanup"
                    and tuple(item.get("command") or ())[:2] == ("volume", "delete")
                )
                # Accepted deletions owned by live workers may await absence
                # concurrently. A replayed, abandoned, ambiguous or unscoped
                # operation must retain the conservative cleanup barrier.
                if (
                    resource_id
                    and affected
                    and resource_id not in affected
                    and independent_delete
                    and item.get("outcome") == CloudOperationOutcome.IN_PROGRESS.value
                    and item.get("accepted") is True
                    and transaction is not None
                    and transaction.kind in {"server-delete", "port-delete", "cleanup"}
                    and item.get("operation_id") in transaction.operation_ids
                    and transaction.resolve_ambiguous_on_success
                ):
                    continue
                if resource_id and kind == "migration" and affected:
                    continue
                return (
                    f"cloud operation {item.get('operation_id')} ({kind or 'unknown'}) "
                    f"remains {item.get('outcome')}",
                    item,
                )
        return None

    def settle(
        self,
        kind: str,
        description: str,
        *,
        seconds: float | None = None,
        fresh: bool = False,
    ) -> float:
        """Credit elapsed convergence time; only inventory scans demand a new window."""
        policy = self._policy(kind)
        with self.lock:
            requested = self._scaled_delay(
                policy.quiet_after if seconds is None else seconds,
                self.quiet_period_scale,
                fresh=fresh,
            )
            elapsed = (
                max(0.0, time.monotonic() - self._last_completed_at)
                if self._last_completed_at and not fresh
                else 0.0
            )
            quiet = max(0.0, requested - elapsed)
            self._record(
                "dataplane-settlement",
                description,
                kind=kind,
                quiet_period_seconds=quiet,
                requested_seconds=requested,
                credited_seconds=min(requested, elapsed),
                fresh_window=fresh,
                adaptive_level=self._adaptive_level,
            )
        self._sleep(quiet, description)
        return quiet


__all__ = [
    "CloudOperationCoordinator",
    "HostCloudOperationState",
    "CloudOperationIntent",
    "CloudOperationOutcome",
    "CloudOperationPolicy",
    "CloudOperationTransaction",
    "TERMINAL_CLOUD_OPERATION_OUTCOMES",
    "UNRESOLVED_CLOUD_OPERATION_OUTCOMES",
]
