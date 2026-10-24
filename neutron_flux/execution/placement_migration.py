from __future__ import annotations

import dataclasses
import ipaddress
import math
import time
from collections.abc import Callable
from typing import Any

from ..cancellation import raise_if_cancelled
from ..check_plan import (
    migration_barrier_specs,
    migration_baseline_specs,
    migration_probe_spec,
)
from ..cloud_operation import CloudOperationOutcome
from ..constants import MIGRATION_DOWNTIME_TOLERANCE_NOTE
from ..continuity_phases import continuity_outage_bounds, partition_continuity
from ..engine import TestEngine
from ..errors import (
    AmbiguousCloudOperationError,
    PlacementUnavailableError,
    RetryableMigrationError,
    RunCancelledError,
    SuiteError,
    UnsafeMigrationStateError,
    UnverifiableMigrationError,
)
from ..migration_completion import migration_completion
from ..models import ComputeHostInfo, Endpoint, TestSpec


def _migration_validation_failures(
    migration_succeeded: bool | None,
    completion_proof: dict[str, Any] | None,
    completion_complete: bool,
    completion_consistent: bool,
    placement_verified: bool | None,
) -> list[str]:
    failures: list[str] = []
    if migration_succeeded is False and not (
        completion_proof is not None
        and completion_complete
        and not completion_consistent
    ):
        failed_checks = (
            migration_completion(completion_proof)["failed_checks"]
            if completion_proof is not None
            else []
        )
        names = {
            "port_binding_verified": "Neutron port validation",
            "volume_attachment_verified": "volume attachment validation",
            "guest_marker_verified": "guest disk marker validation",
            "endpoint_ready": "guest readiness validation",
        }
        nova_completed = bool(
            completion_consistent
            and (completion_proof or {}).get("migration_record_verified") is True
            and (completion_proof or {}).get("task_state_cleared") is True
            and placement_verified is True
        )
        failures.append(
            "Nova migration completed; post-migration validation failed: "
            + ", ".join(
                names.get(check, check.replace("_", " ")) for check in failed_checks
            )
            if nova_completed and failed_checks
            else "migration completion validation failed"
        )
    if placement_verified is False:
        failures.append("the migration did not verify the requested placement")
    return failures


def _continuity_observation(
    validation_failures: list[str], transport_failures: list[str], passable: bool
) -> str:
    if transport_failures:
        return "traffic-interrupted"
    if validation_failures:
        return "migration-validation-failed"
    return (
        "traffic-continuity-measured" if passable else "continuity-evidence-incomplete"
    )


class PlacementMigrationMixin:
    @staticmethod
    def _live_retry_backoff(seconds: int) -> None:
        for _ in range(seconds):
            raise_if_cancelled()
            time.sleep(1)

    def _execute_migration_attempts(
        self: Any,
        attempts: list[tuple[Endpoint, Endpoint, ComputeHostInfo]],
        *,
        migration_kind: str,
        submission_budget: int = 2,
        attempt_offset: int = 0,
        pre_submission_barrier: Callable[
            [int, str, Endpoint, Endpoint, ComputeHostInfo], bool
        ]
        | None = None,
    ) -> tuple[
        object | None,
        Endpoint | None,
        list[dict[str, object]],
        str | None,
        bool,
    ]:
        """Submit within the configured attempt budget, and retry only after authoritative failure."""
        result = None
        migrated_endpoint: Endpoint | None = None
        attempt_details: list[dict[str, object]] = []
        terminal_error: str | None = None
        all_unavailable = True
        if not attempts:
            return result, migrated_endpoint, attempt_details, terminal_error, True

        budget = max(1, int(submission_budget))
        selected = attempts[0]
        unsuitable_hosts: set[str] = set()
        submissions = 0
        while submissions < budget:
            moving, stationary, target = selected
            submissions += 1
            attempt_number = attempt_offset + submissions
            target_host = str(getattr(target, "host", "") or "")
            attempt: dict[str, object] = {
                "attempt": attempt_number,
                "submission_number": attempt_number,
                "effective_submission_budget": budget,
                "migration_kind": migration_kind,
                "endpoint": moving.label,
                "source_host": moving.host,
                "target_host": target_host,
                "stationary_peer": stationary.label,
                "stationary_host": stationary.host,
            }
            recovery_retry = bool(
                migration_kind == "live"
                and moving.metadata.get("_live_migration_retry", {}).get("target_host")
                == target_host
            )
            if recovery_retry:
                attempt["baseline"] = (
                    "original healthy baseline; fresh rollback and ownership checks required"
                )
            if (
                not recovery_retry
                and pre_submission_barrier is not None
                and not pre_submission_barrier(
                    attempt_number,
                    migration_kind,
                    moving,
                    stationary,
                    target,
                )
            ):
                barrier_result = next(
                    (
                        row
                        for row in reversed(self.reporter.results)
                        if row.scenario == "Compute migration safety barrier"
                        and row.details.get("submission_number") == attempt_number
                        and row.details.get("migration_kind") == migration_kind
                    ),
                    None,
                )
                attempt.update(
                    {
                        "status": "unverified-safety-barrier",
                        "cloud_operation_outcome": "NOT_SUBMITTED",
                        "retry_permitted": False,
                        "retry_reason": (
                            "fresh pre-migration connectivity checks did not pass"
                        ),
                        "message": (
                            "; ".join(barrier_result.details.get("failure_reasons", []))
                            or barrier_result.message
                            if barrier_result is not None
                            else "Fresh migration safety checks did not pass"
                        ),
                        "blocking_result_id": (
                            barrier_result.test_id
                            if barrier_result is not None
                            else None
                        ),
                    }
                )
                attempt_details.append(attempt)
                terminal_error = None
                break

            coordinator = getattr(self.builder, "cloud_operation_coordinator", None)
            if coordinator is not None:
                coordinator.annotate_current_transaction(
                    resource_ids=[
                        moving.server_id,
                        moving.management_port_id,
                        moving.test_port_id or "",
                    ],
                    source_host=moving.host,
                    destination_host=target_host,
                    availability_zone=target.availability_zone,
                    attempt=attempt_number,
                    pre_state={
                        "effective_submission_budget": budget,
                        "moving_endpoint": moving.label,
                        "stationary_endpoint": stationary.label,
                    },
                )
            self.logger.section(
                f"{migration_kind.title()} migration submission "
                f"{attempt_number}/{attempt_offset + budget}: "
                f"{moving.label} {moving.host} -> {target_host}"
            )
            try:
                if migration_kind == "live":
                    result = self.builder.live_migrate_endpoint(
                        moving, target, stationary
                    )
                else:
                    result = self.builder.cold_migrate_endpoint(moving, target)
            except AmbiguousCloudOperationError as exc:
                attempt.update(
                    {
                        "status": "ambiguous",
                        "cloud_operation_outcome": "AMBIGUOUS",
                        "retry_safe": False,
                        "retry_permitted": False,
                        "retry_reason": "command acceptance could not be proven",
                        "host_quarantined": True,
                        "message": str(exc),
                    }
                )
                attempt_details.append(attempt)
                all_unavailable = False
                terminal_error = str(exc)
                if coordinator is not None:
                    coordinator.keep_current_ambiguity(str(exc))
                break
            except UnverifiableMigrationError as exc:
                attempt.update(
                    {
                        "status": "unverified-safety-barrier",
                        "cloud_operation_outcome": "NOT_SUBMITTED",
                        "retry_safe": False,
                        "retry_permitted": False,
                        "message": str(exc),
                    }
                )
                attempt_details.append(attempt)
                terminal_error = None
                break
            except RetryableMigrationError as exc:
                attempt["status"] = "unavailable" if exc.unavailable else "failed"
                attempt["cloud_operation_outcome"] = (
                    "FAILED_RETRYABLE" if exc.proven_failure else "AMBIGUOUS"
                )
                attempt["retry_safe"] = bool(exc.proven_failure)
                attempt["retry_permitted"] = False
                attempt["accepted"] = exc.accepted
                attempt["target_unsuitable"] = exc.target_unsuitable
                attempt["evidence"] = exc.evidence
                attempt["message"] = str(exc)
                attempt_details.append(attempt)
                all_unavailable = all_unavailable and exc.unavailable
                if not exc.proven_failure:
                    terminal_error = str(exc)
                    attempt["host_quarantined"] = True
                    if coordinator is not None:
                        coordinator.keep_current_ambiguity(str(exc))
                    break

                if coordinator is not None:
                    records = coordinator.current_transaction_records()
                    if records:
                        latest = records[-1]
                        if latest.get("outcome") in {
                            "COMMAND_REJECTED",
                            "AMBIGUOUS",
                            "IN_PROGRESS",
                        }:
                            coordinator.resolve(
                                str(latest["operation_id"]),
                                CloudOperationOutcome.FAILED_RETRYABLE,
                                evidence=exc.evidence,
                                message=(
                                    "Authoritative evidence proved failure and "
                                    "the retry safety barrier passed"
                                ),
                            )

                next_selected = selected
                destination_changed = False
                if exc.target_unsuitable:
                    unsuitable_hosts.add(target_host)
                    next_selected = next(
                        (
                            candidate
                            for candidate in attempts
                            if str(getattr(candidate[2], "host", "") or "")
                            not in unsuitable_hosts
                        ),
                        selected,
                    )
                    destination_changed = next_selected is not selected
                    if not destination_changed:
                        attempt["retry_reason"] = (
                            "destination was proven unsuitable and no validated "
                            "alternate destination exists"
                        )
                        terminal_error = None if exc.unavailable else str(exc)
                        break

                retry_permitted = submissions < budget
                attempt["retry_permitted"] = retry_permitted
                attempt["retry_reason"] = (
                    "proven terminal failure; alternate destination was revalidated"
                    if destination_changed
                    else "proven terminal failure; retrying the same destination"
                )
                attempt["destination_reselected"] = destination_changed
                if not retry_permitted:
                    if exc.evidence.get("recovery_retry"):
                        moving.metadata.pop("_live_migration_retry", None)
                        attempt["cloud_operation_outcome"] = "FAILED_FINAL"
                        attempt["retry_reason"] = (
                            "live submission budget exhausted; guest recovery remains unverified"
                        )
                        if coordinator is not None:
                            records = coordinator.current_transaction_records()
                            if records:
                                coordinator.resolve(
                                    str(records[-1]["operation_id"]),
                                    CloudOperationOutcome.FAILED_FINAL,
                                    evidence=exc.evidence,
                                    message="Live retry budget exhausted after verified rollback",
                                )
                    terminal_error = None if all_unavailable else str(exc)
                    break
                selected = next_selected
                self.logger.log(
                    f"{migration_kind.title()} migration submission "
                    f"{attempt_number} failed with authoritative retry-safe "
                    f"evidence: {exc}",
                    "WARNING",
                )
                if migration_kind == "live":
                    backoff = min(60, 10 * submissions)
                    attempt["retry_backoff_seconds"] = backoff
                    self.reporter.event(
                        "live-migration-retry-backoff",
                        f"Waiting {backoff}s before live submission {attempt_number + 1}",
                        server_id=moving.server_id,
                        attempt=attempt_number,
                        backoff_seconds=backoff,
                    )
                    self._live_retry_backoff(backoff)
                continue
            except PlacementUnavailableError as exc:
                attempt.update(
                    {
                        "status": "unavailable",
                        "cloud_operation_outcome": "COMMAND_REJECTED",
                        "retry_safe": False,
                        "retry_permitted": False,
                        "message": str(exc),
                    }
                )
                attempt_details.append(attempt)
                self.logger.log(
                    f"{migration_kind.title()} migration target {target_host} was unavailable: {exc}",
                    "WARNING",
                )
                break
            except UnsafeMigrationStateError as exc:
                journal_outcome = None
                if coordinator is not None:
                    records = coordinator.current_transaction_records()
                    journal_outcome = (
                        str(records[-1].get("outcome")) if records else None
                    )
                ambiguous = journal_outcome in {"AMBIGUOUS", "IN_PROGRESS"}
                attempt.update(
                    {
                        "status": "ambiguous" if ambiguous else "unsafe",
                        "cloud_operation_outcome": (
                            "AMBIGUOUS"
                            if ambiguous
                            else "CONTROL_PLANE_DID_NOT_CONVERGE"
                        ),
                        "retry_safe": False,
                        "retry_permitted": False,
                        "host_quarantined": ambiguous,
                        "message": str(exc),
                    }
                )
                attempt_details.append(attempt)
                all_unavailable = False
                terminal_error = str(exc)
                if ambiguous and coordinator is not None:
                    coordinator.keep_current_ambiguity(str(exc))
                break
            except RunCancelledError:
                raise
            except SuiteError as exc:
                attempt.update(
                    {
                        "status": "failed",
                        "cloud_operation_outcome": "FAILED_FINAL",
                        "retry_safe": False,
                        "retry_permitted": False,
                        "message": str(exc),
                    }
                )
                attempt_details.append(attempt)
                all_unavailable = False
                terminal_error = str(exc)
                break

            completion = migration_completion(dataclasses.asdict(result))
            settlement = result.details.get("operation_settlement_assessment") or {}
            settled = completion["verified"] is True or (
                settlement.get("verified") is True
                and settlement.get("validation_status") == completion["status"]
            )
            attempt["status"] = (
                "succeeded"
                if completion["verified"] is True
                else "completion-unverified"
                if completion["verified"] is None
                else "validation-failed"
            )
            attempt["cloud_operation_outcome"] = "SUCCEEDED" if settled else "AMBIGUOUS"
            attempt["completion_assessment"] = completion
            if settlement:
                attempt["operation_settlement_assessment"] = settlement
            if coordinator is not None and not settled:
                coordinator.keep_current_ambiguity(
                    "Migration completion remains unverified; resubmission prohibited"
                )
            attempt["retry_safe"] = completion["verified"] is True
            attempt["retry_permitted"] = False
            attempt_details.append(attempt)
            migrated_endpoint = moving
            all_unavailable = False
            break
        return (
            result,
            migrated_endpoint,
            attempt_details,
            terminal_error,
            all_unavailable,
        )

    def _attempt_configured_migration(
        self: Any,
        *,
        dependencies: tuple[str, ...],
        source: Endpoint,
        destination: Endpoint,
        current_relation: str,
        desired_relation: str,
        desired_label: str,
        pre_submission_barrier: Callable[
            [int, str, Endpoint, Endpoint, ComputeHostInfo], bool
        ]
        | None = None,
    ) -> (
        tuple[
            TestSpec,
            object | None,
            Endpoint | None,
            list[dict[str, object]],
            list[tuple[Endpoint, Endpoint, ComputeHostInfo]],
            bool,
            str,
            str | None,
            bool,
        ]
        | None
    ):
        migration_mode = str(getattr(self.config, "migration_mode", "live-preferred"))
        live_requested = migration_mode in {"live-preferred", "live-only"}
        lifecycle = self._placement_control_spec(
            dependencies,
            source=source,
            destination=destination,
            kind=f"MIGRATION-{desired_label.upper()}",
            display_name=(
                f"Create {desired_label} placement using the configured migration strategy — "
                f"{source.label} / {destination.label}"
            ),
            scenario=(
                "Cold migration lifecycle"
                if migration_mode == "cold-only"
                else "Compute migration and placement lifecycle"
            ),
            expectation="placement-achieved",
        )
        live_capability = (
            self._placement_control_spec(
                dependencies,
                source=source,
                destination=destination,
                kind=f"LIVE-MIGRATION-{desired_label.upper()}",
                display_name=(
                    f"Live-migrate an endpoint into {desired_label} placement — "
                    f"{source.label} / {destination.label}"
                ),
                scenario="Live migration capability",
                expectation="live-migration-complete",
            )
            if live_requested
            else None
        )
        self._append_runtime_specs(
            [lifecycle, *([live_capability] if live_capability is not None else [])]
        )

        maximum_attempts = self.config.migration_submission_budget
        attempts, selection_reason = self._compute_migration_attempts(
            source,
            destination,
            desired_relation=desired_relation,
            maximum_attempts=maximum_attempts,
        )
        if not attempts:
            message = (
                f"Could not create {desired_label} coverage: {selection_reason}. "
                f"The existing {current_relation} placement was still fully tested."
            )
            if live_capability is not None:
                self.reporter.result(
                    live_capability.id,
                    live_capability.category,
                    "UNVERIFIED",
                    message,
                    source=destination.host,
                    destination=source.host if desired_relation == "same" else None,
                    expected=live_capability.expectation,
                    observed="placement-unavailable",
                    authoritative=True,
                    details={
                        "current_relation": current_relation,
                        "desired_relation": desired_label,
                        "availability_zone": destination.availability_zone,
                        "maximum_attempts": maximum_attempts,
                    },
                    display_name=live_capability.display_name,
                    scenario=live_capability.scenario,
                )
            self.reporter.result(
                lifecycle.id,
                lifecycle.category,
                "UNVERIFIED",
                message,
                source=destination.host,
                destination=source.host if desired_relation == "same" else None,
                expected=lifecycle.expectation,
                observed="placement-unavailable",
                authoritative=True,
                details={
                    "current_relation": current_relation,
                    "desired_relation": desired_label,
                    "availability_zone": destination.availability_zone,
                    "maximum_attempts": maximum_attempts,
                    "migration_mode": migration_mode,
                },
                display_name=lifecycle.display_name,
                scenario=lifecycle.scenario,
            )
            return

        result = None
        migrated_endpoint: Endpoint | None = None
        attempt_details: list[dict[str, object]] = []
        terminal_error: str | None = None
        all_unavailable = True
        fallback_used = False
        live_attempt_details: list[dict[str, object]] = []
        live_terminal_error: str | None = None
        live_all_unavailable = True
        fallback_enabled = bool(
            migration_mode == "live-preferred"
            and getattr(self.config, "cold_migration_fallback", True)
        )

        if live_requested:
            (
                result,
                migrated_endpoint,
                live_attempt_details,
                live_terminal_error,
                live_all_unavailable,
            ) = self._execute_migration_attempts(
                attempts,
                migration_kind="live",
                submission_budget=max(1, int(self.config.live_migration_attempts)),
                pre_submission_barrier=pre_submission_barrier,
            )
            attempt_details.extend(live_attempt_details)
            terminal_error = live_terminal_error
            all_unavailable = live_all_unavailable

            if result is not None and migrated_endpoint is not None:
                recovery_checks = (
                    result.port_binding_verified,
                    result.migration_record_verified,
                    result.volume_attachment_verified,
                    result.guest_marker_verified,
                    result.endpoint_ready,
                )
                recovery_incomplete = bool(
                    result.details.get("recovery_retry")
                    and any(value is not True for value in recovery_checks)
                )
                completion = migration_completion(dataclasses.asdict(result))
                self.reporter.result(
                    live_capability.id,
                    live_capability.category,
                    "FAIL" if recovery_incomplete else completion["status"],
                    (
                        f"Live migration moved {migrated_endpoint.label} from "
                        f"{result.source_host} to {result.destination_host} using "
                        f"{('block live migration' if getattr(self.config, 'effective_migration_storage', 'auto') == 'host' else 'shared/volume-backed live migration')} "
                        f"(boot_storage={getattr(self.config, 'storage', 'unknown')}, "
                        f"configured_migration_storage={getattr(self.config, 'migration_storage', 'auto')}, "
                        f"effective_migration_storage={getattr(self.config, 'effective_migration_storage', 'auto')})"
                        + (
                            "; recovery retry moved the VM but final endpoint validation did not pass"
                            if recovery_incomplete
                            else ""
                        )
                    ),
                    source=result.source_host,
                    destination=result.destination_host,
                    expected=live_capability.expectation,
                    observed=(
                        "migration-validation-failed"
                        if recovery_incomplete
                        else "live-migration-complete"
                        if completion["verified"] is True
                        else "migration-completion-unverified"
                        if completion["verified"] is None
                        else "migration-validation-failed"
                    ),
                    authoritative=True,
                    details={
                        **dataclasses.asdict(result),
                        "attempts": live_attempt_details,
                        "completion_assessment": completion,
                    },
                    display_name=live_capability.display_name,
                    scenario=live_capability.scenario,
                )
            elif (
                fallback_enabled
                and live_attempt_details
                and live_attempt_details[-1].get("cloud_operation_outcome")
                == "FAILED_RETRYABLE"
            ):
                from ..failure_injection import inject_failure

                last_live = live_attempt_details[-1]
                rejected_hosts = {
                    str(item.get("target_host") or "")
                    for item in live_attempt_details
                    if item.get("target_unsuitable")
                }
                if rejected_hosts:
                    failed_host = str(last_live.get("target_host") or "")
                    alternate = next(
                        (
                            candidate
                            for candidate in attempts
                            if str(getattr(candidate[2], "host", "") or "")
                            not in rejected_hosts
                        ),
                        None,
                    )
                    cold_attempts = [alternate] if alternate is not None else []
                    cold_reason = (
                        "validated reverse direction selected after "
                        f"{failed_host or 'the selected host'} was proven unsuitable"
                        if alternate is not None
                        else "No separately validated destination remained after "
                        f"{failed_host or 'the selected host'} was proven unsuitable"
                    )
                else:
                    cold_attempts = [attempts[0]]
                    cold_reason = "eligible"
                fallback_live_status = "UNVERIFIED" if live_all_unavailable else "FAIL"
                if cold_attempts:
                    cold_target = str(
                        getattr(cold_attempts[0][2], "host", "") or "unknown"
                    )
                    live_message = (
                        f"Live migration did not complete after {len(live_attempt_details)} "
                        "safe attempt(s); Flux will attempt the configured cold-"
                        f"migration fallback on validated target {cold_target}"
                    )
                    live_observed = "cold-fallback-required"
                else:
                    live_message = (
                        f"Live migration did not complete after {len(live_attempt_details)} "
                        "safe attempt(s), and the configured cold-migration fallback "
                        f"could not be submitted safely: {cold_reason}"
                    )
                    live_observed = "cold-fallback-unavailable"
                self.reporter.result(
                    live_capability.id,
                    live_capability.category,
                    fallback_live_status,
                    live_message,
                    source=destination.host,
                    destination=source.host if desired_relation == "same" else None,
                    expected=live_capability.expectation,
                    observed=live_observed,
                    authoritative=True,
                    details={
                        "health": (
                            "warning"
                            if fallback_live_status == "UNVERIFIED"
                            else "critical"
                        ),
                        "migration_mode": migration_mode,
                        "storage_mode": getattr(
                            self.config, "effective_migration_storage", "auto"
                        ),
                        "configured_storage_mode": getattr(
                            self.config, "migration_storage", "auto"
                        ),
                        "live_attempts": live_attempt_details,
                        "cold_fallback": {
                            "available": bool(cold_attempts),
                            "reason": cold_reason,
                            "moving_endpoint": (
                                cold_attempts[0][0].label if cold_attempts else None
                            ),
                            "target_host": (
                                str(getattr(cold_attempts[0][2], "host", "") or "")
                                if cold_attempts
                                else None
                            ),
                        },
                    },
                    display_name=live_capability.display_name,
                    scenario=live_capability.scenario,
                )
                if cold_attempts:
                    inject_failure(self.config, "before-cold-fallback")
                    (
                        result,
                        migrated_endpoint,
                        cold_details,
                        terminal_error,
                        all_unavailable,
                    ) = self._execute_migration_attempts(
                        cold_attempts,
                        migration_kind="cold",
                        submission_budget=1,
                        attempt_offset=len(live_attempt_details),
                        pre_submission_barrier=pre_submission_barrier,
                    )
                    attempt_details.extend(cold_details)
                    fallback_used = result is not None and migrated_endpoint is not None
                else:
                    terminal_error = None
                    all_unavailable = True
                    attempt_details.append(
                        {
                            "migration_kind": "cold",
                            "status": "unavailable",
                            "retry_safe": True,
                            "message": cold_reason,
                        }
                    )
            elif live_capability is not None:
                not_submitted = bool(live_attempt_details) and all(
                    item.get("cloud_operation_outcome") == "NOT_SUBMITTED"
                    for item in live_attempt_details
                )
                live_status = (
                    "UNVERIFIED"
                    if live_all_unavailable and live_terminal_error is None
                    else "FAIL"
                )
                self.reporter.result(
                    live_capability.id,
                    live_capability.category,
                    live_status,
                    (
                        "Live migration was not submitted: "
                        + str(
                            live_attempt_details[-1].get("message")
                            or "Migration safety checks did not pass"
                        )
                        if not_submitted
                        else f"Live migration did not complete after {len(live_attempt_details)} "
                        f"attempt(s)"
                        + (
                            f"; retries stopped because {live_terminal_error}"
                            if live_terminal_error
                            else ""
                        )
                    ),
                    source=destination.host,
                    destination=source.host if desired_relation == "same" else None,
                    expected=live_capability.expectation,
                    observed=(
                        "fresh-functional-baseline-unavailable"
                        if not_submitted
                        else "live-migration-failed"
                    ),
                    authoritative=True,
                    details={
                        "migration_mode": migration_mode,
                        "storage_mode": getattr(
                            self.config, "effective_migration_storage", "auto"
                        ),
                        "configured_storage_mode": getattr(
                            self.config, "migration_storage", "auto"
                        ),
                        "attempts": live_attempt_details,
                        **(
                            {
                                "cloud_operation_outcome": "NOT_SUBMITTED",
                                "lifecycle_cloud_operation_performed": False,
                            }
                            if not_submitted
                            else {}
                        ),
                    },
                    display_name=live_capability.display_name,
                    scenario=live_capability.scenario,
                )
        else:
            (
                result,
                migrated_endpoint,
                attempt_details,
                terminal_error,
                all_unavailable,
            ) = self._execute_migration_attempts(
                attempts,
                migration_kind="cold",
                submission_budget=maximum_attempts,
                pre_submission_barrier=pre_submission_barrier,
            )

        return (
            lifecycle,
            result,
            migrated_endpoint,
            attempt_details,
            attempts,
            fallback_used,
            migration_mode,
            terminal_error,
            all_unavailable,
        )

    @staticmethod
    def _live_continuity_verdict(
        continuity: dict[str, object],
    ) -> tuple[str, str, str, dict[str, object]]:
        if continuity.get("available") is not True:
            return (
                "UNVERIFIED",
                "continuity-evidence-unavailable",
                str(
                    continuity.get("reason")
                    or "The guest continuity monitor was unavailable"
                ),
                {**continuity, "health": "warning", "evidence_complete": False},
            )
        icmp = continuity.get("icmp") or {}
        tcp = continuity.get("tcp") or {}
        udp = continuity.get("udp") or {}
        thresholds = continuity.get("thresholds") or {}
        if not isinstance(icmp, dict):
            icmp = {}
        if not isinstance(tcp, dict):
            tcp = {}
        if not isinstance(udp, dict):
            udp = {}
        if not isinstance(thresholds, dict):
            thresholds = {}
        udp_response = udp.get("response") or {}
        if not isinstance(udp_response, dict):
            udp_response = {}

        def finite_loss(value: object) -> float | None:
            try:
                parsed = float(value)
            except (TypeError, ValueError):
                return None
            return parsed if math.isfinite(parsed) and 0.0 <= parsed <= 100.0 else None

        def finite_nonnegative(value: object, default: float) -> float:
            try:
                parsed = float(value)
            except (TypeError, ValueError):
                return default
            return parsed if math.isfinite(parsed) and parsed >= 0.0 else default

        migration_value = continuity.get("migration_succeeded")
        migration_succeeded = migration_value if type(migration_value) is bool else None
        tcp_survived = tcp.get("survived") is True
        tcp_connected = tcp.get("connected") is True
        receiver = tcp.get("server_result") or {}
        if not isinstance(receiver, dict):
            receiver = {}
        sent_bytes, received_bytes = tcp.get("bytes_sent"), receiver.get("bytes")
        delivery_evidence = (
            type(sent_bytes) is int
            and sent_bytes > 0
            and type(received_bytes) is int
            and received_bytes > 0
            and received_bytes == sent_bytes
        )
        delivery_mismatch = (
            type(sent_bytes) is int
            and type(received_bytes) is int
            and (sent_bytes <= 0 or received_bytes != sent_bytes)
        )
        udp_sent, udp_received = udp.get("sent"), udp_response.get("received")
        udp_counts_valid = (
            type(udp_sent) is int
            and udp_sent > 0
            and type(udp_received) is int
            and 0 <= udp_received <= udp_sent
            and udp_response.get("sent") == udp_sent
            and type(udp.get("session_id")) is int
            and udp_response.get("session_id") == udp.get("session_id")
        )
        udp_last = udp_response.get("max_sequence")
        udp_sequence_valid = (
            udp_counts_valid
            and type(udp_last) is int
            and (-1 <= udp_last < udp_sent)
            and (udp_received == 0 or udp_last >= 0)
        )
        raw_icmp_total = icmp.get("samples", icmp.get("total"))
        try:
            icmp_total = int(raw_icmp_total or 0)
        except (TypeError, ValueError):
            icmp_total = 0
        try:
            icmp_lost = int(icmp.get("lost") or 0)
        except (TypeError, ValueError):
            icmp_lost = 0
        icmp_loss = finite_loss(icmp.get("loss_pct"))
        udp_loss = finite_loss(udp_response.get("loss_pct"))
        outage = icmp.get("outage") or {}
        if not isinstance(outage, dict):
            outage = {}
        outage_lower = finite_nonnegative(
            outage.get("outage_lower_bound_s", icmp.get("longest_outage_s")), 0.0
        )
        outage_upper = finite_nonnegative(
            outage.get("outage_upper_bound_s"), outage_lower
        )
        try:
            failed_observations = int(outage.get("failed_observations") or 0)
        except (TypeError, ValueError):
            failed_observations = 0

        icmp_limit = finite_nonnegative(thresholds.get("icmp_loss_pct"), 0.0)
        udp_limit = finite_nonnegative(thresholds.get("udp_loss_pct"), 1.0)
        outage_limit = finite_nonnegative(thresholds.get("outage_lower_bound_s"), 1.0)
        full_window = continuity.get("full_migration_window") is True
        ready = continuity.get("ready_before_migration") is True
        sampling_complete = continuity.get("sampling_complete") is True

        raw_samples = icmp.get("raw_samples") or []
        if not isinstance(raw_samples, list):
            raw_samples = []
        usable_samples = [
            item
            for item in raw_samples
            if isinstance(item, dict) and isinstance(item.get("ok"), bool)
        ]
        icmp_recovered = usable_samples[-1]["ok"] if usable_samples else None
        # The last sequenced datagram must be close to the end of observation;
        # a final statistics control reply cannot disguise a dead data stream.
        trailing_udp_seconds = (
            max(0, udp_sent - 1 - udp_last) * 0.05 if udp_sequence_valid else None
        )
        udp_recovered = (
            udp_received > 0 and trailing_udp_seconds <= outage_limit
            if udp_sequence_valid
            else None
        )
        connectivity_recovered = (
            False
            if icmp_recovered is False or udp_recovered is False
            else True
            if icmp_recovered is True and udp_recovered is True
            else None
        )
        recovery_basis = (
            "independent final ICMP and receiver-side UDP sequence evidence"
        )
        udp_loss_consistent = bool(
            udp_counts_valid
            and udp_loss is not None
            and abs(udp_loss - ((udp_sent - udp_received) * 100.0 / udp_sent)) < 0.001
        )
        icmp_counts_consistent = bool(
            icmp_total > 0
            and len(usable_samples) == icmp_total
            and sum(not sample["ok"] for sample in usable_samples) == icmp_lost
            and icmp_loss is not None
            and abs(icmp_loss - icmp_lost * 100.0 / icmp_total) < 0.001
        )
        target_id = continuity.get("target_server_id")
        target_ip = continuity.get("target_fixed_ip")
        ready_identity = tcp.get("receiver_identity")
        if not isinstance(ready_identity, dict):
            ready_identity = {}

        def known_text(value: object) -> bool:
            return isinstance(value, str) and bool(value.strip())

        def same_address(left: object, right: object) -> bool:
            if not isinstance(left, str) or not isinstance(right, str):
                return False
            if not left.strip() or not right.strip():
                return False
            try:
                return ipaddress.ip_address(left) == ipaddress.ip_address(right)
            except ValueError:
                return False

        target_known = known_text(target_id) and same_address(target_ip, target_ip)
        live_identity_valid = bool(
            target_known
            and tcp.get("identity_verified") is True
            and udp.get("identity_verified") is True
            and receiver.get("probe_id") == target_id
            and udp_response.get("probe_id") == target_id
            and same_address(receiver.get("local_ip"), target_ip)
            and same_address(udp_response.get("local_ip"), target_ip)
            and known_text(receiver.get("instance_id"))
            and receiver.get("instance_id") == udp_response.get("instance_id")
            and known_text(receiver.get("token"))
            and ready_identity.get("token") == receiver.get("token")
        )
        route_proofs = [
            continuity.get(key) for key in ("data_path_before", "data_path_after")
        ]
        routes_verified = all(
            isinstance(proof, dict) and proof.get("verified") is True
            for proof in route_proofs
        )
        evidence_complete = bool(
            migration_succeeded is True
            and ready
            and sampling_complete
            and tcp_connected
            and delivery_evidence
            and tcp.get("terminal") is True
            and udp.get("terminal") is True
            and continuity.get("workers_complete") is True
            and icmp_total > 0
            and icmp_loss is not None
            and udp_loss_consistent
            and udp_sequence_valid
            and full_window
            and icmp_counts_consistent
            and live_identity_valid
            and routes_verified
        )
        phase_evidence = continuity.get("phase_evidence")
        phase_evidence = phase_evidence if isinstance(phase_evidence, dict) else {}
        phase_required = continuity.get("measurement_phase_contract") == 1
        phase_complete = not phase_required
        if phase_required:
            # Recompute partitions from launch/send times and receiver bitmap.
            # A caller-supplied 'verified' flag or filtered summary is not proof.
            reconstructed = partition_continuity(
                {
                    "readiness": continuity.get("readiness"),
                    "observation_duration_s": continuity.get("observation_duration_s"),
                    "icmp": phase_evidence.get("raw_icmp_observations"),
                    "udp": udp,
                },
                {
                    "phase_markers_required": True,
                    "phase_markers": continuity.get("phase_markers"),
                },
                continuity_outage_bounds,
                sample_interval_s=finite_nonnegative(
                    thresholds.get("sample_interval_s"), 0.25
                ),
            )
            protected = reconstructed["phases"].get("protected", {})
            rebuilt_icmp = protected.get("icmp", {})
            rebuilt_udp = protected.get("udp", {})
            phase_complete = bool(
                reconstructed["verified"] is True
                and usable_samples == rebuilt_icmp.get("raw_samples")
                and icmp_total == rebuilt_icmp.get("samples")
                and icmp_lost == rebuilt_icmp.get("lost")
                and icmp_loss == rebuilt_icmp.get("loss_pct")
                and outage == rebuilt_icmp.get("outage")
                and udp.get("protected_measurement") == rebuilt_udp
            )
            # Always grade actual reconstructed observations, never fabricated
            # summaries. Missing timing stays unverified; raw evidence is kept.
            if rebuilt_icmp:
                icmp_total = rebuilt_icmp["samples"]
                icmp_lost = rebuilt_icmp["lost"]
                icmp_loss = finite_loss(rebuilt_icmp["loss_pct"])
                outage = rebuilt_icmp["outage"]
                outage_lower = outage["outage_lower_bound_s"]
                outage_upper = outage["outage_upper_bound_s"]
                failed_observations = outage["failed_observations"]
            udp_loss = finite_loss(rebuilt_udp.get("loss_pct"))
        tolerance_complete = bool(
            phase_complete
            and full_window
            and ready
            and sampling_complete
            and icmp_counts_consistent
            and udp_loss_consistent
            and udp_sequence_valid
        )
        completion_proof = continuity.get("migration_completion_evidence")
        completion_proof = (
            completion_proof if isinstance(completion_proof, dict) else {}
        )
        completion_detail = continuity.get("completion_assessment")
        completion_detail = (
            completion_detail if isinstance(completion_detail, dict) else {}
        )
        completion_checks = completion_detail.get("checks")
        completion_checks = (
            completion_checks if isinstance(completion_checks, dict) else {}
        )
        placement_verified = completion_checks.get("placement_verified")
        if placement_verified is None and completion_proof:
            placement_verified = migration_completion(completion_proof)["checks"][
                "placement_verified"
            ]
        proof_supplied = "migration_completion_evidence" in continuity
        completion_consistent = True
        completion_complete = True
        if proof_supplied:
            rebuilt_completion = migration_completion(completion_proof)
            completion_complete = rebuilt_completion["verified"] is True
            completion_consistent = bool(
                completion_proof
                and migration_succeeded is rebuilt_completion["verified"]
                and (
                    not known_text(continuity.get("moving_server_id"))
                    or completion_proof.get("server_id")
                    == continuity["moving_server_id"]
                )
                and (
                    "verified" not in completion_detail
                    or completion_detail["verified"] is rebuilt_completion["verified"]
                )
                and all(
                    key in rebuilt_completion["checks"]
                    and value is rebuilt_completion["checks"][key]
                    for key, value in completion_checks.items()
                )
            )
            placement_verified = placement_verified if completion_consistent else None
        evidence_complete = bool(
            evidence_complete
            and phase_complete
            and placement_verified is True
            and completion_complete
            and completion_consistent
        )
        validation_failure_reasons = _migration_validation_failures(
            migration_succeeded,
            completion_proof if proof_supplied else None,
            completion_complete,
            completion_consistent,
            placement_verified,
        )
        transport_failure_reasons: list[str] = []
        advisories: list[str] = []
        if any(
            isinstance(proof, dict) and proof.get("verified") is False
            for proof in route_proofs
        ):
            validation_failure_reasons.append(
                "continuity selected an interface other than the declared data port"
            )
        if delivery_mismatch:
            transport_failure_reasons.append(
                "TCP receiver delivery did not match the original stream"
            )
        if tcp.get("error") and tcp_survived:
            transport_failure_reasons.append(
                "TCP survival claim conflicts with a recorded stream error"
            )
        if udp.get("error"):
            transport_failure_reasons.append(
                "UDP continuity failed: " + str(udp["error"])
            )
        if tcp_connected and not tcp_survived:
            transport_failure_reasons.append(
                "the established TCP session did not complete"
                + (f": {tcp['error']}" if tcp.get("error") else "")
            )
        if connectivity_recovered is False:
            transport_failure_reasons.append(
                "connectivity had not recovered when continuity monitoring ended"
            )
        failure_reasons = validation_failure_reasons + transport_failure_reasons
        tolerance_reasons: list[str] = []
        if icmp_loss is not None and icmp_loss > icmp_limit:
            tolerance_reasons.append(
                f"ICMP failed observations {icmp_loss:.2f}% exceeded {icmp_limit:.2f}%"
            )
        if udp_loss is not None and udp_loss > udp_limit:
            tolerance_reasons.append(
                f"sequenced UDP application-delivery loss {udp_loss:.2f}% "
                f"exceeded {udp_limit:.2f}%"
            )
        if outage_lower > outage_limit:
            tolerance_reasons.append(
                f"sampled failed-observation span {outage_lower:.3f}s exceeded "
                f"{outage_limit:.3f}s"
            )

        if (
            not failure_reasons
            and not tolerance_reasons
            and ((icmp_loss or 0.0) > 0 or (udp_loss or 0.0) > 0)
        ):
            advisories.append(
                "transient failed observations or UDP delivery loss remained within the declared limits"
            )
        critical = bool(failure_reasons)
        passable = bool(
            evidence_complete and tcp_survived and connectivity_recovered is True
        )
        status = "FAIL" if critical else "PASS" if passable else "UNVERIFIED"
        interruption_observations = tolerance_reasons if status == "PASS" else []
        observed = _continuity_observation(
            validation_failure_reasons, transport_failure_reasons, passable
        )
        outage_text = (
            f"{failed_observations} consecutive failed observation(s), sampled span "
            f"{outage_lower:.3f}s (sample-based bracket {outage_lower:.3f}-{outage_upper:.3f}s)"
            if failed_observations
            else "no failed ICMP observation run"
        )

        def component(value: object) -> str:
            return (
                "PASS" if value is True else "FAIL" if value is False else "UNVERIFIED"
            )

        tcp_assessment = (
            "FAIL"
            if delivery_mismatch
            or tcp.get("error")
            or (
                tcp.get("terminal") is True
                and tcp.get("survived") is False
                and tcp_connected
            )
            else "PASS"
            if tcp_connected
            and tcp_survived
            and delivery_evidence
            and live_identity_valid
            and tcp.get("terminal") is True
            else "UNVERIFIED"
        )
        outcomes = {
            "vm_placement": component(placement_verified),
            "migration_completion": component(
                migration_succeeded if completion_consistent else None
            ),
            "tcp_session": tcp_assessment,
            "traffic_recovery": component(connectivity_recovered),
            "interruption_tolerance": "UNVERIFIED"
            if not tolerance_complete
            else "OBSERVATION"
            if tolerance_reasons
            else "PASS",
        }
        message = (
            f"VM placement={outcomes['vm_placement']}; migration completion={outcomes['migration_completion']}; "
            f"Long-lived TCP connected={tcp_connected}, survived={tcp_survived}; "
            + (
                f"ICMP failed observations {icmp_lost}/{icmp_total} ({icmp_loss:.2f}%), "
                if icmp_loss is not None
                else "ICMP failed-observation rate unavailable, "
            )
            + outage_text
            + "; "
            + (
                f"sequenced UDP application-delivery loss={udp_loss:.2f}%"
                if udp_loss is not None
                else "sequenced UDP application-delivery loss unavailable"
            )
            + f"; recovery={connectivity_recovered} ({recovery_basis})"
        )
        if failure_reasons:
            message += "; " + "; ".join(failure_reasons)
        if tolerance_reasons:
            message += "; interruption measurements: " + "; ".join(tolerance_reasons)
        if interruption_observations:
            message += "; observation: " + MIGRATION_DOWNTIME_TOLERANCE_NOTE
        if advisories:
            message += "; advisory: " + "; ".join(advisories)
        if not evidence_complete and not critical:
            incomplete: list[str] = []
            if migration_succeeded is not True:
                incomplete.append("successful migration was not verified")
            if placement_verified is not True:
                incomplete.append("requested placement was not verified")
            if not completion_complete:
                incomplete.append("supplied migration completion proof was incomplete")
            if not completion_consistent:
                incomplete.append(
                    "migration completion claims conflicted with supplied proof"
                )
            if not phase_complete:
                incomplete.append(
                    "startup/migration/post-migration attribution was incomplete"
                )
            if not target_known:
                incomplete.append(
                    "the intended destination VM and fixed IP were not identified"
                )
            if not ready:
                incomplete.append("probes were not ready before migration")
            if not sampling_complete:
                incomplete.append("fixed-cadence sampling was incomplete")
            if not full_window:
                incomplete.append("the full migration window was not observed")
            if not tcp_connected:
                incomplete.append("the TCP baseline was not established")
            if icmp_total <= 0 or icmp_loss is None:
                incomplete.append("ICMP evidence was incomplete")
            if not icmp_counts_consistent:
                incomplete.append("ICMP counts did not match the raw observations")
            if not live_identity_valid:
                incomplete.append(
                    "continuity receiver/session identity was not verified"
                )
            if not routes_verified:
                incomplete.append(
                    "continuity data-interface selection was not verified"
                )
            if not delivery_evidence:
                incomplete.append("TCP receiver delivery evidence was incomplete")
            if not udp_loss_consistent or not udp_sequence_valid:
                incomplete.append("UDP receiver count/sequence evidence was incomplete")
            if continuity.get("workers_complete") is not True:
                incomplete.append("monitor worker completion was not verified")
            if connectivity_recovered is None:
                incomplete.append("recovery could not be verified")
            if incomplete:
                message += "; " + "; ".join(incomplete)
        message += (
            f"; interruption tolerance={outcomes['interruption_tolerance']} "
            f"(ICMP failed observations <= {icmp_limit:g}%, UDP delivery loss <= {udp_limit:g}%, sampled failed-observation span <= {outage_limit:g}s; "
            + (
                "ready-through-post-migration"
                if phase_required
                else "legacy whole-monitor window"
            )
            + ")"
        )
        details = {
            **continuity,
            "migration_outcomes": outcomes,
            "tolerance_failure_reasons": tolerance_reasons,
            "interruption_observations": interruption_observations,
            "interruption_tolerance_note": MIGRATION_DOWNTIME_TOLERANCE_NOTE,
            "transport_failure_reasons": transport_failure_reasons,
            "validation_failure_reasons": validation_failure_reasons,
            "phase_evidence_complete": phase_complete,
            "completion_evidence_consistent": completion_consistent,
            "evaluated_thresholds": {
                "icmp_loss_pct": icmp_limit,
                "udp_loss_pct": udp_limit,
                "outage_lower_bound_s": outage_limit,
            },
            "migration_succeeded": migration_succeeded,
            "connectivity_recovered": connectivity_recovered,
            "recovery_basis": recovery_basis,
            "continuity_failure_reasons": failure_reasons,
            "continuity_advisories": advisories,
            "packet_loss_is_advisory_after_recovery": status == "PASS",
            "receiver_delivery_verified": delivery_evidence,
            "icmp_recovered": icmp_recovered,
            "udp_recovered": udp_recovered,
            "udp_trailing_loss_s": trailing_udp_seconds,
            "evidence_complete": evidence_complete,
            "health": (
                "critical"
                if status == "FAIL"
                else "warning"
                if interruption_observations or advisories or status == "UNVERIFIED"
                else "good"
            ),
        }
        return status, observed, message, details

    @staticmethod
    def _migration_baseline_specs(specs: list[TestSpec]) -> list[TestSpec]:
        return migration_baseline_specs(specs)

    def _functional_baseline_results(
        self: Any, specs: list[TestSpec]
    ) -> tuple[list[TestSpec], list[Any]]:
        reachable_specs = self._migration_baseline_specs(specs)
        result_lookup = getattr(self.reporter, "get_result", None)
        results = [
            result_lookup(spec.id) if callable(result_lookup) else None
            for spec in reachable_specs
        ]
        return reachable_specs, results

    def _pre_migration_functional_barrier(
        self: Any,
        specs: list[TestSpec],
        engine: TestEngine,
        *,
        dependencies: tuple[str, ...],
        source: Endpoint,
        destination: Endpoint,
        current_relation: str,
        submission_number: int,
        migration_kind: str,
    ) -> bool:
        """Require every selected dataplane path to pass freshly before submission."""
        selected = [
            migration_probe_spec(spec) for spec in migration_barrier_specs(specs)
        ]
        protocols = {
            str(spec.protocol) for spec in self._migration_baseline_specs(specs)
        }
        missing = sorted({"icmp", "tcp", "udp"} - protocols)
        barrier = self._placement_control_spec(
            dependencies,
            source=source,
            destination=destination,
            kind=f"MIGRATION-FUNCTIONAL-BASELINE-{submission_number}",
            display_name=(
                f"Verify fresh functional baseline before {migration_kind} "
                f"migration submission {submission_number}"
            ),
            scenario="Compute migration safety barrier",
            expectation="fresh-functional-matrix",
        )
        self._append_runtime_specs([barrier])
        if missing:
            self.reporter.result(
                barrier.id,
                barrier.category,
                "UNVERIFIED",
                "Migration was not submitted because required fresh baseline "
                f"protocols were absent: {', '.join(missing)}",
                source=source.host,
                destination=destination.host,
                expected=barrier.expectation,
                observed="functional-protocol-coverage-incomplete",
                authoritative=True,
                details={
                    "submission_number": submission_number,
                    "migration_kind": migration_kind,
                    "missing_protocols": missing,
                    "lifecycle_cloud_operation_performed": False,
                },
                display_name=barrier.display_name,
                scenario=barrier.scenario,
            )
            return False

        token = self._placement_identity_token(
            *dependencies,
            source.server_id,
            destination.server_id,
            getattr(self, "_placement_workflow_id", ""),
            migration_kind,
            str(submission_number),
        )
        rounds: list[dict[str, object]] = []
        result_lookup = getattr(self.reporter, "get_result", None)
        for round_number in (1,):
            round_specs = [
                dataclasses.replace(
                    spec,
                    id=(
                        f"{spec.id}-PRE-MIGRATION-{submission_number}-"
                        f"ROUND-{round_number}-{token}"
                    ),
                    phase="placement",
                    display_name=(
                        f"{spec.display_name or spec.id} — pre-migration "
                        f"safety round {round_number}/1"
                    ),
                    scenario="Compute migration safety barrier",
                    metadata={
                        **spec.metadata,
                        "supplemental": True,
                        "pre_migration_functional_barrier": True,
                        **(
                            {
                                "planned_check_id": self._placement_check_bindings[
                                    "MIGRATION-FUNCTIONAL-BASELINE"
                                ],
                                "check_sample": True,
                            }
                            if getattr(self, "_placement_check_bindings", {}).get(
                                "MIGRATION-FUNCTIONAL-BASELINE"
                            )
                            else {}
                        ),
                        "submission_number": submission_number,
                        "round": round_number,
                        "round_total": 1,
                        "sample_index": sample_index,
                        "sample_total": len(selected),
                        "compute_placement": current_relation,
                    },
                )
                for sample_index, spec in enumerate(selected, start=1)
            ]
            self._append_runtime_specs(round_specs)
            engine.run_specs(round_specs)
            observed = [
                result_lookup(spec.id) if callable(result_lookup) else None
                for spec in round_specs
            ]
            failed = [
                spec.id
                for spec, result in zip(round_specs, observed, strict=False)
                if result is None or result.status != "PASS"
            ]
            rounds.append(
                {
                    "round": round_number,
                    "test_ids": [spec.id for spec in round_specs],
                    "failed_test_ids": failed,
                }
            )
            event = getattr(self.reporter, "event", None)
            if callable(event):
                event(
                    "migration-functional-safety-observation",
                    f"Functional safety round {round_number}/1 completed",
                    submission_number=submission_number,
                    migration_kind=migration_kind,
                    failed_test_ids=failed,
                )
            if failed:
                failure_reasons = [
                    f"{spec.display_name or spec.id}: {result.message if result else 'No result recorded'}"
                    for spec, result in zip(round_specs, observed, strict=False)
                    if result is None or result.status != "PASS"
                ]
                self.reporter.result(
                    barrier.id,
                    barrier.category,
                    "UNVERIFIED",
                    "Migration was not submitted because a fresh functional "
                    f"safety round did not pass: {'; '.join(failure_reasons)}",
                    source=source.host,
                    destination=destination.host,
                    expected=barrier.expectation,
                    observed="fresh-functional-baseline-failed",
                    authoritative=True,
                    details={
                        "submission_number": submission_number,
                        "migration_kind": migration_kind,
                        "rounds": rounds,
                        "failure_reasons": failure_reasons,
                        "lifecycle_cloud_operation_performed": False,
                    },
                    display_name=barrier.display_name,
                    scenario=barrier.scenario,
                )
                return False

        self.reporter.result(
            barrier.id,
            barrier.category,
            "PASS",
            "All selected pre-migration probes passed, using the protocols applicable to each path: "
            + ", ".join(protocol.upper() for protocol in sorted(protocols)),
            source=source.host,
            destination=destination.host,
            expected=barrier.expectation,
            observed="fresh-functional-matrix",
            authoritative=True,
            details={
                "submission_number": submission_number,
                "migration_kind": migration_kind,
                "rounds": rounds,
                "protocols": sorted(protocols),
            },
            display_name=barrier.display_name,
            scenario=barrier.scenario,
        )
        return True

    def _record_unavailable_migration_baseline(
        self: Any,
        dependencies: tuple[str, ...],
        source: Endpoint,
        destination: Endpoint,
        current_relation: str,
        reachable_specs: list[TestSpec],
        reachable_results: list[Any],
    ) -> None:
        baseline = self._placement_control_spec(
            dependencies,
            source=source,
            destination=destination,
            kind="MIGRATION-BASELINE",
            display_name=(
                "Verify functional baseline before compute migration — "
                f"{source.label} / {destination.label}"
            ),
            scenario="Compute migration and placement lifecycle",
            expectation="baseline-reachable",
        )
        self._append_runtime_specs([baseline])
        failed_ids = [
            spec.id
            for spec, result in zip(reachable_specs, reachable_results, strict=False)
            if result is not None and result.status in {"FAIL", "ERROR"}
        ]
        self.reporter.result(
            baseline.id,
            baseline.category,
            "UNVERIFIED",
            "Migration was not attempted because none of the required "
            "functional endpoint paths passed before the lifecycle cloud operation",
            source=source.host,
            destination=destination.host,
            expected=baseline.expectation,
            observed="functional-baseline-unavailable",
            authoritative=True,
            details={
                "dependencies": list(dependencies),
                "current_relation": current_relation,
                "failed_baseline_tests": failed_ids,
                "lifecycle_cloud_operation_performed": False,
            },
            display_name=baseline.display_name,
            scenario=baseline.scenario,
        )
        self.logger.log(
            "Skipping compute migration for this endpoint pair because the "
            "pre-migration functional baseline is unavailable",
            "WARNING",
        )


__all__ = ["PlacementMigrationMixin"]
