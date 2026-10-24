from __future__ import annotations

import shlex
from collections.abc import Sequence
from typing import Any


class SuiteError(RuntimeError):
    """Expected suite failure with an operator-readable message."""


class MeasurementExecutionError(SuiteError):
    """Execution failed before a usable probe verdict was returned."""

    def __init__(self, message: str, *, evidence: dict[str, Any] | None = None):
        super().__init__(message)
        self.evidence = dict(evidence or {})


class SSHExecutionError(MeasurementExecutionError):
    """The management transport is unavailable; no dataplane verdict exists."""


class PortValidationError(SuiteError):
    """Preserve the last observed ports when migration validation fails."""

    def __init__(self, message: str, *, ports: dict[str, Any]) -> None:
        super().__init__(message)
        self.ports = ports


class DependentMeasurementUnavailable(SuiteError):
    """A derived performance result could not run after one root failure."""


class PathReachabilityError(SuiteError):
    """A performance probe proved that the measured network path is unreachable.

    The first affected measurement is an authoritative network FAIL. Remaining
    measurements for that path are dependencies and therefore UNVERIFIED.
    """


class CloudOperationBlockedError(SuiteError):
    """A disruptive operation was refused by the cloud operation safety model."""


class AmbiguousCloudOperationError(CloudOperationBlockedError):
    """A submitted cloud operation could not be authoritatively classified."""


class RunCancelledError(SuiteError):
    """The operator cancelled the active Flux run or child command."""


class UnsupportedTopologyError(SuiteError):
    """The discovered cloud cannot support the requested adaptive plan."""


class PlacementUnavailableError(SuiteError):
    """Requested compute-placement coverage cannot be created in this cloud."""

    def __init__(self, message: str, *, target_unsuitable: bool = True) -> None:
        super().__init__(message)
        self.target_unsuitable = target_unsuitable


class RetryableMigrationError(SuiteError):
    """Authoritative evidence proves a migration retry is safe.

    Recovery to the original host alone is not proof of failure.  Callers set
    ``proven_failure`` only for a deterministic pre-acceptance rejection or a
    new Nova migration record with a terminal failed/cancelled state.
    """

    def __init__(
        self,
        message: str,
        *,
        unavailable: bool = False,
        proven_failure: bool = True,
        accepted: bool | None = False,
        target_unsuitable: bool = False,
        evidence: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.unavailable = unavailable
        self.proven_failure = proven_failure
        self.accepted = accepted
        self.target_unsuitable = target_unsuitable
        self.evidence = dict(evidence or {})


class UnsafeMigrationStateError(SuiteError):
    """A failed migration left placement or guest readiness uncertain."""


class UnverifiableMigrationError(PlacementUnavailableError):
    """Required authoritative migration safety fields were unavailable."""


class SetupFailureError(SuiteError):
    """The suite could not establish the reusable test execution environment.

    This is distinct from an individual network assertion.  Examples include a
    controller bootstrap failure or an inability to start the transient probe
    process used by every endpoint VM.
    """


class ProbeServiceError(SetupFailureError):
    """The transient in-memory TCP/UDP probe process could not be started."""


class ControllerUnavailableError(SetupFailureError):
    """The shared SSH control path failed a bounded recovery check."""


class CommandTimeoutError(SuiteError):
    """A local command exceeded its timeout without a usable exit result.

    Create paths may catch this exception and perform exact-name recovery when
    the remote API could have accepted the request before the local client was
    terminated.
    """

    def __init__(self, command: Sequence[str], timeout: int | None) -> None:
        self.command = list(command)
        self.timeout = timeout
        rendered_timeout = f" after {timeout}s" if timeout is not None else ""
        super().__init__(
            f"Command timed out{rendered_timeout}: {shlex.join(self.command)}"
        )


class CommandError(SuiteError):
    """A local command exited unsuccessfully."""

    def __init__(
        self,
        command: Sequence[str],
        returncode: int,
        stdout: str,
        stderr: str,
    ) -> None:
        self.command = list(command)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        detail = stderr.strip() or stdout.strip() or "no command output"
        super().__init__(
            f"Command failed ({returncode}): {shlex.join(command)}\n{detail}"
        )
