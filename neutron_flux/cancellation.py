from __future__ import annotations

import os
import signal
import subprocess
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from typing import Any

from .errors import RunCancelledError


class _CancellationState:
    """Process-wide cancellation coordination for one foreground Flux action.

    Flux executes AZ lanes in worker threads while Python delivers signals only
    to the main thread.  A plain ``KeyboardInterrupt`` therefore cannot stop a
    worker that is blocked in ``openstack`` or ``ssh``.  This state object gives
    every thread one shared terminal signal and tracks child process groups so
    the first operator interrupt can wake those workers before cleanup begins.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._event = threading.Event()
        self._local = threading.local()
        self._reason: str | None = None
        self._cleanup_mode = False
        self._hard_abort = False
        self._hard_abort_reason: str | None = None
        self._processes: dict[int, subprocess.Popen[str]] = {}

    def reset(self) -> None:
        with self._lock:
            self._event.clear()
            self._reason = None
            self._cleanup_mode = False
            self._hard_abort = False
            self._hard_abort_reason = None
            self._processes.clear()
        self._local.reconciliation_depth = 0

    def request(self, reason: str) -> bool:
        """Request cancellation and return ``True`` only for the first request."""
        with self._lock:
            first = not self._event.is_set() and self._reason is None
            if self._reason is None:
                self._reason = reason
            if not self._cleanup_mode:
                self._event.set()
            processes = list(self._processes.values())
        for process in processes:
            self._terminate(process)
        return first

    def force_abort(self, reason: str) -> None:
        """Stop active children while leaving final state publication possible."""
        with self._lock:
            self._hard_abort = True
            self._hard_abort_reason = self._hard_abort_reason or reason
            self._cleanup_mode = False
            self._reason = self._reason or reason
            self._event.set()
            processes = list(self._processes.values())
        for process in processes:
            self._terminate(process, force=True)

    def begin_cleanup(self) -> None:
        """Allow the controlled cleanup phase after all execution workers stop."""
        with self._lock:
            if self._hard_abort:
                return
            self._cleanup_mode = True
            self._event.clear()
            self._processes = {
                pid: process
                for pid, process in self._processes.items()
                if process.poll() is None
            }

    @property
    def requested(self) -> bool:
        with self._lock:
            return self._reason is not None

    @property
    def active(self) -> bool:
        """Return whether execution cancellation is currently being enforced.

        The original signal reason remains available while controlled cleanup
        runs, but cleanup commands must not be reclassified as cancelled merely
        because an earlier execution-phase child exited with a signal-like code.
        """
        with self._lock:
            active = self._event.is_set() and not self._cleanup_mode
            hard_abort = self._hard_abort
        return hard_abort or (active and not self.reconciling)

    @property
    def reconciling(self) -> bool:
        return int(getattr(self._local, "reconciliation_depth", 0)) > 0

    @property
    def hard_abort(self) -> bool:
        with self._lock:
            return self._hard_abort

    @property
    def cleanup_mode(self) -> bool:
        with self._lock:
            return self._cleanup_mode

    @property
    def hard_abort_reason(self) -> str:
        with self._lock:
            return self._hard_abort_reason or "operator requested an emergency abort"

    @contextmanager
    def reconciliation(self) -> Iterator[None]:
        """Suppress ordinary cancellation only in the reconciling worker."""
        depth = int(getattr(self._local, "reconciliation_depth", 0))
        self._local.reconciliation_depth = depth + 1
        try:
            yield
        finally:
            self._local.reconciliation_depth = depth

    @property
    def reason(self) -> str:
        with self._lock:
            return self._reason or "operator cancellation requested"

    def raise_if_requested(self) -> None:
        with self._lock:
            requested = self._event.is_set() and not self._cleanup_mode
            hard_abort = self._hard_abort
            reason = self._reason or "operator cancellation requested"
        if hard_abort or (requested and not self.reconciling):
            raise RunCancelledError(reason)

    def register(self, process: subprocess.Popen[str]) -> None:
        key = int(getattr(process, "pid", id(process)))
        with self._lock:
            if process.poll() is None:
                self._processes[key] = process
            force = self._hard_abort
            cancel_now = force or (
                self._event.is_set() and not self._cleanup_mode and not self.reconciling
            )
        if cancel_now:
            self._terminate(process, force=force)

    def unregister(self, process: subprocess.Popen[str]) -> None:
        key = int(getattr(process, "pid", id(process)))
        with self._lock:
            self._processes.pop(key, None)

    @staticmethod
    def _terminate(process: subprocess.Popen[str], *, force: bool = False) -> None:
        if process.poll() is not None:
            return
        pid = getattr(process, "pid", None)
        try:
            if pid is None:
                raise ProcessLookupError
            os.killpg(int(pid), signal.SIGKILL if force else signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError, TypeError, ValueError):
            try:
                process.kill() if force else process.terminate()
            except (ProcessLookupError, OSError):
                return


_STATE = _CancellationState()


def reset_cancellation() -> None:
    _STATE.reset()


def request_cancellation(reason: str) -> bool:
    return _STATE.request(reason)


def force_cancellation_abort(reason: str) -> None:
    _STATE.force_abort(reason)


def begin_cleanup_after_cancellation() -> None:
    _STATE.begin_cleanup()


def cancellation_active() -> bool:
    return _STATE.active


def hard_abort_requested() -> bool:
    return _STATE.hard_abort


def cleanup_in_progress() -> bool:
    return _STATE.cleanup_mode


def hard_abort_reason() -> str:
    return _STATE.hard_abort_reason


def cancellation_reason() -> str:
    return _STATE.reason


def raise_if_cancelled() -> None:
    _STATE.raise_if_requested()


def register_process(process: subprocess.Popen[str]) -> None:
    _STATE.register(process)


def unregister_process(process: subprocess.Popen[str]) -> None:
    _STATE.unregister(process)


@contextmanager
def cancellation_reconciliation() -> Iterator[None]:
    with _STATE.reconciliation():
        yield


def _stop_and_reap(process: subprocess.Popen[str]) -> None:
    """Stop the process group and reap its child even if pipe handling fails."""
    _CancellationState._terminate(process, force=hard_abort_requested())
    drained = False
    try:
        process.communicate(timeout=5)
        drained = True
    except (subprocess.TimeoutExpired, OSError, ValueError):
        pass
    finally:
        if not drained:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                process.kill()
            finally:
                try:
                    process.communicate()
                except (OSError, ValueError):
                    pass
                finally:
                    process.wait()


def run_cancellable(
    command: Sequence[str],
    *,
    input_text: str | None = None,
    timeout: int | float | None = None,
    env: dict[str, str] | None = None,
    stdout: Any = subprocess.PIPE,
    stderr: Any = subprocess.PIPE,
    stdin: Any = None,
    text: bool = True,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run a local child in its own process group and cancel it cooperatively."""
    raise_if_cancelled()
    actual_stdin = subprocess.PIPE if input_text is not None else stdin
    process: subprocess.Popen[str] | None = None
    try:
        process = subprocess.Popen(
            list(command),
            text=text,
            stdin=actual_stdin,
            stdout=stdout,
            stderr=stderr,
            env=env,
            start_new_session=True,
        )
        register_process(process)
        out, err = process.communicate(input=input_text, timeout=timeout)
    except (KeyboardInterrupt, RunCancelledError, subprocess.TimeoutExpired):
        if process is not None:
            _stop_and_reap(process)
        raise
    finally:
        if process is not None:
            unregister_process(process)
    if cancellation_active() and process.returncode in {130, 143, -2, -15}:
        raise RunCancelledError(cancellation_reason())
    result = subprocess.CompletedProcess(list(command), process.returncode, out, err)
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode,
            list(command),
            output=out,
            stderr=err,
        )
    raise_if_cancelled()
    return result
