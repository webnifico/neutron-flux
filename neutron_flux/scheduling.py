"""Bounded execution and process-wide measurement isolation.

Admission limits bound work already allowed by the plan; they never increase
the number of endpoint roles or allocate additional quota.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from contextlib import contextmanager
from typing import Any, TypeVar

from .cancellation import raise_if_cancelled
from .errors import ControllerUnavailableError, RunCancelledError, SuiteError

T = TypeVar("T")
R = TypeVar("R")
PROBE_WORKERS = 8
READ_WORKERS = 4
LIFECYCLE_WORKERS = 2
_READ_SLOTS = threading.BoundedSemaphore(READ_WORKERS)
_PROBE_SLOTS = threading.BoundedSemaphore(PROBE_WORKERS)
_LIFECYCLE_SLOTS = threading.BoundedSemaphore(LIFECYCLE_WORKERS)
_TIMING_LOCAL = threading.local()


@contextmanager
def timed(reporter: Any, category: str, label: str) -> Iterator[None]:
    """Record elapsed and exclusive time on this thread, including failures."""
    stack = getattr(_TIMING_LOCAL, "stack", None)
    if stack is None:
        stack = []
        _TIMING_LOCAL.stack = stack
    frame = [time.monotonic(), 0.0]
    stack.append(frame)
    success = False
    try:
        yield
        success = True
    finally:
        elapsed = max(0.0, time.monotonic() - frame[0])
        stack.pop()
        if stack:
            stack[-1][1] += elapsed
        event = getattr(reporter, "event", None)
        if callable(event):
            event(
                "runtime-timing",
                label,
                category=category,
                elapsed_seconds=round(elapsed, 6),
                self_seconds=round(max(0.0, elapsed - frame[1]), 6),
                thread=threading.current_thread().name,
                completed=success,
            )


@contextmanager
def admission(kind: str, reporter: Any = None) -> Iterator[None]:
    semaphore = {
        "api-read": _READ_SLOTS,
        "probe": _PROBE_SLOTS,
        "lifecycle": _LIFECYCLE_SLOTS,
    }[kind]
    acquired = False
    try:
        with timed(reporter, "admission-wait", kind):
            while not acquired:
                acquired = semaphore.acquire(timeout=0.1)
                if not acquired:
                    raise_if_cancelled()
        raise_if_cancelled()
        yield
    finally:
        if acquired:
            semaphore.release()


class ActivityGate:
    """Concurrent ordinary work; exclusive measurements and disruptions.

    Shared admission is reentrant and permits a finite admitted batch to start
    its child workers while an exclusive waiter exists. Otherwise a parent
    holding a shared lease and joining those children could deadlock. Callers
    must use bounded batches rather than an unbounded producer.
    """

    def __init__(self) -> None:
        self._condition = threading.Condition(threading.RLock())
        self._readers: dict[int, int] = {}
        self._writer: int | None = None
        self._write_depth = 0
        self._resources: dict[str, tuple[Any, int]] = {}

    @contextmanager
    def scope(
        self, *, exclusive: bool = False, reporter: Any = None, label: str = "activity"
    ) -> Iterator[None]:
        owner = threading.get_ident()
        acquired = False
        try:
            with timed(reporter, "activity-wait", label), self._condition:
                if exclusive:
                    if self._readers.get(owner) and self._writer != owner:
                        raise RuntimeError(
                            "A shared activity cannot upgrade to exclusive"
                        )
                    while self._writer not in {None, owner} or (
                        self._writer != owner and self._readers
                    ):
                        raise_if_cancelled()
                        self._condition.wait(0.1)
                    self._writer = owner
                    self._write_depth += 1
                else:
                    while self._writer not in {None, owner}:
                        raise_if_cancelled()
                        self._condition.wait(0.1)
                    self._readers[owner] = self._readers.get(owner, 0) + 1
                acquired = True
            raise_if_cancelled()
            yield
        finally:
            if acquired:
                with self._condition:
                    if exclusive:
                        self._write_depth -= 1
                        if not self._write_depth:
                            self._writer = None
                    else:
                        self._readers[owner] -= 1
                        if not self._readers[owner]:
                            del self._readers[owner]
                    self._condition.notify_all()

    @contextmanager
    def resources(self, keys: Iterable[str]) -> Iterator[None]:
        """Serialize operations on identical resource IDs without a global lock."""
        selected = sorted(set(str(key) for key in keys if key))
        locks = []
        acquired = []
        with self._condition:
            for key in selected:
                lock, users = self._resources.get(key, (threading.RLock(), 0))
                self._resources[key] = (lock, users + 1)
                locks.append((key, lock))
        try:
            for _, lock in locks:
                while not lock.acquire(timeout=0.1):
                    raise_if_cancelled()
                acquired.append(lock)
            yield
        finally:
            for lock in reversed(acquired):
                lock.release()
            with self._condition:
                for key, lock in locks:
                    users = self._resources[key][1] - 1
                    if users:
                        self._resources[key] = (lock, users)
                    else:
                        del self._resources[key]


ACTIVITY = ActivityGate()


def bounded_map(
    function: Callable[[T], R], values: Iterable[T], *, workers: int
) -> list[R]:
    """Keep at most workers tasks outstanding and join all work before raising."""
    items = list(values)
    if workers <= 1 or len(items) <= 1:
        results = []
        for item in items:
            raise_if_cancelled()
            results.append(function(item))
        return results
    results_by_index: dict[int, R] = {}
    iterator = iter(enumerate(items))
    pending: dict[Future[R], int] = {}
    submitted: list[Future[R]] = []
    with ThreadPoolExecutor(
        max_workers=min(workers, len(items)), thread_name_prefix="flux"
    ) as pool:

        def submit_next() -> None:
            item = next(iterator, None)
            if item is not None:
                raise_if_cancelled()
                index, value = item
                future = pool.submit(function, value)
                pending[future] = index
                submitted.append(future)

        try:
            for _ in range(min(workers, len(items))):
                submit_next()
            while pending:
                raise_if_cancelled()
                complete, _ = wait(pending, timeout=0.1, return_when=FIRST_COMPLETED)
                # Inspect every completed future before admitting more work.
                # Do not raise yet: a running peer may report cancellation or
                # lost shared control after this ordinary operation fails.
                if any(future.exception() is not None for future in complete):
                    break
                for future in complete:
                    results_by_index[pending.pop(future)] = future.result()
                for _ in complete:
                    submit_next()
        finally:
            for future in pending:
                future.cancel()
    # The pool has joined every started worker. Inspect all submitted work,
    # including peers completed after admission stopped, without losing the
    # first failed future to a pending.pop(). Parent-thread exceptions unwind
    # through the finally above unchanged and do not enter this selection.
    errors = [
        error
        for future in submitted
        if not future.cancelled() and (error := future.exception()) is not None
    ]
    if errors:
        # Unexpected exceptions must abort rather than become an optional
        # SuiteError fallback. Cancellation and shared-control loss likewise
        # take precedence over an ordinary read/validation failure.
        for preferred in (
            lambda error: not isinstance(error, SuiteError),
            lambda error: isinstance(error, RunCancelledError),
            lambda error: isinstance(error, ControllerUnavailableError),
        ):
            for error in errors:
                if preferred(error):
                    raise error
        raise errors[0]
    return [results_by_index[index] for index in range(len(items))]


def timing_summary(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    categories: dict[str, dict[str, Any]] = {}
    for event in events:
        if event.get("type") != "runtime-timing":
            continue
        details = event.get("details") or {}
        category = str(details.get("category") or "other")
        row = categories.setdefault(
            category, {"count": 0, "elapsed_seconds": 0.0, "self_seconds": 0.0}
        )
        row["count"] += 1
        for key in ("elapsed_seconds", "self_seconds"):
            row[key] = round(row[key] + float(details.get(key) or 0.0), 6)
    return {
        "schema_version": 1,
        "categories": categories,
        "interpretation": (
            "Elapsed spans can nest. Self time excludes nested spans on the same "
            "thread. Concurrent threads overlap; neither sum is run wall time."
        ),
        "limits": {
            "api_reads": READ_WORKERS,
            "functional_probes": PROBE_WORKERS,
            "endpoint_lifecycles": LIFECYCLE_WORKERS,
            "measurement_windows": 1,
        },
    }
