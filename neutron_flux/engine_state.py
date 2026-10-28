from __future__ import annotations

import copy
import threading
from collections.abc import Callable
from concurrent.futures import Future
from dataclasses import dataclass
from typing import Any, TypedDict

from .config import Config
from .models import Discovery
from .reporting import Reporter
from .resources import ResourceBuilder


class RouteObservationCache:
    """Share each route lookup only within one concurrent probe wave."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pending: dict[tuple[str, str, str, int], Future[dict[str, Any]]] = {}

    def observe(
        self,
        key: tuple[str, str, str, int],
        reader: Callable[[], dict[str, Any]],
    ) -> dict[str, Any]:
        with self._lock:
            future = self._pending.get(key)
            owner = future is None
            if future is None:
                future = Future()
                self._pending[key] = future
        if owner:
            try:
                value = reader()
            except BaseException as exc:
                # Release waiting peers even when the operator cancels the
                # reader. No exception is converted into successful evidence.
                future.set_exception(exc)
                raise
            else:
                future.set_result(value)
        return copy.deepcopy(future.result())


class LifecycleRecord(TypedDict, total=False):
    """Shared schema for persisted lifecycle evidence.

    Operation-specific records may carry additional keys, but the common
    cloud operation and restoration markers are declared here so lifecycle handlers
    no longer exchange an entirely untyped ``dict[str, Any]``.
    """

    start_confirmed: bool
    cloud_operation_performed: bool
    baseline: bool
    baseline_outcome: str
    authoritative: bool
    temporary_rule_id: str | None
    detach_requested: bool
    detach_confirmed: bool
    detached: bool
    routes_installed: bool
    route_setup_error: str


class LifecycleStateStore(dict[str, LifecycleRecord]):
    """Run-local lifecycle state with one authoritative missing-state error."""

    def require(self, key: str) -> LifecycleRecord:
        try:
            return self[key]
        except KeyError as exc:
            raise KeyError(f"Lifecycle baseline is unavailable: {key}") from exc


@dataclass(frozen=True)
class EngineDependencies:
    config: Config
    discovery: Discovery
    builder: ResourceBuilder
    reporter: Reporter
