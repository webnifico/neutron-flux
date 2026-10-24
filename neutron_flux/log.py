from __future__ import annotations

import datetime as dt
import os
import pathlib
import re
import sys
import threading
import weakref
from collections.abc import Callable
from typing import TextIO

_STATUS_COLOURS = {
    "PASS": 32,
    "FAIL": 31,
    "FAILED": 31,
    "ERROR": 31,
    "SETUP FAILED": 31,
    "CLEANUP INCOMPLETE": 31,
    "WARNING": 33,
    "WARN": 33,
    "UNVERIFIED": 33,
    "PASS WITH WARNING": 33,
    "PASS WITH WARNINGS": 33,
    "PASS WITH GAPS": 33,
    "PARTIAL": 33,
    "INCOMPLETE": 33,
    "CANCELLED": 33,
    "NOT RUN": 33,
    "NOT RUN — SETUP ERROR": 33,
    "NOT RUN — PREREQUISITE": 33,
    "NOT RUN — CANCELLED": 33,
    "NOT RUN — NOT APPLICABLE": 33,
    "NOT RUN — UNSUPPORTED": 33,
}
_STATUS_ALTERNATIVES = "|".join(
    re.escape(status) for status in sorted(_STATUS_COLOURS, key=len, reverse=True)
)
_RESULT_TAG = re.compile(r"\[(" + _STATUS_ALTERNATIVES + r")\]")
_SUMMARY_STATUS = re.compile(r"(?<![\w/.-])(" + _STATUS_ALTERNATIVES + r")(?![\w/.-])")


def terminal_text(
    message: str, *, level: str | None = None, stream: TextIO | None = None
) -> str:
    """Colour only the terminal copy; callers retain the original report text."""
    target = sys.stdout if stream is None else stream
    if os.environ.get("NO_COLOR") or os.environ.get("TERM", "").lower() == "dumb":
        return message
    try:
        enabled = target.isatty()
    except (AttributeError, OSError, ValueError):
        enabled = False
    if not enabled:
        return message

    def paint(text: str, status: str) -> str:
        # Restore only the foreground; preserve the terminal's background/style.
        return f"\033[{_STATUS_COLOURS[status]}m{text}\033[39m"

    if level in {"ERROR", "FAIL", "WARNING", "WARN"}:
        return paint(message, level) if message else message
    if level is not None:
        return _RESULT_TAG.sub(
            lambda match: paint(match.group(), match.group(1)), message
        )
    return _SUMMARY_STATUS.sub(
        lambda match: paint(match.group(), match.group(1)), message
    )


class Logger:
    def __init__(self, path: pathlib.Path, *, prefix: str = ""):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.path, flags, 0o600)
        self.handle = os.fdopen(descriptor, "a", encoding="utf-8", buffering=1)
        self._finalizer = weakref.finalize(self, self.handle.close)
        self.heartbeat: Callable[[], None] | None = None
        self.prefix = prefix
        self._lock = threading.RLock()

    def close(self) -> None:
        with self._lock:
            if self._finalizer.alive:
                self._finalizer()

    def _beat(self) -> None:
        if self.heartbeat:
            self.heartbeat()

    def log(self, message: str = "", level: str = "INFO") -> None:
        with self._lock:
            stamp = dt.datetime.now().astimezone().isoformat(timespec="seconds")
            rendered = f"{self.prefix}{message}" if message else ""
            line = f"[{stamp}] [{level}] {rendered}" if rendered else ""
            print(terminal_text(line, level=level), flush=True)
            self.handle.write(line + "\n")
            self._beat()

    def raw(self, message: str = "") -> None:
        with self._lock:
            rendered = f"{self.prefix}{message}" if message else ""
            print(terminal_text(rendered), flush=True)
            self.handle.write(rendered + "\n")
            self._beat()

    def section(self, message: str) -> None:
        self.log()
        self.log(f"==> {message}")
