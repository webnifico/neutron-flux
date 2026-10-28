from __future__ import annotations

import dataclasses
import datetime as dt
import fcntl
import json
import os
import pathlib
import stat
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

from .cloud_operation_reconciliation import cloud_operation_scope_fingerprint
from .errors import SuiteError
from .models import RunCheckpoint
from .operation_compat import scope_lock_filename
from .progress import progress_text
from .results_io import atomic_write_text
from .utils import iso_utc, validate_run_id

TERMINAL_STATES = {"COMPLETED", "CLEANUP_INCOMPLETE", "CANCELLED"}
_CHECKPOINT_STATES = frozenset(
    {
        "NEW",
        "INITIALIZING",
        "PLANNED",
        "RUNNING",
        "TESTS_COMPLETE",
        "CLEANING",
        "COMPLETED",
        "CLEANUP_INCOMPLETE",
        "INTERRUPTED",
        "FAILED",
        "CANCELLED",
    }
)
_CLEANUP_STATES = frozenset(
    {"NOT_STARTED", "RUNNING", "COMPLETE", "INCOMPLETE", "RETAINED"}
)
_CHECKPOINT_ACTIONS = frozenset({"plan", "run", "cleanup"})


class StateStore:
    def __init__(self, report_dir: pathlib.Path):
        self.report_dir = report_dir
        if self.report_dir.is_symlink():
            raise SuiteError(
                f"Report directory must not be a symbolic link: {self.report_dir}"
            )
        try:
            self.report_dir.mkdir(parents=True, exist_ok=True)
            self.runs_dir = self.report_dir / "runs"
            if self.runs_dir.is_symlink():
                raise SuiteError(
                    f"Runs directory must not be a symbolic link: {self.runs_dir}"
                )
            self.runs_dir.mkdir(parents=True, exist_ok=True)
        except SuiteError:
            raise
        except OSError as exc:
            raise SuiteError(
                f"Could not prepare Neutron Flux report directory {report_dir}: {exc}"
            ) from exc
        self.corrupt_state_files: list[tuple[pathlib.Path, str]] = []
        self._lock = threading.RLock()

    def _run_path(self, run_id: str) -> pathlib.Path:
        path = self.runs_dir / validate_run_id(run_id)
        if path.is_symlink():
            raise SuiteError(f"Run directory must not be a symbolic link: {path}")
        return path

    @staticmethod
    def _reject_existing_symlink(path: pathlib.Path, *, label: str) -> None:
        if path.is_symlink():
            raise SuiteError(f"{label} must not be a symbolic link: {path}")

    def state_path(self, run_id: str) -> pathlib.Path:
        path = self._run_path(run_id) / "state.json"
        self._reject_existing_symlink(path, label="Run checkpoint")
        return path

    def run_dir(self, run_id: str) -> pathlib.Path:
        path = self._run_path(run_id)
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise SuiteError(
                f"Could not prepare run state directory {path}: {exc}"
            ) from exc
        return path

    def save(self, checkpoint: RunCheckpoint) -> pathlib.Path:
        with self._lock:
            checkpoint.run_id = validate_run_id(checkpoint.run_id)
            checkpoint.updated_at = iso_utc()
            checkpoint.last_activity = checkpoint.updated_at
            path = self.state_path(checkpoint.run_id)
            self._validate_checkpoint(checkpoint, path)
            atomic_write_text(
                path,
                json.dumps(dataclasses.asdict(checkpoint), indent=2, sort_keys=True)
                + "\n",
            )
            self._update_latest_pointer(path, checkpoint.run_id)
            return path

    def _update_latest_pointer(self, path: pathlib.Path, run_id: str) -> None:
        latest = self.report_dir / "latest-run"
        temporary: pathlib.Path | None = None
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                dir=self.report_dir,
                prefix=".latest-run.",
                suffix=".tmp",
            )
            os.close(descriptor)
            temporary = pathlib.Path(temporary_name)
            temporary.unlink()
            temporary.symlink_to(path.parent)
            os.replace(temporary, latest)
            temporary = None
        except OSError:
            atomic_write_text(self.report_dir / "latest-run.txt", run_id + "\n")
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def load(self, run_id: str) -> RunCheckpoint:
        run_id = validate_run_id(run_id)
        path = self.state_path(run_id)
        if not path.is_file():
            raise SuiteError(f"Run checkpoint not found: {run_id}")
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            checkpoint = RunCheckpoint(**raw)
            self._validate_checkpoint(checkpoint, path)
            return checkpoint
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            raise SuiteError(f"Invalid run checkpoint {path}: {exc}") from exc

    def list(self) -> list[RunCheckpoint]:
        checkpoints: list[RunCheckpoint] = []
        self.corrupt_state_files = []
        for path in self.runs_dir.glob("*/state.json"):
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                checkpoint = RunCheckpoint(**raw)
                self._validate_checkpoint(checkpoint, path)
                checkpoints.append(checkpoint)
            except (OSError, json.JSONDecodeError, TypeError, SuiteError) as exc:
                self.corrupt_state_files.append((path, str(exc)))
        return sorted(
            checkpoints,
            key=lambda item: self._timestamp(item.updated_at),
            reverse=True,
        )

    @staticmethod
    def _timestamp(value: str) -> float:
        try:
            parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError) as exc:
            raise SuiteError(
                f"checkpoint updated_at is not valid ISO-8601: {value!r}"
            ) from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.timestamp()

    @staticmethod
    def _validated_id_list(value: object, *, field: str) -> list[str]:
        if not isinstance(value, list):
            raise SuiteError(f"checkpoint {field} must be an array")
        output: list[str] = []
        for item in value:
            if not isinstance(item, str) or not item.strip():
                raise SuiteError(
                    f"checkpoint {field} entries must be non-empty strings"
                )
            if item in output:
                raise SuiteError(f"checkpoint {field} contains duplicate ID {item!r}")
            output.append(item)
        return output

    @classmethod
    def _validate_checkpoint(
        cls, checkpoint: RunCheckpoint, path: pathlib.Path
    ) -> None:
        expected = validate_run_id(path.parent.name, key="checkpoint directory run ID")
        if path.parent.is_symlink():
            raise SuiteError(
                f"checkpoint directory must not be a symbolic link: {path.parent}"
            )
        if path.is_symlink():
            raise SuiteError(f"checkpoint file must not be a symbolic link: {path}")
        actual = validate_run_id(checkpoint.run_id, key="checkpoint run_id")
        if actual != expected:
            raise SuiteError(
                f"checkpoint run_id {actual!r} does not match directory {expected!r}"
            )
        checkpoint.run_id = actual
        if checkpoint.state not in _CHECKPOINT_STATES:
            raise SuiteError(f"checkpoint state is invalid: {checkpoint.state!r}")
        if checkpoint.action not in _CHECKPOINT_ACTIONS:
            raise SuiteError(f"checkpoint action is invalid: {checkpoint.action!r}")
        if not isinstance(checkpoint.phase, str) or not checkpoint.phase.strip():
            raise SuiteError("checkpoint phase must be a non-empty string")
        if checkpoint.current_batch is not None and not isinstance(
            checkpoint.current_batch, str
        ):
            raise SuiteError("checkpoint current_batch must be a string or null")
        if checkpoint.cleanup_state not in _CLEANUP_STATES:
            raise SuiteError(
                f"checkpoint cleanup_state is invalid: {checkpoint.cleanup_state!r}"
            )
        completed = cls._validated_id_list(
            checkpoint.completed_test_ids, field="completed_test_ids"
        )
        failed = cls._validated_id_list(
            checkpoint.failed_test_ids, field="failed_test_ids"
        )
        pending = cls._validated_id_list(
            checkpoint.pending_test_ids, field="pending_test_ids"
        )
        checkpoint.active_group_ids = cls._validated_id_list(
            checkpoint.active_group_ids, field="active_group_ids"
        )
        if not set(failed).issubset(completed):
            raise SuiteError(
                "checkpoint failed_test_ids must be a subset of completed_test_ids"
            )
        overlap = set(completed).intersection(pending)
        if overlap:
            raise SuiteError(
                "checkpoint completed_test_ids and pending_test_ids overlap: "
                + ", ".join(sorted(overlap))
            )
        if not isinstance(checkpoint.metadata, dict):
            raise SuiteError("checkpoint metadata must be an object")
        if not isinstance(checkpoint.manifest_path, str):
            raise SuiteError("checkpoint manifest_path must be a string")
        if (
            not isinstance(checkpoint.report_dir, str)
            or not checkpoint.report_dir.strip()
        ):
            raise SuiteError("checkpoint report_dir must be a non-empty string")
        for field in ("started_at", "updated_at", "last_activity"):
            cls._timestamp(getattr(checkpoint, field))

    @staticmethod
    def _is_incomplete(checkpoint: RunCheckpoint) -> bool:
        if checkpoint.cleanup_state == "COMPLETE":
            return False
        return checkpoint.cleanup_state in {"INCOMPLETE", "RETAINED", "RUNNING"} or (
            checkpoint.state not in TERMINAL_STATES
            and (
                bool(checkpoint.pending_test_ids)
                or checkpoint.state
                in {
                    "INTERRUPTED",
                    "RUNNING",
                    "FAILED",
                    "CLEANING",
                    "TESTS_COMPLETE",
                }
            )
        )

    def latest(
        self, *, incomplete_only: bool = False, run_id: str | None = None
    ) -> RunCheckpoint:
        if run_id:
            selected = self.load(run_id)
            if incomplete_only and not self._is_incomplete(selected):
                raise SuiteError(
                    f"Run {selected.run_id} is complete and is not eligible for recovery cleanup"
                )
            return selected
        items = self.list()
        if incomplete_only:
            items = [item for item in items if self._is_incomplete(item)]
        if not items and self.corrupt_state_files:
            newest = max(
                self.corrupt_state_files,
                key=lambda item: item[0].stat().st_mtime if item[0].exists() else 0.0,
            )
            raise SuiteError(
                "No valid eligible checkpoint can be selected because a Neutron "
                f"Flux checkpoint is corrupt: {newest[0]}: {newest[1]}"
            )
        if items and self.corrupt_state_files:
            selected_path = self.state_path(items[0].run_id)
            try:
                selected_mtime = selected_path.stat().st_mtime
            except OSError:
                selected_mtime = 0.0
            newer_corrupt: list[tuple[pathlib.Path, str, float]] = []
            for path, error in self.corrupt_state_files:
                try:
                    modified = path.stat().st_mtime
                except OSError:
                    # The inventory changed while it was being read.  A vanished
                    # corrupt checkpoint cannot safely outrank the valid one.
                    continue
                if modified >= selected_mtime:
                    newer_corrupt.append((path, error, modified))
            if newer_corrupt:
                path, error, _ = max(newer_corrupt, key=lambda item: item[2])
                raise SuiteError(
                    f"Newest Neutron Flux checkpoint is corrupt and cannot be skipped safely: {path}: {error}"
                )
        if not items:
            qualifier = " incomplete" if incomplete_only else ""
            raise SuiteError(
                f"No{qualifier} Neutron Flux run checkpoint found under {self.report_dir}"
            )
        return items[0]

    @contextmanager
    def _exclusive_lock(
        self,
        lock_path: pathlib.Path,
        *,
        label: str,
        active_message: str,
        wait_seconds: int = 0,
    ) -> Iterator[None]:
        self._reject_existing_symlink(lock_path, label=label)
        if lock_path.parent.is_symlink():
            raise SuiteError(
                f"{label} parent must not be a symbolic link: {lock_path.parent}"
            )
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + wait_seconds
        fd: int | None = None
        lock_identity: tuple[int, int] | None = None
        while True:
            try:
                flags = os.O_CREAT | os.O_RDWR
                if hasattr(os, "O_CLOEXEC"):
                    flags |= os.O_CLOEXEC
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                fd = os.open(lock_path, flags, 0o600)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    os.close(fd)
                    fd = None
                    if time.monotonic() >= deadline:
                        raise SuiteError(active_message) from None
                    time.sleep(1)
                    continue
                identity = {
                    **self._current_process_identity(),
                    "lock_protocol": "flock-v1",
                    "state": "active",
                }
                payload = (json.dumps(identity, sort_keys=True) + "\n").encode()
                os.ftruncate(fd, 0)
                os.lseek(fd, 0, os.SEEK_SET)
                offset = 0
                while offset < len(payload):
                    written = os.write(fd, payload[offset:])
                    if written <= 0:
                        raise OSError("lock identity write made no progress")
                    offset += written
                os.fsync(fd)
                stat = os.fstat(fd)
                lock_identity = (stat.st_dev, stat.st_ino)
                break
            except SuiteError:
                raise
            except OSError as exc:
                if fd is not None:
                    os.close(fd)
                    fd = None
                raise SuiteError(
                    f"Could not acquire {label.lower()} {lock_path}: {exc}"
                ) from exc
        try:
            yield
        finally:
            if fd is not None and lock_identity is not None:
                try:
                    current = lock_path.stat()
                except FileNotFoundError:
                    current = None
                if (
                    current is not None
                    and (
                        current.st_dev,
                        current.st_ino,
                    )
                    == lock_identity
                ):
                    released = {
                        **self._current_process_identity(),
                        "lock_protocol": "flock-v1",
                        "state": "released",
                    }
                    payload = (json.dumps(released, sort_keys=True) + "\n").encode()
                    os.ftruncate(fd, 0)
                    os.lseek(fd, 0, os.SEEK_SET)
                    os.write(fd, payload)
                    os.fsync(fd)
            if fd is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)

    @contextmanager
    def lock(self, run_id: str, *, wait_seconds: int = 0) -> Iterator[None]:
        lock_path = self.run_dir(run_id) / "run.lock"
        with self._exclusive_lock(
            lock_path,
            label="Run lock",
            active_message=(
                f"Run {run_id} is already active; lock exists at {lock_path}"
            ),
            wait_seconds=wait_seconds,
        ):
            yield

    def _scope_cloud_operation_lock_path(self) -> pathlib.Path:
        """Return a secure per-user lock path keyed by OpenStack identity."""
        uid = os.getuid() if hasattr(os, "getuid") else None
        runtime_dir = os.getenv("XDG_RUNTIME_DIR", "").strip()
        if runtime_dir:
            root = pathlib.Path(runtime_dir) / "neutron-flux"
        else:
            suffix = str(uid) if uid is not None else "user"
            root = pathlib.Path(tempfile.gettempdir()) / f"neutron-flux-{suffix}"
        if root.is_symlink():
            raise SuiteError(
                f"Global cloud operation lock directory is a symlink: {root}"
            )
        try:
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
            metadata = root.stat()
        except OSError as exc:
            raise SuiteError(
                f"Could not prepare global cloud operation lock directory {root}: {exc}"
            ) from exc
        if not stat.S_ISDIR(metadata.st_mode):
            raise SuiteError(
                f"Global cloud operation lock path is not a directory: {root}"
            )
        if uid is not None and metadata.st_uid != uid:
            raise SuiteError(
                f"Global cloud operation lock directory is not owned by uid {uid}: {root}"
            )
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            try:
                root.chmod(0o700)
                metadata = root.stat()
            except OSError as exc:
                raise SuiteError(
                    f"Could not secure global cloud operation lock directory {root}: {exc}"
                ) from exc
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                raise SuiteError(
                    f"Global cloud operation lock directory permissions are unsafe: {root}"
                )
        scope = cloud_operation_scope_fingerprint()
        return root / scope_lock_filename(scope)

    @contextmanager
    def cloud_operation_lock(self, *, wait_seconds: int = 0) -> Iterator[None]:
        """Serialize changing Flux processes targeting the same OpenStack scope."""
        lock_path = self._scope_cloud_operation_lock_path()
        with self._exclusive_lock(
            lock_path,
            label="OpenStack-scope cloud operation lock",
            active_message=(
                "Another Neutron Flux cloud operation process is active for this "
                f"OpenStack scope; lock exists at {lock_path}"
            ),
            wait_seconds=wait_seconds,
        ):
            yield

    def active_lock(self, run_id: str) -> bool:
        """Return whether a local run lock is currently held.

        New lock files use a kernel-backed advisory lock, so this remains
        accurate even when a container cannot inspect another process in
        ``/proc``. Legacy PID-only lock files retain their previous behaviour.
        """
        lock_path = self._run_path(run_id) / "run.lock"
        self._reject_existing_symlink(lock_path, label="Run lock")
        if not lock_path.exists():
            return False
        fd: int | None = None
        acquired = False
        try:
            flags = os.O_RDWR
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(lock_path, flags)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except BlockingIOError:
                return True
            try:
                raw = json.loads(lock_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                raw = None
            if isinstance(raw, dict) and raw.get("lock_protocol") == "flock-v1":
                return False
            return not self._stale_lock(lock_path)
        except OSError:
            return True
        finally:
            if fd is not None:
                if acquired:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)

    @staticmethod
    def _boot_id() -> str | None:
        try:
            return (
                pathlib.Path("/proc/sys/kernel/random/boot_id")
                .read_text(encoding="utf-8")
                .strip()
                or None
            )
        except OSError:
            return None

    @staticmethod
    def _process_start_ticks(pid: int) -> str | None:
        # Some hardened containers permit /proc/self but deny an explicit
        # /proc/<current-pid> lookup.  They identify the same process.
        path = (
            pathlib.Path("/proc/self/stat")
            if pid == os.getpid()
            else pathlib.Path(f"/proc/{pid}/stat")
        )
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return None
        # The process name is parenthesized and may contain spaces, so ordinary
        # whitespace splitting can shift the documented field numbers. Fields
        # after the final ')' begin with field 3 (state); starttime is field 22.
        closing = text.rfind(")")
        if closing < 0:
            return None
        fields = text[closing + 1 :].strip().split()
        return fields[19] if len(fields) > 19 else None

    @classmethod
    def _current_process_identity(cls) -> dict[str, object]:
        pid = os.getpid()
        return {
            "pid": pid,
            "process_start_ticks": cls._process_start_ticks(pid),
            "boot_id": cls._boot_id(),
        }

    @classmethod
    def _stale_lock(cls, path: pathlib.Path) -> bool:
        try:
            text = path.read_text(encoding="utf-8").strip()
            try:
                raw = json.loads(text)
            except json.JSONDecodeError:
                raw = int(text)
            if type(raw) is int:
                pid = raw
                expected_start = None
                expected_boot = None
            elif isinstance(raw, dict):
                if (
                    raw.get("lock_protocol") == "flock-v1"
                    and raw.get("state") == "released"
                ):
                    return True
                raw_pid = raw["pid"]
                if type(raw_pid) is int:
                    pid = raw_pid
                elif isinstance(raw_pid, str) and raw_pid.strip().isdigit():
                    pid = int(raw_pid.strip())
                else:
                    return True
                expected_start = raw.get("process_start_ticks")
                expected_boot = raw.get("boot_id")
            else:
                return True
            if pid <= 0:
                return True
        except (OSError, ValueError, KeyError, TypeError):
            # A competing process can observe the O_EXCL-created lock between
            # creation and the identity write.  Do not reclaim a fresh partial
            # file; only an invalid lock that has remained unchanged for a
            # conservative grace period is considered abandoned.
            try:
                return time.time() - path.stat().st_mtime >= 30.0
            except OSError:
                return True
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        if expected_boot and cls._boot_id() and expected_boot != cls._boot_id():
            return True
        current_start = cls._process_start_ticks(pid)
        if (
            expected_start
            and current_start
            and str(expected_start) != str(current_start)
        ):
            return True
        return False

    def print_status(self, checkpoint: RunCheckpoint) -> str:
        completed = len(checkpoint.completed_test_ids)
        failed = len(checkpoint.failed_test_ids)
        pending = len(checkpoint.pending_test_ids)
        active = ", ".join(checkpoint.active_group_ids) or "none"
        lock_path = self.run_dir(checkpoint.run_id) / "run.lock"
        if lock_path.exists():
            process_state = (
                "active process"
                if self.active_lock(checkpoint.run_id)
                else "stale lock"
            )
        else:
            process_state = "no active process"
        age = "unknown"
        try:
            updated = dt.datetime.fromisoformat(checkpoint.last_activity)
            now = dt.datetime.now(updated.tzinfo or dt.timezone.utc)
            age = f"{max(0, int((now - updated).total_seconds()))} seconds ago"
        except (TypeError, ValueError):
            pass
        return "\n".join(
            [
                f"Run ID: {checkpoint.run_id}",
                f"Suite pass: {checkpoint.metadata.get('repeat_index', 1)}/{checkpoint.metadata.get('repeat_count', 1)}",
                f"State: {checkpoint.state}",
                f"Process: {process_state}",
                f"Phase: {checkpoint.phase}",
                f"Current batch: {checkpoint.current_batch or 'none'}",
                f"Active groups: {active}",
                progress_text(
                    checkpoint.metadata.get("test_progress")
                    or {
                        "recorded": completed,
                        "known": len(
                            set(checkpoint.completed_test_ids)
                            | set(checkpoint.pending_test_ids)
                        ),
                        "plan_available": bool(completed or pending),
                    }
                ),
                *(
                    [
                        f"Pending checks: {checkpoint.metadata['test_progress']['pending']}"
                    ]
                    if checkpoint.metadata.get("test_progress", {}).get(
                        "schema_version"
                    )
                    == 3
                    else [
                        f"Completed tests: {completed}",
                        f"Failed tests: {failed}",
                        f"Pending tests: {pending}",
                    ]
                ),
                f"Cleanup state: {checkpoint.cleanup_state}",
                f"Last activity: {checkpoint.last_activity} ({age})",
                f"Report directory: {checkpoint.report_dir}",
            ]
        )
