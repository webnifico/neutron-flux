"""Load sibling diagnostic artifacts for an offline report, without following stored paths."""

from __future__ import annotations

import json
import pathlib
from typing import Any

from .operator_evidence import diagnostic_snapshot, mapping
from .utils import unique_safe_name


def _read_bounded(path: pathlib.Path, limit: int) -> str:
    if path.is_symlink() or not path.is_file():
        return ""
    with path.open("rb") as stream:
        content = stream.read(limit + 1)
    if len(content) > limit:
        return ""
    return content.decode("utf-8", errors="replace")


def with_diagnostic_artifacts(
    payload: dict[str, Any], run_dir: pathlib.Path
) -> dict[str, Any]:
    """Enrich presentation only. Historical contracts/details remain unchanged."""
    results = []
    root = run_dir / "failures"
    for result in payload.get("results") or []:
        result = dict(result)
        details = mapping(result.get("details"))
        test_id = str(result.get("test_id") or "")
        if (
            details.get("diagnostic_snapshot")
            or not details.get("diagnostic_directory")
            or not test_id
        ):
            results.append(result)
            continue
        directory = root / unique_safe_name(test_id, 120)
        try:
            if root.is_symlink() or directory.is_symlink():
                raise ValueError("Diagnostic directory is a symbolic link")
            raw = _read_bounded(directory / "diagnostics.json", 2_000_000)
            snapshot = mapping(json.loads(raw)) if raw else {}
            if snapshot.get("test") != test_id:
                raise ValueError("Matching diagnostic snapshot is unavailable")
            for role, guest in mapping(snapshot.get("guests")).items():
                if role in {"source", "destination"} and isinstance(guest, dict):
                    output = _read_bounded(directory / f"{role}.txt", 256_000)
                    guest["output"] = output or guest.get("output") or ""
                    if not guest["output"]:
                        guest["usable"] = False
                        guest["error"] = (
                            guest.get("error")
                            or "Saved guest transcript is unavailable: missing, empty, symlinked, or larger than the report's size limit."
                        )
            result["operator_diagnostics"] = diagnostic_snapshot(snapshot)
        except (OSError, ValueError) as exc:
            result["operator_diagnostic_note"] = (
                f"Saved guest diagnostics could not be embedded: {exc}."
            )
        results.append(result)
    return {**payload, "results": results}
