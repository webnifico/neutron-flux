from __future__ import annotations

import re
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

from neutron_flux.constants import (
    DISPLAY_VERSION,
    RELEASE_IDENTIFIER,
    RELEASE_REVISION,
    RELEASE_STAGE,
    VERSION,
)

ROOT = Path(__file__).resolve().parents[2]


def test_release_identity_is_consistent():
    match = re.fullmatch(r"(\d+\.\d+\.\d+)(rc\d+)?", VERSION)
    assert match is not None
    core, revision = match.groups()
    assert RELEASE_REVISION == (revision or "")
    assert RELEASE_STAGE == ("release candidate" if revision else "stable")
    assert RELEASE_IDENTIFIER == (f"{core}-{revision}" if revision else core)
    assert DISPLAY_VERSION == f"{RELEASE_IDENTIFIER} ({RELEASE_STAGE})"


def test_release_builder_uses_canonical_identity():
    builder = runpy.run_path(str(ROOT / "support/scripts/build-release.py"))
    archive_filename = builder["archive_filename"]
    release_identifier = builder["release_identifier"]

    assert release_identifier() == RELEASE_IDENTIFIER
    assert (
        archive_filename(RELEASE_IDENTIFIER)
        == f"neutron-flux-v{RELEASE_IDENTIFIER}.zip"
    )
    assert archive_filename(RELEASE_IDENTIFIER, "build2") == (
        f"neutron-flux-v{RELEASE_IDENTIFIER}-build2.zip"
    )


def test_cli_reports_human_release_identity():
    completed = subprocess.run(
        [sys.executable, "-m", "neutron_flux", "--version"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert completed.stdout.strip() == f"neutron-flux {DISPLAY_VERSION}"


def test_release_identity_checks_accept_coherent_stable_metadata(tmp_path):
    """The identity helpers support stable metadata; this is not a full gate run."""
    package = tmp_path / "neutron_flux"
    package.mkdir()
    scripts = tmp_path / "support/scripts"
    scripts.mkdir(parents=True)
    (scripts / "build-release.py").write_text(
        (ROOT / "support/scripts/build-release.py").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    constants = (ROOT / "neutron_flux/constants.py").read_text(encoding="utf-8")
    (package / "constants.py").write_text(
        re.sub(r'^VERSION = ".*"$', 'VERSION = "1.0.0"', constants, flags=re.MULTILINE),
        encoding="utf-8",
    )
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        pyproject.replace(
            "Development Status :: 4 - Beta",
            "Development Status :: 5 - Production/Stable",
        ),
        encoding="utf-8",
    )

    validator = runpy.run_path(str(ROOT / "support/scripts/validate-release.py"))
    validate_identity = validator["validate_release_identity"]
    validate_identity.__globals__["ROOT"] = tmp_path
    validate_identity.__globals__["PACKAGE"] = package
    identity = validate_identity()
    assert identity == {
        "VERSION": "1.0.0",
        "RELEASE_STAGE": "stable",
        "RELEASE_REVISION": "",
        "RELEASE_IDENTIFIER": "1.0.0",
        "DISPLAY_VERSION": "1.0.0 (stable)",
    }

    auditor = runpy.run_path(str(ROOT / "support/scripts/source-audit.py"))
    check_versions = auditor["check_versions"]
    check_versions.__globals__["ROOT"] = tmp_path
    check_versions.__globals__["PACKAGE"] = package
    check_versions()


def test_release_quality_gates_fail_closed_when_a_tool_is_missing(monkeypatch):
    validator = runpy.run_path(str(ROOT / "support/scripts/validate-release.py"))
    run_quality_gates = validator["run_quality_gates"]
    imported = run_quality_gates.__globals__["importlib"]
    real_find_spec = imported.util.find_spec

    def find_spec(module: str):
        return None if module == "bandit" else real_find_spec(module)

    monkeypatch.setattr(imported.util, "find_spec", find_spec)
    monkeypatch.setitem(
        run_quality_gates.__globals__,
        "run",
        lambda *_args, **_kwargs: pytest.fail(
            "No quality command may run after a missing dependency is detected"
        ),
    )

    with pytest.raises(RuntimeError, match=r"missing: bandit.*\[test,dev\]"):
        run_quality_gates()
