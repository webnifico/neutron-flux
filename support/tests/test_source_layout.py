"""Source archives reject release-specific names and generated validation debris."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path
from zipfile import ZipFile

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    ("relative", "contents", "reason"),
    [
        (
            "support/tests/test_r99_cleanup.py",
            "",
            "name source and fixtures by behavior",
        ),
        (
            "support/tests/test_rc99_cleanup.py",
            "",
            "name source and fixtures by behavior",
        ),
        (
            "support/fixtures/cleanup-rc99.json",
            "{}",
            "name source and fixtures by behavior",
        ),
        (
            "support/fixtures/rc99-cleanup.json",
            "{}",
            "name source and fixtures by behavior",
        ),
        ("support/docs/RC99-VALIDATION.md", "", "name source and fixtures by behavior"),
        ("neutron_flux/reporting_r99.py", "", "name source and fixtures by behavior"),
        ("support/validation/current.json", "{}", "evidence belongs outside source"),
        ("support/history/test_cleanup.py.txt", "", "evidence belongs outside source"),
        ("support/test-output.log", "", "logs belong outside source"),
        ("recovery.sh", "", "recovery artifacts belong outside source"),
        ("recovery.md", "", "recovery artifacts belong outside source"),
        ("results.json", "{}", "recovery artifacts belong outside source"),
        ("manifest.jsonl", "{}", "recovery artifacts belong outside source"),
        ("validation/latest.json", "{}", "evidence belongs outside source"),
        (
            "live-certification-artifacts/latest.json",
            "{}",
            "evidence belongs outside source",
        ),
        ("neutron_flux/config.py.bak", "", "temporary editing artifacts"),
        ("neutron_flux/config.py.orig", "", "temporary editing artifacts"),
        ("neutron_flux/config.py.rej", "", "temporary editing artifacts"),
        ("support/cleanup-notes.md~", "", "temporary editing artifacts"),
        (
            "support/tests/test_cleanup.py",
            "def test_rc99_cleanup(): pass\n",
            "release-named test identifier",
        ),
        (
            "support/tests/test_version.py",
            'EXPECTED = "1.0.0rc99"\n',
            "derive release identity",
        ),
    ],
)
def test_archive_rejects_historical_source_debris(
    tmp_path, monkeypatch, relative, contents, reason
):
    builder = runpy.run_path(str(ROOT / "support/scripts/build-release.py"))
    source = tmp_path / "source"
    package = source / "neutron_flux"
    package.mkdir(parents=True)
    (package / "constants.py").write_text('RELEASE_IDENTIFIER = "1.0.0"\n')
    invalid = source / relative
    invalid.parent.mkdir(parents=True, exist_ok=True)
    invalid.write_text(contents)
    archive = tmp_path / "candidate.zip"
    monkeypatch.setitem(builder["main"].__globals__, "ROOT", source)
    monkeypatch.setattr(sys, "argv", ["build-release.py", "--output", str(archive)])

    with pytest.raises(RuntimeError, match=reason):
        builder["main"]()
    assert not archive.exists()


def test_archive_keeps_behavior_tests_and_json_fixtures(tmp_path, monkeypatch):
    builder = runpy.run_path(str(ROOT / "support/scripts/build-release.py"))
    source = tmp_path / "source"
    files = {
        "neutron_flux/constants.py": 'RELEASE_IDENTIFIER = "1.0.0"\n',
        "support/tests/test_cleanup.py": "def test_cleanup_preserves_ownership(): pass\n",
        "support/tests/fixtures/cleanup_unknown_inventory.json": '{"schema_version": 1, "inventory": null}\n',
        "support/docs/TESTING.md": "# Testing\n",
    }
    for relative, contents in files.items():
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
    archive = tmp_path / "candidate.zip"
    monkeypatch.setitem(builder["main"].__globals__, "ROOT", source)
    monkeypatch.setattr(sys, "argv", ["build-release.py", "--output", str(archive)])

    assert builder["main"]() == 0
    with ZipFile(archive) as packaged:
        assert set(packaged.namelist()) == {f"neutron-flux/{name}" for name in files}


def test_archive_excludes_all_supported_archive_formats(tmp_path, monkeypatch):
    builder = runpy.run_path(str(ROOT / "support/scripts/build-release.py"))
    monkeypatch.setitem(builder["included"].__globals__, "ROOT", tmp_path)
    for suffix in (
        ".zip",
        ".tar.gz",
        ".tar.xz",
        ".tar.bz2",
        ".tgz",
        ".txz",
        ".whl",
        ".sha256",
    ):
        path = tmp_path / ("old-release" + suffix)
        path.write_bytes(b"old build")
        assert not builder["included"](path)


def test_source_audit_detects_disconnected_modules(tmp_path, monkeypatch):
    auditor = runpy.run_path(str(ROOT / "support/scripts/source-audit.py"))
    for value in auditor.values():
        if callable(value) and hasattr(value, "__globals__"):
            monkeypatch.setitem(value.__globals__, "ROOT", tmp_path)
    package = tmp_path / "neutron_flux"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "__main__.py").write_text("from .cli import main\nmain()\n")
    (package / "cli.py").write_text("def main(): pass\n")
    (package / "unused.py").write_text("def old_workflow(): pass\n")
    assert auditor["unreachable_modules"](list(package.glob("*.py"))) == [
        "neutron_flux.unused"
    ]
