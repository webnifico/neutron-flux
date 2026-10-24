from __future__ import annotations

import pathlib
import runpy
import sys
from zipfile import ZipFile

from .test_qualification_lifecycle import _Cleanup, _pair


def _same_az_pair(source, destination):
    return _pair(f"HQ-{source}-{destination}", source, destination, "az1", "az1")


class RotationCleanup(_Cleanup):
    def __init__(self, builder):
        super().__init__(builder)
        self.failed_side = None

    def cleanup_group_side(self, group_id, side):
        self.side_calls.append((group_id, side))
        return side != self.failed_side


def test_release_archive_excludes_coverage_worker_files(tmp_path, monkeypatch):
    builder = runpy.run_path(
        str(pathlib.Path(__file__).parents[1] / "scripts/build-release.py")
    )
    source = tmp_path / "source"
    package = source / "neutron_flux"
    package.mkdir(parents=True)
    (package / "constants.py").write_text('RELEASE_IDENTIFIER = "1.0.0"\n')
    (source / "README.md").write_text("Release contents\n")
    for name in (
        ".coverage",
        ".coverage.shard-00",
        ".coverage.host.123",
        "coverage.json",
    ):
        (source / name).write_bytes(b"temporary coverage output")
    archive = tmp_path / "candidate.zip"
    monkeypatch.setitem(builder["main"].__globals__, "ROOT", source)
    monkeypatch.setattr(sys, "argv", ["build-release.py", "--output", str(archive)])

    assert builder["main"]() == 0
    with ZipFile(archive) as zipped:
        assert set(zipped.namelist()) == {
            "neutron-flux/README.md",
            "neutron-flux/neutron_flux/constants.py",
        }
