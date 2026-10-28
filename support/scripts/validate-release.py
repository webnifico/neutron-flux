#!/usr/bin/env python3
"""Run offline release gates from a clean source checkout."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import re
import runpy
import subprocess
import sys
import tempfile
import zipfile
from email.parser import Parser

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 release gate
    import tomli as tomllib  # type: ignore[no-redef]

ROOT = pathlib.Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "neutron_flux"
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
QUALITY_TOOLS = {"bandit", "mypy", "ruff"}


def executable_module_available(module: str) -> bool:
    """Return whether ``python -m <module>`` has an executable entry point."""

    try:
        return importlib.util.find_spec(f"{module}.__main__") is not None
    except (ImportError, ModuleNotFoundError, AttributeError):
        return False


def run(
    *command: str,
    cwd: pathlib.Path = ROOT,
    env: dict[str, str] | None = None,
    timeout_seconds: int | None = None,
) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=True,
        timeout=timeout_seconds,
    )


def source_members() -> set[str]:
    return {
        path.relative_to(ROOT).as_posix()
        for path in PACKAGE.rglob("*.py")
        if "__pycache__" not in path.parts
    }


def validate_release_identity() -> dict[str, str]:
    values = runpy.run_path(str(PACKAGE / "constants.py"))
    identity = {
        key: values.get(key)
        for key in (
            "VERSION",
            "RELEASE_STAGE",
            "RELEASE_REVISION",
            "RELEASE_IDENTIFIER",
            "DISPLAY_VERSION",
        )
    }
    if not all(
        isinstance(identity[key], str) and identity[key]
        for key in (
            "VERSION",
            "RELEASE_STAGE",
            "RELEASE_IDENTIFIER",
            "DISPLAY_VERSION",
        )
    ) or not isinstance(identity["RELEASE_REVISION"], str):
        raise RuntimeError(f"Incomplete release identity in constants.py: {identity}")

    version = identity["VERSION"]
    match = re.fullmatch(r"(?P<base>\d+\.\d+\.\d+)(?P<revision>rc\d+)?", version)
    if match is None:
        raise RuntimeError(f"Invalid stable or RC package version: {version!r}")
    revision = match.group("revision") or ""
    expected_identifier = (
        f"{match.group('base')}-{revision}" if revision else match.group("base")
    )
    expected_stage = "release candidate" if revision else "stable"
    expected = {
        "RELEASE_STAGE": expected_stage,
        "RELEASE_REVISION": revision,
        "RELEASE_IDENTIFIER": expected_identifier,
        "DISPLAY_VERSION": f"{expected_identifier} ({expected_stage})",
    }
    for key, value in expected.items():
        if identity[key] != value:
            raise RuntimeError(
                f"Release identity mismatch for {key}: "
                f"expected {value!r}, got {identity[key]!r}"
            )

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject["project"]
    if "version" in project or "version" not in project.get("dynamic", []):
        raise RuntimeError("pyproject.toml must declare only a dynamic version")
    version_source = (
        pyproject.get("tool", {})
        .get("setuptools", {})
        .get("dynamic", {})
        .get("version", {})
        .get("attr")
    )
    if version_source != "neutron_flux.constants.VERSION":
        raise RuntimeError(
            "Package metadata is not derived from neutron_flux.constants.VERSION"
        )
    expected_classifier = (
        "Development Status :: 4 - Beta"
        if revision
        else "Development Status :: 5 - Production/Stable"
    )
    if expected_classifier not in project.get("classifiers", []):
        raise RuntimeError(f"Package stage requires classifier {expected_classifier!r}")

    builder = runpy.run_path(str(ROOT / "support/scripts/build-release.py"))
    builder_identifier = builder["release_identifier"]()
    default_archive = builder["archive_filename"](builder_identifier)
    expected_archive = f"neutron-flux-v{expected_identifier}.zip"
    if builder_identifier != expected_identifier or default_archive != expected_archive:
        raise RuntimeError(
            "Release builder identity mismatch: "
            f"identifier={builder_identifier!r}, archive={default_archive!r}"
        )

    dev_requirements = project.get("optional-dependencies", {}).get("dev", [])
    declared_tools = {
        re.split(r"[<>=!~;\s\[]", requirement, maxsplit=1)[0].lower()
        for requirement in dev_requirements
    }
    missing_tools = sorted(QUALITY_TOOLS - declared_tools)
    if missing_tools:
        raise RuntimeError(
            f"Development dependencies omit quality tools: {missing_tools}"
        )
    print(
        "Release identity: "
        f"package={version}, release={identity['RELEASE_IDENTIFIER']}",
        flush=True,
    )
    return identity  # type: ignore[return-value]


def validate_wheel(wheel: pathlib.Path, expected_version: str) -> None:
    expected = source_members()
    with zipfile.ZipFile(wheel) as archive:
        members = set(archive.namelist())
        metadata_files = sorted(
            member for member in members if member.endswith(".dist-info/METADATA")
        )
        if len(metadata_files) != 1:
            raise RuntimeError(
                f"Expected one wheel metadata file, found: {metadata_files}"
            )
        metadata = Parser().parsestr(archive.read(metadata_files[0]).decode("utf-8"))
        archive.testzip()
    if metadata.get("Name") != "neutron-flux":
        raise RuntimeError(f"Wheel project name is incorrect: {metadata.get('Name')!r}")
    if metadata.get("Version") != expected_version:
        raise RuntimeError(
            "Wheel version does not match the runtime source: "
            f"{metadata.get('Version')!r} != {expected_version!r}"
        )
    if f"-{expected_version}-" not in wheel.name:
        raise RuntimeError(
            f"Wheel filename does not contain {expected_version!r}: {wheel}"
        )
    missing = sorted(expected - members)
    if missing:
        raise RuntimeError(f"Wheel omitted production modules: {missing}")
    unexpected = sorted(
        member
        for member in members - expected
        if member.startswith("neutron_flux/") and member.endswith(".py")
    )
    if unexpected:
        raise RuntimeError(f"Wheel contains stale production modules: {unexpected}")


def build_wheel(source: pathlib.Path, output: pathlib.Path) -> pathlib.Path:
    environment = os.environ.copy()
    environment["PIP_CACHE_DIR"] = str(output.parent / "pip-cache")
    environment["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    environment["PIP_NO_INPUT"] = "1"
    if executable_module_available("build"):
        run(
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(output),
            ".",
            cwd=source,
            env=environment,
        )
    elif executable_module_available("pip"):
        run(
            sys.executable,
            "-m",
            "pip",
            "wheel",
            ".",
            "--no-deps",
            "--no-build-isolation",
            "--no-index",
            "--progress-bar",
            "off",
            "--wheel-dir",
            str(output),
            cwd=source,
            env=environment,
        )
    else:
        raise RuntimeError(
            "Wheel validation needs a PEP 517 frontend. "
            "Install the project development dependencies with "
            "`python -m pip install -e '.[test,dev]'`."
        )
    wheels = list(output.glob("*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"Expected one wheel, found: {wheels}")
    return wheels[0]


def installed_wheel_smoke(
    wheel: pathlib.Path,
    directory: pathlib.Path,
    identity: dict[str, str],
) -> None:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    site_packages = directory / "site-packages"
    smoke_dir = directory / "work"
    site_packages.mkdir(parents=True)
    smoke_dir.mkdir(parents=True)
    with zipfile.ZipFile(wheel) as archive:
        archive.extractall(site_packages)
        entry_points = [
            name
            for name in archive.namelist()
            if name.endswith(".dist-info/entry_points.txt")
        ]
        if len(entry_points) != 1:
            raise RuntimeError(
                f"Expected one wheel entry-point file, found: {entry_points}"
            )
        entry_text = archive.read(entry_points[0]).decode("utf-8")
    if "neutron-flux = neutron_flux.cli:main" not in entry_text:
        raise RuntimeError("Wheel console entry point is missing or incorrect")
    environment["PYTHONPATH"] = str(site_packages)
    run(
        sys.executable,
        "-m",
        "neutron_flux",
        "--version",
        cwd=smoke_dir,
        env=environment,
    )
    run(sys.executable, "-m", "neutron_flux", "--help", cwd=smoke_dir, env=environment)
    run(
        sys.executable,
        "-c",
        (
            "import pathlib, neutron_flux; "
            "from importlib.metadata import version as installed_version; "
            "from neutron_flux.constants import DISPLAY_VERSION, RELEASE_IDENTIFIER; "
            "from neutron_flux.cli import parser; "
            f"root = pathlib.Path({str(site_packages)!r}).resolve(); "
            "module = pathlib.Path(neutron_flux.__file__).resolve(); "
            "assert module.is_relative_to(root), (module, root); "
            f"assert neutron_flux.__version__ == {identity['VERSION']!r}; "
            f"assert installed_version('neutron-flux') == {identity['VERSION']!r}; "
            f"assert RELEASE_IDENTIFIER == {identity['RELEASE_IDENTIFIER']!r}; "
            f"assert DISPLAY_VERSION == {identity['DISPLAY_VERSION']!r}; "
            "assert parser().prog == 'neutron-flux'; "
            "print(DISPLAY_VERSION)"
        ),
        cwd=smoke_dir,
        env=environment,
    )
    run(
        sys.executable,
        "-c",
        (
            "from neutron_flux.cli import parser; "
            "from neutron_flux.config import Config; "
            "value = Config.from_args(parser().parse_args(['run', '--image', 'debian-13', '--flavor', 'small', '--storage', 'host', '--external-networks', 'Public1', '--live-attempts', '17'])); "
            "assert value.live_migration_attempts == 17; "
            "assert value.migration_submission_budget == 18; "
            "assert value.performance_enabled"
        ),
        cwd=smoke_dir,
        env=environment,
    )

    payload = {
        "schema_version": 1,
        "tool": "neutron-flux",
        "tool_version": identity["DISPLAY_VERSION"],
        "run": {
            "run_id": "wheel-smoke",
            "action": "run",
            "started_at": "2026-07-22T00:00:00+00:00",
            "finished_at": "2026-07-22T00:01:00+00:00",
            "final_status": "PASS",
        },
        "configuration": {"evidence_enabled": True},
        "summary": {
            "counts": {"PASS": 1},
            "total_results": 1,
            "performance": {},
            "categories": {"smoke": {"PASS": 1}},
        },
        "results": [
            {
                "test_id": "WHEEL-SMOKE",
                "display_name": "Installed wheel smoke",
                "category": "smoke",
                "status": "PASS",
                "message": "installed command completed",
                "details": {},
            }
        ],
        "performance": [],
        "resources": [],
        "cleanup": {"attempted": True, "complete": True},
        "events": [],
        "setup_failures": [],
        "error": None,
        "traceback": None,
    }
    baseline = smoke_dir / "baseline.json"
    candidate = smoke_dir / "candidate.json"
    baseline.write_text(json.dumps(payload), encoding="utf-8")
    candidate_payload = json.loads(json.dumps(payload))
    candidate_payload["run"]["run_id"] = "wheel-smoke-candidate"
    candidate_payload["run"]["started_at"] = "2026-07-23T00:00:00+00:00"
    candidate.write_text(json.dumps(candidate_payload), encoding="utf-8")
    report_dir = smoke_dir / "report-output"
    comparison_dir = smoke_dir / "comparison-output"
    trend_dir = smoke_dir / "trend-output"
    run(
        sys.executable,
        "-m",
        "neutron_flux",
        "report",
        str(candidate),
        "--output-dir",
        str(report_dir),
        cwd=smoke_dir,
        env=environment,
    )
    run(
        sys.executable,
        "-m",
        "neutron_flux",
        "compare",
        str(baseline),
        str(candidate),
        "--output-dir",
        str(comparison_dir),
        cwd=smoke_dir,
        env=environment,
    )
    run(
        sys.executable,
        "-m",
        "neutron_flux",
        "trend",
        str(baseline),
        str(candidate),
        "--output-dir",
        str(trend_dir),
        cwd=smoke_dir,
        env=environment,
    )
    expected_outputs = [
        report_dir / "report.html",
        report_dir / "report.txt",
        report_dir / "report.junit.xml",
        report_dir / "host-qualification.csv",
        report_dir / "incident-summary.md",
        report_dir / "replay-plan.json",
        report_dir / "replay-plan.txt",
        comparison_dir / "comparison.html",
        comparison_dir / "comparison.json",
        comparison_dir / "comparison.txt",
        comparison_dir / "replay-plan.json",
        comparison_dir / "replay-plan.txt",
        trend_dir / "trend.html",
        trend_dir / "trend.json",
        trend_dir / "trend.txt",
    ]
    missing = [str(path) for path in expected_outputs if not path.is_file()]
    if missing:
        raise RuntimeError(f"Installed offline commands omitted outputs: {missing}")


def validate_source_archive(directory: pathlib.Path) -> pathlib.Path:
    directory.mkdir(parents=True, exist_ok=True)
    first = directory / "first.zip"
    second = directory / "second.zip"
    for output in (first, second):
        run(
            sys.executable,
            "support/scripts/build-release.py",
            "validation",
            "--output",
            str(output),
        )
    first_hash = hashlib.sha256(first.read_bytes()).hexdigest()
    second_hash = hashlib.sha256(second.read_bytes()).hexdigest()
    if first_hash != second_hash:
        raise RuntimeError(
            f"Release ZIP is not reproducible: {first_hash} != {second_hash}"
        )
    with zipfile.ZipFile(first) as archive:
        archive.testzip()
        names = archive.namelist()
        if not names or any(not name.startswith("neutron-flux/") for name in names):
            raise RuntimeError("Release ZIP does not have one neutron-flux root")
        if any(item.date_time != ZIP_TIMESTAMP for item in archive.infolist()):
            raise RuntimeError("Release ZIP contains variable timestamps")
        forbidden = {
            "neutron-flux/neutron_flux/inventory_recording.py",
        }
        leaked = sorted(
            name
            for name in names
            if name in forbidden
            or name.startswith(
                (
                    "neutron-flux/support/recordings/",
                    "neutron-flux/support/history/",
                    "neutron-flux/support/validation/",
                )
            )
        )
        if leaked:
            raise RuntimeError(
                f"Removed cloud-recording artifacts leaked into ZIP: {leaked}"
            )
        report_leaks = sorted(
            name for name in names if "/neutron-flux-reports/" in name
        )
        if report_leaks:
            raise RuntimeError(
                "Generated run evidence leaked into release ZIP: "
                + ", ".join(report_leaks[:5])
            )
        workflow = "neutron-flux/.github/workflows/live-certification.yml"
        if workflow not in names:
            raise RuntimeError(
                "Release ZIP omitted the active live-certification workflow"
            )
        extract_root = directory / "extracted"
        archive.extractall(extract_root)
    source = extract_root / "neutron-flux"
    run(sys.executable, "-m", "compileall", "-q", "neutron_flux", cwd=source)
    run(sys.executable, "support/scripts/source-audit.py", cwd=source)
    run(sys.executable, "support/scripts/openstack-command-audit.py", cwd=source)
    return source


def run_quality_gates() -> None:
    gates = (
        ("ruff", ("check", "neutron_flux", "support")),
        (
            "ruff",
            ("format", "--check", "neutron_flux", "support"),
        ),
        ("bandit", ("-q", "-r", "neutron_flux", "-ll")),
        ("mypy", ()),
    )
    missing = sorted(
        {module for module, _ in gates if importlib.util.find_spec(module) is None}
    )
    if missing:
        raise RuntimeError(
            "Release quality gates require every development tool; missing: "
            f"{', '.join(missing)}. Install them with "
            'python -m pip install ".[test,dev]".'
        )
    for module, arguments in gates:
        run(sys.executable, "-m", module, *arguments)


def coverage_test_shards(shard_count: int = 8) -> list[list[pathlib.Path]]:
    """Balance test files across deterministic coverage subprocesses."""

    if shard_count < 1:
        raise ValueError("Coverage shard count must be positive")
    test_root = ROOT / "support" / "tests"
    test_files = sorted(test_root.glob("test_*.py"))
    if not test_files:
        raise RuntimeError(f"No release tests were found under {test_root}")
    shards: list[list[pathlib.Path]] = [[] for _ in range(shard_count)]
    sizes = [0 for _ in range(shard_count)]
    for path in sorted(test_files, key=lambda item: (-item.stat().st_size, item.name)):
        index = min(range(shard_count), key=lambda item: (sizes[item], item))
        shards[index].append(path)
        sizes[index] += path.stat().st_size
    return [sorted(shard) for shard in shards if shard]


def run_test_and_coverage_gates() -> None:
    """Run the complete suite once, then collect coverage in isolated shards."""

    environment = os.environ.copy()
    # Third-party pytest plugins installed in the caller's environment must not
    # alter release-gate behavior. Load only the project-declared plugins.
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    run(
        sys.executable,
        "-m",
        "pytest",
        "-vv",
        "-W",
        "error",
        "-p",
        "pytest_asyncio.plugin",
        env=environment,
        timeout_seconds=600,
    )
    for path in [ROOT / ".coverage", *ROOT.glob(".coverage.*")]:
        if path.is_file():
            path.unlink()
    shards = coverage_test_shards()
    for index, shard in enumerate(shards):
        shard_environment = environment.copy()
        shard_environment["COVERAGE_FILE"] = str(ROOT / f".coverage.shard-{index:02d}")
        arguments = [
            sys.executable,
            "-m",
            "coverage",
            "run",
            "--branch",
            "--source=neutron_flux",
            "-m",
            "pytest",
            "-q",
            "-W",
            "error",
            "-p",
            "pytest_asyncio.plugin",
        ]
        arguments.extend(str(path.relative_to(ROOT)) for path in shard)
        run(*arguments, env=shard_environment, timeout_seconds=300)
    run(
        sys.executable,
        "-m",
        "coverage",
        "combine",
        timeout_seconds=120,
    )
    run(
        sys.executable,
        "-m",
        "coverage",
        "report",
        "--skip-covered",
        "--fail-under=67",
        timeout_seconds=120,
    )


def main() -> int:
    identity = validate_release_identity()
    run(sys.executable, "-m", "compileall", "-q", "neutron_flux")
    run(sys.executable, "support/scripts/source-audit.py")
    run(sys.executable, "support/scripts/openstack-command-audit.py")
    run_quality_gates()
    run_test_and_coverage_gates()
    with tempfile.TemporaryDirectory(prefix="neutron-flux-release-") as temporary:
        directory = pathlib.Path(temporary)
        source = validate_source_archive(directory / "source-archive")
        wheel_dir = directory / "wheel"
        wheel_dir.mkdir()
        wheel = build_wheel(source, wheel_dir)
        validate_wheel(wheel, identity["VERSION"])
        installed_wheel_smoke(wheel, directory / "installed-smoke", identity)
    print("Release validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
