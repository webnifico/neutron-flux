#!/usr/bin/env python3
"""Create a clean revisioned source ZIP without local build/test artifacts."""

from __future__ import annotations

import argparse
import ast
import pathlib
import re
import runpy
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
EXCLUDED_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".nox",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "htmlcov",
    "neutron-flux-reports",
    "venv",
}
EXCLUDED_NAMES = {".coverage", "coverage.json"}
INCLUDED_EXAMPLE_ARCHIVES = {
    "support/examples/neutron-flux-v1.0.0-lab-report.zip",
}
EXCLUDED_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".whl",
    ".zip",
    ".tar",
    ".gz",
    ".xz",
    ".bz2",
    ".tgz",
    ".txz",
    ".sha256",
}
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
REVISION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
RELEASE_NAMED_SOURCE = re.compile(r"(?:^|[-_])rc?\d+(?=$|[-_.])", re.IGNORECASE)
GENERATED_SUPPORT_DIRS = {"history", "validation", "recordings"}
GENERATED_RUN_FILES = {
    "results.json",
    "state.json",
    "plan.json",
    "manifest.jsonl",
    "cloud-operations.jsonl",
    "resource-identities.jsonl",
    "mutations.jsonl",
    "events.jsonl",
    "report.html",
    "report.txt",
    "report.junit.xml",
    "recovery.md",
    "recovery.sh",
}
TEMPORARY_SUFFIXES = {".bak", ".orig", ".rej", ".swp", ".swo", ".tmp"}
GENERATED_ROOT_DIRS = {
    "live-certification-artifacts",
    "validation",
    "history",
    "recordings",
}


def release_identifier() -> str:
    constants = runpy.run_path(str(ROOT / "neutron_flux" / "constants.py"))
    identifier = constants.get("RELEASE_IDENTIFIER")
    if not isinstance(identifier, str) or not identifier:
        raise RuntimeError("constants.py does not define a release identifier")
    if not REVISION_PATTERN.fullmatch(identifier):
        raise RuntimeError(f"Unsafe release identifier: {identifier!r}")
    return identifier


def archive_filename(identifier: str, revision: str | None = None) -> str:
    suffix = f"-{revision}" if revision else ""
    return f"neutron-flux-v{identifier}{suffix}.zip"


def excluded_file(name: str) -> bool:
    relative = pathlib.PurePosixPath(name)
    if relative.as_posix() in INCLUDED_EXAMPLE_ARCHIVES:
        return False
    basename = relative.name
    return (
        basename in EXCLUDED_NAMES
        or basename.startswith(".coverage.")
        or relative.suffix in EXCLUDED_SUFFIXES
    )


def included(path: pathlib.Path) -> bool:
    relative = path.relative_to(ROOT)
    if any(
        part in EXCLUDED_DIRS or part.endswith(".egg-info") for part in relative.parts
    ):
        return False
    if excluded_file(relative.as_posix()):
        return False
    return path.is_file() and not path.is_symlink()


def validate_source_layout() -> None:
    """Keep behavior-based source and fixtures separate from generated evidence."""
    errors: list[str] = []
    for path in sorted(ROOT.rglob("*")):
        relative = path.relative_to(ROOT)
        if any(
            part in EXCLUDED_DIRS or part.endswith(".egg-info")
            for part in relative.parts
        ):
            continue
        if (
            len(relative.parts) == 2
            and relative.parts[0] == "support"
            and relative.parts[1] in GENERATED_SUPPORT_DIRS
        ):
            errors.append(
                f"{relative}: historical/generated evidence belongs outside source"
            )
        if relative.parts[0] in GENERATED_ROOT_DIRS:
            errors.append(f"{relative}: generated evidence belongs outside source")
        if not path.is_file() or excluded_file(relative.as_posix()):
            continue
        if any(RELEASE_NAMED_SOURCE.search(part) for part in relative.parts):
            errors.append(
                f"{relative}: name source and fixtures by behavior, not release"
            )
        if path.suffix == ".log":
            errors.append(f"{relative}: generated logs belong outside source")
        if path.name in GENERATED_RUN_FILES and relative.parts[:3] != (
            "support",
            "tests",
            "fixtures",
        ):
            errors.append(
                f"{relative}: generated run or recovery artifacts belong outside source"
            )
        if path.suffix in TEMPORARY_SUFFIXES or path.name.endswith("~"):
            errors.append(
                f"{relative}: temporary editing artifacts belong outside source"
            )
        if relative.parts[:2] == ("support", "tests") and path.suffix == ".py":
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                ):
                    if RELEASE_NAMED_SOURCE.search(node.name):
                        errors.append(
                            f"{relative}:{node.lineno}: release-named test identifier {node.name}"
                        )
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    if re.fullmatch(
                        r"(?:neutron-flux-v)?\d+\.\d+\.\d+-?rc\d+(?:\.zip)?", node.value
                    ):
                        errors.append(
                            f"{relative}:{node.lineno}: derive release identity from constants"
                        )
    if errors:
        raise RuntimeError("Source layout failed:\n- " + "\n- ".join(errors))


def archive_info(path: pathlib.Path) -> zipfile.ZipInfo:
    relative = pathlib.Path("neutron-flux") / path.relative_to(ROOT)
    info = zipfile.ZipInfo(relative.as_posix(), date_time=ZIP_TIMESTAMP)
    info.create_system = 3
    mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
    info.external_attr = mode << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    info.flag_bits |= 0x800
    return info


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "revision",
        nargs="?",
        help="optional build revision appended to the canonical release identity",
    )
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    if args.revision is not None and not REVISION_PATTERN.fullmatch(args.revision):
        raise SystemExit(
            "revision must contain only letters, digits, dot, underscore, and hyphen"
        )
    identifier = release_identifier()
    output = args.output or ROOT.parent / archive_filename(identifier, args.revision)
    output = output.resolve()

    validate_source_layout()

    symlinks = [
        path.relative_to(ROOT).as_posix()
        for path in ROOT.rglob("*")
        if path.is_symlink()
        and not any(part in EXCLUDED_DIRS for part in path.relative_to(ROOT).parts)
    ]
    if symlinks:
        raise RuntimeError(
            "Release source contains symbolic links, which are not packaged: "
            + ", ".join(sorted(symlinks))
        )
    files = sorted(path for path in ROOT.rglob("*") if included(path))
    with zipfile.ZipFile(output, "w") as archive:
        for path in files:
            archive.writestr(
                archive_info(path),
                path.read_bytes(),
                compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            )

    with zipfile.ZipFile(output) as archive:
        bad = [
            name
            for name in archive.namelist()
            if any(
                part in EXCLUDED_DIRS or part.endswith(".egg-info")
                for part in pathlib.PurePosixPath(name).parts
            )
            or excluded_file(
                pathlib.PurePosixPath(name).relative_to("neutron-flux").as_posix()
            )
        ]
        if bad:
            raise RuntimeError(f"Release archive contains excluded artifacts: {bad}")
        timestamps = {item.date_time for item in archive.infolist()}
        if timestamps != {ZIP_TIMESTAMP}:
            raise RuntimeError(
                f"Release archive has non-deterministic timestamps: {timestamps}"
            )
        archive.testzip()
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
