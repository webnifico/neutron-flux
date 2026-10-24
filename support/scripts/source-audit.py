#!/usr/bin/env python3
"""Dependency-free structural release checks for the Neutron Flux source tree."""

from __future__ import annotations

import ast
import pathlib
import re
import runpy
import sys

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 release gate
    import tomli as tomllib  # type: ignore[no-redef]

ROOT = pathlib.Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "neutron_flux"

MAX_PRODUCTION_FILE_LINES = 1_850
MAX_TEST_FILE_LINES = 1_050
MAX_FUNCTION_LINES = 550
MAX_ATTR_DEFINED_SUPPRESSIONS = 31
# Includes the re-raising handler that releases route-cache waiters on cancellation.
MAX_BROAD_EXCEPTION_HANDLERS = 24
# Canonical Ruff wrapping expands this legacy contract module beyond the global
# physical-line ceiling without adding statements. Keep a narrow cap here until
# its compatibility helpers are split into dedicated modules.
PRODUCTION_FILE_LINE_LIMITS = {
    "neutron_flux/result_contract.py": 2_000,
}


def fail(message: str) -> None:
    raise RuntimeError(message)


def module_name(path: pathlib.Path) -> str:
    relative = path.relative_to(ROOT).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def resolve_internal_import(
    current: str,
    path: pathlib.Path,
    node: ast.ImportFrom,
    modules: set[str],
) -> set[str]:
    if node.level:
        current_parts = current.split(".")
        base_parts = current_parts if path.name == "__init__.py" else current_parts[:-1]
        upward = node.level - 1
        base_parts = base_parts[: len(base_parts) - upward] if upward else base_parts
        target = ".".join(
            base_parts + ((node.module or "").split(".") if node.module else [])
        )
    else:
        target = node.module or ""
    if not target.startswith("neutron_flux"):
        return set()
    found: set[str] = set()
    if target in modules:
        found.add(target)
    for alias in node.names:
        candidate = f"{target}.{alias.name}" if target else alias.name
        if candidate in modules:
            found.add(candidate)
    return found


def _is_type_checking_guard(node: ast.expr) -> bool:
    return (isinstance(node, ast.Name) and node.id == "TYPE_CHECKING") or (
        isinstance(node, ast.Attribute)
        and node.attr == "TYPE_CHECKING"
        and isinstance(node.value, ast.Name)
        and node.value.id == "typing"
    )


def _runtime_imports(tree: ast.AST) -> list[ast.Import | ast.ImportFrom]:
    output: list[ast.Import | ast.ImportFrom] = []

    class Visitor(ast.NodeVisitor):
        def visit_If(self, node: ast.If) -> None:
            if _is_type_checking_guard(node.test):
                for child in node.orelse:
                    self.visit(child)
                return
            self.generic_visit(node)

        def visit_Import(self, node: ast.Import) -> None:
            output.append(node)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            output.append(node)

    Visitor().visit(tree)
    return output


def import_graph(paths: list[pathlib.Path]) -> dict[str, set[str]]:
    modules = {module_name(path) for path in paths}
    graph = {name: set() for name in modules}
    path_by_module = {module_name(path): path for path in paths}
    for current, path in path_by_module.items():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in _runtime_imports(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in modules:
                        graph[current].add(alias.name)
            else:
                graph[current].update(
                    resolve_internal_import(current, path, node, modules)
                )
        graph[current].discard(current)
    return graph


def find_cycles(graph: dict[str, set[str]]) -> list[list[str]]:
    index = 0
    indexes: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    active: set[str] = set()
    components: list[list[str]] = []

    def visit(node: str) -> None:
        nonlocal index
        indexes[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        active.add(node)
        for neighbour in graph[node]:
            if neighbour not in indexes:
                visit(neighbour)
                lowlinks[node] = min(lowlinks[node], lowlinks[neighbour])
            elif neighbour in active:
                lowlinks[node] = min(lowlinks[node], indexes[neighbour])
        if lowlinks[node] != indexes[node]:
            return
        component: list[str] = []
        while True:
            member = stack.pop()
            active.remove(member)
            component.append(member)
            if member == node:
                break
        components.append(component)

    for node in graph:
        if node not in indexes:
            visit(node)
    return [component for component in components if len(component) > 1]


def unreachable_modules(paths: list[pathlib.Path]) -> list[str]:
    """Every production module must be reachable from the installed entry point."""
    graph = import_graph(paths)
    pending = ["neutron_flux", "neutron_flux.__main__"]
    reached: set[str] = set()
    while pending:
        module = pending.pop()
        if module in reached:
            continue
        reached.add(module)
        pending.extend(graph.get(module, ()))
        # Python imports each package initializer on the way to a submodule.
        parts = module.split(".")
        pending.extend(".".join(parts[:index]) for index in range(1, len(parts)))
    return sorted(set(graph) - reached)


def check_versions() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject["project"]
    constants_tree = ast.parse((PACKAGE / "constants.py").read_text(encoding="utf-8"))
    constants: dict[str, str] = {}
    for node in constants_tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            constants[node.targets[0].id] = node.value.value
    package_version = constants.get("VERSION")
    if not package_version or not re.fullmatch(
        r"\d+\.\d+\.\d+(?:rc\d+)?", package_version
    ):
        fail(
            "constants.py VERSION must be a PEP 440 stable or RC version, "
            f"got {package_version!r}"
        )
    if "version" in project:
        fail("pyproject.toml must derive its version instead of duplicating VERSION")
    if "version" not in project.get("dynamic", []):
        fail("pyproject.toml must declare version as dynamic")
    dynamic_version = (
        pyproject.get("tool", {})
        .get("setuptools", {})
        .get("dynamic", {})
        .get("version", {})
    )
    if dynamic_version.get("attr") != "neutron_flux.constants.VERSION":
        fail("pyproject.toml must derive version from neutron_flux.constants.VERSION")

    runtime = runpy.run_path(str(PACKAGE / "constants.py"))
    match = re.fullmatch(
        r"(?P<base>\d+\.\d+\.\d+)(?P<revision>rc\d+)?", package_version
    )
    if match is None:  # Defensive; the version shape was checked above.
        fail(f"Unable to derive release identity from {package_version!r}")
    revision = match.group("revision") or ""
    expected_identifier = (
        f"{match.group('base')}-{revision}" if revision else match.group("base")
    )
    if runtime.get("RELEASE_IDENTIFIER") != expected_identifier:
        fail(
            "Human release identity mismatch: expected "
            f"{expected_identifier!r}, got {runtime.get('RELEASE_IDENTIFIER')!r}"
        )
    if runtime.get("RELEASE_REVISION") != revision:
        fail("Release revision is not derived from VERSION")
    expected_stage = "release candidate" if revision else "stable"
    if runtime.get("RELEASE_STAGE") != expected_stage:
        fail(f"Package stage must be {expected_stage!r}")
    expected_classifier = (
        "Development Status :: 4 - Beta"
        if revision
        else "Development Status :: 5 - Production/Stable"
    )
    if expected_classifier not in project.get("classifiers", []):
        fail(f"Package stage requires classifier {expected_classifier!r}")

    lock_path = ROOT / "uv.lock"
    if lock_path.is_file():
        lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
        locked = [
            item
            for item in lock.get("package", [])
            if item.get("name") == "neutron-flux"
            and item.get("source") == {"editable": "."}
        ]
        locked_version = locked[0].get("version") if len(locked) == 1 else None
        if len(locked) != 1 or locked_version not in {None, package_version}:
            fail(
                f"uv.lock project version does not match constants.py VERSION: {locked}"
            )


def check_source() -> None:
    production = sorted(PACKAGE.rglob("*.py"))
    tests = sorted((ROOT / "support" / "tests").glob("test_*.py"))
    errors: list[str] = []
    attr_suppressions = 0
    broad_exceptions = 0

    for path in [*production, *tests]:
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT)
        lines = text.splitlines()
        limit = (
            MAX_TEST_FILE_LINES
            if path in tests
            else PRODUCTION_FILE_LINE_LIMITS.get(
                relative.as_posix(), MAX_PRODUCTION_FILE_LINES
            )
        )
        if len(lines) > limit:
            errors.append(f"{relative}: {len(lines)} lines exceeds {limit}")
        if re.search(r"\b(?:TODO|FIXME|XXX|HACK)\b", text):
            errors.append(f"{relative}: contains an unresolved maintenance marker")
        if "shell=True" in text or "shell = True" in text or "os.system(" in text:
            errors.append(f"{relative}: uses a prohibited shell execution primitive")
        attr_suppressions += text.count('mypy: disable-error-code="attr-defined"')
        tree = ast.parse(text, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                length = (node.end_lineno or node.lineno) - node.lineno + 1
                if length > MAX_FUNCTION_LINES:
                    errors.append(
                        f"{relative}:{node.lineno} {node.name} is {length} lines; "
                        f"maximum is {MAX_FUNCTION_LINES}"
                    )
            if isinstance(node, ast.ExceptHandler):
                exception = node.type
                if isinstance(exception, ast.Name) and exception.id in {
                    "Exception",
                    "BaseException",
                }:
                    broad_exceptions += 1

    if attr_suppressions > MAX_ATTR_DEFINED_SUPPRESSIONS:
        errors.append(
            f"attr-defined suppression count increased to {attr_suppressions}; "
            f"maximum is {MAX_ATTR_DEFINED_SUPPRESSIONS}"
        )
    if broad_exceptions > MAX_BROAD_EXCEPTION_HANDLERS:
        errors.append(
            f"broad exception handler count increased to {broad_exceptions}; "
            f"maximum is {MAX_BROAD_EXCEPTION_HANDLERS}"
        )

    cycles = find_cycles(import_graph(production))
    if cycles:
        errors.append(f"internal import cycles detected: {cycles}")
    disconnected = unreachable_modules(production)
    if disconnected:
        errors.append(f"production modules unreachable from the CLI: {disconnected}")
    if errors:
        fail("Source audit failed:\n- " + "\n- ".join(errors))

    print(
        "Source audit passed: "
        f"{len(production)} modules, no import cycles, "
        f"{attr_suppressions} attr-defined suppressions, "
        f"{broad_exceptions} broad exception handlers"
    )


def main() -> int:
    builder = runpy.run_path(str(ROOT / "support/scripts/build-release.py"))
    builder["validate_source_layout"]()
    check_versions()
    check_source()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        raise SystemExit(1) from exc
