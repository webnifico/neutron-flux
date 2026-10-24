#!/usr/bin/env python3
"""Static safety audit for every OpenStackClient command construction site.

This is intentionally independent of a live cloud. It verifies command object
spelling, global-option placement, output-formatter ownership, migration
microversion handling, and operator recovery commands. Runtime unit tests cover
the dynamic argument builders that cannot be fully resolved from the AST.
"""

from __future__ import annotations

import ast
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "neutron_flux"
CALL_METHODS = {
    "run",
    "json",
    "optional_json",
    "value",
    "value_result",
}
JSON_METHODS = {"json", "optional_json"}
GLOBAL_VALUE_OPTIONS = {
    "--os-compute-api-version",
    "--os-volume-api-version",
    "--os-network-api-version",
    "--os-placement-api-version",
    "--os-interface",
    "--os-region-name",
    "--os-cloud",
}
FORMAT_OPTIONS = {"-f", "--format", "-c", "--column", "--sort-column"}

# Documented OSC command objects/actions used by Flux. Longer tuples are checked
# before shorter ones so multi-word objects cannot be mistaken for a prefix.
VALID_PREFIXES = sorted(
    {
        ("token", "issue"),
        ("configuration", "show"),
        ("availability", "zone", "list"),
        ("compute", "service", "list"),
        ("console", "log", "show"),
        ("aggregate", "list"),
        ("aggregate", "show"),
        ("image", "show"),
        ("flavor", "show"),
        ("keypair", "create"),
        ("keypair", "list"),
        ("keypair", "show"),
        ("keypair", "delete"),
        ("server", "create"),
        ("server", "list"),
        ("server", "show"),
        ("server", "set"),
        ("server", "start"),
        ("server", "stop"),
        ("server", "delete"),
        ("server", "migrate"),
        ("server", "migration", "list"),
        ("server", "migration", "show"),
        ("server", "migration", "confirm"),
        ("server", "migration", "revert"),
        ("server", "migrate", "confirm"),
        ("server", "migrate", "revert"),
        ("server", "volume", "list"),
        ("server", "group", "list"),
        ("server", "group", "create"),
        ("server", "group", "show"),
        ("server", "group", "delete"),
        ("volume", "create"),
        ("volume", "list"),
        ("volume", "show"),
        ("volume", "delete"),
        ("volume", "service", "list"),
        ("volume", "type", "show"),
        ("network", "create"),
        ("network", "list"),
        ("network", "show"),
        ("network", "delete"),
        ("network", "segment", "list"),
        ("network", "segment", "show"),
        ("subnet", "create"),
        ("subnet", "list"),
        ("subnet", "show"),
        ("subnet", "delete"),
        ("subnet", "pool", "list"),
        ("subnet", "pool", "show"),
        ("port", "create"),
        ("port", "list"),
        ("port", "show"),
        ("port", "delete"),
        ("router", "create"),
        ("router", "list"),
        ("router", "show"),
        ("router", "set"),
        ("router", "unset"),
        ("router", "delete"),
        ("router", "add", "port"),
        ("router", "add", "subnet"),
        ("router", "add", "route"),
        ("router", "remove", "port"),
        ("router", "remove", "subnet"),
        ("router", "remove", "route"),
        ("floating", "ip", "create"),
        ("floating", "ip", "list"),
        ("floating", "ip", "show"),
        ("floating", "ip", "set"),
        ("floating", "ip", "unset"),
        ("floating", "ip", "delete"),
        ("security", "group", "create"),
        ("security", "group", "list"),
        ("security", "group", "show"),
        ("security", "group", "delete"),
        ("security", "group", "rule", "create"),
        ("security", "group", "rule", "list"),
        ("security", "group", "rule", "show"),
        ("security", "group", "rule", "delete"),
        ("address", "scope", "list"),
        ("address", "group", "show"),
        ("extension", "list"),
        ("quota", "show"),
        ("resource", "provider", "allocation", "show"),
    },
    key=len,
    reverse=True,
)


def literal_args(node: ast.Call) -> list[str | None]:
    values: list[str | None] = []
    for arg in node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            values.append(arg.value)
        else:
            values.append(None)
    return values


def strip_global_prefix(values: list[str | None]) -> tuple[list[str | None], list[str]]:
    index = 0
    errors: list[str] = []
    while index < len(values):
        value = values[index]
        if value not in GLOBAL_VALUE_OPTIONS:
            break
        if index + 1 >= len(values) or values[index + 1] is None:
            errors.append(f"global option {value} has no statically visible value")
            break
        index += 2
    for value in values[index:]:
        if value in GLOBAL_VALUE_OPTIONS:
            errors.append(f"global option {value} appears after the command object")
    return values[index:], errors


def matches_known_prefix(command: list[str | None]) -> bool:
    # Router route helpers select only the documented add/remove verb at runtime.
    if len(command) >= 3 and command[:3] == ["router", None, "route"]:
        return True
    for prefix in VALID_PREFIXES:
        if len(command) >= len(prefix) and tuple(command[: len(prefix)]) == prefix:
            return True
    return False


def audit() -> tuple[list[str], int, int]:
    errors: list[str] = []
    call_count = 0
    literal_count = 0
    for path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(
                node.func, ast.Attribute
            ):
                continue
            method = node.func.attr
            if method not in CALL_METHODS:
                continue
            # Restrict this audit to OSC wrapper calls, not unrelated .run/.json methods.
            rendered = ast.unparse(node.func.value)
            if not (
                rendered.endswith("osc") or ".osc" in rendered or rendered == "self"
            ):
                continue
            call_count += 1
            values = literal_args(node)
            command, placement_errors = strip_global_prefix(values)
            location = f"{path.relative_to(ROOT)}:{node.lineno}"
            errors.extend(f"{location}: {item}" for item in placement_errors)
            if method in JSON_METHODS and any(
                value in FORMAT_OPTIONS for value in values if value
            ):
                errors.append(
                    f"{location}: JSON wrapper call supplies its own formatter option"
                )
            if command and command[0] is not None:
                literal_count += 1
                if not matches_known_prefix(command):
                    visible = " ".join(value or "<dynamic>" for value in command[:5])
                    errors.append(
                        f"{location}: unknown OpenStack command prefix: {visible}"
                    )

            # Known high-risk argument shapes.
            concrete = [value for value in command if value is not None]
            if concrete[:3] == ["server", "migration", "list"]:
                if "--server" not in concrete:
                    errors.append(
                        f"{location}: server migration list must filter with --server"
                    )
            if concrete[:2] == ["server", "migrate"]:
                # All migration cloud operations must flow through the negotiated helper.
                source = (
                    ast.get_source_segment(path.read_text(encoding="utf-8"), node) or ""
                )
                if "_migration_command_args" not in source and path.name not in {
                    "live_migration.py",
                    "migration_execution.py",
                }:
                    errors.append(
                        f"{location}: server migrate bypasses microversion negotiation"
                    )

    migration_source = (PACKAGE / "runtime" / "migration_validation.py").read_text(
        encoding="utf-8"
    )
    required_fragments = (
        '"server",\n                    "migration",\n                    "list",\n                    "--server"',
        '("--os-compute-api-version", "2.56")',
        '("--os-compute-api-version", "2.latest")',
        "no migration command was submitted",
    )
    for fragment in required_fragments:
        if fragment not in migration_source:
            errors.append(
                f"migration validation is missing required safety fragment: {fragment!r}"
            )

    deletion_source = (PACKAGE / "cleanup_components" / "deletion.py").read_text(
        encoding="utf-8"
    )
    force_pattern = re.compile(
        r'"--os-compute-api-version",\s*"2\.latest",\s*"server",\s*"delete",\s*"--force"',
        re.S,
    )
    if not force_pattern.search(deletion_source):
        errors.append(
            "forced server deletion is not protected by compute microversion 2.latest"
        )

    recovery_source = (PACKAGE / "cleanup_components" / "recovery.py").read_text(
        encoding="utf-8"
    )
    for expected in (
        "openstack floating ip delete",
        "openstack server delete",
        "openstack router delete",
        "openstack port delete",
        "openstack subnet delete",
        "openstack network delete",
        "openstack volume delete --force",
        "openstack security group delete",
        "openstack server group delete",
        "openstack keypair delete",
    ):
        if expected not in recovery_source:
            errors.append(f"recovery command missing or misspelled: {expected}")

    return errors, call_count, literal_count


def main() -> int:
    errors, call_count, literal_count = audit()
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(
        f"OpenStack command audit passed: {call_count} wrapper call sites, "
        f"{literal_count} statically resolved command families, migration and "
        "recovery safety checks passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
