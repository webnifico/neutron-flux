from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence


class OpenStackCloudOperationCommand:
    COMMAND_PHRASES: dict[tuple[str, ...], str] = {
        ("security", "group", "rule", "create"): "security-group-rule",
        ("security", "group", "rule", "delete"): "security-group-rule",
        ("security", "group", "create"): "security-group",
        ("security", "group", "delete"): "security-group",
        ("security", "group", "set"): "security-group",
        ("floating", "ip", "create"): "floating-ip",
        ("floating", "ip", "delete"): "floating-ip",
        ("floating", "ip", "set"): "floating-ip",
        ("floating", "ip", "unset"): "floating-ip",
        ("router", "add", "subnet"): "router-interface",
        ("router", "remove", "subnet"): "router-interface",
        ("router", "add", "port"): "router-interface",
        ("router", "remove", "port"): "router-interface",
        ("router", "add", "route"): "router-cloud-operation",
        ("router", "remove", "route"): "router-cloud-operation",
        ("router", "set"): "router-gateway",
        ("router", "unset"): "router-gateway",
        ("server", "create"): "server-create",
        ("server", "delete"): "server-delete",
        ("server", "group", "create"): "server-group",
        ("server", "group", "delete"): "server-group",
        ("server", "stop"): "server-lifecycle",
        ("server", "start"): "server-lifecycle",
        ("server", "reboot"): "server-lifecycle",
        ("server", "suspend"): "server-lifecycle",
        ("server", "resume"): "server-lifecycle",
        ("server", "shelve"): "server-lifecycle",
        ("server", "unshelve"): "server-lifecycle",
        ("server", "migration", "confirm"): "migration",
        ("server", "migration", "revert"): "migration",
        ("server", "migration", "abort"): "migration",
        ("server", "migration", "force", "complete"): "migration",
        ("server", "migrate", "confirm"): "migration",
        ("server", "migrate", "revert"): "migration",
        ("server", "migrate"): "migration",
        ("server", "resize"): "migration",
        ("port", "create"): "port-create",
        ("port", "delete"): "port-delete",
        ("port", "set"): "port-create",
        ("port", "unset"): "port-delete",
        ("network", "create"): "network-topology",
        ("network", "delete"): "network-topology",
        ("network", "set"): "network-topology",
        ("subnet", "create"): "network-topology",
        ("subnet", "delete"): "network-topology",
        ("subnet", "set"): "network-topology",
        ("router", "create"): "network-topology",
        ("router", "delete"): "network-topology",
        ("volume", "create"): "volume",
        ("volume", "delete"): "volume",
        ("volume", "set"): "volume",
        ("keypair", "create"): "keypair",
        ("keypair", "delete"): "keypair",
    }
    _BOOLEAN_OPTIONS = frozenset(
        {
            "--debug",
            "--insecure",
            "--fit-width",
            "--timing",
            "--verbose",
            "--wait",
            "--force",
            "--enable",
            "--disable",
            "--share",
            "--no-share",
            "--public",
            "--private",
            "--live-migration",
            "--block-migration",
            "--shared-migration",
            "--disk-overcommit",
            "--no-disk-overcommit",
            "--hard",
            "--soft",
            "--bootable",
            "--non-bootable",
            "--read-only",
            "--read-write",
            "--increment",
            "--decrement",
            "--enable-port-security",
            "--disable-port-security",
            "--no-port-security",
            "--enable-dhcp",
            "--disable-dhcp",
            "--dhcp",
            "--no-dhcp",
            "--no-security-group",
            "--enable-snat",
            "--disable-snat",
            "--external",
            "--internal",
            "--ingress",
            "--egress",
            "--default",
            "--no-default",
            "--tagged",
            "--untagged",
        }
    )

    @classmethod
    def _command_tokens(cls, args: Sequence[str]) -> list[str]:
        tokens = [str(item) for item in args]
        index = 0
        while index < len(tokens) and tokens[index].startswith("-"):
            option = tokens[index].split("=", 1)[0].lower()
            if "=" in tokens[index] or option in cls._BOOLEAN_OPTIONS:
                index += 1
            else:
                index += 2
        return tokens[index:]

    @classmethod
    def _matched_command(
        cls, args: Sequence[str]
    ) -> tuple[tuple[str, ...], str, list[str]] | None:
        tokens = cls._command_tokens(args)
        lowered = [item.lower() for item in tokens]
        for phrase in sorted(cls.COMMAND_PHRASES, key=len, reverse=True):
            if tuple(lowered[: len(phrase)]) == phrase:
                return phrase, cls.COMMAND_PHRASES[phrase], tokens[len(phrase) :]
        return None

    @classmethod
    def classify_openstack_command(cls, args: tuple[str, ...]) -> str | None:
        # argparse exits before submission for help/version, anywhere before --.
        options = args[: args.index("--")] if "--" in args else args
        if any(value in {"--help", "-h", "--version"} for value in options):
            return None
        matched = cls._matched_command(args)
        return matched[1] if matched is not None else None

    @staticmethod
    def command_fingerprint(command: Sequence[str]) -> str:
        encoded = json.dumps(list(command), separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    @classmethod
    def _parsed_arguments(
        cls, tokens: Sequence[str]
    ) -> tuple[list[str], dict[str, list[str]]]:
        positionals: list[str] = []
        options: dict[str, list[str]] = {}
        index = 0
        while index < len(tokens):
            token = str(tokens[index])
            if token == "--":
                positionals.extend(str(item) for item in tokens[index + 1 :])
                break
            if not token.startswith("-"):
                positionals.append(token)
                index += 1
                continue
            name, separator, inline = token.partition("=")
            lowered = name.lower()
            if separator:
                options.setdefault(lowered, []).append(inline)
                index += 1
                continue
            if lowered in cls._BOOLEAN_OPTIONS:
                options.setdefault(lowered, [])
                index += 1
                continue
            if index + 1 < len(tokens) and not str(tokens[index + 1]).startswith("-"):
                options.setdefault(lowered, []).append(str(tokens[index + 1]))
                index += 2
                continue
            options.setdefault(lowered, [])
            index += 1
        return positionals, options

    @staticmethod
    def _unique_resources(values: Sequence[str]) -> tuple[str, ...]:
        output: list[str] = []
        for raw in values:
            value = str(raw).strip()
            if value and value not in output:
                output.append(value)
        return tuple(output)

    @classmethod
    def _resource_ids_from_command(cls, command: Sequence[str]) -> tuple[str, ...]:
        matched = cls._matched_command(command)
        if matched is None:
            return ()
        phrase, _kind, tail = matched
        positionals, options = cls._parsed_arguments(tail)
        resources: list[str] = []

        if phrase[:3] in {
            ("router", "add", "subnet"),
            ("router", "remove", "subnet"),
            ("router", "add", "port"),
            ("router", "remove", "port"),
        }:
            resources.extend(positionals[:2])
        elif phrase[:3] in {
            ("router", "add", "route"),
            ("router", "remove", "route"),
        }:
            resources.extend(positionals[-1:])
        elif phrase[:2] in {("router", "set"), ("router", "unset")}:
            resources.extend(positionals[-1:])
            resources.extend(options.get("--external-gateway", ()))
        elif phrase[:3] == ("floating", "ip", "create"):
            resources.extend(positionals[:1])
            resources.extend(options.get("--port", ()))
        elif phrase[:3] in {
            ("floating", "ip", "set"),
            ("floating", "ip", "unset"),
        }:
            resources.extend(positionals[-1:])
            resources.extend(options.get("--port", ()))
        elif phrase[:3] == ("security", "group", "rule"):
            resources.extend(positionals[-1:])
        elif phrase[:2] == ("server", "create"):
            resources.extend(positionals[-1:])
            for option in ("--network", "--port", "--volume"):
                resources.extend(options.get(option, ()))
        elif phrase[:2] == ("port", "create"):
            resources.extend(positionals[-1:])
            resources.extend(options.get("--network", ()))
        elif phrase[:2] in {("port", "set"), ("port", "unset")}:
            resources.extend(positionals[-1:])
            for option in ("--network", "--security-group"):
                resources.extend(options.get(option, ()))
        else:
            resources.extend(positionals)
        return cls._unique_resources(resources)

    @classmethod
    def classify(cls, args: Sequence[str]) -> str | None:
        return cls.classify_openstack_command(tuple(args))

    @classmethod
    def fingerprint(cls, command: Sequence[str]) -> str:
        return cls.command_fingerprint(command)

    @classmethod
    def resource_ids(cls, command: Sequence[str]) -> tuple[str, ...]:
        return cls._resource_ids_from_command(command)


__all__ = ["OpenStackCloudOperationCommand"]
