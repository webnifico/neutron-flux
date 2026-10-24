from __future__ import annotations

import dataclasses
import json
import os
import re
import shlex
import subprocess
from contextlib import nullcontext
from typing import Any, Literal

from .cancellation import run_cancellable
from .cloud_operation import CloudOperationCoordinator
from .errors import CommandError, CommandTimeoutError, RunCancelledError, SuiteError
from .gateway_policy import assert_router_gateway_defaults
from .log import Logger
from .scheduling import admission, timed

PresenceState = Literal["present", "absent", "unknown"]


@dataclasses.dataclass(frozen=True)
class PresenceResult:
    state: PresenceState
    detail: str = ""
    returncode: int = 0
    data: dict[str, Any] | None = None

    @property
    def present(self) -> bool:
        return self.state == "present"

    @property
    def absent(self) -> bool:
        return self.state == "absent"

    @property
    def unknown(self) -> bool:
        return self.state == "unknown"


class OpenStack:
    """Bounded structured wrapper around the OpenStack command-line client.

    Every command requests machine-readable output where possible, enforces a
    timeout, and converts failures into typed suite errors. Rendered OpenStack
    commands remain available in reports and recovery artifacts.
    """

    DEFAULT_TIMEOUT_SECONDS = 120

    _RESOURCE_NAMES = (
        "server",
        "network",
        "subnet",
        "router",
        "port",
        "volume",
        "security group",
        "server group",
        "floating ip",
        "keypair",
        "image",
        "flavor",
        "subnet pool",
        "address scope",
        "network segment",
    )
    _NOT_FOUND_INFRASTRUCTURE_MARKERS = (
        "service endpoint",
        "endpoint does not exist",
        "service catalog",
        "catalog entry",
        "plugin could not be found",
        "command could not be found",
        "api endpoint",
        "endpoint for service",
        "no service with a name or id",
        "no endpoint with a name or id",
        "no volume type with a name or id",
        "volume type could not be found",
        "authentication required",
        "unauthorized",
        "forbidden",
    )
    _UNSUPPORTED_PATTERNS = (
        "not supported",
        "unsupported",
        "unrecognized arguments",
        "invalid choice",
        "is not an openstack command",
        "requires microversion",
        "microversion is not supported",
        "requested microversion",
        "unknown command",
    )

    def __init__(
        self,
        logger: Logger,
        cloud_operation_coordinator: CloudOperationCoordinator | None = None,
    ):
        self.logger = logger
        self.backend_name = "openstack-cli"
        self.cloud_operation_coordinator = cloud_operation_coordinator
        self._floating_ip_formatter_warning = False
        # Cache a client capability failure, never a resource observation.
        self._floating_ip_show_formatter_broken = False

    def run(
        self,
        *args: str,
        check: bool = True,
        timeout: int | None = None,
        input_text: str | None = None,
        quiet: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        assert_router_gateway_defaults(args)
        command = ["openstack", *map(str, args)]
        command_timeout = (
            timeout if timeout is not None else self.DEFAULT_TIMEOUT_SECONDS
        )

        def invoke() -> subprocess.CompletedProcess[str]:
            try:
                environment = os.environ.copy()
                # OS_COMPUTE_API_VERSION is a global python-openstackclient
                # environment variable. Some client/plugin combinations inspect it
                # even when an explicit command-line selector is present, which can
                # leak a rejected ambient version into otherwise valid migration
                # evidence. Compute microversions required by this suite are always
                # passed explicitly on the command line, so the ambient value must
                # never participate in a Flux command.
                environment.pop("OS_COMPUTE_API_VERSION", None)
                return run_cancellable(
                    command,
                    input_text=input_text,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=command_timeout,
                    check=False,
                    env=environment,
                )
            except FileNotFoundError as exc:
                raise SuiteError("Required command not found: openstack") from exc
            except subprocess.TimeoutExpired as exc:
                raise CommandTimeoutError(command, command_timeout) from exc

        coordinator = self.cloud_operation_coordinator
        cloud_operation_kind = (
            coordinator.classify_openstack_command(tuple(map(str, args)))
            if coordinator is not None
            else None
        )
        reporter = getattr(coordinator, "reporter", None)

        def measured_invoke() -> subprocess.CompletedProcess[str]:
            # Writes are paced by the cloud operation coordinator. Reads have a separate
            # process-wide budget, including reads made outside worker pools.
            with (
                admission("api-read", reporter)
                if cloud_operation_kind is None
                else nullcontext()
            ):
                with timed(
                    reporter,
                    "api-write"
                    if cloud_operation_kind
                    or tuple(map(str, args[:2]))
                    in {("server", "set"), ("server", "unset")}
                    else "api-read",
                    self._timing_label(tuple(map(str, args))),
                ):
                    return invoke()

        result = (
            coordinator.execute(
                cloud_operation_kind, tuple(map(str, args)), measured_invoke
            )
            if coordinator is not None and cloud_operation_kind is not None
            else measured_invoke()
        )
        if result.returncode in {130, 143, -2, -15}:
            raise RunCancelledError(
                f"Operator cancelled command: {shlex.join(command)}"
            )
        if check and result.returncode != 0:
            raise CommandError(command, result.returncode, result.stdout, result.stderr)
        if not quiet and result.stdout.strip():
            self.logger.log(result.stdout.rstrip())
        return result

    @classmethod
    def _timing_label(cls, args: tuple[str, ...]) -> str:
        """Expose command families in timing, without resource IDs or secrets."""
        tokens = list(args)
        while len(tokens) >= 2 and tokens[0].startswith("--os-"):
            tokens = tokens[2:]
        resource = cls._expected_resource_from_args(tuple(tokens))
        if not resource:
            return "OpenStack CLI"
        index = len(resource.split())
        verb = tokens[index] if len(tokens) > index else ""
        if verb not in {
            "list",
            "show",
            "create",
            "delete",
            "set",
            "unset",
            "add",
            "remove",
            "start",
            "stop",
            "migrate",
            "resize",
            "reboot",
            "confirm",
        }:
            return "openstack " + resource
        return "openstack " + resource + " " + verb

    @classmethod
    def _combined_output(cls, result: subprocess.CompletedProcess[str]) -> str:
        return "\n".join(
            item.strip() for item in (result.stderr, result.stdout) if item.strip()
        )

    @classmethod
    def _expected_resource_from_args(cls, args: tuple[str, ...]) -> str | None:
        tokens = [str(item).strip().lower() for item in args]
        # Drop global option/value pairs before examining the command object.
        index = 0
        while index < len(tokens) and tokens[index].startswith("--os-"):
            index += 2
        command = tokens[index:]
        phrases = (
            ("security", "group"),
            ("server", "group"),
            ("floating", "ip"),
            ("subnet", "pool"),
            ("address", "scope"),
            ("network", "segment"),
        )
        for phrase in phrases:
            if tuple(command[: len(phrase)]) == phrase:
                return " ".join(phrase)
        if command and command[0] in cls._RESOURCE_NAMES:
            return command[0]
        return None

    @staticmethod
    def _resource_name_pattern(resource: str) -> str:
        """Return a regex accepting OSC resource-name spelling variants.

        Different python-openstackclient plugins render multi-word resource
        names inconsistently in not-found messages.  For example, Neutron may
        emit any of ``Security Group``, ``security_group`` or
        ``SecurityGroup``.  Treat spaces, underscores, hyphens, and no
        separator as equivalent while retaining exact word order.
        """
        words = re.findall(r"[a-z0-9]+", resource.lower())
        if not words:
            return re.escape(resource.lower())
        return r"[\s_-]*".join(re.escape(word) for word in words)

    @classmethod
    def is_not_found_result(
        cls,
        result: subprocess.CompletedProcess[str],
        *,
        expected_resource: str | None = None,
    ) -> bool:
        if result.returncode == 0:
            return False
        text = cls._combined_output(result)
        lowered = text.lower()
        if any(marker in lowered for marker in cls._NOT_FOUND_INFRASTRUCTURE_MARKERS):
            return False
        expected = (expected_resource or "").strip().lower().replace("_", " ")
        if expected:
            escaped = cls._resource_name_pattern(expected)
            # A missing Server Group/Network Segment is not evidence that the
            # requested Server/Network disappeared. Match the object type as a
            # whole, including multi-word resource names and plugin spelling.
            suffixes = {
                resource[len(expected) + 1 :].split()[0]
                for resource in (*cls._RESOURCE_NAMES, "volume type")
                if resource.startswith(expected + " ")
            }
            if suffixes:
                escaped += r"(?![\s_-]*(?:" + "|".join(sorted(suffixes)) + r")\b)"
            patterns = (
                # python-openstackclient commonly renders an already-absent
                # object as ``No Server found for <id>`` (and equivalent
                # wording for Neutron/Cinder resources).  This is a positive
                # absence result, not an API uncertainty.
                rf"\bno\s+{escaped}\s+(?:was\s+)?found(?:\s+for\b|\b)",
                rf"\bno\s+{escaped}\b.*\b(?:name|id|name or id)\b",
                rf"\b{escaped}\b.*\b(?:not found|could not be found|does not exist)\b",
                rf"\bnotfound(?:exception)?\b.*\b{escaped}\b",
            )
            if any(re.search(pattern, lowered, re.IGNORECASE) for pattern in patterns):
                return True
            # Many OpenStack services return only a generic 404 body for a
            # resource-specific SHOW request.  The caller supplies the expected
            # resource type, so this is safe after infrastructure errors were
            # excluded above.
            if "404" in lowered and any(
                marker in lowered
                for marker in (
                    "the resource could not be found",
                    "resource not found",
                    "notfoundexception",
                )
            ):
                return True
            return False
        # Without an expected resource, accept only explicit managed-resource
        # wording.  Ambiguous service/catalog messages remain UNKNOWN.
        for resource in cls._RESOURCE_NAMES:
            escaped = cls._resource_name_pattern(resource)
            fallback_patterns = (
                rf"\bno\s+{escaped}\s+(?:was\s+)?found(?:\s+for\b|\b)",
                rf"\b{escaped}\b.*\b(?:not found|could not be found|does not exist)\b",
            )
            if any(
                re.search(pattern, lowered, re.IGNORECASE)
                for pattern in fallback_patterns
            ):
                return True
        return False

    @classmethod
    def is_unsupported_result(cls, result: subprocess.CompletedProcess[str]) -> bool:
        if result.returncode == 0:
            return False
        lowered = cls._combined_output(result).lower()
        return any(marker in lowered for marker in cls._UNSUPPORTED_PATTERNS)

    @classmethod
    def is_transient_result(cls, result: subprocess.CompletedProcess[str]) -> bool:
        if result.returncode == 0:
            return False
        lowered = cls._combined_output(result).lower()
        markers = (
            "http 429",
            "http 500",
            "http 502",
            "http 503",
            "http 504",
            "service unavailable",
            "gateway timeout",
            "bad gateway",
            "temporarily unavailable",
            "connection reset",
            "connection timed out",
            "read timed out",
            "connect timeout",
            "connection refused",
            "temporary failure in name resolution",
            "name or service not known",
            "nodename nor servname provided",
            "remote end closed connection",
            "remote disconnected",
            "unexpected eof",
            "eof occurred",
            "broken pipe",
            "network is unreachable",
            "no route to host",
        )
        return any(marker in lowered for marker in markers)

    @classmethod
    def is_transient_exception(cls, exc: BaseException) -> bool:
        if isinstance(exc, CommandTimeoutError):
            return True
        if isinstance(exc, CommandError):
            result = subprocess.CompletedProcess(
                exc.command, exc.returncode, exc.stdout, exc.stderr
            )
            return cls.is_transient_result(result)
        return False

    def _decode_json(self, args: tuple[str, ...], text: str) -> Any:
        stripped = text.strip()
        if not stripped:
            return None
        try:
            return json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise SuiteError(
                "OpenStack command returned invalid JSON: "
                f"openstack {shlex.join(args)}\n{stripped[:500]}"
            ) from exc

    def json(self, *args: str, check: bool = True, timeout: int | None = None) -> Any:
        """Return JSON while preserving failures that are not genuine absence.

        ``check=False`` remains useful for show/capability probes, but no longer
        turns authentication, authorization, endpoint, or HTTP 5xx failures into
        empty data. Only a recognized resource-not-found or unsupported-command
        response returns ``None``.
        """
        if (
            len(args) == 4
            and args[:3] == ("floating", "ip", "show")
            and self._floating_ip_show_formatter_broken
        ):
            detail = self._floating_ip_list_detail(
                args[3], timeout=timeout, allow_missing=True
            )
            if detail is not None:
                return detail
            # A missing LIST row cannot establish absence. SHOW must still
            # supply authoritative not-found evidence.
        result = self.run(*args, "-f", "json", check=False, timeout=timeout)
        if result.returncode != 0:
            if (
                len(args) == 4
                and args[:3] == ("floating", "ip", "show")
                and self._is_floating_ip_formatter_error(result)
            ):
                self._floating_ip_show_formatter_broken = True
                return self._floating_ip_list_detail(args[3], timeout=timeout)
            expected = self._expected_resource_from_args(tuple(map(str, args)))
            if not check and (
                self.is_not_found_result(result, expected_resource=expected)
                or self.is_unsupported_result(result)
            ):
                return None
            raise CommandError(
                ["openstack", *map(str, args), "-f", "json"],
                result.returncode,
                result.stdout,
                result.stderr,
            )
        return self._decode_json(tuple(map(str, args)), result.stdout)

    @classmethod
    def _is_floating_ip_formatter_error(
        cls, result: subprocess.CompletedProcess[str]
    ) -> bool:
        return (
            result.returncode != 0
            and cls._combined_output(result) == "Invalid formatter provided."
        )

    def _floating_ip_list_detail(
        self,
        resource_id: str,
        *,
        timeout: int | None = None,
        allow_missing: bool = False,
    ) -> dict[str, Any] | None:
        """Recover identity/association fields after OSC's SHOW formatter fails.

        LIST uses a different set of field formatters. Only an exact, unique ID
        with explicit association fields is usable. Missing list rows never
        establish absence: filtering, visibility or pagination could hide them.
        This is a read-only fallback, not a retry of a failed cloud operation, and does
        not reconstruct SHOW-only fields such as port_details.
        """
        rows = self.json("floating", "ip", "list", timeout=timeout)
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise SuiteError(
                "Floating-IP formatter fallback returned malformed inventory"
            )
        matches = []
        for row in rows:
            detail = {
                str(key).lower().replace(" ", "_"): value for key, value in row.items()
            }
            if detail.get("id") == resource_id:
                matches.append(detail)
        if not matches and allow_missing:
            return None
        if len(matches) != 1:
            raise SuiteError(
                f"Floating-IP formatter fallback could not uniquely identify {resource_id}; "
                "presence and association remain unknown"
            )
        detail = matches[0]
        if "port_id" not in detail and "port" in detail:
            detail["port_id"] = detail.pop("port")
        if (
            not isinstance(detail.get("floating_ip_address"), str)
            or not detail["floating_ip_address"].strip()
            or any(
                key not in detail
                or (detail[key] is not None and not isinstance(detail[key], str))
                for key in ("port_id", "fixed_ip_address")
            )
        ):
            raise SuiteError(
                f"Floating-IP formatter fallback lacks valid association fields for {resource_id}"
            )
        detail["_read_evidence"] = (
            "floating ip list: exact unique ID after show formatter error"
        )
        if not self._floating_ip_formatter_warning:
            self.logger.log(
                "OpenStack floating ip show failed with 'Invalid formatter provided.'. "
                "Using exact-ID floating ip list evidence for identity and association; "
                "check python-openstackclient/osc-lib package compatibility.",
                "WARNING",
            )
            self._floating_ip_formatter_warning = True
        return detail

    def optional_json(self, *args: str, timeout: int | None = None) -> Any:
        """Return ``None`` only when the client/API capability is unsupported."""
        result = self.run(*args, "-f", "json", check=False, timeout=timeout)
        if result.returncode == 0:
            return self._decode_json(tuple(map(str, args)), result.stdout)
        if self.is_unsupported_result(result):
            return None
        raise CommandError(
            ["openstack", *map(str, args), "-f", "json"],
            result.returncode,
            result.stdout,
            result.stderr,
        )

    def value_result(
        self,
        *args: str,
        column: str,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return self.run(
            *args,
            "-f",
            "value",
            "-c",
            column,
            check=False,
            timeout=timeout,
        )

    def value(
        self,
        *args: str,
        column: str,
        check: bool = True,
        timeout: int | None = None,
    ) -> str:
        result = self.value_result(*args, column=column, timeout=timeout)
        if check and result.returncode != 0:
            raise CommandError(
                ["openstack", *map(str, args), "-f", "value", "-c", column],
                result.returncode,
                result.stdout,
                result.stderr,
            )
        return result.stdout.strip()

    def presence(
        self, resource_type: str, resource_id: str, *, include_data: bool = False
    ) -> PresenceResult:
        words = {
            "security_group": ["security", "group"],
            "server_group": ["server", "group"],
            "floating_ip": ["floating", "ip"],
            "keypair": ["keypair"],
        }.get(resource_type, [resource_type.replace("_", " ")])
        flattened: list[str] = []
        for word in words:
            flattened.extend(word.split())
        args = (*flattened, "show", resource_id)
        if resource_type == "floating_ip" and self._floating_ip_show_formatter_broken:
            try:
                evidence = self._floating_ip_list_detail(
                    resource_id, timeout=60, allow_missing=True
                )
            except RunCancelledError:
                raise
            except SuiteError as exc:
                return PresenceResult("unknown", detail=str(exc))
            if evidence is not None:
                return PresenceResult(
                    "present",
                    detail=evidence["_read_evidence"],
                    data=evidence if include_data else None,
                )
            # A fresh SHOW is still required to confirm a missing object's absence.
        formatting = ("-f", "json") if include_data else ()
        result = self.run(*args, *formatting, check=False, timeout=60)
        if result.returncode == 0:
            data = None
            if include_data:
                try:
                    data = self._decode_json(args, result.stdout)
                except SuiteError as exc:
                    return PresenceResult("unknown", detail=str(exc))
                if not isinstance(data, dict):
                    return PresenceResult(
                        "unknown",
                        detail="Resource observation did not return a JSON object",
                    )
            return PresenceResult("present", returncode=0, data=data)
        detail = self._combined_output(result) or "no command output"
        if resource_type == "floating_ip" and self._is_floating_ip_formatter_error(
            result
        ):
            self._floating_ip_show_formatter_broken = True
            try:
                evidence = self._floating_ip_list_detail(resource_id, timeout=60)
            except RunCancelledError:
                raise
            except SuiteError as exc:
                return PresenceResult(
                    "unknown",
                    detail=f"{detail} Fallback failed: {exc}",
                    returncode=result.returncode,
                )
            if evidence is None:
                return PresenceResult(
                    "unknown", detail="Floating-IP identity was not found in LIST"
                )
            return PresenceResult(
                "present",
                detail=evidence["_read_evidence"],
                data=evidence if include_data else None,
            )
        if self.is_not_found_result(
            result, expected_resource=resource_type.replace("_", " ")
        ):
            return PresenceResult("absent", detail=detail, returncode=result.returncode)
        return PresenceResult("unknown", detail=detail, returncode=result.returncode)

    def exists(self, resource_type: str, resource_id: str) -> bool:
        """Compatibility boolean that refuses to hide an unknown API result."""
        presence = self.presence(resource_type, resource_id)
        if presence.unknown:
            raise SuiteError(
                f"Could not determine whether {resource_type} {resource_id} exists: "
                f"{presence.detail}"
            )
        return presence.present

    @staticmethod
    def render(*args: str) -> str:
        return shlex.join(["openstack", *map(str, args)])
