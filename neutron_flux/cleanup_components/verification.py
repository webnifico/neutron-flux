from __future__ import annotations

# mypy: disable-error-code="attr-defined"
import json

from ..errors import RunCancelledError
from ..models import ResourceRecord
from ..scheduling import READ_WORKERS, bounded_map


class CleanupVerificationMixin:
    """Compatibility mixin for this cleanup concern."""

    def _verify_placement_allocations(self) -> list[str]:
        """Check for allocations left behind for deleted test servers.

        The Placement OSC plugin is not installed in every environment. A
        command-not-found response is therefore treated as unsupported rather
        than a cleanup failure. A successful query with non-empty allocations is
        authoritative and is surfaced as a leftover.
        """
        resources = [
            resource
            for resource in self.reporter.resources
            if resource.resource_type == "server"
        ]

        def read_presence(resource: ResourceRecord) -> tuple[bool, list[str]]:
            try:
                server_still_exists = self.osc.exists("server", resource.id)
            except RunCancelledError:
                raise
            except Exception as exc:
                return False, [
                    f"placement-allocation:{resource.id}:verification-error:"
                    f"server presence unknown: {exc}"
                ]
            return not server_still_exists, []

        def read_allocation(resource: ResourceRecord) -> tuple[list[str], bool]:
            result = self.osc.run(
                "resource",
                "provider",
                "allocation",
                "show",
                resource.id,
                "-f",
                "json",
                check=False,
                timeout=30,
            )
            if result.returncode != 0:
                if self.osc.is_unsupported_result(result):
                    return [], True
                if self.osc.is_not_found_result(
                    result,
                    expected_resource="resource provider allocation",
                ):
                    return [], False
                detail = (
                    result.stderr or result.stdout
                ).strip() or "unknown OpenStack error"
                return [
                    f"placement-allocation:{resource.id}:verification-error:{detail}"
                ], False
            try:
                payload = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                return [
                    f"placement-allocation:{resource.id}:verification-error:invalid JSON: {exc}"
                ], False
            if not isinstance(payload, (dict, list)):
                return [
                    f"placement-allocation:{resource.id}:verification-error:unexpected payload type {type(payload).__name__}"
                ], False
            allocations = (
                payload.get("allocations", payload)
                if isinstance(payload, dict)
                else payload
            )
            if (
                isinstance(payload, dict)
                and "allocations" in payload
                and not isinstance(allocations, dict)
            ):
                return [
                    f"placement-allocation:{resource.id}:verification-error:"
                    "allocations must be a JSON object"
                ], False
            if allocations:
                return [f"placement_allocation:{resource.id}:{resource.name}"], False
            return [], False

        # Fresh presence and allocation reads are independent across servers.
        # Keep the existing read limit and collect results in inventory order.
        observations = bounded_map(read_presence, resources, workers=READ_WORKERS)
        leftovers = [issue for _, issues in observations for issue in issues]
        absent = [
            resource
            for resource, (confirmed_absent, _) in zip(
                resources, observations, strict=True
            )
            if confirmed_absent
        ]
        if not absent:
            return leftovers
        first_issues, unsupported = read_allocation(absent[0])
        leftovers.extend(first_issues)
        if unsupported:
            # CLI command availability is process-wide. Do not run the same
            # unavailable plugin once for every deleted server in this sweep.
            return leftovers
        for issues, _ in bounded_map(read_allocation, absent[1:], workers=READ_WORKERS):
            leftovers.extend(issues)
        return leftovers
