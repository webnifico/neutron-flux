from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import SuiteError
from .network_contract import group_resource_slug
from .results_io import append_text

DEFAULT_RESOURCE_NAME_LIMIT = 80
SERVER_RESOURCE_NAME_LIMIT = 63

_ROLE_ALIASES = {
    "a": "project-a",
    "b": "project-b",
    "endpoint-a": "project-a",
    "endpoint-b": "project-b",
    "tenant-a": "project-a",
    "tenant-b": "project-b",
    "east-west": "project-router",
}
_COMPACT_ROLE_ALIASES = {
    "project-a": "a",
    "project-b": "b",
    "project-router": "router",
    "controller": "ctrl",
    "controller-management": "ctrl-mgmt",
    "controller-probe": "ctrl-probe",
    "endpoint-management": "ep-mgmt",
    "project-a-data": "a-data",
    "project-b-data": "b-data",
    "management": "mgmt",
    "management-bastion": "bastion",
    "bastion-access": "access",
    "bastion-management": "bastion-mgmt",
}
_RESOURCE_TYPE_ALIASES = {
    "network": "net",
    "subnet": "subnet",
    "router": "router",
    "port": "port",
    "server": "vm",
    "volume": "volume",
    "security-group": "sg",
    "security_group": "sg",
    "keypair": "key",
}
_FORBIDDEN_GENERATED_TERMS = (
    "extra-route",
    "extra_route",
    "tenant",
    "fabric-scale",
)


class ResourceNameCollisionError(SuiteError):
    """Raised before an OpenStack create can reuse a run-local resource name."""


@dataclass
class _Reservation:
    identity: str
    resource_type: str
    claimed_for_create: bool = False


class ResourceNameRegistry:
    """One allocator for physical names and topology lifetimes in a run scope.

    Allocation and create claims are fsynced before returning. Deleted resources
    never release their identities. The runner's existing run lock excludes a
    second process; this lock serializes the workers sharing that run.
    """

    def __init__(self, prefix: str, *, journal_path: Path | None = None):
        self.prefix = _clean(prefix, lowercase=False)
        self._lock = threading.RLock()
        self._reservations: dict[str, _Reservation] = {}
        self._generations: dict[str, int] = {}
        self._sequence = 0
        self.journal_path: Path | None = None
        self._journal_failed = False
        if journal_path is not None:
            self.attach_journal(journal_path)

    def attach_journal(self, path: Path) -> None:
        with self._lock:
            if self.journal_path == path:
                return
            if self.journal_path is not None or self._reservations or self._generations:
                raise SuiteError("Cannot replace an active resource identity journal")
            if path.is_symlink() or path.parent.is_symlink():
                raise SuiteError(
                    f"Resource identity journal must not be a symbolic link: {path}"
                )
            try:
                lines = (
                    path.read_text(encoding="utf-8").splitlines(keepends=True)
                    if path.exists()
                    else []
                )
                for line in lines:
                    if not line.endswith("\n"):
                        raise ValueError("incomplete journal record")
                    self._apply(json.loads(line))
            except (OSError, ValueError, TypeError, KeyError, SuiteError) as exc:
                self._journal_failed = True
                raise SuiteError(
                    f"Cannot replay resource identity journal {path}: {exc}"
                ) from exc
            self.journal_path = path
            self._journal_failed = True
            append_text(path, "")
            self._journal_failed = False

    def _apply(self, record: dict[str, Any]) -> None:
        if (
            not isinstance(record, dict)
            or record.get("schema") != 1
            or record.get("prefix") != self.prefix
        ):
            raise ValueError("invalid resource identity journal scope or schema")
        event = record.get("event")
        if event == "generation":
            group = record["group"]
            generation = record["generation"]
            if (
                not isinstance(group, str)
                or not group.strip()
                or type(generation) is not int
                or generation != self._generations.get(group, 0) + 1
            ):
                raise ValueError("invalid topology generation sequence")
            self._generations[group] = generation
        elif event == "reserve":
            name = self._validate_name(record["name"])
            sequence = record["sequence"]
            identity = record["identity"]
            resource_type = record["resource_type"]
            if (
                type(sequence) is not int
                or sequence != self._sequence + 1
                or name in self._reservations
            ):
                raise ValueError("invalid resource allocation sequence")
            if (
                not isinstance(identity, str)
                or not identity.strip()
                or not isinstance(resource_type, str)
                or not resource_type.strip()
            ):
                raise ValueError("invalid resource allocation identity")
            self._reservations[name] = _Reservation(identity, resource_type)
            self._sequence = sequence
        elif event == "claim":
            existing = self._reservations[record["name"]]
            if existing.claimed_for_create:
                raise ValueError("duplicate resource create claim")
            existing.claimed_for_create = True
        else:
            raise ValueError("unknown resource identity journal event")

    def _record(self, event: str, **fields: Any) -> None:
        if self._journal_failed:
            raise SuiteError(
                "Resource identity journal requires recovery before further creation"
            )
        record = {"schema": 1, "prefix": self.prefix, "event": event, **fields}
        # Only a complete durable append and replay permit further allocation.
        # This also blocks reuse after a short write or an interrupted append.
        self._journal_failed = True
        if self.journal_path is not None:
            append_text(self.journal_path, json.dumps(record, sort_keys=True) + "\n")
        self._apply(record)
        self._journal_failed = False

    def allocate_group_generation(self, group_id: str) -> int:
        group = str(group_id or "").strip()
        if not group:
            raise ValueError("Group generation identity must not be empty")
        with self._lock:
            generation = self._generations.get(group, 0) + 1
            self._record("generation", group=group, generation=generation)
            return generation

    def allocate(
        self,
        *,
        identity: str,
        descriptor: str,
        role: str,
        resource_type: str,
        limit: int,
    ) -> str:
        """Allocate a new physical resource, independent of logical scheduling IDs."""
        suffix, compact_suffix = _role_and_type_suffix(role, resource_type)
        with self._lock:
            name = _bounded_name(
                self.prefix,
                descriptor,
                suffix,
                token=f"r{self._sequence + 1:x}",
                limit=limit,
                compact_suffix=compact_suffix,
            )
            return self.reserve(name, identity=identity, resource_type=resource_type)

    def _validate_name(self, name: str) -> str:
        candidate = str(name or "").strip()
        if not candidate or _clean(candidate, lowercase=False) != candidate:
            raise ValueError(
                f"Resource name {candidate!r} is not in normalized OpenStack form"
            )
        if candidate != self.prefix and not candidate.startswith(f"{self.prefix}-"):
            raise ValueError(
                f"Managed resource name {candidate!r} does not preserve run prefix {self.prefix!r}"
            )
        return candidate

    def reserve(self, name: str, *, identity: str, resource_type: str) -> str:
        candidate = self._validate_name(name)
        semantic_identity = str(identity or "").strip()
        if not semantic_identity:
            raise ValueError("Resource-name reservation identity must not be empty")
        canonical_type = _canonical_resource_type(resource_type)
        with self._lock:
            existing = self._reservations.get(candidate)
            if existing is None:
                self._record(
                    "reserve",
                    sequence=self._sequence + 1,
                    name=candidate,
                    identity=semantic_identity,
                    resource_type=canonical_type,
                )
            elif (
                existing.identity != semantic_identity
                or existing.resource_type != canonical_type
            ):
                raise ResourceNameCollisionError(
                    f"Resource name collision for {candidate!r}: "
                    f"{existing.resource_type}/{existing.identity!r} is already reserved, "
                    f"cannot reserve {canonical_type}/{semantic_identity!r}"
                )
            return candidate

    def claim_for_create(
        self,
        name: str,
        *,
        resource_type: str,
        identity: str | None = None,
    ) -> str:
        """Claim the same physical name once; retries must reconcile its operation."""
        candidate = self._validate_name(name)
        canonical_type = _canonical_resource_type(resource_type)
        with self._lock:
            existing = self._reservations.get(candidate)
            if existing is None:
                self.reserve(
                    candidate,
                    identity=identity or f"runtime-create:{canonical_type}:{candidate}",
                    resource_type=canonical_type,
                )
                existing = self._reservations[candidate]
            if existing.resource_type != canonical_type or (
                identity is not None and existing.identity != identity
            ):
                raise ResourceNameCollisionError(
                    f"Resource name {candidate!r} was reserved for a different identity or type"
                )
            if existing.claimed_for_create:
                raise ResourceNameCollisionError(
                    f"Resource name {candidate!r} has already been claimed for "
                    f"{canonical_type} creation in this run"
                )
            self._record("claim", name=candidate)
            return candidate

    def snapshot(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {
                name: {
                    "identity": item.identity,
                    "resource_type": item.resource_type,
                    "claimed_for_create": item.claimed_for_create,
                }
                for name, item in self._reservations.items()
            }


# Keep ownership for the process lifetime, including gaps between executors.
_RUN_REGISTRIES: dict[tuple[str, str | None], ResourceNameRegistry] = {}
_RUN_REGISTRIES_LOCK = threading.RLock()


def _clean(value: Any, *, lowercase: bool = True) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or "")).strip("-.")
    if lowercase:
        cleaned = cleaned.lower()
    return cleaned or "unnamed"


def _canonical_resource_type(value: Any) -> str:
    raw = _clean(value)
    return _RESOURCE_TYPE_ALIASES.get(raw, raw)


def canonical_project_side(value: Any) -> str:
    """Return the canonical project-side identity while accepting legacy aliases."""

    raw = _clean(value)
    return _ROLE_ALIASES.get(raw, raw)


def resource_name_registry(
    prefix: str, *, run_dir: Path | None = None
) -> ResourceNameRegistry:
    """Return the shared allocator; production builders always attach its journal."""
    canonical_prefix = _clean(prefix, lowercase=False)
    key = (canonical_prefix, str(run_dir.resolve()) if run_dir is not None else None)
    with _RUN_REGISTRIES_LOCK:
        registry = _RUN_REGISTRIES.get(key)
        if registry is None:
            registry = ResourceNameRegistry(canonical_prefix)
            _RUN_REGISTRIES[key] = registry
        if run_dir is not None:
            registry.attach_journal(run_dir / "resource-identities.jsonl")
        return registry


def _registry_for(owner: Any) -> ResourceNameRegistry:
    if isinstance(owner, ResourceNameRegistry):
        return owner
    if isinstance(owner, str):
        return resource_name_registry(owner)
    registry = getattr(owner, "resource_name_registry", None)
    if not isinstance(registry, ResourceNameRegistry):
        registry = resource_name_registry(owner.name_prefix)
        owner.resource_name_registry = registry
    return registry


def _family_token(group: Any) -> str:
    families = [
        int(value)
        for value in (getattr(group, "families", None) or [])
        if str(value).isdigit()
    ]
    if len(families) == 1:
        return f"ipv{families[0]}"
    if families:
        return "dual-stack"
    return "control"


def _bounded_name(
    prefix: str,
    descriptor: str,
    suffix: str,
    *,
    token: str,
    limit: int,
    compact_suffix: str,
) -> str:
    """Shorten labels only; never truncate or hash the allocated identity."""
    prefix = _clean(prefix, lowercase=False)
    descriptor = _clean(descriptor)
    for candidate_suffix in dict.fromkeys((suffix, compact_suffix)):
        fixed = f"{prefix}-{token}-{candidate_suffix}"
        if len(fixed) > limit:
            continue
        budget = limit - len(fixed) - 1
        excerpt = descriptor[: max(0, budget)].rstrip("-.")
        if excerpt:
            return f"{prefix}-{token}-{excerpt}-{candidate_suffix}"
        return fixed
    raise SuiteError(
        f"Resource-name limit {limit} cannot preserve run prefix {prefix!r}, "
        f"allocated identity {token!r}, and role {suffix!r}"
    )


def _role_and_type_suffix(role: Any, resource_type: Any) -> tuple[str, str]:
    canonical_role = canonical_project_side(role)
    canonical_type = _canonical_resource_type(resource_type)
    if canonical_type == "vm" and canonical_role in {"project-a", "project-b"}:
        side = canonical_role.rsplit("-", 1)[-1]
        # Endpoint server names historically end in -a/-b. Keep that useful
        # at-a-glance distinction while retaining both the role and resource
        # type in the readable suffix.
        return f"{canonical_role}-vm-{side}", f"vm-{side}"
    full = f"{canonical_role}-{canonical_type}"
    compact_role = _COMPACT_ROLE_ALIASES.get(canonical_role, canonical_role)
    compact = f"{compact_role}-{canonical_type}"
    return full, compact


def resource_name(
    owner: Any,
    group: Any,
    *,
    generation: int,
    role: str,
    resource_type: str,
    limit: int = DEFAULT_RESOURCE_NAME_LIMIT,
) -> str:
    """Allocate a physical name; logical group/generation remains journal metadata."""

    canonical_role = canonical_project_side(role)
    canonical_type = _canonical_resource_type(resource_type)
    descriptor = "-".join(
        (
            group_resource_slug(getattr(group, "kind", "")),
            _family_token(group),
            f"g{int(generation)}",
        )
    )
    lowered_descriptor = descriptor.lower()
    if any(term in lowered_descriptor for term in _FORBIDDEN_GENERATED_TERMS):
        raise ValueError(
            f"Generated resource descriptor contains legacy terminology: {descriptor}"
        )
    semantic_identity = "|".join(
        (
            group_resource_slug(getattr(group, "kind", "")),
            str(getattr(group, "id", "") or ""),
            _family_token(group),
            f"g{int(generation)}",
            canonical_role,
            canonical_type,
        )
    )
    return _registry_for(owner).allocate(
        identity=semantic_identity,
        descriptor=descriptor,
        role=canonical_role,
        resource_type=canonical_type,
        limit=limit,
    )


def managed_resource_name(
    owner: Any,
    *,
    identity: str,
    role: str,
    resource_type: str,
    limit: int = SERVER_RESOURCE_NAME_LIMIT,
) -> str:
    """Allocate a new run-wide control resource, retaining its logical identity."""

    canonical_type = _canonical_resource_type(resource_type)
    canonical_role = canonical_project_side(role)
    semantic_identity = "|".join(
        (
            "managed",
            str(identity or "").strip(),
            canonical_role,
            canonical_type,
        )
    )
    return _registry_for(owner).allocate(
        identity=semantic_identity,
        descriptor="managed",
        role=canonical_role,
        resource_type=canonical_type,
        limit=limit,
    )


def claim_runtime_resource_name(
    owner: Any,
    name: str,
    *,
    resource_type: str,
    identity: str | None = None,
) -> str:
    """Claim a generated name before cloud operation, preserving partial-test builders."""

    prefix = str(getattr(owner, "name_prefix", "") or "").strip()
    if not prefix:
        # Extracted unit tests intentionally construct a ResourceBuilder with
        # only the fields required by one method. Normal runtime builders always
        # have a run prefix and therefore always take the guarded path.
        return name
    return _registry_for(owner).claim_for_create(
        name,
        resource_type=resource_type,
        identity=identity,
    )


def endpoint_resource_stem(
    owner: Any,
    group: Any,
    *,
    generation: int,
    side: str,
    limit: int = SERVER_RESOURCE_NAME_LIMIT,
) -> str:
    return resource_name(
        owner,
        group,
        generation=generation,
        role=f"endpoint-{str(side).strip().lower()}",
        resource_type="server",
        limit=limit,
    )


__all__ = [
    "DEFAULT_RESOURCE_NAME_LIMIT",
    "ResourceNameCollisionError",
    "ResourceNameRegistry",
    "SERVER_RESOURCE_NAME_LIMIT",
    "canonical_project_side",
    "claim_runtime_resource_name",
    "endpoint_resource_stem",
    "managed_resource_name",
    "resource_name",
    "resource_name_registry",
]
