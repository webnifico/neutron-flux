from __future__ import annotations

# mypy: disable-error-code="attr-defined"
import dataclasses
from typing import Any


@dataclasses.dataclass(frozen=True)
class LaunchSelection:
    image_id: str
    image_name: str
    image_min_disk_gib: int
    image_virtual_size_gib: int
    image_required_disk_gib: int
    flavor_id: str
    flavor_name: str
    flavor_vcpus: int
    flavor_ram_mb: int
    flavor_disk_gib: int
    ssh_user: str
    volume_type_availability_zones: frozenset[str] | None = None


@dataclasses.dataclass(frozen=True)
class SecurityGroupBundle:
    controller_security_group_id: str
    endpoint_management_security_group_id: str
    data_security_group_ids: dict[str, str]
    management_cidr: str
    security_group_rules: dict[str, list[dict[str, Any]]]


class RouterSnapshot(dict[str, Any]):
    """Typed-at-the-boundary router snapshot used for exact restoration.

    It intentionally remains a ``dict`` subclass for backward compatibility
    with existing callers, manifests, and tests that use mapping operations.
    """

    @property
    def router_id(self) -> str:
        return str(self.get("router_id") or "")
