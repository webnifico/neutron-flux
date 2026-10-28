from __future__ import annotations

import tempfile
import threading
from dataclasses import dataclass, field
from functools import wraps
from pathlib import Path
from typing import Any, Generic, TypeVar

from ..config import Config
from ..constants import MIN_TEST_RAM_MB, TOOL_NAME
from ..models import ComputeHostInfo, Discovery, Endpoint, Plan, RuntimeGroup
from ..openstack import OpenStack
from ..reporting import Reporter, ResourceTracker
from ..resource_naming import (
    ResourceNameRegistry,
    managed_resource_name,
    resource_name_registry,
)
from ..translation_safety import floating_ip_target_sides
from .types import LaunchSelection, SecurityGroupBundle

T = TypeVar("T")


def serialized_lifecycle(method: Any) -> Any:
    """Reserve a lifecycle window and consolidate its settlement deadline.

    Independent port/server creation shares admission; disruptive lifecycles
    are exclusive. The fallback lock supports standalone runtime integrations.
    """

    kind_by_method = {
        "_create_management_network": "network-topology",
        "_create_bastion_access_topology": "network-topology",
        "_create_bastion_floating_ip": "floating-ip",
        "_create_port": "port-create",
        "_create_server": "server-create",
        "_create_endpoints": "server-create",
        "live_migrate_endpoint": "migration",
        "cold_migrate_endpoint": "migration",
    }

    @wraps(method)
    def wrapped(self: Any, *args: Any, **kwargs: Any) -> Any:
        coordinator = getattr(self, "cloud_operation_coordinator", None)
        kind = kind_by_method.get(method.__name__, "generic")
        description = f"{method.__name__} lifecycle sequence"
        if coordinator is not None:
            with coordinator.freeze(kind, description):
                try:
                    return method(self, *args, **kwargs)
                finally:
                    # The method's own API readback/settlement normally completes
                    # before this final quiet period.  On a failed cloud operation it also
                    # prevents an immediate retry or cleanup action from landing on
                    # the same OVS/OVN state transition.
                    coordinator.settle(kind, f"settlement after {description}")

        lock = getattr(self, "lifecycle_lock", None)
        if lock is None:
            lock = threading.RLock()
            self.lifecycle_lock = lock
        with lock:
            return method(self, *args, **kwargs)

    return wrapped


class StateField(Generic[T]):
    """Compatibility descriptor backed by :class:`ResourceRuntimeState`.

    Several unit tests intentionally construct ``ResourceBuilder`` with
    ``__new__`` and populate only the fields required by the method under test.
    The descriptor therefore falls back to the instance dictionary until the
    normal constructor installs ``_state``.
    """

    def __init__(self, name: str):
        self.name = name

    def __get__(self, instance: object | None, owner: type | None = None) -> T:
        if instance is None:
            return self  # type: ignore[return-value]
        state = instance.__dict__.get("_state")
        if state is not None:
            return getattr(state, self.name)
        try:
            return instance.__dict__[self.name]
        except KeyError as exc:
            raise AttributeError(self.name) from exc

    def __set__(self, instance: object, value: T) -> None:
        state = instance.__dict__.get("_state")
        if state is not None:
            setattr(state, self.name, value)
        else:
            instance.__dict__[self.name] = value


@dataclass(frozen=True)
class RuntimeDependencies:
    """Stable collaborators shared by all runtime subsystems."""

    config: Config
    discovery: Discovery
    plan: Plan
    osc: OpenStack
    reporter: Reporter
    tracker: ResourceTracker


@dataclass
class ResourceRuntimeState:
    """Explicit mutable state owned by a single ``ResourceBuilder`` run."""

    launch_selection: LaunchSelection | None
    run_tag: str
    name_prefix: str
    work_dir: Path
    key_path: Path
    public_key_path: Path
    keypair_name: str
    resource_name_registry: ResourceNameRegistry

    image_id: str = ""
    image_name: str = ""
    flavor_id: str = ""
    flavor_name: str = ""
    flavor_vcpus: int = 1
    flavor_ram_mb: int = MIN_TEST_RAM_MB
    flavor_disk_gb: int = 0
    ssh_user: str = ""

    management_network_id: str = ""
    management_subnet_id: str = ""
    management_sg_id: str = ""
    controller_sg_id: str = ""
    endpoint_management_sg_id: str = ""
    test_sg_id: str = ""
    test_sg_ids: dict[str, str] = field(default_factory=dict)
    security_control_ports: dict[int, int] = field(default_factory=dict)
    security_control_authoritative: dict[int, bool] = field(default_factory=dict)
    security_control_matching_rules: dict[int, list[dict[str, Any]]] = field(
        default_factory=dict
    )
    address_group_cache: dict[str, tuple[bool, list[str]]] = field(default_factory=dict)
    management_cidr: str = ""

    controller: Endpoint | None = None
    bastion: Endpoint | None = None
    control_address: str = ""
    controller_command_address: str = ""
    controller_via_proxy: bool = False
    controller_probe_ports: list[dict[str, Any]] = field(default_factory=list)
    controller_probe_sources: dict[int, str] = field(default_factory=dict)
    controller_probe_subnets: dict[int, str] = field(default_factory=dict)
    controller_probe_mode: str = "none"
    controller_bootstrap_diagnostics: list[dict[str, Any]] = field(default_factory=list)
    controller_access_error: str | None = None
    controller_failure_diagnostics: dict[str, Any] | None = None
    controller_recheck_required: bool = False
    last_ssh_readiness: dict[str, dict[str, Any]] = field(default_factory=dict)

    security_group_rules: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    shared_security_group_bundle: SecurityGroupBundle | None = None
    security_control_port_seed: int | None = None
    runtime_groups: list[RuntimeGroup] = field(default_factory=list)
    fip_group_ids: set[str] = field(default_factory=set)
    server_sequence: int = 0
    group_failures: dict[str, str] = field(default_factory=dict)
    group_failure_types: dict[str, str] = field(default_factory=dict)

    compute_host_inventory_cache: dict[str, ComputeHostInfo] | None = None
    aggregate_inventory_available: bool | None = None
    aggregate_inventory_count: int | None = None
    aggregate_inventory_state: str = "unknown"
    aggregate_inventory_errors: list[str] = field(default_factory=list)

    selected_availability_zone: str | None = None
    discovered_compute_availability_zone: str | None = None
    selected_availability_zone_reason: str = "not selected"
    pending_neutron_az_validation: dict[str, dict[str, Any]] = field(
        default_factory=dict
    )
    availability_zone_candidates: list[str | None] = field(
        default_factory=lambda: [None]
    )
    volume_availability_zones: set[str] | None = None
    volume_availability_zone_inventory_reason: str = "not queried"

    @classmethod
    def create(
        cls,
        config: Config,
        plan: Plan,
        reporter: Reporter,
        launch_selection: LaunchSelection | None,
    ) -> ResourceRuntimeState:
        work_dir = Path(tempfile.mkdtemp(prefix=f"{TOOL_NAME}-{reporter.run_id}-"))
        initial_control_port = 1024 + (
            (config.tcp_port + 2 - 1024) % (65535 - 1024 + 1)
        )
        name_registry = resource_name_registry(
            reporter.name_prefix, run_dir=reporter.run_dir
        )
        return cls(
            launch_selection=launch_selection,
            run_tag=reporter.run_tag,
            name_prefix=reporter.name_prefix,
            work_dir=work_dir,
            key_path=work_dir / "id_ed25519",
            public_key_path=work_dir / "id_ed25519.pub",
            keypair_name=managed_resource_name(
                name_registry,
                identity="run-ssh-keypair",
                role="ssh",
                resource_type="keypair",
            ),
            resource_name_registry=name_registry,
            security_control_ports={4: initial_control_port, 6: initial_control_port},
            security_control_authoritative={4: False, 6: False},
            security_control_matching_rules={4: [], 6: []},
            fip_group_ids={
                group_id
                for item in plan.tests
                for group_id in floating_ip_target_sides(item)
            },
        )
