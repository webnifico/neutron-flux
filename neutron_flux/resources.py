from __future__ import annotations

import shutil
import threading
import time
from typing import Any

from .cloud_operation import CloudOperationCoordinator
from .config import Config
from .constants import MIN_TEST_RAM_MB
from .failure_injection import inject_failure
from .guest_network import GuestNetworkVerifier
from .models import Discovery, Endpoint, Plan, RuntimeGroup
from .openstack import OpenStack
from .probe_service import ProbeServiceManager
from .reporting import Reporter, ResourceTracker
from .resource_naming import (
    ResourceNameRegistry,
    resource_name_registry,
)
from .runtime.availability import AvailabilityRuntimeMixin
from .runtime.compute import ComputeRuntimeMixin
from .runtime.context import ResourceRuntimeState, RuntimeDependencies, StateField
from .runtime.control_plane import ControlPlaneRuntimeMixin
from .runtime.launch import (
    _image_admin_user,
    _image_disk_requirements,
    _volume_type_availability_zones,
    resolve_launch_selection,
    validate_launch_selection_quota,
)
from .runtime.live_migration import LiveMigrationRuntimeMixin
from .runtime.migration import MigrationRuntimeMixin
from .runtime.probes import ProbeRuntimeMixin
from .runtime.router import RouterRuntimeMixin
from .runtime.security import SecurityRuntimeMixin
from .runtime.topology import TopologyRuntimeMixin
from .runtime.types import LaunchSelection, SecurityGroupBundle


class ResourceBuilder(
    SecurityRuntimeMixin,
    AvailabilityRuntimeMixin,
    ControlPlaneRuntimeMixin,
    TopologyRuntimeMixin,
    RouterRuntimeMixin,
    ComputeRuntimeMixin,
    LiveMigrationRuntimeMixin,
    MigrationRuntimeMixin,
    ProbeRuntimeMixin,
):
    lifecycle_lock: Any = None
    cloud_operation_coordinator: CloudOperationCoordinator | None = None
    lifecycle_settlement_enabled = False
    launch_selection = StateField[LaunchSelection | None]("launch_selection")
    run_tag = StateField[str]("run_tag")
    name_prefix = StateField[str]("name_prefix")
    work_dir = StateField[Any]("work_dir")
    key_path = StateField[Any]("key_path")
    public_key_path = StateField[Any]("public_key_path")
    keypair_name = StateField[str]("keypair_name")
    resource_name_registry = StateField[Any]("resource_name_registry")
    image_id = StateField[str]("image_id")
    image_name = StateField[str]("image_name")
    flavor_id = StateField[str]("flavor_id")
    flavor_name = StateField[str]("flavor_name")
    flavor_vcpus = StateField[int]("flavor_vcpus")
    flavor_ram_mb = StateField[int]("flavor_ram_mb")
    flavor_disk_gb = StateField[int]("flavor_disk_gb")
    ssh_user = StateField[str]("ssh_user")
    management_network_id = StateField[str]("management_network_id")
    management_subnet_id = StateField[str]("management_subnet_id")
    management_sg_id = StateField[str]("management_sg_id")
    controller_sg_id = StateField[str]("controller_sg_id")
    endpoint_management_sg_id = StateField[str]("endpoint_management_sg_id")
    test_sg_id = StateField[str]("test_sg_id")
    test_sg_ids = StateField[dict[str, str]]("test_sg_ids")
    security_control_ports = StateField[dict[int, int]]("security_control_ports")
    security_control_authoritative = StateField[dict[int, bool]](
        "security_control_authoritative"
    )
    security_control_matching_rules = StateField[dict[int, list[dict[str, Any]]]](
        "security_control_matching_rules"
    )
    _address_group_cache = StateField[dict[str, tuple[bool, list[str]]]](
        "address_group_cache"
    )
    management_cidr = StateField[str]("management_cidr")
    controller = StateField[Endpoint | None]("controller")
    bastion = StateField[Endpoint | None]("bastion")
    control_address = StateField[str]("control_address")
    controller_command_address = StateField[str]("controller_command_address")
    controller_via_proxy = StateField[bool]("controller_via_proxy")
    controller_probe_ports = StateField[list[dict[str, Any]]]("controller_probe_ports")
    controller_probe_sources = StateField[dict[int, str]]("controller_probe_sources")
    controller_probe_subnets = StateField[dict[int, str]]("controller_probe_subnets")
    controller_probe_mode = StateField[str]("controller_probe_mode")
    controller_bootstrap_diagnostics = StateField[list[dict[str, Any]]](
        "controller_bootstrap_diagnostics"
    )
    _last_ssh_readiness = StateField[dict[str, dict[str, Any]]]("last_ssh_readiness")
    _controller_access_error = StateField[str | None]("controller_access_error")
    _controller_failure_diagnostics = StateField[dict[str, Any] | None](
        "controller_failure_diagnostics"
    )
    _controller_recheck_required = StateField[bool]("controller_recheck_required")
    security_group_rules = StateField[dict[str, list[dict[str, Any]]]](
        "security_group_rules"
    )
    shared_security_group_bundle = StateField[SecurityGroupBundle | None](
        "shared_security_group_bundle"
    )
    security_control_port_seed = StateField[int | None]("security_control_port_seed")
    runtime_groups = StateField[list[RuntimeGroup]]("runtime_groups")
    fip_group_ids = StateField[set[str]]("fip_group_ids")
    server_sequence = StateField[int]("server_sequence")
    group_failures = StateField[dict[str, str]]("group_failures")
    group_failure_types = StateField[dict[str, str]]("group_failure_types")
    _compute_host_inventory_cache = StateField[Any]("compute_host_inventory_cache")
    _aggregate_inventory_available = StateField[bool | None](
        "aggregate_inventory_available"
    )
    _aggregate_inventory_count = StateField[int | None]("aggregate_inventory_count")
    _aggregate_inventory_state = StateField[str]("aggregate_inventory_state")
    _aggregate_inventory_errors = StateField[list[str]]("aggregate_inventory_errors")
    selected_availability_zone = StateField[str | None]("selected_availability_zone")
    discovered_compute_availability_zone = StateField[str | None](
        "discovered_compute_availability_zone"
    )
    selected_availability_zone_reason = StateField[str](
        "selected_availability_zone_reason"
    )
    pending_neutron_az_validation = StateField[dict[str, dict[str, Any]]](
        "pending_neutron_az_validation"
    )
    availability_zone_candidates = StateField[list[str | None]](
        "availability_zone_candidates"
    )
    volume_availability_zones = StateField[set[str] | None]("volume_availability_zones")
    volume_availability_zone_inventory_reason = StateField[str](
        "volume_availability_zone_inventory_reason"
    )

    def __init__(
        self,
        config: Config,
        discovery: Discovery,
        plan: Plan,
        osc: OpenStack,
        reporter: Reporter,
        tracker: ResourceTracker,
        launch_selection: LaunchSelection | None = None,
        lifecycle_lock: Any | None = None,
        cloud_operation_coordinator: CloudOperationCoordinator | None = None,
    ):
        self.dependencies = RuntimeDependencies(
            config=config,
            discovery=discovery,
            plan=plan,
            osc=osc,
            reporter=reporter,
            tracker=tracker,
        )
        if not hasattr(tracker, "deletion_callbacks"):
            tracker.deletion_callbacks = []
        tracker.deletion_callbacks.append(self._forget_deleted_resource)

        # Compatibility aliases remain stable for callers and extracted runtime
        # modules, while mutable run data has one explicit typed owner.
        self.config = config
        self.discovery = discovery
        self.plan = plan
        self.osc = osc
        self.reporter = reporter
        self.logger = reporter.logger
        self.tracker = tracker
        self.cloud_operation_coordinator = cloud_operation_coordinator
        self.lifecycle_lock = (
            cloud_operation_coordinator.lock
            if cloud_operation_coordinator is not None
            else (lifecycle_lock or threading.RLock())
        )
        self.lifecycle_settlement_enabled = True
        self._state = ResourceRuntimeState.create(
            config, plan, reporter, launch_selection
        )
        self.guest_network = GuestNetworkVerifier(self._runtime_subnet)
        self.probe_service = ProbeServiceManager(config.tcp_port, config.udp_port)

    @property
    def state(self) -> ResourceRuntimeState:
        """Return the complete mutable runtime state for diagnostics and tests."""

        return self._state

    def _forget_deleted_resource(self, item: Any) -> None:
        self.pending_neutron_az_validation.pop(f"{item.resource_type}:{item.id}", None)
        for runtime in self.runtime_groups:
            for endpoint in runtime.endpoints:
                if endpoint.server_id == item.id:
                    self._last_ssh_readiness.pop(f"True:{endpoint.management_ip}", None)
        coordinator = self.cloud_operation_coordinator
        if coordinator is not None:
            with coordinator.lock:
                for key in list(coordinator.placement_evidence):
                    if item.id == key[0] or item.id in key[1]:
                        coordinator.placement_evidence.pop(key, None)

    def allocate_group_generation(self, group_id: str) -> int:
        """The builder alone owns topology lifetimes, including side rotation."""
        registry = getattr(self, "resource_name_registry", None)
        if not isinstance(registry, ResourceNameRegistry):
            prefix = str(getattr(self, "name_prefix", "") or "").strip()
            registry = (
                resource_name_registry(prefix)
                if prefix
                else ResourceNameRegistry("test")
            )
            self.resource_name_registry = registry
        return registry.allocate_group_generation(group_id)

    def prepare(self) -> None:
        started = time.monotonic()
        self.logger.section("Preparing VM execution prerequisites")
        self.logger.log(
            "Preparation step 1/6: validating requested image, flavor, and storage mode"
        )
        self._resolve_image_flavor_user()
        self.logger.log(
            f"Preparation step 1/6 complete in {time.monotonic() - started:.1f}s"
        )

        step_started = time.monotonic()
        self.logger.log(
            "Preparation step 2/6: discovering compute, storage, and Neutron availability zones and migration cohorts"
        )
        self._select_run_availability_zone()
        self._prepare_neutron_placement()
        self.logger.log(
            f"Preparation step 2/6 complete in {time.monotonic() - step_started:.1f}s"
        )
        keypair_bootstrap_complete = False
        try:
            step_started = time.monotonic()
            self.logger.log(
                "Preparation step 3/6: creating the temporary SSH key and OpenStack keypair"
            )
            self._create_ssh_key()
            self._create_keypair()
            keypair_bootstrap_complete = True
            self.logger.log(
                f"Preparation step 3/6 complete in {time.monotonic() - step_started:.1f}s"
            )
        finally:
            if not keypair_bootstrap_complete:
                # The cloud keypair is not tracked until creation succeeds. Remove
                # local private material immediately when bootstrap fails before
                # the tracked cleanup path exists.
                shutil.rmtree(self.work_dir, ignore_errors=True)

        step_started = time.monotonic()
        self.logger.log(
            "Preparation step 4/6: creating the isolated management network and subnet"
        )
        self._create_management_network()
        self.logger.log(
            f"Preparation step 4/6 complete in {time.monotonic() - step_started:.1f}s"
        )

        step_started = time.monotonic()
        self.logger.log(
            "Preparation step 5/6: creating security groups, reconciling rules, and selecting control ports"
        )
        self._create_security_groups()
        if self.cloud_operation_coordinator is not None:
            self.cloud_operation_coordinator.settle(
                "security-group",
                "allow the run-wide security-group rule bundle to converge before port creation",
                seconds=15.0,
            )
        self.logger.log(
            f"Preparation step 5/6 complete in {time.monotonic() - step_started:.1f}s"
        )

        step_started = time.monotonic()
        self.logger.log(
            "Preparation step 6/6: creating and validating the probe controller"
        )
        inject_failure(self.config, "before-controller-create")
        self._create_controller()
        self._refresh_neutron_placements()
        inject_failure(self.config, "after-controller-create")
        self.logger.log(
            f"Preparation step 6/6 complete in {time.monotonic() - step_started:.1f}s; "
            f"all VM prerequisites prepared in {time.monotonic() - started:.1f}s"
        )

    def _resolve_image_flavor_user(self) -> None:
        selection = getattr(self, "launch_selection", None) or resolve_launch_selection(
            self.config, self.osc, self.logger
        )
        self.launch_selection = selection
        self.image_id = selection.image_id
        self.image_name = selection.image_name
        self.flavor_id = selection.flavor_id
        self.flavor_name = selection.flavor_name
        self.flavor_vcpus = selection.flavor_vcpus
        self.flavor_ram_mb = selection.flavor_ram_mb
        self.flavor_disk_gb = selection.flavor_disk_gib
        self.ssh_user = selection.ssh_user
        self._validate_selected_flavor_quota()

    def _validate_selected_flavor_quota(self) -> None:
        """Recheck quota using the exact selected flavor and root volume size."""
        selection = getattr(self, "launch_selection", None)
        if selection is None:
            selection = LaunchSelection(
                image_id=getattr(self, "image_id", "unknown"),
                image_name=getattr(self, "image_name", "unknown"),
                image_min_disk_gib=0,
                image_virtual_size_gib=0,
                image_required_disk_gib=0,
                flavor_id=getattr(self, "flavor_id", "unknown"),
                flavor_name=getattr(self, "flavor_name", "unknown"),
                flavor_vcpus=max(1, int(getattr(self, "flavor_vcpus", 1))),
                flavor_ram_mb=max(
                    1, int(getattr(self, "flavor_ram_mb", MIN_TEST_RAM_MB))
                ),
                flavor_disk_gib=max(0, int(getattr(self, "flavor_disk_gb", 0))),
                ssh_user=getattr(self, "ssh_user", "") or "unknown",
            )
        validate_launch_selection_quota(
            self.config, self.discovery, self.plan, selection
        )

    @staticmethod
    def _image_admin_user(image: dict[str, Any]) -> str | None:
        return _image_admin_user(image)


__all__ = [
    "LaunchSelection",
    "ResourceBuilder",
    "SecurityGroupBundle",
    "_image_admin_user",
    "_image_disk_requirements",
    "_volume_type_availability_zones",
    "resolve_launch_selection",
    "validate_launch_selection_quota",
]
