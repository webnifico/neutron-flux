from __future__ import annotations

import dataclasses
from typing import Any


@dataclasses.dataclass
class SegmentInfo:
    id: str
    network_id: str
    network_type: str | None
    physical_network: str | None
    segmentation_id: str | int | None
    name: str | None = None
    raw: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class NetworkInfo:
    id: str
    name: str
    external: bool
    shared: bool
    network_type: str | None
    physical_network: str | None
    segmentation_id: str | int | None
    mtu: int | None
    port_security_enabled: bool | None
    raw: dict[str, Any]
    segment_ids: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class SubnetInfo:
    id: str
    name: str
    network_id: str
    cidr: str
    ip_version: int
    gateway_ip: str | None
    dhcp_enabled: bool
    allocation_pools: list[Any]
    subnetpool_id: str | None
    ipv6_address_mode: str | None
    ipv6_ra_mode: str | None
    dns_nameservers: list[str]
    address_class: str
    raw: dict[str, Any]
    segment_id: str | None = None
    address_scope_id: str | None = None
    service_types: list[str] = dataclasses.field(default_factory=list)

    @property
    def has_assignable_addresses(self) -> bool:
        return bool(self.allocation_pools)

    def supports_device_owner(self, device_owner: str) -> bool:
        """Return whether this subnet is intended for the supplied port owner.

        An empty service-type list is Neutron's compatibility fallback. When
        service types exist, respect the operator's exact device-owner intent
        even though an explicitly requested subnet can bypass automatic IPAM
        service-subnet selection.
        """
        normalized = {str(item).strip().lower() for item in self.service_types}
        return not normalized or device_owner.lower() in normalized

    @property
    def supports_compute_endpoint(self) -> bool:
        return self.supports_device_owner("compute:nova")

    @property
    def supports_router_gateway(self) -> bool:
        return self.supports_device_owner("network:router_gateway")

    @property
    def supports_floating_ip(self) -> bool:
        return self.supports_device_owner("network:floatingip")


@dataclasses.dataclass
class PoolInfo:
    id: str
    name: str
    ip_version: int
    address_scope_id: str | None
    prefixes: list[str]
    default_prefix_length: int
    min_prefix_length: int
    max_prefix_length: int
    shared: bool
    project_id: str | None
    provider_pool: bool
    raw: dict[str, Any]

    @property
    def is_default(self) -> bool:
        """Return Neutron's explicit default-pool flag without inferring a role."""

        value = self.raw.get("is_default")
        if value is None:
            value = self.raw.get("default")
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return value is True

    @property
    def shared_default(self) -> bool:
        """Whether Neutron explicitly publishes the pool shared and default."""

        return self.shared and self.is_default


@dataclasses.dataclass
class QuotaInfo:
    resource: str
    limit: int | None
    used: int | None
    reserved: int = 0

    @property
    def available(self) -> int | None:
        if self.limit is None or self.limit < 0 or self.used is None:
            return None
        return max(0, self.limit - self.used - self.reserved)


@dataclasses.dataclass
class Discovery:
    project_id: str
    project_name: str
    cloud: str | None
    networks: list[NetworkInfo]
    subnets: list[SubnetInfo]
    pools: list[PoolInfo]
    address_scopes: list[dict[str, Any]]
    quotas: dict[str, Any]
    segments: list[SegmentInfo] = dataclasses.field(default_factory=list)
    quota_info: dict[str, QuotaInfo] = dataclasses.field(default_factory=dict)
    occupied_cidrs: list[str] = dataclasses.field(default_factory=list)
    network_extensions: list[str] = dataclasses.field(default_factory=list)
    neutron_availability_zones: dict[str, dict[str, bool]] | None = None
    region_name: str | None = None

    def subnets_for_network(self, network_id: str) -> list[SubnetInfo]:
        return [subnet for subnet in self.subnets if subnet.network_id == network_id]

    def subnet(self, subnet_id: str) -> SubnetInfo:
        return next(item for item in self.subnets if item.id == subnet_id)

    def network(self, network_id: str) -> NetworkInfo:
        return next(item for item in self.networks if item.id == network_id)

    def pool(self, pool_id: str | None) -> PoolInfo | None:
        if not pool_id:
            return None
        return next((item for item in self.pools if item.id == pool_id), None)

    def segment(self, segment_id: str | None) -> SegmentInfo | None:
        if not segment_id:
            return None
        return next((item for item in self.segments if item.id == segment_id), None)


@dataclasses.dataclass
class PlannedGroup:
    id: str
    kind: str
    label: str
    network_id: str | None
    network_name: str | None
    subnet_ids: list[str]
    families: list[int]
    pool_id: str | None = None
    pool_name: str | None = None
    external_network_id: str | None = None
    external_network_name: str | None = None
    external_subnet_id: str | None = None
    floating_subnet_id: str | None = None
    address_scope_id: str | None = None
    prefix_length: int | None = None
    synthetic_cidr: str | None = None
    segment_id: str | None = None
    physical_network: str | None = None
    relationship: str = "provider"
    expected_routing: str = "reachable"
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class TestSpec:
    id: str
    category: str
    operation: str
    family: int | None
    expectation: str
    expectation_reason: str
    authoritative: bool
    dependencies: list[str]
    source_group_id: str | None = None
    destination_group_id: str | None = None
    source_side: str = "A"
    destination_side: str = "A"
    source_subnet_id: str | None = None
    destination_subnet_id: str | None = None
    protocol: str | None = None
    phase: str = "cross"
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)
    display_name: str | None = None
    scenario: str | None = None
    # Selection prerequisites make a targeted plan complete.  Passing
    # prerequisites additionally suppress a dependent probe when the named
    # baseline did not pass.  They are separate because restoration operations
    # must still run after a failed cloud operation result.
    requires: list[str] = dataclasses.field(default_factory=list)
    requires_pass: list[str] = dataclasses.field(default_factory=list)

    @property
    def test_id(self) -> str:
        return self.id


@dataclasses.dataclass
class HostQualificationHost:
    host: str
    availability_zone: str | None
    enabled: bool
    up: bool
    aggregate_ids: list[str] = dataclasses.field(default_factory=list)
    aggregate_names: list[str] = dataclasses.field(default_factory=list)
    service_ids: list[str] = dataclasses.field(default_factory=list)
    aliases: list[str] = dataclasses.field(default_factory=list)
    blockers: list[str] = dataclasses.field(default_factory=list)

    @property
    def eligible(self) -> bool:
        return not self.blockers and self.enabled and self.up


@dataclasses.dataclass
class HostQualificationPair:
    pair_id: str
    source_host: str
    destination_host: str
    source_availability_zone: str | None
    destination_availability_zone: str | None
    same_host: bool
    same_availability_zone: bool
    execution_mode: str
    status: str = "PLANNED"
    blockers: list[str] = dataclasses.field(default_factory=list)

    @property
    def eligible(self) -> bool:
        return self.status == "PLANNED" and not self.blockers


@dataclasses.dataclass
class HostQualificationPlan:
    enabled: bool
    generated_at: str | None
    inventory_fingerprint: str | None
    strategy: str
    profile: str
    cycles: int
    include_same_host: bool
    requested_hosts: list[str] = dataclasses.field(default_factory=list)
    requested_aggregates: list[str] = dataclasses.field(default_factory=list)
    requested_pairs: list[list[str]] = dataclasses.field(default_factory=list)
    resolved_aggregate_ids: list[str] = dataclasses.field(default_factory=list)
    resolved_aggregate_names: list[str] = dataclasses.field(default_factory=list)
    hosts: list[HostQualificationHost] = dataclasses.field(default_factory=list)
    pairs: list[HostQualificationPair] = dataclasses.field(default_factory=list)
    warnings: list[str] = dataclasses.field(default_factory=list)
    estimates: dict[str, int] = dataclasses.field(default_factory=dict)
    aggregate_policy: dict[str, Any] = dataclasses.field(default_factory=dict)

    @property
    def eligible_pairs(self) -> list[HostQualificationPair]:
        return [pair for pair in self.pairs if pair.eligible]

    @property
    def availability_zones(self) -> list[str]:
        return sorted(
            {
                zone
                for host in self.hosts
                if host.eligible
                for zone in [host.availability_zone]
                if zone
            }
        )


@dataclasses.dataclass
class Plan:
    provider_groups: list[PlannedGroup]
    tenant_groups: list[PlannedGroup]
    estimated: dict[str, int]
    skipped: list[dict[str, str]]
    tests: list[TestSpec] = dataclasses.field(default_factory=list)
    warnings: list[str] = dataclasses.field(default_factory=list)
    host_qualification: HostQualificationPlan | None = None
    selection_mode: str = "all"
    requested_test_ids: list[str] = dataclasses.field(default_factory=list)
    automatically_included_test_ids: list[str] = dataclasses.field(default_factory=list)
    checks: list[dict[str, Any]] = dataclasses.field(default_factory=list)

    @property
    def groups(self) -> list[PlannedGroup]:
        return [*self.provider_groups, *self.tenant_groups]

    def group(self, group_id: str) -> PlannedGroup:
        return next(item for item in self.groups if item.id == group_id)


@dataclasses.dataclass
class PlannedPathTest:
    test_id: str
    category: str
    family: int | None
    control_path: list[str]
    data_path: list[str]
    operation: str
    expectation: str

    @property
    def signature(self) -> tuple[Any, ...]:
        return (
            self.category,
            self.family,
            tuple(self.control_path),
            tuple(self.data_path),
            self.operation,
            self.expectation,
        )


@dataclasses.dataclass
class ProbeResult:
    outcome: str
    success: bool
    elapsed_ms: int
    attempts: int
    stdout: str = ""
    stderr: str = ""
    command: str = ""
    source_ip: str | None = None
    destination_ip: str | None = None
    protocol: str | None = None
    diagnostics: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class PolicyDecision:
    status: str
    message: str
    expected: str
    observed: str
    authoritative: bool


@dataclasses.dataclass
class TestResult:
    test_id: str
    category: str
    status: str
    family: int | None
    source: str | None
    destination: str | None
    message: str
    started_at: str
    duration_ms: int
    details: dict[str, Any]
    expected: str | None = None
    observed: str | None = None
    authoritative: bool | None = None
    likely_failure: str | None = None
    display_name: str | None = None
    scenario: str | None = None
    contract: dict[str, Any] = dataclasses.field(default_factory=dict)
    path_signature: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class ResourceRecord:
    sequence: int
    resource_type: str
    id: str
    name: str
    parent_id: str | None
    metadata: dict[str, Any]
    created_at: str
    deleted_at: str | None = None
    delete_status: str | None = None
    cleanup_state: str = "PRESENT"
    cleanup_attempts: int = 0
    cleanup_error: str | None = None


@dataclasses.dataclass
class ComputeHostInfo:
    host: str
    availability_zone: str | None
    enabled: bool
    up: bool
    aggregate_ids: set[str] = dataclasses.field(default_factory=set)
    aggregate_names: set[str] = dataclasses.field(default_factory=set)
    service_ids: list[str] = dataclasses.field(default_factory=list)
    service_records: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    aliases: set[str] = dataclasses.field(default_factory=set)
    blockers: list[str] = dataclasses.field(default_factory=list)

    @property
    def eligible(self) -> bool:
        return self.enabled and self.up and not self.blockers


@dataclasses.dataclass
class ZoneCapability:
    name: str
    enabled_hosts: list[str]
    migration_cohort_size: int
    cinder_available: bool | None
    network_availability: dict[str, bool | None]
    warnings: list[str] = dataclasses.field(default_factory=list)
    different_host_coverage_available: bool = False
    volume_type_available: bool | None = None


@dataclasses.dataclass
class ZoneExecutionPlan:
    zones: list[str]
    mode: str
    capabilities: dict[str, ZoneCapability]
    explicit_selection: bool
    parallel_workers: int
    warnings: list[str] = dataclasses.field(default_factory=list)

    @property
    def includes_per_zone(self) -> bool:
        return self.mode in {"per-zone", "both"}

    @property
    def includes_cross_zone(self) -> bool:
        return self.mode in {"cross-zone", "both"}


@dataclasses.dataclass
class MigrationResult:
    server_id: str
    source_host: str
    destination_host: str
    source_availability_zone: str | None
    destination_availability_zone: str | None
    confirmed: bool
    automatically_confirmed: bool
    port_binding_verified: bool | None
    migration_record_verified: bool | None = True
    migration_record_error: str | None = None
    task_state_cleared: bool | None = True
    volume_attachment_verified: bool | None = True
    volume_validation_error: str | None = None
    guest_marker_verified: bool | None = True
    guest_marker_error: str | None = None
    port_validation_error: str | None = None
    endpoint_ready: bool = True
    endpoint_recovery_error: str | None = None
    details: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class Endpoint:
    label: str
    server_id: str
    server_name: str
    management_port_id: str
    management_ip: str
    test_port_id: str | None
    test_mac: str | None
    fixed_ips: dict[str, str]
    host: str | None
    availability_zone: str | None
    volume_id: str | None
    side: str = "A"
    port_security_enabled: bool | None = None
    network_table_base: int = 100
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class RuntimeGroup:
    plan: PlannedGroup
    network_id: str
    network_name: str
    subnet_ids: list[str]
    router_id: str | None
    endpoints: list[Endpoint]
    source_nat_enabled: bool | None
    fips: dict[str, dict[str, str]]
    generation: int = 1
    original_router_state: dict[str, Any] = dataclasses.field(default_factory=dict)
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)

    def endpoint(self, side: str) -> Endpoint | None:
        side = side.upper()
        return next(
            (item for item in self.endpoints if item.side.upper() == side), None
        )


@dataclasses.dataclass
class RunCheckpoint:
    run_id: str
    state: str
    action: str
    phase: str
    current_batch: str | None
    started_at: str
    updated_at: str
    last_activity: str
    completed_test_ids: list[str]
    failed_test_ids: list[str]
    pending_test_ids: list[str]
    active_group_ids: list[str]
    manifest_path: str
    report_dir: str
    plan_path: str | None = None
    error: str | None = None
    cleanup_state: str = "NOT_STARTED"
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)
