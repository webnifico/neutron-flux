from __future__ import annotations

import argparse
import dataclasses
import pathlib
from typing import Any


@dataclasses.dataclass
class Config:
    action: str
    prefix: str
    report_dir: pathlib.Path
    image: str | None
    flavor: str | None
    storage: str | None
    ssh_user: str | None
    availability_zones: list[str]
    availability_zones_all: bool
    zone_mode: str
    mgmt_cidr: str | None
    no_routing_group_ipv4_cidr: str | None
    no_routing_group_ipv6_cidr: str | None
    include_no_routing_group_controls: bool
    ipv4_targets: list[str]
    ipv6_targets: list[str]
    ipv4_targets_configured: bool
    ipv6_targets_configured: bool
    tcp_port: int
    udp_port: int
    ssh_timeout: int
    resource_timeout: int
    convergence_timeout: int
    convergence_interval: int
    progress_interval: int
    keep_resources: bool
    auto_cleanup_on_failure: bool
    volume_size: int
    volume_type: str | None
    max_active_endpoints: int
    cleanup_timeouts: dict[str, int]
    external_networks: list[str] = dataclasses.field(default_factory=list)
    exclude_external_networks: list[str] = dataclasses.field(default_factory=list)
    routing_contracts: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    allow_cross_az_volumes: bool = False
    allow_cross_az_networking: bool = False
    network_az: str | None = None
    router_az: str | None = None
    failure_injection: str | None = None
    compute_host_connectivity_enabled: bool = True
    require_shared_compute_aggregate: bool | None = None
    compute_migration_max_attempts: int = 2
    migration_mode: str = "live-preferred"
    migration_storage: str = "auto"
    live_migration_attempts: int = 5
    cold_migration_fallback: bool = True
    live_migration_continuity: bool = True
    input_sources: dict[str, str] = dataclasses.field(default_factory=dict)
    cleanup_orphans: bool = False
    cleanup_dry_run: bool = False
    cleanup_assume_yes: bool = False
    cleanup_include_active: bool = False
    orphan_grace_minutes: int = 30
    performance_profile: str = "standard"
    performance_enabled: bool = True
    performance_duration_seconds: int = 3
    performance_repeats: int = 2
    performance_max_paths: int = 0
    performance_tcp_streams: list[int] = dataclasses.field(
        default_factory=lambda: [1, 4]
    )
    performance_udp_rates_mbps: list[int] = dataclasses.field(
        default_factory=lambda: [10]
    )
    performance_udp_packet_sizes: list[int] = dataclasses.field(
        default_factory=lambda: [128, 1200]
    )
    performance_udp_adaptive_calibration: bool = True
    performance_udp_calibration_min_rate_mbps: int = 1
    performance_udp_calibration_max_attempts: int = 4
    performance_udp_calibration_backoff_factor: float = 0.5
    performance_ping_count: int = 20
    performance_ping_warmup_count: int = 5
    performance_enforce_thresholds: bool = False
    performance_udp_sender_achievement_threshold_pct: float = 90.0
    performance_udp_loss_threshold_pct: float = 1.0
    performance_udp_reordering_threshold_pct: float = 0.1
    performance_loaded_latency_ratio_threshold: float = 10.0
    performance_asymmetry_threshold_pct: float = 50.0
    performance_variation_threshold_pct: float = 25.0
    fabric_scale_enabled: bool = False
    fabric_scale_pairs: list[int] = dataclasses.field(default_factory=lambda: [1, 2, 4])
    fabric_scale_runs: int = 2
    fabric_scale_duration_seconds: int = 15
    html_report_enabled: bool = True
    junit_report_enabled: bool = True
    evidence_enabled: bool = True
    target_hosts: list[str] = dataclasses.field(default_factory=list)
    target_aggregates: list[str] = dataclasses.field(default_factory=list)
    target_host_pairs: list[tuple[str, str]] = dataclasses.field(default_factory=list)
    include_same_host: bool = False
    qualification_strategy: str = "auto"
    qualification_profile: str = "full"
    qualification_cycles: int = 1
    resume_run_id: str | None = None
    test_ids: list[str] = dataclasses.field(default_factory=list)
    include_derived_tests: bool = False
    repeat_count: int = 1
    repeat_index: int = 1
    repeat_root_id: str | None = None
    repeat_next_id: str | None = None
    repeat_exit_code: int = 0
    quiet_period_scale: float = 0.3
    operation_gap_scale: float = 0.3

    @property
    def host_qualification_enabled(self) -> bool:
        return bool(
            self.target_hosts or self.target_aggregates or self.target_host_pairs
        )

    @property
    def selective_run(self) -> bool:
        return bool(self.test_ids)

    @property
    def derived_tests_suppressed(self) -> bool:
        return self.selective_run and not self.include_derived_tests

    @property
    def effective_migration_storage(self) -> str:
        """Return the live-migration disk contract Flux will request.

        Neutron Flux intentionally creates only two supported boot layouts:

        * ``storage=host``: Nova-managed local root disk, requiring block live
          migration.
        * ``storage=volume``: Cinder volume-backed root, using shared migration.

        Flux does not create mixed root/ephemeral/swap layouts.  Therefore the
        default ``migration_storage=auto`` is deterministic from the suite's
        own boot contract rather than delegated to Nova.  Explicit values are
        accepted only when they match that boot contract.
        """
        configured = str(self.migration_storage or "auto").strip().lower()
        if configured in {"host", "shared"}:
            return configured
        if self.storage == "host":
            return "host"
        if self.storage == "volume":
            return "shared"
        return "auto"

    @property
    def migration_submission_budget(self) -> int:
        return (
            self.live_migration_attempts + (1 if self.cold_migration_fallback else 0)
            if self.migration_mode != "cold-only"
            else self.compute_migration_max_attempts
        )

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> Config:
        from .configuration.cli import config_from_args

        return config_from_args(cls, args)
