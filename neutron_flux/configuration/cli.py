"""The only public configuration entry point: explicit CLI values and defaults.

Saved execution snapshots are internal recovery records, not user input files.
No YAML/JSON configuration files or legacy configuration environment variables
are read here.
"""

from __future__ import annotations

import ipaddress
import pathlib
from typing import Any

from ..constants import DEFAULT_REPORT_DIRNAME
from ..errors import SuiteError
from ..utils import validate_run_id


def _csv(value: Any, flag: str) -> list[str]:
    if value is None:
        return []
    items = [part.strip() for part in str(value).split(",")]
    if not items or any(not part for part in items):
        raise SuiteError(f"{flag} requires non-empty comma-separated values")
    return list(dict.fromkeys(items))


def _integer(args, key, default, minimum=1, maximum=None):
    supplied = getattr(args, key, None)
    value = default if supplied is None else supplied
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise SuiteError(f"--{key.replace('_', '-')} must be an integer >= {minimum}")
    if maximum is not None and value > maximum:
        raise SuiteError(f"--{key.replace('_', '-')} must be <= {maximum}")
    return value


def config_from_args(cls, args):
    action = str(args.action)
    resume = getattr(args, "resume", None)
    if resume is not None:
        resume = validate_run_id(resume, key="--resume")
    launch = action in {"plan", "run"} and not resume
    image, flavor, storage = (
        getattr(args, key, None) for key in ("image", "flavor", "storage")
    )
    networks = _csv(getattr(args, "external_networks", None), "--external-networks")
    if launch:
        missing = [
            flag
            for flag, value in (
                ("--image", image),
                ("--flavor", flavor),
                ("--storage", storage),
                ("--external-networks", networks),
            )
            if not value
        ]
        if missing:
            raise SuiteError("Required: " + ", ".join(missing))
    volume_type = getattr(args, "volume_type", None)
    if volume_type is not None and storage != "volume":
        raise SuiteError("--volume-type requires --storage volume")
    raw_zones = getattr(args, "zones", None)
    zones_all = bool(raw_zones and str(raw_zones).strip().lower() == "all")
    zones = [] if zones_all else _csv(raw_zones, "--zones")
    if any(zone.lower() == "all" for zone in zones):
        raise SuiteError("--zones all cannot be mixed with zone names")
    hosts = _csv(getattr(args, "target_hosts", None), "--target-hosts")
    aggregates = _csv(getattr(args, "target_aggregates", None), "--target-aggregates")
    pairs = []
    seen = set()
    for text in _csv(getattr(args, "target_host_pairs", None), "--target-host-pairs"):
        parts = text.split(":")
        if len(parts) != 2 or not all(item.strip() for item in parts):
            raise SuiteError("--target-host-pairs entries must be HOST:HOST")
        pair = tuple(item.strip() for item in parts)
        if frozenset(pair) not in seen:
            seen.add(frozenset(pair))
            pairs.append(pair)
    targeted = bool(hosts or aggregates or pairs)
    if pairs and (hosts or aggregates):
        raise SuiteError(
            "--target-host-pairs cannot combine with host or aggregate lists"
        )
    if targeted and (zones or zones_all):
        raise SuiteError(
            "Host selection determines compute AZs; do not combine it with --zones"
        )
    migration = getattr(args, "migration_mode", None) or "live"
    if migration not in {"live", "cold"}:
        raise SuiteError("--migration-mode must be live or cold")
    attempts = _integer(args, "live_attempts", 5)
    if migration == "cold" and getattr(args, "live_attempts", None) is not None:
        raise SuiteError("--live-attempts applies only to live migration")
    aggregate_policy = getattr(args, "shared_aggregate", None) or "auto"
    if aggregate_policy not in {"auto", "required", "ignore"}:
        raise SuiteError("--shared-aggregate must be auto, required, or ignore")
    profile = getattr(args, "performance_profile", None) or "standard"
    if profile not in {"standard", "exhaustive"}:
        raise SuiteError("--performance-profile must be standard or exhaustive")
    levels = []
    for text in _csv(
        getattr(args, "concurrent_vm_pairs", None), "--concurrent-vm-pairs"
    ):
        try:
            count = int(text) if text.isdecimal() else 0
        except ValueError:
            count = 0
        if not 1 <= count <= 32:
            raise SuiteError(
                "--concurrent-vm-pairs counts must be integers between 1 and 32"
            )
        if count not in levels:
            levels.append(count)
    if not levels and any(
        getattr(args, key, None) is not None
        for key in ("concurrent_repeats", "concurrent_duration")
    ):
        raise SuiteError("Concurrent measurement tuning requires --concurrent-vm-pairs")
    repeat = _integer(args, "repeat", 1)
    concurrent_repeats = _integer(args, "concurrent_repeats", 2, maximum=10)
    duration = _integer(args, "concurrent_duration", 15, minimum=3, maximum=120)
    targets = {}
    for family, default in ((4, "1.1.1.1"), (6, "2606:4700:4700::1111")):
        value = getattr(args, f"ping_target_ipv{family}", None) or default
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise SuiteError(
                f"--ping-target-ipv{family} requires an IPv{family} address"
            ) from exc
        if (
            address.version != family
            or address.is_unspecified
            or address.is_multicast
            or address.is_loopback
            or address.is_link_local
            or str(address) == "255.255.255.255"
            or getattr(address, "scope_id", None) is not None
            or getattr(address, "ipv4_mapped", None) is not None
        ):
            raise SuiteError(
                f"--ping-target-ipv{family} requires a usable unicast IPv{family} address"
            )
        targets[family] = str(address)
    keep = bool(getattr(args, "keep_resources", False))
    directory = (
        pathlib.Path(
            getattr(args, "output_dir", None)
            or pathlib.Path.cwd() / DEFAULT_REPORT_DIRNAME
        )
        .expanduser()
        .absolute()
    )
    sources = {
        key: "CLI"
        for key, value in vars(args).items()
        if value not in (None, False, "", [])
    }
    sources["networks"] = sources.get("external_networks", "default")
    return cls(
        action=action,
        prefix="nflux",
        report_dir=directory,
        image=image,
        flavor=flavor,
        storage=storage,
        ssh_user=None,
        availability_zones=zones,
        availability_zones_all=zones_all,
        zone_mode="both" if zones_all or len(zones) > 1 else "per-zone",
        mgmt_cidr=None,
        no_routing_group_ipv4_cidr=None,
        no_routing_group_ipv6_cidr=None,
        include_no_routing_group_controls=True,
        ipv4_targets=[targets[4]],
        ipv6_targets=[targets[6]],
        ipv4_targets_configured=getattr(args, "ping_target_ipv4", None) is not None,
        ipv6_targets_configured=getattr(args, "ping_target_ipv6", None) is not None,
        tcp_port=18080,
        udp_port=18081,
        ssh_timeout=15,
        resource_timeout=600,
        convergence_timeout=180,
        convergence_interval=5,
        progress_interval=15,
        keep_resources=keep,
        auto_cleanup_on_failure=not keep,
        volume_size=20,
        volume_type=volume_type,
        max_active_endpoints=2,
        cleanup_timeouts={
            "server": 180,
            "volume": 180,
            "port": 90,
            "router": 90,
            "subnet": 90,
            "network": 90,
            "floating_ip": 60,
            "security_group": 60,
            "keypair": 30,
        },
        external_networks=networks,
        compute_host_connectivity_enabled=True,
        require_shared_compute_aggregate={
            "auto": None,
            "required": True,
            "ignore": False,
        }[aggregate_policy],
        migration_mode="cold-only" if migration == "cold" else "live-preferred",
        live_migration_attempts=attempts,
        cold_migration_fallback=migration == "live",
        live_migration_continuity=migration == "live",
        cleanup_orphans=action == "cleanup",
        cleanup_dry_run=bool(getattr(args, "dry_run", False)),
        cleanup_assume_yes=bool(getattr(args, "yes", False)),
        cleanup_include_active=action == "cleanup",
        performance_profile=profile,
        performance_repeats=3 if profile == "exhaustive" else 2,
        performance_tcp_streams=[1, 4, 8] if profile == "exhaustive" else [1, 4],
        performance_udp_rates_mbps=[10, 50] if profile == "exhaustive" else [10],
        performance_ping_count=50 if profile == "exhaustive" else 20,
        fabric_scale_enabled=bool(levels),
        fabric_scale_pairs=levels or [1, 2, 4],
        fabric_scale_runs=concurrent_repeats,
        fabric_scale_duration_seconds=duration,
        target_hosts=hosts,
        target_aggregates=aggregates,
        target_host_pairs=pairs,
        qualification_strategy="rolling",
        qualification_profile="full",
        qualification_cycles=1,
        repeat_count=repeat,
        resume_run_id=resume,
        input_sources=sources,
    )
