from __future__ import annotations

import pathlib
from typing import Any

import pytest

from neutron_flux.config import Config
from neutron_flux.models import (
    Discovery,
    NetworkInfo,
    PoolInfo,
    QuotaInfo,
    SegmentInfo,
    SubnetInfo,
)


@pytest.fixture
def config_factory(tmp_path: pathlib.Path):
    def make(**overrides: Any) -> Config:
        values: dict[str, Any] = {
            "action": "plan",
            "migration_mode": "cold-only",
            "cold_migration_fallback": False,
            "live_migration_continuity": False,
            "live_migration_attempts": 2,
            "quiet_period_scale": 1.0,
            "operation_gap_scale": 1.0,
            "prefix": "fixture",
            "report_dir": tmp_path / "reports",
            "image": "debian-13",
            "flavor": "x1.nano",
            "storage": "host",
            "ssh_user": None,
            "availability_zones": [],
            "availability_zones_all": False,
            "zone_mode": "per-zone",
            "mgmt_cidr": None,
            "no_routing_group_ipv4_cidr": None,
            "no_routing_group_ipv6_cidr": None,
            "include_no_routing_group_controls": True,
            "ipv4_targets": ["1.1.1.1", "8.8.8.8"],
            "ipv6_targets": [],
            "ipv4_targets_configured": False,
            "ipv6_targets_configured": False,
            "tcp_port": 18080,
            "udp_port": 18081,
            "ssh_timeout": 15,
            "resource_timeout": 600,
            "convergence_timeout": 30,
            "convergence_interval": 1,
            "progress_interval": 5,
            "keep_resources": False,
            "auto_cleanup_on_failure": True,
            "volume_size": 20,
            "volume_type": None,
            "max_active_endpoints": 2,
            "external_networks": ["Public1", "Public2", "Public3"],
            "exclude_external_networks": [],
            "cleanup_timeouts": {
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
            "failure_injection": None,
            "input_sources": {
                "image": "test fixture",
                "flavor": "test fixture",
                "storage": "test fixture",
                "networks": "test fixture",
            },
        }
        if "prefer_ephemeral_boot" in overrides:
            prefer_ephemeral = bool(overrides.pop("prefer_ephemeral_boot"))
            overrides.setdefault("storage", "host" if prefer_ephemeral else "volume")
        migration_mode = overrides.get("migration_mode")
        if migration_mode == "live-preferred":
            overrides.setdefault("cold_migration_fallback", True)
            overrides.setdefault("live_migration_continuity", True)
        elif migration_mode == "live-only":
            overrides.setdefault("cold_migration_fallback", False)
            overrides.setdefault("live_migration_continuity", True)
        elif migration_mode == "cold-only":
            overrides.setdefault("cold_migration_fallback", False)
            overrides.setdefault("live_migration_continuity", False)
        values.update(overrides)
        return Config(**values)

    return make


def _subnet(
    subnet_id: str,
    name: str,
    network_id: str,
    cidr: str,
    gateway: str,
    pool_id: str | None,
    scope_id: str | None,
    *,
    segment_id: str | None = None,
    ipv6_address_mode: str | None = None,
    ipv6_ra_mode: str | None = None,
) -> SubnetInfo:
    family = 6 if ":" in cidr else 4
    return SubnetInfo(
        id=subnet_id,
        name=name,
        network_id=network_id,
        cidr=cidr,
        ip_version=family,
        gateway_ip=gateway,
        dhcp_enabled=False,
        allocation_pools=[{"start": "allocated", "end": "allocated"}],
        subnetpool_id=pool_id,
        ipv6_address_mode=ipv6_address_mode,
        ipv6_ra_mode=ipv6_ra_mode,
        dns_nameservers=[],
        address_class="ula" if family == 6 else "private",
        raw={},
        segment_id=segment_id,
        address_scope_id=scope_id,
    )


@pytest.fixture
def discovery_fixture() -> Discovery:
    networks = [
        NetworkInfo(
            "n1", "Public1", True, True, "flat", "provider1", None, 1500, True, {}
        ),
        NetworkInfo(
            "n2", "Public2", True, True, "flat", "provider2", None, 1500, True, {}
        ),
        NetworkInfo(
            "n3", "Public3", True, True, "flat", "provider3", None, 1500, True, {}
        ),
    ]
    subnets = [
        _subnet(
            "s1v4", "public1-ipv4", "n1", "172.20.0.0/22", "172.20.0.1", "pp4", "scope4"
        ),
        _subnet(
            "s1v6",
            "public1-ipv6",
            "n1",
            "fdbf:9ed6:2194:b040::/64",
            "fdbf:9ed6:2194:b040::1",
            "pp6",
            "scope6",
        ),
        _subnet(
            "s2v6",
            "public2-ipv6",
            "n2",
            "fd78:d2c4:9e0b:41dc::/64",
            "fd78:d2c4:9e0b:41dc::1",
            None,
            None,
        ),
        _subnet(
            "s3v4", "public3-ipv4", "n3", "172.20.4.0/22", "172.20.4.1", None, None
        ),
    ]
    pools = [
        PoolInfo(
            "pp4",
            "ProviderIPv4",
            4,
            "scope4",
            ["172.20.0.0/22"],
            22,
            22,
            22,
            True,
            None,
            True,
            {},
        ),
        PoolInfo(
            "pp6",
            "ProviderIPv6",
            6,
            "scope6",
            ["fdbf:9ed6:2194:b040::/64"],
            64,
            64,
            64,
            True,
            None,
            True,
            {},
        ),
        PoolInfo(
            "tp4",
            "SelfServeIPv4",
            4,
            "scope4",
            ["172.20.8.0/21"],
            24,
            24,
            28,
            True,
            None,
            False,
            {},
        ),
        PoolInfo(
            "tp6",
            "SelfServeIPv6",
            6,
            "scope6",
            ["fd00:1234::/48"],
            64,
            64,
            64,
            True,
            None,
            False,
            {},
        ),
    ]
    return Discovery(
        project_id="project-id",
        project_name="admin",
        cloud=None,
        networks=networks,
        subnets=subnets,
        pools=pools,
        address_scopes=[],
        quotas={},
        segments=[],
        quota_info={},
        occupied_cidrs=[item.cidr for item in subnets],
    )


@pytest.fixture
def routed_discovery() -> Discovery:
    network = NetworkInfo(
        "routed",
        "RoutedPublic",
        True,
        True,
        "vlan",
        None,
        None,
        1500,
        True,
        {},
        segment_ids=["seg-a", "seg-b"],
    )
    segments = [
        SegmentInfo("seg-a", "routed", "vlan", "phys-a", 101, "rack-a", {}),
        SegmentInfo("seg-b", "routed", "vlan", "phys-b", 102, "rack-b", {}),
    ]
    subnets = [
        _subnet(
            "ra",
            "rack-a-v4",
            "routed",
            "198.51.100.0/25",
            "198.51.100.1",
            None,
            None,
            segment_id="seg-a",
        ),
        _subnet(
            "rb",
            "rack-b-v4",
            "routed",
            "198.51.100.128/25",
            "198.51.100.129",
            None,
            None,
            segment_id="seg-b",
        ),
    ]
    return Discovery(
        "project-id",
        "admin",
        None,
        [network],
        subnets,
        [],
        [],
        {},
        segments=segments,
        quota_info={},
        occupied_cidrs=[item.cidr for item in subnets],
    )


@pytest.fixture
def abundant_quotas():
    return {
        name: QuotaInfo(name, 10000, 0)
        for name in (
            "instances",
            "cores",
            "ram",
            "ports",
            "networks",
            "subnets",
            "routers",
            "floating_ips",
            "security_groups",
            "security_group_rules",
            "volumes",
        )
    }
