from __future__ import annotations

import argparse
import base64
import dataclasses
import io
import json
import os
import re
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.cleanup import CleanupManager
from neutron_flux.cli import _successful_for_cleanup, parser
from neutron_flux.config import Config
from neutron_flux.constants import (
    DISPLAY_VERSION,
    RELEASE_STAGE,
    RESULT_STATUSES,
    TOOL_NAME,
    VERSION,
)
from neutron_flux.diagnostics import DiagnosticCollector
from neutron_flux.discovery import Discoverer
from neutron_flux.engine import TestEngine as FluxTestEngine
from neutron_flux.errors import (
    CommandError,
    CommandTimeoutError,
    PlacementUnavailableError,
    RetryableMigrationError,
    SetupFailureError,
    SuiteError,
)
from neutron_flux.executor import AdaptiveExecutor
from neutron_flux.failure_injection import inject_failure
from neutron_flux.guest_network import GuestNetworkVerifier
from neutron_flux.log import Logger
from neutron_flux.models import (
    Endpoint,
    Plan,
    PlannedGroup,
    PoolInfo,
    ProbeResult,
    QuotaInfo,
    ResourceRecord,
    RunCheckpoint,
    RuntimeGroup,
    SegmentInfo,
    SubnetInfo,
)
from neutron_flux.models import (
    TestSpec as FluxTestSpec,
)
from neutron_flux.openstack import OpenStack
from neutron_flux.planning import Planner
from neutron_flux.policy import PolicyEvaluator, TopologyPolicy
from neutron_flux.probe_service import ProbeServiceManager
from neutron_flux.probes import (
    ProbeContext,
    ProbeRegistry,
    RunnerFIPProbe,
    TCPProbe,
    UDPProbe,
    classify_command_outcome,
)
from neutron_flux.reporting import Reporter, ResourceTracker
from neutron_flux.resources import ResourceBuilder, resolve_launch_selection
from neutron_flux.state import StateStore
from neutron_flux.utils import iso_utc, unique_safe_name


def build_plan(config, discovery, tmp_path):
    return Planner(config, discovery, Logger(tmp_path / "planner.log")).build()


def decoded_payloads(command: str) -> list[str]:
    payloads: list[str] = []
    for token in re.findall(r"[A-Za-z0-9+/=]{80,}", command):
        try:
            payloads.append(base64.b64decode(token).decode())
        except Exception:
            continue
    return payloads


def completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(["cmd"], returncode, stdout, stderr)


class FakeProbeProcess:
    def __init__(self, stdout: str, stderr: str = ""):
        self.stdout = io.StringIO(stdout)
        self.stderr = io.StringIO(stderr)
        self._running = True
        self.returncode = None

    def poll(self):
        return None if self._running else self.returncode

    def terminate(self):
        self._running = False
        self.returncode = -15

    def kill(self):
        self._running = False
        self.returncode = -9

    def wait(self, timeout=None):
        self._running = False
        if self.returncode is None:
            self.returncode = 0
        return self.returncode


def endpoint(label="source", side="A"):
    return Endpoint(
        label=label,
        server_id=f"server-{label}",
        server_name=f"server-{label}",
        management_port_id=f"mgmt-{label}",
        management_ip="10.254.0.10",
        test_port_id=f"test-{label}",
        test_mac="fa:16:3e:00:00:01",
        fixed_ips={"s4": "192.0.2.10", "s6": "fd00::10"},
        host="compute1",
        availability_zone="az1",
        volume_id=None,
        side=side,
    )


def required_args(action: str = "plan", **overrides):
    values = {
        "action": action,
        "config": None,
        "image": "debian-13",
        "flavor": "x1.nano",
        "storage": "host",
        "volume_size": None,
        "volume_type": None,
        "external_networks": "Public1,Public2,Public3",
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def _external_selection_rows():
    return [
        {"ID": "n1", "Name": "Public1"},
        {"ID": "n2", "Name": "Public2"},
        {"ID": "n3", "Name": "Public3"},
    ]


def _selection_discoverer(config, all_rows=None):
    osc = mock.Mock()
    osc.json.return_value = (
        list(all_rows) if all_rows is not None else list(_external_selection_rows())
    )
    logger = mock.Mock()
    return Discoverer(osc, logger, config), osc, logger


def make_reporter(config, run_id="run-1"):
    return Reporter(dataclasses.replace(config, action="run"), run_id)


def _placement_builder(config, inventory, *, aggregate_inventory=True):
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config
    builder._aggregate_inventory_available = aggregate_inventory
    builder.compute_host_inventory = lambda refresh=False: dict(inventory)
    return builder


def _placement_executor(config, source, destination, builder):
    group = PlannedGroup(
        "placement-group",
        "provider",
        "Placement group",
        "network-id",
        "network-name",
        ["subnet-id"],
        [4],
    )
    spec = FluxTestSpec(
        id="PLACEMENT-BASE-ICMP",
        category="provider-subnet",
        operation="probe",
        family=4,
        expectation="reachable",
        expectation_reason="same subnet",
        authoritative=True,
        dependencies=[group.id],
        display_name="Provider IPv4 ICMP",
        scenario="Provider subnet connectivity",
        source_side="A",
        destination_side="B",
        protocol="icmp",
    )
    plan = Plan([group], [], {}, [], tests=[spec])
    runtime = RuntimeGroup(
        plan=group,
        network_id="network-id",
        network_name="network-name",
        subnet_ids=["subnet-id"],
        router_id=None,
        endpoints=[source, destination],
        source_nat_enabled=None,
        fips={},
    )
    recorded = []
    reporter = SimpleNamespace(
        event=lambda *args, **kwargs: None,
        save_plan=lambda: None,
        result=lambda test_id, category, status, message, **kwargs: recorded.append(
            SimpleNamespace(
                test_id=test_id,
                category=category,
                status=status,
                message=message,
                **kwargs,
            )
        ),
    )
    executor = object.__new__(AdaptiveExecutor)
    executor.config = config
    executor.plan = plan
    executor.builder = builder
    executor.reporter = reporter
    executor.logger = SimpleNamespace(
        section=lambda message: None, log=lambda *args, **kwargs: None
    )
    executor.active = {group.id: runtime}
    executor._refresh_checkpoint = lambda: None
    executor._live_retry_backoff = lambda seconds: None
    return executor, spec, recorded


def _az_builder(config, inventory, *, aggregate_state="complete"):
    builder = object.__new__(ResourceBuilder)
    builder.config = config
    builder.logger = mock.Mock()
    builder.reporter = mock.Mock()
    builder.reporter.run_id = "run"
    builder.reporter.event = mock.Mock()
    builder._aggregate_inventory_state = aggregate_state
    builder._aggregate_inventory_available = aggregate_state == "complete"
    builder._aggregate_inventory_errors = []
    builder.compute_host_inventory = mock.Mock(return_value=inventory)
    builder.selected_availability_zone = None
    builder.selected_availability_zone_reason = ""
    return builder


def _zone_launch_selection():
    from neutron_flux.resources import LaunchSelection

    return LaunchSelection(
        image_id="image-id",
        image_name="debian-13",
        image_min_disk_gib=0,
        image_virtual_size_gib=2,
        image_required_disk_gib=2,
        flavor_id="flavor-id",
        flavor_name="x1.nano",
        flavor_vcpus=1,
        flavor_ram_mb=512,
        flavor_disk_gib=10,
        ssh_user="debian",
    )


def _zone_hosts():
    from neutron_flux.models import ComputeHostInfo

    return {
        "c1": ComputeHostInfo("c1", "bc-van1", True, True, {"agg1"}, {"a1"}),
        "c2": ComputeHostInfo("c2", "bc-van1", True, True, {"agg1"}, {"a1"}),
        "c3": ComputeHostInfo("c3", "bc-van2", True, True, {"agg2"}, {"a2"}),
        "c4": ComputeHostInfo("c4", "bc-van2", True, True, {"agg2"}, {"a2"}),
    }


# Export private helper names as well; split test modules intentionally share this legacy fixture surface.
__all__ = [name for name in globals() if not name.startswith("__")]
