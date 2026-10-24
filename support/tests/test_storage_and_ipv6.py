from __future__ import annotations

import dataclasses
from collections import Counter
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from neutron_flux.cli import parser
from neutron_flux.config import Config
from neutron_flux.errors import UnsupportedTopologyError
from neutron_flux.log import Logger
from neutron_flux.planning import Planner
from neutron_flux.reporting_components.html import build_run_payload, render_html
from neutron_flux.resources import ResourceBuilder


def _args(storage: str, *extra: str):
    return parser().parse_args(
        [
            "run",
            "--image",
            "debian-13",
            "--flavor",
            "x1.nano",
            "--storage",
            storage,
            "--external-networks",
            "Public1,Public2,Public3",
            *extra,
        ]
    )


def test_host_boot_auto_requests_block_live_migration():
    config = Config.from_args(_args("host", "--migration-mode", "live"))
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config
    assert config.migration_storage == "auto"
    assert config.effective_migration_storage == "host"
    assert builder._live_migration_storage_args() == ["--block-migration"]


def test_volume_boot_auto_requests_shared_live_migration():
    config = Config.from_args(_args("volume", "--migration-mode", "live"))
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config
    assert config.migration_storage == "auto"
    assert config.effective_migration_storage == "shared"
    assert builder._live_migration_storage_args() == ["--shared-migration"]


def test_ipv6_only_selected_network_is_still_in_data_plane(
    config_factory, discovery_fixture, tmp_path
):
    config = config_factory(
        storage="host",
        external_networks=["Public1", "Public2", "Public3"],
    )
    plan = Planner(config, discovery_fixture, Logger(tmp_path / "plan.log")).build()
    public2 = next(group for group in plan.provider_groups if group.network_id == "n2")
    assert public2.families == [6]
    assert any(
        test.family == 6
        and public2.id in {test.source_group_id, test.destination_group_id}
        for test in plan.tests
    )


def test_controller_uses_ipv4_provider_while_ipv6_tests_remain_endpoint_based(
    config_factory, discovery_fixture
):
    plan = SimpleNamespace(
        provider_groups=Planner(
            config_factory(),
            discovery_fixture,
            SimpleNamespace(
                section=lambda *_: None,
                log=lambda *_: None,
            ),
        )._provider_groups([])
    )
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.plan = plan
    builder.discovery = discovery_fixture
    builder.controller_probe_mode = ""
    specs = builder._controller_probe_specs()
    assert len(specs) == 1
    assert specs[0]["families"] == [4]
    assert specs[0]["network_id"] == "n1"
    assert builder.controller_probe_mode == "provider-ipv4-control"


def test_report_explains_ipv4_control_and_ipv6_endpoint_data_path(
    config_factory, tmp_path
):
    config = config_factory(
        action="run",
        report_dir=tmp_path / "reports",
        storage="volume",
        migration_storage="auto",
    )
    reporter = SimpleNamespace(
        results=[],
        discovery=None,
        config=config,
        run_id="run-sample",
        action="run",
        started=datetime(2026, 7, 23, tzinfo=timezone.utc),
        run_tag="tag",
        name_prefix="flux-tag",
        setup_failed=False,
        interrupted=False,
        cleanup_summary={"complete": True},
        setup_failures=[],
        error=None,
        plan=None,
        resources=[],
        events=[],
        traceback=None,
    )
    payload = build_run_payload(
        reporter,
        finished=datetime(2026, 7, 23, 0, 1, tzinfo=timezone.utc),
        final_status="PASS",
        counts=Counter(),
    )
    assert payload["configuration"]["migration"]["effective_storage"] == "not used"
    assert payload["configuration"]["migration"]["transport"] == "not used"
    paths = payload["configuration"]["network_paths"]
    assert paths == {
        "runner_control_family": "IPv4",
        "ipv6_test_origin": "OpenStack endpoint VMs",
        "runner_ipv6_required": False,
    }
    rendered = render_html(payload)
    assert "Control / IPv6 data" in rendered
    assert "runner_control_family" in rendered
    assert "IPv6 tests originate from" in rendered


def test_pure_ipv6_selected_topology_is_rejected_without_ipv4_control(
    config_factory, discovery_fixture, tmp_path
):
    ipv6_only = dataclasses.replace(
        discovery_fixture,
        networks=[item for item in discovery_fixture.networks if item.id == "n2"],
        subnets=[item for item in discovery_fixture.subnets if item.network_id == "n2"],
        pools=[],
    )
    with pytest.raises(UnsupportedTopologyError, match="IPv4.*control path"):
        Planner(
            config_factory(external_networks=["Public2"]),
            ipv6_only,
            Logger(tmp_path / "ipv6-only-plan.log"),
        ).build()
