from __future__ import annotations

from ._shared import *  # noqa: F403, F405


def _complete_inventory(builder, hosts):
    builder._aggregate_inventory_state = "complete"
    builder._aggregate_inventory_count = len(
        {a for h in hosts.values() for a in h.aggregate_ids}
    )
    return hosts


def test_config_parses_cli_zone_list_and_all(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    listed = Config.from_args(
        required_args(zones="bc-van1, bc-van2,bc-van1", zone_mode="both")
    )
    assert listed.availability_zones == ["bc-van1", "bc-van2"]
    assert listed.availability_zones_all is False
    assert listed.zone_mode == "both"
    assert listed.input_sources["zones"] == "CLI"

    all_zones = Config.from_args(required_args(zones="all", zone_mode="cross-zone"))
    assert all_zones.availability_zones == []
    assert all_zones.availability_zones_all is True
    assert all_zones.zone_mode == "both"


def test_zone_preflight_requires_selected_networks_in_every_zone(
    tmp_path, config_factory, discovery_fixture, monkeypatch
):
    from neutron_flux.zones import ZonePreflight

    config = config_factory(
        availability_zones=["bc-van1", "bc-van2"],
        zone_mode="both",
        action="plan",
        external_networks=["Public1", "Public2", "Public3"],
    )
    for network in discovery_fixture.networks:
        network.raw.update(
            {
                "status": "ACTIVE",
                "admin_state_up": True,
                "availability_zones": ["bc-van1", "bc-van2"],
                "availability_zone_hints": ["bc-van1", "bc-van2"],
            }
        )
    plan = build_plan(config, discovery_fixture, tmp_path)
    reporter = Reporter(config, "zone-preflight-ok")
    monkeypatch.setattr(
        ResourceBuilder,
        "compute_host_inventory",
        lambda self, refresh=False: _complete_inventory(self, _zone_hosts()),
    )
    zone_plan = ZonePreflight(
        config,
        discovery_fixture,
        plan,
        mock.Mock(),
        reporter,
        _zone_launch_selection(),
    ).build()
    assert zone_plan.zones == ["bc-van1", "bc-van2"]
    assert zone_plan.mode == "both"
    assert zone_plan.capabilities["bc-van1"].migration_cohort_size == 2
    reporter.logger.close()


def test_zone_preflight_treats_network_az_metadata_as_advisory(
    tmp_path, config_factory, discovery_fixture, monkeypatch
):
    from neutron_flux.zones import ZonePreflight

    config = config_factory(
        availability_zones=["bc-van1", "bc-van2"],
        zone_mode="cross-zone",
        action="plan",
    )
    for network in discovery_fixture.networks:
        network.raw.update(
            {
                "status": "ACTIVE",
                "admin_state_up": True,
                "availability_zones": ["bc-van1"],
                "availability_zone_hints": ["bc-van1"],
            }
        )
    plan = build_plan(config, discovery_fixture, tmp_path)
    reporter = Reporter(config, "zone-preflight-missing")
    monkeypatch.setattr(
        ResourceBuilder,
        "compute_host_inventory",
        lambda self, refresh=False: _complete_inventory(self, _zone_hosts()),
    )
    zone_plan = ZonePreflight(
        config,
        discovery_fixture,
        plan,
        mock.Mock(),
        reporter,
        _zone_launch_selection(),
    ).build()
    assert zone_plan.capabilities["bc-van2"].network_availability["n1"] is None
    assert not any(
        "metadata does not list compute AZ" in warning for warning in zone_plan.warnings
    )
    reporter.logger.close()


def test_zone_preflight_allows_single_host_lane_with_partial_placement_coverage(
    tmp_path, config_factory, discovery_fixture, monkeypatch
):
    from neutron_flux.models import ComputeHostInfo
    from neutron_flux.zones import ZonePreflight

    config = config_factory(
        availability_zones=["bc-van1", "bc-van2"],
        zone_mode="per-zone",
        action="plan",
    )
    for network in discovery_fixture.networks:
        network.raw.update(
            {
                "status": "ACTIVE",
                "admin_state_up": True,
                "availability_zones": ["bc-van1", "bc-van2"],
            }
        )
    hosts = _zone_hosts()
    hosts["c4"] = ComputeHostInfo("c4", "bc-van2", False, True, {"agg2"}, {"a2"})
    plan = build_plan(config, discovery_fixture, tmp_path)
    reporter = Reporter(config, "zone-preflight-hosts")
    monkeypatch.setattr(
        ResourceBuilder,
        "compute_host_inventory",
        lambda self, refresh=False: _complete_inventory(self, hosts),
    )
    zone_plan = ZonePreflight(
        config,
        discovery_fixture,
        plan,
        mock.Mock(),
        reporter,
        _zone_launch_selection(),
    ).build()
    capability = zone_plan.capabilities["bc-van2"]
    assert capability.enabled_hosts == ["c3"]
    assert capability.migration_cohort_size == 1
    assert capability.different_host_coverage_available is False
    assert any(
        "intra-compute coverage will run" in item for item in capability.warnings
    )
    reporter.logger.close()


def test_generated_network_and_router_commands_include_selected_zone_hint(
    config_factory,
    discovery_fixture,
):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.discovery = discovery_fixture
    builder.discovery.network_extensions = [
        "network_availability_zone",
        "router_availability_zone",
    ]
    builder.discovery.neutron_availability_zones = {
        "network": {"bc-van2": True},
        "router": {"bc-van2": True},
    }
    builder.osc = mock.Mock()
    builder.selected_availability_zone = "bc-van2"
    assert builder._availability_zone_hint_args() == [
        "--availability-zone-hint",
        "bc-van2",
    ]


def test_explicit_zone_resource_validation_requires_actual_and_hint(
    config_factory, monkeypatch, discovery_fixture
):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(convergence_timeout=1, convergence_interval=1)
    builder.discovery = discovery_fixture
    builder.discovery.network_extensions = [
        "network_availability_zone",
        "router_availability_zone",
    ]
    builder.discovery.neutron_availability_zones = {
        "network": {"bc-van2": True},
        "router": {"bc-van2": True},
    }
    builder.selected_availability_zone = "bc-van2"
    builder.osc = mock.Mock()
    builder.osc.json.return_value = {
        "availability_zones": ["bc-van1"],
        "availability_zone_hints": ["bc-van2"],
    }
    ticks = iter([0.0, 0.0, 2.0])
    monkeypatch.setattr("neutron_flux.resources.time.monotonic", lambda: next(ticks))
    monkeypatch.setattr("neutron_flux.resources.time.sleep", lambda _seconds: None)

    with pytest.raises(SuiteError, match="outside requested Neutron AZ"):
        builder._validate_created_resource_zone(
            "network",
            "network-id",
            {
                "availability_zones": ["bc-van1"],
                "availability_zone_hints": ["bc-van2"],
            },
        )


def test_explicit_zone_resource_validation_accepts_requested_zone(
    config_factory, discovery_fixture
):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.discovery = discovery_fixture
    builder.discovery.network_extensions = [
        "network_availability_zone",
        "router_availability_zone",
    ]
    builder.discovery.neutron_availability_zones = {
        "network": {"bc-van2": True},
        "router": {"bc-van2": True},
    }
    builder.selected_availability_zone = "bc-van2"
    builder.osc = mock.Mock()

    builder._validate_created_resource_zone(
        "router",
        "router-id",
        {
            "availability_zones": ["bc-van2"],
            "availability_zone_hints": ["bc-van2"],
        },
    )

    builder.osc.json.assert_not_called()


def test_unique_safe_name_hashes_distinguishing_truncated_suffix():
    first = unique_safe_name("shared-prefix-" + "x" * 80 + "-bc-van1", 36)
    second = unique_safe_name("shared-prefix-" + "x" * 80 + "-bc-van2", 36)

    assert first != second
    assert len(first) == 36
    assert len(second) == 36


def test_scoped_results_pass_adaptive_executor_plan_consistency(
    tmp_path, config_factory
):
    from neutron_flux.reporting import ScopedReporter

    config = config_factory(action="run")
    parent = Reporter(config, "scoped-executor-consistency")
    scoped = ScopedReporter(parent, "az-bc-van1", availability_zone="bc-van1")
    spec = FluxTestSpec(
        id="TEST-ONE",
        category="same-subnet",
        operation="probe",
        family=4,
        expectation="reachable",
        expectation_reason="test",
        authoritative=True,
        dependencies=["group"],
    )
    scoped.result("TEST-ONE", "same-subnet", "PASS", "ok")
    executor = object.__new__(AdaptiveExecutor)
    executor.plan = Plan([], [], {}, [], tests=[spec])
    executor.reporter = scoped

    executor._validate_plan_consistency()
    parent.logger.close()


def test_zone_preflight_all_selects_every_usable_zone_in_parallel(
    tmp_path, config_factory, discovery_fixture, monkeypatch
):
    from neutron_flux.zones import ZonePreflight

    config = config_factory(
        availability_zones=[],
        availability_zones_all=True,
        zone_mode="both",
        action="plan",
    )
    for network in discovery_fixture.networks:
        network.raw.update(
            {
                "status": "ACTIVE",
                "admin_state_up": True,
                "availability_zones": ["bc-van1", "bc-van2"],
                "availability_zone_hints": ["bc-van1", "bc-van2"],
            }
        )
    plan = build_plan(config, discovery_fixture, tmp_path)
    reporter = Reporter(config, "zone-preflight-all")
    monkeypatch.setattr(
        ResourceBuilder,
        "compute_host_inventory",
        lambda self, refresh=False: _complete_inventory(self, _zone_hosts()),
    )

    zone_plan = ZonePreflight(
        config,
        discovery_fixture,
        plan,
        mock.Mock(),
        reporter,
        _zone_launch_selection(),
    ).build()

    assert zone_plan.zones == ["bc-van1", "bc-van2"]
    assert zone_plan.parallel_workers == 2
    reporter.logger.close()


def test_explicit_zone_resource_validation_defers_until_after_scheduling(
    config_factory, monkeypatch, discovery_fixture
):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(convergence_timeout=1, convergence_interval=1)
    builder.discovery = discovery_fixture
    builder.discovery.network_extensions = [
        "network_availability_zone",
        "router_availability_zone",
    ]
    builder.discovery.neutron_availability_zones = {
        "network": {"bc-van2": True},
        "router": {"bc-van2": True},
    }
    builder.selected_availability_zone = "bc-van2"
    builder.osc = mock.Mock()
    builder.osc.json.return_value = {
        "availability_zones": ["bc-van2"],
        "availability_zone_hints": ["bc-van2"],
    }
    ticks = iter([0.0, 0.0])
    monkeypatch.setattr("neutron_flux.resources.time.monotonic", lambda: next(ticks))
    monkeypatch.setattr("neutron_flux.resources.time.sleep", lambda _seconds: None)

    builder._validate_created_resource_zone(
        "network",
        "network-id",
        {"availability_zones": [], "availability_zone_hints": ["bc-van2"]},
    )

    builder.osc.json.assert_not_called()
    assert "network:network-id" in builder.pending_neutron_az_validation
    builder._refresh_neutron_placements()
    builder.osc.json.assert_called_once_with(
        "network", "show", "network-id", timeout=60
    )
    assert builder.pending_neutron_az_validation == {}


def test_quota_parser_accepts_hyphenated_security_group_rule_fields():
    from neutron_flux.discovery import Discoverer

    quotas = Discoverer._quota_info(
        {
            "secgroup-rules": {"limit": 100, "in_use": 57},
            "security-group": {"limit": 20, "in_use": 6},
        }
    )

    assert quotas["security_group_rules"].limit == 100
    assert quotas["security_group_rules"].used == 57
    assert quotas["security_group_rules"].available == 43
    assert quotas["security_groups"].limit == 20
    assert quotas["security_groups"].used == 6


def test_shared_aggregate_policy_does_not_merge_unaggregated_hosts(
    tmp_path, config_factory, discovery_fixture, monkeypatch
):
    from neutron_flux.models import ComputeHostInfo
    from neutron_flux.zones import ZonePreflight

    config = config_factory(
        availability_zones=["bc-van1"],
        zone_mode="per-zone",
        require_shared_compute_aggregate=True,
        action="plan",
    )
    for network in discovery_fixture.networks:
        network.raw.update(
            {
                "status": "ACTIVE",
                "admin_state_up": True,
                "availability_zones": ["bc-van1"],
            }
        )
    hosts = {
        "c1": ComputeHostInfo("c1", "bc-van1", True, True),
        "c2": ComputeHostInfo("c2", "bc-van1", True, True),
    }
    monkeypatch.setattr(
        ResourceBuilder,
        "compute_host_inventory",
        lambda self, refresh=False: _complete_inventory(self, hosts),
    )
    plan = build_plan(config, discovery_fixture, tmp_path)
    reporter = Reporter(config, "unaggregated-strict")
    zone_plan = ZonePreflight(
        config,
        discovery_fixture,
        plan,
        mock.Mock(),
        reporter,
        _zone_launch_selection(),
    ).build()

    capability = zone_plan.capabilities["bc-van1"]
    assert capability.migration_cohort_size == 1
    assert capability.different_host_coverage_available is False
    assert any("no shared aggregate cohort" in item for item in capability.warnings)
    reporter.logger.close()


def test_unaggregated_hosts_are_eligible_when_shared_aggregate_is_not_required(
    tmp_path, config_factory, discovery_fixture, monkeypatch
):
    from neutron_flux.models import ComputeHostInfo
    from neutron_flux.zones import ZonePreflight

    config = config_factory(
        availability_zones=["bc-van1"],
        zone_mode="per-zone",
        require_shared_compute_aggregate=False,
        action="plan",
    )
    for network in discovery_fixture.networks:
        network.raw.update(
            {
                "status": "ACTIVE",
                "admin_state_up": True,
                "availability_zones": ["bc-van1"],
            }
        )
    hosts = {
        "c1": ComputeHostInfo("c1", "bc-van1", True, True),
        "c2": ComputeHostInfo("c2", "bc-van1", True, True),
    }
    monkeypatch.setattr(
        ResourceBuilder,
        "compute_host_inventory",
        lambda self, refresh=False: _complete_inventory(self, hosts),
    )
    plan = build_plan(config, discovery_fixture, tmp_path)
    reporter = Reporter(config, "unaggregated-relaxed")
    zone_plan = ZonePreflight(
        config,
        discovery_fixture,
        plan,
        mock.Mock(),
        reporter,
        _zone_launch_selection(),
    ).build()

    capability = zone_plan.capabilities["bc-van1"]
    assert capability.migration_cohort_size == 2
    assert capability.different_host_coverage_available is True
    reporter.logger.close()


def test_volume_type_availability_zone_parser_accepts_mapping_and_text():
    from neutron_flux.resources import _volume_type_availability_zones

    expected = frozenset({"bc-van1", "bc-van2"})
    assert (
        _volume_type_availability_zones(
            {"properties": {"RESKEY:availability_zones": "bc-van1,bc-van2"}}
        )
        == expected
    )
    assert (
        _volume_type_availability_zones(
            {"properties": "RESKEY:availability_zones='bc-van1,bc-van2'"}
        )
        == expected
    )


def test_zone_preflight_defaults_storage_on_volume_type_az_mismatch(
    tmp_path, config_factory, discovery_fixture, monkeypatch
):
    from neutron_flux.zones import ZonePreflight

    config = config_factory(
        availability_zones=["bc-van1", "bc-van2"],
        zone_mode="per-zone",
        storage="volume",
        volume_type="ceph_shared",
        action="plan",
    )
    for network in discovery_fixture.networks:
        network.raw.update(
            {
                "status": "ACTIVE",
                "admin_state_up": True,
                "availability_zones": ["bc-van1", "bc-van2"],
            }
        )
    monkeypatch.setattr(
        ResourceBuilder,
        "compute_host_inventory",
        lambda self, refresh=False: _complete_inventory(self, _zone_hosts()),
    )
    monkeypatch.setattr(
        ResourceBuilder,
        "_volume_availability_zone_inventory",
        lambda self: {"bc-van1", "bc-van2"},
    )
    selection = dataclasses.replace(
        _zone_launch_selection(),
        volume_type_availability_zones=frozenset({"bc-van1"}),
    )
    plan = build_plan(config, discovery_fixture, tmp_path)
    reporter = Reporter(config, "volume-type-zone-mismatch")

    result = ZonePreflight(
        config,
        discovery_fixture,
        plan,
        mock.Mock(),
        reporter,
        selection,
    ).build()
    assert result.zones == ["bc-van1", "bc-van2"]
    assert any(
        "Compute AZ bc-van2: root volumes will use Cinder defaults" in warning
        for warning in result.warnings
    )
    reporter.logger.close()


def test_automatic_az_selection_prefers_volume_type_compatible_zones(config_factory):
    from neutron_flux.models import ComputeHostInfo

    inventory = {
        "az1-1": ComputeHostInfo("az1-1", "bc-van1", True, True, {"a"}, {"a"}),
        "az1-2": ComputeHostInfo("az1-2", "bc-van1", True, True, {"a"}, {"a"}),
        "az2-1": ComputeHostInfo("az2-1", "bc-van2", True, True, {"b"}, {"b"}),
    }
    config = config_factory(action="run", storage="volume", volume_type="ceph_shared")
    builder = _az_builder(config, inventory)
    builder.launch_selection = dataclasses.replace(
        _zone_launch_selection(),
        volume_type_availability_zones=frozenset({"bc-van2"}),
    )
    builder._volume_availability_zone_inventory = mock.Mock(
        return_value={"bc-van1", "bc-van2"}
    )

    builder._select_run_availability_zone()

    assert builder.selected_availability_zone == "bc-van2"


def test_fip_return_restores_after_detach_confirmation_is_uncertain():
    engine = object.__new__(FluxTestEngine)
    state = {
        "id": "fip-id",
        "address": "198.51.100.10",
        "port_id": "port-id",
        "fixed_ip": "10.0.0.10",
        "source": "runner",
        "target": endpoint(),
        "authoritative": True,
        "baseline": True,
        "detach_requested": True,
        "detach_confirmed": False,
        "detached": False,
    }
    engine.lifecycle = {"fip:group": state}
    engine.config = SimpleNamespace(failure_injection="")
    engine.builder = SimpleNamespace(
        osc=SimpleNamespace(run=mock.Mock(return_value=completed())),
        wait_floating_ip_association=mock.Mock(
            return_value={
                "matched": True,
                "attempts": 1,
                "port_id": state["port_id"],
                "fixed_ip_address": state["fixed_ip"],
                "floating_ip_address": state["address"],
            }
        ),
    )
    engine._wait_fip_state = mock.Mock(
        return_value=ProbeResult(
            outcome="reachable",
            success=True,
            elapsed_ms=1,
            attempts=1,
            destination_ip=state["address"],
            protocol="tcp",
        )
    )
    engine._record = mock.Mock()
    spec = FluxTestSpec(
        id="FIP-RETURN",
        category="floating-ip-lifecycle",
        operation="fip-return",
        family=4,
        expectation="reachable",
        expectation_reason="restore the floating IP",
        authoritative=True,
        dependencies=["group"],
        destination_group_id="group",
        protocol="tcp",
    )

    engine._run_fip_return(spec)

    engine.builder.osc.run.assert_called_once()
    assert state["detach_requested"] is False
    assert state["detached"] is False
    assert (
        engine._record.call_args.args[1].diagnostics["detach_confirmed_before_restore"]
        is False
    )


def test_created_router_is_journaled_before_zone_validation():
    builder = object.__new__(ResourceBuilder)
    builder.name_prefix = "nflux"
    builder.run_tag = "run-tag"
    builder.osc = mock.Mock()
    builder.osc.json.return_value = {"id": "router-id"}
    builder.tracker = mock.Mock()
    builder._availability_zone_hint_args = mock.Mock(return_value=[])
    builder._validate_created_resource_zone = mock.Mock(
        side_effect=SuiteError("wrong availability zone")
    )
    order = mock.Mock()
    order.attach_mock(builder.tracker.add, "track")
    order.attach_mock(builder._validate_created_resource_zone, "validate")
    group = PlannedGroup("g", "tenant-pool", "group", None, None, [], [4])

    with pytest.raises(SuiteError, match="wrong availability zone"):
        builder._create_scenario_router(group, generation=1, suffix="a")

    assert [item[0] for item in order.mock_calls[:2]] == ["track", "validate"]
    assert order.mock_calls[0].args[1] == "router-id"
