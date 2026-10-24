from __future__ import annotations

from ._shared import *  # noqa: F403, F405


def test_aggregate_plan_preserves_full_suite_per_zone_and_adds_cross_zone(
    tmp_path, config_factory, discovery_fixture
):
    from neutron_flux.models import ZoneCapability, ZoneExecutionPlan
    from neutron_flux.multi_zone import aggregate_plan

    config = config_factory()
    base = build_plan(config, discovery_fixture, tmp_path)
    zone_plan = ZoneExecutionPlan(
        zones=["bc-van1", "bc-van2"],
        mode="both",
        capabilities={
            zone: ZoneCapability(zone, [f"{zone}-c1", f"{zone}-c2"], 2, None, {})
            for zone in ("bc-van1", "bc-van2")
        },
        explicit_selection=True,
        parallel_workers=2,
    )
    expanded = aggregate_plan(base, zone_plan)
    per_zone_ids = [item.id for item in expanded.tests if item.id.startswith("AZ-")]
    cross_ids = [
        item.id for item in expanded.tests if item.id.startswith("CROSS-ZONE-")
    ]
    assert len(per_zone_ids) == len(base.tests) * 2
    assert cross_ids
    assert any("@bc-van1" in item.id for item in expanded.groups)
    assert any("@bc-van2" in item.id for item in expanded.groups)
    assert len(expanded.tests) == len(set(item.id for item in expanded.tests))
    assert expanded.estimated["security_groups_created"] == 4
    assert expanded.estimated["security_group_rules_peak"] == (
        base.estimated["security_group_rules_peak"] + 2
    )
    assert expanded.estimated["test_results"] == len(expanded.tests)


def test_explicit_multi_zone_summary_reports_only_aggregate_estimates(
    tmp_path, config_factory, discovery_fixture
):
    from neutron_flux.log import Logger
    from neutron_flux.models import ZoneCapability, ZoneExecutionPlan
    from neutron_flux.multi_zone import aggregate_plan
    from neutron_flux.planning import Planner

    # Match the live three-AZ Public1/Public2/Public3 inventory: the selected
    # external subnets are not allocated from the self-service subnet pools.
    discovery = dataclasses.replace(  # noqa: F405
        discovery_fixture,
        subnets=[
            dataclasses.replace(  # noqa: F405
                subnet,
                subnetpool_id=None,
                address_scope_id=None,
            )
            if subnet.network_id in {"n1", "n2", "n3"}
            else subnet
            for subnet in discovery_fixture.subnets
        ],
    )
    zones = ["bc-van1", "bc-van2", "bc-van3"]
    config = config_factory(
        action="run",
        availability_zones=[],
        availability_zones_all=True,
        zone_mode="both",
        storage="volume",
        volume_size=20,
        volume_type="ultra",
        migration_mode="live-preferred",
        performance_enabled=True,
        fabric_scale_pairs=[1, 2, 4],
        fabric_scale_runs=2,
        fabric_scale_duration_seconds=15,
    )
    log_path = tmp_path / "aggregate-plan.log"
    logger = Logger(log_path)
    planner = Planner(config, discovery, logger)
    base = planner.build()
    zone_plan = ZoneExecutionPlan(
        zones=zones,
        mode="both",
        capabilities={
            zone: ZoneCapability(zone, [f"{zone}-c1", f"{zone}-c2"], 2, None, {})
            for zone in zones
        },
        explicit_selection=True,
        parallel_workers=3,
    )
    expanded = aggregate_plan(base, zone_plan)

    # Suite prints only this post-expansion summary for an explicit AZ scope.
    planner._print_summary(expanded)
    logger.close()

    text = log_path.read_text(encoding="utf-8")
    result_lines = [
        line for line in text.splitlines() if "Estimated test results:" in line
    ]
    assert len(result_lines) == 1
    egress_recovery = [
        spec for spec in base.tests if spec.id.endswith("-AFTER-SERVER-START")
    ]
    assert len(egress_recovery) == 2
    assert len(base.tests) == 208
    assert expanded.estimated["cross_zone_tests"] == 216
    expected_results = len(base.tests) * len(zones) + 216
    assert len([spec for spec in expanded.tests if spec.id.startswith("AZ-")]) == len(
        base.tests
    ) * len(zones)
    assert len(expanded.tests) == expected_results
    assert expanded.estimated["test_results"] == expected_results
    assert result_lines[0].endswith(str(expected_results))
    assert f"Estimated test results: {len(base.tests)}" not in text


def test_summary_groups_results_by_zone_and_cross_zone(tmp_path, config_factory):
    config = config_factory(action="run")
    reporter = Reporter(config, "zone-summary")
    reporter.result(
        "AZ-BC-VAN1-PASS",
        "same-subnet",
        "PASS",
        "ok",
        details={"availability_zone": "bc-van1"},
    )
    reporter.result(
        "CROSS-ZONE-1",
        "cross-zone-connectivity",
        "PASS",
        "ok",
        details={
            "source_availability_zone": "bc-van1",
            "destination_availability_zone": "bc-van2",
        },
    )
    summary = reporter._summary(
        "PASS", reporter.started, mock.Mock(get=lambda *args: 0)
    )
    assert "AVAILABILITY-ZONE RESULTS" in summary
    assert "CROSS-ZONE RESULTS" in summary
    assert "bc-van1" in summary and "bc-van2" in summary
    reporter.logger.close()


def test_scoped_reporter_merges_runtime_tests_into_parent_plan(
    tmp_path, config_factory
):
    from neutron_flux.reporting import ScopedReporter

    config = config_factory(action="run")
    parent = Reporter(config, "scoped-plan-merge")
    parent.plan = Plan([], [], {}, [], tests=[])
    scoped = ScopedReporter(parent, "az-bc-van1", availability_zone="bc-van1")
    runtime = FluxTestSpec(
        id="PLACEMENT-RUNTIME",
        category="compute-placement",
        operation="placement",
        family=None,
        expectation="reachable",
        expectation_reason="runtime placement",
        authoritative=True,
        dependencies=[],
    )
    scoped.plan = Plan([], [], {}, [], tests=[runtime])

    scoped.save_plan()

    assert [item.id for item in parent.plan.tests] == ["AZ-BC-VAN1-PLACEMENT-RUNTIME"]
    assert parent.plan_path.is_file()
    parent.logger.close()


def test_scoped_reporter_resource_prefixes_remain_unique_after_bounding(
    tmp_path, config_factory
):
    from neutron_flux.reporting import ScopedReporter

    config = config_factory(action="run")
    parent = Reporter(config, "nflux-20260721160905-a84a8d")
    scoped = [
        ScopedReporter(parent, f"az-{zone}", availability_zone=zone)
        for zone in ("bc-van1", "bc-van2", "bc-van3")
    ]

    prefixes = [item.name_prefix for item in scoped]
    keypairs = [f"{item.name_prefix}-key" for item in scoped]
    assert len(set(prefixes)) == 3
    assert len(set(keypairs)) == 3
    assert all(len(item) <= 36 for item in prefixes)
    assert all(len(item) <= 63 for item in keypairs)
    parent.logger.close()


def test_scoped_reporter_cleanup_exposes_shared_manifest_errors(
    tmp_path, config_factory
):
    from neutron_flux.reporting import ScopedReporter

    config = config_factory(action="run")
    parent = Reporter(config, "scoped-cleanup")
    scoped = ScopedReporter(parent, "az-bc-van1", availability_zone="bc-van1")
    scoped.manifest_errors.append("example parser warning")

    assert scoped.manifest_errors is parent.manifest_errors
    assert parent.manifest_errors == ["example parser warning"]
    parent.logger.close()


def test_scoped_reporter_cleanup_runs_without_manifest_attribute_error(
    tmp_path, config_factory
):
    from neutron_flux.reporting import ScopedReporter

    config = config_factory(action="run")
    parent = Reporter(config, "scoped-cleanup-run")
    scoped = ScopedReporter(parent, "az-bc-van1", availability_zone="bc-van1")
    osc = mock.Mock()
    tracker = ResourceTracker(scoped)
    manager = CleanupManager(osc, scoped, tracker, config)
    manager._delete_all_types = mock.Mock()
    manager._remove_local_keys = mock.Mock()
    manager._verify_placement_allocations = mock.Mock(return_value=[])
    manager._clear_recovery_artifacts = mock.Mock()

    assert manager.cleanup(adopt_discovered=False) is True
    assert scoped.cleanup_summary["complete"] is True
    parent.logger.close()


def test_scoped_reporter_exposes_lane_local_ids_for_executor_consistency(
    tmp_path, config_factory
):
    from neutron_flux.reporting import ScopedReporter

    config = config_factory(action="run")
    parent = Reporter(config, "scoped-result-ids")
    scoped = ScopedReporter(parent, "az-bc-van1", availability_zone="bc-van1")
    scoped.result("TEST-ONE", "same-subnet", "PASS", "ok")

    assert parent.results[0].test_id == "AZ-BC-VAN1-TEST-ONE"
    assert scoped.results[0].test_id == "TEST-ONE"
    assert scoped.get_result("TEST-ONE").test_id == "TEST-ONE"
    assert scoped.has_result("TEST-ONE") is True
    parent.logger.close()


def test_multi_zone_quota_uses_one_shared_security_group_bundle(
    config_factory, discovery_fixture
):
    from neutron_flux.models import QuotaInfo
    from neutron_flux.zones import ZonePreflight

    config = config_factory(storage="host")
    plan = Plan(
        [],
        [],
        {
            "peak_instances": 3,
            "peak_ports": 8,
            "peak_created_networks": 4,
            "peak_created_subnets": 4,
            "peak_created_routers": 2,
            "peak_floating_ips": 2,
            "security_groups_created": 4,
            "security_group_rules_peak": 24,
        },
        [],
    )
    discovery_fixture.quota_info = {
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
            "key_pairs",
        )
    }
    # Four groups and 24 rules are enough for any number of AZ lanes because
    # Neutron SGs are project-wide and shared by the run.
    discovery_fixture.quota_info["security_groups"] = QuotaInfo("security_groups", 4, 0)
    discovery_fixture.quota_info["security_group_rules"] = QuotaInfo(
        "security_group_rules", 27, 0
    )
    preflight = object.__new__(ZonePreflight)
    preflight.config = config
    preflight.discovery = discovery_fixture
    preflight.plan = plan
    preflight.launch_selection = _zone_launch_selection()

    preflight._validate_parallel_quota(3)

    discovery_fixture.quota_info["security_group_rules"] = QuotaInfo(
        "security_group_rules", 26, 0
    )
    with pytest.raises(SuiteError, match="security_group_rules.*need parallel peak 27"):
        preflight._validate_parallel_quota(3)


def test_shared_security_group_lanes_use_distinct_control_ports(
    tmp_path, config_factory, discovery_fixture
):
    from neutron_flux.resources import SecurityGroupBundle

    config = config_factory(report_dir=tmp_path)
    plan = Plan([], [], {}, [])
    bundle = SecurityGroupBundle(
        controller_security_group_id="controller",
        endpoint_management_security_group_id="management",
        data_security_group_ids={"A": "data-a", "B": "data-b"},
        management_cidr="10.254.1.0/24",
        security_group_rules={
            "controller": [],
            "management": [],
            "data-a": [],
            "data-b": [],
        },
    )
    ports = []
    reporters = []
    for index, seed in enumerate((18082, 18086, 18090), start=1):
        reporter = Reporter(config, f"shared-sg-lane-{index}")
        reporters.append(reporter)
        builder = ResourceBuilder(
            config,
            discovery_fixture,
            plan,
            mock.Mock(),
            reporter,
            ResourceTracker(reporter),
        )
        builder.management_cidr = bundle.management_cidr
        builder.security_control_port_seed = seed
        builder.list_security_group_rules = mock.Mock(return_value=[])

        builder._adopt_shared_security_groups(bundle)
        ports.append(builder.security_control_ports[4])
        assert builder.test_sg_ids == {"A": "data-a", "B": "data-b"}

    assert ports == [18082, 18086, 18090]
    assert len(set(ports)) == 3
    for reporter in reporters:
        reporter.logger.close()


def test_multi_zone_orchestrator_assigns_one_bundle_to_every_lane(
    tmp_path, config_factory, discovery_fixture, monkeypatch
):
    import shutil

    from neutron_flux.models import ZoneCapability, ZoneExecutionPlan
    from neutron_flux.multi_zone import MultiZoneOrchestrator
    from neutron_flux.resources import SecurityGroupBundle

    config = config_factory(
        action="run",
        report_dir=tmp_path,
        availability_zones=["bc-van1", "bc-van2", "bc-van3"],
        zone_mode="both",
    )
    base_plan = Plan([], [], {}, [])
    zone_plan = ZoneExecutionPlan(
        zones=["bc-van1", "bc-van2", "bc-van3"],
        mode="both",
        capabilities={
            zone: ZoneCapability(zone, [f"{zone}-c1", f"{zone}-c2"], 2, None, {})
            for zone in ("bc-van1", "bc-van2", "bc-van3")
        },
        explicit_selection=True,
        parallel_workers=3,
    )
    bundle = SecurityGroupBundle(
        controller_security_group_id="controller",
        endpoint_management_security_group_id="management",
        data_security_group_ids={"A": "data-a", "B": "data-b"},
        management_cidr="10.254.1.0/24",
        security_group_rules={},
    )
    reporter = Reporter(config, "shared-sg-orchestrator")
    orchestrator = MultiZoneOrchestrator(
        config,
        discovery_fixture,
        base_plan,
        zone_plan,
        reporter,
        _zone_launch_selection(),
    )
    monkeypatch.setattr(orchestrator, "_prepare_shared_security_groups", lambda: bundle)
    monkeypatch.setattr(MultiZoneOrchestrator, "_prepare_lane", lambda self, lane: None)

    orchestrator.prepare()

    assert set(orchestrator.lanes) == {"bc-van1", "bc-van2", "bc-van3"}
    assert all(
        lane.builder.shared_security_group_bundle is bundle
        for lane in orchestrator.lanes.values()
    )
    assert {
        lane.builder.security_control_port_seed for lane in orchestrator.lanes.values()
    } == {18082, 18338, 18594}
    assert all(
        lane.config.mgmt_cidr == "10.254.1.0/24" for lane in orchestrator.lanes.values()
    )
    captured_locks = []

    class FakeAdaptiveExecutor:
        def __init__(self, *args):
            captured_locks.append(args[-1])

        def run(self):
            return None

    monkeypatch.setattr(
        "neutron_flux.multi_zone.AdaptiveExecutor", FakeAdaptiveExecutor
    )
    for lane in orchestrator.lanes.values():
        orchestrator._run_lane(lane)
    assert captured_locks == [orchestrator.performance_lock] * 3

    import typing

    from neutron_flux.executor import AdaptiveExecutor
    from neutron_flux.multi_zone import CrossZoneExecutor

    assert "performance_lock" in typing.get_type_hints(AdaptiveExecutor.__init__)
    assert "performance_lock" in typing.get_type_hints(CrossZoneExecutor.__init__)

    for lane in orchestrator.lanes.values():
        shutil.rmtree(lane.builder.work_dir, ignore_errors=True)
    reporter.logger.close()


def test_cross_zone_cleanup_runs_when_batch_build_raises(monkeypatch):
    import neutron_flux.multi_zone as multi_zone
    from neutron_flux.multi_zone import CrossZoneExecutor

    group = PlannedGroup("g", "provider", "group", "n", "n", ["s"], [4])
    executor = object.__new__(CrossZoneExecutor)
    executor.base_plan = Plan([group], [], {}, [])
    executor.logger = mock.Mock()
    executor.lanes = {"bc-van1": object()}
    executor.workers = 1
    executor._build_batch = mock.Mock(side_effect=RuntimeError("build failed"))
    executor._cleanup_batch = mock.Mock()
    executor._record_unavailable_batch = mock.Mock()
    monkeypatch.setattr(
        multi_zone,
        "_cross_zone_base_batches",
        lambda _plan: {("g",): []},
    )

    with pytest.raises(RuntimeError, match="build failed"):
        executor.run()

    executor._cleanup_batch.assert_called_once_with(("g",))


def test_cross_zone_build_errors_are_collected_before_raising_setup_failure():
    from collections import defaultdict

    from neutron_flux.multi_zone import CrossZoneExecutor

    group = PlannedGroup("g@bc-van1", "provider", "group", "n", "n", ["s"], [4])
    lane = SimpleNamespace(
        plan=SimpleNamespace(group=lambda _group_id: group),
        builder=SimpleNamespace(
            build_group=mock.Mock(side_effect=SuiteError("endpoint setup failed")),
            runtime_groups=[],
        ),
    )
    executor = object.__new__(CrossZoneExecutor)
    executor.lanes = {"bc-van1": lane}
    executor.workers = 1
    executor.generations = defaultdict(int)
    executor.logger = mock.Mock()

    with pytest.raises(SetupFailureError, match="endpoint setup failed"):
        executor._build_batch(("g",))
    assert "endpoint setup failed" in executor.logger.log.call_args.args[0]


def test_cross_zone_performance_control_uses_endpoint_owning_lane():
    from neutron_flux.multi_zone import _CrossZonePerformanceControl

    first = mock.Mock()
    second = mock.Mock()
    first.ssh_endpoint.return_value = "first"
    second.ssh_endpoint.return_value = "second"
    control = _CrossZonePerformanceControl({"server-a": first, "server-b": second})
    endpoint_a = SimpleNamespace(server_id="server-a", label="A")
    endpoint_b = SimpleNamespace(server_id="server-b", label="B")

    assert control.ssh_endpoint(endpoint_a, "command", timeout=12) == "first"
    assert control.ssh_endpoint(endpoint_b, "command", timeout=34) == "second"
    first.ssh_endpoint.assert_called_once_with(endpoint_a, "command", timeout=12)
    second.ssh_endpoint.assert_called_once_with(endpoint_b, "command", timeout=34)


def test_cross_zone_executor_records_dynamic_performance_specs(
    tmp_path, config_factory, monkeypatch
):
    import threading

    import neutron_flux.multi_zone as multi_zone
    from neutron_flux.multi_zone import CrossZoneExecutor
    from neutron_flux.performance import PerformanceSession
    from neutron_flux.reporting import ScopedReporter

    config = config_factory(action="run", report_dir=tmp_path / "reports")
    parent = Reporter(config, "cross-zone-performance")
    parent.plan = Plan([], [], {}, [], tests=[])
    scoped = ScopedReporter(parent, "cross-zone", availability_zone=None)
    scoped.plan = Plan([], [], {}, [], tests=[])

    endpoint_a = endpoint("source", "A")
    endpoint_b = dataclasses.replace(
        endpoint("destination", "A"), server_id="server-destination"
    )
    group_a = PlannedGroup("ga", "provider", "A", "na", "na", ["sa"], [4])
    group_b = PlannedGroup("gb", "provider", "B", "nb", "nb", ["sb"], [4])
    runtime_a = RuntimeGroup(group_a, "na", "na", ["sa"], None, [endpoint_a], None, {})
    runtime_b = RuntimeGroup(group_b, "nb", "nb", ["sb"], None, [endpoint_b], None, {})
    builder_a = SimpleNamespace(ssh_endpoint=mock.Mock(return_value="a"))
    builder_b = SimpleNamespace(ssh_endpoint=mock.Mock(return_value="b"))
    lanes = {
        "az-a": SimpleNamespace(builder=builder_a),
        "az-b": SimpleNamespace(builder=builder_b),
    }
    source_lane = SimpleNamespace(config=config)
    source_spec = FluxTestSpec(
        id="CROSS-ZONE-BASE",
        category="cross-zone-connectivity",
        operation="probe",
        family=4,
        expectation="reachable",
        expectation_reason="passed",
        authoritative=True,
        dependencies=["ga", "gb"],
        source_group_id="ga",
        destination_group_id="gb",
        source_side="A",
        destination_side="A",
        protocol="tcp",
        phase="cross-zone",
    )
    dynamic = FluxTestSpec(
        id="PERF-CROSS-ZONE-TCP",
        category="network-performance",
        operation="performance-tcp-throughput",
        family=4,
        expectation="measurement-complete",
        expectation_reason="eligible",
        authoritative=True,
        dependencies=["ga", "gb"],
    )
    captured = {}

    class FakePerformanceRunner:
        def __init__(self, config, builder, reporter, engine, *, session):
            captured["builder"] = builder
            captured["session"] = session

        def plan_specs(self, specs, *, stage):
            captured["source_specs"] = list(specs)
            captured["stage"] = stage
            return [dynamic]

        def run_specs(self, specs):
            captured["run_specs"] = list(specs)
            captured["builder"].ssh_endpoint(endpoint_b, "probe", timeout=5)

    monkeypatch.setattr(multi_zone, "PerformanceRunner", FakePerformanceRunner)
    executor = object.__new__(CrossZoneExecutor)
    executor.config = config
    executor.reporter = scoped
    executor.lanes = lanes
    executor.performance_session = PerformanceSession()
    executor.performance_lock = threading.RLock()

    executor._run_performance(
        source_lane,
        SimpleNamespace(),
        [source_spec],
        {"az-a": {"ga": runtime_a}, "az-b": {"gb": runtime_b}},
    )

    assert captured["stage"] == "cross-zone"
    assert captured["source_specs"] == [source_spec]
    assert captured["run_specs"] == [dynamic]
    builder_b.ssh_endpoint.assert_called_once_with(endpoint_b, "probe", timeout=5)
    assert any(
        item.id == "CROSS-ZONE-PERF-CROSS-ZONE-TCP" for item in parent.plan.tests
    )
    parent.logger.close()
