from __future__ import annotations

from neutron_flux.gateway_policy import assert_router_gateway_defaults

from ._shared import *  # noqa: F403, F405


def test_management_network_has_no_gateway(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(mgmt_cidr="10.48.0.0/24")
    builder.discovery = SimpleNamespace(
        subnets=[],
        pools=[],
        occupied_cidrs=[],
        network_extensions=[],
        neutron_availability_zones=None,
    )
    builder.name_prefix = "run"
    builder.run_tag = "tag"
    builder.management_cidr = ""
    builder.tracker = mock.Mock()
    calls = []
    builder.osc = SimpleNamespace(
        json=lambda *args, **kwargs: (
            calls.append(args)
            or ({"id": "net"} if args[0] == "network" else {"id": "subnet"})
        )
    )
    builder._create_management_network()
    subnet_call = next(args for args in calls if args[0] == "subnet")
    assert "--gateway" in subnet_call
    assert subnet_call[subnet_call.index("--gateway") + 1] == "none"


def test_security_groups_use_probe_ports_not_ssh_for_data(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.name_prefix = "run"
    builder.management_cidr = "10.48.0.0/24"
    builder.reporter = mock.Mock()
    builder.logger = mock.Mock()
    builder.probe_service = mock.Mock()
    builder.security_control_ports = {4: 18082, 6: 18082}
    builder.security_control_authoritative = {4: False, 6: False}
    builder.security_control_matching_rules = {4: [], 6: []}
    builder._create_security_group = mock.Mock(
        side_effect=["controller", "mgmt", "data-a", "data-b"]
    )
    calls = []

    def json_call(*args, **kwargs):
        calls.append(args)
        if args[:5] == ("security", "group", "rule", "list", "controller"):
            return []
        if args[:5] == ("security", "group", "rule", "list", "mgmt"):
            return []
        if args[:5] in {
            ("security", "group", "rule", "list", "data-a"),
            ("security", "group", "rule", "list", "data-b"),
        }:
            return []
        if args[:4] == ("security", "group", "rule", "create"):
            return {"id": f"rule-{len(calls)}"}
        return []

    builder.osc = SimpleNamespace(
        json=json_call,
        run=lambda *args, **kwargs: calls.append(args) or completed(),
    )
    builder._create_security_groups()
    data_calls = [
        args
        for args in calls
        if args[:4] == ("security", "group", "rule", "create")
        and args[-1] in {"data-a", "data-b"}
    ]
    rendered = " ".join(" ".join(map(str, args)) for args in data_calls)
    assert "18080" in rendered and "18081" in rendered
    assert "--dst-port 22" not in rendered
    assert "--egress" in rendered


def test_router_source_nat_cloud_operation_api_is_removed():
    assert not hasattr(ResourceBuilder, "set_router_source_nat")
    assert not hasattr(ResourceBuilder, "restore_router_state")


@pytest.mark.parametrize("flag", ["--enable-snat", "--disable-snat", "--fixed-ip"])
def test_admin_only_router_gateway_fields_are_globally_rejected(flag):
    with pytest.raises(SuiteError, match="project-member-visible defaults"):
        assert_router_gateway_defaults(("router", "set", flag, "value", "router-id"))


def test_member_router_gateway_omits_admin_only_fields_and_observes_default(
    config_factory,
):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.osc = mock.Mock()
    builder.osc.run.return_value = completed()
    builder.wait_router_source_nat = mock.Mock(
        return_value={
            "matched": True,
            "state": {
                "external_gateway_info": {
                    "network_id": "external-network",
                    "enable_snat": True,
                    "external_fixed_ips": [
                        {"subnet_id": "external-subnet", "ip_address": "172.20.4.20"}
                    ],
                }
            },
            "differences": [],
        }
    )
    builder._record_router_addresses = mock.Mock()
    builder.logger = mock.Mock()

    snapshot = builder.configure_router_external_gateway_default(
        "router-id",
        "router-name",
        external_network_id="external-network",
        external_subnet_id="external-subnet",
        ip_version=4,
    )

    assert builder.osc.run.call_args.args == (
        "router",
        "set",
        "--external-gateway",
        "external-network",
        "router-id",
    )
    rendered = builder.osc.run.call_args.args
    assert "--fixed-ip" not in rendered
    assert "--enable-snat" not in rendered
    assert "--disable-snat" not in rendered
    assert snapshot["external_gateway_info"]["enable_snat"] is True


def test_member_router_gateway_refuses_disabled_neutron_default(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.osc = mock.Mock()
    builder.osc.run.return_value = completed()
    builder.wait_router_source_nat = mock.Mock(
        return_value={
            "matched": False,
            "state": {
                "external_gateway_info": {
                    "network_id": "external-network",
                    "enable_snat": False,
                }
            },
            "differences": ["enable_snat did not become True"],
        }
    )

    with pytest.raises(SuiteError, match="did not override"):
        builder.configure_router_external_gateway_default(
            "router-id",
            "router-name",
            external_network_id="external-network",
            external_subnet_id="external-subnet",
            ip_version=4,
        )
    assert "--enable-snat" not in builder.osc.run.call_args.args


def test_router_gateway_parser_does_not_treat_false_text_as_true():
    builder = object.__new__(ResourceBuilder)
    assert builder._gateway_info({"enable_snat": "False"})["enable_snat"] is False
    assert builder._gateway_info({"enable_snat": "true"})["enable_snat"] is True


def test_server_create_is_ephemeral_and_az_unconstrained_by_default(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.server_sequence = 0
    builder.flavor_id = "f1"
    builder.keypair_name = "key"
    builder.image_id = "img"
    builder.image_name = "debian-13"
    builder.tracker = mock.Mock()
    builder.logger = mock.Mock()
    builder.reporter = mock.Mock()
    builder._wait_for_status = mock.Mock()
    builder.osc = mock.Mock()
    builder.osc.run.return_value = completed(stdout=json.dumps({"id": "server"}))
    builder.osc.json.return_value = {"id": "server", "status": "ACTIVE"}
    builder._create_server("vm", ["p1"], role="endpoint")
    builder._wait_for_server_settlement = mock.Mock(
        return_value=builder.osc.json.return_value
    )
    args = builder.osc.run.call_args.args
    assert "--image" in args
    assert "--availability-zone" not in args
    assert "--block-device" not in args
    assert "--user-data" not in args
    assert "--use-config-drive" not in args
    assert "--config-drive" not in args


def test_selected_availability_zone_is_used_for_every_server(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(availability_zones=["az1", "az3"])
    builder.selected_availability_zone = "az1"
    builder.server_sequence = 0
    builder.flavor_id = "f1"
    builder.keypair_name = "key"
    builder.image_id = "img"
    builder.image_name = "debian-13"
    builder.tracker = mock.Mock()
    builder.logger = mock.Mock()
    builder.reporter = mock.Mock()
    builder._wait_for_status = mock.Mock()
    builder.osc = mock.Mock()
    builder.osc.run.return_value = completed(stdout=json.dumps({"id": "server"}))
    builder.osc.json.return_value = {"id": "server", "status": "ACTIVE"}
    builder._create_server("vm1", ["p1"], role="endpoint")
    builder._wait_for_server_settlement = mock.Mock(
        return_value=builder.osc.json.return_value
    )
    first = builder.osc.run.call_args.args
    builder._create_server("vm2", ["p2"], role="endpoint")
    second = builder.osc.run.call_args.args
    assert first[first.index("--availability-zone") + 1] == "az1"
    assert second[second.index("--availability-zone") + 1] == "az1"


def test_cleanup_server_delete_uses_normal_delete_after_settlement(config_factory):
    manager = object.__new__(CleanupManager)
    manager.config = config_factory()
    manager.logger = mock.Mock()
    manager.osc = mock.Mock()
    manager.osc.run.return_value = completed()
    manager._wait_server_settled_before_delete = mock.Mock(
        return_value={"task_state": None, "status": "ACTIVE"}
    )
    manager._delete_server(
        ResourceRecord(1, "server", "server-id", "vm", None, {}, iso_utc())
    )
    assert manager.osc.run.call_args.args[:3] == ("server", "delete", "server-id")
    manager.osc.exists.assert_not_called()


def test_cleanup_record_state_machine_marks_already_absent(config_factory, tmp_path):
    reporter = make_reporter(config_factory(report_dir=tmp_path / "reports"))
    tracker = ResourceTracker(reporter)
    record = tracker.add("port", "p1", "port")
    osc = mock.Mock()
    osc.exists.return_value = False
    manager = CleanupManager(osc, reporter, tracker, reporter.config)
    manager._delete_record(record, mock.Mock())
    assert record.cleanup_state == "DELETED"
    assert record.delete_status == "already-absent"


def test_cleanup_timeout_marks_failed_and_continues(
    config_factory, tmp_path, monkeypatch
):
    reporter = make_reporter(config_factory(report_dir=tmp_path / "reports"))
    tracker = ResourceTracker(reporter)
    record = tracker.add("port", "p1", "port")
    osc = mock.Mock()
    osc.exists.return_value = True
    manager = CleanupManager(osc, reporter, tracker, reporter.config)
    monkeypatch.setattr(manager, "_wait_absent", lambda *a, **k: False)
    manager._delete_record(record, lambda _record: None)
    assert record.cleanup_state == "FAILED"
    assert record.delete_status == "leftover"


def test_recovery_artifacts_contain_only_openstack_commands(config_factory, tmp_path):
    reporter = make_reporter(config_factory(report_dir=tmp_path / "reports"))
    tracker = ResourceTracker(reporter)
    record = tracker.add("server", "s1", "vm")
    record.cleanup_state = "FAILED"
    manager = CleanupManager(mock.Mock(), reporter, tracker, reporter.config)
    manager._cleanup_progress_details = lambda *a: {"host": "compute1"}
    manager._write_recovery_artifacts()
    shell = (reporter.run_dir / "recovery.sh").read_text()
    markdown = (reporter.run_dir / "recovery.md").read_text()
    assert "openstack server delete s1" in shell
    assert "openstack server delete --force" not in shell
    assert "virsh" not in shell
    assert "database" not in shell.lower()
    assert "compute1" in markdown


def test_cleanup_clears_router_routes_returned_as_osc_string(config_factory, tmp_path):
    reporter = make_reporter(config_factory(report_dir=tmp_path / "reports"))
    tracker = ResourceTracker(reporter)
    osc = mock.Mock()
    osc.json.return_value = {
        "routes": "[{'destination': '198.51.100.0/24', 'nexthop': '192.0.2.1'}]"
    }
    osc.run.return_value = completed()
    manager = CleanupManager(osc, reporter, tracker, reporter.config)

    manager._clear_router_routes("router-id")

    osc.run.assert_called_once_with(
        "router",
        "remove",
        "route",
        "--route",
        "destination=198.51.100.0/24,gateway=192.0.2.1",
        "router-id",
        check=False,
        timeout=min(60, reporter.config.resource_timeout),
    )


def test_cleanup_preserves_dependency_safe_resource_order():
    manager = object.__new__(CleanupManager)
    deleted_types = []
    manager._delete_type = lambda resource_type, _handler: deleted_types.append(
        resource_type
    )

    manager._delete_all_types()

    assert deleted_types == [
        "floating_ip",
        "server",
        "router",
        "port",
        "subnet",
        "network",
        "volume",
        "security_group",
        "server_group",
        "keypair",
    ]


def test_cleanup_is_idempotent_for_missing_resources(config_factory, tmp_path):
    reporter = make_reporter(config_factory(report_dir=tmp_path / "reports"))
    tracker = ResourceTracker(reporter)
    tracker.add("network", "n1", "net")
    osc = mock.Mock()
    osc.exists.return_value = False
    osc.json.return_value = []
    manager = CleanupManager(osc, reporter, tracker, reporter.config)
    assert manager.cleanup() is True
    assert manager.cleanup() is True


def test_state_status_shows_active_process_and_pending(tmp_path, monkeypatch):
    store = StateStore(tmp_path / "reports")
    checkpoint = RunCheckpoint(
        "run",
        "RUNNING",
        "run",
        "cross-topology",
        "2/5",
        iso_utc(),
        iso_utc(),
        iso_utc(),
        ["a"],
        [],
        ["b", "c"],
        ["g1"],
        "manifest",
        "report",
    )
    store.save(checkpoint)
    lock = store.run_dir("run") / "run.lock"
    lock.write_text(str(os.getpid()))
    text = store.print_status(checkpoint)
    assert "Process: active process" in text
    assert "Pending tests: 2" in text
    assert "Current batch: 2/5" in text


def test_state_store_finds_interrupted_run_for_cleanup(tmp_path):
    store = StateStore(tmp_path / "reports")
    checkpoint = RunCheckpoint(
        "run",
        "INTERRUPTED",
        "run",
        "group-local",
        None,
        iso_utc(),
        iso_utc(),
        iso_utc(),
        ["a"],
        [],
        ["b"],
        [],
        "manifest",
        "report",
    )
    store.save(checkpoint)
    assert store.latest(incomplete_only=True).run_id == "run"


def test_reporter_deduplicates_results_writes_one_report_and_prints_summary(
    config_factory, tmp_path, capsys
):
    config = config_factory(report_dir=tmp_path / "reports", action="run")
    reporter = Reporter(config, "run")
    reporter.cleanup_summary.update({"attempted": True, "complete": True, "deleted": 3})
    reporter.result(
        "T1",
        "same-subnet",
        "PASS",
        "traffic returned the expected token",
        expected="reachable",
        observed="reachable",
        authoritative=True,
        display_name="Same tenant subnet TCP probe",
        scenario="Tenant same-network connectivity",
    )
    reporter.result(
        "T1",
        "same-subnet",
        "PASS",
        "traffic returned the expected token",
        expected="reachable",
        observed="reachable",
        authoritative=True,
        display_name="Same tenant subnet TCP probe",
        scenario="Tenant same-network connectivity",
    )
    assert len(reporter.results) == 1
    assert reporter.finalize(0) == 0

    terminal = capsys.readouterr().out
    report = reporter.report_path.read_text(encoding="utf-8")
    assert "NEUTRON FLUX FINAL SUMMARY" in terminal
    assert "Path: Fixed IP → fixed IP on the same subnet" in terminal
    assert "Why this passed:" in terminal
    assert "Final status:    PASS" in terminal
    assert "NEUTRON FLUX FINAL SUMMARY" in report
    assert "Same project subnet TCP probe" in report

    user_facing = [
        path.name
        for path in reporter.run_dir.iterdir()
        if path.suffix in {".txt", ".log", ".md", ".csv", ".xml"}
    ]
    assert sorted(user_facing) == [
        "host-qualification.csv",
        "incident-summary.md",
        "replay-plan.txt",
        "report.junit.xml",
        "report.txt",
    ]


def test_reporter_marks_zero_network_execution_as_failed_setup(
    config_factory, tmp_path, capsys
):
    reporter = Reporter(
        config_factory(report_dir=tmp_path / "reports", action="run"), "run"
    )
    reporter.plan = Plan(
        [],
        [],
        {},
        [],
        tests=[
            FluxTestSpec(
                "CONTROL-SSH",
                "control",
                "control",
                4,
                "reachable",
                "controller ready",
                True,
                [],
                scenario="Controller readiness",
            ),
            FluxTestSpec(
                "NET-1",
                "same-subnet",
                "probe",
                4,
                "reachable",
                "same subnet",
                True,
                ["g1"],
                scenario="Provider subnet connectivity",
            ),
        ],
    )
    reporter.cleanup_summary.update({"attempted": True, "complete": True})
    reporter.result(
        "CONTROL-SSH",
        "control",
        "PASS",
        "controller ready",
        scenario="Controller readiness",
    )
    reporter.result(
        "NET-1",
        "same-subnet",
        "SKIP",
        "transient probe failed to start",
        scenario="Provider subnet connectivity",
    )
    assert reporter.finalize(0) == 2
    output = capsys.readouterr().out
    assert "Final status:    SETUP FAILED" in output
    assert "Checks not run:                       1" in output
    assert "No network connectivity validations were completed." in output


def test_reporter_exit_code_prioritizes_cleanup_incomplete(config_factory, tmp_path):
    reporter = Reporter(
        config_factory(report_dir=tmp_path / "reports", action="run"), "run"
    )
    reporter.cleanup_summary.update({"attempted": True, "complete": False})
    reporter.result("T1", "same-subnet", "PASS", "ok")
    assert reporter.finalize(0) == 3


def test_manifest_reloads_latest_record_state(config_factory, tmp_path):
    reporter = Reporter(
        config_factory(report_dir=tmp_path / "reports", action="run"), "run"
    )
    tracker = ResourceTracker(reporter)
    item = tracker.add("port", "p1", "port")
    tracker.mark_deleted(item)
    loaded = ResourceTracker.load_manifest(reporter.manifest_path)
    assert len(loaded) == 1
    assert loaded[0].delete_status == "deleted"


def test_executor_rejects_three_group_cross_test(config_factory, tmp_path):
    groups = [
        PlannedGroup(f"g{i}", "provider", f"g{i}", f"n{i}", f"n{i}", [f"s{i}"], [4])
        for i in range(3)
    ]
    spec = FluxTestSpec(
        "T",
        "route",
        "probe",
        4,
        "reachable",
        "reason",
        True,
        ["g0", "g1", "g2"],
        phase="cross",
    )
    plan = Plan(groups, [], {}, [], tests=[spec])
    executor = object.__new__(AdaptiveExecutor)
    executor.plan = plan
    executor.reporter = SimpleNamespace(has_result=lambda _id: False)
    with pytest.raises(SuiteError, match="three-VM invariant"):
        executor._run_cross_phase()


def test_executor_plan_consistency_rejects_extra_results():
    executor = object.__new__(AdaptiveExecutor)
    executor.plan = Plan(
        [],
        [],
        {},
        [],
        tests=[FluxTestSpec("A", "c", "probe", 4, "reachable", "r", True, [])],
    )
    executor.reporter = SimpleNamespace(
        results=[SimpleNamespace(test_id="A"), SimpleNamespace(test_id="EXTRA")]
    )
    with pytest.raises(SuiteError, match="unplanned"):
        executor._validate_plan_consistency()


def test_diagnostics_classifies_common_failures():
    assert (
        DiagnosticCollector._classify(
            ProbeResult("blocked", False, 1, 1, stderr="No route to host")
        )
        == "ROUTING"
    )
    assert (
        DiagnosticCollector._classify(
            ProbeResult("blocked", False, 1, 1, stderr="Connection refused")
        )
        == "PROBE_SERVICE"
    )
    assert (
        DiagnosticCollector._classify(
            ProbeResult(
                "blocked",
                False,
                1,
                1,
                stderr="Destination Host Unreachable",
                source_ip="192.0.2.1",
            )
        )
        == "ARP"
    )


def test_openstack_adapter_rejects_invalid_json(tmp_path, monkeypatch):
    logger = Logger(tmp_path / "log")
    adapter = OpenStack(logger)
    monkeypatch.setattr(adapter, "run", lambda *a, **k: completed(stdout="not json"))
    with pytest.raises(SuiteError, match="invalid JSON"):
        adapter.json("server", "list")


def test_fixed_ip_parser_handles_osc_string():
    value = "[{'subnet_id': 's4', 'ip_address': '192.0.2.10'}, {'subnet_id': 's6', 'ip_address': 'fd00::10'}]"
    assert ResourceBuilder._fixed_ips({"fixed_ips": value}) == {
        "s4": "192.0.2.10",
        "s6": "fd00::10",
    }


def test_engine_concise_error_removes_python_traceback_noise():
    text = 'Traceback (most recent call last):\n  File "<string>", line 1\n^^^^^^^^^^^^\nTimeoutError: timed out'
    assert FluxTestEngine._concise(text) == "TimeoutError: timed out"


def test_controller_uses_one_provider_ipv4_control_port(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    builder = object.__new__(ResourceBuilder)
    builder.plan = plan
    builder.discovery = discovery_fixture
    builder.controller_probe_mode = "none"
    specs = builder._controller_probe_specs()
    assert len(specs) == 1
    assert specs[0]["families"] == [4]
    assert len(specs[0]["subnet_ids"]) == 1


def test_selected_flavor_quota_recheck_uses_real_vcpu_and_ram(
    config_factory, discovery_fixture
):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.discovery = discovery_fixture
    builder.plan = SimpleNamespace(estimated={"peak_instances": 3, "peak_volumes": 3})
    builder.flavor_name = "large-test"
    builder.flavor_vcpus = 8
    builder.flavor_ram_mb = 16384
    builder.flavor_disk_gb = 20
    discovery_fixture.quota_info = {
        "instances": QuotaInfo("instances", 10, 0),
        "cores": QuotaInfo("cores", 16, 0),
        "ram": QuotaInfo("ram", 32768, 0),
    }
    with pytest.raises(SuiteError, match="Selected flavor does not fit"):
        builder._validate_selected_flavor_quota()


def test_cleanup_can_select_a_retained_completed_run(tmp_path):
    store = StateStore(tmp_path)
    checkpoint = RunCheckpoint(
        run_id="retained-run",
        state="COMPLETED",
        action="run",
        phase="resources-retained",
        current_batch=None,
        started_at="2026-07-19T00:00:00+00:00",
        updated_at="2026-07-19T00:00:00+00:00",
        last_activity="2026-07-19T00:00:00+00:00",
        completed_test_ids=[],
        failed_test_ids=[],
        pending_test_ids=[],
        active_group_ids=[],
        manifest_path=str(tmp_path / "manifest.jsonl"),
        report_dir=str(tmp_path),
        cleanup_state="RETAINED",
    )
    store.save(checkpoint)
    assert store.latest(incomplete_only=True).run_id == "retained-run"


def test_source_nat_plans_observe_default_and_never_schedule_setting_cloud_operation(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    assert not any(item.operation == "source-nat-observe" for item in plan.tests)
    profiles = [
        item for item in plan.tests if item.category == "source-nat-packet-size"
    ]
    assert profiles
    assert all(item.operation == "snat-packet-size-profile" for item in profiles)
    assert all(
        item.metadata.get("egress_translation_mode") == "router-source-nat"
        and item.metadata.get("require_no_floating_ip") is True
        for item in profiles
    )


def test_zero_disk_flavor_still_uses_nova_image_boot(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(prefer_ephemeral_boot=True)
    builder.server_sequence = 0
    builder.flavor_id = "f-zero"
    builder.flavor_name = "zero-disk"
    builder.flavor_disk_gb = 0
    builder.keypair_name = "key"
    builder.image_id = "img"
    builder.image_name = "debian-13"
    builder.tracker = mock.Mock()
    builder.logger = mock.Mock()
    builder.reporter = mock.Mock()
    builder._wait_for_status = mock.Mock()
    builder.osc = mock.Mock()
    builder.osc.run.return_value = completed(stdout=json.dumps({"id": "server"}))
    builder.osc.json.return_value = {"id": "server", "status": "ACTIVE"}
    builder._create_server("vm-zero", ["p1"], role="endpoint")
    builder._wait_for_server_settlement = mock.Mock(
        return_value=builder.osc.json.return_value
    )
    create_args = builder.osc.run.call_args.args
    assert "--image" in create_args
    assert "volume" not in create_args


def test_failed_image_boot_does_not_silently_create_a_volume(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(prefer_ephemeral_boot=True)
    builder.server_sequence = 0
    builder.flavor_id = "f1"
    builder.flavor_name = "small"
    builder.flavor_disk_gb = 0
    builder.keypair_name = "key"
    builder.image_id = "img"
    builder.image_name = "debian-13"
    builder.tracker = mock.Mock()
    builder.logger = mock.Mock()
    builder.reporter = mock.Mock()
    builder.osc = mock.Mock()
    builder.osc.run.return_value = completed(1, stderr="No valid host")
    builder.osc.json.return_value = None
    builder._recover_created_resource_by_name = mock.Mock(return_value=None)
    with pytest.raises(SuiteError, match="Nova could not create host-root-disk server"):
        builder._create_server("vm-fail", ["p1"], role="endpoint")
    assert not any(
        call.args[:2] == ("volume", "create")
        for call in builder.osc.json.call_args_list
    )


def test_extra_route_scenario_is_skipped_when_extension_is_known_absent(
    config_factory, discovery_fixture, tmp_path
):
    discovery_fixture.network_extensions = ["router", "security-group", "port-security"]
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    assert not any(group.kind == "extra-route-pair" for group in plan.groups)
    assert any(
        "static-route (extraroute API) extension is not available" in item["reason"]
        for item in plan.skipped
    )


def test_plan_reserves_four_security_groups_and_default_source_nat(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    assert plan.estimated["security_groups_created"] == 4
    assert plan.estimated["security_group_rules_peak"] == 24
    assert not any(item.operation == "source-nat-observe" for item in plan.tests)
    translation_groups = [
        item
        for item in plan.tenant_groups
        if item.kind == "private-translation-project-network"
    ]
    assert translation_groups
    assert all(
        item.metadata["source_nat_mode"] == "cloud-default"
        and item.metadata["source_nat_controlled_by_flux"] is False
        for item in translation_groups
    )


def test_security_control_ignores_destination_self_rule_for_separate_source_group(
    config_factory,
):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.list_security_group_rules = mock.Mock(
        return_value=[
            {
                "direction": "ingress",
                "ethertype": "IPv4",
                "protocol": None,
                "remote_group_id": "destination-sg",
                "port_range_min": None,
                "port_range_max": None,
            },
            {
                "direction": "ingress",
                "ethertype": "IPv4",
                "protocol": "tcp",
                "remote_ip_prefix": "0.0.0.0/0",
                "port_range_min": 18080,
                "port_range_max": 18080,
            },
        ]
    )
    allowed, matching = builder.security_group_allows_port(
        "destination-sg",
        4,
        "tcp",
        18082,
        source_security_group_id="source-sg",
    )
    assert allowed is False
    assert matching == []
    port, authoritative, rules = builder.choose_security_control_port(
        destination_security_group_id="destination-sg",
        source_security_group_id="source-sg",
        family=4,
    )
    assert port == 18082
    assert authoritative is True
    assert rules == []


def test_security_control_becomes_inconclusive_for_broad_external_rule(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory()
    broad = {
        "direction": "ingress",
        "ethertype": "IPv4",
        "protocol": "tcp",
        "remote_ip_prefix": "0.0.0.0/0",
        "port_range_min": None,
        "port_range_max": None,
    }
    builder.list_security_group_rules = mock.Mock(return_value=[broad])
    port, authoritative, rules = builder.choose_security_control_port(
        destination_security_group_id="destination-sg",
        source_security_group_id="source-sg",
        family=4,
    )
    assert port == 18082
    assert authoritative is False
    assert rules == [broad]


def test_temporary_security_rule_is_scoped_to_source_group(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.security_group_rules = {}
    builder.osc = mock.Mock()
    builder.osc.json.return_value = {"id": "rule-id"}
    builder.list_security_group_rules = mock.Mock(return_value=[])
    rule_id = builder.add_temporary_security_rule(
        destination_security_group_id="destination-sg",
        source_security_group_id="source-sg",
        family=4,
        protocol="tcp",
        port=18082,
    )
    assert rule_id == "rule-id"
    args = builder.osc.json.call_args.args
    assert "--remote-group" in args
    assert args[args.index("--remote-group") + 1] == "source-sg"
    assert args[-1] == "destination-sg"


def test_router_interface_port_uses_dynamic_neutron_ipam(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.run_tag = "run-tag"
    builder.tracker = mock.Mock()
    builder.osc = mock.Mock()
    builder.osc.json.return_value = {
        "id": "transit-port",
        "fixed_ips": [{"subnet_id": "transit-subnet", "ip_address": "192.0.2.7"}],
    }
    group = PlannedGroup(
        id="extra",
        kind="extra-route-pair",
        label="Two router",
        network_id=None,
        network_name=None,
        subnet_ids=[],
        families=[4],
        pool_id="pool",
        prefix_length=24,
    )
    port_id, address = builder._create_router_interface_port(
        network_id="transit-network",
        subnet_id="transit-subnet",
        name="transit-a",
        group=group,
        generation=1,
        side="A",
    )
    assert port_id == "transit-port"
    assert address == "192.0.2.7"
    args = builder.osc.json.call_args.args
    assert "--fixed-ip" in args
    fixed_arg = args[args.index("--fixed-ip") + 1]
    assert fixed_arg == "subnet=transit-subnet"
    assert "ip-address=" not in fixed_arg


def test_two_router_topology_uses_no_gateway_transit_and_explicit_ports(
    config_factory,
):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.name_prefix = "run"
    builder.osc = mock.Mock()
    builder.osc.run.return_value = completed()
    builder._create_generated_tenant_network = mock.Mock(
        side_effect=[
            ("net-a", "tenant-a", "subnet-a", "10.0.1.0/24"),
            ("net-b", "tenant-b", "subnet-b", "10.0.2.0/24"),
            ("net-t", "transit", "subnet-t", "10.0.3.0/24"),
        ]
    )
    builder._create_scenario_router = mock.Mock(
        side_effect=[("router-a", "router-a-name"), ("router-b", "router-b-name")]
    )
    builder._create_router_interface_port = mock.Mock(
        side_effect=[("port-a", "10.0.3.10"), ("port-b", "10.0.3.11")]
    )
    builder._attach_router_port = mock.Mock()
    builder._create_endpoints = mock.Mock(return_value=[])
    group = PlannedGroup(
        id="extra-route-ipv4",
        kind="extra-route-pair",
        label="Two-router IPv4",
        network_id=None,
        network_name=None,
        subnet_ids=[],
        families=[4],
        pool_id="pool",
        prefix_length=24,
    )
    runtime = builder._build_extra_route_pair(group, sides=(), generation=1)
    calls = builder._create_generated_tenant_network.call_args_list
    assert calls[2].kwargs["no_gateway"] is True
    router_add_subnet_calls = [
        call.args
        for call in builder.osc.run.call_args_list
        if call.args[:3] == ("router", "add", "subnet")
    ]
    assert (
        "router",
        "add",
        "subnet",
        "router-a",
        "subnet-a",
    ) in router_add_subnet_calls
    assert (
        "router",
        "add",
        "subnet",
        "router-b",
        "subnet-b",
    ) in router_add_subnet_calls
    assert not any("subnet-t" in call for call in router_add_subnet_calls)
    assert builder._attach_router_port.call_count == 2
    assert runtime.metadata["transit_port_ids"] == {"A": "port-a", "B": "port-b"}
    assert runtime.metadata["routes"]["A"]["gateway"] == "10.0.3.11"
    assert runtime.metadata["routes"]["B"]["gateway"] == "10.0.3.10"
