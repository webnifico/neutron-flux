from __future__ import annotations

from neutron_flux.network_contract import (
    FLOATING_IP_TARGET_CONTRACT,
    PRIVATE_TRANSLATION_PROJECT_NETWORK,
)

from ._shared import *  # noqa: F403, F405


def test_executor_records_one_setup_error_and_blocks_dependent_assertions(
    config_factory, tmp_path
):
    config = config_factory(action="run")
    reporter = Reporter(config, "setup-error-run")
    specs = [
        FluxTestSpec(
            id="setup",
            category="router-extra-route",
            operation="extra-route-baseline",
            family=4,
            expectation="blocked",
            expectation_reason="baseline",
            authoritative=True,
            dependencies=["extra"],
            display_name="Two-router topology setup",
            scenario="Routing between two Neutron routers using extra routes",
        ),
        FluxTestSpec(
            id="dependent",
            category="router-extra-route",
            operation="extra-route-add",
            family=4,
            expectation="reachable",
            expectation_reason="routes",
            authoritative=True,
            dependencies=["extra"],
            display_name="Dependent route test",
            scenario="Routing between two Neutron routers using extra routes",
        ),
    ]
    executor = object.__new__(AdaptiveExecutor)
    executor.reporter = reporter
    executor.builder = SimpleNamespace(
        group_failure_type=lambda group_id: "two-router-topology-construction"
    )
    executor._mark_specs_unavailable(
        specs,
        "duplicate transit address",
        setup_error=True,
    )
    assert reporter.get_result("setup").status == "ERROR"
    assert reporter.get_result("dependent").status == "BLOCKED_BY_SETUP_ERROR"
    reporter.logger.close()


@pytest.mark.parametrize(
    ("status", "expected_final"),
    [
        ("UNVERIFIED", "PASS WITH WARNINGS"),
        ("BLOCKED_BY_PREREQUISITE", "SETUP FAILED"),
        ("SKIP", "SETUP FAILED"),
        ("FAIL", "FAIL"),
        ("ERROR", "ERROR"),
    ],
)
def test_reporter_final_status_distinguishes_findings_from_execution_errors(
    config_factory, status, expected_final
):
    config = config_factory(action="run")
    reporter = Reporter(config, f"status-{status.lower()}")
    reporter.plan = Plan([], [], {}, [], tests=[])
    reporter.cleanup_summary.update({"attempted": True, "complete": True})
    reporter.result(
        "network-test",
        "test",
        status,
        "result",
        expected="reachable",
        observed="blocked" if status != "ERROR" else "error",
        scenario="Network scenario",
    )
    reporter.finalize(0)
    output = reporter.report_path.read_text()
    assert f"Final status:    {expected_final}" in output


def test_reporter_summary_grades_every_executed_probe_and_lists_every_test(
    config_factory, tmp_path
):
    reporter = Reporter(
        config_factory(report_dir=tmp_path / "reports", action="run"),
        "clear-summary",
    )
    reporter.plan = Plan([], [], {}, [], tests=[object(), object(), object()])
    reporter.cleanup_summary.update({"attempted": True, "complete": True})
    reporter.result(
        "required-pass",
        "provider-network-connectivity",
        "PASS",
        "selected provider networks were reachable",
        expected="reachable",
        observed="reachable",
        display_name="Provider network TCP connectivity",
        scenario="Provider network connectivity",
    )
    reporter.result(
        "required-unverified",
        "security-group",
        "UNVERIFIED",
        "a broad existing rule prevented isolation",
        expected="blocked",
        observed="reachable",
        scenario="Security-group lifecycle",
    )
    reporter.result(
        "required-fail",
        "tenant-provider-connectivity",
        "FAIL",
        "the selected path was blocked",
        expected="reachable",
        observed="blocked",
        scenario="Tenant/provider fixed-IP connectivity",
    )
    assert reporter.finalize(0) == 1
    output = reporter.report_path.read_text(encoding="utf-8")
    assert "Final status:    FAIL" in output
    assert "FAIL — 1 passed, 1 failed, 1 unverified" in output
    assert "Validations:                          3" in output
    assert "Informational" not in output
    assert "DETAILED RESULTS BY CATEGORY" in output
    assert "required-pass" in output
    assert "required-unverified" in output
    assert "required-fail" in output
    assert "Expected result:" in output
    assert (
        "Actual result: The recorded traffic probe could not reach the destination."
        in output
    )
    assert (
        "Why this failed: The destination did not return the required successful response."
        in output
    )
    stored = [
        json.loads(line)
        for line in reporter.result_journal_path.read_text(
            encoding="utf-8"
        ).splitlines()
    ]
    failed = next(item for item in stored if item["test_id"] == "required-fail")
    assert failed["message"] == "the selected path was blocked"
    assert failed["status"] == "FAIL"


def test_reporter_prints_verdict_breakdown_for_every_result_category(
    config_factory, tmp_path
):
    reporter = Reporter(
        config_factory(report_dir=tmp_path / "reports", action="run"),
        "category-summary",
    )
    reporter.plan = Plan([], [], {}, [], tests=[object()] * 7)
    reporter.cleanup_summary.update({"attempted": True, "complete": True})
    reporter.result("same-pass", "same-subnet", "PASS", "ok")
    reporter.result("same-skip", "same-subnet", "SKIP", "unsupported")
    reporter.result("sg-pass", "security-group", "PASS", "allow worked")
    reporter.result(
        "sg-unverified", "security-group", "UNVERIFIED", "deny not isolated"
    )
    reporter.result("migration-fail", "compute-placement", "FAIL", "wrong host")
    reporter.result(
        "provider-pass",
        "provider-network-connectivity",
        "PASS",
        "reachable",
    )
    reporter.result(
        "not-run",
        "floating-ip-lifecycle",
        "BLOCKED_BY_SETUP_ERROR",
        "setup failed",
    )

    assert reporter.finalize(0) == 1
    output = reporter.report_path.read_text(encoding="utf-8")
    assert "CATEGORY RESULTS" in output
    assert "Same-network connectivity" in output
    assert "PASS WITH GAPS" in output
    assert "Security-group enforcement" in output
    assert "PASS WITH WARNINGS" in output
    assert "Compute placement and migration" in output
    assert "FAILED" in output
    assert "Provider network connectivity" in output
    assert "INFORMATIONAL" not in output
    assert "provider-pass" in output
    assert "Floating-IP lifecycle" in output
    assert "NOT RUN" in output
    assert "Executed tests receive PASS, FAIL, UNVERIFIED or ERROR verdicts." in output
    assert "N/A means the check does not apply" in output
    assert "DETAILED RESULTS BY CATEGORY" in output


def test_cleanup_does_not_resubmit_delete_for_server_already_deleting(
    config_factory,
):
    manager = object.__new__(CleanupManager)
    manager.config = config_factory()
    manager.logger = mock.Mock()
    manager.osc = mock.Mock()
    manager.osc.json.return_value = {"task_state": "deleting", "status": "ACTIVE"}
    manager._wait_server_settled_before_delete = mock.Mock(
        return_value=manager.osc.json.return_value
    )
    manager._delete_server(
        ResourceRecord(1, "server", "server-id", "vm", None, {}, iso_utc())
    )
    manager.osc.run.assert_not_called()


def test_cleanup_refuses_to_delete_compute_port_while_server_exists(config_factory):
    manager = object.__new__(CleanupManager)
    manager.config = config_factory()
    manager.logger = mock.Mock()
    manager.osc = mock.Mock()
    manager.osc.json.return_value = {
        "device_owner": "compute:nova",
        "device_id": "server-id",
    }
    manager.osc.exists.return_value = True
    with pytest.raises(SuiteError, match="remains attached"):
        manager._delete_port(
            ResourceRecord(1, "port", "port-id", "port", None, {}, iso_utc())
        )
    manager.osc.run.assert_not_called()


def test_verified_cleanup_removes_stale_recovery_artifacts(config_factory, tmp_path):
    reporter = Reporter(config_factory(), "cleanup-resolved")
    manager = object.__new__(CleanupManager)
    manager.reporter = reporter
    manager.logger = reporter.logger
    (reporter.run_dir / "recovery.md").write_text("old")
    (reporter.run_dir / "recovery.sh").write_text("old")
    reporter.cleanup_summary["recovery_markdown"] = str(
        reporter.run_dir / "recovery.md"
    )
    reporter.cleanup_summary["recovery_script"] = str(reporter.run_dir / "recovery.sh")
    manager._clear_recovery_artifacts()
    assert not (reporter.run_dir / "recovery.md").exists()
    assert not (reporter.run_dir / "recovery.sh").exists()


def test_reporter_rejects_conflicting_duplicate_result_ids(config_factory, tmp_path):
    config = config_factory(report_dir=tmp_path / "reports", action="run")
    reporter = Reporter(config, "run-conflict")
    reporter.result("T1", "same-subnet", "PASS", "first")
    with pytest.raises(SuiteError, match="Conflicting duplicate test result ID T1"):
        reporter.result("T1", "same-subnet", "FAIL", "second")
    reporter.logger.close()
    assert "recovery_markdown" not in reporter.cleanup_summary
    assert "recovery_script" not in reporter.cleanup_summary
    reporter.logger.close()


def test_floating_ip_is_created_lazily_with_default_router_snat(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.logger = mock.Mock()
    builder.capture_router_state = mock.Mock(
        return_value={
            "external_gateway_info": {
                "network_id": "external",
                "enable_snat": True,
                "external_fixed_ips": [
                    {"subnet_id": "external-subnet", "ip_address": "192.0.2.10"}
                ],
            }
        }
    )
    endpoint = Endpoint(
        label="tenant:A",
        server_id="server-a",
        server_name="server-a",
        management_port_id="mgmt-a",
        management_ip="10.254.0.10",
        test_port_id="test-a",
        test_mac="fa:16:3e:00:00:01",
        fixed_ips={"tenant-subnet": "10.0.0.10"},
        host=None,
        availability_zone=None,
        volume_id=None,
        side="A",
    )
    plan = PlannedGroup(
        id="tenant",
        kind=PRIVATE_TRANSLATION_PROJECT_NETWORK,
        label="Private translation through Public1",
        network_id="tenant-network",
        network_name="tenant-network",
        subnet_ids=["tenant-subnet"],
        families=[4],
        prefix_length=24,
        synthetic_cidr="10.0.0.0/24",
        external_network_id="external",
        external_subnet_id="external-subnet",
        floating_subnet_id="external-subnet",
        metadata={
            "fixed_address_role": "disposable-private",
            "source_nat_mode": "cloud-default",
            "source_nat_controlled_by_flux": False,
            "source_nat_default_expected": True,
            "floating_ip_target_allowed": True,
            "floating_ip_target_contract": FLOATING_IP_TARGET_CONTRACT,
            "floating_ip_endpoint_side": "A",
        },
    )
    runtime = RuntimeGroup(
        plan=plan,
        network_id="tenant-network",
        network_name="tenant-network",
        subnet_ids=["tenant-subnet"],
        router_id="router-id",
        endpoints=[endpoint],
        source_nat_enabled=True,
        fips={},
        metadata={"floating_ip_fixed_subnet_id": "tenant-subnet"},
    )

    def allocate(group):
        group.fips[endpoint.label] = {
            "id": "fip-id",
            "address": "198.51.100.10",
            "fixed_ip": "10.0.0.10",
            "port_id": "test-a",
        }

    builder._create_group_fips = mock.Mock(side_effect=allocate)
    builder.ensure_group_fips(runtime)
    builder._create_group_fips.assert_called_once_with(runtime)
    assert runtime.fips[endpoint.label]["fixed_ip"] == "10.0.0.10"


def test_floating_ip_allocation_accepts_observed_default_snat(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.logger = mock.Mock()
    builder.capture_router_state = mock.Mock(
        return_value={"external_gateway_info": {"enable_snat": True}}
    )
    endpoint = Endpoint(
        label="tenant:A",
        server_id="server-a",
        server_name="server-a",
        management_port_id="mgmt-a",
        management_ip="10.254.0.10",
        test_port_id="test-a",
        test_mac="fa:16:3e:00:00:01",
        fixed_ips={"tenant-subnet": "10.0.0.10"},
        host=None,
        availability_zone=None,
        volume_id=None,
        side="A",
    )
    plan = PlannedGroup(
        id="tenant",
        kind=PRIVATE_TRANSLATION_PROJECT_NETWORK,
        label="Private translation through Public1",
        network_id="tenant-network",
        network_name="tenant-network",
        subnet_ids=["tenant-subnet"],
        families=[4],
        prefix_length=24,
        synthetic_cidr="10.0.0.0/24",
        external_network_id="external",
        external_subnet_id="external-subnet",
        floating_subnet_id="external-subnet",
        metadata={
            "fixed_address_role": "disposable-private",
            "source_nat_mode": "cloud-default",
            "source_nat_controlled_by_flux": False,
            "source_nat_default_expected": True,
            "floating_ip_target_allowed": True,
            "floating_ip_target_contract": FLOATING_IP_TARGET_CONTRACT,
            "floating_ip_endpoint_side": "A",
        },
    )
    runtime = RuntimeGroup(
        plan=plan,
        network_id="tenant-network",
        network_name="tenant-network",
        subnet_ids=["tenant-subnet"],
        router_id="router-id",
        endpoints=[endpoint],
        source_nat_enabled=True,
        fips={},
        metadata={"floating_ip_fixed_subnet_id": "tenant-subnet"},
    )

    def allocate(target):
        target.fips[endpoint.label] = {"id": "fip-id", "address": "203.0.113.10"}

    builder._create_group_fips = mock.Mock(side_effect=allocate)
    builder.ensure_group_fips(runtime)
    builder._create_group_fips.assert_called_once_with(runtime)


def test_unscoped_ipv4_requires_outbound_snat_but_observes_reverse(
    config_factory, discovery_fixture, tmp_path
):
    pool = next(item for item in discovery_fixture.pools if item.id == "tp4")
    pool.address_scope_id = None
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    groups = [
        item
        for item in plan.tenant_groups
        if item.kind == "project-network" and item.pool_id == "tp4"
    ]
    assert groups
    assert all(item.relationship == TopologyPolicy.UNASSIGNED for item in groups)
    assert all(item.expected_routing == "directional-default-snat" for item in groups)
    routed = [
        item
        for item in plan.tests
        if item.category == "project-provider-connectivity"
        and any(group.id in item.dependencies for group in groups)
    ]
    assert routed
    for item in routed:
        source_is_project = item.source_group_id in {group.id for group in groups}
        assert item.authoritative is source_is_project
        assert item.expectation == ("reachable" if source_is_project else "observation")


def test_unscoped_ipv6_pool_allocation_does_not_declare_routing(
    config_factory, discovery_fixture, tmp_path
):
    pool = next(item for item in discovery_fixture.pools if item.id == "tp6")
    pool.address_scope_id = None
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    groups = [
        item
        for item in plan.tenant_groups
        if item.kind == "project-network"
        and item.pool_id == "tp6"
        and item.relationship == TopologyPolicy.UNASSIGNED
    ]
    assert groups
    assert all(item.expected_routing == "observation" for item in groups)
    routed = [
        item
        for item in plan.tests
        if item.category == "project-provider-connectivity"
        and any(group.id in item.dependencies for group in groups)
    ]
    assert not routed
    assert any(
        "No declared routing expectation" in item["reason"] for item in plan.skipped
    )


def test_v59_every_usable_pool_gets_external_and_router_scenarios(
    config_factory, discovery_fixture, tmp_path
):
    discovery_fixture.pools.append(
        PoolInfo(
            id="tp4-secondary",
            name="SelfServeIPv4Secondary",
            ip_version=4,
            address_scope_id="scope4",
            prefixes=["10.40.0.0/16"],
            default_prefix_length=26,
            min_prefix_length=24,
            max_prefix_length=28,
            shared=True,
            project_id=None,
            provider_pool=False,
            raw={},
        )
    )
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    tenant_pool_ids = {
        item.pool_id for item in plan.tenant_groups if item.kind == "project-network"
    }
    assert {"tp4", "tp4-secondary"}.issubset(tenant_pool_ids)
    assert any(
        item.kind == "one-router-project-networks" and item.pool_id == "tp4-secondary"
        for item in plan.tenant_groups
    )
    assert any(
        item.kind == "two-router-static-routing" and item.pool_id == "tp4-secondary"
        for item in plan.tenant_groups
    )
    secondary_groups = [
        item for item in plan.tenant_groups if item.pool_id == "tp4-secondary"
    ]
    assert secondary_groups
    assert all(item.prefix_length == 26 for item in secondary_groups)


def test_v59_provider_subnets_require_allocation_and_compute_service(
    config_factory, discovery_fixture, tmp_path
):
    s1 = discovery_fixture.subnet("s1v4")
    s3 = discovery_fixture.subnet("s3v4")
    s1.allocation_pools = []
    s3.service_types = ["network:router_gateway"]
    planner = Planner(
        config_factory(),
        discovery_fixture,
        Logger(tmp_path / "provider-role.log"),
    )
    skipped = []
    providers = planner._provider_groups(skipped)
    provider_subnets = {
        subnet_id for group in providers for subnet_id in group.subnet_ids
    }
    assert "s1v4" not in provider_subnets
    assert "s3v4" not in provider_subnets
    reasons = " ".join(item["reason"] for item in skipped)
    assert "no allocation pool" in reasons
    assert "compute:nova" in reasons


def test_direct_routed_pool_never_reuses_external_subnet_as_fip_source(
    config_factory, discovery_fixture, tmp_path
):
    gateway = discovery_fixture.subnet("s1v4")
    gateway.service_types = ["network:router_gateway"]
    fip_subnet = SubnetInfo(
        id="s1-fip",
        name="public1-floating-ip",
        network_id="n1",
        cidr="198.51.100.0/24",
        ip_version=4,
        gateway_ip=None,
        dhcp_enabled=False,
        allocation_pools=[{"start": "198.51.100.10", "end": "198.51.100.250"}],
        subnetpool_id=None,
        ipv6_address_mode=None,
        ipv6_ra_mode=None,
        dns_nameservers=[],
        address_class="private",
        raw={},
        segment_id=None,
        address_scope_id="scope4",
        service_types=["network:floatingip"],
    )
    discovery_fixture.subnets.append(fip_subnet)
    discovery_fixture.occupied_cidrs.append(fip_subnet.cidr)
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    group = next(
        item
        for item in plan.tenant_groups
        if item.kind == "project-network"
        and item.pool_id == "tp4"
        and item.external_subnet_id == "s1v4"
    )
    assert group.floating_subnet_id is None
    assert group.metadata["routed_fixed_ip_topology"] is True
    assert group.metadata["floating_ip_eligible"] is False
    assert not any(
        spec.destination_group_id == group.id
        and spec.operation in {"fip-baseline", "fip-withdraw", "fip-return"}
        for spec in plan.tests
    )
    assert group.metadata["fixed_ip_cross_test_available"] is False
    assert any(
        "fixed-IP validations are omitted" in item["reason"] for item in plan.skipped
    )


def test_v59_floating_ip_command_uses_role_specific_subnet(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.run_tag = "run-tag"
    builder.logger = mock.Mock()
    builder.tracker = mock.Mock()
    builder.osc = mock.Mock()
    builder.osc.json.return_value = {
        "id": "fip-id",
        "floating_ip_address": "198.51.100.20",
    }
    builder.wait_floating_ip_association = mock.Mock(return_value={"matched": True})
    floating = SubnetInfo(
        id="fip-subnet",
        name="fip-subnet",
        network_id="external",
        cidr="198.51.100.0/24",
        ip_version=4,
        gateway_ip=None,
        dhcp_enabled=False,
        allocation_pools=[],
        subnetpool_id=None,
        ipv6_address_mode=None,
        ipv6_ra_mode=None,
        dns_nameservers=[],
        address_class="private",
        raw={},
        service_types=["network:floatingip"],
    )
    builder.discovery = SimpleNamespace(subnet=lambda subnet_id: floating)
    endpoint_a = Endpoint(
        label="tenant:A",
        server_id="server-a",
        server_name="server-a",
        management_port_id="mgmt-a",
        management_ip="10.254.0.10",
        test_port_id="test-a",
        test_mac="fa:16:3e:00:00:01",
        fixed_ips={"tenant-subnet": "10.0.0.10"},
        host=None,
        availability_zone=None,
        volume_id=None,
        side="A",
    )
    plan = PlannedGroup(
        id="tenant",
        kind=PRIVATE_TRANSLATION_PROJECT_NETWORK,
        label="Private translation",
        network_id=None,
        network_name=None,
        subnet_ids=[],
        families=[4],
        prefix_length=24,
        synthetic_cidr="10.0.0.0/24",
        external_network_id="external",
        external_subnet_id="gateway-subnet",
        floating_subnet_id="fip-subnet",
        metadata={
            "fixed_address_role": "disposable-private",
            "source_nat_mode": "cloud-default",
            "source_nat_controlled_by_flux": False,
            "source_nat_default_expected": True,
            "floating_ip_target_allowed": True,
            "floating_ip_target_contract": FLOATING_IP_TARGET_CONTRACT,
            "floating_ip_endpoint_side": "A",
        },
    )
    runtime = RuntimeGroup(
        plan=plan,
        network_id="tenant-network",
        network_name="tenant-network",
        subnet_ids=["tenant-subnet"],
        router_id="router",
        endpoints=[endpoint_a],
        source_nat_enabled=True,
        fips={},
        metadata={"floating_ip_fixed_subnet_id": "tenant-subnet"},
    )
    builder._create_group_fips(runtime)
    args = builder.osc.json.call_args.args
    assert args[args.index("--subnet") + 1] == "fip-subnet"
    builder.tracker.add.assert_called_once()
    tracked = builder.tracker.add.call_args.kwargs
    assert tracked["floating_subnet_id"] == "fip-subnet"
    assert tracked["router_gateway_subnet_id"] == "gateway-subnet"


def test_v59_unselected_external_pool_remains_provider_classified(
    config_factory,
):
    config = config_factory(
        external_networks=["Public1"],
        exclude_external_networks=[],
    )

    class FakeOSC:
        def run(self, *args, **kwargs):
            assert args == ("configuration", "show", "-c", "region_name", "-f", "json")
            return mock.Mock(returncode=0, stdout='{"region_name": "RegionTest"}')

        backend_name = "fake-openstack"

        def json(self, *args, **kwargs):
            command = tuple(args)
            if command == ("token", "issue"):
                return {
                    "project_id": "project",
                    "project_name": "admin",
                }
            if command == ("network", "list", "--external"):
                return [
                    {"ID": "n1", "Name": "Public1"},
                    {"ID": "n2", "Name": "Public2"},
                ]
            if command == ("network", "list"):
                return [
                    {"ID": "n1", "Name": "Public1"},
                    {"ID": "n2", "Name": "Public2"},
                ]
            if command == ("subnet", "list", "--network", "n1"):
                return [{"ID": "s1"}]
            if command == ("subnet", "list", "--network", "n2"):
                return [{"ID": "s2"}]
            if command == ("subnet", "show", "s1"):
                return {
                    "id": "s1",
                    "name": "public1",
                    "network_id": "n1",
                    "cidr": "192.0.2.0/24",
                    "ip_version": 4,
                    "gateway_ip": "192.0.2.1",
                    "allocation_pools": [{"start": "192.0.2.10", "end": "192.0.2.250"}],
                    "subnetpool_id": "provider-pool-1",
                    "service_types": [],
                }
            if command == ("subnet", "show", "s2"):
                return {
                    "id": "s2",
                    "name": "public2",
                    "network_id": "n2",
                    "cidr": "198.51.100.0/24",
                    "ip_version": 4,
                    "gateway_ip": "198.51.100.1",
                    "allocation_pools": [
                        {
                            "start": "198.51.100.10",
                            "end": "198.51.100.250",
                        }
                    ],
                    "subnetpool_id": "provider-pool-2",
                    "service_types": [],
                }
            if command == ("network", "show", "n1"):
                return {
                    "id": "n1",
                    "name": "Public1",
                    "router:external": True,
                    "shared": True,
                    "provider:network_type": "flat",
                    "provider:physical_network": "provider1",
                    "mtu": 1500,
                }
            if command == (
                "network",
                "segment",
                "list",
                "--network",
                "n1",
            ):
                return []
            if command == ("subnet", "list", "--long"):
                return []
            if command == ("subnet", "pool", "list", "--long"):
                return [
                    {"ID": "provider-pool-1"},
                    {"ID": "provider-pool-2"},
                    {"ID": "tenant-pool"},
                ]
            if command == (
                "subnet",
                "pool",
                "show",
                "provider-pool-1",
            ):
                return {
                    "id": "provider-pool-1",
                    "name": "Provider1",
                    "ip_version": 4,
                    "default_prefix_length": 24,
                    "min_prefix_length": 24,
                    "max_prefix_length": 24,
                    "prefixes": ["192.0.2.0/24"],
                    "shared": True,
                }
            if command == (
                "subnet",
                "pool",
                "show",
                "provider-pool-2",
            ):
                return {
                    "id": "provider-pool-2",
                    "name": "Provider2",
                    "ip_version": 4,
                    "default_prefix_length": 24,
                    "min_prefix_length": 24,
                    "max_prefix_length": 24,
                    "prefixes": ["198.51.100.0/24"],
                    "shared": True,
                }
            if command == ("subnet", "pool", "show", "tenant-pool"):
                return {
                    "id": "tenant-pool",
                    "name": "Tenant",
                    "ip_version": 4,
                    "default_prefix_length": 24,
                    "min_prefix_length": 24,
                    "max_prefix_length": 28,
                    "prefixes": ["10.0.0.0/8"],
                    "shared": True,
                }
            if command == ("address", "scope", "list"):
                return []
            if command == ("extension", "list", "--network"):
                return []
            if command in {
                ("quota", "show", "--usage"),
                ("quota", "show"),
            }:
                return {}
            raise AssertionError(f"Unexpected command: {command}")

    discovery = Discoverer(
        FakeOSC(),
        mock.Mock(),
        config,
    ).discover()
    assert [item.id for item in discovery.networks] == ["n1"]
    pools = {item.id: item for item in discovery.pools}
    assert pools["provider-pool-1"].provider_pool is True
    assert pools["provider-pool-2"].provider_pool is True
    assert pools["tenant-pool"].provider_pool is False


def test_v59_security_rule_prefix_is_evaluated_against_actual_source(
    config_factory,
):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder.list_security_group_rules = mock.Mock(
        return_value=[
            {
                "direction": "ingress",
                "ethertype": "IPv4",
                "protocol": "tcp",
                "remote_ip_prefix": "10.0.0.0/24",
                "port_range_min": 18082,
                "port_range_max": 18082,
            }
        ]
    )
    allowed, _ = builder.security_group_allows_port(
        "destination",
        4,
        "tcp",
        18082,
        source_ip="192.0.2.10",
        conservative_without_source=False,
    )
    assert allowed is False
    allowed, rules = builder.security_group_allows_port(
        "destination",
        4,
        "tcp",
        18082,
        source_ip="10.0.0.10",
        conservative_without_source=False,
    )
    assert allowed is True
    assert len(rules) == 1


def test_v59_security_rule_address_group_is_resolved(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder._address_group_cache = {}
    builder.osc = mock.Mock()
    builder.osc.json.return_value = {"addresses": ["203.0.113.0/24"]}
    builder.list_security_group_rules = mock.Mock(
        return_value=[
            {
                "direction": "ingress",
                "ethertype": "IPv4",
                "protocol": "tcp",
                "remote_address_group_id": "address-group",
                "port_range_min": 18082,
                "port_range_max": 18082,
            }
        ]
    )
    allowed, _ = builder.security_group_allows_port(
        "destination",
        4,
        "tcp",
        18082,
        source_ip="192.0.2.10",
        conservative_without_source=False,
    )
    assert allowed is False
    allowed, _ = builder.security_group_allows_port(
        "destination",
        4,
        "tcp",
        18082,
        source_ip="203.0.113.10",
        conservative_without_source=False,
    )
    assert allowed is True


def test_v59_unreadable_address_group_is_conservative(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory()
    builder._address_group_cache = {}
    builder.osc = mock.Mock()
    builder.osc.json.return_value = None
    builder.list_security_group_rules = mock.Mock(
        return_value=[
            {
                "direction": "ingress",
                "ethertype": "IPv4",
                "protocol": "tcp",
                "remote_address_group_id": "address-group",
                "port_range_min": 18082,
                "port_range_max": 18082,
            }
        ]
    )
    allowed, rules = builder.security_group_allows_port(
        "destination",
        4,
        "tcp",
        18082,
        source_ip="192.0.2.10",
        conservative_without_source=False,
    )
    assert allowed is True
    assert len(rules) == 1


def test_v59_routed_provider_three_segments_use_full_pairwise_matrix(
    config_factory, routed_discovery, tmp_path
):
    routed_discovery.networks[0].segment_ids.append("seg-c")
    routed_discovery.segments.append(
        SegmentInfo(
            "seg-c",
            "routed",
            "vlan",
            "phys-c",
            103,
            "rack-c",
            {},
        )
    )
    routed_discovery.subnets.append(
        SubnetInfo(
            id="rc",
            name="rack-c-v4",
            network_id="routed",
            cidr="203.0.113.0/25",
            ip_version=4,
            gateway_ip="203.0.113.1",
            dhcp_enabled=False,
            allocation_pools=[{"start": "203.0.113.10", "end": "203.0.113.120"}],
            subnetpool_id=None,
            ipv6_address_mode=None,
            ipv6_ra_mode=None,
            dns_nameservers=[],
            address_class="private",
            raw={},
            segment_id="seg-c",
            address_scope_id=None,
        )
    )
    routed_discovery.occupied_cidrs.append("203.0.113.0/25")
    plan = build_plan(config_factory(), routed_discovery, tmp_path)
    routed_tests = [item for item in plan.tests if item.category == "routed-provider"]
    assert len(routed_tests) == 18
    pairs = {
        (
            item.source_group_id,
            item.destination_group_id,
        )
        for item in routed_tests
        if item.protocol == "icmp"
    }
    assert len(pairs) == 6


def test_v59_representative_lifecycle_tests_are_labeled(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    selected = [
        item
        for item in plan.tests
        if str(item.metadata.get("coverage_scope") or "").startswith("sampled")
    ]
    assert selected
    for item in selected:
        assert "Sampled" in ((item.display_name or "") + (item.scenario or ""))


def test_v59_guest_route_diagnostic_does_not_claim_gateway_reachability():
    captured = {}

    def executor(command):
        captured["command"] = command
        return completed(0, stdout='{"errors": []}')

    verifier = GuestNetworkVerifier(
        lambda subnet_id: {
            "cidr": "192.0.2.0/24",
            "gateway": "192.0.2.1",
            "mtu": 1500,
        }
    )
    verifier.verify(
        label="test",
        mac_address="fa:16:3e:00:00:01",
        fixed_ips={"subnet": "192.0.2.10"},
        executor=executor,
    )
    command = captured["command"]
    assert "no usable guest route lookup exists" in command
    assert "gateway {gateway} is not reachable" not in command
