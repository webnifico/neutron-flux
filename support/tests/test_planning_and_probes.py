from __future__ import annotations

from ._shared import *  # noqa: F403, F405


def test_adaptive_fixture_plan_excludes_retired_nested_public_suite(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    assert plan.estimated["test_results"] == 217
    assert not any(
        item.kind == "nested-public-project-network" for item in plan.tenant_groups
    )
    assert len(plan.tests) == 217
    assert len({item.id for item in plan.tests}) == 217
    added_coverage = [
        s
        for s in plan.tests
        if s.metadata.get("server_start_recovery")
        or s.metadata.get("hairpin_topology") == "different-routers"
    ]
    assert len(added_coverage) == 8
    assert len(plan.tests) - len(added_coverage) == 209
    assert all(item.operation != "source-nat-observe" for item in plan.tests)


def test_plan_has_three_vm_normal_peak(config_factory, discovery_fixture, tmp_path):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    assert plan.estimated["normal_peak_instances"] == 3
    assert plan.estimated["peak_instances"] == 4
    assert plan.estimated["peak_endpoint_instances"] == 2


def test_plan_estimates_actual_scheduler_generations(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    assert plan.estimated["group_loads"] == 29
    assert plan.estimated["endpoint_vm_boots"] == 44
    assert plan.estimated["project_network_topology_generations"] == 23
    assert plan.estimated["networks_created"] == 30
    assert plan.estimated["routers_created"] == 25
    # External checks stay with their existing topology, including recovery;
    # the adaptive scheduler must not create another VM just to ping a target.
    assert all(s.phase == "intra" for s in plan.tests if s.operation == "egress")
    assert plan.estimated["peak_created_networks"] == 4
    assert plan.estimated["peak_created_routers"] == 2


def test_routing_group_pairing_avoids_full_cross_product(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    normal = [
        item
        for item in plan.tenant_groups
        if item.kind in {"project-network", "routing-unassigned-project-network"}
    ]
    assert len(normal) == 4
    relationships = [item.relationship for item in normal]
    assert relationships.count(TopologyPolicy.DIRECT) == 2
    assert relationships.count(TopologyPolicy.UNASSIGNED) == 2
    assert all(
        "matching address scope" in item.label.lower()
        for item in normal
        if item.relationship == TopologyPolicy.DIRECT
    )
    assert all(
        "direct" not in item.label.lower() and "isolated" not in item.label.lower()
        for item in normal
        if item.relationship == TopologyPolicy.UNASSIGNED
    )


def test_only_one_no_routing_group_topology_per_family(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    no_group = [
        item
        for item in plan.tenant_groups
        if item.relationship == TopologyPolicy.UNASSIGNED
        and item.kind in {"project-network", "routing-unassigned-project-network"}
    ]
    assert sorted(item.families[0] for item in no_group) == [4, 6]


def test_generated_control_cidrs_avoid_openstack_visible_cidrs(
    config_factory, discovery_fixture, tmp_path
):
    # Remove the naturally discovered no-routing-group paths so synthetic
    # controls are needed and can be validated.
    discovery_fixture.subnets = [
        item for item in discovery_fixture.subnets if item.id not in {"s2v6", "s3v4"}
    ]
    discovery_fixture.networks = [
        item for item in discovery_fixture.networks if item.id == "n1"
    ]
    discovery_fixture.occupied_cidrs.extend(["10.250.0.0/24", "10.32.0.0/24"])
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    ipv4 = next(
        item
        for item in plan.tenant_groups
        if item.kind == "private-translation-project-network"
        and not item.metadata.get("fip_peer_for")
    )
    assert ipv4.synthetic_cidr not in {"10.250.0.0/24", "10.32.0.0/24"}


def test_routed_provider_segments_are_separate_groups(
    config_factory, routed_discovery, tmp_path
):
    plan = build_plan(
        config_factory(include_no_routing_group_controls=False),
        routed_discovery,
        tmp_path,
    )
    assert len(plan.provider_groups) == 2
    assert {item.segment_id for item in plan.provider_groups} == {"seg-a", "seg-b"}
    assert all(len(item.subnet_ids) == 1 for item in plan.provider_groups)


def test_dynamic_ipv6_subnet_is_skipped_without_aborting_other_tests(
    config_factory, discovery_fixture, tmp_path
):
    discovery_fixture.subnet("s1v6").ipv6_address_mode = "slaac"
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    assert any(
        item["resource"] == "Public1/public1-ipv6"
        and "statically configured IPv6 only" in item["reason"]
        for item in plan.skipped
    )
    assert any(4 in group.families for group in plan.provider_groups)
    assert all("s1v6" not in group.subnet_ids for group in plan.provider_groups)


def test_same_subnet_protocols_cover_both_directions(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    group = plan.provider_groups[0]
    subnet_id = group.subnet_ids[0]
    selected = [
        item
        for item in plan.tests
        if item.category == "same-subnet"
        and item.source_group_id == group.id
        and item.source_subnet_id == subnet_id
    ]
    assert {
        (item.source_side, item.destination_side, item.protocol) for item in selected
    } == {
        ("A", "B", "icmp"),
        ("A", "B", "tcp"),
        ("A", "B", "udp"),
        ("B", "A", "icmp"),
        ("B", "A", "tcp"),
        ("B", "A", "udp"),
    }


def test_plan_has_mtu_boundary_local_limit_and_security_lifecycle_per_family(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    mtu = [item for item in plan.tests if item.category == "mtu"]
    assert sorted((item.family, item.protocol) for item in mtu) == [
        (4, "mtu"),
        (6, "mtu"),
    ]
    assert {item.operation for item in mtu} == {"mtu-scenario"}
    assert all(item.metadata["atomic_scenario"] for item in mtu)
    controls = [item for item in plan.tests if item.category == "security-group"]
    assert sorted((item.family, item.operation) for item in controls) == [
        (4, "security-allow"),
        (4, "security-deny"),
        (4, "security-restore"),
        (6, "security-allow"),
        (6, "security-deny"),
        (6, "security-restore"),
    ]


def test_fip_covers_every_eligible_topology_with_three_protocol_baselines(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    baseline = [item for item in plan.tests if item.category == "floating-ip"]
    lifecycle = [
        item for item in plan.tests if item.category == "floating-ip-lifecycle"
    ]
    destination_groups = {item.destination_group_id for item in baseline}
    assert destination_groups == {
        "private-translation-ipv4-external-s1v4",
        "private-translation-ipv4-external-s3v4",
    }
    assert len(baseline) == 3 * len(destination_groups)
    assert len(lifecycle) == 2 * len(destination_groups)
    assert {item.protocol for item in baseline} == {"icmp", "tcp", "udp"}
    assert {item.operation for item in baseline} == {"fip-baseline"}
    assert {item.operation for item in lifecycle} == {"fip-withdraw", "fip-return"}
    assert all(
        item.metadata["observer_mode"] == "controlled-provider"
        for item in baseline + lifecycle
    )
    assert all(
        item.metadata["coverage_scope"]
        == "every eligible disposable private IPv4 translation topology"
        for item in baseline + lifecycle
    )
    assert all(item.authoritative is True for item in baseline)
    assert all(item.authoritative is False for item in lifecycle)
    assert all(
        item.destination_group_id in item.dependencies for item in baseline + lifecycle
    )


def test_default_public_ipv4_egress_is_required(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    egress = [item for item in plan.tests if item.category == "egress"]
    ordinary = [s for s in egress if not s.metadata.get("server_start_recovery")]
    recovery = [s for s in egress if s.metadata.get("server_start_recovery")]
    assert len(ordinary) == 4
    assert len(recovery) == 2
    assert {s.metadata["target"] for s in recovery} == {"1.1.1.1", "8.8.8.8"}
    assert all(s.source_side == "B" and s.phase == "intra" for s in egress)
    assert {s.source_group_id for s in recovery} <= {
        group.id for group in plan.provider_groups
    }
    assert all(
        s.requires
        == [
            next(
                p.id
                for p in ordinary
                if p.metadata["target"] == s.metadata["target"]
                and p.source_group_id == s.source_group_id
            )
        ]
        and len(s.requires_pass) == 1
        for s in recovery
    )
    assert all(item.family == 4 for item in egress)
    assert all(
        item.expectation == "reachable" and item.authoritative for item in egress
    )


def test_configured_ula_target_is_required(config_factory, discovery_fixture, tmp_path):
    config = config_factory(
        ipv6_targets=["fd00:beef::1"],
        ipv6_targets_configured=True,
    )
    plan = build_plan(config, discovery_fixture, tmp_path)
    ipv6 = [
        item for item in plan.tests if item.category == "egress" and item.family == 6
    ]
    assert ipv6
    assert any(item.expectation == "reachable" and item.authoritative for item in ipv6)


def test_plan_has_exact_lifecycle_pairing(config_factory, discovery_fixture, tmp_path):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    assert {
        item.operation for item in plan.tests if item.category == "server-lifecycle"
    } == {
        "server-stop",
        "server-start",
    }
    router_lifecycle = [
        item for item in plan.tests if item.category == "router-interface-lifecycle"
    ]
    assert {item.operation for item in router_lifecycle} == {
        "router-lifecycle-scenario",
    }
    assert all(item.authoritative for item in router_lifecycle)
    assert {item.expectation for item in router_lifecycle} == {"lifecycle-complete"}
    assert all(item.metadata["atomic_scenario"] for item in router_lifecycle)
    assert all(len(item.dependencies) == 1 for item in router_lifecycle)


def test_quota_preflight_checks_instances_cores_and_ram(
    config_factory, discovery_fixture, tmp_path
):
    discovery_fixture.quota_info = {
        "instances": SimpleNamespace(available=100),
        "cores": SimpleNamespace(available=100),
        "ram": SimpleNamespace(available=100),
    }
    with pytest.raises(SuiteError, match="ram"):
        build_plan(config_factory(), discovery_fixture, tmp_path)


@pytest.mark.parametrize(
    "expectation,outcome,status",
    [
        ("reachable", "reachable", "PASS"),
        ("reachable", "blocked", "FAIL"),
        ("blocked", "blocked", "PASS"),
        ("blocked", "reachable", "FAIL"),
        ("withdrawn", "blocked", "PASS"),
        ("restored", "reachable", "PASS"),
    ],
)
def test_policy_evaluator_required_paths(expectation, outcome, status):
    spec = FluxTestSpec("t", "c", "probe", 4, expectation, "reason", True, [])
    probe = ProbeResult(outcome, outcome == "reachable", 1, 1)
    assert PolicyEvaluator().evaluate(spec, probe).status == status


def test_policy_evaluator_requires_authority_for_fip():
    spec = FluxTestSpec(
        id="fip",
        category="floating-ip",
        operation="fip-baseline",
        family=4,
        expectation="reachable",
        expectation_reason="same-subnet source is not authoritative",
        authoritative=False,
        dependencies=[],
        metadata={"authority_required": True},
    )
    probe = ProbeResult(
        outcome="blocked",
        success=False,
        elapsed_ms=1,
        attempts=1,
        destination_ip="203.0.113.10",
        protocol="tcp",
    )
    decision = PolicyEvaluator().evaluate(spec, probe)
    assert decision.status == "UNVERIFIED"
    assert decision.authoritative is False


def test_policy_evaluator_never_grades_without_authority():
    spec = FluxTestSpec("t", "c", "probe", 4, "reachable", "reason", False, [])
    probe = ProbeResult("blocked", False, 1, 1)
    assert PolicyEvaluator().evaluate(spec, probe).status == "UNVERIFIED"


def test_routing_group_policy_is_human_readable():
    direct = TopologyPolicy.project_expectation(
        TopologyPolicy.routing_relationship("s", "s"), 6
    )
    isolated = TopologyPolicy.project_expectation(
        TopologyPolicy.routing_relationship("a", "b"), 6
    )
    unassigned = TopologyPolicy.project_expectation(
        TopologyPolicy.routing_relationship(None, "b"), 6
    )
    assert direct.expectation == "reachable" and direct.authoritative is True
    assert "matching explicit address scopes" in direct.reason
    assert (
        isolated.expectation == "blocked"
        and "different explicit address scopes" in isolated.reason
    )
    assert unassigned.expectation == "observation" and unassigned.authoritative is False
    assert "neither fixed-IP reachability nor isolation" in unassigned.reason


def test_tcp_probe_binds_source_and_uses_dedicated_port():
    commands = []
    context = ProbeContext(
        lambda _ep, cmd: commands.append(cmd) or completed(),
        lambda cmd: completed(),
        18080,
        18081,
    )
    probe = TCPProbe(context).endpoint(endpoint(), "192.0.2.10", "192.0.2.11", 4)
    assert probe.success
    assert probe.diagnostics["destination_port"] == 18080
    assert "192.0.2.10" in commands[0]
    assert "18080" in commands[0]
    assert ",22))" not in commands[0]


def test_udp_probe_uses_token_echo_port():
    commands = []
    context = ProbeContext(
        lambda _ep, cmd: commands.append(cmd) or completed(),
        lambda cmd: completed(),
        18080,
        18081,
    )
    probe = UDPProbe(context).endpoint(endpoint(), "192.0.2.10", "192.0.2.11", 4)
    assert probe.success
    assert "18081" in commands[0]


def test_mtu_probe_calculates_family_header_difference():
    commands = []
    registry = ProbeRegistry(
        ProbeContext(
            lambda _ep, cmd: commands.append(cmd) or completed(),
            lambda cmd: completed(),
            18080,
            18081,
        )
    )
    v4 = registry.endpoint(
        "mtu", endpoint(), "192.0.2.10", "192.0.2.11", 4, network_mtu=1500
    )
    v6 = registry.endpoint(
        "mtu", endpoint(), "fd00::10", "fd00::11", 6, network_mtu=1500
    )
    assert v4.diagnostics["payload"] == 1472
    assert v6.diagnostics["payload"] == 1452


def test_runner_fip_probe_marks_outside_subnet_authoritative(monkeypatch):
    route = completed(stdout="203.0.113.10 via 192.0.2.1 dev eth0 src 192.0.2.50\n")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: route)
    fake_socket = mock.Mock()
    fake_socket.recv.return_value = b"nflux-placeholder"
    with (
        mock.patch(
            "neutron_flux.probes.uuid.uuid4",
            return_value=SimpleNamespace(hex="placeholder"),
        ),
        mock.patch("neutron_flux.probes.socket.socket", return_value=fake_socket),
    ):
        probe, authoritative = RunnerFIPProbe(
            ProbeContext(lambda e, c: completed(), lambda c: completed(), 18080, 18081)
        ).run("203.0.113.10", "203.0.113.0/24")
    assert authoritative is True
    assert probe.success is True
    assert probe.source_ip == "192.0.2.50"


def test_runner_probe_handles_missing_ip_command(monkeypatch):
    monkeypatch.setattr(subprocess, "run", mock.Mock(side_effect=FileNotFoundError))
    probe, authoritative = RunnerFIPProbe(
        ProbeContext(lambda e, c: completed(), lambda c: completed(), 18080, 18081)
    ).run("203.0.113.10", "203.0.113.0/24")
    assert probe.outcome == "error"
    assert authoritative is False


def test_probe_classification_never_turns_execution_failure_into_blocked():
    assert classify_command_outcome(127, "", "ping: command not found") == "error"
    assert classify_command_outcome(255, "", "stdio forwarding failed") == "error"
    assert classify_command_outcome(1, "", "TimeoutError: timed out") == "blocked"


def test_plan_includes_openstack_only_router_scenarios(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    scenarios = {item.scenario for item in plan.tests}
    assert "Routing between project networks through one Neutron router" in scenarios
    assert "Routing between two Neutron routers using static routes" in scenarios
    assert all("BGP" not in (item.display_name or "") for item in plan.tests)


def test_all_planned_results_have_human_names_and_no_inferred_path_labels(
    config_factory, discovery_fixture, tmp_path
):
    plan = build_plan(config_factory(), discovery_fixture, tmp_path)
    assert all(item.display_name and item.scenario for item in plan.tests)
    for item in plan.tests:
        visible = " ".join(
            [item.display_name or "", item.scenario or "", item.expectation_reason]
        ).lower()
        assert "direct l2" not in visible
        assert "direct l3" not in visible
        assert "routing-isolated" not in visible


def test_guest_network_verifier_is_read_only_and_checks_static_ipv6():
    captured = []
    verifier = GuestNetworkVerifier(
        lambda _subnet: {"cidr": "fd00::/64", "gateway": "fd00::1", "mtu": 1442}
    )
    details = {
        "interface": "ens4",
        "mtu": 1442,
        "addresses": [{"address": "fd00::10", "prefix_length": 64, "flags": []}],
        "routes": [],
        "errors": [],
    }
    verifier.verify(
        label="vm:A",
        mac_address="fa:16:3e:00:00:01",
        fixed_ips={"s6": "fd00::10"},
        executor=lambda command: (
            captured.append(command) or completed(stdout=json.dumps(details))
        ),
    )
    command = captured[0]
    assert (
        "ip -j" not in command
    )  # Python argv form is used instead of shell cloud_operation.
    assert "subprocess.run" in command
    assert "tentative" in command
    assert "dadfailed" in command
    assert "systemctl" not in command
    assert "/etc/" not in command
    assert "address add" not in command
    assert "route replace" not in command
    assert "rule add" not in command
    assert "sysctl" not in command


def test_same_subnet_result_records_compute_placement_and_warns_when_colocated():
    engine = object.__new__(FluxTestEngine)
    engine.policy = PolicyEvaluator()
    engine.diagnostics = mock.Mock()
    engine.reporter = mock.Mock()
    source = endpoint("source", "A")
    destination = endpoint("destination", "B")
    source.host = "compute1"
    destination.host = "compute1"
    spec = FluxTestSpec(
        id="SAME-4",
        category="same-subnet",
        operation="probe",
        family=4,
        expectation="reachable",
        expectation_reason="the source and destination use the same Neutron subnet",
        authoritative=True,
        dependencies=["group"],
        protocol="icmp",
        display_name="Provider subnet connectivity — IPv4 A to B ICMP",
        scenario="Provider subnet connectivity",
    )
    probe = ProbeResult(
        outcome="reachable",
        success=True,
        elapsed_ms=1,
        attempts=1,
        source_ip="192.0.2.10",
        destination_ip="192.0.2.11",
        protocol="icmp",
    )
    engine._record(spec, probe, source, destination)
    kwargs = engine.reporter.result.call_args.kwargs
    assert kwargs["details"]["compute_placement"] == "same compute host"
    assert kwargs["details"]["source_compute_host"] == "compute1"
    assert (
        "does not verify an inter-compute path"
        in engine.reporter.result.call_args.args[3]
    )


def test_probe_service_is_transient_and_writes_no_guest_configuration():
    commands = []
    manager = ProbeServiceManager(18080, 18081, startup_timeout=1)
    target = endpoint()

    def launch(_endpoint, command):
        commands.append(command)
        return FakeProbeProcess(
            "NEUTRON_FLUX_READY tcp=18080 control_tcp=18082 udp=18081 families=IPv4,IPv6\n"
        )

    manager.start(target, launch)
    command = commands[0]
    assert "neutron-flux-transient-probe" in command
    assert "exec python3 -u -c" in command
    assert "nohup" not in command
    assert "TCP_PORT = 18080" in command
    assert (
        "CONTROL_TCP_PORTS = {socket.AF_INET: 18082, socket.AF_INET6: 18082}" in command
    )
    assert "UDP_PORT = 18081" in command
    assert "NEUTRON_FLUX_READY" in command
    assert "systemctl" not in command
    assert "/etc/" not in command
    assert "/usr/local/" not in command
    assert "install -" not in command
    assert manager.is_running(target)
    assert manager.stop_all() == 1
    assert not manager.is_running(target)


def test_probe_service_raises_with_remote_startup_error():
    manager = ProbeServiceManager(18080, 18081, startup_timeout=1)
    with pytest.raises(
        SuiteError,
        match=r"Could not start the transient probe process.*Address already in use",
    ):
        manager.start(
            endpoint(),
            lambda _ep, _command: FakeProbeProcess(
                "NEUTRON_FLUX_ERROR OSError: [Errno 98] Address already in use\n"
            ),
        )
