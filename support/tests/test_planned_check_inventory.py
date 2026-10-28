"""Complete planning exercised through real reporters and runtime generators."""

from __future__ import annotations

import copy
import dataclasses
import json
import re
import threading
from collections import Counter
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from neutron_flux.check_ledger import check_ledger, finalize_checks, resolve_checks
from neutron_flux.check_plan import build_check_plan, describe_check_plan
from neutron_flux.errors import SuiteError
from neutron_flux.executor import AdaptiveExecutor
from neutron_flux.models import (
    ComputeHostInfo,
    MigrationResult,
    Plan,
    PlannedGroup,
    RuntimeGroup,
)
from neutron_flux.models import TestSpec as Spec
from neutron_flux.performance import PerformanceRunner, PerformanceSession
from neutron_flux.plan_contract import (
    create_plan_contract,
    load_plan_contract,
    plan_dict,
    plan_from_dict,
)
from neutron_flux.progress import progress_text, reporter_progress
from neutron_flux.reporting import Reporter
from neutron_flux.reporting_components.html import build_run_payload
from neutron_flux.utils import utc_now

from .test_performance_and_html import _endpoint


def network_plan(groups=("g",)):
    planned_groups, specs = [], []
    for group in groups:
        planned_groups.append(
            PlannedGroup(
                group, "provider", group, "network", "network", ["subnet"], [4]
            )
        )
        for protocol in ("icmp", "tcp", "udp"):
            for source, destination in (("A", "B"), ("B", "A")):
                specs.append(
                    Spec(
                        f"{group}-{protocol}-{source}{destination}",
                        "same-subnet",
                        "probe",
                        4,
                        "reachable",
                        "same subnet",
                        True,
                        [group],
                        source_group_id=group,
                        destination_group_id=group,
                        source_side=source,
                        destination_side=destination,
                        source_subnet_id="subnet",
                        destination_subnet_id="subnet",
                        protocol=protocol,
                        phase="intra",
                        display_name=f"{group} {protocol} {source}/{destination}",
                    )
                )
    return Plan(planned_groups, [], {}, [], tests=specs)


@pytest.fixture
def harness(config_factory):
    reporters = []

    def make(*, groups=("g",), **kwargs):
        config = config_factory(
            action="run",
            migration_mode="live-only",
            live_migration_continuity=True,
            **kwargs,
        )
        plan = network_plan(groups)
        build_check_plan(plan, config)
        reporter = Reporter(config, f"sample-{len(reporters)}")
        reporters.append(reporter)
        reporter.plan = plan
        reporter.save_plan()
        endpoints = {
            side: _endpoint(side, side, f"192.0.2.{10 + index}", f"compute{index + 1}")
            for index, side in enumerate(("A", "B"))
        }

        def emit(specs):
            for spec in specs:
                reporter.result(
                    spec.id,
                    spec.category,
                    "PASS",
                    "reachable",
                    family=spec.family,
                    expected=spec.expectation,
                    observed="reachable",
                    authoritative=True,
                    display_name=spec.display_name,
                    scenario=spec.scenario,
                )

        engine = SimpleNamespace(
            run_specs=emit,
            lifecycle={},
            _endpoint_address=lambda group_id, side, subnet_id: (
                endpoints[side],
                endpoints[side].fixed_ips["subnet"],
            ),
            _network_mtu=lambda group_id: 1500,
        )
        executor = AdaptiveExecutor.__new__(AdaptiveExecutor)
        executor.config, executor.plan, executor.reporter = config, plan, reporter
        executor.logger = reporter.logger
        executor._refresh_checkpoint = lambda: None
        executor.performance_session = PerformanceSession()
        executor.performance_lock = threading.RLock()
        executor.active = {
            group.id: RuntimeGroup(
                group,
                "network",
                "network",
                ["subnet"],
                None,
                list(endpoints.values()),
                None,
                {},
            )
            for group in plan.groups
        }
        executor.builder = SimpleNamespace()
        return config, plan, reporter, engine, executor, endpoints

    yield make
    for reporter in reporters:
        reporter.logger.close()


def fake_measurements(monkeypatch):
    monkeypatch.setattr(
        PerformanceRunner, "_resolve", lambda self, path: SimpleNamespace(plan=path)
    )
    monkeypatch.setattr(
        PerformanceRunner, "_local_probe_server", lambda *args: nullcontext()
    )
    monkeypatch.setattr(
        PerformanceRunner,
        "_measure",
        lambda self, resolved: ({name: {} for name, _ in self.MEASUREMENTS}, {}),
    )
    monkeypatch.setattr(
        PerformanceRunner,
        "_record_measurement",
        lambda self, spec, *args, **kwargs: self.reporter.result(
            spec.id,
            spec.category,
            "PASS",
            "Measured",
            expected=spec.expectation,
            observed="measurement-complete",
            authoritative=True,
        ),
    )


def test_upfront_inventory_lists_each_measurement_and_migration_branch(harness, capsys):
    config, plan, reporter, *_ = harness()
    assert Counter(row["kind"] for row in plan.checks) == {
        "network": 6,
        "performance": 14,
        "migration": 14,
    }
    assert len({row["id"] for row in plan.checks}) == 34
    assert reporter_progress(reporter)["planned"] == 34
    assert reporter_progress(reporter)["planned_recorded"] == 0
    describe_check_plan(plan, reporter.logger)
    output = capsys.readouterr().out
    assert (
        "Planned: 34 checks" in output
        and "port binding" in output
        and "Retries and samples" in output
    )
    roundtrip = plan_from_dict(plan_dict(plan))
    assert roundtrip.checks == plan.checks
    assert roundtrip.tests == plan.tests


@pytest.mark.parametrize("reverse_pass", [True, False])
def test_performance_binds_existing_checks_or_closes_failed_prerequisites(
    harness, monkeypatch, reverse_pass
):
    fake_measurements(monkeypatch)
    config, plan, reporter, engine, executor, _ = harness()
    original = copy.deepcopy(plan.checks)
    for spec in plan.tests:
        status = "FAIL" if not reverse_pass and spec.id == "g-tcp-BA" else "PASS"
        reporter.result(
            spec.id,
            spec.category,
            status,
            "TCP reverse failed" if status == "FAIL" else "reachable",
        )
    executor._run_performance(list(plan.tests), engine, stage="group-local")
    rows = [row for row in check_ledger(reporter) if row["stage"] == "group-local"]
    assert len(rows) == 7
    assert {row["outcome"] for row in rows} == (
        {"PASSED"} if reverse_pass else {"BLOCKED"}
    )
    if not reverse_pass:
        assert all("reverse" in row["reason"].lower() for row in rows)
    assert plan.checks == original
    assert reporter_progress(reporter)["planned"] == 34
    assert "additional" not in progress_text(reporter_progress(reporter))


def test_performance_cap_is_reserved_then_explained_without_changing_total(
    harness, monkeypatch
):
    fake_measurements(monkeypatch)
    config, plan, reporter, engine, executor, _ = harness(
        groups=("g", "h"), performance_max_paths=1
    )
    total = len(plan.checks)
    base = list(plan.tests)
    engine.run_specs(base)
    for group in ("g", "h"):
        executor._run_performance(
            [spec for spec in base if spec.dependencies == [group]],
            engine,
            stage="group-local",
        )
    rows = [row for row in check_ledger(reporter) if row["stage"] == "group-local"]
    assert Counter(row["outcome"] for row in rows) == {"PASSED": 7, "INAPPLICABLE": 7}
    assert all(
        "limit of 1" in row["reason"]
        for row in rows
        if row["outcome"] == "INAPPLICABLE"
    )
    assert reporter_progress(reporter)["planned"] == total


@pytest.mark.parametrize("target_available", [True, False])
def test_live_migration_and_safety_samples_never_expand_workload(
    harness, monkeypatch, target_available, capsys
):
    fake_measurements(monkeypatch)
    config, plan, reporter, engine, executor, endpoints = harness()
    original = copy.deepcopy(plan.checks)
    base = list(plan.tests)
    engine.run_specs(base)
    executor._run_performance(base, engine, stage="group-local")
    target = ComputeHostInfo("compute1", "az1", True, True)

    def migrate(moving, selected, stationary):
        old = moving.host
        moving.host = selected.host
        return MigrationResult(
            moving.server_id,
            old,
            selected.host,
            "az1",
            "az1",
            True,
            False,
            True,
            details={"migration_mode": "live", "continuity": {"state": "completed"}},
        )

    executor.builder = SimpleNamespace(
        select_compute_migration_target=lambda *args, **kwargs: (
            (target, "eligible")
            if target_available
            else (None, "no eligible destination host")
        ),
        live_migrate_endpoint=migrate,
        cloud_operation_coordinator=SimpleNamespace(
            annotate_current_transaction=lambda **kwargs: None
        ),
    )
    executor._run_compute_placement_validation(base, engine, dependencies=("g",))
    finalize_checks(reporter)
    rows = check_ledger(reporter)
    assert all(row["outcome"] != "PENDING" for row in rows)
    assert plan.checks == original
    progress = reporter_progress(reporter)
    assert progress["planned"] == progress["planned_recorded"] == 34
    output = capsys.readouterr().out
    fractions = re.findall(r"Progress: (\d+)/(\d+)", output)
    assert {denominator for _, denominator in fractions} == {"34"}
    assert [int(n) for n, _ in fractions] == sorted(int(n) for n, _ in fractions)
    if target_available:
        assert "Supporting sample [PASS]" in output
        assert len(reporter.results) > len(plan.checks)
        safety = next(row for row in rows if "fresh migration safety" in row["title"])
        assert safety["outcome"] == "PASSED"
        assert (
            len(safety["evidence_ids"]) == 7
        )  # One fresh six-path matrix plus its assessment
        assert all(
            row["outcome"] == "PASSED"
            for row in rows
            if row["stage"] == "post-live-migration"
        )
    else:
        assert all(
            "no eligible destination host" in row["reason"]
            for row in rows
            if row["stage"] == "post-migration"
        )


def test_unplanned_work_is_rejected_before_execution(harness):
    _, plan, reporter, *_ = harness()
    rogue = dataclasses.replace(plan.tests[0], id="ROGUE", metadata={})
    plan.tests.append(rogue)
    with pytest.raises(SuiteError, match="Unplanned check ROGUE"):
        reporter.save_plan()
    plan.tests.pop()
    with pytest.raises(SuiteError, match="Unplanned result ROGUE"):
        reporter.result("ROGUE", "same-subnet", "PASS", "should not be accepted")


@pytest.mark.parametrize("mode", ["cancel", "setup-error"])
def test_terminal_run_accounts_for_unreached_conditions(harness, mode):
    _, plan, reporter, *_ = harness()
    if mode == "cancel":
        reporter.interrupted = True
        reporter.cancellation_reason = "operator stopped the run"
    else:
        reporter.error = "VM preparation failed"
        reporter.setup_failed = True
    finalize_checks(reporter)
    rows = check_ledger(reporter)
    assert {row["outcome"] for row in rows} == (
        {"CANCELLED"} if mode == "cancel" else {"BLOCKED"}
    )
    assert reporter_progress(reporter)["planned_recorded"] == len(plan.checks)
    assert reporter_progress(reporter)["planned_executed"] == 0


def test_plan_and_completed_conditions_survive_restart(harness):
    config, plan, reporter, engine, *_ = harness()
    engine.run_specs(list(plan.tests))
    host_check = next(row["id"] for row in plan.checks if row["stage"] == "placement")
    resolve_checks(reporter, {host_check: ("PASSED", "Both host identities are known")})
    reporter.interrupted = True
    reporter.cancellation_reason = "stopped"
    finalize_checks(reporter)
    reporter.logger.close()
    resumed = Reporter(
        dataclasses.replace(config, resume_run_id=reporter.run_id),
        reporter.run_id,
        load_existing=True,
    )
    try:
        resumed.plan = plan_from_dict(plan_dict(plan))
        resumed.save_plan()
        progress = reporter_progress(resumed)
        assert progress["planned"] == 34
        assert progress["planned_recorded"] == 7
        assert progress["pending"] == 27
        assert (
            next(row for row in check_ledger(resumed) if row["id"] == host_check)[
                "outcome"
            ]
            == "PASSED"
        )
    finally:
        resumed.logger.close()


def test_json_and_dashboard_use_same_complete_inventory(harness):
    _, plan, reporter, *_ = harness()
    finalize_checks(reporter)
    payload = build_run_payload(
        reporter, final_status="BLOCKED", finished=utc_now(), counts=Counter()
    )
    assert len(payload["planned_check_ledger"]) == len(plan.checks)
    assert payload["summary"]["test_progress"] == reporter_progress(reporter)
    assert payload["dashboard"]["coverage_matrix"]["total"] == len(plan.checks)
    json.dumps(payload, allow_nan=False)


def test_approved_contract_rejects_changed_inventory(harness, discovery_fixture):
    config, plan, reporter, *_ = harness()
    reporter.plan_contract = create_plan_contract(config, discovery_fixture, plan, {})
    reporter.save_plan()
    contract, loaded = load_plan_contract(reporter.plan_path)
    assert loaded.checks == plan.checks
    assert contract["plan"]["checks"] == plan.checks
    plan.checks.append({**plan.checks[0], "id": "EXTRA"})
    with pytest.raises(SuiteError, match="approved check inventory changed"):
        reporter.save_plan()


def test_simultaneous_zone_lanes_share_fixed_inventory(config_factory, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    from neutron_flux.check_plan import copy_bindings
    from neutron_flux.models import ZoneExecutionPlan
    from neutron_flux.multi_zone import aggregate_plan, clone_plan_for_zone, zone_scope
    from neutron_flux.reporting import ScopedReporter

    fake_measurements(monkeypatch)
    config = config_factory(
        action="run", migration_mode="live-only", live_migration_continuity=True
    )
    base = network_plan()
    zones = ZoneExecutionPlan(["az1", "az2"], "both", {}, True, 2)
    aggregate = aggregate_plan(base, zones, config)
    build_check_plan(aggregate, config)
    parent = Reporter(config, "sample-zones")
    parent.plan = aggregate
    parent.save_plan()
    total = len(aggregate.checks)
    approved = {spec.id: spec for spec in aggregate.tests}

    def lane(zone):
        reporter = ScopedReporter(parent, zone_scope(zone), availability_zone=zone)
        plan = clone_plan_for_zone(base, zone)
        for spec in plan.tests:
            copy_bindings(spec, approved[reporter.scoped_test_id(spec.id)])
        reporter.plan = plan
        reporter.save_plan()
        for spec in plan.tests:
            reporter.result(spec.id, spec.category, "PASS", "reachable")
        endpoints = {
            side: _endpoint(f"{zone}-{side}", side, f"192.0.2.{10 + index}", "compute")
            for index, side in enumerate(("A", "B"))
        }
        engine = SimpleNamespace(
            _endpoint_address=lambda group, side, subnet: (
                endpoints[side],
                endpoints[side].fixed_ips["subnet"],
            )
        )
        runner = PerformanceRunner(config, SimpleNamespace(), reporter, engine)
        specs = runner.plan_specs(plan.tests, stage="group-local")
        plan.tests.extend(specs)
        reporter.save_plan()
        runner.run_specs(specs)
        return {spec.metadata["planned_check_id"] for spec in specs}

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            a, b = list(pool.map(lane, zones.zones))
        assert len(a) == len(b) == 7 and a.isdisjoint(b)
        progress = reporter_progress(parent)
        assert progress["planned"] == total
        assert progress["planned_recorded"] == 26
        assert progress["outcomes"] == {"PASSED": 26, "PENDING": total - 26}
    finally:
        parent.logger.close()


@pytest.mark.parametrize(
    "profile,strategy",
    [("full", "rolling"), ("connectivity", "rolling"), ("performance", "stable")],
)
def test_complete_host_pair_scopes_respect_profile_and_strategy(
    config_factory, discovery_fixture, tmp_path, profile, strategy
):
    from neutron_flux.pair_suite import pair_scope_plans

    from .test_full_pair_suite import full_plan

    config, _, plan = full_plan(
        config_factory,
        discovery_fixture,
        tmp_path,
        qualification_profile=profile,
        qualification_strategy=strategy,
        migration_mode="live-only",
        live_migration_continuity=True,
        fabric_scale_enabled=True,
    )
    build_check_plan(plan, config)
    assert len({row["id"] for row in plan.checks}) == len(plan.checks)
    assert len(pair_scope_plans(plan)) == 4
    transitions = [spec for spec in plan.tests if spec.operation == "pair-transition"]
    assert len(transitions) == len({s.metadata["workflow_batch"] for s in transitions})
    assert all(s.metadata["pair_placement"] == "opposite" for s in transitions)
    if profile == "connectivity":
        assert {row["kind"] for row in plan.checks} == {"network", "migration"}
    else:
        assert any(row["kind"] == "performance" for row in plan.checks)
    # Coordinated transitions own placement, including stable qualification.
    assert not any(
        s.metadata.get("check_bindings", {}).get("placement") for s in plan.tests
    )
    assert not any(row["stage"] == "post-live-migration" for row in plan.checks)
    payload = plan_dict(plan)
    # Within the existing bounded plan loader limit, including a substantial host matrix.
    assert len(json.dumps(payload).encode()) < 16 * 1024 * 1024
    before = copy.deepcopy(plan.checks)
    build_check_plan(plan, config)
    assert plan.checks == before


@pytest.mark.parametrize(
    "performance,placement", [(False, False), (False, True), (True, False)]
)
def test_disabled_features_do_not_inflate_plan(harness, performance, placement):
    _, plan, *_ = harness(
        performance_enabled=performance, compute_host_connectivity_enabled=placement
    )
    counts = Counter(row["kind"] for row in plan.checks)
    assert bool(counts["performance"]) == performance
    assert bool(counts["migration"]) == placement


def test_selected_tests_suppress_derived_work(config_factory):
    config = config_factory(test_ids=["g-tcp-AB"])
    plan = network_plan()
    build_check_plan(plan, config)
    assert all(row["kind"] == "network" for row in plan.checks)


def test_floating_ip_has_six_forward_only_planned_measurements(config_factory):
    config = config_factory(action="run", compute_host_connectivity_enabled=False)
    plan = network_plan()
    spec = dataclasses.replace(
        plan.tests[0],
        id="FIP",
        operation="fip-baseline",
        protocol="tcp",
        source_group_id=None,
        source_side="runner",
    )
    plan.tests = [spec]
    build_check_plan(plan, config)
    perf = [row for row in plan.checks if row["kind"] == "performance"]
    assert len(perf) == 6
    assert all(row["measurement"] != "asymmetry" for row in perf)
    assert set(
        spec.metadata["check_bindings"]["performance"]["group-local"].values()
    ) == {row["id"] for row in perf}


def test_cross_group_failed_baseline_is_preplanned(harness):
    config, plan, reporter, engine, executor, endpoints = harness(groups=("g", "h"))
    base = network_plan(("g", "h"))
    cross = dataclasses.replace(
        base.tests[0],
        id="CROSS",
        phase="cross",
        dependencies=["g", "h"],
        source_group_id="g",
        destination_group_id="h",
        source_side="A",
        destination_side="B",
    )
    base.tests = [cross]
    build_check_plan(base, config)
    reporter.plan = executor.plan = base
    reporter.save_plan()
    reporter.result(cross.id, cross.category, "FAIL", "No connectivity")
    executor._run_compute_placement_validation([cross], engine, dependencies=("g", "h"))
    assert len(base.checks) == 3
    assert reporter_progress(reporter)["planned_recorded"] == 3
    assert {row["outcome"] for row in check_ledger(reporter)} == {
        "FAILED",
        "PASSED",
        "BLOCKED",
    }


def test_safety_probe_failure_is_evidence_under_one_blocked_check(harness):
    config, plan, reporter, engine, executor, endpoints = harness(
        performance_enabled=False
    )
    base = list(plan.tests)
    engine.run_specs(base)
    target = ComputeHostInfo("compute1", "az1", True, True)
    submitted = []
    executor.builder = SimpleNamespace(
        select_compute_migration_target=lambda *args, **kwargs: (target, "eligible"),
        live_migrate_endpoint=lambda *args: submitted.append(True),
        cloud_operation_coordinator=SimpleNamespace(
            annotate_current_transaction=lambda **kwargs: None
        ),
    )

    def fail_round(specs):
        for spec in specs:
            reporter.result(
                spec.id,
                spec.category,
                "FAIL",
                "UDP packets were not delivered",
                observed="unreachable",
            )

    engine.run_specs = fail_round
    executor._run_compute_placement_validation(base, engine, dependencies=("g",))
    rows = check_ledger(reporter)
    gate = next(row for row in rows if "fresh migration safety" in row["title"])
    assert gate["outcome"] == "BLOCKED" and gate["evidence_ids"]
    assert not submitted
    assert len(rows) == reporter_progress(reporter)["planned_recorded"]


@pytest.mark.parametrize("mode", ["live-preferred", "live-only", "cold-only"])
def test_connectivity_safety_failure_reports_no_migration_submission(harness, mode):
    config, plan, reporter, engine, executor, endpoints = harness(
        performance_enabled=False
    )
    config.migration_mode = mode
    mtu = dataclasses.replace(
        plan.tests[0],
        id="provider-mtu",
        operation="mtu-scenario",
        protocol="mtu",
        category="mtu",
        expectation="boundary-confirmed",
        metadata={},
        display_name="Provider MTU boundary",
    )
    plan.tests.append(mtu)
    plan.checks = []
    build_check_plan(plan, config)
    reporter.save_plan()
    base = list(plan.tests)
    engine.run_specs(base)
    submitted = []
    executor.builder = SimpleNamespace(
        select_compute_migration_target=lambda *args, **kwargs: (
            ComputeHostInfo("compute1", "az1", True, True),
            "eligible",
        ),
        live_migrate_endpoint=lambda *args: submitted.append("live"),
        cold_migrate_endpoint=lambda *args: submitted.append("cold"),
        cloud_operation_coordinator=SimpleNamespace(
            annotate_current_transaction=lambda **kwargs: None
        ),
    )
    failure = "UDP packets were not delivered"

    def safety_round(specs):
        for spec in specs:
            reporter.result(
                spec.id,
                spec.category,
                "FAIL" if spec.protocol == "udp" else "PASS",
                failure if spec.protocol == "udp" else "reachable",
                display_name=spec.display_name,
                observed="unreachable" if spec.protocol == "udp" else "reachable",
            )

    engine.run_specs = safety_round
    executor._run_compute_placement_validation(base, engine, dependencies=("g",))
    assert submitted == []
    controls = mtu.metadata["check_bindings"]["placement"]
    expected = [controls["MIGRATION"]]
    if mode != "cold-only":
        expected.append(controls["LIVE-MIGRATION"])
    for row in check_ledger(reporter):
        if row["id"] in expected:
            assert row["outcome"] == "BLOCKED"
            assert "not submitted" in row["reason"]
            assert "UDP packets were not delivered" in row["reason"]
            result = reporter.get_result(row["result_id"])
            assert result.details["cloud_operation_outcome"] == "NOT_SUBMITTED"
            assert result.details["lifecycle_cloud_operation_performed"] is False
    gate = next(
        r
        for r in check_ledger(reporter)
        if r["id"] == controls["MIGRATION-FUNCTIONAL-BASELINE"]
    )
    assert "UDP packets were not delivered" in gate["reason"]


@pytest.mark.parametrize(
    "expected,authoritative", [("observation", False), ("blocked", True)]
)
@pytest.mark.parametrize("cross_group", [False, True])
def test_observation_and_isolation_paths_have_no_reachable_baseline_checks(
    config_factory, expected, authoritative, cross_group
):
    plan = network_plan(("a", "b"))
    plan.tests = [
        dataclasses.replace(
            spec,
            expectation=expected,
            authoritative=authoritative,
            dependencies=["a", "b"] if cross_group else ["a"],
            source_group_id="a",
            destination_group_id="b" if cross_group else "a",
            phase="cross" if cross_group else "intra",
        )
        for spec in plan.tests[:6]
    ]
    build_check_plan(plan, config_factory(migration_mode="live-preferred"))
    controls = plan.tests[0].metadata["check_bindings"]["placement"]
    assert set(controls) == {"HOST-DISCOVERY"}
    assert not any("baseline" in row["title"] for row in plan.checks)
    assert not any(row["kind"] == "performance" for row in plan.checks)


@pytest.mark.parametrize("mode", ["live-preferred", "live-only", "cold-only"])
@pytest.mark.parametrize("mtu_status", ["PASS", "FAIL", "UNVERIFIED"])
def test_mtu_observation_does_not_block_migration_or_post_migration_checks(
    harness, monkeypatch, mode, mtu_status
):
    monkeypatch.setattr(
        "neutron_flux.execution.placement_migration.time.sleep", lambda _: None
    )
    fake_measurements(monkeypatch)
    config, plan, reporter, engine, executor, endpoints = harness()
    config.migration_mode = mode
    mtu_spec = dataclasses.replace(
        plan.tests[0],
        id="atomic-mtu",
        operation="mtu-scenario",
        protocol="mtu",
        category="mtu",
        expectation="mtu-behavior-assessed",
        metadata={},
    )
    plan.tests.append(mtu_spec)
    plan.checks = []
    build_check_plan(plan, config)
    reporter.save_plan()
    base = list(plan.tests)
    planned_count = len(plan.checks)
    calls = []

    def emit(specs):
        calls.extend(specs)
        for spec in specs:
            is_mtu = spec.operation == "mtu-scenario"
            reporter.result(
                spec.id,
                spec.category,
                mtu_status if is_mtu else "PASS",
                "Advertised 1500, observed 1442 bytes" if is_mtu else "reachable",
                expected=spec.expectation,
                observed="path-mtu-below-advertised" if is_mtu else "reachable",
                details={"health": "warning", "mtu_advisory": True} if is_mtu else {},
            )

    engine.run_specs = emit
    engine.run_specs(base)
    executor._run_performance(base, engine, stage="group-local")
    submitted = []

    def migrate(moving, selected, stationary=None):
        kind = "cold" if mode == "cold-only" else "live"
        submitted.append(kind)
        old = moving.host
        moving.host = selected.host
        return MigrationResult(
            moving.server_id,
            old,
            selected.host,
            "az1",
            "az1",
            True,
            kind == "cold",
            True,
            details={"migration_mode": kind, "continuity": {"state": "completed"}},
        )

    executor.builder = SimpleNamespace(
        select_compute_migration_target=lambda *args, **kwargs: (
            ComputeHostInfo("compute1", "az1", True, True),
            "eligible",
        ),
        live_migrate_endpoint=migrate,
        cold_migrate_endpoint=migrate,
        cloud_operation_coordinator=SimpleNamespace(
            annotate_current_transaction=lambda **kwargs: None
        ),
    )
    executor._run_compute_placement_validation(base, engine, dependencies=("g",))
    finalize_checks(reporter)
    rows = check_ledger(reporter)
    assert submitted == ["cold" if mode == "cold-only" else "live"]
    controls = mtu_spec.metadata["check_bindings"]["placement"]
    by_id = {row["id"]: row for row in rows}
    assert by_id[controls["MIGRATION"]]["outcome"] == "PASSED"
    gate = by_id[controls["MIGRATION-FUNCTIONAL-BASELINE"]]
    assert gate["outcome"] == "PASSED"
    gate_result = next(
        item
        for item in reversed(reporter.results)
        if item.scenario == "Compute migration safety barrier"
        and item.observed == "fresh-functional-matrix"
    )
    assert gate_result.details["protocols"] == ["icmp", "tcp", "udp"]
    assert len(gate_result.details["rounds"]) == 1
    assert not any(
        spec.protocol == "mtu" and spec.metadata.get("pre_migration_functional_barrier")
        for spec in calls
    )
    assert len([spec for spec in calls if spec.operation == "mtu-scenario"]) == 2
    post = by_id[mtu_spec.metadata["check_bindings"]["post-migration"]]
    assert (
        post["outcome"]
        == {"PASS": "PASSED", "FAIL": "FAILED", "UNVERIFIED": "UNVERIFIED"}[mtu_status]
    )
    assert not any(row["outcome"] == "BLOCKED" for row in rows)
    assert all(
        row["outcome"] == "PASSED"
        for row in rows
        if row["stage"] == "post-live-migration" and mode != "cold-only"
    )
    assert len(plan.checks) == planned_count
    for check in plan.checks:
        if (
            check["id"] in controls.values()
            and check["id"] != controls["HOST-DISCOVERY"]
        ):
            assert "atomic-mtu" not in check["prerequisites"]


def test_load_levels_are_one_declared_check(harness, monkeypatch):
    from neutron_flux.concurrent_load import ConcurrentLoadRunner

    config, plan, reporter, _, executor, _ = harness(fabric_scale_enabled=True)
    load_checks = [row for row in plan.checks if row["kind"] == "load"]
    assert len(load_checks) == 1
    executor.cleanup_manager = SimpleNamespace()
    runner = ConcurrentLoadRunner(executor)
    append = executor._append_runtime_specs

    class Registered(Exception):
        pass

    def register(specs):
        append(specs)
        raise Registered

    monkeypatch.setattr(executor, "_append_runtime_specs", register)
    with pytest.raises(Registered):
        runner.run()
    registered = [
        spec
        for spec in plan.tests
        if spec.operation == "performance-concurrent-path-load"
    ]
    assert len(registered) == 1
    assert registered[0].metadata["planned_check_id"] == load_checks[0]["id"]
    assert reporter_progress(reporter)["planned"] == len(plan.checks)


def test_resume_replays_finished_baseline_when_conditional_work_is_unfinished(
    harness, monkeypatch
):
    from neutron_flux.check_resume import prepare_check_resume

    fake_measurements(monkeypatch)
    config, plan, reporter, engine, executor, _ = harness()
    base = list(plan.tests)
    engine.run_specs(base)
    total = len(plan.checks)
    executor.config = dataclasses.replace(config, resume_run_id=reporter.run_id)
    prepare_check_resume(executor)
    rechecks = [spec for spec in plan.tests if spec.metadata.get("resume_recheck")]
    assert len(rechecks) == 6
    assert {spec.metadata["planned_check_id"] for spec in rechecks} == {
        spec.id for spec in base
    }
    engine.run_specs(rechecks)
    executor._run_performance(rechecks, engine, stage="group-local")
    assert reporter_progress(reporter)["planned"] == total
    assert reporter_progress(reporter)["planned_recorded"] == 13
    assert all(
        row["outcome"] == "PASSED"
        for row in check_ledger(reporter)
        if row["stage"] == "group-local"
    )


@pytest.mark.parametrize("host_pairs", [False, True])
def test_generated_topologies_bind_every_performance_and_post_migration_candidate(
    config_factory, discovery_fixture, tmp_path, monkeypatch, host_pairs
):
    from collections import defaultdict

    from neutron_flux.check_ledger import validate_check_bindings
    from neutron_flux.check_plan import batch_key

    from ._shared import build_plan
    from .test_full_pair_suite import full_plan

    if host_pairs:
        config, _, plan = full_plan(
            config_factory,
            discovery_fixture,
            tmp_path,
            action="run",
            migration_mode="live-only",
            live_migration_continuity=True,
        )
    else:
        config = config_factory(
            action="run", migration_mode="live-only", live_migration_continuity=True
        )
        plan = build_plan(config, discovery_fixture, tmp_path)
    build_check_plan(plan, config)
    original = copy.deepcopy(plan.checks)
    reporter = Reporter(config, "sample-generated")
    reporter.plan = plan
    reporter.save_plan()

    def validate_runtime_plan():
        validate_check_bindings(plan)
        reporter._check_binding_cache = None

    # Exercise real generators without rewriting a large file per batch.
    monkeypatch.setattr(reporter, "save_plan", validate_runtime_plan)
    endpoints = (
        _endpoint("a", "A", "192.0.2.10", "compute1"),
        _endpoint("b", "B", "192.0.2.11", "compute2"),
    )
    monkeypatch.setattr(
        PerformanceRunner,
        "_resolve_endpoints",
        lambda *args: (*endpoints, "192.0.2.10", "192.0.2.11", None),
    )
    engine = SimpleNamespace(
        lifecycle={
            f"fip:{group.id}": {"id": group.id, "authoritative": True, "baseline": True}
            for group in plan.groups
        }
    )
    executor = AdaptiveExecutor.__new__(AdaptiveExecutor)
    executor.plan, executor.reporter = plan, reporter
    executor._refresh_checkpoint = lambda: None
    batches = defaultdict(list)
    for spec in list(plan.tests):
        reporter.result(
            spec.id,
            spec.category,
            "PASS",
            "Authoritative fixture observation",
            emit_console=False,
        )
        if spec.dependencies and spec.phase in {"intra", "cross"}:
            batches[batch_key(spec)].append(spec)
    measured = 0
    try:
        for specs in batches.values():
            stage = "group-local" if specs[0].phase == "intra" else "cross-topology"
            runner = PerformanceRunner(config, SimpleNamespace(), reporter, engine)
            performance_specs = runner.plan_specs(specs, stage=stage)
            executor._append_runtime_specs(performance_specs)
            measured += len(performance_specs)
            if (
                specs[0]
                .metadata.get("check_bindings", {})
                .get("placement", {})
                .get("MIGRATION")
            ):
                migrated = executor._placement_probe_specs(
                    specs,
                    relation="intra-compute",
                    source=endpoints[0],
                    destination=endpoints[1],
                )
                executor._append_runtime_specs(migrated)
                for spec in migrated:
                    reporter.result(
                        spec.id,
                        spec.category,
                        "PASS",
                        "Post migration observation",
                        emit_console=False,
                    )
                runner = PerformanceRunner(config, SimpleNamespace(), reporter, engine)
                performance_specs = runner.plan_specs(
                    migrated, stage="post-live-migration"
                )
                executor._append_runtime_specs(performance_specs)
                measured += len(performance_specs)
        validate_check_bindings(plan)
        assert measured > 0
        assert plan.checks == original
        assert reporter_progress(reporter)["planned"] == len(original)
    finally:
        reporter.logger.close()


def test_lane_diagnostic_is_evidence_without_changing_assessment(harness):
    _, plan, reporter, engine, *_ = harness()
    engine.run_specs([plan.tests[0]])
    before = reporter_progress(reporter)
    reporter.result(
        "LANE-EXECUTION-ERROR",
        "execution-control",
        "ERROR",
        "Lane stopped during release",
        details={
            "planned_check_id": plan.tests[0].id,
            "check_sample": True,
            "root_lane_error": True,
            "tool_failure": True,
        },
    )
    assert reporter_progress(reporter) == before
    row = check_ledger(reporter)[0]
    assert "LANE-EXECUTION-ERROR" in row["evidence_ids"]
    assert row["outcome"] == "PASSED"


def test_hidden_nova_placement_explains_downstream_blocks(harness):
    _, plan, reporter, engine, executor, endpoints = harness(performance_enabled=False)
    base = list(plan.tests)
    engine.run_specs(base)
    for endpoint in endpoints.values():
        endpoint.host = None
    executor._run_compute_placement_validation(base, engine, dependencies=("g",))
    blocked = [row for row in check_ledger(reporter) if row["outcome"] == "BLOCKED"]
    assert blocked
    assert all(
        "Nova did not expose compute-host placement" in row["reason"] for row in blocked
    )
    assert reporter_progress(reporter)["planned_recorded"] == len(plan.checks)


def test_resuming_only_load_does_not_repeat_finished_network_checks(harness):
    from neutron_flux.check_resume import prepare_check_resume

    config, plan, reporter, engine, executor, _ = harness(fabric_scale_enabled=True)
    engine.run_specs(list(plan.tests))
    resolve_checks(
        reporter,
        {
            row["id"]: ("PASSED", "Already assessed")
            for row in plan.checks
            if row["kind"] not in {"network", "load"}
        },
    )
    before = len(plan.tests)
    executor.config = dataclasses.replace(config, resume_run_id=reporter.run_id)
    prepare_check_resume(executor)
    assert len(plan.tests) == before
    assert reporter_progress(reporter)["pending"] == 1
