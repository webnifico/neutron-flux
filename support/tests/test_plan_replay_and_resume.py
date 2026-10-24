from __future__ import annotations

import dataclasses
import json
import subprocess
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.capability_preflight import CapabilityPreflight
from neutron_flux.cli import _hydrate_config_from_plan
from neutron_flux.coverage_ledger import (
    build_coverage_ledger,
    materialize_missing_results,
)
from neutron_flux.errors import SuiteError
from neutron_flux.models import (
    HostQualificationHost,
    HostQualificationPair,
    HostQualificationPlan,
    Plan,
    PlannedGroup,
    QuotaInfo,
)
from neutron_flux.models import (
    TestResult as FluxTestResult,
)
from neutron_flux.models import (
    TestSpec as FluxTestSpec,
)
from neutron_flux.plan_contract import (
    attach_runtime_plan,
    create_plan_contract,
    drift_diff,
    format_drift,
    load_plan_contract,
    verify_plan_contract,
)
from neutron_flux.reporting import Reporter


def _qualification(*, cycles: int = 2) -> HostQualificationPlan:
    return HostQualificationPlan(
        enabled=True,
        generated_at="2026-07-26T00:00:00Z",
        inventory_fingerprint="a" * 64,
        strategy="rolling",
        profile="full",
        cycles=cycles,
        include_same_host=False,
        resolved_aggregate_ids=["42"],
        resolved_aggregate_names=["edge"],
        hosts=[
            HostQualificationHost(
                "compute1",
                "az1",
                True,
                True,
                aggregate_ids=["42"],
                aggregate_names=["edge"],
                service_ids=["service-1"],
            ),
            HostQualificationHost(
                "compute2",
                "az2",
                True,
                True,
                service_ids=["service-2"],
            ),
        ],
        pairs=[
            HostQualificationPair(
                "HQ-PAIR",
                "compute1",
                "compute2",
                "az1",
                "az2",
                False,
                False,
                "independent-cross-az",
            )
        ],
    )


def _plan(*, qualification: bool = True) -> Plan:
    group = PlannedGroup(
        "provider-public1",
        "provider",
        "Public1",
        "n1",
        "Public1",
        ["s1v4"],
        [4],
    )
    spec = FluxTestSpec(
        id="PROVIDER-IPV4-A-TO-B",
        category="provider-subnet",
        operation="probe",
        family=4,
        expectation="reachable",
        expectation_reason="provider peers should communicate",
        authoritative=True,
        dependencies=[group.id],
        source_group_id=group.id,
        destination_group_id=group.id,
        source_side="A",
        destination_side="B",
        protocol="icmp",
        phase="intra",
        display_name="Provider IPv4 reachability",
    )
    return Plan(
        [group],
        [],
        {
            "peak_instances": 4,
            "peak_cores": 4,
            "peak_ram_mb": 2048,
            "peak_ports": 8,
            "peak_volumes": 0,
        },
        [],
        tests=[spec],
        host_qualification=_qualification() if qualification else None,
    )


def _contract(config, discovery_fixture):
    discovery = dataclasses.replace(
        discovery_fixture,
        cloud="recorded-cloud",
        network_extensions=["external-net", "port-security", "standard-attr-tag"],
        quota_info={
            name: QuotaInfo(name, 100, 1)
            for name in ("instances", "cores", "ram", "ports", "volumes")
        },
    )
    return create_plan_contract(config, discovery, _plan())


def test_immutable_plan_round_trip_and_runtime_resume(
    config_factory,
    discovery_fixture,
    tmp_path,
):
    config = config_factory(
        action="plan",
        target_hosts=["compute1", "compute2"],
        qualification_cycles=2,
        performance_enabled=True,
    )
    plan = _plan()
    contract = _contract(config, discovery_fixture)
    saved = attach_runtime_plan(contract, plan)
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(saved), encoding="utf-8")

    approved, approved_plan = load_plan_contract(path)
    resumed, runtime_plan = load_plan_contract(path, prefer_runtime_plan=True)

    assert approved["fingerprint"] == resumed["fingerprint"]
    assert approved_plan.host_qualification.generated_at is None
    assert runtime_plan.host_qualification.generated_at == "2026-07-26T00:00:00Z"
    assert runtime_plan.tests[0].id == "PROVIDER-IPV4-A-TO-B"


def test_plan_tampering_and_runtime_tampering_are_rejected(
    config_factory,
    discovery_fixture,
    tmp_path,
):
    contract = attach_runtime_plan(
        _contract(config_factory(), discovery_fixture),
        _plan(),
    )
    path = tmp_path / "plan.json"
    contract["configuration"]["flavor"] = "tampered"
    path.write_text(json.dumps(contract), encoding="utf-8")
    with pytest.raises(SuiteError, match="fingerprint mismatch"):
        load_plan_contract(path)

    contract = attach_runtime_plan(
        _contract(config_factory(), discovery_fixture),
        _plan(),
    )
    contract["runtime_plan"]["estimated"]["peak_instances"] = 999
    path.write_text(json.dumps(contract), encoding="utf-8")
    with pytest.raises(SuiteError, match="runtime plan fingerprint mismatch"):
        load_plan_contract(path, prefer_runtime_plan=True)


def test_plan_drift_is_exact_and_human_readable(
    config_factory,
    discovery_fixture,
):
    approved = _contract(config_factory(), discovery_fixture)
    current = json.loads(json.dumps(approved))
    current["configuration"]["flavor"] = "x2.large"
    current["inventory"]["networks"][0]["mtu"] = 1450
    current["inventory"]["hosts"][0]["availability_zone"] = "az9"
    current["plan"]["estimated"]["peak_ports"] = 99

    changes = verify_plan_contract(approved, current)

    assert {item["path"] for item in changes} == {
        "configuration.flavor",
        "inventory.networks",
        "inventory.hosts",
        "plan.estimated.peak_ports",
    }
    rendered = format_drift(changes)
    assert "approved='x1.nano'; current='x2.large'" in rendered
    assert "inventory.networks" in rendered


def test_drift_diff_classifies_added_removed_and_changed_values():
    assert drift_diff({"a": 1}, {"a": 2, "b": 3}) == [
        {
            "path": "a",
            "change": "changed",
            "approved": 1,
            "current": 2,
        },
        {
            "path": "b",
            "change": "added",
            "approved": None,
            "current": 3,
        },
    ]
    assert drift_diff({"a": 1}, {})[0]["change"] == "removed"


def test_approved_plan_hydrates_launch_and_execution_configuration(
    config_factory,
    discovery_fixture,
    tmp_path,
):
    source = config_factory(
        image="approved-image",
        flavor="approved-flavor",
        target_hosts=["compute1", "compute2"],
        qualification_strategy="stable",
        qualification_cycles=3,
        performance_enabled=True,
        performance_repeats=4,
        performance_udp_rates_mbps=[25, 100],
        migration_mode="live-preferred",
        cold_migration_fallback=True,
        live_migration_continuity=True,
    )
    path = tmp_path / "plan.json"
    path.write_text(
        json.dumps(_contract(source, discovery_fixture)),
        encoding="utf-8",
    )
    target = config_factory(
        image=None,
        flavor=None,
        target_hosts=[],
        performance_enabled=False,
        migration_mode="cold-only",
        cold_migration_fallback=False,
        live_migration_continuity=False,
    )

    _hydrate_config_from_plan(target, path)

    assert target.image == "approved-image"
    assert target.flavor == "approved-flavor"
    assert target.target_hosts == ["compute1", "compute2"]
    assert target.qualification_strategy == "stable"
    assert target.qualification_cycles == 3
    assert target.performance_enabled is True
    assert target.performance_repeats == 4
    assert target.performance_udp_rates_mbps == [25, 100]
    assert target.migration_mode == "live-preferred"
    assert target.cold_migration_fallback is True
    assert target.live_migration_continuity is True


class _CapabilityCloud:
    def __init__(
        self,
        *,
        microversion_ok: bool = True,
        forced_host_syntax: bool = True,
        binding_visible: bool = True,
        cinder_ok: bool = True,
    ):
        self.microversion_ok = microversion_ok
        self.forced_host_syntax = forced_host_syntax
        self.binding_visible = binding_visible
        self.cinder_ok = cinder_ok
        self.calls: list[tuple[str, ...]] = []

    def run(self, *args: str, **_kwargs):
        self.calls.append(args)
        if args[:2] == ("server", "create"):
            output = (
                "--availability-zone <zone:host>" if self.forced_host_syntax else ""
            )
            return subprocess.CompletedProcess(args, 0, output, "")
        if args[:3] == ("volume", "service", "list"):
            return subprocess.CompletedProcess(
                args,
                0 if self.cinder_ok else 1,
                "",
                "" if self.cinder_ok else "Cinder unavailable",
            )
        return subprocess.CompletedProcess(
            args,
            0 if self.microversion_ok else 1,
            "",
            "" if self.microversion_ok else "microversion rejected",
        )

    def json(self, *args: str, **_kwargs):
        self.calls.append(args)
        if args[:2] == ("port", "list"):
            return [{"ID": "port-1"}]
        if args[:2] == ("port", "show"):
            return (
                {"id": "port-1", "binding:host_id": "compute1"}
                if self.binding_visible
                else {"id": "port-1"}
            )
        raise AssertionError(args)


def test_capability_preflight_proves_visible_contract(
    config_factory,
    discovery_fixture,
):
    config = config_factory(
        action="run",
        target_hosts=["compute1", "compute2"],
    )
    discovery = dataclasses.replace(
        discovery_fixture,
        network_extensions=["external-net", "port-security", "standard-attr-tag"],
        quota_info={
            name: QuotaInfo(name, 10000, 0)
            for name in ("instances", "cores", "ram", "ports", "volumes")
        },
    )
    cloud = _CapabilityCloud()

    result = CapabilityPreflight(
        config,
        discovery,
        _plan(),
        cloud,
        mock.Mock(),
    ).run()

    checks = {item["id"]: item for item in result["checks"]}
    assert result["complete"] is True
    assert result["blockers"] == []
    assert checks["nova-microversion-2.53"]["status"] == "PASS"
    assert checks["nova-host-inventory"]["status"] == "PASS"
    assert checks["nova-forced-host-policy"]["status"] == "DEFERRED"
    assert checks["neutron-port-binding-visibility"]["status"] == "PASS"
    assert checks["quota-headroom"]["status"] == "PASS"
    port_list = next(call for call in cloud.calls if call[:2] == ("port", "list"))
    assert port_list == (
        "port",
        "list",
        "--network",
        discovery.networks[0].id,
    )
    assert "--limit" not in port_list


@pytest.mark.parametrize("inventory", [None, {}, [{"Name": "missing-id"}]])
def test_binding_inventory_probe_is_optional_and_runtime_enforced(
    config_factory,
    discovery_fixture,
    inventory,
):
    class ProbeCloud(_CapabilityCloud):
        def json(self, *args: str, **kwargs):
            if args[:2] == ("port", "list"):
                self.calls.append(args)
                return inventory
            return super().json(*args, **kwargs)

    discovery = dataclasses.replace(
        discovery_fixture,
        network_extensions=["external-net", "port-security", "standard-attr-tag"],
        quota_info={
            name: QuotaInfo(name, 10000, 0)
            for name in ("instances", "cores", "ram", "ports", "volumes")
        },
    )
    cloud = ProbeCloud()

    result = CapabilityPreflight(
        config_factory(action="run"),
        discovery,
        _plan(),
        cloud,
        mock.Mock(),
    ).run()

    check = next(
        item
        for item in result["checks"]
        if item["id"] == "neutron-port-binding-visibility"
    )
    assert check["status"] == "DEFERRED"
    assert check["required"] is False
    assert check["evidence"]["runtime_enforcement"] is True
    assert result["blockers"] == []
    assert not any(call[:2] == ("port", "show") for call in cloud.calls)


@pytest.mark.parametrize(
    ("cloud_operation", "expected_blocker"),
    [
        ("microversion", "nova-microversion-2.53"),
        ("host_fields", "nova-host-inventory"),
        ("extensions", "neutron-required-extensions"),
        ("cinder", "cinder-service"),
        ("quota", "quota-headroom"),
    ],
)
def test_capability_preflight_blocks_before_cloud_operation(
    config_factory,
    discovery_fixture,
    cloud_operation,
    expected_blocker,
):
    config = config_factory(
        action="run",
        storage="volume" if cloud_operation == "cinder" else "host",
        target_hosts=["compute1", "compute2"],
    )
    plan = _plan()
    if cloud_operation == "host_fields":
        plan.host_qualification.hosts[0].service_ids = []
    extensions = (
        ["external-net"]
        if cloud_operation == "extensions"
        else ["external-net", "port-security"]
    )
    quotas = {
        name: QuotaInfo(name, 100, 0)
        for name in ("instances", "cores", "ram", "ports", "volumes")
    }
    if cloud_operation == "quota":
        quotas["ports"] = QuotaInfo("ports", 1, 1)
    discovery = dataclasses.replace(
        discovery_fixture,
        network_extensions=extensions,
        quota_info=quotas,
    )
    cloud = _CapabilityCloud(
        microversion_ok=cloud_operation != "microversion",
        cinder_ok=cloud_operation != "cinder",
    )

    result = CapabilityPreflight(
        config,
        discovery,
        plan,
        cloud,
        mock.Mock(),
    ).run()

    assert expected_blocker in result["blockers"]
    assert result["complete"] is False


def test_reporter_resume_reopens_cancelled_and_synthetic_rows(
    config_factory,
):
    config = config_factory(action="run")
    initial = Reporter(config, "resume-journal")
    initial.result("DONE", "probe", "PASS", "completed")
    initial.result(
        "CANCELLED",
        "probe",
        "NOT_RUN_CANCELLED",
        "cancelled",
        details={"coverage_outcome": "NEVER_RAN"},
    )
    initial.result(
        "SYNTHETIC",
        "probe",
        "BLOCKED_BY_SETUP_ERROR",
        "never ran",
        details={"coverage_outcome": "NEVER_RAN"},
    )
    initial.logger.close()

    resumed = Reporter(config, "resume-journal", load_existing=True)

    assert resumed.has_result("DONE")
    assert not resumed.has_result("CANCELLED")
    assert not resumed.has_result("SYNTHETIC")
    resumed.result("CANCELLED", "probe", "PASS", "completed after resume")
    journal = resumed.result_journal_path.read_text(encoding="utf-8")
    assert journal.count('"test_id": "DONE"') == 1
    assert journal.count('"test_id": "CANCELLED"') == 1
    assert "SYNTHETIC" not in journal
    assert any(event["type"] == "resume-results-reopened" for event in resumed.events)
    resumed.logger.close()


def test_resume_prefers_new_journal_result_over_old_cancelled_json(
    config_factory,
):
    config = config_factory(action="run")
    initial = Reporter(config, "resume-precedence")
    initial.logger.close()
    cancelled = FluxTestResult(
        "ROW",
        "probe",
        "NOT_RUN_CANCELLED",
        None,
        None,
        None,
        "cancelled",
        "2026-07-26T00:00:00Z",
        0,
        {"coverage_outcome": "NEVER_RAN"},
    )
    payload = {
        "run": {
            "run_id": "resume-precedence",
            "started_at": "2026-07-26T00:00:00Z",
        },
        "results": [dataclasses.asdict(cancelled)],
    }
    initial.results_path.write_text(json.dumps(payload), encoding="utf-8")
    completed = dataclasses.replace(
        cancelled,
        status="PASS",
        message="completed on first resume",
        details={},
    )
    initial.result_journal_path.write_text(
        json.dumps(dataclasses.asdict(completed)) + "\n",
        encoding="utf-8",
    )

    resumed = Reporter(config, "resume-precedence", load_existing=True)

    assert resumed.get_result("ROW").status == "PASS"
    resumed.logger.close()


def test_materializes_every_missing_plan_row_with_reason():
    plan = _plan(qualification=False)
    reporter = SimpleNamespace(
        action="run",
        interrupted=False,
        cancellation_reason=None,
        setup_failed=False,
        error=None,
        recorded=[],
        has_result=lambda _test_id: False,
    )
    reporter.result = lambda *args, **kwargs: reporter.recorded.append((args, kwargs))

    assert materialize_missing_results(reporter, plan) == 1
    args, kwargs = reporter.recorded[0]
    assert args[2] == "BLOCKED_BY_PREREQUISITE"
    assert kwargs["details"]["coverage_outcome"] == "NEVER_RAN"


def test_coverage_ledger_tracks_each_topology_pair_cycle_exactly():
    plan = _plan()
    completed = {"provider-public1:HQ-PAIR:C1"}

    ledger = build_coverage_ledger(
        plan,
        [],
        completed_pair_cycles=completed,
    )

    pair_rows = [item for item in ledger if item["kind"] == "host-pair-cycle"]
    assert [item["id"] for item in pair_rows] == [
        "provider-public1:HQ-PAIR:C1",
        "provider-public1:HQ-PAIR:C2",
    ]
    assert [item["outcome"] for item in pair_rows] == ["COMPLETED", "NEVER_RAN"]
    assert pair_rows[0]["host_pair_id"] == "HQ-PAIR"
    assert pair_rows[0]["topology_group_id"] == "provider-public1"
