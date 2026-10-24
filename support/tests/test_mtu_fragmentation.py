from __future__ import annotations

import dataclasses
from types import SimpleNamespace
from unittest import mock

from neutron_flux.engine_handlers.common import EngineCommonMixin
from neutron_flux.errors import SuiteError
from neutron_flux.models import Endpoint
from neutron_flux.mtu_contract import (
    classify_fragmentation_location,
    classify_mtu_contract_probe,
    make_mtu_observation,
    resolve_mtu_contract,
)
from neutron_flux.performance import (
    PerformancePath,
    PerformanceRunner,
    ResolvedPerformancePath,
)
from neutron_flux.reporting_components.dashboard_model import _measurement_summary
from neutron_flux.terminology import category_label, friendly_operator_text


def _endpoint(label: str, side: str, address: str) -> Endpoint:
    return Endpoint(
        label=label,
        server_id=label,
        server_name=label,
        management_port_id=f"{label}-management",
        management_ip=address,
        test_port_id=f"{label}-test",
        test_mac="fa:16:3e:00:00:01",
        fixed_ips={"subnet": address},
        host=f"compute-{side.lower()}",
        availability_zone="az1",
        volume_id=None,
        side=side,
    )


def _path(*, stage: str = "group-local") -> ResolvedPerformancePath:
    plan = PerformancePath(
        path_id="PATH-SAMPLE",
        source_spec_id="FUNCTIONAL-SAMPLE",
        category="tenant-router",
        family=4,
        source_group_id="project-pair",
        destination_group_id="project-pair",
        source_side="A",
        destination_side="B",
        source_subnet_id="side-A",
        destination_subnet_id="side-B",
        stage=stage,
    )
    source_evidence = make_mtu_observation(
        label="Project network A",
        reported_mtu=1500,
        authority="live Neutron network.mtu",
        authoritative=True,
        resource_type="network",
        resource_id="network-a",
    )
    destination_evidence = make_mtu_observation(
        label="Project network B",
        reported_mtu=1500,
        authority="live Neutron network.mtu",
        authoritative=True,
        resource_type="network",
        resource_id="network-b",
    )
    return ResolvedPerformancePath(
        plan=plan,
        source=_endpoint("source", "A", "10.0.0.10"),
        destination=_endpoint("destination", "B", "10.1.0.10"),
        source_ip="10.0.0.10",
        destination_ip="10.1.0.10",
        source_mtu=1500,
        destination_mtu=1500,
        placement="cross-compute",
        availability_scope="same-az",
        source_mtu_evidence=source_evidence,
        destination_mtu_evidence=destination_evidence,
        router_ids=("router-sample",),
    )


def _counter_snapshot(
    *,
    frag_creates: int = 0,
    reasm_ok: int = 0,
    family: int = 4,
    available: bool = True,
) -> dict:
    if family == 4:
        counters = {"FragCreates": frag_creates, "ReasmOKs": reasm_ok}
    else:
        counters = {"Ip6FragCreates": frag_creates, "Ip6ReasmOKs": reasm_ok}
    return {
        "family": family,
        "available": available,
        "source": "/proc/net/snmp" if family == 4 else "/proc/net/snmp6",
        "counters": counters if available else {},
        "error": None if available else "counter file unavailable",
    }


def _fragment_profile(
    *,
    family: int = 4,
    source_before: dict | None = None,
    source_after: dict | None = None,
) -> dict:
    before = source_before or _counter_snapshot(family=family)
    after = source_after or _counter_snapshot(family=family)
    return {
        "family": family,
        "source_mtu": 9000,
        "path_mtu": 1500,
        "tested_packet_size": 9000,
        "applicable": True,
        "capability": "supported",
        "fragmentation_model": (
            "ipv4-fragmentation-permitted"
            if family == 4
            else "ipv6-source-fragmentation-only"
        ),
        "source_fragment_counters": {
            "before": before,
            "after_permitted": after,
        },
    }


def test_neutron_mtu_provenance_accounts_for_geneve_once():
    evidence = make_mtu_observation(
        label="private network",
        reported_mtu=8942,
        authority="live Neutron network.mtu",
        authoritative=True,
        resource_type="network",
        resource_id="net-private",
        network_type="geneve",
    )
    assert evidence["effective_mtu"] == 8942
    assert evidence["fallback_used"] is False
    assert "already accounts for overlay encapsulation overhead" in str(
        evidence["derivation_note"]
    )


def test_missing_neutron_mtu_is_a_diagnostic_fallback_not_a_contract():
    missing = make_mtu_observation(
        label="private network",
        reported_mtu=None,
        authority="live Neutron network.mtu",
        authoritative=True,
        resource_type="network",
        resource_id="net-private",
    )
    peer = make_mtu_observation(
        label="peer network",
        reported_mtu=9000,
        authority="live Neutron network.mtu",
        authoritative=True,
        resource_type="network",
        resource_id="net-peer",
    )
    contract = resolve_mtu_contract([missing, peer])
    assert contract["expected_mtu"] == 1500
    assert contract["fallback_used"] is True
    assert contract["authoritative"] is False
    probe = classify_mtu_contract_probe(
        {
            "discovery_confidence": "confirmed-lower-boundary",
            "discovered_mtu": 1424,
            "expected_probe_classification": "local-mtu-rejected",
        },
        expected_mtu=1500,
        contract_authoritative=False,
    )
    assert probe["advertised_mtu_contract_status"] == "unverified"


def test_network_mtu_resolution_uses_the_endpoint_side_network():
    group = SimpleNamespace(
        network_id="network-a",
        network_name="Project A",
        metadata={
            "network_ids": {"A": "network-a", "B": "network-b"},
            "network_names": {"A": "Project A", "B": "Project B"},
        },
    )
    osc = mock.Mock()
    osc.json.return_value = {
        "id": "network-b",
        "mtu": 9000,
        "provider:network_type": "geneve",
    }
    harness = SimpleNamespace(
        _group=lambda _group_id: group,
        builder=SimpleNamespace(osc=osc),
        discovery=SimpleNamespace(
            network=lambda _network_id: (_ for _ in ()).throw(StopIteration)
        ),
    )
    observation = EngineCommonMixin._network_mtu_observation(
        harness,
        "project-pair",
        "B",
    )
    osc.json.assert_called_once_with("network", "show", "network-b", check=False)
    assert observation["resource_id"] == "network-b"
    assert observation["effective_mtu"] == 9000


def test_router_backend_is_only_ovn_when_agent_inventory_confirms_it():
    osc = mock.Mock()
    osc.json.return_value = [
        {"Agent Type": "OVN Controller agent"},
        {"Agent Type": "OVN Metadata agent"},
    ]
    harness = SimpleNamespace(builder=SimpleNamespace(osc=osc))
    evidence = EngineCommonMixin._network_router_backend_evidence(harness)
    assert evidence["backend"] == "ovn"
    assert evidence["confirmed"] is True
    osc.json.assert_called_once_with(
        "network",
        "agent",
        "list",
        check=False,
    )


def test_router_backend_inventory_permission_failure_is_non_blocking():
    osc = mock.Mock()
    osc.json.side_effect = SuiteError("Forbidden: policy does not allow agent list")
    harness = SimpleNamespace(builder=SimpleNamespace(osc=osc))
    evidence = EngineCommonMixin._network_router_backend_evidence(harness)
    assert evidence["backend"] == "unknown"
    assert evidence["confirmed"] is False
    assert "Forbidden" in evidence["lookup_error"]


def test_mixed_router_backends_do_not_make_an_ovn_specific_claim():
    osc = mock.Mock()
    osc.json.return_value = [
        {"Agent Type": "OVN Controller agent"},
        {"Agent Type": "L3 agent"},
    ]
    harness = SimpleNamespace(builder=SimpleNamespace(osc=osc))
    evidence = EngineCommonMixin._network_router_backend_evidence(harness)
    assert evidence["backend"] == "mixed-or-ambiguous"
    assert evidence["confirmed"] is False


def test_external_or_transit_network_can_be_the_real_mtu_limiter():
    path = _path()
    external = make_mtu_observation(
        label="External provider network",
        reported_mtu=1500,
        authority="live Neutron network.mtu",
        authoritative=True,
        resource_type="network",
        resource_id="external-network",
    )
    widened = dataclasses.replace(
        path,
        source_mtu=9000,
        destination_mtu=9000,
        source_mtu_evidence=make_mtu_observation(
            label="Project A",
            reported_mtu=9000,
            authority="live Neutron network.mtu",
            authoritative=True,
            resource_type="network",
            resource_id="project-a",
        ),
        destination_mtu_evidence=make_mtu_observation(
            label="Project B",
            reported_mtu=9000,
            authority="live Neutron network.mtu",
            authoritative=True,
            resource_type="network",
            resource_id="project-b",
        ),
        additional_mtu_evidence=(external,),
    )
    assert widened.expected_mtu == 1500
    assert widened.mtu_contract["limiting_constraints"][0]["resource_id"] == (
        "external-network"
    )


def test_ipv4_source_fragmentation_is_not_mislabeled_as_ovn():
    profile = _fragment_profile(
        source_before=_counter_snapshot(frag_creates=100),
        source_after=_counter_snapshot(frag_creates=106),
    )
    result = classify_fragmentation_location(
        profile,
        destination_before=_counter_snapshot(reasm_ok=20),
        destination_after=_counter_snapshot(reasm_ok=23),
        router_ids=["router-one"],
        router_backend_evidence={"backend": "ovn", "confirmed": True},
    )
    assert result["fragmentation_location"] == "source"
    assert result["ovn_router_fragmentation_observed"] is None
    assert "Source guest" in result["fragmentation_location_label"]
    assert (
        result["endpoint_observations"]["source_fragment_creation"]["directly_observed"]
        is True
    )
    assert result["component_inference"]["status"] == "not-needed"


def test_ipv4_ovn_router_fragmentation_requires_counter_corroboration():
    result = classify_fragmentation_location(
        _fragment_profile(),
        destination_before=_counter_snapshot(reasm_ok=20),
        destination_after=_counter_snapshot(reasm_ok=23),
        router_ids=["router-one"],
        router_backend_evidence={"backend": "ovn", "confirmed": True},
    )
    assert result["fragmentation_location"] == "in-path"
    assert result["ovn_router_fragmentation_observed"] is None
    assert result["attribution_confidence"] == "endpoint-counter-inference"
    assert result["in_path_fragmentation_observed"] is False
    assert result["in_path_fragmentation_inferred"] is True
    assert result["router_ids"] == ["router-one"]
    assert result["component_inference"]["component"] == (
        "ovn-backed-neutron-router-path"
    )
    assert result["component_inference"]["directly_observed"] is False
    assert "no component-local evidence" in result["attribution_reason"]


def test_two_router_path_does_not_guess_which_ovn_router_fragmented():
    result = classify_fragmentation_location(
        _fragment_profile(),
        destination_before=_counter_snapshot(reasm_ok=20),
        destination_after=_counter_snapshot(reasm_ok=23),
        router_ids=["router-a", "router-b"],
        router_backend_evidence={"backend": "ovn", "confirmed": True},
    )
    assert result["fragmentation_location"] == "in-path"
    assert result["component_inference"]["status"] == "multiple-candidates"
    assert "no component-local evidence" in result["attribution_reason"]


def test_unknown_router_backend_does_not_make_an_ovn_specific_claim():
    result = classify_fragmentation_location(
        _fragment_profile(),
        destination_before=_counter_snapshot(reasm_ok=20),
        destination_after=_counter_snapshot(reasm_ok=23),
        router_ids=["router-one"],
        router_backend_evidence={"backend": "unknown", "confirmed": False},
    )
    assert result["fragmentation_location"] == "in-path"
    assert result["router_fragmentation_observed"] is None
    assert result["ovn_router_fragmentation_observed"] is None
    assert result["component_inference"]["component"] == "neutron-router-path"
    assert result["component_inference"]["directly_observed"] is False


def test_unconfirmed_ovn_string_does_not_make_an_ovn_specific_claim():
    result = classify_fragmentation_location(
        _fragment_profile(),
        destination_before=_counter_snapshot(reasm_ok=20),
        destination_after=_counter_snapshot(reasm_ok=23),
        router_ids=["router-one"],
        router_backend_evidence={"backend": "ovn", "confirmed": False},
    )
    assert result["fragmentation_location"] == "in-path"
    assert result["ovn_router_fragmentation_observed"] is None
    assert result["component_inference"]["confidence"] == "path-context-only"


def test_ipv6_never_attributes_fragmentation_to_a_router():
    result = classify_fragmentation_location(
        _fragment_profile(family=6),
        destination_before=_counter_snapshot(reasm_ok=20, family=6),
        destination_after=_counter_snapshot(reasm_ok=23, family=6),
        router_ids=["router-one"],
    )
    assert result["fragmentation_location"] == "unverified"
    assert result["ovn_router_fragmentation_observed"] is None


def test_capability_without_source_counters_keeps_location_unverified():
    unavailable = _counter_snapshot(available=False)
    result = classify_fragmentation_location(
        _fragment_profile(source_before=unavailable, source_after=unavailable),
        destination_before=_counter_snapshot(reasm_ok=20),
        destination_after=_counter_snapshot(reasm_ok=23),
        router_ids=["router-one"],
    )
    assert result["fragmentation_location"] == "unverified"
    assert result["capability"] == "supported"


def test_fragmentation_probe_uses_confirmed_boundary_not_advertised_mtu(
    config_factory, tmp_path, monkeypatch
):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    runner = PerformanceRunner(
        config,
        SimpleNamespace(),
        SimpleNamespace(
            logger=SimpleNamespace(section=lambda *_: None, log=lambda *_: None)
        ),
        SimpleNamespace(),
    )
    monkeypatch.setattr(
        runner,
        "_mtu_probe",
        lambda *_args, **_kwargs: {
            "reachable": True,
            "discovered_mtu": 1424,
            "discovery_confidence": "confirmed-lower-boundary",
            "expected_probe_classification": "no-reply",
            "path_boundary_confirmed": True,
            "above_expected_reachable": False,
        },
    )
    captured: list[int] = []

    def fragmentation(*args, **_kwargs):
        captured.append(int(args[5]))
        return {
            "capability": "supported",
            "fragmentation_location": "unverified",
        }

    monkeypatch.setattr(runner, "_fragmentation_probe", fragmentation)
    payload = runner._measure_mtu_family(_path(), None)
    assert captured == [1424, 1424]
    assert payload["metrics"]["forward"]["advertised_mtu_contract_status"] == "failed"


def test_post_migration_local_constraint_is_persistent_or_cleared(
    config_factory, tmp_path, monkeypatch
):
    config = config_factory(
        action="run",
        report_dir=tmp_path / "reports",
        convergence_interval=0,
    )
    runner = PerformanceRunner(
        config,
        SimpleNamespace(),
        SimpleNamespace(),
        SimpleNamespace(),
    )
    path = _path(stage="post-live-migration-inter-compute")
    initial = classify_mtu_contract_probe(
        {
            "discovered_mtu": 1424,
            "discovery_confidence": "confirmed-lower-boundary",
            "expected_probe_classification": "local-mtu-rejected",
        },
        expected_mtu=1500,
        contract_authoritative=True,
    )
    monkeypatch.setattr(
        "neutron_flux.performance_measurements.time.sleep",
        lambda _seconds: None,
    )
    runner._mtu_probe = mock.Mock(
        return_value={
            "discovered_mtu": 1424,
            "discovery_confidence": "confirmed-lower-boundary",
            "expected_probe_classification": "local-mtu-rejected",
        }
    )
    persistent = runner._post_migration_mtu_settlement(
        path,
        initial,
        source=path.source,
        source_ip=path.source_ip,
        destination_ip=path.destination_ip,
    )
    assert (
        persistent["post_migration_persistence"]["classification"]
        == "persistent-local-mtu-constraint-unverified"
    )

    recovered_probe = {
        "discovered_mtu": 1500,
        "discovery_confidence": "expected-confirmed",
        "expected_probe_classification": "success",
    }
    runner._mtu_probe = mock.Mock(side_effect=[recovered_probe, recovered_probe])
    transient = runner._post_migration_mtu_settlement(
        path,
        initial,
        source=path.source,
        source_ip=path.source_ip,
        destination_ip=path.destination_ip,
    )
    assert (
        transient["post_migration_persistence"]["classification"]
        == "local-constraint-cleared"
    )
    assert transient["discovered_mtu"] == 1500


def test_dashboard_model_exposes_contract_pmtud_and_fragment_location():
    result = {
        "status": "FAIL",
        "display_name": "Path MTU, PMTUD, and TCP MSS",
        "details": {
            "measurement": "mtu-mss",
            "health": "critical",
            "metrics": {
                "expected_mtu": 9000,
                "source_mtu": 9000,
                "destination_mtu": 9000,
                "contract_authoritative": True,
                "mtu_contract_formula": "minimum(project A=9000, project B=9000)",
                "mtu_constraints": [
                    {
                        "label": "Project A",
                        "effective_mtu": 9000,
                        "authority": "live Neutron network.mtu",
                        "authoritative": True,
                    }
                ],
                "limiting_mtu_constraints": [],
                "forward": {
                    "discovered_mtu": 1500,
                    "advertised_mtu_contract_status": "failed",
                    "pmtud_status": "df-path-boundary-observed",
                    "post_migration_persistence": {
                        "classification": "persistent-lower-boundary",
                        "reason": "repeated",
                    },
                    "fragmentation": {
                        "capability": "supported",
                        "fragmentation_location": "ovn-router",
                        "fragmentation_location_label": (
                            "OVN logical router fragmented the packet"
                        ),
                        "attribution_confidence": "counter-corroborated",
                        "router_ids": ["router-one"],
                    },
                },
            },
        },
    }
    summary = _measurement_summary(result)
    assert summary is not None
    values = summary["values"]
    assert values["contract_authoritative"] is True
    assert values["forward_contract_status"] == "failed"
    assert values["forward_fragmentation_location"] is None
    assert "forward_fragmentation_component_inference" not in values
    assert values["forward_fragmentation_component_directly_observed"] is False
    assert values["forward_persistence"] == "persistent-lower-boundary"


def test_operator_language_is_centralized_and_keeps_compute_terms():
    visible = friendly_operator_text(
        "Representative tenant extra-route source-NAT validation"
    ).lower()
    assert "representative" not in visible
    assert "tenant" not in visible
    assert "extra-route" not in visible
    assert "source-nat" not in visible
    assert category_label("router-extra-route") == "Router static-route connectivity"
    assert friendly_operator_text("intra-compute and inter-compute") == (
        "intra-compute and inter-compute"
    )
