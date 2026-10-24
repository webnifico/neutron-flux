"""Read batches overlap without moving placement or policy state into workers."""

from __future__ import annotations

import threading
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.errors import SuiteError
from neutron_flux.runtime.availability import AvailabilityRuntimeMixin
from neutron_flux.runtime.security import SecurityRuntimeMixin
from neutron_flux.scheduling import READ_WORKERS


class ParallelReads:
    def __init__(self, identities, *, fail=None, invalid=None):
        self.identities = identities
        self.fail = fail
        self.invalid = invalid
        self.barrier = threading.Barrier(READ_WORKERS)
        self.lock = threading.Lock()
        self.active = 0
        self.peak = 0
        self.completed = []
        self.last_finished = threading.Event()

    def read(self, identity, result):
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            self.barrier.wait(timeout=5)
            # Make completion order differ from inventory order deliberately.
            if identity == self.identities[0]:
                assert self.last_finished.wait(timeout=5)
            if identity == self.identities[READ_WORKERS - 1]:
                self.last_finished.set()
            if identity == self.fail:
                raise SuiteError(f"unavailable: {identity}")
            return None if identity == self.invalid else result
        finally:
            with self.lock:
                self.completed.append(identity)
                self.active -= 1


def placement_runtime():
    builder = AvailabilityRuntimeMixin()
    builder.config = SimpleNamespace(resource_timeout=90)
    identities = [f"net-{index}" for index in range(8)]
    builder.pending_neutron_az_validation = {
        "network:deleted": {},
        "network:another-group": {},
        **{f"network:{identity}": {"selection": identity} for identity in identities},
    }
    builder.reporter = SimpleNamespace(
        resources=[
            SimpleNamespace(
                resource_type="network",
                id=identity,
                delete_status="deleted" if identity == "deleted" else "",
                metadata={
                    "group_id": (
                        "other"
                        if identity == "another-group"
                        else None
                        if identity == "net-3"
                        else "current"
                    )
                },
            )
            for identity in ["deleted", "another-group", *identities[:-1]]
        ]
    )
    return builder, identities


def test_placement_reads_overlap_but_validation_is_ordered_on_caller():
    builder, identities = placement_runtime()
    reads = ParallelReads(identities)
    caller = threading.get_ident()
    validated = []

    def read(*args, **kwargs):
        assert args[:2] == ("network", "show")
        assert kwargs == {"timeout": 60}
        return reads.read(args[2], {"identity": args[2]})

    def validate(resource_type, resource_id, detail, **kwargs):
        assert threading.get_ident() == caller
        assert reads.active == 0
        assert resource_type == "network"
        assert detail == {"identity": resource_id}
        assert kwargs == {
            "selection": {"selection": resource_id},
            "after_scheduling": True,
        }
        validated.append(resource_id)
        builder.pending_neutron_az_validation.pop(f"network:{resource_id}")

    builder.osc = SimpleNamespace(json=read)
    builder._validate_created_resource_zone = validate
    builder._refresh_neutron_placements("current")
    assert reads.peak == READ_WORKERS
    assert reads.completed.index(identities[0]) > reads.completed.index(identities[3])
    assert validated == identities
    assert builder.pending_neutron_az_validation == {"network:another-group": {}}


@pytest.mark.parametrize("fault", ["read-error", "invalid-inventory"])
def test_placement_read_failure_publishes_no_partial_evidence(fault):
    builder, identities = placement_runtime()
    # One complete bounded batch prevents a failing read from admitting more work.
    identities = identities[:READ_WORKERS]
    builder.pending_neutron_az_validation = {
        f"network:{identity}": {"selection": identity} for identity in identities
    }
    before = dict(builder.pending_neutron_az_validation)
    reads = ParallelReads(
        identities,
        fail=identities[-1] if fault == "read-error" else None,
        invalid=identities[-1] if fault == "invalid-inventory" else None,
    )
    builder.osc = SimpleNamespace(json=lambda *args, **kwargs: reads.read(args[2], {}))
    builder._validate_created_resource_zone = mock.Mock()
    with pytest.raises(SuiteError):
        builder._refresh_neutron_placements("current")
    assert reads.active == 0
    assert set(reads.completed) == set(identities)
    builder._validate_created_resource_zone.assert_not_called()
    assert builder.pending_neutron_az_validation == before


def security_runtime(monkeypatch):
    monkeypatch.setattr(
        "neutron_flux.runtime.security.managed_resource_name",
        lambda _builder, **kwargs: kwargs["identity"],
    )
    builder = SecurityRuntimeMixin()
    builder.config = SimpleNamespace(
        tcp_port=18080, udp_port=18081, progress_interval=5
    )
    builder.management_cidr = "10.0.0.0/24"
    builder.logger = mock.Mock()
    builder.reporter = mock.Mock()
    builder.security_control_ports = {}
    builder.security_control_authoritative = {}
    builder.security_control_matching_rules = {}
    builder.security_group_rules = {"unrelated": [{"id": "preserved"}]}
    return builder


@pytest.mark.parametrize("failing_phase", [None, "initial", "final"])
def test_security_reads_batch_but_policy_changes_and_publish_remain_serial(
    monkeypatch, failing_phase
):
    builder = security_runtime(monkeypatch)
    caller = threading.get_ident()
    identities = ["controller", "management", "data-a", "data-b"]
    phase_reads = {
        phase: ParallelReads(
            identities,
            fail="data-b" if failing_phase == phase else None,
        )
        for phase in ("initial", "final")
    }
    read_counts = dict.fromkeys(identities, 0)
    read_lock = threading.Lock()
    created_groups = []
    created_rules = []
    normalized = []
    original_normalize = builder._normalize_security_group_rule
    original_matches = builder._security_rule_matches

    def create_group(_name):
        assert threading.get_ident() == caller
        identity = identities[len(created_groups)]
        created_groups.append(identity)
        return identity

    def normalize(row):
        assert threading.get_ident() == caller
        normalized.append(row["id"])
        return original_normalize(row)

    def matches(rule, desired):
        assert threading.get_ident() == caller
        assert all(reads.active == 0 for reads in phase_reads.values())
        return original_matches(rule, desired)

    def json_call(*args, **kwargs):
        if args[:4] == ("security", "group", "rule", "list"):
            identity = args[4]
            with read_lock:
                phase = "initial" if read_counts[identity] == 0 else "final"
                read_counts[identity] += 1
            return phase_reads[phase].read(
                identity,
                [
                    {
                        "id": f"{phase}-{identity}",
                        "direction": "egress",
                        "ethertype": "IPv4",
                        "protocol": None,
                        "remote_ip_prefix": "0.0.0.0/0",
                    }
                ],
            )
        assert args[:4] == ("security", "group", "rule", "create")
        assert threading.get_ident() == caller
        assert all(reads.active == 0 for reads in phase_reads.values())
        created_rules.append(args)
        return {"id": f"created-{len(created_rules)}"}

    builder._create_security_group = create_group
    builder._normalize_security_group_rule = normalize
    builder._security_rule_matches = matches
    builder.osc = SimpleNamespace(json=json_call)
    if failing_phase:
        with pytest.raises(SuiteError, match="unavailable: data-b"):
            builder._create_security_groups(select_control_ports=False)
        assert builder.security_group_rules == {"unrelated": [{"id": "preserved"}]}
        builder.reporter.event.assert_not_called()
        assert bool(created_rules) is (failing_phase == "final")
    else:
        builder._create_security_groups(select_control_ports=False)
        assert list(builder.security_group_rules) == ["unrelated", *identities]
        assert [
            builder.security_group_rules[group][0]["id"] for group in identities
        ] == [f"final-{group}" for group in identities]
        assert normalized[:4] == [f"initial-{group}" for group in identities]
        assert normalized[-4:] == [f"final-{group}" for group in identities]
        assert len(created_rules) == 20
        builder.reporter.event.assert_called_once()
    assert created_groups == identities
    for phase, reads in phase_reads.items():
        if phase == "final" and failing_phase == "initial":
            assert not reads.completed
        else:
            assert reads.peak == READ_WORKERS
            assert reads.active == 0
            assert set(reads.completed) == set(identities)


def test_security_inventory_batch_is_capped_and_normalized_in_input_order():
    builder = SecurityRuntimeMixin()
    identities = [f"sg-{index}" for index in range(8)]
    reads = ParallelReads(identities)
    caller = threading.get_ident()
    normalized = []

    def normalize(row):
        assert threading.get_ident() == caller
        assert reads.active == 0
        normalized.append(row["id"])
        return row

    builder._normalize_security_group_rule = normalize
    builder.osc = SimpleNamespace(
        json=lambda *args, **kwargs: reads.read(args[4], [{"id": args[4]}])
    )
    inventories = builder._list_security_group_rule_inventories(identities)
    assert reads.peak == READ_WORKERS
    assert normalized == identities
    assert list(inventories) == identities


def test_security_invalid_inventory_does_not_publish_partial_map():
    builder = SecurityRuntimeMixin()
    identities = [f"sg-{index}" for index in range(READ_WORKERS)]
    reads = ParallelReads(identities, invalid=identities[-1])
    builder.security_group_rules = {"existing": []}
    builder.osc = SimpleNamespace(
        json=lambda *args, **kwargs: reads.read(args[4], [{"id": args[4]}])
    )
    with pytest.raises(SuiteError, match="invalid security-group rule inventory"):
        inventories = builder._list_security_group_rule_inventories(identities)
        builder.security_group_rules.update(inventories)
    assert builder.security_group_rules == {"existing": []}
    assert reads.active == 0
