from __future__ import annotations

import dataclasses
import subprocess
import threading
import time
from unittest.mock import Mock

import pytest

import neutron_flux.discovery as discovery_module
from neutron_flux.discovery import Discoverer
from neutron_flux.errors import CommandError
from neutron_flux.scheduling import READ_WORKERS


class InventoryOSC:
    backend_name = "fixture"

    def __init__(self, stage=None, *, failure=None):
        self.stage = stage
        self.failure = failure
        self.parties = 3 if stage == "project" else READ_WORKERS
        self.barrier = threading.Barrier(self.parties) if stage else None
        self.lock = threading.Lock()
        self.active = 0
        self.peak = 0
        self.finished = []
        self.calls = []
        self.networks = [{"id": f"n{i}", "name": f"Network {i}"} for i in range(8)]

    def run(self, *args, **kwargs):
        return subprocess.CompletedProcess(args, 0, '{"region_name":"region"}', "")

    @staticmethod
    def _stage(args):
        if args[:3] == ("subnet", "list", "--network"):
            return "external-subnets"
        if args[:2] == ("network", "show"):
            return "networks"
        if args[:2] == ("subnet", "show") and args[2].startswith("q"):
            return "occupied"
        if args[:3] == ("subnet", "pool", "show"):
            return "pools"
        if args in {
            ("address", "scope", "list"),
            ("extension", "list", "--network"),
            ("quota", "show", "--usage"),
        }:
            return "project"
        return None

    def json(self, *args, **kwargs):
        with self.lock:
            self.calls.append(args)
        tracked = self._stage(args) == self.stage and self.stage is not None
        if tracked:
            with self.lock:
                self.active += 1
                self.peak = max(self.peak, self.active)
            try:
                assert self.barrier is not None
                self.barrier.wait(timeout=5)
                if args == self.failure:
                    return self._response(args)
                # Deliberately let later input rows finish first.
                suffix = args[-1][-1:]
                index = int(suffix) if suffix.isdigit() else 0
                time.sleep((8 - index) * 0.001)
                return self._response(args)
            finally:
                with self.lock:
                    self.finished.append(args)
                    self.active -= 1
        return self._response(args)

    def _response(self, args):
        if args == self.failure:
            raise CommandError(["openstack", *args], 1, "", "inventory unavailable")
        if args == ("token", "issue"):
            return {"project_id": "project"}
        if args in {("network", "list", "--external"), ("network", "list")}:
            return list(self.networks)
        if args[:3] == ("subnet", "list", "--network"):
            return [{"id": f"s-{args[3]}"}]
        if args[:2] == ("subnet", "show"):
            identity = args[2]
            index = int(identity[-1])
            if identity.startswith("q"):
                return {"id": identity, "cidr": f"10.{index}.0.0/24"}
            return {
                "id": identity,
                "cidr": f"198.18.{index}.0/24",
                "ip_version": 4,
                "subnetpool_id": f"pool{index}",
            }
        if args[:2] == ("network", "show"):
            return {"id": args[2], "name": "Network " + args[2][-1]}
        if args[:3] == ("network", "segment", "list"):
            return [{"id": "segment" + args[-1][-1]}]
        if args[:3] == ("network", "segment", "show"):
            # Segment IDs belong to the list row even if show omits its ID.
            return {"network_type": "flat", "physical_network": "provider"}
        if args == ("subnet", "list", "--long"):
            return [{"id": f"q{i}"} for i in range(8)]
        if args == ("subnet", "pool", "list", "--long"):
            return [{"id": f"pool{i}"} for i in range(8)]
        if args[:3] == ("subnet", "pool", "show"):
            return {"id": args[3], "prefixes": ["198.18.0.0/16"]}
        if args == ("address", "scope", "list"):
            return [{"id": "scope"}]
        if args == ("extension", "list", "--network"):
            return [{"alias": "router"}, {"alias": "qos"}]
        if args == ("quota", "show", "--usage"):
            return {"instances": 100}
        raise AssertionError(args)


def _discover(config_factory, osc):
    config = config_factory(external_networks=[f"n{i}" for i in range(8)])
    return Discoverer(osc, Mock(), config).discover()


@pytest.mark.parametrize(
    "stage", ["external-subnets", "networks", "occupied", "pools", "project"]
)
def test_independent_discovery_reads_overlap_within_the_read_budget(
    config_factory, stage
):
    osc = InventoryOSC(stage)
    result = _discover(config_factory, osc)
    assert osc.peak == min(READ_WORKERS, osc.parties)
    assert osc.active == 0
    assert [item.id for item in result.networks] == [f"n{i}" for i in range(8)]
    assert [item.id for item in result.subnets] == [f"s-n{i}" for i in range(8)]
    assert [item.id for item in result.segments] == [f"segment{i}" for i in range(8)]
    assert [item.id for item in result.pools] == [f"pool{i}" for i in range(8)]
    assert all(item.provider_pool for item in result.pools)
    assert result.network_extensions == ["qos", "router"]
    assert result.occupied_cidrs == sorted(
        [f"10.{i}.0.0/24" for i in range(8)] + [f"198.18.{i}.0/24" for i in range(8)]
    )


def test_discovery_output_is_stable_and_models_are_built_on_the_caller(
    config_factory, monkeypatch
):
    parent = threading.get_ident()
    for name in ("NetworkInfo", "SubnetInfo", "SegmentInfo", "PoolInfo"):
        constructor = getattr(discovery_module, name)

        def construct(*args, _constructor=constructor, **kwargs):
            assert threading.get_ident() == parent
            return _constructor(*args, **kwargs)

        monkeypatch.setattr(discovery_module, name, construct)
    parallel = _discover(config_factory, InventoryOSC("networks"))
    with monkeypatch.context() as serial:
        serial.setattr(
            discovery_module,
            "bounded_map",
            lambda function, values, *, workers: [function(value) for value in values],
        )
        sequential = _discover(config_factory, InventoryOSC())
    assert dataclasses.asdict(parallel) == dataclasses.asdict(sequential)


def test_discovery_read_error_is_propagated_after_admitted_reads_join(
    config_factory,
):
    failed = ("network", "show", "n1")
    osc = InventoryOSC("networks", failure=failed)
    with pytest.raises(CommandError, match="inventory unavailable"):
        _discover(config_factory, osc)
    assert osc.active == 0
    assert failed in osc.finished
    assert not any(args[:3] == ("subnet", "pool", "list") for args in osc.calls)
