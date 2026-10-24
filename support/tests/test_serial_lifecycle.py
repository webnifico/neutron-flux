from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

from neutron_flux.cleanup import CleanupManager
from neutron_flux.models import ResourceRecord
from neutron_flux.resources import ResourceBuilder
from neutron_flux.utils import iso_utc

from ._shared import completed


def test_shared_lifecycle_lock_serializes_port_creation(config_factory):
    shared_lock = threading.RLock()
    active = 0
    peak = 0
    counter = 0
    guard = threading.Lock()

    def make_builder():
        builder = object.__new__(ResourceBuilder)
        builder.lifecycle_lock = shared_lock
        builder.config = config_factory()
        builder.run_tag = "neutron-flux-test"
        builder.tracker = mock.Mock()
        builder._network_port_security_enabled = mock.Mock(return_value=True)
        builder.osc = mock.Mock()

        def create(*_args, **_kwargs):
            nonlocal active, peak, counter
            with guard:
                active += 1
                peak = max(peak, active)
                counter += 1
                port_id = f"port-{counter}"
            time.sleep(0.03)
            with guard:
                active -= 1
            return {
                "id": port_id,
                "device_id": "",
                "binding:host_id": "",
                "port_security_enabled": True,
            }

        builder.osc.json.side_effect = create
        return builder

    first = make_builder()
    second = make_builder()
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(first._create_port, "p1", "n1", ["s1"], "sg1"),
            pool.submit(second._create_port, "p2", "n1", ["s1"], "sg1"),
        ]
        [future.result() for future in futures]

    assert peak == 1


def test_server_settlement_requires_two_matching_inventory_reads(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(
        resource_timeout=5,
        convergence_timeout=5,
        convergence_interval=0,
    )
    builder.logger = mock.Mock()
    builder.osc = mock.Mock()

    def inventory(*args, **_kwargs):
        if args[:2] == ("server", "show"):
            return {
                "id": "server-1",
                "status": "ACTIVE",
                "OS-EXT-STS:task_state": None,
                "OS-EXT-SRV-ATTR:host": "compute2",
            }
        return {
            "id": "port-1",
            "status": "ACTIVE",
            "device_id": "server-1",
            "binding:host_id": "compute2",
        }

    builder.osc.json.side_effect = inventory
    result = builder._wait_for_server_settlement(
        "server-1",
        ["port-1"],
        expected_statuses={"active"},
        expected_host="compute2",
        timeout=5,
    )

    assert result["status"] == "ACTIVE"
    assert builder.osc.json.call_count == 4


def test_force_delete_is_only_used_after_extended_normal_delete_timeout(
    config_factory,
):
    manager = object.__new__(CleanupManager)
    manager.config = config_factory()
    manager.logger = mock.Mock()
    manager.osc = mock.Mock()
    manager.osc.exists.return_value = True
    manager.osc.run.return_value = completed()
    manager._cleanup_progress_details = mock.Mock(
        return_value={"task_state": "deleting", "status": "ACTIVE"}
    )
    manager._wait_absent = mock.Mock(side_effect=[False, True])
    resource = ResourceRecord(1, "server", "server-id", "vm", None, {}, iso_utc())

    assert manager._server_delete_fallback(resource) is True
    assert manager._wait_absent.call_args_list[0].args[:3] == (
        "server",
        "server-id",
        180,
    )
    assert manager.osc.run.call_args.args[:5] == (
        "--os-compute-api-version",
        "2.latest",
        "server",
        "delete",
        "--force",
    )


def test_compute_port_waits_for_detachment_before_explicit_delete(config_factory):
    manager = object.__new__(CleanupManager)
    manager.config = config_factory(convergence_interval=0)
    manager.logger = mock.Mock()
    manager.osc = mock.Mock()
    manager.osc.exists.return_value = False
    attached = {
        "id": "port-id",
        "device_owner": "compute:nova",
        "device_id": "server-id",
        "binding:host_id": "compute1",
        "status": "ACTIVE",
    }
    detached = {
        "id": "port-id",
        "device_owner": "",
        "device_id": "",
        "binding:host_id": "",
        "status": "DOWN",
    }
    manager.osc.json.side_effect = [attached, detached, detached]
    manager.osc.run.return_value = completed()

    manager._delete_port(
        ResourceRecord(1, "port", "port-id", "endpoint-port", None, {}, iso_utc())
    )

    assert manager.osc.run.call_args.args[:3] == ("port", "delete", "port-id")


def test_router_port_bypasses_compute_detachment_barrier() -> None:
    manager = CleanupManager.__new__(CleanupManager)
    manager.osc = mock.Mock()
    manager.osc.exists.return_value = False
    manager.config = mock.Mock(convergence_interval=0, resource_timeout=30)
    manager.logger = mock.Mock()
    resource = ResourceRecord(
        sequence=1,
        resource_type="port",
        id="router-port",
        name="router-port",
        parent_id=None,
        metadata={},
        created_at="",
    )
    detail = {
        "device_owner": "network:router_interface",
        "device_id": "router-uuid",
        "binding:host_id": "",
    }

    assert manager._wait_port_detached(resource, detail) is detail


def test_new_port_requires_two_stable_unbound_reads_before_attachment(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(
        convergence_interval=0,
        convergence_timeout=15,
        resource_timeout=30,
    )
    builder.logger = mock.Mock()
    builder.osc = mock.Mock()
    unbound = {
        "id": "port-id",
        "status": "DOWN",
        "device_owner": "",
        "device_id": "",
        "binding:host_id": "",
        "fixed_ips": [{"ip_address": "10.0.0.10"}],
    }
    builder.osc.json.side_effect = [unbound, unbound]

    assert (
        builder._wait_for_port_attachment_ready("port-id", "endpoint-port", timeout=1)
        == unbound
    )
    assert builder.osc.json.call_count == 2
