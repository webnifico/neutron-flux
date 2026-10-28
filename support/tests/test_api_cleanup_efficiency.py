from __future__ import annotations

import json
import subprocess
import threading
from collections import Counter
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.cleanup import CleanupManager
from neutron_flux.errors import CommandError, RunCancelledError, SuiteError
from neutron_flux.models import ResourceRecord
from neutron_flux.openstack import OpenStack, PresenceResult
from neutron_flux.reporting import Reporter, ResourceTracker
from neutron_flux.utils import iso_utc


def _completed(payload=None, *, error=""):
    return subprocess.CompletedProcess(
        [], 1 if error else 0, json.dumps(payload) if payload is not None else "", error
    )


def _fip(port="port-a"):
    return {
        "ID": "floating-one",
        "Floating IP Address": "198.51.100.20",
        "Fixed IP Address": "10.0.0.20" if port else None,
        "Port": port,
    }


def test_formatter_capability_is_remembered_but_association_is_always_fresh():
    osc = OpenStack(mock.Mock())
    osc.run = mock.Mock(
        side_effect=[
            _completed(error="Invalid formatter provided."),
            _completed([_fip()]),
            _completed([_fip("port-b")]),
            _completed([_fip(None)]),
        ]
    )
    assert osc.json("floating", "ip", "show", "floating-one")["port_id"] == "port-a"
    assert osc.json("floating", "ip", "show", "floating-one")["port_id"] == "port-b"
    assert (
        osc.presence("floating_ip", "floating-one", include_data=True).data["port_id"]
        is None
    )
    assert [call.args[:3] for call in osc.run.call_args_list] == [
        ("floating", "ip", "show"),
        ("floating", "ip", "list"),
        ("floating", "ip", "list"),
        ("floating", "ip", "list"),
    ]


@pytest.mark.parametrize("presence", [False, True])
def test_cached_formatter_mode_uses_show_to_confirm_missing_list_row(presence):
    osc = OpenStack(mock.Mock())
    osc._floating_ip_show_formatter_broken = True
    osc.run = mock.Mock(
        side_effect=[
            _completed([]),
            _completed(error="No FloatingIP found for floating-one"),
        ]
    )
    if presence:
        assert osc.presence("floating_ip", "floating-one").absent
    else:
        assert osc.json("floating", "ip", "show", "floating-one", check=False) is None
    assert [call.args[:3] for call in osc.run.call_args_list] == [
        ("floating", "ip", "list"),
        ("floating", "ip", "show"),
    ]


def test_hidden_list_row_never_establishes_absence():
    osc = OpenStack(mock.Mock())
    osc._floating_ip_show_formatter_broken = True
    osc.run = mock.Mock(
        side_effect=[
            _completed([]),
            _completed(error="Invalid formatter provided."),
            _completed([]),
        ]
    )
    assert osc.presence("floating_ip", "floating-one").unknown


@pytest.mark.parametrize("rows", [[_fip(), _fip()], [{"ID": "floating-one"}], ["bad"]])
def test_cached_formatter_mode_still_rejects_bad_or_ambiguous_lists(rows):
    osc = OpenStack(mock.Mock())
    osc._floating_ip_show_formatter_broken = True
    osc.run = mock.Mock(return_value=_completed(rows))
    assert osc.presence("floating_ip", "floating-one").unknown
    with pytest.raises(SuiteError):
        osc.json("floating", "ip", "show", "floating-one", check=False)
    assert all(c.args[:3] == ("floating", "ip", "list") for c in osc.run.call_args_list)


@pytest.mark.parametrize(
    "error",
    ["HTTP 401 Unauthorized", "HTTP 403 Forbidden", "HTTP 503 Service Unavailable"],
)
def test_cached_formatter_mode_does_not_hide_read_failures(error):
    osc = OpenStack(mock.Mock())
    osc._floating_ip_show_formatter_broken = True
    osc.run = mock.Mock(return_value=_completed(error=error))
    assert osc.presence("floating_ip", "floating-one").unknown
    with pytest.raises(CommandError):
        osc.json("floating", "ip", "show", "floating-one", check=False)


def test_cached_formatter_mode_propagates_cancellation():
    osc = OpenStack(mock.Mock())
    osc._floating_ip_show_formatter_broken = True
    osc.run = mock.Mock(side_effect=RunCancelledError("cancelled"))
    with pytest.raises(RunCancelledError):
        osc.presence("floating_ip", "floating-one")


@pytest.mark.parametrize("project", [False, True])
def test_cleanup_inventory_reads_overlap_but_ownership_merges_on_parent(
    config_factory, project
):
    reporter = Reporter(config_factory(action="cleanup"), "nflux-20000101000000-abcd03")
    tracker = ResourceTracker(reporter)
    parent = threading.get_ident()
    add = tracker.add
    journal_threads = []

    def record(*args, **kwargs):
        journal_threads.append(threading.get_ident())
        return add(*args, **kwargs)

    tracker.add = record
    lock = threading.Lock()
    family_barrier = threading.Barrier(4, timeout=5)
    server_barrier = threading.Barrier(4, timeout=5)
    calls = Counter()
    active = peak = family_started = server_started = 0
    stale = "nflux-20200101000000-abcd01"
    live = "nflux-20200101000000-abcd02"

    def inventory(*args, **kwargs):
        nonlocal active, peak, family_started, server_started
        is_show = args[:2] == ("server", "show")
        with lock:
            calls[args] += 1
            active += 1
            peak = max(peak, active)
            index = server_started if is_show else family_started
            if is_show:
                server_started += 1
            else:
                family_started += 1
        try:
            if index < 4:
                (server_barrier if is_show else family_barrier).wait()
            if is_show:
                live_server = project and args[2] == "server-0"
                return {
                    "id": args[2],
                    "name": f"{live if live_server else stale}-vm",
                    "properties": {
                        "neutron_flux_run_id": live
                        if live_server
                        else stale
                        if project
                        else reporter.run_id,
                        "neutron_flux_state": "active" if live_server else "complete",
                        "neutron_flux_heartbeat": iso_utc()
                        if live_server
                        else "2020-01-01T00:00:00Z",
                    },
                }
            if args[:2] == ("server", "list"):
                return [{"ID": f"server-{i}", "Name": "vm"} for i in range(6)]
            if not project and args[:2] in {("network", "list"), ("router", "list")}:
                return [{"ID": args[0], "Name": f"{reporter.name_prefix}-{args[0]}"}]
            return []
        finally:
            with lock:
                active -= 1

    manager = CleanupManager(
        SimpleNamespace(json=inventory), reporter, tracker, reporter.config
    )
    try:
        if project:
            result = manager._discover_project_orphans()
            assert [row["id"] for row in result["protected"]] == ["server-0"]
            assert [row["id"] for row in result["candidates"]] == [
                f"server-{i}" for i in range(1, 6)
            ]
        else:
            assert manager._adopt_orphans(reporter.run_tag, reporter.name_prefix) == 8
            assert [row.id for row in reporter.resources] == [
                *[f"server-{i}" for i in range(6)],
                "router",
                "network",
            ]
            assert journal_threads == [parent] * 8
        assert peak == 4
        assert all(calls[("server", "show", f"server-{i}")] == 1 for i in range(6))
    finally:
        reporter.logger.close()


def test_post_delete_timeout_and_first_poll_share_one_fresh_read(config_factory):
    reporter = Reporter(config_factory(action="cleanup"), "delete-observation-reuse")
    tracker = ResourceTracker(reporter)
    resource = tracker.add("server", "server-one", "vm")
    osc = SimpleNamespace(presence=mock.Mock(return_value=PresenceResult("present")))
    manager = CleanupManager(osc, reporter, tracker, reporter.config)
    manager._cleanup_observation = mock.Mock(return_value=(False, {}))
    manager._cleanup_progress_details = mock.Mock(
        side_effect=AssertionError("extra read")
    )
    order = []
    handler = mock.Mock(side_effect=lambda _resource: order.append("delete"))
    manager._cleanup_observation.side_effect = lambda *_: (
        order.append("fresh-after-delete") or False,
        {},
    )
    try:
        manager._delete_record(resource, handler)
        assert resource.delete_status == "deleted"
        assert order == ["delete", "fresh-after-delete"]
        manager._cleanup_observation.assert_called_once_with("server", "server-one")
        manager._cleanup_progress_details.assert_not_called()
    finally:
        reporter.logger.close()


def test_reused_present_observation_still_requires_fresh_absence(
    config_factory, monkeypatch
):
    manager = object.__new__(CleanupManager)
    manager.config = config_factory()
    manager.logger = mock.Mock()
    manager._cleanup_observation = mock.Mock(return_value=(False, {}))
    monkeypatch.setattr(
        "neutron_flux.cleanup_components.deletion.time.sleep", lambda *_: None
    )
    assert manager._wait_absent(
        "server", "server-one", 10, "vm", (True, {"task_state": "deleting"})
    )
    manager._cleanup_observation.assert_called_once_with("server", "server-one")
    resource = ResourceRecord(1, "server", "server-one", "vm", None, {}, iso_utc())
    assert manager._deletion_timeout(resource, {"task_state": "deleting"}) >= 300


@pytest.mark.parametrize("kind", ["router", "network"])
def test_cleanup_port_details_overlap_before_ordered_mutations(config_factory, kind):
    manager = object.__new__(CleanupManager)
    manager.config = config_factory()
    manager.logger = mock.Mock()
    manager._clear_router_routes = mock.Mock()
    parent = threading.get_ident()
    barrier = threading.Barrier(3, timeout=5)
    lock = threading.Lock()
    completed_reads = set()
    mutations = []

    def read(*args, **kwargs):
        if args[:2] == ("port", "list"):
            return [{"ID": f"port-{i}"} for i in range(3)]
        if args[:2] == ("port", "show"):
            assert not mutations
            barrier.wait()
            with lock:
                completed_reads.add(args[2])
            return {
                "id": args[2],
                "device_owner": "network:router_interface" if kind == "router" else "",
            }
        raise AssertionError(args)

    def remove(*args, **kwargs):
        if args[:2] == ("router", "remove") or args[-2:] == ("delete", "resource"):
            assert completed_reads == {f"port-{i}" for i in range(3)}
            assert threading.get_ident() == parent
            mutations.append(args[-1])
        return _completed()

    manager.osc = SimpleNamespace(json=read, exists=lambda *_: True, run=remove)
    manager._delete_port = lambda resource: (
        mutations.append(resource.id),
        threading.get_ident() == parent or pytest.fail("mutation left parent thread"),
    )
    resource = ResourceRecord(1, kind, "resource", "fixture", None, {}, iso_utc())
    if kind == "router":
        manager._delete_router(resource)
    else:
        manager._delete_network(resource)
    assert mutations == ["port-0", "port-1", "port-2", "resource"]


@pytest.mark.parametrize("project", [False, True])
def test_parallel_inventory_server_errors_cannot_approve_cleanup(
    config_factory, project
):
    reporter = Reporter(config_factory(action="cleanup"), "nflux-20000101000000-abcd04")
    tracker = ResourceTracker(reporter)

    def read(*args, **kwargs):
        if args[:2] == ("server", "list"):
            return [{"ID": "server-one", "Name": "vm"}]
        if args[:2] == ("server", "show"):
            raise SuiteError("HTTP 503 server detail unavailable")
        return []

    manager = CleanupManager(
        SimpleNamespace(json=read), reporter, tracker, reporter.config
    )
    try:
        if project:
            with pytest.raises(SuiteError, match="HTTP 503"):
                manager._discover_project_orphans()
        else:
            errors = []
            assert (
                manager._adopt_orphans(
                    reporter.run_tag, reporter.name_prefix, discovery_errors=errors
                )
                == 0
            )
            assert any(
                "ownership verification failed" in error and "HTTP 503" in error
                for error in errors
            )
        assert reporter.resources == []
    finally:
        reporter.logger.close()


def test_parallel_inventory_cancellation_prevents_parent_journal_updates(
    config_factory,
):
    reporter = Reporter(config_factory(action="cleanup"), "nflux-20000101000000-abcd05")
    tracker = ResourceTracker(reporter)

    def read(*args, **kwargs):
        if args[:2] == ("network", "list"):
            raise RunCancelledError("cancelled inventory")
        if args[:2] == ("router", "list"):
            return [{"ID": "router-one", "Name": f"{reporter.name_prefix}-router"}]
        return []

    manager = CleanupManager(
        SimpleNamespace(json=read), reporter, tracker, reporter.config
    )
    try:
        with pytest.raises(RunCancelledError, match="cancelled inventory"):
            manager._adopt_orphans(reporter.run_tag, reporter.name_prefix)
        assert reporter.resources == []
    finally:
        reporter.logger.close()
