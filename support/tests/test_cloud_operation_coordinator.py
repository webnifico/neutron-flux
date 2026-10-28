from __future__ import annotations

import subprocess

import pytest

from neutron_flux.cloud_operation import CloudOperationCoordinator
from neutron_flux.openstack import OpenStack


class _Logger:
    def __init__(self) -> None:
        self.lines: list[tuple[str, str]] = []

    def log(self, message: str, level: str = "INFO") -> None:
        self.lines.append((level, message))


class _Reporter:
    def __init__(self) -> None:
        self.logger = _Logger()
        self.events: list[dict[str, object]] = []

    def event(self, event_type: str, message: str, **details: object) -> None:
        self.events.append({"type": event_type, "message": message, "details": details})


def test_classifies_every_dataplane_cloud_operation_family() -> None:
    classify = CloudOperationCoordinator.classify_openstack_command
    assert classify(("port", "create", "p1")) == "port-create"
    assert classify(("port", "delete", "p1")) == "port-delete"
    assert classify(("server", "create", "vm1")) == "server-create"
    assert classify(("server", "delete", "vm1")) == "server-delete"
    assert classify(("server", "migrate", "--live-migration", "vm1")) == "migration"
    assert classify(("server", "migration", "confirm", "vm1")) == "migration"
    assert classify(("router", "add", "subnet", "r1", "s1")) == "router-interface"
    assert classify(("floating", "ip", "set", "--port", "p1", "f1")) == "floating-ip"
    assert (
        classify(("security", "group", "rule", "create", "sg1"))
        == "security-group-rule"
    )
    assert classify(("port", "show", "p1")) is None
    assert classify(("server", "list")) is None


def test_cloud_operations_are_spaced_and_quiet_periods_are_recorded() -> None:
    reporter = _Reporter()
    coordinator = CloudOperationCoordinator(reporter)
    sleeps: list[tuple[float, str]] = []
    coordinator._sleep = lambda seconds, reason: sleeps.append((seconds, reason))  # type: ignore[method-assign]

    coordinator.execute("port-create", ("port", "create", "p1"), lambda: "p1")
    coordinator.execute("port-delete", ("port", "delete", "p1"), lambda: "gone")

    assert any("after port-create cloud operation" in reason for _, reason in sleeps)
    assert any("spacing before port-delete" in reason for _, reason in sleeps)
    assert any("after port-delete cloud operation" in reason for _, reason in sleeps)
    finishes = [
        item for item in reporter.events if item["type"] == "cloud-operation-finish"
    ]
    assert len(finishes) == 2
    assert finishes[0]["details"]["kind"] == "port-create"
    assert finishes[1]["details"]["kind"] == "port-delete"


def test_failed_cloud_operation_increases_adaptive_backoff() -> None:
    reporter = _Reporter()
    coordinator = CloudOperationCoordinator(reporter)
    coordinator._sleep = lambda *_args, **_kwargs: None  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="boom"):
        coordinator.execute(
            "port-create",
            ("port", "create", "p1"),
            lambda: (_ for _ in ()).throw(RuntimeError("boom")),
        )

    assert coordinator.adaptive_factor == 1.5
    finish = next(
        item for item in reporter.events if item["type"] == "cloud-operation-finish"
    )
    assert finish["details"]["success"] is False
    assert finish["details"]["adaptive_level_after"] == 1


def test_openstack_adapter_cannot_bypass_coordinator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reporter = _Reporter()
    coordinator = CloudOperationCoordinator(reporter)
    coordinator._sleep = lambda *_args, **_kwargs: None  # type: ignore[method-assign]
    calls: list[list[str]] = []

    def fake_run(command, **_kwargs):
        calls.append(list(command))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("neutron_flux.openstack.run_cancellable", fake_run)
    osc = OpenStack(reporter.logger, cloud_operation_coordinator=coordinator)

    osc.run("port", "show", "p1")
    osc.run("port", "delete", "p1")

    starts = [
        item for item in reporter.events if item["type"] == "cloud-operation-start"
    ]
    assert len(starts) == 1
    assert starts[0]["details"]["kind"] == "port-delete"
    assert calls == [
        ["openstack", "port", "show", "p1"],
        ["openstack", "port", "delete", "p1"],
    ]


def test_freeze_keeps_multistep_lifecycle_under_one_global_lock() -> None:
    reporter = _Reporter()
    coordinator = CloudOperationCoordinator(reporter)
    coordinator._sleep = lambda *_args, **_kwargs: None  # type: ignore[method-assign]

    with coordinator.freeze("migration", "migration sequence"):
        coordinator.execute("port-delete", ("port", "delete", "p1"), lambda: None)
        coordinator.settle("migration", "migration rebinding settled")

    event_types = [
        item["type"] for item in reporter.events if item["type"] != "runtime-timing"
    ]
    assert event_types[0] == "cloud-operation-freeze-start"
    assert "cloud-operation-start" in event_types
    assert "dataplane-settlement" in event_types
    assert event_types[-1] == "cloud-operation-freeze-end"


def test_nonzero_openstack_result_increases_backoff_without_hiding_result() -> None:
    reporter = _Reporter()
    coordinator = CloudOperationCoordinator(reporter)
    coordinator._sleep = lambda *_args, **_kwargs: None  # type: ignore[method-assign]
    result = subprocess.CompletedProcess(
        ["openstack", "port", "delete", "p1"], 1, "", "HTTP 503 service unavailable"
    )

    returned = coordinator.execute(
        "port-delete",
        ("port", "delete", "p1"),
        lambda: result,
    )

    assert returned is result
    assert coordinator.adaptive_factor == 1.5
    finish = [
        item for item in reporter.events if item["type"] == "cloud-operation-finish"
    ][-1]
    assert finish["details"]["success"] is False
