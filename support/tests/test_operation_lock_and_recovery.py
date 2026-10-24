from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
from types import SimpleNamespace

import pytest

from neutron_flux.cloud_operation import (
    CloudOperationCoordinator,
    CloudOperationOutcome,
)
from neutron_flux.cloud_operation_reconciliation import (
    cloud_operation_scope_fingerprint,
)
from neutron_flux.errors import (
    RetryableMigrationError,
)
from neutron_flux.execution.placement_migration import PlacementMigrationMixin
from neutron_flux.models import ComputeHostInfo, Endpoint
from neutron_flux.state import StateStore


class _Logger:
    def __init__(self) -> None:
        self.lines: list[tuple[str, str]] = []

    def log(self, message: str, level: str = "INFO") -> None:
        self.lines.append((level, message))

    def section(self, message: str) -> None:
        self.lines.append(("SECTION", message))


class _Reporter:
    def __init__(self, run_dir: pathlib.Path, report_dir: pathlib.Path) -> None:
        self.logger = _Logger()
        self.events: list[dict[str, object]] = []
        self.run_dir = run_dir
        self.config = SimpleNamespace(report_dir=report_dir)

    def event(self, event_type: str, message: str, **details: object) -> None:
        self.events.append({"type": event_type, "message": message, "details": details})


def _coordinator(tmp_path: pathlib.Path) -> CloudOperationCoordinator:
    run_dir = tmp_path / "runs" / "current"
    run_dir.mkdir(parents=True, exist_ok=True)
    coordinator = CloudOperationCoordinator(_Reporter(run_dir, tmp_path))
    coordinator._sleep = lambda *_args, **_kwargs: None
    return coordinator


def _write_operation(
    path: pathlib.Path,
    *,
    operation_id: str,
    outcome: str = "AMBIGUOUS",
    resource_id: str = "server-old",
    scope_fingerprint: str | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "schema_version": 1,
        "record_type": "operation",
        "operation_id": operation_id,
        "transaction_id": f"transaction-{operation_id}",
        "kind": "migration",
        "resource_ids": [resource_id],
        "source_host": "compute1",
        "destination_host": "compute2",
        "outcome": outcome,
        "submitted": True,
    }
    if scope_fingerprint is not None:
        record["scope_fingerprint"] = scope_fingerprint
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")


def _endpoint(side: str, host: str) -> Endpoint:
    return Endpoint(
        label=f"group:{side}",
        server_id=f"server-{side}",
        server_name=f"server-{side}",
        management_port_id=f"management-{side}",
        management_ip=f"10.0.0.{2 if side == 'A' else 3}",
        test_port_id=f"test-{side}",
        test_mac=f"fa:16:3e:00:00:0{1 if side == 'A' else 2}",
        fixed_ips={"subnet": f"192.0.2.{2 if side == 'A' else 3}"},
        host=host,
        availability_zone="az1",
        volume_id=None,
        side=side,
    )


def test_global_cloud_operation_lock_blocks_a_second_process(tmp_path):
    report_dir = tmp_path / "reports"
    store = StateStore(report_dir)
    root = pathlib.Path(__file__).resolve().parents[2]
    script = """
from neutron_flux.errors import SuiteError
from neutron_flux.state import StateStore
import pathlib, sys
try:
    with StateStore(pathlib.Path(sys.argv[1])).cloud_operation_lock():
        print('ACQUIRED')
except SuiteError as exc:
    print('BLOCKED:' + str(exc))
"""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(root)
    with store.cloud_operation_lock():
        blocked = subprocess.run(
            [sys.executable, "-c", script, str(tmp_path / "other-reports")],
            cwd=root,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
    acquired = subprocess.run(
        [sys.executable, "-c", script, str(report_dir)],
        cwd=root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    assert blocked.stdout.startswith("BLOCKED:")
    assert "Another Neutron Flux cloud operation process is active" in blocked.stdout
    assert acquired.stdout.strip() == "ACQUIRED"


def test_historical_operation_can_be_resolved_and_replayed_as_terminal(tmp_path):
    journal = tmp_path / "runs" / "old" / "cloud-operations.jsonl"
    _write_operation(journal, operation_id="old-op")
    coordinator = _coordinator(tmp_path)
    assert coordinator.cleanup_blocker("server-old") is not None

    coordinator.resolve(
        "old-op",
        CloudOperationOutcome.FAILED_FINAL,
        evidence={"result": "Nova reports migration failed"},
        message="Authoritative Nova reconciliation proved terminal failure",
    )

    assert coordinator.cleanup_blocker("server-old") is None
    rows = [json.loads(line) for line in journal.read_text().splitlines()]
    assert rows[-1]["outcome"] == "FAILED_FINAL"
    assert rows[-1]["reconciled_from_outcome"] == "AMBIGUOUS"
    replayed = _coordinator(tmp_path)
    assert replayed.cloud_operation_summary()["unresolved_count"] == 0


def test_historical_operation_from_another_scope_does_not_block(tmp_path, monkeypatch):
    monkeypatch.setenv("OS_CLOUD", "current-cloud")
    journal = tmp_path / "runs" / "old" / "cloud-operations.jsonl"
    _write_operation(
        journal,
        operation_id="other-cloud-op",
        scope_fingerprint=cloud_operation_scope_fingerprint(
            {"OS_CLOUD": "other-cloud"}
        ),
    )
    coordinator = _coordinator(tmp_path)
    assert coordinator.cloud_operation_summary()["unresolved_count"] == 0
    assert coordinator.cleanup_blocker("server-old") is None


def test_malformed_historical_line_is_reported_without_fake_global_blocker(tmp_path):
    journal = tmp_path / "runs" / "old" / "cloud-operations.jsonl"
    journal.parent.mkdir(parents=True)
    journal.write_text("{not-json}\n", encoding="utf-8")
    coordinator = _coordinator(tmp_path)
    summary = coordinator.cloud_operation_summary()
    assert summary["unresolved_count"] == 0
    assert summary["external_replay_warnings"]
    assert coordinator.cleanup_blocker() is None


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        (("router", "add", "subnet", "router-1", "subnet-1"), ("router-1", "subnet-1")),
        (("router", "remove", "port", "router-1", "port-1"), ("router-1", "port-1")),
        (
            ("router", "set", "--external-gateway", "network-1", "router-1"),
            ("router-1", "network-1"),
        ),
        (("floating", "ip", "set", "--port", "port-1", "fip-1"), ("fip-1", "port-1")),
        (
            ("server", "migration", "confirm", "server-1", "migration-1"),
            ("server-1", "migration-1"),
        ),
        (("--os-cloud", "prod", "--insecure", "port", "delete", "port-1"), ("port-1",)),
    ],
)
def test_cloud_operation_resource_parser_records_all_relevant_resources(
    command, expected
):
    assert CloudOperationCoordinator._resource_ids_from_command(command) == expected


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        (
            (
                "server",
                "migrate",
                "--live-migration",
                "--shared-migration",
                "server-1",
            ),
            ("server-1",),
        ),
        (
            (
                "port",
                "create",
                "--network",
                "network-1",
                "--no-security-group",
                "port-1",
            ),
            ("port-1", "network-1"),
        ),
        (
            (
                "subnet",
                "create",
                "--network",
                "network-1",
                "--no-dhcp",
                "subnet-1",
            ),
            ("subnet-1",),
        ),
        (
            (
                "security",
                "group",
                "rule",
                "create",
                "--ingress",
                "security-group-1",
            ),
            ("security-group-1",),
        ),
    ],
)
def test_boolean_options_do_not_consume_resource_identifiers(command, expected):
    assert CloudOperationCoordinator._resource_ids_from_command(command) == expected


@pytest.mark.parametrize(
    ("phrase", "expected_kind"),
    list(CloudOperationCoordinator.COMMAND_PHRASES.items()),
)
def test_every_registered_cloud_operation_phrase_is_classifiable(phrase, expected_kind):
    command = tuple(phrase) + ("resource-1",)
    assert (
        CloudOperationCoordinator.classify_openstack_command(command) == expected_kind
    )


def test_one_attempt_budget_submits_exactly_once_and_reports_the_real_budget():
    moving = _endpoint("B", "compute1")
    stationary = _endpoint("A", "compute1")
    target = ComputeHostInfo("compute2", "az1", True, True)
    calls: list[str] = []

    def fail_once(*_args):
        calls.append("submit")
        raise RetryableMigrationError(
            "authoritative rejection",
            proven_failure=True,
            accepted=False,
            evidence={"status": "failed"},
        )

    holder = type("PlacementHarness", (PlacementMigrationMixin,), {})()
    holder.builder = SimpleNamespace(
        live_migrate_endpoint=fail_once,
        cloud_operation_coordinator=None,
    )
    holder.logger = _Logger()
    result = holder._execute_migration_attempts(
        [(moving, stationary, target)],
        migration_kind="live",
        submission_budget=1,
    )

    _migration, _endpoint_result, details, terminal_error, _all_unavailable = result
    assert calls == ["submit"]
    assert len(details) == 1
    assert details[0]["effective_submission_budget"] == 1
    assert details[0]["retry_permitted"] is False
    assert terminal_error == "authoritative rejection"
    assert any("1/1" in message for _level, message in holder.logger.lines)


def test_source_audit_ignores_type_checking_only_import_cycles(tmp_path):
    import importlib.util

    script = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "source-audit.py"
    spec = importlib.util.spec_from_file_location("neutron_flux_source_audit", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    root = tmp_path
    package = root / "neutron_flux"
    package.mkdir()
    first = package / "first.py"
    second = package / "second.py"
    first.write_text("from . import second\n", encoding="utf-8")
    second.write_text(
        "from typing import TYPE_CHECKING\n"
        "if TYPE_CHECKING:\n"
        "    from . import first\n",
        encoding="utf-8",
    )
    module.ROOT = root
    graph = module.import_graph([first, second])
    assert graph["neutron_flux.first"] == {"neutron_flux.second"}
    assert graph["neutron_flux.second"] == set()
    assert module.find_cycles(graph) == []
