from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.cloud_operation import CloudOperationCoordinator
from neutron_flux.errors import CommandTimeoutError
from neutron_flux.models import Endpoint
from neutron_flux.runtime.control.servers import ServerRuntimeMixin
from neutron_flux.runtime.migration_validation import MigrationValidationMixin


class _Logger:
    def __init__(self) -> None:
        self.lines: list[tuple[str, str]] = []

    def log(self, message: str, level: str = "INFO") -> None:
        self.lines.append((level, message))


class _Reporter:
    def __init__(self, run_dir, report_dir) -> None:
        self.logger = _Logger()
        self.events: list[dict[str, object]] = []
        self.run_dir = run_dir
        self.config = SimpleNamespace(report_dir=report_dir)

    def event(self, event_type: str, message: str, **details: object) -> None:
        self.events.append({"type": event_type, "message": message, "details": details})


def _coordinator(tmp_path) -> CloudOperationCoordinator:
    run_dir = tmp_path / "runs" / "current"
    run_dir.mkdir(parents=True, exist_ok=True)
    coordinator = CloudOperationCoordinator(_Reporter(run_dir, tmp_path))
    coordinator._sleep = lambda *_args, **_kwargs: None
    return coordinator


def _endpoint() -> Endpoint:
    return Endpoint(
        label="provider:B",
        server_id="server-b",
        server_name="server-b",
        management_port_id="port-mgmt",
        management_ip="10.0.0.3",
        test_port_id="port-test",
        test_mac="fa:16:3e:00:00:02",
        fixed_ips={"subnet": "192.0.2.3"},
        host="compute1",
        availability_zone="az1",
        volume_id="volume-b",
        side="B",
    )


def test_server_settlement_supports_migration_stability_and_power_checks():
    harness = ServerRuntimeMixin()
    harness.config = SimpleNamespace(
        resource_timeout=5,
        convergence_timeout=5,
        convergence_interval=0,
    )
    harness.logger = _Logger()
    server_reads = 0

    def json_result(resource: str, action: str, resource_id: str, **_kwargs):
        nonlocal server_reads
        assert action == "show"
        if resource == "server":
            server_reads += 1
            return {
                "status": "ACTIVE",
                "OS-EXT-STS:task_state": None,
                "OS-EXT-STS:power_state": 1,
                "OS-EXT-SRV-ATTR:host": "compute2",
            }
        return {
            "device_id": "server-b",
            "binding:host_id": "compute2",
            "status": "ACTIVE",
        }

    harness.osc = SimpleNamespace(json=json_result)
    detail = harness._wait_for_server_settlement(
        "server-b",
        ["port-mgmt", "port-test"],
        expected_statuses={"active"},
        expected_host="compute2",
        stable_observations=3,
        require_power_state=True,
    )

    assert detail["OS-EXT-SRV-ATTR:host"] == "compute2"
    assert server_reads == 3
    assert any("stable_reads=3" in message for _level, message in harness.logger.lines)


def test_migration_baseline_scopes_quarantine_to_server_ports_and_volumes():
    endpoint = _endpoint()
    coordinator = mock.Mock()
    harness = MigrationValidationMixin()
    harness.config = SimpleNamespace(storage="volume", resource_timeout=60)
    harness.cloud_operation_coordinator = coordinator
    harness._json_with_transient_retry = mock.Mock(
        return_value={
            "device_id": endpoint.server_id,
            "status": "ACTIVE",
            "binding:host_id": endpoint.host,
            "mac_address": "fa:16:3e:00:00:02",
            "fixed_ips": [{"subnet_id": "subnet", "ip_address": "192.0.2.3"}],
            "security_group_ids": ["sg-1"],
        }
    )
    harness._fixed_ips = mock.Mock(return_value={"subnet": "192.0.2.3"})
    harness._port_security_groups = mock.Mock(return_value={"sg-1"})
    harness._migration_rows = mock.Mock(return_value=([], None))
    harness._server_volume_ids = mock.Mock(return_value={"volume-b", "volume-c"})
    harness._verify_expected_volume_attachment = mock.Mock(
        return_value=(True, None, {})
    )
    harness._create_guest_migration_marker = mock.Mock(return_value={"marker": "ok"})

    state = harness._capture_endpoint_migration_state(endpoint)

    assert state["volume_ids"] == {"volume-b", "volume-c"}
    call = coordinator.annotate_current_transaction.call_args
    assert call.kwargs["resource_ids"] == [
        "server-b",
        "port-mgmt",
        "port-test",
        "volume-b",
        "volume-c",
    ]


def test_ambiguous_migration_blocks_only_direct_resources(tmp_path):
    coordinator = _coordinator(tmp_path)
    with coordinator.transaction(
        "migration",
        "ambiguous live migration",
        resource_ids=["server-b", "port-mgmt", "port-test", "volume-b"],
        source_host="compute1",
        destination_host="compute2",
    ):
        with pytest.raises(CommandTimeoutError):
            coordinator.execute(
                "migration",
                (
                    "server",
                    "migrate",
                    "--live-migration",
                    "--host",
                    "compute2",
                    "server-b",
                ),
                lambda: (_ for _ in ()).throw(
                    CommandTimeoutError(["openstack", "server", "migrate"], 60)
                ),
            )
        coordinator.keep_current_ambiguity("post-submission verification failed")

    for resource_id in ("server-b", "port-mgmt", "port-test", "volume-b"):
        assert coordinator.cleanup_blocker(resource_id) is not None
    assert coordinator.cleanup_blocker("server-a") is None
    assert coordinator.cleanup_blocker("controller-server") is None
    assert coordinator.cleanup_blocker("run-keypair") is None
    assert coordinator.cleanup_blocker() is not None


def test_nonmigration_ambiguity_remains_run_wide_cleanup_blocker(tmp_path):
    coordinator = _coordinator(tmp_path)
    with coordinator.transaction(
        "port-create",
        "ambiguous port create",
        resource_ids=["port-new"],
    ):
        with pytest.raises(CommandTimeoutError):
            coordinator.execute(
                "port-create",
                ("port", "create", "--network", "network-1", "port-new"),
                lambda: (_ for _ in ()).throw(
                    CommandTimeoutError(["openstack", "port", "create"], 60)
                ),
            )
        coordinator.keep_current_ambiguity("port creation acceptance unknown")

    assert coordinator.cleanup_blocker("unrelated-server") is not None
