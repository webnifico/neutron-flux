from __future__ import annotations

import copy
import time
from typing import Any

from ..cancellation import raise_if_cancelled
from ..errors import RunCancelledError, SuiteError
from ..models import Endpoint
from ..utils import list_value, nova_task_state_cleared, pick


class LiveMigrationRetryMixin:
    """Revalidate a rolled-back live migration without requiring guest traffic."""

    _LIVE_RETRY_KEY = "_live_migration_retry"
    _TERMINAL_MIGRATION_STATES = {
        "confirmed",
        "finished",
        "completed",
        "done",
        "cancelled",
        "canceled",
        "error",
        "failed",
        "reverted",
    }

    def _live_retry_has_down_ports(self: Any, endpoint: Endpoint) -> bool:
        for port_id in (endpoint.management_port_id, endpoint.test_port_id):
            if not port_id:
                continue
            try:
                port = self._json_with_transient_retry(
                    "port",
                    "show",
                    port_id,
                    check=False,
                    timeout=min(30, self.config.resource_timeout),
                    context="checking whether live rollback left a port DOWN",
                )
            except RunCancelledError:
                raise
            except SuiteError:
                continue
            if (
                isinstance(port, dict)
                and str(pick(port, "status", default="")).upper() == "DOWN"
            ):
                return True
        return False

    def _live_action_rows(self: Any, endpoint: Endpoint) -> list[dict[str, Any]]:
        rows = self._json_with_transient_retry(
            "server",
            "event",
            "list",
            endpoint.server_id,
            check=False,
            timeout=min(30, self.config.resource_timeout),
            context=f"reading live-migration actions for {endpoint.label}",
        )
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise SuiteError("Nova did not expose usable server action records")
        return [
            row
            for row in rows
            if str(pick(row, "action", default="")).replace("_", "-")
            == "live-migration"
        ]

    def _live_action_ids(self: Any, endpoint: Endpoint) -> set[str] | None:
        try:
            rows = self._live_action_rows(endpoint)
            ids = {str(pick(row, "request_id", default="") or "") for row in rows}
            return ids if "" not in ids else None
        except RunCancelledError:
            raise
        except SuiteError as exc:
            self.logger.log(
                f"Live-migration action inventory unavailable: {exc}", "WARNING"
            )
            return None

    def _live_rollback_evidence(
        self: Any, endpoint: Endpoint, before: dict[str, Any]
    ) -> dict[str, Any]:
        prior_ids = before.get("live_action_ids")
        if prior_ids is None:
            raise SuiteError(
                "Pre-migration action IDs are unavailable; rollback cannot be correlated"
            )
        rows = self._live_action_rows(endpoint)
        new_rows = [row for row in rows if pick(row, "request_id") not in prior_ids]
        if len(new_rows) != 1 or not pick(new_rows[0], "request_id"):
            raise SuiteError(
                "Nova did not expose exactly one new live-migration action"
            )
        request_id = str(pick(new_rows[0], "request_id"))
        detail = self._json_with_transient_retry(
            "server",
            "event",
            "show",
            endpoint.server_id,
            request_id,
            check=False,
            timeout=min(30, self.config.resource_timeout),
            context=f"verifying destination rollback for {endpoint.label}",
        )
        if not isinstance(detail, dict):
            raise SuiteError("Nova did not expose live-migration action details")
        if str(pick(detail, "request_id", "id", default="")) != request_id:
            raise SuiteError("Nova returned a different live-migration action")
        events = list_value(pick(detail, "events", default=[]))
        if not events or any(not isinstance(event, dict) for event in events):
            raise SuiteError("Nova did not expose rollback events")
        if any(not pick(event, "finish_time") for event in events):
            raise SuiteError("A live-migration action event has not finished")
        rollbacks = [
            event
            for event in events
            if pick(event, "event") == "compute_rollback_live_migration_at_destination"
        ]
        if not rollbacks or any(
            str(pick(event, "result", default="")).lower() != "success"
            for event in rollbacks
        ):
            raise SuiteError("Nova has not confirmed successful destination rollback")
        return {"request_id": request_id, "events": events, "rollback_verified": True}

    def _live_retry_observation(
        self: Any, endpoint: Endpoint, target_host: str, before: dict[str, Any]
    ) -> dict[str, Any]:
        source_host = before.get("source_host")
        if before.get("server_id") != endpoint.server_id or not source_host:
            raise SuiteError(
                "The retry baseline does not identify this server and source host"
            )
        rows, error = self._migration_rows(endpoint.server_id)
        if rows is None or before.get("migration_ids") is None:
            raise SuiteError(
                f"Migration inventory is unavailable: {error or 'missing baseline'}"
            )
        if any(
            str(pick(row, "status", default="") or "").lower()
            not in self._TERMINAL_MIGRATION_STATES
            for row in rows
        ):
            raise SuiteError("A migration is still running or has an unknown state")
        new_rows = [
            row
            for row in rows
            if self._migration_row_id(row) not in before["migration_ids"]
        ]
        if len(new_rows) != 1:
            raise SuiteError("Expected exactly one new failed live-migration record")
        row = new_rows[0]
        if (
            not self._migration_row_id(row)
            or str(pick(row, "status", default="")).lower()
            not in {"failed", "error", "cancelled", "canceled", "reverted"}
            or str(pick(row, "type", "migration_type", default="")).lower()
            not in self._LIVE_TYPES
            or pick(row, "source_compute", "source_host") != source_host
            or pick(row, "dest_compute", "destination_compute", "dest_host")
            != target_host
        ):
            raise SuiteError("The failed migration does not match this live submission")
        server = self._json_with_transient_retry(
            "server",
            "show",
            endpoint.server_id,
            check=False,
            timeout=min(30, self.config.resource_timeout),
            context=f"verifying source state for live retry of {endpoint.label}",
        )
        required = (
            ("status",),
            ("os_ext_sts_task_state", "task_state"),
            ("os_ext_sts_power_state", "power_state"),
            ("os_ext_srv_attr_host", "host"),
        )
        if not isinstance(server, dict) or not all(
            self._migration_field_visible(server, *keys) for keys in required
        ):
            raise SuiteError("Nova hid required source-server state")
        state = {
            "status": str(pick(server, "status", default="")).lower(),
            "host": pick(server, "os_ext_srv_attr_host", "host"),
            "task_state": pick(server, "os_ext_sts_task_state", "task_state"),
            "task_state_cleared": nova_task_state_cleared(server),
            "power_state": str(
                pick(server, "os_ext_sts_power_state", "power_state")
            ).lower(),
        }
        if (
            state["status"] != "active"
            or state["host"] != source_host
            or state["task_state_cleared"] is not True
            or state["power_state"] not in {"1", "running", "active"}
        ):
            raise SuiteError(
                f"Source server has not settled after live failure: {state}"
            )
        expected_ports = {
            port
            for port in (endpoint.management_port_id, endpoint.test_port_id)
            if port
        }
        if set(before.get("ports", {})) != expected_ports:
            raise SuiteError("Retry baseline does not contain all endpoint ports")
        ports = {}
        for port_id, expected in before["ports"].items():
            port = self._json_with_transient_retry(
                "port",
                "show",
                port_id,
                check=False,
                timeout=min(30, self.config.resource_timeout),
                context=f"verifying port identity for live retry: {port_id}",
            )
            if not isinstance(port, dict) or not all(
                self._migration_field_visible(port, *keys)
                for keys in (
                    ("device_id",),
                    ("binding_host_id", "binding:host_id"),
                    ("binding_vif_type", "binding:vif_type"),
                    ("status",),
                    ("mac_address",),
                    ("fixed_ips",),
                    ("security_group_ids", "security_groups"),
                )
            ):
                raise SuiteError(
                    f"Neutron hid required retry fields for port {port_id}"
                )
            actual = {
                "mac_address": str(pick(port, "mac_address", default="")),
                "fixed_ips": self._fixed_ips(port),
                "security_groups": sorted(self._port_security_groups(port)),
            }
            if any(actual[key] != expected[key] for key in actual):
                raise SuiteError(f"Port {port_id} identity changed after migration")
            actual.update(
                device_id=pick(port, "device_id"),
                binding_host_id=pick(port, "binding_host_id", "binding:host_id"),
                binding_vif_type=pick(port, "binding_vif_type", "binding:vif_type"),
                status=str(pick(port, "status", default="")).upper(),
            )
            if (
                actual["device_id"] != endpoint.server_id
                or actual["binding_host_id"] != source_host
                or not actual["binding_vif_type"]
                or actual["binding_vif_type"] in {"unbound", "binding_failed"}
                or actual["status"] not in {"ACTIVE", "DOWN"}
            ):
                raise SuiteError(
                    f"Port {port_id} has not returned to its source binding: {actual}"
                )
            ports[port_id] = actual
        volume_ids = (
            set()
            if self.config.storage == "host"
            else self._server_volume_ids(endpoint.server_id)
        )
        if (
            volume_ids is None
            or before.get("volume_ids") is None
            or volume_ids != set(before["volume_ids"])
        ):
            raise SuiteError(
                "Volume attachments changed or could not be verified after migration"
            )
        for volume_id in sorted(volume_ids):
            verified, error, volume = self._verify_expected_volume_attachment(
                volume_id, endpoint.server_id
            )
            attachments = list_value(pick(volume, "attachments", default=[]))
            if verified is not True or len(attachments) != 1:
                raise SuiteError(
                    f"Volume {volume_id} attachment did not settle: {error or attachments}"
                )
            host = str(pick(attachments[0], "host_name", default="") or "")
            if host and host.split(".")[0] != str(source_host).split(".")[0]:
                raise SuiteError(f"Volume {volume_id} remains attached on {host}")
        rollback = self._live_rollback_evidence(endpoint, before)
        return {
            "server": state,
            "ports": ports,
            "volume_ids": sorted(volume_ids),
            "migration_record": row,
            "migration_ids": sorted(self._migration_row_id(r) for r in rows),
            "rollback": rollback,
            "recovery_retry": True,
            "network_recovery_verified": False,
        }

    def _prepare_live_retry(
        self: Any, endpoint: Endpoint, target_host: str, before: dict[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Require stable source ownership and a completed rollback before retry."""
        if not before.get("guest_marker"):
            raise SuiteError(
                "The original guest marker is unavailable for retry validation"
            )
        deadline = time.monotonic() + min(120, self.config.resource_timeout)
        observations: list[dict[str, Any]] = []
        last_error = "Source rollback has not settled"
        while time.monotonic() < deadline:
            raise_if_cancelled()
            try:
                observation = self._live_retry_observation(
                    endpoint, target_host, before
                )
            except RunCancelledError:
                raise
            except SuiteError as exc:
                observations.clear()
                last_error = str(exc)
            else:
                if observations and observation != observations[-1]:
                    observations.clear()
                observations.append(observation)
                if len(observations) == 3:
                    rebased = copy.deepcopy(before)
                    rebased["migration_ids"] = set(observation["migration_ids"])
                    rebased["live_action_ids"] = set(before["live_action_ids"]) | {
                        observation["rollback"]["request_id"]
                    }
                    evidence = {**observation, "stable_observations": 3}
                    self.reporter.event(
                        "live-migration-retry-ready",
                        "Nova rollback and source ownership verified; guest network recovery remains unverified",
                        server_id=endpoint.server_id,
                        target_host=target_host,
                        **evidence,
                    )
                    return rebased, evidence
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(5, remaining))
        raise SuiteError(f"Live-migration rollback did not settle: {last_error}")
