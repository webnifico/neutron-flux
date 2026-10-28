from __future__ import annotations

import copy
import json
import re
import subprocess
import time
from contextlib import nullcontext
from typing import Any

# mypy: disable-error-code="attr-defined"
from ...errors import (
    CommandError,
    CommandTimeoutError,
    PlacementUnavailableError,
    SuiteError,
)
from ...failure_injection import inject_failure
from ...resource_naming import (
    claim_runtime_resource_name,
    managed_resource_name,
)
from ...scheduling import READ_WORKERS, bounded_map
from ...utils import (
    iso_utc,
    list_value,
    normalized_map,
    nova_task_state_cleared,
    pick,
    required_text,
    safe_name,
)
from ..context import serialized_lifecycle


class ServerRuntimeMixin:
    """Compatibility mixin for this control-plane concern."""

    def _recover_created_resource_by_name(
        self, resource_type: str, name: str, *, timeout: int = 60
    ) -> dict[str, Any] | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                detail = self.osc.json(
                    *resource_type.split(),
                    "show",
                    name,
                    check=False,
                    timeout=min(30, timeout),
                )
            except (CommandError, CommandTimeoutError) as exc:
                if self.osc.is_transient_exception(exc):
                    self.logger.log(
                        f"Transient error while resolving possibly-created {resource_type} {name}: {exc}",
                        "WARNING",
                    )
                    time.sleep(2)
                    continue
                # Authentication/control-plane failures are not absence and
                # must not be hidden by timeout recovery.
                raise SuiteError(
                    f"Could not resolve possibly-created {resource_type} {name}: {exc}"
                ) from exc
            if isinstance(detail, dict):
                return detail
            time.sleep(2)
        return None

    def _discard_failed_boot_volume(
        self, volume_id: str, volume_record: Any | None
    ) -> None:
        delete_args = ["volume", "delete"]
        delete_args.append("--force")
        result = self.osc.run(
            *delete_args,
            volume_id,
            check=False,
            timeout=min(60, self.config.resource_timeout),
        )
        if result.returncode != 0:
            if (
                self.osc.is_not_found_result(result, expected_resource="volume")
                and volume_record is not None
            ):
                self.tracker.mark_deleted(volume_record, "already-absent")
            return
        deadline = time.monotonic() + min(
            60, self.config.cleanup_timeouts.get("volume", 60)
        )
        while time.monotonic() < deadline:
            presence = self.osc.presence("volume", volume_id)
            if presence.absent:
                if volume_record is not None:
                    self.tracker.mark_deleted(
                        volume_record, "deleted-after-server-rejection"
                    )
                return
            if presence.unknown:
                self.logger.log(
                    f"Could not verify deletion of rejected boot volume {volume_id}: "
                    f"{presence.detail}; final cleanup will retry it",
                    "WARNING",
                )
                return
            time.sleep(self.config.convergence_interval)
        self.logger.log(
            f"Rejected boot volume {volume_id} is still present; final cleanup will retry it",
            "WARNING",
        )

    @serialized_lifecycle
    def _create_server(
        self,
        name: str,
        port_ids: list[str],
        *,
        role: str,
        group_id: str | None = None,
        endpoint_side: str | None = None,
        allow_az_fallback: bool = False,
        target_host: str | None = None,
        target_availability_zone: str | None = None,
    ) -> dict[str, Any]:
        coordinator = getattr(self, "cloud_operation_coordinator", None)
        if coordinator is not None and port_ids:
            coordinator.settle(
                "server-create",
                f"allow {len(port_ids)} prepared port(s) for {name} to settle before Nova attachment",
                seconds=10.0,
            )
        selected_az = (
            target_availability_zone
            if target_host
            else getattr(self, "selected_availability_zone", None)
        )
        if target_host and not selected_az:
            raise PlacementUnavailableError(
                f"Exact placement on {target_host} requires a verified availability zone"
            )
        if target_host and allow_az_fallback:
            raise SuiteError(
                "Exact host placement cannot use availability-zone fallback"
            )
        candidates = (
            list(getattr(self, "availability_zone_candidates", []) or [])
            if allow_az_fallback
            else [selected_az]
        )
        if not candidates:
            candidates = [selected_az]
        claim_runtime_resource_name(
            self,
            name,
            resource_type="server",
        )
        errors: list[str] = []
        for attempt, selected_az in enumerate(candidates, start=1):
            try:
                if allow_az_fallback:
                    self._validate_controller_network_zone(
                        selected_az
                        or getattr(self, "discovered_compute_availability_zone", None)
                    )
                result = self._create_server_in_az(
                    name,
                    port_ids,
                    selected_az=selected_az,
                    role=role,
                    group_id=group_id,
                    endpoint_side=endpoint_side,
                    target_host=target_host,
                )
            except PlacementUnavailableError as exc:
                if not allow_az_fallback:
                    raise
                errors.append(f"{selected_az or 'Nova default'}: {exc}")
                if attempt < len(candidates):
                    self.logger.log(
                        f"Controller scheduling was rejected in {selected_az or 'Nova default'}; trying the next compute AZ candidate",
                        "WARNING",
                    )
                    continue
                raise PlacementUnavailableError(
                    "No availability-zone candidate could schedule the controller: "
                    + " | ".join(errors)
                ) from exc
            reported_az = str(result.get("availability_zone") or "").strip()
            actual_az = reported_az or selected_az
            if allow_az_fallback and not actual_az:
                host = str(result.get("host") or "").strip()
                if host:
                    try:
                        host_info = self.compute_host_inventory(refresh=False).get(host)
                    except PlacementUnavailableError:
                        host_info = None
                    if host_info and host_info.availability_zone:
                        actual_az = host_info.availability_zone
            if allow_az_fallback and not actual_az:
                raise SuiteError(
                    "Nova created the controller but did not expose its availability "
                    "zone or a host-to-AZ mapping; same-AZ endpoint placement cannot "
                    "be guaranteed"
                )
            if allow_az_fallback and self._availability_zone_is_internal(actual_az):
                raise SuiteError(
                    f"Nova placed the controller in reserved availability zone {actual_az}"
                )
            if allow_az_fallback:
                self._validate_controller_network_zone(actual_az)
            if selected_az and reported_az and reported_az != selected_az:
                raise SuiteError(
                    f"Nova placed server {name} in availability zone {reported_az}, "
                    f"but {selected_az} was requested"
                )
            reported_host = str(result.get("host") or "").strip()
            if target_host and reported_host != target_host:
                raise PlacementUnavailableError(
                    f"Nova placed server {name} on {reported_host or 'an unknown host'}, "
                    f"but exact host {target_host} was requested"
                )
            if allow_az_fallback and actual_az != self.selected_availability_zone:
                previous = self.selected_availability_zone
                self.selected_availability_zone = actual_az
                self.selected_availability_zone_reason = f"controller scheduling fallback after NoValidHost in {previous or 'Nova default'}"
                self.availability_zone_candidates = [actual_az]
                self.logger.log(
                    f"Locked run availability zone to {actual_az or 'Nova default'} after successful controller boot"
                )
                self.reporter.event(
                    "availability-zone-fallback-selected",
                    "Controller boot selected the next ranked availability zone",
                    previous_availability_zone=previous,
                    availability_zone=actual_az,
                    failed_candidates=errors,
                )
            elif allow_az_fallback:
                self.selected_availability_zone = actual_az
                self.availability_zone_candidates = [actual_az]
                self.logger.log(
                    f"Locked run availability zone to {actual_az or 'Nova default'} after successful controller boot"
                )
            return result
        raise PlacementUnavailableError(
            "No availability-zone candidate was available for server creation"
        )

    def _create_server_in_az(
        self,
        name: str,
        port_ids: list[str],
        *,
        selected_az: str | None,
        role: str,
        group_id: str | None = None,
        endpoint_side: str | None = None,
        target_host: str | None = None,
    ) -> dict[str, Any]:
        coordinator = getattr(self, "cloud_operation_coordinator", None)
        with coordinator.lock if coordinator is not None else nullcontext():
            self.server_sequence = getattr(self, "server_sequence", 0) + 1
            server_sequence = self.server_sequence
        run_id = getattr(self.reporter, "run_id", None)
        if not isinstance(run_id, str) or not run_id:
            run_id = "unknown-run"
        run_tag = getattr(self, "run_tag", None)
        if not isinstance(run_tag, str) or not run_tag:
            run_tag = f"neutron-flux-{run_id}"

        common = [
            "server",
            "create",
            "--flavor",
            self.flavor_id,
            "--key-name",
            self.keypair_name,
            "--property",
            "neutron_flux_managed=true",
            "--property",
            f"neutron_flux_run_id={run_id}",
            "--property",
            f"neutron_flux_run={run_tag}",
            "--property",
            f"neutron_flux_role={role}",
            "--property",
            "neutron_flux_state=active",
            "--property",
            f"neutron_flux_heartbeat={iso_utc()}",
        ]
        for port_id in port_ids:
            common.extend(["--port", port_id])
        if selected_az:
            placement = f"{selected_az}:{target_host}" if target_host else selected_az
            common.extend(["--availability-zone", placement])
        if target_host:
            common.extend(
                [
                    "--property",
                    f"neutron_flux_requested_host={target_host}",
                    "--property",
                    f"neutron_flux_requested_az={selected_az}",
                ]
            )

        volume_id: str | None = None
        attempt_host_storage = self.config.storage == "host"
        boot_mode = "host-root-disk" if attempt_host_storage else "cinder-root-volume"
        create_args = [*common, "--image", self.image_id]
        data: dict[str, Any] | None = None
        inject_failure(self.config, "before-server-create")
        if attempt_host_storage:
            self.logger.log(
                f"Creating server {name} from image {self.image_name} with storage=host; "
                f"availability_zone={selected_az or 'Nova-selected'}; ports={','.join(port_ids)}"
            )
            try:
                result = self.osc.run(
                    *create_args,
                    name,
                    "-f",
                    "json",
                    check=False,
                    timeout=self.config.resource_timeout,
                )
            except CommandTimeoutError as exc:
                data = self._recover_created_resource_by_name(
                    "server", name, timeout=min(90, self.config.resource_timeout)
                )
                if data is None:
                    raise SuiteError(
                        f"Nova server-create timed out and no server named {name} became visible"
                    ) from exc
                self.logger.log(
                    f"Recovered server {name} by exact name after OpenStackClient timed out",
                    "WARNING",
                )
            else:
                if result.returncode == 0:
                    if result.stdout.strip():
                        try:
                            data = json.loads(result.stdout)
                        except json.JSONDecodeError:
                            data = None
                    if data is None:
                        data = self._recover_created_resource_by_name(
                            "server", name, timeout=30
                        )
                    if data is None:
                        raise SuiteError(
                            f"Server create for {name} succeeded but the new server could not be resolved"
                        )
                else:
                    error = (result.stderr or result.stdout).strip()
                    data = self._recover_created_resource_by_name(
                        "server", name, timeout=15
                    )
                    if not data:
                        if self._is_no_valid_host_message(error):
                            raise PlacementUnavailableError(
                                f"Nova could not create host-root-disk server {name}: "
                                f"{error or 'NoValidHost'}"
                            )
                        raise SuiteError(
                            f"Nova could not create host-root-disk server {name}: {error}"
                        )

        if data is None:
            if str(getattr(self, "name_prefix", "") or "").strip():
                volume_name = managed_resource_name(
                    self,
                    identity=(
                        f"root-volume:{name}:{server_sequence}:"
                        f"{group_id or 'control'}:{endpoint_side or role}"
                    ),
                    role="root",
                    resource_type="volume",
                )
            else:
                volume_name = safe_name(f"{name}-root-{server_sequence}", 63)
            image_required_disk = (
                self.launch_selection.image_required_disk_gib
                if self.launch_selection is not None
                else self.config.volume_size
            )
            volume_size = max(self.config.volume_size, image_required_disk)
            self.logger.log(
                f"Creating root volume {volume_name} from image {self.image_name} ({volume_size} GiB)"
            )
            volume_args = [
                "volume",
                "create",
                "--image",
                self.image_id,
                "--size",
                str(volume_size),
                "--property",
                f"neutron_flux_run={self.run_tag}",
            ]
            if self.config.volume_type:
                volume_args.extend(["--type", self.config.volume_type])
            volume_selection = self._volume_az_selection(selected_az)
            volume_requested_az = volume_selection["requested_availability_zone"]
            if volume_requested_az:
                volume_args.extend(["--availability-zone", volume_requested_az])
            self.logger.log(
                f"Root volume AZ request: {volume_requested_az or 'Cinder default'}; "
                f"compute AZ={selected_az or 'Nova default'}; "
                f"reason={volume_selection['selection_reason']}"
            )
            volume_args.append(volume_name)
            claim_runtime_resource_name(
                self,
                volume_name,
                resource_type="volume",
            )
            try:
                volume = (
                    self.osc.json(*volume_args, timeout=self.config.resource_timeout)
                    or {}
                )
            except CommandTimeoutError as exc:
                volume = (
                    self._recover_created_resource_by_name(
                        "volume",
                        volume_name,
                        timeout=min(90, self.config.resource_timeout),
                    )
                    or {}
                )
                if not volume:
                    raise SuiteError(
                        f"Cinder volume-create timed out and no volume named {volume_name} became visible"
                    ) from exc
                self.logger.log(
                    f"Recovered volume {volume_name} by exact name after OpenStackClient timed out",
                    "WARNING",
                )
            except CommandError as exc:
                recovered_volume = self._recover_created_resource_by_name(
                    "volume", volume_name, timeout=15
                )
                if recovered_volume is not None:
                    volume = recovered_volume
                    self.logger.log(
                        f"Recovered volume {volume_name} by exact name after Cinder returned an error",
                        "WARNING",
                    )
                else:
                    error_detail = exc.stderr.strip() or exc.stdout.strip() or str(exc)
                    if self._is_cinder_placement_unavailable_message(error_detail):
                        raise PlacementUnavailableError(
                            f"Cinder could not create a boot volume in availability zone "
                            f"{volume_requested_az or 'cloud default'}: {error_detail}"
                        ) from exc
                    raise
            volume_id = required_text(
                volume, "id", context=f"Volume create for {volume_name}"
            )
            if not volume_id:
                raise SuiteError(f"Volume creation returned no ID: {volume_name}")
            volume_record = self.tracker.add(
                "volume",
                volume_id,
                volume_name,
                role=role,
                group_id=group_id,
                endpoint_side=endpoint_side,
                availability_zone=volume_requested_az,
                requested_availability_zone=volume_requested_az,
                compute_availability_zone=selected_az,
                placement_policy="cinder-scheduler"
                if volume_requested_az is None
                else "same-az",
                volume_az_selection=volume_selection,
                volume_type=self.config.volume_type,
                size_gb=volume_size,
                image_id=self.image_id,
            )
            volume_detail = self._wait_for_status_details(
                "volume",
                volume_id,
                {"available"},
                {"error", "error_restoring"},
                display_name=volume_name,
            )
            volume_az = str(pick(volume_detail, "availability_zone", default="") or "")
            if (
                volume_az
                and volume_record.metadata.get("availability_zone") != volume_az
            ):
                volume_record.metadata["availability_zone"] = volume_az
                self.reporter.update_resource(volume_record)
            self._validate_created_volume_availability_zone(
                selected_az,
                volume_az,
                volume_name,
                volume_id,
                volume_record,
                selection=volume_selection,
            )
            block_common = list(common)
            block_args = [
                *block_common,
                "--block-device",
                f"uuid={volume_id},source_type=volume,destination_type=volume,boot_index=0,delete_on_termination=true",
            ]
            try:
                data = (
                    self.osc.json(
                        *block_args, name, timeout=self.config.resource_timeout
                    )
                    or {}
                )
            except CommandTimeoutError as exc:
                data = (
                    self._recover_created_resource_by_name(
                        "server", name, timeout=min(90, self.config.resource_timeout)
                    )
                    or {}
                )
                if not data:
                    raise SuiteError(
                        f"Nova volume-backed server-create timed out and no server named {name} became visible"
                    ) from exc
                self.logger.log(
                    f"Recovered volume-backed server {name} by exact name after OpenStackClient timed out",
                    "WARNING",
                )
            except CommandError as exc:
                data = (
                    self._recover_created_resource_by_name("server", name, timeout=15)
                    or {}
                )
                if not data:
                    self._discard_failed_boot_volume(volume_id, volume_record)
                    error_detail = exc.stderr.strip() or exc.stdout.strip() or str(exc)
                    if self._is_no_valid_host_message(error_detail):
                        raise PlacementUnavailableError(error_detail) from exc
                    raise SuiteError(
                        f"Nova could not create volume-backed server {name}: {error_detail}"
                    ) from exc

        server_id = required_text(data, "id", context=f"Server create for {name}")
        if not server_id:
            raise SuiteError(f"Server creation returned no ID: {name}")
        self.tracker.add(
            "server",
            server_id,
            name,
            role=role,
            volume_id=volume_id,
            group_id=group_id,
            endpoint_side=endpoint_side,
            boot_mode=boot_mode,
            requested_host=target_host,
            requested_availability_zone=selected_az,
        )
        active_detail = self._wait_for_status_details(
            "server",
            server_id,
            {"active"},
            {"error"},
            display_name=name,
        )
        if getattr(self, "lifecycle_settlement_enabled", False):
            placement = self.verify_server_placement(
                server_id,
                port_ids,
                expected_statuses={"active"},
                expected_host=target_host,
                expected_availability_zone=selected_az,
                display_name=name,
                initial_server=active_detail,
            )
            detail = placement["server"]
        else:
            detail = active_detail
        inject_failure(self.config, "after-server-active")
        observed_host = str(
            pick(detail, "os_ext_srv_attr_host", "host", default="") or ""
        ).strip()
        observed_az = str(
            pick(
                detail,
                "os_ext_az_availability_zone",
                "availability_zone",
                default="",
            )
            or ""
        ).strip()
        if target_host and observed_host != target_host:
            raise PlacementUnavailableError(
                f"Exact placement verification failed for {name}: requested "
                f"{target_host}, observed {observed_host or 'unknown'}"
            )
        if selected_az and observed_az and observed_az != selected_az:
            raise PlacementUnavailableError(
                f"Availability-zone verification failed for {name}: requested "
                f"{selected_az}, observed {observed_az}"
            )
        self.reporter.event(
            "server-ready",
            f"Server {name} is ACTIVE",
            server_id=server_id,
            boot_mode=boot_mode,
            availability_zone=pick(
                detail, "os_ext_az_availability_zone", "availability_zone"
            ),
            host=pick(detail, "os_ext_srv_attr_host", "host"),
            requested_host=target_host,
            placement_method=(
                "nova-availability-zone-host" if target_host else "nova-scheduler"
            ),
        )
        return {
            "server_id": server_id,
            "server_name": name,
            "volume_id": volume_id,
            "host": pick(detail, "os_ext_srv_attr_host", "host"),
            "availability_zone": pick(
                detail, "os_ext_az_availability_zone", "availability_zone"
            ),
            "boot_mode": boot_mode,
            "requested_host": target_host,
            "placement_method": (
                "nova-availability-zone-host" if target_host else "nova-scheduler"
            ),
        }

    def update_cloud_heartbeat(self, state: str = "active") -> None:
        """Refresh the controller's cloud-visible run heartbeat."""
        controller = getattr(self, "controller", None)
        if controller is None or not controller.server_id:
            return
        result = self.osc.run(
            "server",
            "set",
            "--property",
            "neutron_flux_managed=true",
            "--property",
            f"neutron_flux_run_id={self.reporter.run_id}",
            "--property",
            f"neutron_flux_run={self.run_tag}",
            "--property",
            f"neutron_flux_state={state}",
            "--property",
            f"neutron_flux_heartbeat={iso_utc()}",
            controller.server_id,
            check=False,
            timeout=min(60, self.config.resource_timeout),
        )
        if result.returncode != 0 and not self.osc.is_not_found_result(
            result, expected_resource="server"
        ):
            detail = (result.stderr or result.stdout).strip()
            self.logger.log(
                f"Could not refresh cloud run heartbeat on controller "
                f"{controller.server_id}: {detail or 'unknown OpenStack error'}",
                "WARNING",
            )

    def verify_server_placement(
        self,
        server_id: str,
        port_ids: list[str] | tuple[str, ...],
        *,
        expected_statuses: set[str] | None = None,
        expected_host: str | None = None,
        expected_availability_zone: str | None = None,
        display_name: str | None = None,
        timeout: int | None = None,
        stable_observations: int = 2,
        require_power_state: bool = False,
        reuse_fresh: bool = False,
        initial_server: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Verify placement; optionally reuse recent evidence from this cloud operation epoch."""
        coordinator = getattr(self, "cloud_operation_coordinator", None)
        cache_key = (
            server_id,
            tuple(port_ids),
            tuple(sorted(expected_statuses or {"active"})),
            expected_host,
            expected_availability_zone,
            stable_observations,
            require_power_state,
        )
        epoch = -1
        if coordinator is not None:
            with coordinator.lock:
                epoch = coordinator._sequence
                cached = coordinator.placement_evidence.get(cache_key)
                if (
                    reuse_fresh
                    and initial_server is None
                    and cached
                    and cached[0] == epoch
                    and time.monotonic() - cached[1] <= 15
                ):
                    self.reporter.event(
                        "placement-evidence-reused",
                        "Reused fresh verified Nova/Neutron placement",
                        server_id=server_id,
                        age_seconds=round(time.monotonic() - cached[1], 3),
                    )
                    return copy.deepcopy(cached[2])
                # A refresh supersedes old evidence, even if it discovers an
                # error. A later optional reuse must not resurrect that snapshot.
                coordinator.placement_evidence = {
                    key: value
                    for key, value in coordinator.placement_evidence.items()
                    if key[0] != server_id
                }

        initial = (
            {"initial_server": initial_server} if initial_server is not None else {}
        )
        detail = self._wait_for_server_settlement(
            server_id,
            port_ids,
            expected_statuses=expected_statuses or {"active"},
            expected_host=expected_host,
            display_name=display_name,
            timeout=timeout,
            stable_observations=stable_observations,
            require_power_state=require_power_state,
            **initial,
        )
        observed_host = str(
            pick(detail, "os_ext_srv_attr_host", "host", default="") or ""
        ).strip()
        observed_zone = str(
            pick(
                detail,
                "os_ext_az_availability_zone",
                "availability_zone",
                default="",
            )
            or ""
        ).strip()
        if expected_host and observed_host != expected_host:
            raise PlacementUnavailableError(
                f"Placement verification failed for {display_name or server_id}: "
                f"requested host {expected_host}, observed "
                f"{observed_host or 'hidden'}"
            )
        if expected_availability_zone and observed_zone != expected_availability_zone:
            raise PlacementUnavailableError(
                f"Placement verification failed for {display_name or server_id}: "
                f"requested availability zone {expected_availability_zone}, "
                f"observed {observed_zone or 'hidden'}"
            )
        evidence: dict[str, Any] = {
            "server_id": server_id,
            "server": detail,
            "port_ids": [port_id for port_id in port_ids if port_id],
            "requested_availability_zone": expected_availability_zone,
            "observed_availability_zone": observed_zone or None,
            "expected_statuses": sorted(expected_statuses or {"active"}),
            "stable_observations": max(1, int(stable_observations)),
            "settled": True,
        }
        evidence.update(
            {
                "requested_host": expected_host,
                "observed_host": observed_host or None,
            }
        )
        self.reporter.event(
            "placement-verified",
            "Verified Nova placement and Neutron binding settlement for "
            + f"{display_name or server_id}",
            **{key: value for key, value in evidence.items() if key != "server"},
        )
        if coordinator is not None:
            with coordinator.lock:
                if epoch == coordinator._sequence:
                    # Bounded to live/fresh evidence; it is never restored on resume.
                    now = time.monotonic()
                    coordinator.placement_evidence = {
                        key: value
                        for key, value in coordinator.placement_evidence.items()
                        if value[0] == epoch and now - value[1] <= 15
                    }
                    coordinator.placement_evidence[cache_key] = (
                        epoch,
                        now,
                        copy.deepcopy(evidence),
                    )
        return evidence

    def _wait_for_server_settlement(
        self,
        server_id: str,
        port_ids: list[str] | tuple[str, ...],
        *,
        expected_statuses: set[str],
        expected_host: str | None = None,
        display_name: str | None = None,
        timeout: int | None = None,
        stable_observations: int = 2,
        require_power_state: bool = False,
        initial_server: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Wait for a stable Nova state and matching Neutron bindings.

        A status transition is not considered complete until Nova exposes an
        empty task state and the requested number of consecutive inventory
        reads agree. Attached ports must visibly belong to the server, and
        their binding hosts must agree with Nova. Migration callers may also
        require Nova's power-state field to prove that the guest is running.
        This deliberately slows lifecycle churn so a later operation cannot
        race the previous VIF plug, unplug, or migration.
        """

        limit = timeout or min(
            self.config.resource_timeout,
            max(60, self.config.convergence_timeout),
        )
        deadline = time.monotonic() + limit
        required_stable_reads = max(1, int(stable_observations))
        stable_reads = 0
        previous_signature: tuple[Any, ...] | None = None
        last_summary = "no inventory returned"
        label = display_name or server_id
        expected = {item.lower() for item in expected_statuses}
        normalized_ports = [item for item in port_ids if item]

        while time.monotonic() < deadline:
            if initial_server is not None:
                # The just-completed ACTIVE poll is the first Nova read. Its
                # task, power, host and ports still undergo full settlement
                # validation; another matching complete observation is needed.
                detail = initial_server
                initial_server = None
            else:
                detail = (
                    self.osc.json(
                        "server",
                        "show",
                        server_id,
                        check=False,
                        timeout=min(30, self.config.resource_timeout),
                    )
                    or {}
                )
            if not isinstance(detail, dict):
                stable_reads = 0
                previous_signature = None
                time.sleep(self.config.convergence_interval)
                continue

            status = str(pick(detail, "status", default="") or "").lower()
            task_state = str(
                pick(detail, "os_ext_sts_task_state", "task_state", default="") or ""
            ).lower()
            host = str(pick(detail, "os_ext_srv_attr_host", "host", default="") or "")
            normalized_detail = normalized_map(detail)
            task_state_visible = any(
                key in normalized_detail
                for key in {"os_ext_sts_task_state", "task_state"}
            )
            server_identity_matches = (
                "id" not in normalized_detail
                or str(normalized_detail["id"]) == server_id
            )
            power_state_visible = any(
                key in normalized_detail
                for key in {"os_ext_sts_power_state", "power_state"}
            )
            power_state = (
                str(
                    pick(
                        detail,
                        "os_ext_sts_power_state",
                        "power_state",
                        default="",
                    )
                    or ""
                )
                .strip()
                .lower()
            )
            power_running = not require_power_state or (
                power_state_visible
                and power_state in {"1", "running", "active", "powered on", "power_on"}
            )
            task_clear = nova_task_state_cleared(detail) is True
            host_matches = not expected_host or host == expected_host
            server_ready = (
                status in expected
                and task_clear
                and power_running
                and host_matches
                and server_identity_matches
            )
            ports_ready = server_ready
            port_signature: list[tuple[str, str, str, str]] = []

            def read_port(port_id: str) -> Any:
                return self.osc.json(
                    "port",
                    "show",
                    port_id,
                    check=False,
                    timeout=min(30, self.config.resource_timeout),
                )

            # Pending Nova state cannot pass settlement. Read Neutron only
            # once Nova is eligible, then require the same consecutive complete
            # Nova/Neutron observations as before.
            ports_to_read = normalized_ports if server_ready else []
            ports = bounded_map(read_port, ports_to_read, workers=READ_WORKERS)
            for port_id, port in zip(ports_to_read, ports, strict=True):
                if not isinstance(port, dict) or not port:
                    ports_ready = False
                    port_signature.append((port_id, "", "", "missing"))
                    continue
                normalized_port = normalized_map(port)
                device_visible = "device_id" in normalized_port
                binding_visible = any(
                    key in normalized_port
                    for key in {"binding_host_id", "binding_host"}
                )
                device_id = str(pick(port, "device_id", default="") or "")
                binding_host = str(
                    pick(
                        port,
                        "binding_host_id",
                        "binding:host_id",
                        "binding_host",
                        default="",
                    )
                    or ""
                )
                port_status = str(pick(port, "status", default="") or "").lower()
                port_identity_matches = (
                    "id" not in normalized_port or str(normalized_port["id"]) == port_id
                )
                if (
                    not port_identity_matches
                    or not device_visible
                    or device_id != server_id
                    or not binding_visible
                    or not host
                    or not binding_host
                    or binding_host != host
                ):
                    ports_ready = False
                port_signature.append((port_id, device_id, binding_host, port_status))

            signature: tuple[Any, ...] = (
                status,
                task_state,
                power_state if require_power_state else "",
                host,
                tuple(port_signature),
            )
            ready = (
                status in expected
                and task_clear
                and power_running
                and host_matches
                and server_identity_matches
                and ports_ready
            )
            last_summary = (
                f"status={status or 'unknown'}, task_state={task_state or ('none' if task_clear else 'unverified' if task_state_visible else 'hidden')}, "
                f"power_state={power_state or ('hidden' if require_power_state else 'not-required')}, "
                f"host={host or 'unknown'}, ports_ready={ports_ready}"
            )
            if ready and signature == previous_signature:
                stable_reads += 1
            elif ready:
                stable_reads = 1
            else:
                stable_reads = 0
            previous_signature = signature
            if stable_reads >= required_stable_reads:
                self.logger.log(
                    f"Server lifecycle settled for {label} ({server_id}): "
                    f"{last_summary}, stable_reads={stable_reads}"
                )
                return detail
            time.sleep(self.config.convergence_interval)

        raise SuiteError(
            f"Timed out waiting for server lifecycle settlement for {label} "
            f"({server_id}) after {limit}s: {last_summary}"
        )

    def _wait_for_status(
        self,
        resource_type: str,
        resource_id: str,
        success: set[str],
        failure: set[str],
        *,
        display_name: str | None = None,
    ) -> str:
        detail = self._wait_for_status_details(
            resource_type, resource_id, success, failure, display_name=display_name
        )
        return str(pick(detail, "status", default="") or "").strip().lower()

    def _wait_for_status_details(
        self,
        resource_type: str,
        resource_id: str,
        success: set[str],
        failure: set[str],
        *,
        display_name: str | None = None,
    ) -> dict[str, Any]:
        """Return the terminal observation without a second SHOW for its fields."""
        started = time.monotonic()
        deadline = started + self.config.resource_timeout
        next_progress = started
        last_status = ""
        last_api_error = ""
        label = display_name or resource_id
        expected = ",".join(sorted(value.upper() for value in success))
        while time.monotonic() < deadline:
            try:
                detail_payload = self.osc.json(
                    resource_type,
                    "show",
                    resource_id,
                    timeout=min(60, self.config.resource_timeout),
                )
            except CommandError as exc:
                result = subprocess.CompletedProcess(
                    exc.command, exc.returncode, exc.stdout, exc.stderr
                )
                detail = (result.stderr or result.stdout).strip() or "no command output"
                if self.osc.is_transient_result(result):
                    last_api_error = detail
                    now = time.monotonic()
                    if now >= next_progress:
                        self.logger.log(
                            f"Transient OpenStack API error while waiting for {resource_type} {label} ({resource_id}): {detail}; retrying",
                            "WARNING",
                        )
                        next_progress = now + self.config.progress_interval
                    time.sleep(self.config.convergence_interval)
                    continue
                if self.osc.is_not_found_result(
                    result, expected_resource=resource_type
                ):
                    raise SuiteError(
                        f"{resource_type} {label} ({resource_id}) disappeared while waiting for status {expected}: {detail}"
                    ) from exc
                raise

            if not isinstance(detail_payload, dict):
                raise SuiteError(
                    f"Invalid {resource_type} status observation for {label} ({resource_id})"
                )
            status = (
                str(pick(detail_payload, "status", default="") or "").strip().lower()
            )
            now = time.monotonic()
            elapsed = int(now - started)
            if status and status != last_status:
                self.logger.log(
                    f"{resource_type.capitalize()} {label} ({resource_id}) status={status.upper()} "
                    f"after {elapsed}s"
                )
                last_status = status
                last_api_error = ""
                next_progress = now + self.config.progress_interval
            elif now >= next_progress:
                current = status.upper() if status else "UNKNOWN"
                self.logger.log(
                    f"Still waiting for {resource_type} {label} ({resource_id}): "
                    f"status={current}, expected={expected}, elapsed={elapsed}s/"
                    f"{self.config.resource_timeout}s"
                )
                next_progress = now + self.config.progress_interval
            if status in success:
                return detail_payload
            if status in failure:
                fault = pick(detail_payload, "fault", default=None)
                raise SuiteError(
                    f"{resource_type} {label} ({resource_id}) entered status {status.upper()}"
                    + (f": fault={fault}" if fault else "")
                )
            time.sleep(2)
        current = last_status.upper() if last_status else "UNKNOWN"
        suffix = f"; last API error={last_api_error}" if last_api_error else ""
        raise SuiteError(
            f"Timed out after {self.config.resource_timeout}s waiting for {resource_type} "
            f"{label} ({resource_id}): current={current}, expected={expected}{suffix}"
        )

    @staticmethod
    def _fixed_ips(port: dict[str, Any]) -> dict[str, str]:
        value = pick(port, "fixed_ips", default=[])
        if isinstance(value, str):
            parsed: dict[str, str] = {}
            for chunk in re.findall(r"\{([^{}]+)\}", value):
                subnet_match = re.search(
                    r"['\"]?subnet_id['\"]?\s*[:=]\s*['\"]?([^,'\"}\s]+)",
                    chunk,
                )
                address_match = re.search(
                    r"['\"]?ip_address['\"]?\s*[:=]\s*['\"]?([^,'\"}\s]+)",
                    chunk,
                )
                if subnet_match and address_match:
                    parsed[subnet_match.group(1)] = address_match.group(1)
            if parsed:
                return parsed
        entries = list_value(value)
        result: dict[str, str] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            normalized = normalized_map(entry)
            subnet_id = normalized.get("subnet_id")
            address = normalized.get("ip_address")
            if subnet_id and address:
                result[str(subnet_id)] = str(address)
        return result
