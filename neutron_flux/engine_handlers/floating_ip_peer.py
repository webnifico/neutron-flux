from __future__ import annotations

from typing import Any

from ..errors import SuiteError
from ..icmp_attestation import attested_icmp
from ..models import Endpoint, ProbeResult, RuntimeGroup, TestSpec
from ..translation_safety import validate_runtime_floating_ip_target
from ..utils import pick


class FloatingIPPeerHandlerMixin:
    """Exercise owned floating-IP mappings through the guest data interface."""

    def _peer_fip(
        self: Any, group: RuntimeGroup, endpoint: Endpoint, side: str, fixed_ip: str
    ) -> dict[str, Any]:
        validate_runtime_floating_ip_target(group, side)
        if getattr(self, "post_migration_read_only", False):
            self.builder.ensure_group_fips(group, side=side, allow_create=False)
        else:
            self.builder.ensure_group_fips(group, side=side)
        fip = group.fips.get(endpoint.label)
        if not fip or not fip.get("address") or not fip.get("id"):
            raise SuiteError(f"No floating IP was allocated for {endpoint.label}")
        association = self.builder.wait_floating_ip_association(
            fip["id"],
            expected_port_id=endpoint.test_port_id,
            expected_fixed_ip=fixed_ip,
        )
        if (
            not association.get("matched")
            or association.get("port_id") != endpoint.test_port_id
            or association.get("fixed_ip_address") != fixed_ip
            or association.get("floating_ip_address") != fip["address"]
        ):
            raise SuiteError(
                f"Floating-IP mapping could not be verified for {endpoint.label}: {association}"
            )
        if fip["address"] == fixed_ip:
            raise SuiteError(
                "Floating-IP peer probe must use an address translated to the private data interface"
            )
        endpoint.metadata["floating_ip_association"] = dict(association)
        return {
            **fip,
            "association": association,
            "private_ip": fixed_ip,
            "server_id": endpoint.server_id,
            "router_id": group.router_id,
        }

    def _peer_listener(self: Any, endpoint: Endpoint, protocol: str) -> dict[str, Any]:
        _ready, evidence = self.builder._existing_probe_service_ready(endpoint)
        listener = (evidence.get("listeners") or {}).get("4", {})
        if not listener.get(protocol) or not listener.get("instance_id"):
            raise SuiteError(
                f"Cannot verify {protocol.upper()} listener on {endpoint.label}: {evidence}"
            )
        return {"probe_id": endpoint.server_id, "instance_id": listener["instance_id"]}

    def _verified_fip_probe(
        self: Any,
        protocol: str,
        source: Endpoint,
        source_ip: str,
        floating_ip: str,
        destination: Endpoint,
        fixed_ip: str,
        *,
        mode: str,
        expected_source_ips: set[str] | None = None,
    ) -> ProbeResult:
        before = after = None
        if protocol == "icmp":
            launcher = getattr(self.builder, "_launch_probe_process", None)
            if not callable(launcher):
                raise SuiteError(
                    "Destination ICMP data-port observation is unavailable"
                )
            probe = attested_icmp(
                launcher,
                destination,
                fixed_ip,
                lambda token: self.probes.icmp.endpoint(
                    source,
                    source_ip,
                    floating_ip,
                    4,
                    payload_token=token,
                ),
            )
        else:
            before = self._peer_listener(destination, protocol)
            probe = getattr(self.probes, protocol).endpoint_peer_identity(
                source, source_ip, floating_ip, 4
            )
            try:
                after = self._peer_listener(destination, protocol)
            except SuiteError as exc:
                after = {"inspection_error": str(exc)}
            if before != after:
                probe.outcome, probe.success = "error", False
                probe.stderr = (
                    "Destination probe service changed during the floating-IP test"
                )
            elif probe.success:
                error = self._peer_identity_error(
                    probe, {**before, "fixed_ip": fixed_ip}, mode, ""
                )
                if error:
                    probe.outcome, probe.success = "wrong-destination", False
                    probe.stderr = error
        if probe.success and expected_source_ips is not None:
            if probe.diagnostics.get("observed_peer_ip") not in expected_source_ips:
                probe.outcome, probe.success = "translation-mismatch", False
                probe.stderr = "Destination did not observe the required source translation/address"
        probe.diagnostics.update(
            destination_listener_before=before,
            destination_listener_after=after,
            expected_destination_server_id=destination.server_id,
            expected_destination_fixed_ip=fixed_ip,
            expected_translated_sources=sorted(expected_source_ips)
            if expected_source_ips is not None
            else None,
        )
        return probe

    def _run_fip_peer(self: Any, spec: TestSpec) -> None:
        source_group = self._group(spec.source_group_id)
        destination_group = self._group(spec.destination_group_id)
        source, source_ip = self._endpoint_address(
            spec.source_group_id, spec.source_side, "runtime"
        )
        destination, destination_ip = self._endpoint_address(
            spec.destination_group_id, spec.destination_side, "runtime"
        )
        mode = spec.metadata.get("nat_path")
        same_router = source_group.router_id == destination_group.router_id
        expected_mode = (
            "snat-to-floating-ip"
            if spec.metadata.get("source_without_floating_ip") and not same_router
            else "self-hairpin"
            if source.server_id == destination.server_id
            else "same-router"
            if same_router
            else "different-routers"
        )
        if (
            not source_group.router_id
            or not destination_group.router_id
            or mode != expected_mode
            or spec.family != 4
            or spec.protocol not in {"icmp", "tcp", "udp"}
            or source_group.plan.floating_subnet_id
            != destination_group.plan.floating_subnet_id
        ):
            raise SuiteError(
                "Floating-IP peer topology does not match its declared path"
            )
        source_without_fip = mode == "snat-to-floating-ip"
        snat_evidence = None
        source_fip = None
        if source_without_fip:
            mappings = self.builder.osc.json(
                "floating", "ip", "list", "--port", source.test_port_id
            )
            router = self.builder.capture_router_state(source_group.router_id)
            gateway = self.builder._gateway_info(
                router.get("external_gateway_info") or {}
            )
            gateway_ips = [
                str(pick(row, "ip_address", default=""))
                for row in gateway.get("external_fixed_ips", [])
            ]
            if (
                not isinstance(mappings, list)
                or mappings
                or source_group.fips
                or gateway.get("enable_snat") is not True
                or not gateway_ips
            ):
                raise SuiteError(
                    "SNAT-to-floating-IP source requires verified enabled router SNAT, a gateway address and no floating-IP association"
                )
            snat_evidence = {
                "no_floating_ip_verified": True,
                "source_port_id": source.test_port_id,
                "router_id": source_group.router_id,
                "gateway_ips": gateway_ips,
                "gateway": gateway,
            }
        else:
            source_fip = self._peer_fip(
                source_group, source, spec.source_side, source_ip
            )
        target_fip = (
            source_fip
            if source.server_id == destination.server_id
            else self._peer_fip(
                destination_group, destination, spec.destination_side, destination_ip
            )
        )
        if (
            source.server_id != destination.server_id
            and source_fip is not None
            and source_fip["address"] == target_fip["address"]
        ):
            raise SuiteError(
                "Distinct peer endpoints unexpectedly have the same floating IP"
            )
        protocol = str(spec.protocol)
        expected_sources = (
            set(snat_evidence["gateway_ips"])
            if snat_evidence
            else {source_fip["address"]}
            if mode == "different-routers"
            else None
        )
        probe = self._verified_fip_probe(
            protocol,
            source,
            source_ip,
            target_fip["address"],
            destination,
            destination_ip,
            mode=mode,
            expected_source_ips=expected_sources,
        )
        probe.diagnostics.update(
            {
                "nat_path": mode,
                "source_floating_ip": source_fip,
                "source_router_snat": snat_evidence,
                "destination_floating_ip": target_fip,
                "claim_boundary": "owned IPv4 floating-IP mappings on the same external subnet",
            }
        )
        self._record(spec, probe, source, destination, message=probe.stderr or None)

    @staticmethod
    def _peer_identity_error(
        probe: ProbeResult, expected: dict[str, Any], mode: str, source_fip: str
    ) -> str | None:
        observed = probe.diagnostics
        if (
            observed.get("observer_probe_id") != expected["probe_id"]
            or observed.get("observer_instance_id") != expected["instance_id"]
        ):
            return "Floating-IP reply came from the wrong destination or probe service"
        if (
            mode == "different-routers"
            and source_fip
            and observed.get("observed_peer_ip") != source_fip
        ):
            return (
                "Destination did not observe the source VM's floating IP across routers"
            )
        if (
            expected.get("fixed_ip")
            and observed.get("observer_local_ip") != expected["fixed_ip"]
        ):
            return "Floating-IP reply did not arrive on the intended destination fixed data address"
        return None
