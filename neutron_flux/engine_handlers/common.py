from __future__ import annotations

from typing import Any

# mypy: disable-error-code="attr-defined"
from ..engine_state import RouteObservationCache
from ..errors import RunCancelledError, SuiteError
from ..models import Endpoint, ProbeResult, RuntimeGroup, TestSpec
from ..mtu_contract import make_mtu_observation
from ..path_evidence import data_route_evidence
from ..test_names import packet_path_display_name
from ..utils import iso_utc, pick


class EngineCommonMixin:
    """Compatibility mixin for this test-operation family."""

    def _address_evidence(
        self,
        spec: TestSpec,
        probe: ProbeResult,
        source: Endpoint | None,
        destination: Endpoint | None,
    ) -> dict[str, Any]:
        path: dict[str, Any] = {
            "observed_source_ip": probe.diagnostics.get("observed_peer_ip")
        }
        for role, endpoint, address in (
            ("source", source, probe.source_ip),
            ("destination", destination, probe.destination_ip),
        ):
            if endpoint is None:
                continue
            group = getattr(self, "groups", {}).get(getattr(spec, f"{role}_group_id"))
            fip = (group.fips.get(endpoint.label) or {}) if group else {}
            mapping = probe.diagnostics.get(f"{role}_floating_ip") or {}
            association = mapping.get("association") or {}
            if role == "destination" and not association:
                association = (
                    probe.diagnostics.get("floating_ip_api_state")
                    or probe.diagnostics.get("floating_ip_association")
                    or {}
                )
            prior = not bool(association)
            if prior:
                association = dict(
                    endpoint.metadata.get("floating_ip_association") or {}
                )
            try:
                fixed_ip = (
                    self._address(group, endpoint, getattr(spec, f"{role}_subnet_id"))
                    if group
                    else address
                )
            except SuiteError:
                fixed_ip = None
            status = "none allocated"
            if fip:
                status = (
                    "verified attached"
                    if association.get("matched")
                    and association.get("port_id") == endpoint.test_port_id
                    and association.get("fixed_ip_address") == fixed_ip
                    else "verified detached"
                    if association.get("matched")
                    and "port_id" in association
                    and association.get("port_id") is None
                    else "association unverified"
                )
            if role == "source" and (
                probe.diagnostics.get("source_router_snat") or {}
            ).get("no_floating_ip_verified"):
                status = "none (verified)"
            if fip and prior and status.startswith("verified"):
                status = "last " + status
            path[role] = {
                "server_id": endpoint.server_id,
                "port_id": endpoint.test_port_id,
                "fixed_ip": fixed_ip,
                "fixed_ips": dict(endpoint.fixed_ips),
                "floating_ip": fip.get("address"),
                "floating_ip_id": fip.get("id"),
                "floating_ip_status": status,
                "association": association,
                "probe_address": address,
            }
        return path

    def _record(
        self,
        spec: TestSpec,
        probe: ProbeResult,
        source: Endpoint | None,
        destination: Endpoint | None,
        *,
        message: str | None = None,
    ) -> None:
        route_inspector = getattr(
            getattr(self, "builder", None), "inspect_endpoint_route", None
        )
        if (
            source
            and probe.source_ip
            and probe.destination_ip
            and spec.family in {4, 6}
            and callable(route_inspector)
            and not probe.diagnostics.get("execution_error")
        ):
            route_key = (
                source.server_id,
                probe.source_ip,
                probe.destination_ip,
                int(spec.family),
            )

            def read_route() -> dict[str, Any]:
                try:
                    return route_inspector(
                        source,
                        probe.source_ip,
                        probe.destination_ip,
                        int(spec.family),
                    )
                except RunCancelledError:
                    raise
                except (
                    AttributeError,
                    OSError,
                    SuiteError,
                    TypeError,
                    ValueError,
                ) as exc:
                    return {
                        "returncode": None,
                        "stdout": "",
                        "stderr": self._concise(str(exc)),
                        "source": probe.source_ip,
                        "destination": probe.destination_ip,
                    }

            route_cache = getattr(self, "_route_observation_cache", None)
            route_observation = (
                route_cache.observe(route_key, read_route)
                if isinstance(route_cache, RouteObservationCache)
                else read_route()
            )
            probe.diagnostics.setdefault("endpoint_route", route_observation)

        if (
            source
            and spec.source_group_id
            and probe.source_ip
            and probe.destination_ip
            and probe.attempts > 0
            and probe.outcome not in {"error", "inconclusive"}
        ):
            route_proof = data_route_evidence(
                source,
                probe.source_ip,
                probe.destination_ip,
                probe.diagnostics.get("endpoint_route"),
            )
            probe.diagnostics["data_path_verification"] = route_proof
            if route_proof["verified"] is not True:
                probe.diagnostics["raw_outcome_before_data_path_verification"] = (
                    probe.outcome
                )
                probe.outcome = (
                    "error" if route_proof["verified"] is False else "inconclusive"
                )
                probe.success = False
                message = "Data-path verification failed: " + route_proof["reason"]
                probe.stderr = "\n".join(
                    part for part in (probe.stderr, message) if part
                )

        decision = self.policy.evaluate(spec, probe)
        details = {
            "operation": spec.operation,
            "phase": spec.phase,
            "source_side": spec.source_side,
            "destination_side": spec.destination_side,
            "address_path": self._address_evidence(spec, probe, source, destination),
            "protocol": str(spec.protocol or probe.protocol or "").lower() or None,
            "expectation_reason": spec.expectation_reason,
            "probe": {
                "command": probe.command,
                "attempts": probe.attempts,
                "stdout": probe.stdout,
                "stderr": probe.stderr,
                "diagnostics": probe.diagnostics,
            },
            "dependencies": spec.dependencies,
            **spec.metadata,
        }
        if probe.attempts == 0 and probe.outcome == "inconclusive":
            details["coverage_outcome"] = "NEVER_RAN"
            details["cloud_operation_performed"] = probe.diagnostics.get(
                "cloud_operation_performed", False
            )
        routing_policy = spec.metadata.get("routing_policy")
        if isinstance(routing_policy, dict):
            details["expectation_source"] = routing_policy.get("reason")
            details["authority_classification"] = (
                "operator"
                if routing_policy.get("basis")
                in {"operator-routing-contract", "selected-provider-routing-contract"}
                else "openstack"
                if routing_policy.get("authoritative")
                else "inferred"
            )
        if source:
            details["source_compute_host"] = source.host
            details["source_server_id"] = source.server_id
            details["source_management_ip"] = source.management_ip
        if source:
            details["source_availability_zone"] = source.availability_zone
        if destination:
            details["destination_compute_host"] = destination.host
            details["destination_server_id"] = destination.server_id
            details["destination_management_ip"] = destination.management_ip
        if destination:
            details["destination_availability_zone"] = destination.availability_zone
        if source and destination and source.server_id == destination.server_id:
            details["topology_placement_context"] = {
                key: details[key]
                for key in ("compute_placement", "pair_placement")
                if key in details
            }
            details["compute_placement"] = "same endpoint (self-hairpin)"
            details["packet_path_placement"] = "self"
            if "pair_placement" in details:
                details["pair_placement"] = "self"
        elif source and destination:
            placement = (
                "same compute host"
                if source.host and destination.host and source.host == destination.host
                else "different compute hosts"
                if source.host and destination.host
                else "compute placement unavailable"
            )
            details["compute_placement"] = placement
        likely_failure = None
        if probe.diagnostics.get("execution_error"):
            details["execution_error"] = probe.diagnostics["execution_error"]
        if decision.status in {"FAIL", "ERROR"}:
            likely_failure, diagnostic_details = self.diagnostics.collect(
                spec, probe, source, destination
            )
            details.update(diagnostic_details)
        rendered_message = message or decision.message
        if (
            spec.category == "same-subnet"
            and source
            and destination
            and source.server_id != destination.server_id
            and source.host
            and destination.host
            and source.host == destination.host
        ):
            rendered_message = (
                f"{rendered_message}. Both test VMs were placed on the same Nova compute host; "
                "this result does not verify an inter-compute path"
            )
        if decision.status in {"FAIL", "ERROR"} and probe.stderr:
            rendered_message = f"{rendered_message}: {self._concise(probe.stderr)}"
        self.reporter.result(
            spec.id,
            spec.category,
            decision.status,
            rendered_message,
            family=spec.family,
            source=(
                f"{source.label} ({probe.source_ip})"
                if source and probe.source_ip
                else source.label
                if source
                else probe.source_ip
            ),
            destination=(
                f"{destination.label} ({probe.destination_ip})"
                if destination and probe.destination_ip
                else destination.label
                if destination
                else probe.destination_ip
            ),
            duration_ms=probe.elapsed_ms,
            details=details,
            expected=decision.expected,
            observed=decision.observed,
            authoritative=decision.authoritative,
            likely_failure=likely_failure,
            display_name=packet_path_display_name(spec.display_name, details),
            scenario=spec.scenario,
        )

    def _group(self, group_id: str | None) -> RuntimeGroup:
        if not group_id or group_id not in self.groups:
            raise SuiteError(f"Required runtime group is not active: {group_id}")
        return self.groups[group_id]

    @staticmethod
    def _endpoint(group: RuntimeGroup, side: str) -> Endpoint:
        endpoint = group.endpoint(side)
        if not endpoint:
            raise SuiteError(f"Runtime group {group.plan.id} lacks endpoint {side}")
        return endpoint

    def _endpoint_address(
        self,
        group_id: str | None,
        side: str,
        subnet_id: str | None,
    ) -> tuple[Endpoint, str]:
        group = self._group(group_id)
        endpoint = self._endpoint(group, side)
        return endpoint, self._address(group, endpoint, subnet_id)

    @staticmethod
    def _address(group: RuntimeGroup, endpoint: Endpoint, subnet_id: str | None) -> str:
        if subnet_id in {None, "runtime"}:
            actual = (group.metadata.get("side_subnet_ids") or {}).get(
                endpoint.side.upper(), group.subnet_ids[0]
            )
        elif str(subnet_id).startswith("side-"):
            side = str(subnet_id).split("-", 1)[1].upper()
            actual = (group.metadata.get("side_subnet_ids") or {}).get(side)
            if not actual:
                raise SuiteError(
                    f"Runtime group {group.plan.id} has no subnet for side {side}"
                )
        else:
            actual = str(subnet_id)
        address = endpoint.fixed_ips.get(str(actual))
        if not address:
            raise SuiteError(
                f"Endpoint {endpoint.label} has no fixed address for subnet {actual}"
            )
        return address

    def _network_identity(
        self,
        group_id: str | None,
        side: str | None = None,
    ) -> tuple[str, str]:
        """Resolve the endpoint's network without issuing a cloud request."""
        group = self._group(group_id)
        normalized_side = str(side or "").upper()
        network_ids = group.metadata.get("network_ids") or {}
        network_names = group.metadata.get("network_names") or {}
        network_id = str(network_ids.get(normalized_side) or group.network_id)
        network_name = str(
            network_names.get(normalized_side) or group.network_name or network_id
        )
        return network_id, network_name

    def _network_mtu_observation(
        self,
        group_id: str | None,
        side: str | None = None,
    ) -> dict[str, Any]:
        """Read the exact endpoint network's current Neutron MTU contract."""
        network_id, network_name = EngineCommonMixin._network_identity(
            self, group_id, side
        )
        return EngineCommonMixin._neutron_network_mtu_observation(
            self,
            network_id,
            network_name,
        )

    def _neutron_network_mtu_observation(
        self,
        network_id: str,
        network_name: str | None = None,
    ) -> dict[str, Any]:
        """Read MTU evidence for a Neutron network not represented by a group."""
        network_name = str(network_name or network_id)
        detail = self.builder.osc.json("network", "show", network_id, check=False) or {}
        reported_mtu = pick(detail, "mtu", default=None)
        authority = "live Neutron network.mtu"
        source = "openstack network show"
        discovery_network = None
        try:
            discovery_network = self.discovery.network(network_id)
        except (AttributeError, KeyError, StopIteration, SuiteError):
            discovery_network = None
        if reported_mtu in (None, "") and discovery_network is not None:
            reported_mtu = discovery_network.mtu
            authority = "Neutron discovery network.mtu"
            source = "discovery inventory"
        network_type = pick(
            detail,
            "provider:network_type",
            "provider_network_type",
            "network_type",
            default=(
                discovery_network.network_type
                if discovery_network is not None
                else None
            ),
        )
        physical_network = pick(
            detail,
            "provider:physical_network",
            "provider_physical_network",
            "physical_network",
            default=(
                discovery_network.physical_network
                if discovery_network is not None
                else None
            ),
        )
        segmentation_id = pick(
            detail,
            "provider:segmentation_id",
            "provider_segmentation_id",
            "segmentation_id",
            default=(
                discovery_network.segmentation_id
                if discovery_network is not None
                else None
            ),
        )
        return make_mtu_observation(
            label=f"{network_name} Neutron network",
            reported_mtu=reported_mtu,
            authority=authority,
            authoritative=reported_mtu not in (None, ""),
            resource_type="network",
            resource_id=network_id,
            resource_name=network_name,
            observed_at=iso_utc(),
            network_type=network_type,
            physical_network=physical_network,
            segmentation_id=segmentation_id,
            source=source,
        )

    def _network_mtu(self, group_id: str | None, side: str | None = None) -> int:
        observation = self._network_mtu_observation(group_id, side)
        return int(observation["effective_mtu"])

    def _network_router_backend_evidence(self) -> dict[str, Any]:
        """Identify OVN only when Neutron's visible agent inventory proves it."""
        cached = getattr(self, "_router_backend_evidence_cache", None)
        if isinstance(cached, dict):
            return dict(cached)
        osc = getattr(getattr(self, "builder", None), "osc", None)
        json_call = getattr(osc, "json", None)
        lookup_error = None
        try:
            rows = (
                json_call(
                    "network",
                    "agent",
                    "list",
                    check=False,
                )
                or []
                if callable(json_call)
                else []
            )
        except RunCancelledError:
            raise
        except (OSError, SuiteError, TypeError, ValueError) as exc:
            # Agent inventory is often administrator-only. It strengthens
            # attribution, but its absence must not block the data-plane test.
            rows = []
            lookup_error = str(exc).splitlines()[-1][:500]
        if not isinstance(rows, list):
            rows = []
        agent_types = sorted(
            {
                str(
                    pick(
                        item,
                        "agent_type",
                        "agent type",
                        "binary",
                        default="",
                    )
                    or ""
                ).strip()
                for item in rows
                if isinstance(item, dict)
            }
            - {""}
        )
        normalized = " ".join(agent_types).lower()
        ovn_visible = "ovn" in normalized
        l3_agent_visible = "l3 agent" in normalized or "neutron-l3-agent" in normalized
        if ovn_visible and l3_agent_visible:
            backend = "mixed-or-ambiguous"
            confirmed = False
            reason = (
                "Neutron exposes both OVN and conventional L3 agent types. "
                "Flux cannot prove which backend owns this router and will not "
                "make an OVN-specific fragmentation claim."
            )
        elif ovn_visible:
            backend = "ovn"
            confirmed = True
            reason = "Neutron's visible agent inventory contains an OVN agent type."
        elif l3_agent_visible:
            backend = "neutron-l3-agent"
            confirmed = True
            reason = (
                "Neutron's visible agent inventory contains a conventional L3 agent."
            )
        else:
            backend = "unknown"
            confirmed = False
            reason = (
                "Neutron's visible agent inventory did not identify the router "
                "implementation; Flux will report router-path fragmentation without "
                "calling it OVN-specific."
            )
        if lookup_error:
            reason = (
                "Neutron agent inventory could not be read, so Flux cannot prove "
                f"the router backend: {lookup_error}"
            )
        evidence = {
            "backend": backend,
            "confirmed": confirmed,
            "authority": "openstack network agent list",
            "visible_agent_types": agent_types,
            "lookup_error": lookup_error,
            "reason": reason,
        }
        self._router_backend_evidence_cache = dict(evidence)
        return evidence

    def _require_state(self, key: str) -> dict[str, Any]:
        try:
            state = self.lifecycle.require(key)
        except AttributeError:
            state = self.lifecycle.get(key)
        except KeyError as exc:
            raise SuiteError(str(exc).strip("'")) from exc
        if not state:
            raise SuiteError(f"Lifecycle baseline is unavailable: {key}")
        return state

    @staticmethod
    def _concise(text: str) -> str:
        lines = [line.strip() for line in str(text).splitlines() if line.strip()]
        if not lines:
            return "unknown error"
        useful = [
            line
            for line in lines
            if not set(line).issubset({"^", "~", " "})
            and not line.startswith("File ")
            and not line.startswith("Traceback")
        ]
        value = useful[-1] if useful else lines[-1]
        return value[:500]
