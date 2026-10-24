from __future__ import annotations

from typing import Any

from .az_policy import discover_neutron_zones, select_neutron_zone
from .config import Config
from .errors import SuiteError
from .models import Discovery, Plan
from .utils import iso_utc, normalized_map, pick


class CapabilityPreflight:
    """Collect read-only capability evidence before the first cloud operation."""

    def __init__(
        self,
        config: Config,
        discovery: Discovery,
        plan: Plan,
        osc: Any,
        logger: Any,
    ):
        self.config = config
        self.discovery = discovery
        self.plan = plan
        self.osc = osc
        self.logger = logger
        self.checks: list[dict[str, Any]] = []

    def run(self) -> dict[str, Any]:
        self.logger.section("Capability and policy preflight")
        self._nova_microversion()
        self._host_inventory_visibility()
        self._forced_host_policy()
        self._neutron_binding_visibility()
        self._network_extensions()
        self._neutron_az_placement()
        self._cinder_availability()
        self._quota_headroom()
        blockers = [
            check["id"]
            for check in self.checks
            if check["required"] and check["status"] == "FAIL"
        ]
        summary = {
            "generated_at": iso_utc(),
            "checks": self.checks,
            "counts": {
                status: sum(1 for check in self.checks if check["status"] == status)
                for status in ("PASS", "FAIL", "DEFERRED")
            },
            "blockers": blockers,
            "complete": not blockers,
        }
        for check in self.checks:
            level = (
                "ERROR"
                if check["status"] == "FAIL"
                else ("WARNING" if check["status"] == "DEFERRED" else "INFO")
            )
            self.logger.log(
                f"Capability {check['id']}: {check['status']} — {check['message']}",
                level,
            )
        return summary

    def _add(
        self,
        check_id: str,
        status: str,
        message: str,
        *,
        required: bool,
        evidence: dict[str, Any] | None = None,
        drift_relevant: bool = True,
    ) -> None:
        self.checks.append(
            {
                "id": check_id,
                "status": status,
                "required": required,
                "message": message,
                "evidence": evidence or {},
                "drift_relevant": drift_relevant,
            }
        )

    def _neutron_az_placement(self) -> None:
        try:
            inventory = (
                discover_neutron_zones(
                    self.discovery,
                    self.osc,
                    timeout=min(60, self.config.resource_timeout),
                )
                if not self.config.allow_cross_az_networking
                else {"network": {}, "router": {}}
            )
            zones: list[str | None] = list(self.config.availability_zones)
            if self.plan.host_qualification is not None:
                zones.extend(
                    host.availability_zone
                    for host in self.plan.host_qualification.hosts
                    if host.availability_zone
                )
            selections = []
            for resource_type in ("network", "router"):
                # Automatic compute choice is finalized in ResourceBuilder's
                # read-only preparation, before its first keypair/network write.
                for zone in dict.fromkeys(zones or [None]):
                    if zone is None and not getattr(self.config, f"{resource_type}_az"):
                        continue
                    selections.append(
                        select_neutron_zone(
                            self.config, self.discovery, inventory, resource_type, zone
                        )
                    )
            self._add(
                "neutron-az-placement",
                "PASS",
                "Service-specific Neutron AZ inventory and requested overrides validated; automatic scope is resolved before provisioning",
                required=True,
                evidence={
                    "inventory": inventory,
                    "selections": selections,
                    "allow_cross_az_networking": self.config.allow_cross_az_networking,
                },
            )
        except SuiteError as exc:
            self._add("neutron-az-placement", "FAIL", str(exc), required=True)

    @staticmethod
    def _command_detail(result: Any) -> str:
        return str(
            getattr(result, "stderr", "")
            or getattr(result, "stdout", "")
            or "OpenStack command failed without output"
        ).strip()

    def _nova_microversion(self) -> None:
        result = self.osc.run(
            "--os-compute-api-version",
            "2.53",
            "compute",
            "service",
            "list",
            "--service",
            "nova-compute",
            check=False,
            timeout=min(60, self.config.resource_timeout),
        )
        if result.returncode == 0:
            self._add(
                "nova-microversion-2.53",
                "PASS",
                "Nova accepted the microversion used for placement evidence",
                required=self.config.host_qualification_enabled,
                evidence={"requested": "2.53", "accepted": True},
            )
        else:
            self._add(
                "nova-microversion-2.53",
                "FAIL",
                self._command_detail(result),
                required=self.config.host_qualification_enabled,
                evidence={"requested": "2.53", "accepted": False},
            )

    def _host_inventory_visibility(self) -> None:
        qualification = self.plan.host_qualification
        if qualification is None:
            self._add(
                "nova-host-inventory",
                "PASS",
                "Exact host inventory is not required by this plan",
                required=False,
                evidence={"required": False},
            )
            return
        visible = [
            host.host
            for host in qualification.hosts
            if host.availability_zone and host.service_ids
        ]
        expected = [host.host for host in qualification.hosts]
        missing = sorted(set(expected) - set(visible))
        self._add(
            "nova-host-inventory",
            "FAIL" if missing else "PASS",
            (
                "Nova exposed canonical host, service, and availability-zone fields"
                if not missing
                else "Nova did not expose complete host fields for "
                + ", ".join(missing)
            ),
            required=True,
            evidence={
                "visible_hosts": sorted(visible),
                "missing_hosts": missing,
            },
        )

    def _forced_host_policy(self) -> None:
        if not self.config.host_qualification_enabled:
            self._add(
                "nova-forced-host-policy",
                "PASS",
                "Forced-host scheduling is not required by this plan",
                required=False,
                evidence={"required": False},
            )
            return
        help_result = self.osc.run(
            "server",
            "create",
            "--help",
            check=False,
            timeout=30,
        )
        text = (
            str(getattr(help_result, "stdout", ""))
            + "\n"
            + str(getattr(help_result, "stderr", ""))
        ).lower()
        syntax_visible = "--availability-zone" in text
        self._add(
            "nova-forced-host-policy",
            "DEFERRED" if syntax_visible else "FAIL",
            (
                "Client syntax is available; Nova policy cannot be proven by a "
                "read-only request and will be enforced on the first disposable boot"
                if syntax_visible
                else "The OpenStack client does not expose forced-host placement syntax"
            ),
            required=not syntax_visible,
            evidence={
                "client_syntax_visible": syntax_visible,
                "runtime_enforcement": True,
            },
            drift_relevant=False,
        )

    def _neutron_binding_visibility(self) -> None:
        # ``openstack port list`` has no portable ``--limit`` option.  Scope the
        # read-only sample to one selected network instead; binding visibility
        # is still enforced against every endpoint created by the run.
        network_id = self.discovery.networks[0].id if self.discovery.networks else None
        if network_id:
            ports = self.osc.json(
                "port",
                "list",
                "--network",
                network_id,
                check=False,
                timeout=min(60, self.config.resource_timeout),
            )
        else:
            ports = self.osc.json(
                "port",
                "list",
                check=False,
                timeout=min(60, self.config.resource_timeout),
            )
        if not isinstance(ports, list):
            self._add(
                "neutron-port-binding-visibility",
                "DEFERRED",
                "The optional existing-port binding probe is unavailable; created "
                "ports will be checked before test execution",
                required=False,
                evidence={
                    "port_inventory": False,
                    "network_id": network_id,
                    "runtime_enforcement": True,
                },
                drift_relevant=False,
            )
            return
        if not ports:
            self._add(
                "neutron-port-binding-visibility",
                "DEFERRED",
                "No existing port is available for a read-only binding-field probe; "
                "created ports will be checked before test execution",
                required=False,
                evidence={
                    "port_inventory": True,
                    "sample_available": False,
                    "network_id": network_id,
                    "runtime_enforcement": True,
                },
                drift_relevant=False,
            )
            return
        port_id = next(
            (
                str(pick(item, "id", default="") or "").strip()
                for item in ports
                if isinstance(item, dict) and pick(item, "id", default=None)
            ),
            "",
        )
        if not port_id:
            self._add(
                "neutron-port-binding-visibility",
                "DEFERRED",
                "Neutron returned port rows without a usable ID; created ports will "
                "be checked before test execution",
                required=False,
                evidence={
                    "port_inventory": True,
                    "sample_available": False,
                    "network_id": network_id,
                    "runtime_enforcement": True,
                },
                drift_relevant=False,
            )
            return
        detail = (
            self.osc.json(
                "port",
                "show",
                port_id,
                check=False,
                timeout=min(60, self.config.resource_timeout),
            )
            or {}
        )
        normalized = normalized_map(detail) if isinstance(detail, dict) else {}
        visible = any(key in normalized for key in {"binding_host_id", "binding_host"})
        self._add(
            "neutron-port-binding-visibility",
            "PASS" if visible else "DEFERRED",
            (
                "Neutron exposes port binding-host evidence"
                if visible
                else "The sampled port hid binding-host fields; runtime will require "
                "settlement evidence on each created endpoint"
            ),
            required=False,
            evidence={
                "port_inventory": True,
                "sample_available": True,
                "sample_port_id": port_id,
                "detail_available": isinstance(detail, dict) and bool(detail),
                "binding_host_visible": visible,
                "network_id": network_id,
                "runtime_enforcement": True,
            },
            drift_relevant=False,
        )

    def _network_extensions(self) -> None:
        extensions = set(self.discovery.network_extensions)
        required = {"external-net"}
        if any(network.port_security_enabled for network in self.discovery.networks):
            required.add("port-security")
        if not extensions:
            self._add(
                "neutron-required-extensions",
                "DEFERRED",
                "Neutron returned no extension inventory; individual resource "
                "capabilities remain runtime-enforced",
                required=False,
                evidence={"required": sorted(required), "inventory_available": False},
                drift_relevant=False,
            )
            self._add(
                "neutron-resource-tags",
                "DEFERRED",
                "Neutron returned no extension inventory; tag support will be enforced on the first managed resource",
                required=False,
                evidence={
                    "required_alias": "standard-attr-tag",
                    "inventory_available": False,
                    "runtime_enforcement": True,
                },
                drift_relevant=False,
            )
            return
        missing = sorted(required - extensions)
        self._add(
            "neutron-required-extensions",
            "FAIL" if missing else "PASS",
            (
                "Required Neutron extensions are visible"
                if not missing
                else "Missing Neutron extensions: " + ", ".join(missing)
            ),
            required=True,
            evidence={
                "required": sorted(required),
                "missing": missing,
            },
        )
        tags_available = "standard-attr-tag" in extensions
        self._add(
            "neutron-resource-tags",
            "PASS" if tags_available else "FAIL",
            (
                "Neutron exposes standard resource tags used for ownership and cleanup"
                if tags_available
                else "Missing Neutron extension: standard-attr-tag"
            ),
            required=True,
            evidence={
                "required_alias": "standard-attr-tag",
                "available": tags_available,
            },
        )

    def _cinder_availability(self) -> None:
        if self.config.storage != "volume":
            self._add(
                "cinder-service",
                "PASS",
                "Cinder is not required for host-backed roots",
                required=False,
                evidence={"required": False},
            )
            return
        command = ("volume", "service", "list")
        result = self.osc.run(
            *command,
            check=False,
            timeout=min(60, self.config.resource_timeout),
        )
        self._add(
            "cinder-service",
            "PASS" if result.returncode == 0 else "FAIL",
            (
                "Cinder service inventory is available"
                if result.returncode == 0
                else self._command_detail(result)
            ),
            required=True,
            evidence={
                "required": True,
                "available": result.returncode == 0,
                "project_scoped": False,
            },
        )

    def _quota_headroom(self) -> None:
        mapping = {
            "instances": "peak_instances",
            "cores": "peak_cores",
            "ram": "peak_ram_mb",
            "ports": "peak_ports",
            "volumes": "peak_volumes",
        }
        deficits: dict[str, dict[str, int]] = {}
        evidence: dict[str, Any] = {}
        unknown: list[str] = []
        for quota_name, estimate_name in mapping.items():
            required = int(self.plan.estimated.get(estimate_name, 0) or 0)
            quota = self.discovery.quota_info.get(quota_name)
            available = quota.available if quota is not None else None
            unlimited = bool(
                quota is not None and quota.limit is not None and quota.limit < 0
            )
            evidence[quota_name] = {
                "required": required,
                "available": available,
            }
            if unlimited:
                evidence[quota_name]["unlimited"] = True
            if required > 0 and available is None and not unlimited:
                unknown.append(quota_name)
            if available is not None and required > available:
                deficits[quota_name] = {
                    "required": required,
                    "available": available,
                }
        self._add(
            "quota-headroom",
            "FAIL" if deficits else "DEFERRED" if unknown else "PASS",
            (
                "Insufficient quota: "
                + ", ".join(
                    f"{name} needs {row['required']}, has {row['available']}"
                    for name, row in sorted(deficits.items())
                )
                if deficits
                else "Quota usage is unavailable for "
                + ", ".join(sorted(unknown))
                + "; headroom cannot be verified before resource creation"
                if unknown
                else "Quota headroom satisfies the planned peak"
            ),
            required=True,
            evidence=evidence,
        )


__all__ = ["CapabilityPreflight"]
