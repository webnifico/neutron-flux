from __future__ import annotations

import ipaddress
import time
from typing import Any

# mypy: disable-error-code="attr-defined"
from ..errors import SuiteError
from ..resource_naming import claim_runtime_resource_name, managed_resource_name
from ..scheduling import READ_WORKERS, bounded_map
from ..utils import list_value, normalized_map, pick, required_text
from .types import SecurityGroupBundle


class SecurityRuntimeMixin:
    """Compatibility mixin for the security runtime subsystem."""

    def _create_security_groups(self, *, select_control_ports: bool = True) -> None:
        self.security_group_rules = getattr(self, "security_group_rules", {})
        shared_bundle = getattr(self, "shared_security_group_bundle", None)
        if shared_bundle is not None:
            self._adopt_shared_security_groups(shared_bundle)
            return
        self.logger.log(
            "Creating four isolated security groups for controller, management, and A/B data paths"
        )
        self.controller_sg_id = self._create_security_group(
            managed_resource_name(
                self,
                identity="security-group:controller",
                role="controller",
                resource_type="security-group",
            )
        )
        self.endpoint_management_sg_id = self._create_security_group(
            managed_resource_name(
                self,
                identity="security-group:endpoint-management",
                role="endpoint-management",
                resource_type="security-group",
            )
        )
        self.management_sg_id = self.endpoint_management_sg_id

        # Use different data-plane security groups for A and B endpoints. This
        # prevents administrator/default "same security group" ingress rules
        # from making the negative security-group test permanently reachable.
        self.test_sg_ids = {
            "A": self._create_security_group(
                managed_resource_name(
                    self,
                    identity="security-group:project-a-data",
                    role="project-a-data",
                    resource_type="security-group",
                )
            ),
            "B": self._create_security_group(
                managed_resource_name(
                    self,
                    identity="security-group:project-b-data",
                    role="project-b-data",
                    resource_type="security-group",
                )
            ),
        }
        # Compatibility alias: B is the destination in the group-local
        # security-group transition tests.
        self.test_sg_id = self.test_sg_ids["B"]

        desired: list[dict[str, Any]] = [
            # Runner control path to the controller provider IPv4 port.
            dict(
                sg=self.controller_sg_id,
                direction="ingress",
                family=4,
                protocol="icmp",
                remote="0.0.0.0/0",
            ),
            dict(
                sg=self.controller_sg_id,
                direction="ingress",
                family=4,
                protocol="tcp",
                port=22,
                remote="0.0.0.0/0",
            ),
            # Endpoint management is isolated to the generated management subnet.
            dict(
                sg=self.endpoint_management_sg_id,
                direction="ingress",
                family=4,
                protocol="icmp",
                remote=self.management_cidr,
            ),
            dict(
                sg=self.endpoint_management_sg_id,
                direction="ingress",
                family=4,
                protocol="tcp",
                port=22,
                remote=self.management_cidr,
            ),
        ]
        # Data-plane probes use dedicated ports; SSH/22 is not a test protocol.
        for sg_id in self.test_sg_ids.values():
            desired.extend(
                [
                    dict(
                        sg=sg_id,
                        direction="ingress",
                        family=4,
                        protocol="icmp",
                        remote="0.0.0.0/0",
                    ),
                    dict(
                        sg=sg_id,
                        direction="ingress",
                        family=6,
                        protocol="ipv6-icmp",
                        remote="::/0",
                    ),
                    dict(
                        sg=sg_id,
                        direction="ingress",
                        family=4,
                        protocol="tcp",
                        port=self.config.tcp_port,
                        remote="0.0.0.0/0",
                    ),
                    dict(
                        sg=sg_id,
                        direction="ingress",
                        family=6,
                        protocol="tcp",
                        port=self.config.tcp_port,
                        remote="::/0",
                    ),
                    dict(
                        sg=sg_id,
                        direction="ingress",
                        family=4,
                        protocol="udp",
                        port=self.config.udp_port,
                        remote="0.0.0.0/0",
                    ),
                    dict(
                        sg=sg_id,
                        direction="ingress",
                        family=6,
                        protocol="udp",
                        port=self.config.udp_port,
                        remote="::/0",
                    ),
                ]
            )

        # Explicit egress rules make probe traffic independent of project or
        # operator defaults. Existing equivalent rules are reused.
        for sg_id in (
            self.controller_sg_id,
            self.endpoint_management_sg_id,
            *self.test_sg_ids.values(),
        ):
            desired.extend(
                [
                    dict(
                        sg=sg_id,
                        direction="egress",
                        family=4,
                        protocol=None,
                        remote="0.0.0.0/0",
                    ),
                    dict(
                        sg=sg_id,
                        direction="egress",
                        family=6,
                        protocol=None,
                        remote="::/0",
                    ),
                ]
            )

        desired_by_group: dict[str, list[dict[str, Any]]] = {}
        for rule in desired:
            desired_by_group.setdefault(str(rule["sg"]), []).append(rule)
        rule_inventories = self._list_security_group_rule_inventories(
            list(desired_by_group)
        )
        removed_rule_ids: list[str] = []
        for sg_id, inventory in rule_inventories.items():
            unexpected = [
                rule
                for rule in inventory
                if str(rule.get("direction") or "").lower() == "ingress"
                and not any(
                    self._security_rule_matches(rule, wanted)
                    for wanted in desired_by_group[sg_id]
                )
            ]
            for rule in unexpected:
                rule_id = str(rule.get("id") or "").strip()
                if not rule_id:
                    raise SuiteError(
                        f"Flux-owned security group {sg_id} contains an unexpected ingress rule without an ID"
                    )
                self.logger.log(
                    f"Removing unexpected inherited ingress rule {rule_id} from Flux-owned security group {sg_id}"
                )
                result = self.osc.run(
                    "security",
                    "group",
                    "rule",
                    "delete",
                    rule_id,
                    check=False,
                    timeout=60,
                )
                if result.returncode != 0:
                    refreshed = self.list_security_group_rules(sg_id)
                    if any(str(item.get("id") or "") == rule_id for item in refreshed):
                        raise SuiteError(
                            "Could not remove unexpected inherited ingress rule "
                            f"{rule_id} from Flux-owned security group {sg_id}: "
                            + str(
                                result.stderr or result.stdout or "unknown error"
                            ).strip()
                        )
                removed_rule_ids.append(rule_id)
            if unexpected:
                rule_inventories[sg_id] = self.list_security_group_rules(sg_id)

        created_rule_ids: list[str] = []
        rule_started = time.monotonic()
        next_progress = rule_started + self.config.progress_interval
        self.logger.log(
            f"Reconciling {len(desired)} deterministic security-group rules; existing equivalent rules will be reused"
        )
        for index, rule in enumerate(desired, start=1):
            protocol = str(rule.get("protocol") or "any")
            rule_port_text = f"/{rule['port']}" if rule.get("port") is not None else ""
            self.logger.log(
                f"Security-group rule {index}/{len(desired)}: {rule['direction']} "
                f"IPv{rule['family']} {protocol}{rule_port_text} "
                f"remote={rule.get('remote') or 'any'}"
            )
            existing = rule_inventories[str(rule["sg"])]
            if any(self._security_rule_matches(item, rule) for item in existing):
                pass
            else:
                arguments = [
                    "--ingress" if rule["direction"] == "ingress" else "--egress",
                    "--ethertype",
                    f"IPv{rule['family']}",
                ]
                if rule.get("protocol"):
                    arguments.extend(["--protocol", str(rule["protocol"])])
                if rule.get("port") is not None:
                    arguments.extend(["--dst-port", str(rule["port"])])
                if rule.get("remote"):
                    arguments.extend(["--remote-ip", str(rule["remote"])])
                detail = self.osc.json(
                    "security",
                    "group",
                    "rule",
                    "create",
                    *arguments,
                    str(rule["sg"]),
                    check=False,
                )
                rule_id = str(pick(detail or {}, "id", default="") or "")
                if rule_id:
                    created_rule_ids.append(rule_id)
                    rule_inventories[str(rule["sg"])].append(
                        self._normalize_security_group_rule(
                            {
                                "id": rule_id,
                                "direction": rule["direction"],
                                "ethertype": f"IPv{rule['family']}",
                                "protocol": rule.get("protocol"),
                                "remote_ip_prefix": rule.get("remote"),
                                "port_range_min": rule.get("port"),
                                "port_range_max": rule.get("port"),
                            }
                        )
                    )
                else:
                    matched_id = self._reconcile_created_security_group_rule(
                        rule, index=index, total=len(desired)
                    )
                    if matched_id:
                        created_rule_ids.append(matched_id)
                    rule_inventories[str(rule["sg"])] = self.list_security_group_rules(
                        str(rule["sg"])
                    )
            now = time.monotonic()
            if now >= next_progress:
                self.logger.log(
                    f"Security-group rule reconciliation progress: {index}/{len(desired)} processed, "
                    f"{len(created_rule_ids)} newly created, elapsed={now - rule_started:.0f}s"
                )
                next_progress = now + self.config.progress_interval

        self.logger.log("Refreshing final security-group rule inventories")
        final_inventories = self._list_security_group_rule_inventories(
            list(desired_by_group)
        )
        self.security_group_rules.update(final_inventories)

        # The run-wide multi-zone bundle creates rules once, then each AZ lane
        # selects its own control port while adopting the bundle. Avoid an
        # unnecessary 128-port scan in the shared creator itself.
        if select_control_ports:
            # Choose a real listening control port independently for IPv4 and IPv6.
            # Rules scoped to the destination SG itself do not authorize traffic
            # from the separate source SG, so they are not treated as broad permits.
            for family in (4, 6):
                self.logger.log(
                    f"Scanning IPv{family} ingress rules for an isolated temporary TCP control port"
                )
                port, authoritative, matching = self.choose_security_control_port(
                    destination_security_group_id=self.test_sg_ids["B"],
                    source_security_group_id=self.test_sg_ids["A"],
                    family=family,
                    preferred_port=getattr(self, "security_control_port_seed", None),
                )
                self.security_control_ports[family] = port
                self.security_control_authoritative[family] = authoritative
                self.security_control_matching_rules[family] = matching
            self.probe_service.set_control_ports(self.security_control_ports)

        self.reporter.event(
            "security-groups-ready",
            (
                "Created separate A/B data-plane security groups and selected authoritative control ports where possible"
                if select_control_ports
                else "Created the run-wide shared security-group bundle; each AZ lane will select an isolated control port"
            ),
            controller_security_group=self.controller_sg_id,
            endpoint_management_security_group=self.endpoint_management_sg_id,
            data_security_groups=dict(self.test_sg_ids),
            management_cidr=self.management_cidr,
            created_rule_ids=created_rule_ids,
            removed_unexpected_ingress_rule_ids=removed_rule_ids,
            security_control_ports=dict(self.security_control_ports),
            security_control_authoritative=dict(self.security_control_authoritative),
            security_control_matching_rules=dict(self.security_control_matching_rules),
            actual_data_rules={
                side: self.security_group_rules.get(sg_id, [])
                for side, sg_id in self.test_sg_ids.items()
            },
        )
        if select_control_ports:
            for family in (4, 6):
                authority = (
                    "authoritative"
                    if self.security_control_authoritative[family]
                    else "unverified"
                )
                self.logger.log(
                    f"Selected IPv{family} security-group control TCP port "
                    f"{self.security_control_ports[family]} ({authority})"
                )

    def export_security_group_bundle(self) -> SecurityGroupBundle:
        if not (
            self.controller_sg_id
            and self.endpoint_management_sg_id
            and self.test_sg_ids.get("A")
            and self.test_sg_ids.get("B")
            and self.management_cidr
        ):
            raise SuiteError("Security-group bundle is not fully initialized")
        return SecurityGroupBundle(
            controller_security_group_id=self.controller_sg_id,
            endpoint_management_security_group_id=self.endpoint_management_sg_id,
            data_security_group_ids=dict(self.test_sg_ids),
            management_cidr=self.management_cidr,
            security_group_rules={
                group_id: [dict(rule) for rule in rules]
                for group_id, rules in self.security_group_rules.items()
            },
        )

    def _adopt_shared_security_groups(self, bundle: SecurityGroupBundle) -> None:
        if self.management_cidr != bundle.management_cidr:
            raise SuiteError(
                "Shared multi-zone security groups were created for management CIDR "
                f"{bundle.management_cidr}, but this lane selected {self.management_cidr}"
            )
        self.logger.log(
            "Reusing the run-wide project security groups; Neutron security groups are not availability-zone scoped"
        )
        self.controller_sg_id = bundle.controller_security_group_id
        self.endpoint_management_sg_id = bundle.endpoint_management_security_group_id
        self.management_sg_id = self.endpoint_management_sg_id
        self.test_sg_ids = dict(bundle.data_security_group_ids)
        self.test_sg_id = self.test_sg_ids["B"]
        self.security_group_rules = {
            group_id: [dict(rule) for rule in rules]
            for group_id, rules in bundle.security_group_rules.items()
        }
        for family in (4, 6):
            port, authoritative, matching = self.choose_security_control_port(
                destination_security_group_id=self.test_sg_ids["B"],
                source_security_group_id=self.test_sg_ids["A"],
                family=family,
                preferred_port=getattr(self, "security_control_port_seed", None),
            )
            self.security_control_ports[family] = port
            self.security_control_authoritative[family] = authoritative
            self.security_control_matching_rules[family] = matching
        self.probe_service.set_control_ports(self.security_control_ports)
        self.reporter.event(
            "security-groups-reused",
            "Reused one run-wide security-group bundle for this availability-zone lane",
            controller_security_group=self.controller_sg_id,
            endpoint_management_security_group=self.endpoint_management_sg_id,
            data_security_groups=dict(self.test_sg_ids),
            management_cidr=self.management_cidr,
            security_control_ports=dict(self.security_control_ports),
        )
        self.logger.log(
            "Shared security-group control ports for this lane: "
            + ", ".join(
                f"IPv{family}={self.security_control_ports[family]}"
                for family in (4, 6)
            )
        )

    @classmethod
    def _security_rule_matches(
        cls, rule: dict[str, Any], desired: dict[str, Any]
    ) -> bool:
        direction = str(pick(rule, "direction", default="") or "").lower()
        ethertype = str(pick(rule, "ethertype", "ether type", default="") or "")
        protocol = str(pick(rule, "protocol", default="") or "").lower()
        protocol_aliases = {"icmpv6": "ipv6-icmp", "icmp6": "ipv6-icmp"}
        protocol = protocol_aliases.get(protocol, protocol)
        expected_protocol = str(desired.get("protocol") or "").lower()
        expected_protocol = protocol_aliases.get(expected_protocol, expected_protocol)
        remote = str(
            pick(rule, "remote_ip_prefix", "remote ip prefix", "remote_ip", default="")
            or ""
        )
        if direction and direction != str(desired["direction"]).lower():
            return False
        if ethertype and ethertype.lower() != f"ipv{desired['family']}".lower():
            return False
        if expected_protocol:
            if protocol != expected_protocol:
                return False
        elif protocol not in {"", "none", "any"}:
            return False
        desired_remote = str(desired.get("remote") or "")
        if desired_remote and remote and remote != desired_remote:
            return False
        minimum, maximum = cls._rule_port_range(rule)
        desired_port = desired.get("port")
        if desired_port is None:
            return minimum is None and maximum is None
        return (
            (minimum or 0)
            <= int(desired_port)
            <= (maximum if maximum is not None else minimum or 0)
        )

    def _reconcile_created_security_group_rule(
        self, rule: dict[str, Any], *, index: int, total: int
    ) -> str | None:
        """Resolve one successful rule create without submitting it twice."""
        matched_rule: dict[str, Any] | None = None
        for reconciliation_attempt in range(1, 4):
            current = self.list_security_group_rules(str(rule["sg"]))
            matched_rule = next(
                (item for item in current if self._security_rule_matches(item, rule)),
                None,
            )
            if matched_rule is not None:
                break
            if reconciliation_attempt < 3:
                self.logger.log(
                    f"Security-group rule {index}/{total} was accepted without an ID; "
                    f"waiting for inventory reconciliation ({reconciliation_attempt}/3)",
                    "WARNING",
                )
                time.sleep(max(1, self.config.convergence_interval))
        if matched_rule is None:
            raise SuiteError(
                "OpenStack accepted deterministic security-group rule creation "
                "but the rule did not become visible during reconciliation"
            )
        return str(pick(matched_rule, "id", default="") or "") or None

    def _create_security_group(self, name: str) -> str:
        self.logger.log(f"Creating security group {name}")
        claim_runtime_resource_name(
            self,
            name,
            resource_type="security-group",
        )
        data = (
            self.osc.json(
                "security",
                "group",
                "create",
                "--tag",
                self.run_tag,
                "--description",
                self.run_tag,
                name,
            )
            or {}
        )
        resource_id = required_text(data, "id", context=f"OpenStack create for {name}")
        self.tracker.add("security_group", resource_id, name)
        return resource_id

    @classmethod
    def _normalize_security_group_rule(cls, rule: dict[str, Any]) -> dict[str, Any]:
        """Canonicalize native API and python-openstackclient rule spellings.

        OSC's JSON list formatter uses headings such as ``IP Protocol``,
        ``IP Range`` and one combined ``Port Range`` field.  Treating those as
        absent turns a narrow TCP rule into an apparent all-protocol/all-port
        permit, which destroys the deny/allow/restore authority check.
        """
        normalized = normalized_map(rule)
        protocol = normalized.get("protocol", normalized.get("ip_protocol"))
        protocol_text = (
            str(protocol).strip().lower() if protocol not in (None, "") else None
        )
        aliases = {"icmpv6": "ipv6-icmp", "icmp6": "ipv6-icmp"}
        if protocol_text is not None:
            protocol_text = aliases.get(protocol_text, protocol_text)

        minimum = normalized.get("port_range_min", normalized.get("min_port"))
        maximum = normalized.get("port_range_max", normalized.get("max_port"))
        combined = normalized.get("port_range")
        if (
            minimum in (None, "")
            and maximum in (None, "")
            and combined not in (None, "")
        ):
            text = str(combined).strip()
            if ":" in text:
                left, right = text.split(":", 1)
                minimum, maximum = left.strip(), right.strip()
            elif text:
                minimum = maximum = text

        def integer(value: Any) -> int | None:
            try:
                return int(value) if value not in (None, "") else None
            except (TypeError, ValueError):
                return None

        output = dict(rule)
        output.update(
            {
                "id": normalized.get("id"),
                "direction": normalized.get("direction"),
                "ethertype": normalized.get("ethertype", normalized.get("ether_type")),
                "protocol": protocol_text,
                "remote_ip_prefix": normalized.get(
                    "remote_ip_prefix",
                    normalized.get("ip_range", normalized.get("remote_ip")),
                ),
                "port_range_min": integer(minimum),
                "port_range_max": integer(maximum),
                "remote_group_id": normalized.get(
                    "remote_group_id",
                    normalized.get(
                        "remote_security_group_id",
                        normalized.get("remote_security_group"),
                    ),
                ),
                "remote_address_group_id": normalized.get(
                    "remote_address_group_id", normalized.get("remote_address_group")
                ),
            }
        )
        return output

    def list_security_group_rules(self, security_group_id: str) -> list[dict[str, Any]]:
        rows = self.osc.json(
            "security",
            "group",
            "rule",
            "list",
            security_group_id,
        )
        return self._validated_security_group_rule_inventory(security_group_id, rows)

    def _list_security_group_rule_inventories(
        self, security_group_ids: list[str]
    ) -> dict[str, list[dict[str, Any]]]:
        group_ids = list(security_group_ids)

        def read_rules(security_group_id: str) -> Any:
            return self.osc.json("security", "group", "rule", "list", security_group_id)

        rows_by_group = bounded_map(read_rules, group_ids, workers=READ_WORKERS)
        # No worker mutates rule inventories or reconciles security policy.
        # Publish the complete batch only after caller-thread validation.
        return {
            group_id: self._validated_security_group_rule_inventory(group_id, rows)
            for group_id, rows in zip(group_ids, rows_by_group, strict=True)
        }

    def _validated_security_group_rule_inventory(
        self, security_group_id: str, rows: Any
    ) -> list[dict[str, Any]]:
        if not isinstance(rows, list):
            raise SuiteError(
                f"OpenStack returned an invalid security-group rule inventory for "
                f"{security_group_id}"
            )
        return [
            self._normalize_security_group_rule(item)
            for item in rows
            if isinstance(item, dict)
        ]

    @staticmethod
    def _rule_port_range(rule: dict[str, Any]) -> tuple[int | None, int | None]:
        minimum = pick(rule, "port_range_min", "port range min", "min_port")
        maximum = pick(rule, "port_range_max", "port range max", "max_port")
        combined = pick(rule, "port_range", "port range", default=None)
        if (
            minimum in (None, "")
            and maximum in (None, "")
            and combined not in (None, "")
        ):
            text = str(combined).strip()
            if ":" in text:
                minimum, maximum = (part.strip() for part in text.split(":", 1))
            elif text:
                minimum = maximum = text
        try:
            min_value = int(minimum) if minimum not in (None, "") else None
        except (TypeError, ValueError):
            min_value = None
        try:
            max_value = int(maximum) if maximum not in (None, "") else None
        except (TypeError, ValueError):
            max_value = None
        return min_value, max_value

    @staticmethod
    def _rule_remote_group(rule: dict[str, Any]) -> str | None:
        value = pick(
            rule,
            "remote_group_id",
            "remote group id",
            "remote_security_group_id",
            default=None,
        )
        return str(value) if value not in (None, "") else None

    @staticmethod
    def _rule_remote_prefix(rule: dict[str, Any]) -> str | None:
        value = pick(
            rule,
            "remote_ip_prefix",
            "remote ip prefix",
            "remote_ip",
            default=None,
        )
        return str(value) if value not in (None, "") else None

    @staticmethod
    def _rule_remote_address_group(rule: dict[str, Any]) -> str | None:
        value = pick(
            rule,
            "remote_address_group_id",
            "remote address group id",
            default=None,
        )
        return str(value) if value not in (None, "") else None

    def _address_group_addresses(self, address_group_id: str) -> tuple[bool, list[str]]:
        if address_group_id in self._address_group_cache:
            return self._address_group_cache[address_group_id]
        detail = self.osc.json(
            "address",
            "group",
            "show",
            address_group_id,
            check=False,
        )
        if not isinstance(detail, dict):
            cached_result: tuple[bool, list[str]] = (False, [])
            self._address_group_cache[address_group_id] = cached_result
            return cached_result
        raw_addresses = pick(detail, "addresses", default=None)
        if raw_addresses is None:
            cached_result = (False, [])
            self._address_group_cache[address_group_id] = cached_result
            return cached_result
        addresses = [
            str(item).strip() for item in list_value(raw_addresses) if str(item).strip()
        ]
        cached_result = (True, addresses)
        self._address_group_cache[address_group_id] = cached_result
        return cached_result

    def _security_rule_source_applies(
        self,
        rule: dict[str, Any],
        *,
        family: int,
        source_security_group_id: str | None,
        source_ip: str | None,
        conservative_without_source: bool,
    ) -> bool:
        remote_group_id = self._rule_remote_group(rule)
        if remote_group_id:
            return remote_group_id == source_security_group_id

        remote_prefix = self._rule_remote_prefix(rule)
        if remote_prefix:
            try:
                network = ipaddress.ip_network(remote_prefix, strict=False)
            except ValueError:
                return conservative_without_source
            if network.version != family:
                return False
            if not source_ip:
                # A default route prefix is guaranteed to apply to every
                # source in the family. Narrower prefixes need the actual
                # source address before they can invalidate the baseline.
                if network.prefixlen == 0:
                    return True
                return conservative_without_source
            try:
                address = ipaddress.ip_address(source_ip)
            except ValueError:
                return conservative_without_source
            return address.version == family and address in network

        address_group_id = self._rule_remote_address_group(rule)
        if address_group_id:
            if not source_ip:
                return conservative_without_source
            try:
                address = ipaddress.ip_address(source_ip)
            except ValueError:
                return conservative_without_source
            known, addresses = self._address_group_addresses(address_group_id)
            if not known:
                # Lack of permission or extension support must not produce a
                # false authoritative negative security-group baseline.
                return True
            for value in addresses:
                try:
                    network = ipaddress.ip_network(value, strict=False)
                except ValueError:
                    continue
                if address.version == family and address in network:
                    return True
            return False

        return True

    def _security_rules_allow_port(
        self,
        rules: list[dict[str, Any]],
        family: int,
        protocol: str,
        port: int,
        *,
        source_security_group_id: str | None = None,
        source_ip: str | None = None,
        conservative_without_source: bool = True,
    ) -> tuple[bool, list[dict[str, Any]]]:
        matching: list[dict[str, Any]] = []
        expected_ethertype = f"IPv{family}"
        for raw_rule in rules:
            rule = self._normalize_security_group_rule(raw_rule)
            direction = str(pick(rule, "direction", default="") or "").lower()
            ethertype = str(pick(rule, "ethertype", "ether type", default="") or "")
            rule_protocol = str(pick(rule, "protocol", default="") or "").lower()
            if direction and direction != "ingress":
                continue
            if ethertype and ethertype.lower() != expected_ethertype.lower():
                continue
            if rule_protocol not in {protocol.lower(), "any", "", "none"}:
                continue
            if not self._security_rule_source_applies(
                rule,
                family=family,
                source_security_group_id=source_security_group_id,
                source_ip=source_ip,
                conservative_without_source=conservative_without_source,
            ):
                continue
            minimum, maximum = self._rule_port_range(rule)
            if minimum is None and maximum is None:
                matching.append(raw_rule)
                continue
            if (
                (minimum or 0)
                <= port
                <= (maximum if maximum is not None else minimum or 0)
            ):
                matching.append(raw_rule)
        return bool(matching), matching

    def security_group_allows_port(
        self,
        security_group_id: str,
        family: int,
        protocol: str,
        port: int,
        *,
        source_security_group_id: str | None = None,
        source_ip: str | None = None,
        conservative_without_source: bool = True,
        rules: list[dict[str, Any]] | None = None,
    ) -> tuple[bool, list[dict[str, Any]]]:
        inventory = (
            rules
            if rules is not None
            else self.list_security_group_rules(security_group_id)
        )
        return self._security_rules_allow_port(
            inventory,
            family,
            protocol,
            port,
            source_security_group_id=source_security_group_id,
            source_ip=source_ip,
            conservative_without_source=conservative_without_source,
        )

    def security_groups_allow_port(
        self,
        security_group_ids: list[str],
        family: int,
        protocol: str,
        port: int,
        *,
        source_security_group_id: str | None = None,
        source_ip: str | None = None,
    ) -> tuple[bool, list[dict[str, Any]]]:
        matching: list[dict[str, Any]] = []
        for group_id in dict.fromkeys(security_group_ids):
            allowed, group_rules = self.security_group_allows_port(
                group_id,
                family,
                protocol,
                port,
                source_security_group_id=source_security_group_id,
                source_ip=source_ip,
                conservative_without_source=False,
            )
            if allowed:
                for rule in group_rules:
                    matching.append({**rule, "security_group_id": group_id})
        return bool(matching), matching

    def port_security_group_ids(self, port_id: str) -> list[str]:
        detail = self.osc.json("port", "show", port_id, check=False)
        if not isinstance(detail, dict):
            raise SuiteError(
                f"Could not read security groups attached to port {port_id}"
            )
        return [
            str(item).strip()
            for item in list_value(
                pick(detail, "security_group_ids", "security_groups", default=[])
            )
            if str(item).strip()
        ]

    def choose_security_control_port(
        self,
        *,
        destination_security_group_id: str,
        source_security_group_id: str,
        family: int,
        preferred_port: int | None = None,
    ) -> tuple[int, bool, list[dict[str, Any]]]:
        minimum_port = 1024
        maximum_port = 65535
        span = maximum_port - minimum_port + 1
        preferred = (
            preferred_port if preferred_port is not None else self.config.tcp_port + 2
        )
        first = minimum_port + ((preferred - minimum_port) % span)
        candidates: list[int] = []
        for offset in range(128):
            port = minimum_port + ((first - minimum_port + offset) % span)
            if port in {self.config.tcp_port, self.config.udp_port}:
                continue
            candidates.append(port)
        can_inventory_once = "list_security_group_rules" in getattr(
            self, "__dict__", {}
        ) or hasattr(self, "osc")
        rules = (
            self.list_security_group_rules(destination_security_group_id)
            if can_inventory_once
            else None
        )
        last_matching: list[dict[str, Any]] = []
        for port in candidates:
            allowed, matching = self.security_group_allows_port(
                destination_security_group_id,
                family,
                "tcp",
                port,
                source_security_group_id=source_security_group_id,
                source_ip=None,
                conservative_without_source=False,
                **({"rules": rules} if rules is not None else {}),
            )
            if not allowed:
                return port, True, []
            last_matching = matching
        # A broad administrator rule permits every candidate. Keep a real
        # listener on the default control port but mark the transition
        # unverified rather than pretending the negative baseline is valid.
        return candidates[0], False, last_matching

    def _exact_temporary_security_rule_ids(
        self,
        security_group_id: str,
        *,
        source_security_group_id: str,
        family: int,
        protocol: str,
        port: int,
    ) -> set[str]:
        expected_ethertype = f"IPv{family}".lower()
        output: set[str] = set()
        for rule in self.list_security_group_rules(security_group_id):
            direction = str(pick(rule, "direction", default="") or "").lower()
            ethertype = str(
                pick(rule, "ethertype", "ether type", default="") or ""
            ).lower()
            rule_protocol = str(pick(rule, "protocol", default="") or "").lower()
            minimum, maximum = self._rule_port_range(rule)
            rule_id = str(pick(rule, "id", default="") or "").strip()
            if (
                rule_id
                and direction in {"", "ingress"}
                and ethertype in {"", expected_ethertype}
                and rule_protocol == protocol.lower()
                and minimum == port
                and maximum == port
                and self._rule_remote_group(rule) == source_security_group_id
            ):
                output.add(rule_id)
        return output

    def _wait_security_rule_absent(
        self, security_group_id: str, rule_id: str
    ) -> list[dict[str, Any]]:
        deadline = time.monotonic() + self.config.convergence_timeout
        last_error: str | None = None
        while True:
            try:
                rules = self.list_security_group_rules(security_group_id)
            except SuiteError as exc:
                last_error = str(exc)
            else:
                last_error = None
                if not any(
                    str(pick(item, "id", default="") or "") == rule_id for item in rules
                ):
                    return rules
            if time.monotonic() >= deadline:
                suffix = f": {last_error}" if last_error else ""
                raise SuiteError(
                    f"Temporary security-group rule {rule_id} remained present or "
                    f"could not be verified absent{suffix}"
                )
            time.sleep(self.config.convergence_interval)

    def add_temporary_security_rule(
        self,
        *,
        destination_security_group_id: str,
        source_security_group_id: str,
        family: int,
        protocol: str,
        port: int,
    ) -> str:
        before = self._exact_temporary_security_rule_ids(
            destination_security_group_id,
            source_security_group_id=source_security_group_id,
            family=family,
            protocol=protocol,
            port=port,
        )
        detail = self.osc.json(
            "security",
            "group",
            "rule",
            "create",
            "--ingress",
            "--ethertype",
            f"IPv{family}",
            "--protocol",
            protocol,
            "--dst-port",
            str(port),
            "--remote-group",
            source_security_group_id,
            destination_security_group_id,
            check=False,
        )
        rule_id = str(pick(detail or {}, "id", default="") or "").strip()
        if rule_id:
            try:
                self.security_group_rules[destination_security_group_id] = (
                    self.list_security_group_rules(destination_security_group_id)
                )
            except SuiteError as exc:
                self.logger.log(
                    f"Temporary security-group rule {rule_id} was created, but its "
                    f"inventory refresh failed: {exc}",
                    "WARNING",
                )
            return rule_id

        deadline = time.monotonic() + self.config.convergence_timeout
        created: list[str] = []
        last_error: str | None = None
        while True:
            try:
                after = self._exact_temporary_security_rule_ids(
                    destination_security_group_id,
                    source_security_group_id=source_security_group_id,
                    family=family,
                    protocol=protocol,
                    port=port,
                )
            except SuiteError as exc:
                last_error = str(exc)
            else:
                last_error = None
                created = sorted(after - before)
                if created:
                    break
            if time.monotonic() >= deadline:
                break
            time.sleep(self.config.convergence_interval)
        if len(created) == 1:
            self.logger.log(
                "Recovered temporary security-group rule identity from Neutron "
                f"state after the create response omitted it: {created[0]}",
                "WARNING",
            )
            return created[0]
        if created:
            for item in created:
                self.osc.run(
                    "security",
                    "group",
                    "rule",
                    "delete",
                    item,
                    check=False,
                    timeout=60,
                )
            raise SuiteError(
                "OpenStack created multiple indistinguishable temporary "
                f"security-group rules without returning an ID: {', '.join(created)}"
            )
        suffix = f": {last_error}" if last_error else ""
        raise SuiteError(
            f"OpenStack did not return or expose an ID for the temporary IPv{family} "
            f"{protocol}/{port} security-group rule{suffix}"
        )

    def delete_security_rule(
        self, rule_id: str, security_group_id: str | None = None
    ) -> None:
        result = self.osc.run(
            "security", "group", "rule", "delete", rule_id, check=False, timeout=60
        )
        refresh_id = security_group_id or self.test_sg_id
        refreshed = self._wait_security_rule_absent(refresh_id, rule_id)
        self.security_group_rules[refresh_id] = refreshed
        if result.returncode != 0:
            self.logger.log(
                f"Temporary security-group rule {rule_id} is absent despite a "
                "non-success delete response; treating the desired state as restored",
                "WARNING",
            )
