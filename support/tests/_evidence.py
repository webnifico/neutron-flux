"""Independent boundary fixtures with the evidence emitted by real guests/APIs.

These are not verdict mocks: tests still call the production planner, handlers,
policy and coordinator. Socket and capture integration tests exercise the real
boundary implementations separately.
"""

from __future__ import annotations

from unittest import mock


def association_reader(groups):
    """Resolve a mock Neutron response from the allocation, not requested values."""

    def read(fip_id, **_kwargs):
        for group in groups:
            for ep in group.endpoints:
                allocation = group.fips.get(ep.label) or {}
                if allocation.get("id") == fip_id:
                    return {
                        "matched": True,
                        "port_id": allocation["port_id"],
                        "fixed_ip_address": next(iter(ep.fixed_ips.values())),
                        "floating_ip_address": allocation["address"],
                        "floating_ip_id": fip_id,
                    }
        return {"matched": False, "error": "allocation not found"}

    return mock.Mock(wraps=read)


def data_route(endpoint, source, destination, _family):
    return {
        "returncode": 0,
        "device": "ens4",
        "source": source,
        "destination": destination,
        "stdout": f"{destination} from {source} dev ens4",
        "stderr": "",
        "interfaces": [
            {
                "ifname": "ens3",
                "address": "fa:16:3e:ff:ff:ff",
                "addr_info": [{"local": endpoint.management_ip}],
            },
            {
                "ifname": "ens4",
                "address": endpoint.test_mac,
                "addr_info": [
                    {"local": value} for value in endpoint.fixed_ips.values()
                ],
            },
        ],
    }


def attestation_boundary(_launcher, _destination, _fixed, probe):
    """Replace only the guest packet-capture transport; exercise source probing."""
    return probe("1234567890abcdef1234567890abcdef")


def complete_continuity(
    *,
    icmp_loss=0.0,
    udp_loss=0.0,
    tcp_survived=True,
    recovered=True,
    outage=0.0,
    icmp_limit=1.0,
    udp_limit=1.0,
    outage_limit=1.0,
):
    # 10,000 observations represent percentages down to two decimals exactly.
    count = 10000
    icmp_lost = round(count * icmp_loss / 100)
    udp_lost = round(count * udp_loss / 100)
    samples = [{"ok": index >= icmp_lost} for index in range(count)]
    if recovered is False:
        # Keep totals consistent while placing the last missed sample at end.
        if icmp_lost:
            samples[0]["ok"], samples[-1]["ok"] = True, False
        else:
            samples[-1]["ok"] = False
            icmp_lost = 1
            icmp_loss = 0.01
    return {
        "available": True,
        "ready_before_migration": True,
        "sampling_complete": True,
        "full_migration_window": True,
        "migration_succeeded": True,
        "migration_completion_evidence": {
            "server_id": "fixture-destination",
            "source_host": "compute1",
            "destination_host": "compute2",
            "source_availability_zone": "az1",
            "destination_availability_zone": "az1",
            "migration_record_verified": True,
            "task_state_cleared": True,
            "port_binding_verified": True,
            "volume_attachment_verified": True,
            "guest_marker_verified": True,
            "endpoint_ready": True,
            "confirmed": True,
        },
        "workers_complete": True,
        "target_server_id": "fixture-destination",
        "target_fixed_ip": "192.0.2.20",
        "data_path_before": {"verified": True},
        "data_path_after": {"verified": True},
        "thresholds": {
            "icmp_loss_pct": icmp_limit,
            "udp_loss_pct": udp_limit,
            "outage_lower_bound_s": outage_limit,
        },
        "icmp": {
            "samples": count,
            "lost": icmp_lost,
            "loss_pct": icmp_loss,
            "raw_samples": samples,
            "outage": {
                "failed_observations": icmp_lost,
                "outage_lower_bound_s": outage,
                "outage_upper_bound_s": outage + (0.5 if icmp_lost else 0),
            },
        },
        "tcp": {
            "connected": True,
            "survived": tcp_survived,
            "terminal": True,
            "identity_verified": True,
            "receiver_identity": {
                "probe_id": "fixture-destination",
                "instance_id": "fixture-receiver",
                "local_ip": "192.0.2.20",
                "token": "1234567890abcdef1234567890abcdef",
            },
            "bytes_sent": 65536,
            "server_result": {
                "bytes": 65536,
                "probe_id": "fixture-destination",
                "instance_id": "fixture-receiver",
                "local_ip": "192.0.2.20",
                "token": "1234567890abcdef1234567890abcdef",
            },
            "error": None,
        },
        "udp": {
            "terminal": True,
            "sent": count,
            "error": None,
            "identity_verified": True,
            "session_id": 41,
            "response": {
                "session_id": 41,
                "sent": count,
                "probe_id": "fixture-destination",
                "instance_id": "fixture-receiver",
                "local_ip": "192.0.2.20",
                "received": count - udp_lost,
                "loss_pct": udp_loss,
                "max_sequence": count - 1 if udp_lost < count else -1,
            },
        },
    }


def configure_translation_target(engine, group, target):
    """Give legacy handler tests an explicit, permitted private FIP topology."""
    from neutron_flux.network_contract import PRIVATE_TRANSLATION_PROJECT_NETWORK
    from neutron_flux.translation_safety import FLOATING_IP_TARGET_CONTRACT

    group.plan.kind = PRIVATE_TRANSLATION_PROJECT_NETWORK
    group.plan.synthetic_cidr = "192.0.2.0/24"
    group.plan.floating_subnet_id = "external-floating-subnet"
    group.plan.metadata.update(
        fixed_address_role="disposable-private",
        source_nat_mode="cloud-default",
        source_nat_controlled_by_flux=False,
        source_nat_default_expected=True,
        floating_ip_target_allowed=True,
        floating_ip_target_contract=FLOATING_IP_TARGET_CONTRACT,
        floating_ip_endpoint_sides=["A", "B"],
    )
    group.metadata["floating_ip_fixed_subnet_id"] = group.subnet_ids[0]
    group.fips[target.label]["port_id"] = target.test_port_id
    engine.builder.wait_floating_ip_association = association_reader([group])
    engine.builder._existing_probe_service_ready = mock.Mock(
        return_value=(
            True,
            {"listeners": {"4": {"tcp": True, "udp": True, "instance_id": "process"}}},
        )
    )


def completed_migration_evidence():
    return {
        "server_id": "server-b",
        "source_host": "compute1",
        "destination_host": "compute2",
        "source_availability_zone": "az1",
        "destination_availability_zone": "az1",
        "migration_record_verified": True,
        "task_state_cleared": True,
        "port_binding_verified": True,
        "volume_attachment_verified": True,
        "guest_marker_verified": True,
        "endpoint_ready": True,
    }
