"""Manual commands use the recovered path's family, including migration rows."""

from __future__ import annotations

import copy

import pytest

from neutron_flux.reporting_components.manual_recipes import build_recipe


@pytest.mark.parametrize(
    "source,destination",
    [
        ("2001:db8:1::11c", "2001:db8:1::393"),
        ("2001:db8:2::12", "2001:db8:2::2f"),
        ("2001:db8:3::84", "2001:db8:3::104"),
    ],
)
@pytest.mark.parametrize(
    "assertion",
    [
        "placement-achieved",
        "bound-to-destination",
        "endpoint-ready",
        "live-migration-complete",
    ],
)
def test_captured_twelve_ipv6_migration_shapes_recover_family_after_endpoints(
    source, destination, assertion
):
    # RC3 saved these four readbacks for three IPv6 workflows with no outer
    # family. The addresses were recorded only on their continuity context.
    result = {
        "category": "compute-placement",
        "family": None,
        "expected": assertion,
        "source": "az-test/source-compute",
        "destination": "az-test/target-compute",
        "details": {
            "continuity": {
                "source_ip": source,
                "target_fixed_ip": destination,
                "stationary_server_id": "stationary-vm",
                "moving_server_id": "moving-vm",
            }
        },
    }
    before = copy.deepcopy(result)
    recipe = build_recipe(result)
    route = next(
        row for row in recipe["steps"] if row["title"] == "Confirm the data route"
    )
    assert route["command"] == 'ip -6 route get "$DESTINATION_IP" from "$SOURCE_IP"'
    assert not any("ip -4" in row["command"] for row in recipe["steps"])
    parameters = {row["name"]: row["recorded"] for row in recipe["parameters"]}
    assert parameters["SOURCE_IP"] == source
    assert parameters["DESTINATION_IP"] == destination
    assert result == before


@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("family", [4, 6])
def test_nested_continuity_family_and_addresses_agree(nested, family):
    source, destination = (
        ("192.0.2.10", "192.0.2.20")
        if family == 4
        else ("2001:db8::10", "2001:db8::20")
    )
    details = {
        "continuity": {
            "family": family,
            "source_ip": source,
            "target_fixed_ip": destination,
            "moving_server_id": "moving-vm",
        }
    }
    recipe = build_recipe(
        {
            "category": "compute-placement",
            "expected": "bound-to-destination",
            "details": {"details": details} if nested else details,
        }
    )
    assert any(f"ip -{family} route get" in row["command"] for row in recipe["steps"])
    assert not any("family" in gap for gap in recipe["incomplete"])


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize(
    "category,operation",
    [
        ("same-subnet", "probe"),
        ("egress", "probe"),
        ("server-lifecycle", "server-stop"),
        ("floating-ip-lifecycle", "fip-withdraw"),
        ("router-interface-lifecycle", "router-interface-remove"),
        ("security-group", "security-allow"),
        ("router-static-routing", "static-route-install"),
        ("network-performance", "probe"),
    ],
)
def test_all_manual_contexts_infer_family_from_actual_addresses(
    family, category, operation
):
    source, destination = (
        ("192.0.2.10", "192.0.2.20")
        if family == 4
        else ("2001:db8::10", "2001:db8::20")
    )
    result = {
        "category": category,
        "source": f"Source ({source})",
        "destination": f"Destination ({destination})",
        "expected": "reachable",
        "details": {"operation": operation, "measurement": "mtu-mss"},
    }
    recipe = build_recipe(result)
    commands = "\n".join(row["command"] for row in recipe["steps"])
    assert f"ip -{family} route get" in commands
    assert f"ip -{10 - family} route get" not in commands
    if category == "security-group":
        assert f"--ethertype IPv{family}" in commands


@pytest.mark.parametrize(
    "result_family,detail_family,path_family,source,destination",
    [
        (4, None, None, "2001:db8::10", "2001:db8::20"),
        (None, 6, None, "192.0.2.10", "192.0.2.20"),
        (None, None, 4, "2001:db8::10", "2001:db8::20"),
        (None, None, None, "192.0.2.10", "2001:db8::20"),
        (None, None, None, "invalid-address", "192.0.2.20"),
        (5, None, None, None, None),
        (True, None, None, None, None),
        (None, None, None, None, None),
    ],
)
def test_missing_or_conflicting_family_never_emits_guessed_probes_or_policy_changes(
    result_family, detail_family, path_family, source, destination
):
    recipe = build_recipe(
        {
            "category": "security-group",
            "family": result_family,
            "details": {
                "operation": "security-allow",
                "family": detail_family,
                "source_ip": source,
                "destination_ip": destination,
                "path": {"family": path_family},
            },
        }
    )
    assert not recipe["steps"]
    assert not recipe["changes_state"]
    assert any("family" in gap for gap in recipe["incomplete"])


@pytest.mark.parametrize("family", [4, 6])
def test_explicit_family_without_saved_addresses_remains_current_operator_input(family):
    recipe = build_recipe(
        {"category": "same-subnet", "family": family, "expected": "reachable"}
    )
    assert any(f"ping -{family}" in row["command"] for row in recipe["steps"])
    assert not any("route get" in row["command"] for row in recipe["steps"])
    assert any("endpoint addresses are missing" in gap for gap in recipe["incomplete"])


def test_unknown_family_keeps_read_only_placement_inspection_without_route_guess():
    recipe = build_recipe(
        {
            "category": "compute-placement",
            "expected": "bound-to-destination",
            "details": {"moving_server_id": "moving-vm"},
        }
    )
    assert len(recipe["steps"]) == 1
    assert "openstack server show" in recipe["steps"][0]["command"]
    assert not recipe["changes_state"]
    assert any("No IP family" in gap for gap in recipe["incomplete"])


def test_continuity_family_conflict_retains_inspection_but_not_a_route_guess():
    recipe = build_recipe(
        {
            "category": "compute-placement",
            "expected": "bound-to-destination",
            "details": {
                "continuity": {
                    "family": 4,
                    "source_ip": "2001:db8::10",
                    "target_fixed_ip": "2001:db8::20",
                    "moving_server_id": "moving-vm",
                }
            },
        }
    )
    assert len(recipe["steps"]) == 1
    assert "openstack server show" in recipe["steps"][0]["command"]
    assert any("disagree" in gap for gap in recipe["incomplete"])


def test_referenced_baseline_addresses_are_recovered_before_family_resolution():
    recipe = build_recipe(
        {
            "category": "compute-placement",
            "expected": "fresh-functional-matrix",
            "details": {"rounds": [{"test_ids": ["BASELINE"]}]},
        },
        {
            "results": [
                {
                    "test_id": "AZ-TEST-BASELINE",
                    "family": 6,
                    "source": "Source (2001:db8::10)",
                    "destination": "Destination (2001:db8::20)",
                    "details": {
                        "source_server_id": "source-vm",
                        "destination_server_id": "destination-vm",
                    },
                }
            ]
        },
    )
    assert any("ip -6 route get" in row["command"] for row in recipe["steps"])
    assert not recipe["changes_state"]


def test_external_egress_recovery_does_not_invent_destination_vm_identity():
    recipe = build_recipe(
        {
            "category": "egress",
            "source": "Source VM (2001:db8::10)",
            "destination": "2606:4700:4700::1111",
            "expected": "reachable",
        }
    )
    assert any("ping -6" in row["command"] for row in recipe["steps"])
    assert recipe["destination"]["server_id"] is None
    assert not any("responder" in row["title"].lower() for row in recipe["steps"])
