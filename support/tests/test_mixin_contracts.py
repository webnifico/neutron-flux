from __future__ import annotations

import ast
from pathlib import Path

import pytest

from neutron_flux.cleanup import CleanupManager
from neutron_flux.engine import TestEngine as FluxTestEngine
from neutron_flux.executor import AdaptiveExecutor
from neutron_flux.planning import Planner
from neutron_flux.reporting import Reporter
from neutron_flux.resources import ResourceBuilder

ROOT = Path(__file__).resolve().parents[2]


def _self_attributes(relative_path: str) -> set[str]:
    tree = ast.parse((ROOT / relative_path).read_text(encoding="utf-8"))
    return {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
    }


RESOURCE_INSTANCE_FIELDS = {
    "dependencies",
    "config",
    "discovery",
    "plan",
    "osc",
    "reporter",
    "logger",
    "tracker",
    "_state",
    "guest_network",
    "probe_service",
}
ENGINE_INSTANCE_FIELDS = {
    "dependencies",
    "config",
    "discovery",
    "builder",
    "reporter",
    "logger",
    "policy",
    "probes",
    "diagnostics",
    "lifecycle",
    "_router_backend_evidence_cache",
    "_route_observation_cache",
    "operations",
}
PLANNER_INSTANCE_FIELDS = {"config", "discovery", "logger"}
CLEANUP_INSTANCE_FIELDS = {"osc", "reporter", "tracker", "config", "logger"}
EXECUTOR_INSTANCE_FIELDS = {
    "_placement_check_bindings",
    "_placement_workflow_id",
    "config",
    "plan",
    "builder",
    "reporter",
    "logger",
    "cleanup_manager",
    "state_store",
    "checkpoint",
    "groups",
    "active",
    "failed_groups",
    "generations",
    "group_loads",
    "peak_endpoints",
}
REPORTER_INSTANCE_FIELDS = {
    "config",
    "run_id",
    "run_dir",
    "started",
    "_lock",
    "report_path",
    "log_path",
    "manifest_path",
    "active_path",
    "plan_path",
    "results_path",
    "html_report_path",
    "junit_report_path",
    "run_tag",
    "name_prefix",
    "logger",
    "results",
    "results_by_id",
    "events",
    "setup_failures",
    "setup_failed",
    "discovery",
    "plan",
    "resources",
    "_resource_sequence",
    "manifest_errors",
    "cleanup_summary",
    "error",
    "traceback",
    "interrupted",
    "action",
    "finalized",
}


CASES = [
    (
        ResourceBuilder,
        RESOURCE_INSTANCE_FIELDS,
        [
            "neutron_flux/runtime/availability.py",
            "neutron_flux/runtime/compute.py",
            "neutron_flux/runtime/control_plane.py",
            "neutron_flux/runtime/control/controller.py",
            "neutron_flux/runtime/control/keypairs.py",
            "neutron_flux/runtime/control/servers.py",
            "neutron_flux/runtime/control/ssh.py",
            "neutron_flux/runtime/live_migration.py",
            "neutron_flux/runtime/migration.py",
            "neutron_flux/runtime/probes.py",
            "neutron_flux/runtime/router.py",
            "neutron_flux/runtime/security.py",
            "neutron_flux/runtime/topology.py",
        ],
    ),
    (
        FluxTestEngine,
        ENGINE_INSTANCE_FIELDS,
        [
            "neutron_flux/engine_handlers/common.py",
            "neutron_flux/engine_handlers/endpoint.py",
            "neutron_flux/engine_handlers/floating_ip.py",
            "neutron_flux/engine_handlers/floating_ip_peer.py",
            "neutron_flux/engine_handlers/security.py",
            "neutron_flux/engine_handlers/server_router.py",
        ],
    ),
    (
        Planner,
        PLANNER_INSTANCE_FIELDS,
        [
            "neutron_flux/planner_components/estimates.py",
            "neutron_flux/planner_components/groups.py",
            "neutron_flux/planner_components/tests.py",
        ],
    ),
    (
        CleanupManager,
        CLEANUP_INSTANCE_FIELDS,
        [
            "neutron_flux/cleanup_components/deletion.py",
            "neutron_flux/cleanup_components/orphans.py",
            "neutron_flux/cleanup_components/recovery.py",
            "neutron_flux/cleanup_components/verification.py",
        ],
    ),
    (
        AdaptiveExecutor,
        EXECUTOR_INSTANCE_FIELDS,
        ["neutron_flux/execution/placement.py"],
    ),
    (
        Reporter,
        REPORTER_INSTANCE_FIELDS,
        ["neutron_flux/reporting_components/summary.py"],
    ),
]


@pytest.mark.parametrize("facade,instance_fields,modules", CASES)
def test_extracted_mixins_only_use_declared_facade_contract(
    facade, instance_fields, modules
):
    allowed = set(dir(facade)) | set(instance_fields)
    undeclared = {}
    for module in modules:
        missing = sorted(_self_attributes(module) - allowed)
        if missing:
            undeclared[module] = missing

    assert not undeclared, (
        f"{facade.__name__} extracted modules gained undeclared coupling: {undeclared}"
    )
