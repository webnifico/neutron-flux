from __future__ import annotations

import hashlib
import json
import re
import shlex
from collections.abc import Iterable, Mapping
from typing import Any

from .result_contract import normalize_result_record, typed_verdict

REPLAY_PLAN_SCHEMA_VERSION = 1
_TARGET_VERDICTS = {"FAIL", "ERROR", "UNVERIFIED"}
_PLACEMENT_VARIATION_FIELDS = {
    "contract_type",
    "semantic_test",
    "placement",
    "availability_scope",
    "execution_scope",
    "source_availability_zone",
    "destination_availability_zone",
    "host_pair",
}
_PATH_DISCRIMINATORS = {
    "source",
    "destination",
    "source_group",
    "destination_group",
    "measurement",
    "phase",
    "direction",
    "operation",
    "protocol",
    "destination_port",
    "lifecycle_key",
}


def _replay_command(payload: Mapping[str, Any]) -> str | None:
    configuration = payload.get("configuration")
    config = configuration if isinstance(configuration, Mapping) else {}
    networks = config.get("external_networks") or config.get("networks")
    if (
        not all(config.get(key) for key in ("image", "flavor", "storage"))
        or not networks
    ):
        return None
    parts = ["python3", "neutron-flux.py", "run"]
    if str(config.get("access_mode") or "admin").lower() != "admin":
        return None
    for key in ("image", "flavor", "storage"):
        parts.extend(["--" + key, str(config[key])])
    parts.extend(["--external-networks", ",".join(map(str, networks))])
    if config.get("storage") == "volume" and config.get("volume_type"):
        parts.extend(["--volume-type", str(config["volume_type"])])
    qualification = (
        config.get("host_qualification") or config.get("qualification") or {}
    )
    if qualification.get("target_host_pairs"):
        parts.extend(
            [
                "--target-host-pairs",
                ",".join(":".join(pair) for pair in qualification["target_host_pairs"]),
            ]
        )
    elif qualification.get("target_hosts") or qualification.get("target_aggregates"):
        for key in ("target_hosts", "target_aggregates"):
            if qualification.get(key):
                parts.extend(
                    ["--" + key.replace("_", "-"), ",".join(qualification[key])]
                )
    elif config.get("availability_zones_all"):
        parts.extend(["--zones", "all"])
    elif config.get("availability_zones"):
        parts.extend(["--zones", ",".join(config["availability_zones"])])
    migration = config.get("migration") or {}
    mode = "cold" if migration.get("mode") in {"cold", "cold-only"} else "live"
    parts.extend(["--migration-mode", mode])
    if mode == "live":
        parts.extend(["--live-attempts", str(migration.get("live_attempts") or 5)])
    aggregate = migration.get(
        "require_shared_aggregate",
        config.get("require_shared_compute_aggregate", True),
    )
    parts.extend(
        [
            "--shared-aggregate",
            "required"
            if aggregate is True
            else "ignore"
            if aggregate is False
            else "auto",
        ]
    )
    performance = config.get("performance") or {}
    profile = (
        config.get("performance_profile") or performance.get("profile") or "standard"
    )
    parts.extend(["--performance-profile", profile])
    load = (
        config.get("concurrent_vm_pair_load")
        or config.get("concurrent_load")
        or config.get("fabric")
        or {}
    )
    if load.get("enabled") and load.get("pairs"):
        parts.extend(["--concurrent-vm-pairs", ",".join(map(str, load["pairs"]))])
        parts.extend(
            [
                "--concurrent-repeats",
                str(load.get("runs") or 2),
                "--concurrent-duration",
                str(load.get("duration_seconds") or 15),
            ]
        )
    for family in (4, 6):
        targets = config.get(f"ipv{family}_targets")
        if targets:
            parts.extend([f"--ping-target-ipv{family}", str(targets[0])])
    return shlex.join(parts)


class RerunResolver:
    """Build full-suite rerun guidance from the recorded launch scope."""

    def __init__(self, payload: Mapping[str, Any]) -> None:
        self.payload = payload

    def for_result(self, item: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "result_id": str(item.get("test_id") or item.get("result_id") or ""),
            "kind": "full-suite",
            "selectable_test_id": None,
            "exact_fragment": None,
            "parent_fragment": None,
            "phase_fragment": None,
            "command": _replay_command(self.payload),
            "guidance": "Rerun the complete suite with the recorded supported scope. Individual test selection is no longer exposed. Historical custom settings may require an older release to reproduce exactly.",
        }


def _stable_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _normalized_results(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        normalize_result_record(item)
        for item in payload.get("results") or []
        if isinstance(item, Mapping)
    ]


def _controller_setup_zone(item: Mapping[str, Any]) -> str | None:
    details = item.get("details") or {}
    for key in (
        "availability_zone",
        "source_availability_zone",
        "destination_availability_zone",
    ):
        value = str(details.get(key) or "").strip()
        if value:
            return value
    context = _path_context(item)
    for key in ("source_availability_zone", "destination_availability_zone"):
        value = str(context.get(key) or "").strip()
        if value:
            return value
    execution_scope = str(
        context.get("execution_scope") or details.get("execution_scope") or ""
    ).strip()
    if execution_scope.startswith("az-") and len(execution_scope) > 3:
        return execution_scope[3:]
    match = re.match(
        r"^AZ-(.+?)-CONTROL-(?:SSH|OBSERVATION-PORTS|SETUP|ERROR)(?:-|$)",
        str(item.get("test_id") or ""),
        re.IGNORECASE,
    )
    return match.group(1).lower() if match else None


def _is_controller_setup_result(item: Mapping[str, Any]) -> bool:
    details = item.get("details") or {}
    test_id = str(item.get("test_id") or "").upper()
    scenario = str(item.get("scenario") or "").lower()
    category = str(item.get("category") or "").lower()
    phase = str(details.get("failure_phase") or "").lower()
    return bool(
        details.get("root_setup_error")
        or details.get("root_lane_error")
        or phase in {"controller-bootstrap", "availability-zone-bootstrap"}
        or "controller readiness" in scenario
        or category in {"control", "controller-bootstrap"}
        or "-CONTROL-SSH" in test_id
        or "-CONTROL-OBSERVATION-PORTS" in test_id
    )


def _controller_probe_kind(item: Mapping[str, Any]) -> str:
    test_id = str(item.get("test_id") or "").upper()
    if "CONTROL-SSH" in test_id:
        return "ssh"
    if "CONTROL-OBSERVATION-PORTS" in test_id:
        return "observation-ports"
    return "controller-setup"


def _legacy_setup_targets(
    results: list[dict[str, Any]],
    primary_targets: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Collapse old run-wide blocked output into one bootstrap target per failed AZ."""

    explicit_zones = {
        zone
        for item in primary_targets
        if _is_controller_setup_result(item)
        for zone in [_controller_setup_zone(item)]
        if zone
    }
    healthy_zones = {
        zone
        for item in results
        if _healthy(item) and _is_controller_setup_result(item)
        for zone in [_controller_setup_zone(item)]
        if zone
    }
    candidates: dict[str, list[dict[str, Any]]] = {}
    for item in results:
        if typed_verdict(item) != "BLOCKED" or not _is_controller_setup_result(item):
            continue
        status = str(item.get("status") or "").upper()
        if status != "BLOCKED_BY_SETUP_ERROR":
            continue
        zone = _controller_setup_zone(item)
        if not zone or zone in explicit_zones or zone in healthy_zones:
            continue
        candidates.setdefault(zone, []).append(item)

    selected: list[dict[str, Any]] = []
    for _zone, rows in sorted(candidates.items()):
        rows.sort(
            key=lambda item: (
                0 if _controller_probe_kind(item) == "ssh" else 1,
                str(item.get("test_id") or ""),
            )
        )
        selected.append(rows[0])
    return selected


def _path_context(item: Mapping[str, Any]) -> dict[str, Any]:
    signature = item.get("path_signature") or {}
    context = signature.get("context") or {}
    placement = context.get("placement") or {}
    return {
        "path_key": signature.get("key"),
        "display": signature.get("display"),
        "placement": placement.get("class"),
        "availability_scope": placement.get("availability_scope"),
        "source_host": placement.get("source_host"),
        "destination_host": placement.get("destination_host"),
        "source_availability_zone": placement.get("source_availability_zone"),
        "destination_availability_zone": placement.get("destination_availability_zone"),
        "execution_scope": placement.get("execution_scope"),
    }


def _selection_row(item: Mapping[str, Any], *, role: str) -> dict[str, Any]:
    contract = item.get("contract") or {}
    expectation = contract.get("expectation") or {}
    observation = contract.get("observation") or {}
    setup_target = _is_controller_setup_result(item)
    return {
        "role": role,
        "result_id": item.get("test_id"),
        "display_name": item.get("display_name") or item.get("test_id"),
        "category": item.get("category"),
        "scenario": item.get("scenario"),
        "family": item.get("family"),
        "verdict": typed_verdict(item),
        "contract_type": (
            "controller-bootstrap" if setup_target else contract.get("type")
        ),
        "expectation": expectation.get("code"),
        "observation": observation.get("code"),
        "authority": (
            "neutron-flux-execution-ledger"
            if setup_target and typed_verdict(item) != "PASS"
            else (contract.get("authority") or {}).get("classification")
        ),
        "path": _path_context(item),
        "path_signature": item.get("path_signature") or {},
    }


def _stable_path_identity(item: Mapping[str, Any]) -> dict[str, Any] | None:
    signature = item.get("path_signature") or {}
    identity = dict(signature.get("identity") or {})
    for field in _PLACEMENT_VARIATION_FIELDS:
        identity.pop(field, None)
    has_path_discriminator = any(
        identity.get(field) not in (None, "", [], {}) for field in _PATH_DISCRIMINATORS
    )
    return identity if has_path_discriminator else None


def _same_contract(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    left_contract = left.get("contract") or {}
    right_contract = right.get("contract") or {}
    left_expectation = left_contract.get("expectation") or {}
    right_expectation = right_contract.get("expectation") or {}
    left_authority = left_contract.get("authority") or {}
    right_authority = right_contract.get("authority") or {}
    left_path = _stable_path_identity(left)
    right_path = _stable_path_identity(right)
    return (
        left_contract.get("type") == right_contract.get("type")
        and left_expectation.get("code") == right_expectation.get("code")
        and left_authority.get("classification")
        == right_authority.get("classification")
        and left_authority.get("authoritative") == right_authority.get("authoritative")
        and left.get("family") == right.get("family")
        and left_path is not None
        and left_path == right_path
    )


def _healthy(item: Mapping[str, Any]) -> bool:
    health = str((item.get("details") or {}).get("health") or "good").lower()
    authority = ((item.get("contract") or {}).get("authority") or {}).get(
        "authoritative"
    )
    return (
        typed_verdict(item) == "PASS"
        and authority is True
        and health not in {"warning", "critical"}
    )


def _non_assertive_observation(item: Mapping[str, Any]) -> bool:
    contract = item.get("contract") or {}
    expectation = contract.get("expectation") or {}
    authority = contract.get("authority") or {}
    return bool(
        expectation.get("code") == "observation"
        and authority.get("authoritative") is False
    )


def _derivative_unverified(item: Mapping[str, Any]) -> bool:
    """Exclude dependent rows whose prerequisite already owns the replay case."""

    if typed_verdict(item) != "UNVERIFIED":
        return False
    details = item.get("details") or {}
    probe = details.get("probe") or {}
    message = str(item.get("message") or "").lower()
    if (
        str(item.get("observed") or "") == "functional-baseline-unavailable"
        and details.get("lifecycle_cloud_operation_performed") is False
        and details.get("failed_baseline_tests")
    ):
        return True
    return bool(
        isinstance(probe, Mapping)
        and (probe.get("diagnostics") or {}).get("cloud_operation_performed") is False
        and (
            "baseline" in message
            or "before detachment" in message
            or "restoration was not attempted" in message
        )
    )


def _current_interpretation_pass(item: Mapping[str, Any]) -> bool:
    offline = (item.get("details") or {}).get("offline_interpretation") or {}
    return bool(
        isinstance(offline, Mapping)
        and str(offline.get("interpretation_status") or "") == "PASS"
    )


def _target_group_key(item: Mapping[str, Any]) -> tuple[Any, ...]:
    """Collapse repeated symptoms while retaining distinct contract classes."""

    if _is_controller_setup_result(item):
        return ("controller-bootstrap", _controller_setup_zone(item) or "unknown")
    contract = item.get("contract") or {}
    expectation = contract.get("expectation") or {}
    observation = contract.get("observation") or {}
    details = item.get("details") or {}
    return (
        str(contract.get("type") or item.get("category") or "unknown"),
        item.get("family"),
        str(expectation.get("code") or item.get("expected") or ""),
        str(observation.get("code") or item.get("observed") or ""),
        str(details.get("measurement") or ""),
        str(details.get("egress_translation_mode") or ""),
        str(details.get("fip_observer_mode") or details.get("observer_mode") or ""),
    )


def _control_score(
    target: Mapping[str, Any], candidate: Mapping[str, Any]
) -> tuple[int, ...]:
    target_context = _path_context(target)
    candidate_context = _path_context(candidate)
    return (
        int(candidate.get("category") == target.get("category")),
        int(candidate.get("scenario") == target.get("scenario")),
        int(candidate_context.get("placement") == target_context.get("placement")),
        int(
            candidate_context.get("source_availability_zone")
            == target_context.get("source_availability_zone")
        ),
        int(
            candidate_context.get("destination_availability_zone")
            == target_context.get("destination_availability_zone")
        ),
    )


def _choose_control(
    target: Mapping[str, Any],
    results: Iterable[Mapping[str, Any]],
) -> Mapping[str, Any] | None:
    if _is_controller_setup_result(target):
        target_zone = _controller_setup_zone(target)
        target_kind = _controller_probe_kind(target)
        setup_candidates = [
            item
            for item in results
            if item.get("test_id") != target.get("test_id")
            and _healthy(item)
            and _is_controller_setup_result(item)
            and _controller_probe_kind(item) == target_kind
            and _controller_setup_zone(item) != target_zone
        ]
        if setup_candidates:
            return max(
                setup_candidates,
                key=lambda item: (
                    int(item.get("family") == target.get("family")),
                    str(item.get("test_id") or ""),
                ),
            )
    candidates = [
        item
        for item in results
        if item.get("test_id") != target.get("test_id")
        and _same_contract(target, item)
        and _healthy(item)
    ]
    if not candidates:
        return None
    return max(
        candidates,
        key=lambda item: (_control_score(target, item), str(item.get("test_id") or "")),
    )


def _variation_kind(
    target: Mapping[str, Any], candidate: Mapping[str, Any]
) -> str | None:
    target_context = _path_context(target)
    candidate_context = _path_context(candidate)
    target_zones = (
        target_context.get("source_availability_zone"),
        target_context.get("destination_availability_zone"),
    )
    candidate_zones = (
        candidate_context.get("source_availability_zone"),
        candidate_context.get("destination_availability_zone"),
    )
    if candidate_zones != target_zones and any(candidate_zones):
        return "availability-zone-variation"
    target_hosts = (
        target_context.get("source_host"),
        target_context.get("destination_host"),
    )
    candidate_hosts = (
        candidate_context.get("source_host"),
        candidate_context.get("destination_host"),
    )
    if candidate_hosts != target_hosts and any(candidate_hosts):
        return "host-variation"
    if candidate_context.get("placement") != target_context.get("placement"):
        return "host-variation"
    return None


def _choose_variations(
    target: Mapping[str, Any],
    results: Iterable[Mapping[str, Any]],
    *,
    excluded_result_ids: set[str] | None = None,
) -> list[tuple[str, Mapping[str, Any]]]:
    selected: dict[str, Mapping[str, Any]] = {}
    excluded = excluded_result_ids or set()
    for item in sorted(results, key=lambda row: str(row.get("test_id") or "")):
        result_id = str(item.get("test_id") or "")
        if (
            result_id in excluded
            or item.get("test_id") == target.get("test_id")
            or not _same_contract(target, item)
        ):
            continue
        kind = _variation_kind(target, item)
        if kind is None or kind in selected:
            continue
        selected[kind] = item
        if len(selected) == 2:
            break
    return [(kind, selected[kind]) for kind in sorted(selected)]


def _execution_context(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Keep only the inputs needed to understand or recreate the selected paths."""

    configuration = payload.get("configuration")
    if not isinstance(configuration, Mapping):
        return {}
    selected = {
        "image": configuration.get("image"),
        "flavor": configuration.get("flavor"),
        "storage": configuration.get("storage"),
        "quiet_period_scale": configuration.get("quiet_period_scale"),
        "operation_gap_scale": configuration.get("operation_gap_scale"),
        "volume_size": configuration.get("volume_size"),
        "volume_type": configuration.get("volume_type"),
        "availability_zones": configuration.get("availability_zones"),
        "availability_zones_all": configuration.get("availability_zones_all"),
        "zone_mode": configuration.get("zone_mode"),
        "allow_cross_az_volumes": configuration.get("allow_cross_az_volumes"),
        "allow_cross_az_networking": configuration.get("allow_cross_az_networking"),
        "network_az": configuration.get("network_az"),
        "router_az": configuration.get("router_az"),
        "external_networks": configuration.get("external_networks"),
        "host_qualification": configuration.get("host_qualification"),
        "performance_enabled": configuration.get("performance_enabled"),
        "concurrent_vm_pair_load": configuration.get("concurrent_vm_pair_load"),
        "migration": configuration.get("migration"),
        "network_paths": configuration.get("network_paths"),
    }
    return {
        key: value for key, value in selected.items() if value not in (None, "", [], {})
    }


def build_replay_plan(payload: Mapping[str, Any]) -> dict[str, Any]:
    results = _normalized_results(payload)
    primary_targets = [
        item
        for item in results
        if typed_verdict(item) in _TARGET_VERDICTS
        and not _non_assertive_observation(item)
        and not _derivative_unverified(item)
        and not _current_interpretation_pass(item)
    ]
    expanded_targets = [
        *primary_targets,
        *_legacy_setup_targets(results, primary_targets),
    ]
    severity = {"ERROR": 0, "FAIL": 1, "BLOCKED": 2, "UNVERIFIED": 3}
    expanded_targets.sort(
        key=lambda item: (
            severity.get(typed_verdict(item), 9),
            str((item.get("contract") or {}).get("type") or ""),
            str(item.get("test_id") or ""),
        )
    )
    grouped_targets: dict[tuple[Any, ...], dict[str, Any]] = {}
    for item in expanded_targets:
        grouped_targets.setdefault(_target_group_key(item), item)
    targets = list(grouped_targets.values())

    selections: dict[str, dict[str, Any]] = {}
    cases: list[dict[str, Any]] = []
    reruns = RerunResolver(payload)
    for target in targets:
        target_id = str(target.get("test_id") or "unknown-result")
        setup_target = _is_controller_setup_result(target)
        rerun = reruns.for_result(target)
        selections[target_id] = _selection_row(target, role="target")
        control = _choose_control(target, results)
        control_id: str | None = None
        if control is not None:
            control_id = str(control.get("test_id") or "")
            selections.setdefault(
                control_id, _selection_row(control, role="healthy-control")
            )
        variation_ids: list[str] = []
        for role, variation in _choose_variations(
            target,
            results,
            excluded_result_ids={control_id} if control_id else set(),
        ):
            variation_id = str(variation.get("test_id") or "")
            if not variation_id:
                continue
            selection = _selection_row(variation, role=role)
            prior = selections.get(variation_id)
            if prior is None or prior.get("role") not in {"target", "healthy-control"}:
                selections[variation_id] = selection
            variation_ids.append(variation_id)
        cases.append(
            {
                "target_result_id": target_id,
                "healthy_control_result_id": control_id,
                "variation_result_ids": variation_ids,
                "contract_type": (
                    "controller-bootstrap"
                    if setup_target
                    else (target.get("contract") or {}).get("type")
                ),
                "family": target.get("family"),
                "path_key": (target.get("path_signature") or {}).get("key"),
                "replay_kind": (
                    "controller-bootstrap" if setup_target else "contract-validation"
                ),
                "rerun": rerun,
                "executable_selector": (
                    rerun.get("exact_fragment")
                    or rerun.get("parent_fragment")
                    or rerun.get("phase_fragment")
                ),
                "command": rerun.get("command"),
            }
        )

    commands: list[dict[str, Any]] = []
    command_ids: dict[str, str] = {}
    for case in cases:
        command = case.get("command")
        if not command:
            continue
        if command not in command_ids:
            command_ids[command] = f"suite-rerun-{len(commands) + 1}"
            commands.append(
                {
                    "id": command_ids[command],
                    "command": command,
                    "scope": "full-suite",
                    "case_ids": [],
                }
            )
        case["command_id"] = command_ids[command]
        commands[
            next(
                i
                for i, item in enumerate(commands)
                if item["id"] == command_ids[command]
            )
        ]["case_ids"].append(case["target_result_id"])
    executable_case_count = sum(1 for case in cases if case.get("command"))
    replay_status = (
        "no-replay-required"
        if not cases
        else "ready"
        if executable_case_count == len(cases)
        else "selectors-incomplete"
    )
    run = payload.get("run") or {}
    core: dict[str, Any] = {
        "schema_version": REPLAY_PLAN_SCHEMA_VERSION,
        "kind": "neutron-flux-replay-plan",
        "immutable": True,
        "source_run": {
            "run_id": run.get("run_id"),
            "finished_at": run.get("finished_at"),
            "final_status": run.get("final_status"),
        },
        "status": replay_status,
        "executable_case_count": executable_case_count,
        "case_count": len(cases),
        "command_count": len(commands),
        "commands": commands,
        "execution_context": _execution_context(payload),
        "selection_policy": {
            "targets": [
                *sorted(_TARGET_VERDICTS),
                "one legacy setup-blocked controller target per failed AZ when no explicit setup ERROR exists",
            ],
            "healthy_controls_per_target": 1,
            "host_variations_per_target": 1,
            "availability_zone_variations_per_target": 1,
            "scope": (
                "project-visible OpenStack network contracts and the smallest "
                "controller-bootstrap blockers needed to reach them"
            ),
            "execution_model": (
                "Use the normal approved Neutron Flux plan and safety controls; "
                "this artifact selects the smallest useful evidence set and does "
                "not authorize a new cloud operation path."
            ),
            "excluded": [
                "non-authoritative observation-only paths",
                "dependent unverified lifecycle rows whose baseline already owns the replay",
                "duplicate symptoms sharing the same contract, family, observation, and measurement class",
                "underlay inspection",
                "OVS or OVN internal inspection",
                "automatic root-cause attribution",
                "host agents",
            ],
        },
        "cases": cases,
        "selections": [selections[key] for key in sorted(selections)],
        "collapsed_target_count": max(0, len(expanded_targets) - len(targets)),
    }
    fingerprint = hashlib.sha256(_stable_json(core).encode("utf-8")).hexdigest()
    core["fingerprint"] = f"sha256:{fingerprint}"
    return core


def render_replay_plan_text(plan: Mapping[str, Any]) -> str:
    source = plan.get("source_run") or {}
    lines = [
        "NEUTRON FLUX FAILURE REVIEW AND SUITE RERUN",
        "=" * 100,
        f"Source run: {source.get('run_id') or 'unknown'}",
        f"Source status: {source.get('final_status') or 'unknown'}",
        f"Plan status: {plan.get('status') or 'unknown'}",
        f"Fingerprint: {plan.get('fingerprint') or 'unknown'}",
        "",
    ]
    cases = plan.get("cases") or []
    if not cases:
        lines.append("No failed, erroneous, or unverified contract requires replay.")
        return "\n".join(lines) + "\n"
    for command in plan.get("commands") or []:
        lines.extend(
            [
                f"SUITE RERUN {command['id']} (full recorded scope; not an individual test)",
                command["command"],
                "",
            ]
        )
    for index, case in enumerate(cases, start=1):
        family = case.get("family")
        family_label = (
            f"IPv{family}" if family in {4, 6, "4", "6"} else "IP family not specified"
        )
        contract_label = (
            f"Setup target: controller bootstrap / {family_label}"
            if case.get("replay_kind") == "controller-bootstrap"
            else f"Contract: {case.get('contract_type')} / {family_label}"
        )
        lines.extend(
            [
                f"CASE {index}: {case.get('target_result_id')}",
                f"  {contract_label}",
                f"  Path key: {case.get('path_key')}",
                f"  Healthy control: {case.get('healthy_control_result_id') or 'unavailable'}",
                "  Host/AZ variations: "
                + (", ".join(case.get("variation_result_ids") or []) or "unavailable"),
            ]
        )
        rerun = case.get("rerun") or {}
        if rerun.get("exact_fragment"):
            lines.append(f"  Exact selection fragment: {rerun['exact_fragment']}")
        elif rerun.get("parent_fragment"):
            lines.append(f"  Selectable parent fragment: {rerun['parent_fragment']}")
        elif rerun.get("phase_fragment"):
            lines.append(f"  Phase selection fragment: {rerun['phase_fragment']}")
        if case.get("command_id"):
            lines.append(f"  Suite command: {case['command_id']}")
        elif rerun.get("command"):
            lines.append(f"  Full-suite command: {rerun['command']}")
        lines.append(f"  Rerun note: {rerun.get('guidance') or 'Unavailable'}")
        lines.append("")
    return "\n".join(lines) + "\n"


__all__ = [
    "REPLAY_PLAN_SCHEMA_VERSION",
    "build_replay_plan",
    "render_replay_plan_text",
]
