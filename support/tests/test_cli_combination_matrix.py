"""Exhaust finite CLI interactions and verify the real dispatch boundaries."""

from __future__ import annotations

import itertools
import json
from unittest import mock

import pytest

from neutron_flux import cli
from neutron_flux.config import Config
from neutron_flux.configuration.snapshots import execution_settings
from neutron_flux.errors import SuiteError
from neutron_flux.models import RunCheckpoint
from neutron_flux.plan_contract import create_plan_contract
from neutron_flux.planning import Planner
from neutron_flux.state import StateStore
from neutron_flux.utils import iso_utc

BASE = [
    "--image",
    "debian-13",
    "--flavor",
    "small",
    "--external-networks",
    "Public1,Public2",
]
SCOPES = (
    ("automatic", [], [], False, False),
    ("single-zone", ["--zones", "az1"], ["az1"], False, False),
    ("multiple-zones", ["--zones", "az1,az2"], ["az1", "az2"], False, False),
    ("all-zones", ["--zones", "all"], [], True, False),
    ("single-host", ["--target-hosts", "a"], [], False, True),
    ("multiple-hosts", ["--target-hosts", "a,b"], [], False, True),
    ("aggregate", ["--target-aggregates", "edge"], [], False, True),
    (
        "host-and-aggregate",
        ["--target-hosts", "a", "--target-aggregates", "edge"],
        [],
        False,
        True,
    ),
    ("same-host-pair", ["--target-host-pairs", "a:a"], [], False, True),
    ("different-host-pair", ["--target-host-pairs", "a:b"], [], False, True),
)
CONCURRENCY = (
    ([], False, [1, 2, 4], 2, 15),
    (["--concurrent-vm-pairs", "1"], True, [1], 2, 15),
    (
        [
            "--concurrent-vm-pairs",
            "1,2,4",
            "--concurrent-repeats",
            "1",
            "--concurrent-duration",
            "3",
        ],
        True,
        [1, 2, 4],
        1,
        3,
    ),
    (
        [
            "--concurrent-vm-pairs",
            "32",
            "--concurrent-repeats",
            "10",
            "--concurrent-duration",
            "120",
        ],
        True,
        [32],
        10,
        120,
    ),
)
TARGETS = (
    ([], "1.1.1.1", "2606:4700:4700::1111", False, False),
    (
        ["--ping-target-ipv4", "203.0.113.9"],
        "203.0.113.9",
        "2606:4700:4700::1111",
        True,
        False,
    ),
    (["--ping-target-ipv6", "2001:db8::9"], "1.1.1.1", "2001:db8::9", False, True),
    (
        ["--ping-target-ipv4", "203.0.113.9", "--ping-target-ipv6", "2001:db8::9"],
        "203.0.113.9",
        "2001:db8::9",
        True,
        True,
    ),
)


def configured(argv, parser=None):
    args = (parser or cli.parser()).parse_args(argv)
    cli._validate_action_arguments(args)
    return Config.from_args(args)


def test_all_finite_legal_execution_combinations():
    """34,560 configs; numeric/string domains use documented boundary classes."""
    parser = cli.parser()
    cases = 0
    for (
        action_keep,
        storage_type,
        scope,
        migration,
        aggregate,
        profile,
        repeat,
        load,
        targets,
    ) in itertools.product(
        (("plan", False), ("run", False), ("run", True)),
        (("host", None), ("volume", None), ("volume", "fast")),
        SCOPES,
        ("live", "cold"),
        ("auto", "required", "ignore"),
        ("standard", "exhaustive"),
        (1, 3),
        CONCURRENCY,
        TARGETS,
    ):
        action, keep = action_keep
        storage, volume_type = storage_type
        _scope_name, scope_flags, zones, all_zones, targeted = scope
        load_flags, load_enabled, pairs, measurements, duration = load
        target_flags, ipv4, ipv6, configured4, configured6 = targets
        argv = [
            action,
            *BASE,
            "--storage",
            storage,
            *scope_flags,
            "--migration-mode",
            migration,
            "--shared-aggregate",
            aggregate,
            "--performance-profile",
            profile,
            "--repeat",
            str(repeat),
            *load_flags,
            *target_flags,
        ]
        if volume_type:
            argv += ["--volume-type", volume_type]
        if keep:
            argv += ["--keep-resources"]
        config = configured(argv, parser)
        assert config.action == action, argv
        assert (config.storage, config.volume_type) == storage_type, argv
        assert config.effective_migration_storage == (
            "host" if storage == "host" else "shared"
        ), argv
        assert config.availability_zones == zones, argv
        assert config.availability_zones_all == all_zones, argv
        assert config.zone_mode == (
            "both" if all_zones or len(zones) > 1 else "per-zone"
        ), argv
        assert config.host_qualification_enabled == targeted, argv
        assert config.migration_mode == (
            "live-preferred" if migration == "live" else "cold-only"
        ), argv
        assert config.cold_migration_fallback == (migration == "live"), argv
        assert config.live_migration_continuity == (migration == "live"), argv
        assert (
            config.require_shared_compute_aggregate
            == {"auto": None, "required": True, "ignore": False}[aggregate]
        ), argv
        assert config.performance_profile == profile, argv
        assert config.performance_repeats == (3 if profile == "exhaustive" else 2), argv
        assert config.performance_enabled and config.performance_max_paths == 0, argv
        assert config.repeat_count == repeat, argv
        assert (
            config.fabric_scale_enabled,
            config.fabric_scale_pairs,
            config.fabric_scale_runs,
            config.fabric_scale_duration_seconds,
        ) == (load_enabled, pairs, measurements, duration), argv
        assert (config.ipv4_targets, config.ipv6_targets) == ([ipv4], [ipv6]), argv
        assert (config.ipv4_targets_configured, config.ipv6_targets_configured) == (
            configured4,
            configured6,
        ), argv
        assert config.keep_resources == keep and config.auto_cleanup_on_failure == (
            not keep
        ), argv
        assert config.junit_report_enabled and config.evidence_enabled, argv
        cases += 1
    assert cases == 34560


def test_all_compute_selector_conflicts():
    """32 selector-presence combinations, including each zone spelling."""
    cases = 0
    for zone, hosts, aggregates, pairs in itertools.product(
        (None, "az1", "az1,az2", "all"),
        (None, "a,b"),
        (None, "edge"),
        (None, "a:b"),
    ):
        flags = []
        for name, value in (
            ("zones", zone),
            ("target-hosts", hosts),
            ("target-aggregates", aggregates),
            ("target-host-pairs", pairs),
        ):
            if value:
                flags += ["--" + name, value]
        argv = ["run", *BASE, "--storage", "host", *flags]
        invalid = bool(
            (pairs and (hosts or aggregates))
            or (zone and (hosts or aggregates or pairs))
        )
        if invalid:
            with pytest.raises(SuiteError):
                configured(argv)
        else:
            config = configured(argv)
            assert config.host_qualification_enabled == bool(
                hosts or aggregates or pairs
            )
        cases += 1
    assert cases == 32


def test_every_required_launch_input_presence_combination():
    inputs = (
        ("image", "debian-13"),
        ("flavor", "small"),
        ("storage", "host"),
        ("external-networks", "Public1"),
    )
    for action, present in itertools.product(
        ("plan", "run"), itertools.product((False, True), repeat=4)
    ):
        argv = [action]
        for enabled, (flag, value) in zip(present, inputs, strict=True):
            if enabled:
                argv += ["--" + flag, value]
        if all(present):
            assert configured(argv).action == action
        else:
            with pytest.raises(SuiteError, match="Required:") as exc:
                configured(argv)
            for enabled, (flag, _value) in zip(present, inputs, strict=True):
                assert ("--" + flag in str(exc.value)) == (not enabled)


@pytest.mark.parametrize(
    "flag,boundaries",
    [
        ("--concurrent-repeats", (0, 1, 10, 11)),
        ("--concurrent-duration", (2, 3, 120, 121)),
    ],
)
def test_concurrent_tuning_boundaries_require_enabled_pairs(flag, boundaries):
    for enabled, value in itertools.product((False, True), boundaries):
        argv = ["run", *BASE, "--storage", "host", flag, str(value)]
        if enabled:
            argv += ["--concurrent-vm-pairs", "1"]
        legal = enabled and value in boundaries[1:3]
        if legal:
            config = configured(argv)
            assert config.fabric_scale_enabled
            assert (
                config.fabric_scale_runs
                if flag == "--concurrent-repeats"
                else config.fabric_scale_duration_seconds
            ) == value
        else:
            with pytest.raises(SuiteError):
                configured(argv)


def test_every_documented_concurrent_pair_count():
    argv = ["run", *BASE, "--storage", "host", "--concurrent-vm-pairs"]
    for count in range(1, 33):
        config = configured([*argv, str(count)])
        assert config.fabric_scale_enabled and config.fabric_scale_pairs == [count]
    config = configured(
        [*argv, ",".join(str(count) for count in range(1, 33)) + ",1,32"]
    )
    assert config.fabric_scale_pairs == list(range(1, 33))


def test_every_bounded_concurrent_numeric_combination():
    parser = cli.parser()
    cases = 0
    for pairs, repeats, duration in itertools.product(
        range(1, 33), range(1, 11), range(3, 121)
    ):
        config = configured(
            [
                "run",
                *BASE,
                "--storage",
                "host",
                "--concurrent-vm-pairs",
                str(pairs),
                "--concurrent-repeats",
                str(repeats),
                "--concurrent-duration",
                str(duration),
            ],
            parser,
        )
        assert config.fabric_scale_pairs == [pairs]
        assert config.fabric_scale_runs == repeats
        assert config.fabric_scale_duration_seconds == duration
        cases += 1
    assert cases == 37760


@pytest.mark.parametrize("value", ["0", "33", "-1", "1.5", "one", "1,,2", "1,", "+1"])
def test_invalid_concurrent_counts(value):
    with pytest.raises(SuiteError):
        configured(["run", *BASE, "--storage", "host", "--concurrent-vm-pairs", value])


def test_resume_rejects_every_workload_override_before_state_access(monkeypatch):
    parser = cli.parser()
    monkeypatch.setattr(
        cli,
        "StateStore",
        mock.Mock(side_effect=AssertionError("invalid resume opened state")),
    )
    for option in parser._actions:
        if option.dest not in cli._EXECUTION_OPTIONS - {"resume", "keep_resources"}:
            continue
        value = (
            "1"
            if option.type is int
            else option.choices[0]
            if option.choices
            else "test-value"
        )
        assert (
            cli.main(["run", "--resume", "run-id", option.option_strings[0], value])
            == 2
        )


def test_every_execution_control_is_gated_for_every_command():
    samples = {
        "image": "debian-13",
        "flavor": "small",
        "storage": "host",
        "volume_type": "fast",
        "external_networks": "Public1",
        "zones": "az1",
        "target_hosts": "a",
        "target_aggregates": "edge",
        "target_host_pairs": "a:b",
        "repeat": "2",
        "migration_mode": "cold",
        "live_attempts": "7",
        "shared_aggregate": "required",
        "performance_profile": "exhaustive",
        "concurrent_vm_pairs": "1,2",
        "concurrent_repeats": "3",
        "concurrent_duration": "20",
        "ping_target_ipv4": "203.0.113.9",
        "ping_target_ipv6": "2001:db8::9",
        "resume": "run-id",
        "keep_resources": None,
        "dry_run": None,
        "yes": None,
    }
    for action, (name, value) in itertools.product(cli._ACTIONS, samples.items()):
        argv = [action, "--" + name.replace("_", "-")]
        if value is not None:
            argv += [value]
        args = cli.parser().parse_args(argv)
        allowed = (
            (
                action in {"plan", "run"}
                and name not in {"resume", "keep_resources", "dry_run", "yes"}
            )
            or (action == "run" and name in {"resume", "keep_resources"})
            or (action == "cleanup" and name in {"dry_run", "yes"})
        )
        if allowed:
            cli._validate_action_arguments(args)
        else:
            with pytest.raises(SuiteError, match="does not use"):
                cli._validate_action_arguments(args)


@pytest.mark.parametrize(
    "flag,value",
    [
        ("--ping-target-ipv4", "0.0.0.0"),
        ("--ping-target-ipv4", "224.0.0.1"),
        ("--ping-target-ipv4", "127.0.0.1"),
        ("--ping-target-ipv4", "169.254.0.1"),
        ("--ping-target-ipv4", "2001:db8::1"),
        ("--ping-target-ipv4", "255.255.255.255"),
        ("--ping-target-ipv6", "::"),
        ("--ping-target-ipv6", "ff02::1"),
        ("--ping-target-ipv6", "::1"),
        ("--ping-target-ipv6", "fe80::1"),
        ("--ping-target-ipv6", "1.1.1.1"),
        ("--ping-target-ipv6", "2606:4700:4700::1111%eth0"),
        ("--ping-target-ipv6", "::ffff:1.1.1.1"),
        ("--ping-target-ipv6", "::ffff:224.0.0.1"),
    ],
)
def test_invalid_external_address_never_reaches_cloud_dispatch(
    flag, value, monkeypatch, capsys
):
    dispatch = mock.Mock()
    monkeypatch.setattr(cli, "_execute_locked_action", dispatch)
    monkeypatch.setattr(
        cli,
        "StateStore",
        mock.Mock(side_effect=AssertionError("state must not be opened")),
    )
    assert cli.main(["run", *BASE, "--storage", "host", flag, value]) == 2
    assert "usable unicast" in capsys.readouterr().err
    dispatch.assert_not_called()


def test_oversized_concurrency_number_is_a_configuration_error(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "StateStore",
        mock.Mock(side_effect=AssertionError("state must not be opened")),
    )
    assert (
        cli.main(
            ["run", *BASE, "--storage", "host", "--concurrent-vm-pairs", "9" * 5000]
        )
        == 2
    )
    assert "between 1 and 32" in capsys.readouterr().err


@pytest.mark.parametrize(
    "command,inputs,handler",
    [
        ("report", ["results.json"], "regenerate"),
        ("compare", ["baseline.json", "candidate.json"], "compare_files"),
        ("trend", ["first.json", "second.json", "reports"], "trend_files"),
    ],
)
def test_offline_inputs_accept_output_option_at_every_position(
    command, inputs, handler, tmp_path, monkeypatch
):
    dispatch = mock.Mock(return_value={"report": tmp_path / "written"})
    monkeypatch.setattr(cli, handler, dispatch)
    monkeypatch.setattr(
        cli,
        "StateStore",
        mock.Mock(side_effect=AssertionError("offline command opened cloud state")),
    )
    for index in range(len(inputs) + 1):
        argv = [
            command,
            *inputs[:index],
            "--output-dir",
            str(tmp_path),
            *inputs[index:],
        ]
        assert cli.main(argv) == 0
        call = dispatch.call_args
        assert call.kwargs["destination"] == str(tmp_path)
        if command == "trend":
            assert call.args == (inputs,)
        else:
            assert call.args == tuple(inputs)
    assert dispatch.call_count == len(inputs) + 1


@pytest.mark.parametrize(
    "storage,type_name,migration,profile",
    [
        (storage, type_name, migration, profile)
        for (storage, type_name), migration, profile in itertools.product(
            (("host", None), ("volume", None), ("volume", "fast")),
            ("live", "cold"),
            ("standard", "exhaustive"),
        )
    ],
)
def test_configuration_survives_real_signed_plan_resume(
    storage, type_name, migration, profile, discovery_fixture, tmp_path
):
    argv = [
        "run",
        *BASE,
        "--storage",
        storage,
        "--migration-mode",
        migration,
        "--performance-profile",
        profile,
        "--repeat",
        "3",
        "--zones",
        "az1,az2",
        "--shared-aggregate",
        "ignore",
        "--live-attempts",
        "17",
        "--concurrent-vm-pairs",
        "1,4,32",
        "--concurrent-repeats",
        "10",
        "--concurrent-duration",
        "120",
        "--ping-target-ipv4",
        "203.0.113.9",
        "--ping-target-ipv6",
        "2001:db8::9",
    ]
    if migration == "cold":
        index = argv.index("--live-attempts")
        del argv[index : index + 2]
    if type_name:
        argv += ["--volume-type", type_name]
    source = configured(argv)
    plan = Planner(source, discovery_fixture, mock.Mock()).build()
    contract = create_plan_contract(source, discovery_fixture, plan)
    path = tmp_path / "signed-plan.json"
    path.write_text(json.dumps(contract))
    target = configured(
        [
            "run",
            "--resume",
            "run-id",
            "--output-dir",
            str(tmp_path / "resumed"),
            "--keep-resources",
        ]
    )
    target.repeat_index = 2
    target.repeat_root_id = "root-id"
    cli._hydrate_config_from_plan(target, path)
    assert execution_settings(target) == execution_settings(source)
    assert target.keep_resources and not target.auto_cleanup_on_failure
    assert target.report_dir == tmp_path / "resumed"
    assert target.repeat_index == 2 and target.repeat_root_id == "root-id"
    assert target.resume_run_id == "run-id"
    assert target.effective_migration_storage == (
        "host" if storage == "host" else "shared"
    )
    assert target.migration_submission_budget == (18 if migration == "live" else 2)
    targets = {
        spec.family: spec.metadata["target"]
        for spec in plan.tests
        if spec.operation == "egress"
    }
    assert targets == {4: "203.0.113.9", 6: "2001:db8::9"}


def save_pass(config, store, run_id, exit_code, *, plan_path=None):
    now = iso_utc()
    checkpoint = RunCheckpoint(
        run_id=run_id,
        state="COMPLETED"
        if exit_code in {0, 1}
        else "CANCELLED"
        if exit_code == 130
        else "FAILED",
        action="run",
        phase="finished",
        current_batch=None,
        started_at=now,
        updated_at=now,
        last_activity=now,
        completed_test_ids=[],
        failed_test_ids=[],
        pending_test_ids=[],
        active_group_ids=[],
        manifest_path=str(store.run_dir(run_id) / "manifest.json"),
        report_dir=str(store.run_dir(run_id)),
        cleanup_state="COMPLETE",
        plan_path=str(plan_path) if plan_path else None,
        metadata={
            "repeat_count": config.repeat_count,
            "repeat_index": config.repeat_index,
            "repeat_root_id": config.repeat_root_id,
            "repeat_next_id": config.repeat_next_id,
            "repeat_exit_code": config.repeat_exit_code,
            "pass_exit_code": exit_code,
        },
    )
    store.save(checkpoint)
    return checkpoint


@pytest.mark.parametrize("first_exit", [0, 1, 2, 3, 4, 130])
def test_complete_suite_repeat_obeys_every_exit_class(
    first_exit, tmp_path, monkeypatch
):
    calls = []

    def execute(config, store, run_id, checkpoint, **kwargs):
        calls.append(
            (
                config.repeat_index,
                run_id,
                config.repeat_root_id,
                config.repeat_exit_code,
            )
        )
        code = first_exit if len(calls) == 1 else 0
        save_pass(config, store, run_id, code)
        return code

    monkeypatch.setattr(cli, "_execute_locked_action", execute)
    assert (
        cli.main(
            [
                "run",
                *BASE,
                "--storage",
                "host",
                "--repeat",
                "3",
                "--output-dir",
                str(tmp_path),
            ]
        )
        == first_exit
    )
    expected_passes = 3 if first_exit in {0, 1} else 1
    assert [call[0] for call in calls] == list(range(1, expected_passes + 1))
    assert len({call[1] for call in calls}) == expected_passes
    assert {call[2] for call in calls} == {calls[0][1]}
    assert calls[-1][3] == (first_exit if expected_passes > 1 else 0)
    checkpoints = sorted(
        StateStore(tmp_path).list(), key=lambda item: item.metadata["repeat_index"]
    )
    assert len(checkpoints) == expected_passes
    for previous, following in zip(checkpoints, checkpoints[1:], strict=False):
        assert previous.metadata["repeat_next_id"] == following.run_id


def test_resume_interrupted_repeat_restores_workload_and_continues_same_pass(
    discovery_fixture, tmp_path, monkeypatch
):
    calls = []
    interrupted = False
    original_settings = None

    def execute(config, store, run_id, checkpoint, **kwargs):
        nonlocal interrupted, original_settings
        settings = execution_settings(config)
        if original_settings is None:
            original_settings = settings
        assert settings == original_settings
        calls.append(
            (config.repeat_index, run_id, config.keep_resources, checkpoint is not None)
        )
        plan = Planner(config, discovery_fixture, mock.Mock()).build()
        plan_path = store.run_dir(run_id) / "plan.json"
        plan_path.write_text(
            json.dumps(create_plan_contract(config, discovery_fixture, plan))
        )
        code = 1 if config.repeat_index == 1 else 0
        if config.repeat_index == 2 and not interrupted:
            interrupted = True
            code = 130
        save_pass(config, store, run_id, code, plan_path=plan_path)
        return code

    monkeypatch.setattr(cli, "_execute_locked_action", execute)
    argv = [
        "run",
        *BASE,
        "--storage",
        "volume",
        "--volume-type",
        "fast",
        "--migration-mode",
        "cold",
        "--performance-profile",
        "exhaustive",
        "--repeat",
        "3",
        "--zones",
        "az1,az2",
        "--shared-aggregate",
        "ignore",
        "--concurrent-vm-pairs",
        "1,4",
        "--concurrent-repeats",
        "3",
        "--concurrent-duration",
        "20",
        "--ping-target-ipv4",
        "203.0.113.9",
        "--ping-target-ipv6",
        "2001:db8::9",
        "--output-dir",
        str(tmp_path),
    ]
    assert cli.main(argv) == 130
    first_id, second_id = calls[0][1], calls[1][1]
    assert (
        cli.main(
            [
                "run",
                "--resume",
                first_id,
                "--output-dir",
                str(tmp_path),
                "--keep-resources",
            ]
        )
        == 1
    )
    assert [call[0] for call in calls] == [1, 2, 2, 3]
    assert calls[2][1] == second_id and calls[2][3]
    assert not calls[3][3] and calls[3][1] not in {first_id, second_id}
    assert [call[2] for call in calls] == [False, False, True, True]
    store = StateStore(tmp_path)
    assert all(item.state == "COMPLETED" for item in store.list())
    assert cli.main(["run", "--resume", first_id, "--output-dir", str(tmp_path)]) == 2
    assert len(calls) == 4
