from __future__ import annotations

from ._shared import *  # noqa: F403, F405


def test_compute_placement_defaults_enabled_with_automatic_aggregate_policy(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NEUTRON_FLUX_CONFIG", raising=False)
    config = Config.from_args(required_args("run"))
    assert config.compute_host_connectivity_enabled is True
    assert config.require_shared_compute_aggregate is None
    assert config.compute_migration_max_attempts == 2


def test_same_host_target_rejects_cross_az_even_with_shared_generic_aggregate(
    config_factory,
):
    from neutron_flux.models import ComputeHostInfo

    source = endpoint("source", "A")
    source.host = "compute1"
    source.availability_zone = "az1"
    peer = endpoint("peer", "B")
    peer.host = "compute2"
    peer.availability_zone = "az2"
    inventory = {
        "compute1": ComputeHostInfo(
            "compute1", "az1", True, True, {"shared"}, {"generic"}
        ),
        "compute2": ComputeHostInfo(
            "compute2", "az2", True, True, {"shared"}, {"generic"}
        ),
    }
    builder = _placement_builder(
        config_factory(action="run", migration_mode="cold-only"), inventory
    )

    target, reason = builder.select_compute_migration_target(
        peer, source, desired_relation="same"
    )

    assert target is None
    assert "crossing availability zones" in reason


def test_different_host_target_requires_same_az_and_shared_aggregate(config_factory):
    from neutron_flux.models import ComputeHostInfo

    source = endpoint("source", "A")
    source.host = "compute1"
    source.availability_zone = "az1"
    peer = endpoint("peer", "B")
    peer.host = "compute1"
    peer.availability_zone = "az1"
    inventory = {
        "compute1": ComputeHostInfo(
            "compute1", "az1", True, True, {"az1-agg"}, {"az1"}
        ),
        "compute2": ComputeHostInfo(
            "compute2", "az2", True, True, {"az1-agg"}, {"generic"}
        ),
        "compute3": ComputeHostInfo(
            "compute3", "az1", True, True, {"other"}, {"other"}
        ),
        "compute4": ComputeHostInfo(
            "compute4", "az1", True, True, {"az1-agg"}, {"az1"}
        ),
    }
    builder = _placement_builder(
        config_factory(action="run", migration_mode="cold-only"), inventory
    )

    target, reason = builder.select_compute_migration_target(
        peer, source, desired_relation="different"
    )

    assert reason == "eligible"
    assert target is not None
    assert target.host == "compute4"


def test_compute_target_is_unverified_when_aggregate_inventory_hidden(config_factory):
    from neutron_flux.models import ComputeHostInfo

    source = endpoint("source", "A")
    peer = endpoint("peer", "B")
    inventory = {
        "compute1": ComputeHostInfo("compute1", "az1", True, True),
        "compute2": ComputeHostInfo("compute2", "az1", True, True),
    }
    builder = _placement_builder(
        config_factory(action="run", migration_mode="cold-only"),
        inventory,
        aggregate_inventory=False,
    )

    target, reason = builder.select_compute_migration_target(
        peer, source, desired_relation="different"
    )

    assert target is None
    assert "aggregate inventory is unavailable" in reason


def test_cold_migration_confirms_immediately_after_verify_resize(config_factory):
    from neutron_flux.models import ComputeHostInfo

    events = []
    run_calls = []
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory(action="run", convergence_timeout=5)
    builder.logger = SimpleNamespace(log=lambda message, level=None: None)
    builder.probe_service = SimpleNamespace(
        stop=lambda endpoint: events.append("stop-probe")
    )
    builder.reporter = SimpleNamespace(event=lambda *args, **kwargs: None)
    builder.osc = SimpleNamespace(
        run=lambda *args, **kwargs: run_calls.append(args) or completed(0),
        json=lambda *args, **kwargs: {
            "status": "ACTIVE",
            "OS-EXT-SRV-ATTR:host": "compute2",
            "OS-EXT-AZ:availability_zone": "az1",
        },
    )
    builder._capture_endpoint_migration_state = lambda endpoint: {
        "server_id": endpoint.server_id,
        "source_host": "compute1",
        "source_availability_zone": "az1",
        "ports": {},
        "volume_ids": set(),
    }
    builder._wait_for_migration_handoff = lambda endpoint, target: (
        {"status": "VERIFY_RESIZE"},
        False,
    )
    builder._confirm_cold_migration = lambda endpoint, target: (
        events.append("confirm") or False
    )
    builder._wait_for_status = lambda *args, **kwargs: (
        events.append("wait-active") or "active"
    )
    builder._verify_migrated_ports = lambda endpoint, target, before: (True, {})
    builder._server_volume_ids = lambda server_id: set()
    builder._wait_for_ssh = lambda *args, **kwargs: True
    builder.reconfigure_endpoint = lambda endpoint: events.append("reconfigure")

    migrated = endpoint("migrated", "B")
    migrated.host = "compute1"
    migrated.availability_zone = "az1"
    result = builder.cold_migrate_endpoint(
        migrated,
        ComputeHostInfo("compute2", "az1", True, True, {"agg"}, {"agg"}),
    )

    assert result.confirmed is True
    assert result.automatically_confirmed is False
    assert run_calls[0] == (
        "--os-compute-api-version",
        "2.56",
        "server",
        "migrate",
        "--host",
        "compute2",
        migrated.server_id,
    )
    assert events.index("confirm") < events.index("wait-active")
    assert events.index("wait-active") < events.index("reconfigure")
    assert migrated.host == "compute2"


def test_failed_cold_migration_confirmation_reverts_immediately(config_factory):
    calls = []
    json_responses = iter(
        [
            {
                "status": "VERIFY_RESIZE",
                "OS-EXT-SRV-ATTR:host": "compute2",
                "OS-EXT-AZ:availability_zone": "az1",
            },
            {
                "status": "ACTIVE",
                "OS-EXT-SRV-ATTR:host": "compute1",
                "OS-EXT-AZ:availability_zone": "az1",
            },
        ]
    )

    def run(*args, **kwargs):
        calls.append(args)
        if "confirm" in args:
            return completed(1, stderr="confirmation rejected")
        if "revert" in args:
            return completed(0)
        raise AssertionError(f"unexpected command: {args}")

    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory(action="run", convergence_timeout=5)
    builder.logger = SimpleNamespace(log=lambda message, level=None: None)
    builder.osc = SimpleNamespace(
        run=run,
        json=lambda *args, **kwargs: next(json_responses),
    )
    builder._wait_for_status = lambda *args, **kwargs: calls.append(("wait-active",))
    builder._wait_for_ssh = lambda *args, **kwargs: True
    builder.reconfigure_endpoint = lambda endpoint: calls.append(("reconfigure",))

    migrated = endpoint("migrated", "B")
    migrated.host = "compute1"
    migrated.availability_zone = "az1"

    with pytest.raises(SuiteError, match="reverted immediately"):
        builder._confirm_cold_migration(migrated, "compute2")

    confirm_positions = [index for index, call in enumerate(calls) if "confirm" in call]
    revert_position = next(
        index for index, call in enumerate(calls) if "revert" in call
    )
    assert confirm_positions
    assert max(confirm_positions) < revert_position
    assert ("wait-active",) in calls
    assert ("reconfigure",) in calls
    assert migrated.host == "compute1"


def test_runtime_placement_result_ids_are_collision_resistant():
    executor = object.__new__(AdaptiveExecutor)
    source_one = endpoint("source-one", "A")
    destination_one = endpoint("destination-one", "B")
    source_two = endpoint("source-two", "A")
    destination_two = endpoint("destination-two", "B")
    shared_prefix_one = "pool-b8b3b8ff-9026-41fb-bfb3-0769f9a2dce1-ext-external-one"
    shared_prefix_two = "pool-b8b3b8ff-9026-41fb-bfb3-0769f9a2dce1-ext-external-two"

    first = executor._placement_control_spec(
        (shared_prefix_one,),
        source=source_one,
        destination=destination_one,
        kind="MIGRATION-INTER-COMPUTE",
        display_name="first",
        scenario="Cold migration lifecycle",
        expectation="placement-achieved",
    )
    second = executor._placement_control_spec(
        (shared_prefix_two,),
        source=source_two,
        destination=destination_two,
        kind="MIGRATION-INTER-COMPUTE",
        display_name="second",
        scenario="Cold migration lifecycle",
        expectation="placement-achieved",
    )
    repeated_generation = executor._placement_control_spec(
        (shared_prefix_one,),
        source=source_two,
        destination=destination_two,
        kind="MIGRATION-INTER-COMPUTE",
        display_name="repeat",
        scenario="Cold migration lifecycle",
        expectation="placement-achieved",
    )

    assert len({first.id, second.id, repeated_generation.id}) == 3
    assert first.id.startswith("PLACEMENT-MIGRATION-INTER-COMPUTE-")


def test_runtime_placement_probe_ids_include_endpoint_generation_identity():
    executor = object.__new__(AdaptiveExecutor)
    group_id = "pool-b8b3b8ff-9026-41fb-bfb3-0769f9a2dce1-ext-external-one"
    spec = FluxTestSpec(
        id="TENANT-PROBE",
        category="tenant-provider-connectivity",
        operation="probe",
        family=6,
        expectation="reachable",
        expectation_reason="routing",
        authoritative=True,
        dependencies=[group_id],
    )
    first = executor._placement_probe_specs(
        [spec],
        relation="inter-compute",
        source=endpoint("source-one", "A"),
        destination=endpoint("destination-one", "B"),
    )
    second = executor._placement_probe_specs(
        [spec],
        relation="inter-compute",
        source=endpoint("source-two", "A"),
        destination=endpoint("destination-two", "B"),
    )
    assert first[0].id != second[0].id


def test_compute_placement_unavailable_still_validates_existing_relation(
    config_factory,
):
    source = endpoint("source", "A")
    destination = endpoint("destination", "B")
    source.host = destination.host = "compute1"
    builder = SimpleNamespace(
        select_compute_migration_target=lambda *args, **kwargs: (
            None,
            "only one eligible compute host",
        )
    )
    executor, spec, recorded = _placement_executor(
        config_factory(action="run", migration_mode="cold-only"),
        source,
        destination,
        builder,
    )
    runs = []
    engine = SimpleNamespace(run_specs=lambda specs: runs.append(list(specs)))

    executor._run_compute_placement_validation(
        [spec], engine, dependencies=("placement-group",)
    )

    assert runs == []
    assert any(item.status == "UNVERIFIED" for item in recorded)
    assert "only one eligible compute host" in recorded[-1].message


def test_compute_placement_success_runs_both_relations_and_separate_verdicts(
    config_factory,
):
    from neutron_flux.models import ComputeHostInfo, MigrationResult

    source = endpoint("source", "A")
    destination = endpoint("destination", "B")
    source.host = "compute1"
    destination.host = "compute2"
    target = ComputeHostInfo("compute1", "az1", True, True, {"agg"}, {"agg"})

    def migrate(migrated, selected):
        assert selected is target
        old_host = migrated.host
        migrated.host = selected.host
        return MigrationResult(
            server_id=migrated.server_id,
            source_host=old_host,
            destination_host=selected.host,
            source_availability_zone="az1",
            destination_availability_zone="az1",
            confirmed=True,
            automatically_confirmed=False,
            port_binding_verified=True,
            details={"ports": {}},
        )

    builder = SimpleNamespace(
        select_compute_migration_target=lambda *args, **kwargs: (target, "eligible"),
        cold_migrate_endpoint=migrate,
    )
    executor, spec, recorded = _placement_executor(
        config_factory(action="run", migration_mode="cold-only"),
        source,
        destination,
        builder,
    )
    runs = []
    engine = SimpleNamespace(run_specs=lambda specs: runs.append(list(specs)))

    executor._run_compute_placement_validation(
        [spec], engine, dependencies=("placement-group",)
    )

    assert [batch[0].scenario for batch in runs] == [
        "Intra-compute connectivity",
    ]
    statuses = {item.scenario: item.status for item in recorded}
    assert statuses["Cold migration lifecycle"] == "PASS"
    assert statuses["Post-migration Neutron port binding"] == "PASS"
    assert destination.host == "compute1"


def test_post_migration_port_failure_does_not_relabel_nova_migration_failure(
    config_factory,
):
    from neutron_flux.models import ComputeHostInfo, MigrationResult

    source = endpoint("source", "A")
    destination = endpoint("destination", "B")
    source.host = "compute1"
    destination.host = "compute2"
    target = ComputeHostInfo("compute1", "az1", True, True, {"agg"}, {"agg"})

    def migrate(migrated, selected):
        old_host = migrated.host
        migrated.host = selected.host
        return MigrationResult(
            server_id=migrated.server_id,
            source_host=old_host,
            destination_host=selected.host,
            source_availability_zone="az1",
            destination_availability_zone="az1",
            confirmed=True,
            automatically_confirmed=False,
            port_binding_verified=False,
            port_validation_error="port remained bound to compute2",
            endpoint_ready=True,
            details={},
        )

    builder = SimpleNamespace(
        select_compute_migration_target=lambda *args, **kwargs: (target, "eligible"),
        cold_migrate_endpoint=migrate,
    )
    executor, spec, recorded = _placement_executor(
        config_factory(action="run", migration_mode="cold-only"),
        source,
        destination,
        builder,
    )
    runs = []
    engine = SimpleNamespace(run_specs=lambda specs: runs.append(list(specs)))

    executor._run_compute_placement_validation(
        [spec], engine, dependencies=("placement-group",)
    )

    statuses = {item.scenario: item.status for item in recorded}
    assert statuses["Cold migration lifecycle"] == "PASS"
    assert statuses["Post-migration Neutron port binding"] == "FAIL"
    assert statuses["Post-migration endpoint readiness"] == "PASS"
    assert len(runs) == 1


def test_post_migration_readiness_failure_still_runs_data_plane_checks(
    config_factory,
):
    from neutron_flux.models import ComputeHostInfo, MigrationResult

    source = endpoint("source", "A")
    destination = endpoint("destination", "B")
    source.host = "compute1"
    destination.host = "compute2"
    target = ComputeHostInfo("compute1", "az1", True, True, {"agg"}, {"agg"})

    def migrate(migrated, selected):
        old_host = migrated.host
        migrated.host = selected.host
        return MigrationResult(
            server_id=migrated.server_id,
            source_host=old_host,
            destination_host=selected.host,
            source_availability_zone="az1",
            destination_availability_zone="az1",
            confirmed=True,
            automatically_confirmed=False,
            port_binding_verified=True,
            endpoint_ready=False,
            endpoint_recovery_error="SSH did not return after migration",
            details={},
        )

    builder = SimpleNamespace(
        select_compute_migration_target=lambda *args, **kwargs: (target, "eligible"),
        cold_migrate_endpoint=migrate,
    )
    executor, spec, recorded = _placement_executor(
        config_factory(action="run", migration_mode="cold-only"),
        source,
        destination,
        builder,
    )
    runs = []
    engine = SimpleNamespace(run_specs=lambda specs: runs.append(list(specs)))

    executor._run_compute_placement_validation(
        [spec], engine, dependencies=("placement-group",)
    )

    statuses = {item.scenario: item.status for item in recorded}
    assert statuses["Cold migration lifecycle"] == "PASS"
    assert statuses["Post-migration Neutron port binding"] == "PASS"
    assert statuses["Post-migration endpoint readiness"] == "FAIL"
    blocked = [item for item in recorded if item.status == "BLOCKED_BY_SETUP_ERROR"]
    assert blocked == []
    assert len(runs) == 1
    assert runs[-1][0].scenario == "Intra-compute connectivity"


def test_confirmation_race_accepts_already_active_target_without_revert(
    config_factory,
):
    calls = []

    def run(*args, **kwargs):
        calls.append(args)
        return completed(1, stderr="conflict: resize already confirmed")

    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory(action="run", migration_mode="cold-only")
    builder.logger = SimpleNamespace(log=lambda message, level=None: None)
    builder.osc = SimpleNamespace(
        run=run,
        json=lambda *args, **kwargs: {
            "status": "ACTIVE",
            "OS-EXT-SRV-ATTR:host": "compute2",
        },
    )
    migrated = endpoint("migrated", "B")

    assert builder._confirm_cold_migration(migrated, "compute2") is True
    assert [call for call in calls if "confirm" in call]
    assert not [call for call in calls if "revert" in call]


def test_compute_migration_retries_next_distinct_host(config_factory):
    from neutron_flux.models import ComputeHostInfo, MigrationResult

    source = endpoint("source", "A")
    destination = endpoint("destination", "B")
    source.host = destination.host = "compute1"
    target2 = ComputeHostInfo("compute2", "az1", True, True, {"agg"}, {"agg"})
    target3 = ComputeHostInfo("compute3", "az1", True, True, {"agg"}, {"agg"})
    calls = []

    def migrate(moving, target):
        calls.append((moving.label, target.host))
        if target.host == "compute2":
            raise RetryableMigrationError(
                "NoValidHost on compute2",
                unavailable=True,
                target_unsuitable=True,
            )
        old_host = moving.host
        moving.host = target.host
        return MigrationResult(
            server_id=moving.server_id,
            source_host=old_host,
            destination_host=target.host,
            source_availability_zone="az1",
            destination_availability_zone="az1",
            confirmed=True,
            automatically_confirmed=False,
            port_binding_verified=True,
            details={},
        )

    builder = SimpleNamespace(
        select_compute_migration_targets=lambda *args, **kwargs: (
            [target2, target3],
            "eligible",
        ),
        cold_migrate_endpoint=migrate,
    )
    executor, spec, recorded = _placement_executor(
        config_factory(action="run", migration_mode="cold-only"),
        source,
        destination,
        builder,
    )
    runs = []
    engine = SimpleNamespace(run_specs=lambda specs: runs.append(list(specs)))

    executor._run_compute_placement_validation(
        [spec], engine, dependencies=("placement-group",)
    )

    assert calls == [("destination", "compute2"), ("destination", "compute3")]
    assert [batch[0].scenario for batch in runs] == [
        "Inter-compute connectivity",
    ]
    lifecycle = next(
        item for item in recorded if item.scenario == "Cold migration lifecycle"
    )
    assert lifecycle.status == "PASS"
    assert "attempt 2 after" in lifecycle.message
    assert lifecycle.details["details"]["effective_submission_budget"] == 2
    assert destination.host == "compute3"


def test_compute_migration_retries_only_target_twice(config_factory):
    from neutron_flux.models import ComputeHostInfo

    source = endpoint("source", "A")
    destination = endpoint("destination", "B")
    source.host = destination.host = "compute1"
    target = ComputeHostInfo("compute2", "az1", True, True, {"agg"}, {"agg"})
    calls = []

    def migrate(moving, selected):
        calls.append(selected.host)
        raise RetryableMigrationError("NoValidHost", unavailable=True)

    builder = SimpleNamespace(
        select_compute_migration_targets=lambda *args, **kwargs: ([target], "eligible"),
        cold_migrate_endpoint=migrate,
    )
    executor, spec, recorded = _placement_executor(
        config_factory(action="run", migration_mode="cold-only"),
        source,
        destination,
        builder,
    )
    runs = []
    engine = SimpleNamespace(run_specs=lambda specs: runs.append(list(specs)))

    executor._run_compute_placement_validation(
        [spec], engine, dependencies=("placement-group",)
    )

    assert calls == ["compute2", "compute2"]
    assert runs == []
    lifecycle = next(
        item for item in recorded if item.scenario == "Cold migration lifecycle"
    )
    assert lifecycle.status == "UNVERIFIED"
    assert "2 attempt(s)" in lifecycle.message


def test_same_host_retry_keeps_a_stationary_and_retries_b(config_factory):
    from neutron_flux.models import ComputeHostInfo, MigrationResult

    source = endpoint("source", "A")
    destination = endpoint("destination", "B")
    source.host = "compute1"
    destination.host = "compute2"
    target1 = ComputeHostInfo("compute1", "az1", True, True, {"agg"}, {"agg"})
    calls = []

    def select(moving, stationary, *, desired_relation):
        assert desired_relation == "same"
        assert moving is destination
        assert stationary is source
        return [target1], "eligible"

    def migrate(moving, target):
        calls.append((moving.label, moving.host, target.host))
        if len(calls) == 1:
            raise RetryableMigrationError("first direction rejected", unavailable=True)
        old_host = moving.host
        moving.host = target.host
        return MigrationResult(
            server_id=moving.server_id,
            source_host=old_host,
            destination_host=target.host,
            source_availability_zone="az1",
            destination_availability_zone="az1",
            confirmed=True,
            automatically_confirmed=False,
            port_binding_verified=True,
            details={},
        )

    builder = SimpleNamespace(
        select_compute_migration_targets=select,
        cold_migrate_endpoint=migrate,
    )
    executor, spec, recorded = _placement_executor(
        config_factory(action="run", migration_mode="cold-only"),
        source,
        destination,
        builder,
    )
    runs = []
    engine = SimpleNamespace(run_specs=lambda specs: runs.append(list(specs)))

    executor._run_compute_placement_validation(
        [spec], engine, dependencies=("placement-group",)
    )

    assert calls == [
        ("destination", "compute2", "compute1"),
        ("destination", "compute2", "compute1"),
    ]
    assert [batch[0].scenario for batch in runs] == [
        "Intra-compute connectivity",
    ]
    lifecycle = next(
        item for item in recorded if item.scenario == "Cold migration lifecycle"
    )
    assert lifecycle.status == "PASS"
    assert source.host == destination.host == "compute1"


def test_failed_attempt_is_retryable_only_after_original_endpoint_recovers(
    config_factory,
):
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory(action="run", convergence_timeout=5)
    builder._cold_migrate_endpoint_once = lambda endpoint, target: (
        _ for _ in ()
    ).throw(SuiteError("migration request failed"))
    builder.osc = SimpleNamespace(
        json=lambda *args, **kwargs: {
            "status": "ACTIVE",
            "OS-EXT-STS:task_state": None,
            "OS-EXT-SRV-ATTR:host": "compute1",
            "OS-EXT-AZ:availability_zone": "az1",
        }
    )
    builder._wait_for_ssh = lambda *args, **kwargs: True
    recovered = []
    builder.reconfigure_endpoint = lambda endpoint: recovered.append(endpoint.host)

    migrated = endpoint("migrated", "B")
    target = SimpleNamespace(host="compute2")

    with pytest.raises(RetryableMigrationError, match="restored on the original host"):
        builder.cold_migrate_endpoint(migrated, target)

    assert recovered == ["compute1"]
    assert migrated.host == "compute1"


def test_different_host_selector_returns_all_same_az_shared_aggregate_targets(
    config_factory,
):
    from neutron_flux.models import ComputeHostInfo

    source = endpoint("source", "A")
    source.host = "compute1"
    source.availability_zone = "az1"
    peer = endpoint("peer", "B")
    peer.host = "compute1"
    peer.availability_zone = "az1"
    inventory = {
        "compute1": ComputeHostInfo("compute1", "az1", True, True, {"agg"}, {"agg"}),
        "compute2": ComputeHostInfo("compute2", "az1", True, True, {"agg"}, {"agg"}),
        "compute3": ComputeHostInfo("compute3", "az1", True, True, {"agg"}, {"agg"}),
        "compute4": ComputeHostInfo("compute4", "az2", True, True, {"agg"}, {"agg"}),
        "compute5": ComputeHostInfo(
            "compute5", "az1", True, True, {"other"}, {"other"}
        ),
    }
    builder = _placement_builder(
        config_factory(action="run", migration_mode="cold-only"), inventory
    )

    targets, reason = builder.select_compute_migration_targets(
        peer, source, desired_relation="different"
    )

    assert reason == "eligible"
    assert [target.host for target in targets] == ["compute2", "compute3"]


def test_unsafe_migration_state_stops_all_fallback_attempts(config_factory):
    from neutron_flux.errors import UnsafeMigrationStateError
    from neutron_flux.models import ComputeHostInfo

    source = endpoint("source", "A")
    destination = endpoint("destination", "B")
    source.host = destination.host = "compute1"
    targets = [
        ComputeHostInfo("compute2", "az1", True, True, {"agg"}, {"agg"}),
        ComputeHostInfo("compute3", "az1", True, True, {"agg"}, {"agg"}),
    ]
    calls = []

    def migrate(moving, target):
        calls.append(target.host)
        raise UnsafeMigrationStateError("server placement became uncertain")

    builder = SimpleNamespace(
        select_compute_migration_targets=lambda *args, **kwargs: (
            targets,
            "eligible",
        ),
        cold_migrate_endpoint=migrate,
    )
    executor, spec, recorded = _placement_executor(
        config_factory(action="run", migration_mode="cold-only"),
        source,
        destination,
        builder,
    )
    runs = []
    engine = SimpleNamespace(run_specs=lambda specs: runs.append(list(specs)))

    executor._run_compute_placement_validation(
        [spec], engine, dependencies=("placement-group",)
    )

    assert calls == ["compute2"]
    assert runs == []
    lifecycle = next(
        item for item in recorded if item.scenario == "Cold migration lifecycle"
    )
    assert lifecycle.status == "FAIL"
    assert "not safely retryable" in lifecycle.message


def test_exhausted_safe_execution_failures_are_failed_not_unverified(config_factory):
    from neutron_flux.models import ComputeHostInfo

    source = endpoint("source", "A")
    destination = endpoint("destination", "B")
    source.host = destination.host = "compute1"
    target = ComputeHostInfo("compute2", "az1", True, True, {"agg"}, {"agg"})
    calls = []

    def migrate(moving, selected):
        calls.append(selected.host)
        raise RetryableMigrationError(
            "migration timed out but reverted", unavailable=False
        )

    builder = SimpleNamespace(
        select_compute_migration_targets=lambda *args, **kwargs: ([target], "eligible"),
        cold_migrate_endpoint=migrate,
    )
    executor, spec, recorded = _placement_executor(
        config_factory(action="run", migration_mode="cold-only"),
        source,
        destination,
        builder,
    )
    engine = SimpleNamespace(run_specs=lambda specs: None)

    executor._run_compute_placement_validation(
        [spec], engine, dependencies=("placement-group",)
    )

    assert calls == ["compute2", "compute2"]
    lifecycle = next(
        item for item in recorded if item.scenario == "Cold migration lifecycle"
    )
    assert lifecycle.status == "FAIL"
    assert lifecycle.observed == "migration-attempts-failed"


def test_failed_attempt_on_wrong_host_is_not_retryable(config_factory):
    from neutron_flux.errors import UnsafeMigrationStateError

    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory(action="run", convergence_timeout=5)
    builder._cold_migrate_endpoint_once = lambda endpoint, target: (
        _ for _ in ()
    ).throw(SuiteError("migration validation failed"))
    builder.osc = SimpleNamespace(
        json=lambda *args, **kwargs: {
            "status": "ACTIVE",
            "OS-EXT-SRV-ATTR:host": "compute2",
            "OS-EXT-AZ:availability_zone": "az1",
        }
    )

    migrated = endpoint("migrated", "B")
    target = SimpleNamespace(host="compute2")

    with pytest.raises(UnsafeMigrationStateError, match="not original host"):
        builder.cold_migrate_endpoint(migrated, target)


def test_openstack_presence_distinguishes_absence_from_api_failure(tmp_path):
    osc = OpenStack(Logger(tmp_path / "openstack.log"))
    osc.run = mock.Mock(
        side_effect=[
            completed(1, stderr="No server with a name or ID of dead was found"),
            completed(1, stderr="HttpException: 503 Service Unavailable"),
        ]
    )
    absent = osc.presence("server", "dead")
    assert absent.absent
    with pytest.raises(
        SuiteError, match="Could not determine whether server live exists"
    ):
        osc.exists("server", "live")
    osc.logger.close()


def test_cleanup_api_uncertainty_is_never_reported_complete(config_factory, tmp_path):
    config = config_factory(report_dir=tmp_path / "reports", action="run")
    reporter = Reporter(config, "cleanup-unknown")
    tracker = ResourceTracker(reporter)
    tracker.add("server", "server-1", "server-1")
    osc = mock.Mock()
    osc.exists.side_effect = SuiteError("503 Service Unavailable")
    osc.json.return_value = {}
    manager = CleanupManager(osc, reporter, tracker, config)
    manager._adopt_orphans = mock.Mock(return_value=0)
    manager._delete_all_types = mock.Mock()
    manager._remove_local_keys = mock.Mock()
    manager._verify_placement_allocations = mock.Mock(return_value=[])
    assert manager.cleanup() is False
    assert reporter.cleanup_summary["complete"] is False
    assert any(
        "verification-error" in item for item in reporter.cleanup_summary["leftovers"]
    )
    reporter.logger.close()


def test_automatic_az_selection_prefers_non_internal_non_default_shared_capacity(
    config_factory,
):
    from neutron_flux.models import ComputeHostInfo

    inventory = {
        "internal1": ComputeHostInfo("internal1", "internal", True, True),
        "nova1": ComputeHostInfo("nova1", "nova", True, True, {"n"}, {"n"}),
        "nova2": ComputeHostInfo("nova2", "nova", True, True, {"n"}, {"n"}),
        "az1-1": ComputeHostInfo("az1-1", "bc-van1", True, True, {"a"}, {"a"}),
        "az1-2": ComputeHostInfo("az1-2", "bc-van1", True, True, {"a"}, {"a"}),
        "az1-3": ComputeHostInfo("az1-3", "bc-van1", True, True, {"a"}, {"a"}),
        "az2-1": ComputeHostInfo("az2-1", "bc-van2", True, True, {"b"}, {"b"}),
    }
    builder = _az_builder(
        config_factory(action="run", migration_mode="cold-only"), inventory
    )
    builder._select_run_availability_zone()
    assert builder.selected_availability_zone == "bc-van1"
    assert (
        "largest_policy_eligible_migration_cohort=3"
        in builder.selected_availability_zone_reason
    )


def test_automatic_az_selection_uses_nova_only_as_fallback(config_factory):
    from neutron_flux.models import ComputeHostInfo

    inventory = {
        "internal1": ComputeHostInfo("internal1", "internal", True, True),
        "nova1": ComputeHostInfo("nova1", "nova", True, True, {"n"}, {"n"}),
    }
    builder = _az_builder(
        config_factory(action="run", migration_mode="cold-only"), inventory
    )
    builder._select_run_availability_zone()
    assert builder.selected_availability_zone is None
    assert builder.availability_zone_candidates == [None]


def test_configured_az_allowlist_still_selects_one_run_wide_zone(config_factory):
    from neutron_flux.models import ComputeHostInfo

    inventory = {
        "az1-1": ComputeHostInfo("az1-1", "az1", True, True, {"a"}, {"a"}),
        "az3-1": ComputeHostInfo("az3-1", "az3", True, True, {"c"}, {"c"}),
        "az3-2": ComputeHostInfo("az3-2", "az3", True, True, {"c"}, {"c"}),
    }
    builder = _az_builder(
        config_factory(action="run", availability_zones=["az1", "az3"]), inventory
    )
    builder._select_run_availability_zone()
    assert builder.selected_availability_zone == "az3"


def test_missing_compute_service_health_is_not_assumed_healthy(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run", migration_mode="cold-only")
    builder._compute_host_inventory_cache = None
    builder._aggregate_inventory_available = None
    builder._aggregate_inventory_state = "unknown"
    builder._aggregate_inventory_errors = []
    builder.osc = mock.Mock()
    builder.osc.json.side_effect = [
        [{"Host": "compute1", "Zone": "az1"}],
        [],
    ]
    inventory = builder.compute_host_inventory(refresh=True)
    assert inventory["compute1"].enabled is False
    assert inventory["compute1"].up is False
