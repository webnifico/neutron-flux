from __future__ import annotations

from ._shared import *  # noqa: F403, F405


def test_partial_aggregate_inventory_is_reported_as_partial(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder._compute_host_inventory_cache = None
    builder._aggregate_inventory_available = None
    builder._aggregate_inventory_state = "unknown"
    builder._aggregate_inventory_errors = []
    builder.osc = mock.Mock()
    builder.osc.json.side_effect = [
        [{"Host": "compute1", "Status": "enabled", "State": "up", "Zone": "az1"}],
        [{"ID": "agg1", "Name": "aggregate1"}],
        None,
    ]
    builder.compute_host_inventory(refresh=True)
    assert builder._aggregate_inventory_state == "partial"
    assert "details unavailable" in builder.aggregate_inventory_reason()


def test_lock_identity_detects_pid_reuse(tmp_path):
    store = StateStore(tmp_path / "reports")
    path = store.run_dir("run") / "run.lock"
    path.write_text(
        json.dumps(
            {
                "pid": os.getpid(),
                "process_start_ticks": "definitely-not-current",
                "boot_id": store._boot_id(),
            }
        ),
        encoding="utf-8",
    )
    assert store._stale_lock(path) is True


def test_newest_corrupt_checkpoint_is_not_silently_skipped(tmp_path):
    store = StateStore(tmp_path / "reports")
    reporter_dir = store.run_dir("older")
    checkpoint = RunCheckpoint(
        run_id="older",
        state="COMPLETED",
        action="run",
        phase="finished",
        current_batch=None,
        started_at=iso_utc(),
        updated_at=iso_utc(),
        last_activity=iso_utc(),
        completed_test_ids=[],
        failed_test_ids=[],
        pending_test_ids=[],
        active_group_ids=[],
        manifest_path="",
        report_dir=str(reporter_dir),
        cleanup_state="COMPLETE",
    )
    store.save(checkpoint)
    corrupt = store.run_dir("newer") / "state.json"
    corrupt.write_text("{broken", encoding="utf-8")
    os.utime(
        corrupt,
        (corrupt.stat().st_atime, store.state_path("older").stat().st_mtime + 5),
    )
    with pytest.raises(SuiteError, match="Newest Neutron Flux checkpoint is corrupt"):
        store.latest()


def test_failed_required_assertion_is_failure_for_cleanup_policy():
    reporter = SimpleNamespace(
        results=[SimpleNamespace(status="FAIL")],
        setup_failed=False,
        error=None,
    )
    assert _successful_for_cleanup(0, reporter) is False
    reporter.results = [SimpleNamespace(status="UNVERIFIED")]
    assert _successful_for_cleanup(0, reporter) is True


def test_cleanup_incomplete_precedes_interrupted_status(config_factory, tmp_path):
    config = config_factory(report_dir=tmp_path / "reports", action="run")
    reporter = Reporter(config, "precedence")
    reporter.interrupted = True
    reporter.cleanup_summary.update({"attempted": True, "complete": False})
    assert reporter.finalize(130) == 3
    report = reporter.report_path.read_text(encoding="utf-8")
    assert "Final status:    CLEANUP INCOMPLETE" in report


def test_live_certification_rejects_test_failure_exit_code(config_factory, tmp_path):
    import importlib.util

    script = Path(__file__).parents[1] / "scripts" / "live-certify.py"
    spec = importlib.util.spec_from_file_location("nflux_live_certify", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    config_path = tmp_path / "certify.yml"
    config_path.write_text("{}\n", encoding="utf-8")
    module.write_config = lambda base: config_path
    module.state_files = lambda report_dir: set()
    module.invoke = lambda path, action: completed(returncode=1)
    module.new_run_id = lambda report_dir, before: "failed-run"
    module._outcome = lambda workflow, report_dir, run_id, exit_code: module.RunOutcome(
        workflow=workflow,
        run_id=run_id,
        exit_code=exit_code,
        cleanup_state="COMPLETE",
        checkpoint_state="FAILED",
        final_status="FAIL",
    )

    outcome = module.successful_run(config_factory(action="run"))

    assert outcome.run_id == "failed-run"
    with pytest.raises(RuntimeError, match="exited 1"):
        module.validate_successful_outcome(outcome)


def test_nova_migration_record_is_verified_against_source_and_target(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder.osc = mock.Mock()
    builder.osc.json.return_value = [
        {
            "ID": "migration-new",
            "Source Compute": "compute1",
            "Dest Compute": "compute2",
            "Migration Type": "resize",
            "Status": "confirmed",
        }
    ]
    verified, error, row = builder._verify_nova_migration_record(
        endpoint(), "compute1", "compute2", {"migration-old"}
    )
    assert verified is True
    assert error is None
    assert row["ID"] == "migration-new"


def test_guest_migration_marker_is_written_and_verified(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder.reporter = SimpleNamespace(run_id="run")
    checksum = "a" * 64
    builder.ssh_endpoint = mock.Mock(
        side_effect=[
            completed(
                stdout=f"{checksum}  /home/debian/.marker\n/home/debian/.marker\n"
            ),
            completed(stdout=f"{checksum}  /home/debian/.marker\nTOKEN\n"),
        ]
    )
    target = endpoint()
    marker = builder._create_guest_migration_marker(target)
    marker["token"] = "TOKEN"
    verified, error = builder._verify_guest_migration_marker(target, marker)
    assert verified is True
    assert error is None
    assert marker["path"] == "/home/debian/.marker"


def test_not_found_detection_rejects_missing_service_endpoint(tmp_path):
    osc = OpenStack(Logger(tmp_path / "not-found.log"))
    result = completed(
        1,
        stderr="The network service endpoint does not exist in the service catalog",
    )
    assert osc.is_not_found_result(result) is False
    osc.logger.close()


def test_corrupt_manifest_tail_recovers_valid_records(tmp_path):
    path = tmp_path / "manifest.jsonl"
    record = ResourceRecord(1, "port", "p1", "port-one", None, {}, iso_utc())
    path.write_text(
        json.dumps(dataclasses.asdict(record)) + "\n{broken", encoding="utf-8"
    )
    errors: list[str] = []
    records = ResourceTracker.load_manifest(path, errors=errors)
    assert [item.id for item in records] == ["p1"]
    assert errors and "manifest.jsonl:2" in errors[0]


def test_cleanup_malformed_placement_json_is_incomplete(config_factory, tmp_path):
    config = config_factory(report_dir=tmp_path / "reports", action="run")
    reporter = Reporter(config, "placement-json")
    tracker = ResourceTracker(reporter)
    server = tracker.add("server", "server-1", "server-1")
    tracker.mark_deleted(server)
    osc = mock.Mock()
    osc.exists.return_value = False
    osc.run.return_value = completed(0, stdout="{not-json")
    manager = CleanupManager(osc, reporter, tracker, config)
    manager._adopt_orphans = mock.Mock(return_value=0)
    manager._delete_all_types = mock.Mock()
    manager._remove_local_keys = mock.Mock()
    assert manager.cleanup() is False
    assert any(
        "placement-allocation:server-1:verification-error:invalid JSON" in item
        for item in reporter.cleanup_summary["leftovers"]
    )
    reporter.logger.close()


def test_security_control_port_wraps_within_valid_range(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(tcp_port=65534, udp_port=65535)
    builder.security_group_allows_port = mock.Mock(return_value=(False, []))
    port, authoritative, _rules = builder.choose_security_control_port(
        destination_security_group_id="destination",
        source_security_group_id="source",
        family=4,
    )
    assert 1024 <= port <= 65535
    assert port not in {65534, 65535}
    assert authoritative is True


def test_incomplete_nova_migration_record_is_unverified(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder.osc = mock.Mock()
    builder.osc.json.side_effect = [[{"ID": "2"}], None]
    verified, reason, row = builder._verify_nova_migration_record(
        endpoint(), "compute1", "compute2", {"1"}
    )
    assert verified is None
    assert "did not expose" in str(reason)
    assert row["ID"] == "2"


def test_hidden_migrated_port_status_is_unverified(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run", convergence_timeout=1)
    builder.osc = mock.Mock()
    detail = {
        "mac_address": "fa:16:3e:00:00:01",
        "fixed_ips": [{"subnet_id": "s1", "ip_address": "192.0.2.10"}],
        "security_group_ids": ["sg1"],
        "binding_host_id": "compute2",
    }
    builder.osc.json.return_value = detail
    before = {
        "ports": {
            "p1": {
                "mac_address": detail["mac_address"],
                "fixed_ips": builder._fixed_ips(detail),
                "security_groups": builder._port_security_groups(detail),
            }
        }
    }
    verified, observed = builder._verify_migrated_ports(endpoint(), "compute2", before)
    assert verified is None
    assert observed["p1"]["status"] is None


def test_server_create_timeout_recovers_exact_name(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run", prefer_ephemeral_boot=True)
    builder.selected_availability_zone = None
    builder.availability_zone_candidates = [None]
    builder.server_sequence = 0
    builder.flavor_id = "f1"
    builder.keypair_name = "key"
    builder.image_id = "img"
    builder.image_name = "debian-13"
    builder.tracker = mock.Mock()
    builder.logger = mock.Mock()
    builder.reporter = mock.Mock()
    builder.osc = mock.Mock()
    builder.osc.run.side_effect = CommandTimeoutError(
        ["openstack", "server", "create"], 30
    )
    builder._recover_created_resource_by_name = mock.Mock(
        return_value={"id": "server-1"}
    )
    builder._wait_for_status = mock.Mock()
    builder.osc.json.return_value = {
        "id": "server-1",
        "status": "ACTIVE",
        "OS-EXT-AZ:availability_zone": "bc-van1",
    }
    builder._wait_for_server_settlement = mock.Mock(
        return_value=builder.osc.json.return_value
    )
    result = builder._create_server("vm-timeout", ["p1"], role="endpoint")
    assert result["server_id"] == "server-1"
    builder._recover_created_resource_by_name.assert_called_once_with(
        "server", "vm-timeout", timeout=90
    )


def test_prepare_removes_private_key_material_when_keypair_create_fails(
    config_factory, tmp_path
):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder.work_dir = tmp_path / "keys"
    builder.work_dir.mkdir()
    (builder.work_dir / "id_ed25519").write_text("secret", encoding="utf-8")
    builder.logger = mock.Mock()
    builder._resolve_image_flavor_user = mock.Mock()
    builder._select_run_availability_zone = mock.Mock()
    builder._prepare_neutron_placement = mock.Mock()
    builder._create_ssh_key = mock.Mock()
    builder._create_keypair = mock.Mock(side_effect=SuiteError("keypair rejected"))
    with pytest.raises(SuiteError, match="keypair rejected"):
        builder.prepare()
    assert not builder.work_dir.exists()


def test_controller_no_valid_host_retries_next_ranked_az(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder.selected_availability_zone = "bc-van1"
    builder.availability_zone_candidates = ["bc-van1", "bc-van2"]
    builder.logger = mock.Mock()
    builder.reporter = mock.Mock()
    builder._create_server_in_az = mock.Mock(
        side_effect=[
            PlacementUnavailableError("NoValidHost"),
            {"server_id": "s1", "availability_zone": "bc-van2"},
        ]
    )
    result = builder._create_server(
        "controller", ["p1"], role="controller", allow_az_fallback=True
    )
    assert result["server_id"] == "s1"
    assert builder.selected_availability_zone == "bc-van2"
    assert [
        call.kwargs["selected_az"]
        for call in builder._create_server_in_az.call_args_list
    ] == ["bc-van1", "bc-van2"]


def test_wait_for_status_retries_transient_api_error(config_factory, monkeypatch):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(
        action="run", resource_timeout=2, convergence_interval=0, progress_interval=1
    )
    builder.logger = mock.Mock()
    builder.osc = mock.Mock()
    builder.osc.json.side_effect = [
        CommandError(
            ["openstack", "server", "show", "s1"], 1, "", "503 Service Unavailable"
        ),
        {"status": "ACTIVE"},
    ]
    builder.osc.is_transient_result.side_effect = [True]
    builder.osc.is_not_found_result.return_value = False
    monkeypatch.setattr("neutron_flux.resources.time.sleep", lambda _seconds: None)
    assert builder._wait_for_status("server", "s1", {"active"}, {"error"}) == "active"


def test_wait_for_status_surfaces_permanent_api_error(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run", resource_timeout=2)
    builder.logger = mock.Mock()
    builder.osc = mock.Mock()
    builder.osc.json.side_effect = CommandError(
        ["openstack", "server", "show", "s1"], 1, "", "403 Forbidden"
    )
    builder.osc.is_transient_result.return_value = False
    builder.osc.is_not_found_result.return_value = False
    with pytest.raises(CommandError, match="403 Forbidden"):
        builder._wait_for_status("server", "s1", {"active"}, {"error"})


def test_keypair_create_timeout_recovers_and_tracks(config_factory, tmp_path):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder.public_key_path = tmp_path / "id_ed25519.pub"
    builder.public_key_path.write_text("ssh-ed25519 test", encoding="utf-8")
    builder.key_path = tmp_path / "id_ed25519"
    builder.keypair_name = "run-key"
    builder.tracker = mock.Mock()
    builder.logger = mock.Mock()
    builder.osc = mock.Mock()
    builder.osc.json.side_effect = CommandTimeoutError(
        ["openstack", "keypair", "create"], 60
    )
    builder._recover_created_resource_by_name = mock.Mock(
        return_value={"name": "run-key"}
    )
    builder._create_keypair()
    builder.tracker.add.assert_called_once()
    assert builder.tracker.add.call_args.args[:3] == ("keypair", "run-key", "run-key")


def test_controller_default_probe_requires_observable_actual_az(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder.selected_availability_zone = None
    builder.availability_zone_candidates = [None]
    builder.logger = mock.Mock()
    builder.reporter = mock.Mock()
    builder._create_server_in_az = mock.Mock(
        return_value={"server_id": "s1", "availability_zone": None, "host": None}
    )
    with pytest.raises(
        SuiteError, match="same-AZ endpoint placement cannot be guaranteed"
    ):
        builder._create_server(
            "controller", ["p1"], role="controller", allow_az_fallback=True
        )


def test_controller_default_probe_resolves_az_from_host_inventory(config_factory):
    from neutron_flux.models import ComputeHostInfo

    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder.selected_availability_zone = None
    builder.availability_zone_candidates = [None]
    builder.logger = mock.Mock()
    builder.reporter = mock.Mock()
    builder.compute_host_inventory = mock.Mock(
        return_value={
            "compute1": ComputeHostInfo(
                "compute1", "bc-van1", True, True, {"agg"}, {"agg"}
            )
        }
    )
    builder._create_server_in_az = mock.Mock(
        return_value={"server_id": "s1", "availability_zone": None, "host": "compute1"}
    )
    result = builder._create_server(
        "controller", ["p1"], role="controller", allow_az_fallback=True
    )
    assert result["server_id"] == "s1"
    assert builder.selected_availability_zone == "bc-van1"


def test_openstack_run_does_not_leak_compute_microversion_to_network_commands(
    tmp_path, monkeypatch
):
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["env"] = kwargs["env"]
        return completed(0, stdout="[]")

    monkeypatch.setenv("OS_COMPUTE_API_VERSION", "2.56")
    monkeypatch.setattr("neutron_flux.openstack.run_cancellable", fake_run)
    osc = OpenStack(Logger(tmp_path / "openstack.log"))
    osc.run("network", "list")
    assert captured["command"] == ["openstack", "network", "list"]
    assert "OS_COMPUTE_API_VERSION" not in captured["env"]


def test_neutron_segment_404_is_optional(config_factory):
    error = CommandError(
        ["openstack", "network", "segment", "list"],
        1,
        "",
        "NotFoundException: 404: The resource could not be found.",
    )
    osc = mock.Mock()
    osc.json.side_effect = error
    osc.is_unsupported_result.return_value = False
    discoverer = Discoverer(osc, mock.Mock(), config_factory(action="plan"))
    assert discoverer._network_segment_rows("network-1") is None


def test_required_resource_text_rejects_null_identifier():
    from neutron_flux.utils import required_text

    with pytest.raises(SuiteError, match="returned no usable id"):
        required_text({}, "id", context="Volume create")
    with pytest.raises(SuiteError, match="returned no usable id"):
        required_text({"id": None}, "id", context="Server create")


@pytest.mark.parametrize(
    "message",
    [
        "Connection refused",
        "Temporary failure in name resolution",
        "Remote end closed connection without response",
        "unexpected EOF",
        "Broken pipe",
    ],
)
def test_openstack_transport_failures_are_transient(message):
    assert OpenStack.is_transient_result(completed(1, stderr=message)) is True


def test_migration_record_selection_is_unverified_when_uuid_rows_are_ambiguous(
    config_factory,
):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder._migration_rows = lambda server_id: (
        [
            {
                "id": "old-uuid",
                "source_compute": "compute1",
                "dest_compute": "compute2",
                "migration_type": "resize",
                "status": "error",
            },
            {
                "id": "new-uuid",
                "source_compute": "compute1",
                "dest_compute": "compute2",
                "migration_type": "resize",
                "status": "confirmed",
            },
        ],
        None,
    )
    verified, reason, row = builder._verify_nova_migration_record(
        endpoint(), "compute1", "compute2", set()
    )
    assert verified is None
    assert "Multiple new Nova migration records cannot be correlated" in reason
    assert row == {}


@pytest.mark.parametrize("before_ids", [set(), {"old-uuid"}])
def test_migration_record_selection_requires_one_new_record_even_with_timestamps(
    config_factory, before_ids
):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder._migration_rows = lambda server_id: (
        [
            {
                "id": "old-uuid",
                "source_compute": "compute1",
                "dest_compute": "compute2",
                "migration_type": "resize",
                "status": "error",
                "updated_at": "2026-07-20T01:00:00Z",
            },
            {
                "id": "new-uuid",
                "source_compute": "compute1",
                "dest_compute": "compute2",
                "migration_type": "resize",
                "status": "confirmed",
                "updated_at": "2026-07-20T02:00:00Z",
            },
        ],
        None,
    )
    builder._json_with_transient_retry = mock.Mock(return_value=None)
    verified, reason, row = builder._verify_nova_migration_record(
        endpoint(), "compute1", "compute2", before_ids
    )
    if before_ids:
        assert verified is True
        assert reason is None
        assert row["id"] == "new-uuid"
    else:
        assert verified is None
        assert "Multiple new Nova migration records cannot be correlated" in reason
        assert row == {}


def test_exact_name_recovery_retries_transient_lookup(config_factory, monkeypatch):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder.logger = mock.Mock()
    builder.osc = mock.Mock()
    builder.osc.json.side_effect = [
        CommandTimeoutError(["openstack", "server", "show", "name"], 1),
        {"id": "server-1", "name": "name"},
    ]
    builder.osc.is_transient_exception.return_value = True
    monkeypatch.setattr("neutron_flux.resources.time.sleep", lambda _seconds: None)
    result = builder._recover_created_resource_by_name("server", "name", timeout=2)
    assert result["id"] == "server-1"
    assert builder.osc.json.call_count == 2


def test_confirmation_timeout_is_reconciled_as_remote_success(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder.logger = mock.Mock()
    builder.osc = mock.Mock()
    builder._migration_compute_api_prefix = ("--os-compute-api-version", "2.latest")
    builder.osc.run.side_effect = CommandTimeoutError(
        ["openstack", "server", "migration", "confirm"], 60
    )
    builder._json_with_transient_retry = mock.Mock(
        return_value={"status": "ACTIVE", "OS-EXT-SRV-ATTR:host": "compute2"}
    )
    assert builder._confirm_cold_migration(endpoint(), "compute2") is False


def test_cold_migration_request_timeout_reconciles_and_completes(config_factory):
    from neutron_flux.models import ComputeHostInfo

    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder.logger = mock.Mock()
    builder.reporter = mock.Mock()
    builder.probe_service = SimpleNamespace(stop=lambda endpoint: None)
    builder.osc = mock.Mock()
    builder._migration_compute_api_prefix = ("--os-compute-api-version", "2.latest")
    builder.osc.run.side_effect = CommandTimeoutError(
        ["openstack", "server", "migrate"], 60
    )
    builder._capture_endpoint_migration_state = lambda endpoint: {
        "server_id": endpoint.server_id,
        "source_host": "compute1",
        "source_availability_zone": "az1",
        "ports": {},
        "volume_ids": set(),
        "migration_ids": set(),
        "guest_marker": None,
    }
    builder._wait_for_migration_acceptance = lambda *args, **kwargs: {
        "accepted": True,
        "evidence": "test harness",
    }
    builder._wait_for_migration_handoff = lambda endpoint, target: (
        {"status": "VERIFY_RESIZE"},
        False,
    )
    builder._confirm_cold_migration = lambda endpoint, target: False
    builder._wait_for_status = lambda *args, **kwargs: "active"
    builder._wait_for_active_on_target = lambda endpoint, target: {
        "status": "ACTIVE",
        "OS-EXT-SRV-ATTR:host": "compute2",
        "OS-EXT-AZ:availability_zone": "az1",
        "OS-EXT-STS:task_state": None,
    }
    builder._verify_nova_migration_record = lambda *args, **kwargs: (
        True,
        None,
        {"id": "migration-1"},
    )
    builder._verify_migrated_ports = lambda *args, **kwargs: (True, {})
    builder._server_volume_ids = lambda server_id: set()
    builder._wait_for_ssh = lambda *args, **kwargs: True
    builder.reconfigure_endpoint = lambda endpoint: None

    moving = endpoint("moving", "B")
    result = builder._cold_migrate_endpoint_once(
        moving,
        ComputeHostInfo("compute2", "az1", True, True, {"agg"}, {"agg"}),
    )
    assert result.destination_host == "compute2"
    assert result.confirmed is True


def test_network_cleanup_uses_compute_port_attachment_guard(config_factory):
    manager = object.__new__(CleanupManager)
    manager.config = config_factory(action="cleanup")
    manager.logger = mock.Mock()
    manager.osc = mock.Mock()
    manager.osc.json.side_effect = [
        [{"id": "port-1"}],
        {
            "id": "port-1",
            "name": "attached",
            "device_owner": "compute:nova",
            "device_id": "server-1",
        },
        {
            "id": "port-1",
            "name": "attached",
            "device_owner": "compute:nova",
            "device_id": "server-1",
        },
    ]
    manager.osc.exists.return_value = True
    resource = ResourceRecord(
        1,
        "network",
        "network-1",
        "network-1",
        None,
        {},
        iso_utc(),
    )
    with pytest.raises(SuiteError, match="remains attached to existing server"):
        manager._delete_network(resource)
    manager.osc.run.assert_not_called()


def test_latest_state_tolerates_corrupt_checkpoint_vanishing_during_stat(
    tmp_path, monkeypatch
):
    store = StateStore(tmp_path / "reports")
    checkpoint = RunCheckpoint(
        run_id="valid",
        state="COMPLETED",
        action="run",
        phase="done",
        current_batch=None,
        started_at=iso_utc(),
        updated_at=iso_utc(),
        last_activity=iso_utc(),
        completed_test_ids=[],
        failed_test_ids=[],
        pending_test_ids=[],
        active_group_ids=[],
        manifest_path="manifest.jsonl",
        report_dir=str(tmp_path),
    )
    valid_path = store.state_path("valid")
    valid_path.parent.mkdir(parents=True, exist_ok=True)
    valid_path.write_text("{}", encoding="utf-8")
    corrupt = store.state_path("corrupt")
    store.list = lambda: [checkpoint]
    store.corrupt_state_files = [(corrupt, "truncated")]
    original_stat = Path.stat

    def safe_stat(path, *args, **kwargs):
        if path == corrupt:
            raise FileNotFoundError(path)
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", safe_stat)
    assert store.latest().run_id == "valid"


def test_prepare_logs_each_slow_prerequisite_phase(config_factory):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run")
    builder.logger = mock.Mock()
    builder.work_dir = Path("/tmp/nonexistent-neutron-flux-test-workdir")
    builder._resolve_image_flavor_user = mock.Mock()
    builder._select_run_availability_zone = mock.Mock()
    builder._prepare_neutron_placement = mock.Mock()
    builder._create_ssh_key = mock.Mock()
    builder._create_keypair = mock.Mock()
    builder._create_management_network = mock.Mock()
    builder._create_security_groups = mock.Mock()
    builder._create_controller = mock.Mock()
    builder.prepare()
    messages = [call.args[0] for call in builder.logger.log.call_args_list]
    assert any("Preparation step 1/6" in item for item in messages)
    assert any("Preparation step 2/6" in item for item in messages)
    assert any("Preparation step 5/6" in item for item in messages)
    assert any("Preparation step 6/6" in item for item in messages)


def test_launch_selection_rejects_host_disk_smaller_than_virtual_image(config_factory):
    config = config_factory(action="plan", storage="host")
    osc = mock.Mock()
    osc.json.side_effect = [
        {
            "id": "image-1",
            "name": "debian-13",
            "min_disk": 0,
            "virtual_size": 30 * 1024**3,
            "properties": {"os_admin_user": "debian"},
        },
        {"id": "flavor-1", "name": "x1.local", "ram": 1024, "vcpus": 1, "disk": 20},
    ]
    with pytest.raises(SuiteError, match="virtual_size=30 GiB"):
        resolve_launch_selection(config, osc, mock.Mock())


def test_security_group_rule_without_json_is_reconciled_not_recreated(
    config_factory, monkeypatch
):
    builder = object.__new__(ResourceBuilder)
    builder.config = config_factory(action="run", convergence_interval=0)
    builder.logger = mock.Mock()
    builder.osc = mock.Mock()
    rule = {
        "sg": "sg-1",
        "direction": "ingress",
        "family": 4,
        "protocol": "tcp",
        "port": 18082,
        "remote": "192.0.2.0/24",
    }
    builder.list_security_group_rules = mock.Mock(
        side_effect=[
            [],
            [
                {
                    "id": "rule-1",
                    "direction": "ingress",
                    "ethertype": "IPv4",
                    "protocol": "tcp",
                    "port_range_min": 18082,
                    "port_range_max": 18082,
                    "remote_ip_prefix": "192.0.2.0/24",
                }
            ],
        ]
    )
    monkeypatch.setattr("neutron_flux.resources.time.sleep", lambda _seconds: None)
    assert (
        builder._reconcile_created_security_group_rule(rule, index=1, total=1)
        == "rule-1"
    )
    builder.osc.run.assert_not_called()


@pytest.mark.parametrize(
    ("resource", "message"),
    [
        ("server", "No Server found for 11111111-1111-1111-1111-111111111111"),
        ("port", "No Port found for 22222222-2222-2222-2222-222222222222"),
        ("router", "No Router found for 33333333-3333-3333-3333-333333333333"),
        ("subnet", "No Subnet found for 44444444-4444-4444-4444-444444444444"),
        (
            "network",
            "Error while executing command: No Network found for "
            "55555555-5555-5555-5555-555555555555",
        ),
        ("volume", "No Volume found for 66666666-6666-6666-6666-666666666666"),
        (
            "security group",
            "No Security Group found for 77777777-7777-7777-7777-777777777777",
        ),
        (
            "security group",
            "Error while executing command: No SecurityGroup found for "
            "77777777-7777-7777-7777-777777777778",
        ),
        (
            "server group",
            "No Server Group found for 88888888-8888-8888-8888-888888888888",
        ),
        (
            "server group",
            "No ServerGroup found for 88888888-8888-8888-8888-888888888889",
        ),
        (
            "floating ip",
            "No Floating IP found for 99999999-9999-9999-9999-999999999999",
        ),
        (
            "floating ip",
            "No FloatingIP found for 99999999-9999-9999-9999-999999999998",
        ),
    ],
)
def test_osc_no_resource_found_for_is_confirmed_absence(resource, message):
    result = completed(1, stderr=message)
    assert OpenStack.is_not_found_result(result, expected_resource=resource) is True
    assert OpenStack.is_not_found_result(result) is True


def test_presence_accepts_osc_no_resource_found_for_wording(tmp_path):
    osc = OpenStack(Logger(tmp_path / "presence.log"))
    osc.run = mock.Mock(
        return_value=completed(
            1,
            stderr="Error while executing command: No Server found for server-1",
        )
    )
    result = osc.presence("server", "server-1")
    assert result.absent is True
    assert result.unknown is False
    osc.logger.close()


def test_no_resource_found_fix_does_not_hide_infrastructure_failures():
    service = completed(1, stderr="No service endpoint found for compute")
    volume_type = completed(1, stderr="No volume type with a name or ID of fast exists")
    assert OpenStack.is_not_found_result(service, expected_resource="server") is False
    assert (
        OpenStack.is_not_found_result(volume_type, expected_resource="volume") is False
    )


def test_cleanup_marks_osc_no_server_found_as_already_absent(config_factory, tmp_path):
    config = config_factory(report_dir=tmp_path / "reports", action="cleanup")
    reporter = Reporter(config, "cleanup-presence")
    tracker = ResourceTracker(reporter)
    record = tracker.add("server", "server-1", "server-one")
    osc = OpenStack(reporter.logger)
    osc.run = mock.Mock(
        return_value=completed(1, stderr="No Server found for server-1")
    )
    manager = CleanupManager(osc, reporter, tracker, config)
    handler = mock.Mock()
    manager._delete_record(record, handler)
    assert record.cleanup_state == "DELETED"
    assert record.delete_status == "already-absent"
    assert reporter.cleanup_summary["errors"] == []
    handler.assert_not_called()
    reporter.logger.close()


def test_cleanup_marks_concatenated_security_group_not_found_as_absent(
    config_factory, tmp_path
):
    config = config_factory(report_dir=tmp_path / "reports", action="cleanup")
    reporter = Reporter(config, "cleanup-security-group")
    tracker = ResourceTracker(reporter)
    record = tracker.add("security_group", "sg-1", "security-group-one")
    osc = OpenStack(reporter.logger)
    osc.run = mock.Mock(
        return_value=completed(
            1,
            stderr="Error while executing command: No SecurityGroup found for sg-1",
        )
    )
    manager = CleanupManager(osc, reporter, tracker, config)
    handler = mock.Mock()
    manager._delete_record(record, handler)
    assert record.cleanup_state == "DELETED"
    assert record.delete_status == "already-absent"
    assert reporter.cleanup_summary["errors"] == []
    handler.assert_not_called()
    reporter.logger.close()
