from __future__ import annotations

from neutron_flux.constants import RELEASE_IDENTIFIER

from ._shared import *  # noqa: F403, F405


def test_branding_and_version():
    assert TOOL_NAME == "neutron-flux"
    assert VERSION
    assert RELEASE_STAGE in {"release candidate", "stable"}
    assert DISPLAY_VERSION == f"{RELEASE_IDENTIFIER} ({RELEASE_STAGE})"


def test_cli_has_commands_and_required_launch_flags():
    p = parser()
    for command in ("plan", "run", "status", "cleanup"):
        assert p.parse_args([command]).action == command
    assert p.parse_args([]).action == "run"
    parsed = p.parse_args(
        [
            "run",
            "--image",
            "debian-13",
            "--flavor",
            "x1.nano",
            "--storage",
            "volume",
            "--volume-type",
            "ceph",
            "--external-networks",
            "Public1,Public2",
        ]
    )
    assert parsed.image == "debian-13"
    assert parsed.flavor == "x1.nano"
    assert parsed.storage == "volume"
    assert parsed.volume_type == "ceph"
    assert parsed.external_networks == "Public1,Public2"


def test_cli_rejects_operational_flags():
    with pytest.raises(SystemExit):
        parser().parse_args(["run", "--availability-zone", "az1"])
    with pytest.raises(SystemExit):
        parser().parse_args(["run", "--test-profile", "exhaustive"])


def test_plan_and_run_require_image_flavor_storage_and_networks(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NEUTRON_FLUX_CONFIG", raising=False)
    with pytest.raises(
        SuiteError, match="--image, --flavor, --storage, --external-networks"
    ):
        Config.from_args(argparse.Namespace(action="run"))


def test_status_and_cleanup_do_not_require_launch_inputs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NEUTRON_FLUX_CONFIG", raising=False)
    status = Config.from_args(argparse.Namespace(action="status"))
    cleanup = Config.from_args(argparse.Namespace(action="cleanup"))
    assert status.image is None and status.storage is None
    assert cleanup.flavor is None and cleanup.storage is None


def test_host_storage_rejects_volume_only_options(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SuiteError, match="--volume-type requires --storage volume"):
        Config.from_args(required_args("run", volume_type="ceph"))


def test_config_defaults_to_unconstrained_az_and_static_ipv6(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NEUTRON_FLUX_CONFIG", raising=False)
    config = Config.from_args(required_args())
    assert config.availability_zones == []
    assert config.storage == "host"
    assert config.max_active_endpoints == 2
    assert config.ipv6_targets == ["2606:4700:4700::1111"]


def test_cli_network_list_is_required_and_parsed(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NEUTRON_FLUX_CONFIG", raising=False)
    config = Config.from_args(
        required_args(external_networks=" Public1,Public2,Public1 ")
    )
    assert config.external_networks == ["Public1", "Public2"]
    assert config.exclude_external_networks == []
    assert config.input_sources["networks"] == "CLI"


def test_cli_network_list_rejects_empty_entries(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SuiteError, match="non-empty comma-separated values"):
        Config.from_args(required_args(external_networks="Public1,,Public2"))


def test_result_statuses_have_no_informational_class():
    assert not any(status.startswith("INFORMATIONAL") for status in RESULT_STATUSES)


def test_external_network_allowlist_accepts_names_and_uuids_in_config_order(
    config_factory,
):
    config = config_factory(
        external_networks=["Public3", "n1", "Public3"],
        exclude_external_networks=[],
    )
    discoverer, _, logger = _selection_discoverer(config)
    selected = discoverer._select_external_network_rows(_external_selection_rows())
    assert [row["ID"] for row in selected] == ["n3", "n1"]
    assert any("explicit list" in call.args[0] for call in logger.log.call_args_list)


def test_external_network_exclusion_is_rejected(config_factory):
    config = config_factory(
        external_networks=[],
        exclude_external_networks=["Public2"],
    )
    discoverer, _, _ = _selection_discoverer(config)
    with pytest.raises(SuiteError, match="exclusion-only selection is not supported"):
        discoverer._select_external_network_rows(_external_selection_rows())


def test_external_network_selection_rejects_missing_reference(config_factory):
    config = config_factory(
        external_networks=["DoesNotExist"],
        exclude_external_networks=[],
    )
    discoverer, _, _ = _selection_discoverer(config)
    with pytest.raises(SuiteError, match="was not found"):
        discoverer._select_external_network_rows(_external_selection_rows())


def test_external_network_selection_rejects_ambiguous_name(config_factory):
    config = config_factory(
        external_networks=["Duplicate"],
        exclude_external_networks=[],
    )
    all_rows = [
        *_external_selection_rows(),
        {"ID": "n4", "Name": "Duplicate"},
        {"ID": "n5", "Name": "Duplicate"},
    ]
    external_rows = [
        *_external_selection_rows(),
        {"ID": "n4", "Name": "Duplicate"},
        {"ID": "n5", "Name": "Duplicate"},
    ]
    discoverer, _, _ = _selection_discoverer(config, all_rows=all_rows)
    with pytest.raises(SuiteError, match="ambiguous"):
        discoverer._select_external_network_rows(external_rows)


def test_external_network_selection_rejects_non_external_network(config_factory):
    config = config_factory(
        external_networks=["PrivateNetwork"],
        exclude_external_networks=[],
    )
    all_rows = [
        *_external_selection_rows(),
        {"ID": "private", "Name": "PrivateNetwork"},
    ]
    discoverer, _, _ = _selection_discoverer(config, all_rows=all_rows)
    with pytest.raises(SuiteError, match="is not external"):
        discoverer._select_external_network_rows(_external_selection_rows())


def test_external_network_selection_requires_explicit_list(config_factory):
    config = config_factory(
        external_networks=[],
        exclude_external_networks=[],
    )
    discoverer, _, _ = _selection_discoverer(config)
    with pytest.raises(
        SuiteError, match="No external networks were explicitly selected"
    ):
        discoverer._select_external_network_rows(_external_selection_rows())


def test_failure_injection_is_config_only_and_named(config_factory):
    config = config_factory(failure_injection="before-controller-create,after-planning")
    with pytest.raises(SuiteError, match="before-controller-create"):
        inject_failure(config, "before-controller-create")
    inject_failure(config, "before-server-delete")
