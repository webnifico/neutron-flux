from __future__ import annotations

from types import SimpleNamespace

from neutron_flux.cli import parser
from neutron_flux.config import Config
from neutron_flux.reporting_components.html import build_run_payload, render_html
from neutron_flux.resources import ResourceBuilder


def _args(*extra: str):
    return parser().parse_args(
        [
            "run",
            "--image",
            "debian-13",
            "--flavor",
            "x1.nano",
            "--storage",
            "host",
            "--external-networks",
            "Public1",
            *extra,
        ]
    )


def test_host_storage_defaults_to_live_migration_with_cold_fallback():
    config = Config.from_args(_args())
    assert config.migration_mode == "live-preferred"
    assert config.migration_storage == "auto"
    assert config.effective_migration_storage == "host"
    assert config.live_migration_attempts == 5
    assert config.cold_migration_fallback is True
    assert config.live_migration_continuity is True


def test_auto_storage_derives_transport_from_flux_boot_contract(config_factory):
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.config = config_factory(storage="host", migration_storage="auto")
    assert builder.config.effective_migration_storage == "host"
    assert builder._live_migration_storage_args() == ["--block-migration"]

    builder.config = config_factory(storage="volume", migration_storage="auto")
    assert builder.config.effective_migration_storage == "shared"
    assert builder._live_migration_storage_args() == ["--shared-migration"]


def test_matching_explicit_migration_storage_remains_authoritative(config_factory):
    host_boot = config_factory(storage="host", migration_storage="host")
    volume_boot = config_factory(storage="volume", migration_storage="shared")
    assert host_boot.effective_migration_storage == "host"
    assert volume_boot.effective_migration_storage == "shared"


def test_cold_only_override_still_disables_live_strategy():
    config = Config.from_args(_args("--migration-mode", "cold"))
    assert config.migration_mode == "cold-only"


def test_explicit_live_preferred_retains_continuity_and_cold_fallback():
    config = Config.from_args(_args("--migration-mode", "live"))
    assert config.migration_mode == "live-preferred"
    assert config.live_migration_attempts == 5
    assert config.cold_migration_fallback is True
    assert config.live_migration_continuity is True


def test_report_records_configured_and_effective_migration_storage(
    config_factory, tmp_path
):
    from datetime import datetime, timezone

    config = config_factory(
        action="run",
        report_dir=tmp_path / "reports",
        storage="host",
        migration_mode="live-preferred",
        migration_storage="auto",
    )
    reporter = SimpleNamespace(
        results=[],
        discovery=None,
        config=config,
        run_id="run-sample",
        action="run",
        started=datetime(2026, 7, 23, tzinfo=timezone.utc),
        run_tag="tag",
        name_prefix="flux-tag",
        setup_failed=False,
        interrupted=False,
        cleanup_summary={"complete": True},
        setup_failures=[],
        error=None,
        plan=None,
        resources=[],
        events=[],
        traceback=None,
    )
    from collections import Counter

    payload = build_run_payload(
        reporter,
        finished=datetime(2026, 7, 23, 0, 1, tzinfo=timezone.utc),
        final_status="PASS",
        counts=Counter(),
    )
    migration = payload["configuration"]["migration"]
    assert migration["mode"] == "live-preferred"
    assert migration["storage"] == "auto"
    assert migration["effective_storage"] == "host"
    rendered = render_html(payload)
    assert "effective_storage" in rendered
    assert "Migration storage" in rendered
