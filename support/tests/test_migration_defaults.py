from __future__ import annotations

from neutron_flux.cli import parser
from neutron_flux.config import Config


def _run_args(*extra: str):
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


def test_live_migration_defaults_include_cold_fallback():
    config = Config.from_args(_run_args())

    assert config.migration_mode == "live-preferred"
    assert config.migration_storage == "auto"
    assert config.live_migration_attempts == 5
    assert config.cold_migration_fallback is True
    assert config.live_migration_continuity is True
