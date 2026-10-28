from __future__ import annotations

from unittest import mock

from neutron_flux.cleanup import CleanupManager
from neutron_flux.reporting import Reporter, ResourceTracker


def test_exact_orphan_adoption_rejects_prefix_collision_with_other_run_metadata(
    config_factory, tmp_path
):

    config = config_factory(report_dir=tmp_path / "reports", action="cleanup")
    reporter = Reporter(config, "flux-20260723010101-aaaaaa")
    tracker = ResourceTracker(reporter)
    osc = mock.Mock()

    def json_response(*args, **kwargs):
        if args == ("server", "list"):
            return [{"ID": "server-other", "Name": f"{reporter.name_prefix}-endpoint"}]
        if args == ("server", "show", "server-other"):
            return {
                "id": "server-other",
                "name": f"{reporter.name_prefix}-endpoint",
                "properties": {"neutron_flux_run_id": "flux-20260723010101-bbbbbb"},
            }
        return []

    osc.json.side_effect = json_response
    manager = CleanupManager(osc, reporter, tracker, config)
    try:
        adopted = manager._adopt_orphans(reporter.run_tag, reporter.name_prefix)
        assert adopted == 0
        assert reporter.resources == []
    finally:
        reporter.logger.close()


def test_exact_orphan_adoption_uses_server_metadata_when_name_differs(
    config_factory, tmp_path
):

    config = config_factory(report_dir=tmp_path / "reports", action="cleanup")
    reporter = Reporter(config, "flux-20260723010101-cccccc")
    tracker = ResourceTracker(reporter)
    osc = mock.Mock()

    def json_response(*args, **kwargs):
        if args == ("server", "list"):
            return [{"ID": "server-exact", "Name": "renamed-server"}]
        if args == ("server", "show", "server-exact"):
            return {
                "id": "server-exact",
                "name": "renamed-server",
                "properties": {"neutron_flux_run_id": reporter.run_id},
            }
        return []

    osc.json.side_effect = json_response
    manager = CleanupManager(osc, reporter, tracker, config)
    try:
        adopted = manager._adopt_orphans(reporter.run_tag, reporter.name_prefix)
        assert adopted == 1
        assert [(item.resource_type, item.id) for item in reporter.resources] == [
            ("server", "server-exact")
        ]
        assert reporter.resources[0].metadata["discovered_by"] == "exact-run-metadata"
    finally:
        reporter.logger.close()
