from __future__ import annotations

import copy
import json
import os
import re
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from neutron_flux.discovery import Discoverer
from neutron_flux.errors import CommandTimeoutError
from neutron_flux.reporting_components.html import render_html
from neutron_flux.reporting_components.manual_reproduction import manual_reproduction
from support.tests.test_report_workflow import _payload

from .evidence import expand_evidence


def embedded(html):
    return expand_evidence(
        json.loads(
            re.search(
                r'<script id="run-data" type="application/json">(.*?)</script>',
                html,
                re.S,
            )[1]
        )
    )


@pytest.mark.parametrize(
    "status",
    [
        "PASS",
        "FAIL",
        "ERROR",
        "UNVERIFIED",
        "BLOCKED_BY_SETUP_ERROR",
        "BLOCKED_BY_PREREQUISITE",
        "NOT_RUN_CANCELLED",
        "NOT_APPLICABLE",
    ],
)
def test_manual_guide_for_every_result_status_preserves_record(status):
    payload = _payload()
    payload["results"][0]["status"] = status
    payload["results"][0]["details"]["probe"]["command"] = (
        "ping -4 -n -c 3 -I 10.0.3.107 10.0.4.107"
    )
    before = copy.deepcopy(payload)
    result = embedded(render_html(payload))["dashboard"]["results"][0]
    assert result["status"] == status
    assert (
        result["manual_reproduction"]["commands"][0]["command"]
        == payload["results"][0]["details"]["probe"]["command"]
    )
    assert "one test router" in " ".join(result["manual_reproduction"]["setup"])
    assert "same provider subnet" not in " ".join(
        result["manual_reproduction"]["setup"]
    )
    assert payload == before


def test_manual_commands_preserve_argv_quoting_and_supporting_operations():
    guide = manual_reproduction(
        {
            "category": "security-group",
            "family": 4,
            "details": {
                "before": {"command": ["python3", "-c", "print('quoted value')"]},
                "after": {"command": "ping -c 3 192.0.2.2"},
                "failure_phase": "rule-change",
                "exception_message": "rule was rejected",
            },
        }
    )
    assert len(guide["commands"]) == 2
    import shlex

    assert shlex.split(guide["commands"][0]["command"]) == [
        "python3",
        "-c",
        "print('quoted value')",
    ]
    assert guide["changes_state"]
    assert "Restore the saved rules" in guide["restore"][0]
    assert guide["failure"]["exception_message"] == "rule was rejected"


def test_missing_or_long_commands_never_become_copyable_inventions():
    guide = manual_reproduction(
        {"category": "egress", "status": "BLOCKED_BY_SETUP_ERROR", "details": {}}
    )
    assert not guide["commands"]
    assert "No exact shell command" in guide["missing"][0]
    long = manual_reproduction({"details": {"command": "x" * 32001}})
    assert not long["commands"]
    assert "long command" in long["missing"][0]


def test_region_comes_from_recorded_discovery_not_cloud_or_render_environment(
    monkeypatch,
):
    payload = _payload()
    monkeypatch.setenv("OS_REGION_NAME", "render-machine-region")
    payload["discovery"]["cloud"] = "profile-not-region"
    assert (
        embedded(render_html(payload))["dashboard"]["environment"]["region_name"]
        is None
    )
    payload["discovery"]["region_name"] = "RegionEast"
    result = embedded(render_html(payload))
    assert result["dashboard"]["environment"]["region_name"] == "RegionEast"
    assert result["dashboard"]["environment"]["cloud"] == "profile-not-region"


def test_region_discovery_requests_only_region_column_and_falls_back(monkeypatch):
    monkeypatch.setenv("OS_REGION_NAME", "environment-region")
    osc = Mock()
    osc.run.return_value = subprocess.CompletedProcess(
        [], 0, json.dumps({"region_name": "profile-region"}), ""
    )
    discoverer = Discoverer(osc, Mock())
    assert discoverer._region_name() == "profile-region"
    osc.run.assert_called_once_with(
        "configuration",
        "show",
        "-c",
        "region_name",
        "-f",
        "json",
        check=False,
        timeout=15,
    )
    osc.run.side_effect = CommandTimeoutError(
        ["openstack", "configuration", "show"], 15
    )
    assert discoverer._region_name() == "environment-region"
    monkeypatch.delenv("OS_REGION_NAME")
    assert discoverer._region_name() is None


def test_report_browser_workflow(tmp_path: Path):
    available = subprocess.run(
        ["node", "-e", "require('jsdom')"], capture_output=True, check=False
    )
    if available.returncode:
        pytest.skip(
            "Install jsdom or set NODE_PATH to run the optional DOM interaction checks"
        )
    payload = _payload()
    first = payload["results"][0]
    first["details"]["probe"]["command"] = "ping -4 -n -c 3 -I 10.0.3.107 10.0.4.107"
    second = copy.deepcopy(first)
    second.update(test_id="SECOND-TEST", status="FAIL")
    third = copy.deepcopy(first)
    third.update(test_id="ERROR-TEST", status="ERROR", message="API operation failed")
    third["details"] = {
        "exception_message": "API operation failed",
        "operation": "router update",
    }
    cancelled = copy.deepcopy(third)
    cancelled.update(test_id="CANCELLED-TEST", status="NOT_RUN_CANCELLED")
    inapplicable = copy.deepcopy(third)
    inapplicable.update(test_id="INAPPLICABLE-TEST", status="NOT_APPLICABLE")
    isolated = copy.deepcopy(first)
    isolated.update(
        test_id="EXPECTED-WITHDRAWAL",
        category="server-lifecycle",
        expected="withdrawn",
        observed="blocked",
        message="endpoint service reachability follows the Nova server state",
    )
    isolated["details"]["probe"]["stdout"] = "Destination unreachable: No route"
    no_route_failure = copy.deepcopy(isolated)
    no_route_failure.update(
        test_id="UNEXPECTED-NO-ROUTE", status="FAIL", expected="reachable"
    )
    payload["results"] = [
        first,
        second,
        third,
        cancelled,
        inapplicable,
        isolated,
        no_route_failure,
    ]
    report = tmp_path / "report.html"
    report.write_text(render_html(payload))
    completed = subprocess.run(
        ["node", str(Path(__file__).with_name("report_workflow_dom.cjs")), str(report)],
        capture_output=True,
        text=True,
        env=os.environ.copy(),
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
