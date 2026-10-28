from __future__ import annotations

import subprocess
from types import SimpleNamespace

from neutron_flux.models import Endpoint
from neutron_flux.models import TestSpec as FluxTestSpec
from neutron_flux.performance import PerformanceRunner


def _endpoint(label, side, address, host):
    return Endpoint(
        label,
        "server-" + label,
        "server-" + label,
        "mgmt-" + label,
        address,
        "port-" + label,
        "fa:16:3e:00:00:01",
        {"subnet": address},
        host,
        "az1",
        None,
        side=side,
    )


def test_successful_measurement_retains_commands_options_and_execution_stage(
    config_factory,
):
    from unittest import mock

    from neutron_flux.performance import PerformancePath, ResolvedPerformancePath
    from neutron_flux.utils import iso_utc

    source = _endpoint("a", "A", "192.0.2.10", "compute1")
    destination = _endpoint("b", "B", "192.0.2.11", "compute2")
    reporter = mock.Mock()
    runner = PerformanceRunner(
        config_factory(),
        SimpleNamespace(
            ssh_endpoint=lambda *args, **kwargs: subprocess.CompletedProcess(
                [], 0, '{"mbps":12.5}', ""
            )
        ),
        reporter,
        SimpleNamespace(),
    )
    beginning = iso_utc()
    sample = runner._run_json(
        source,
        "SOURCE = '192.0.2.10'\nDESTINATION = '192.0.2.11'\nPORT = 18080\nDURATION = 3\nSTREAMS = 4\nprint('{}')",
        timeout=15,
    )
    runner._measurement_timings = {
        "tcp-throughput": {
            "started_at": beginning,
            "finished_at": iso_utc(),
            "duration_ms": 1,
        }
    }
    path = ResolvedPerformancePath(
        PerformancePath(
            "path",
            "source",
            "same-subnet",
            4,
            "group",
            "group",
            "A",
            "B",
            "subnet",
            "subnet",
            "group-local",
        ),
        source,
        destination,
        "192.0.2.10",
        "192.0.2.11",
        1500,
        1500,
        "inter",
        "same-zone",
    )
    spec = FluxTestSpec(
        id="PERF",
        category="network-performance",
        operation="performance-tcp-throughput",
        family=4,
        expectation="measured",
        expectation_reason="eligible path",
        authoritative=True,
        dependencies=["group"],
        metadata={
            "performance_measurement": "tcp-throughput",
            "execution_stage": "post-live-migration",
        },
    )
    runner._record_measurement(
        spec,
        path,
        {
            "health": "good",
            "metrics": {
                "forward": {"streams": {"1": {"median_mbps": 12.5, "runs": [sample]}}}
            },
        },
        started=0,
    )
    details = reporter.result.call_args.kwargs["details"]
    assert details["execution_stage"] == "post-live-migration"
    assert details["command_evidence"][0]["options"]["streams"] == 4
    assert details["command_evidence"][0]["server_id"] == source.server_id
    assert sample["execution_evidence"]["options"]["destination"] == "192.0.2.11"
    assert sample["mbps"] == 12.5
