from __future__ import annotations

import dataclasses
import json
import re
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.engine import TestEngine as FluxTestEngine
from neutron_flux.errors import RunCancelledError, SSHExecutionError
from neutron_flux.models import RuntimeGroup
from neutron_flux.operator_evidence import evidence_facts
from neutron_flux.reporting import Reporter
from neutron_flux.runtime.probes import ProbeRuntimeMixin

from ._shared import endpoint
from .test_diagnostics_and_measurement_classification import _spec


class _Runtime(ProbeRuntimeMixin):
    def _ssh_base(self, address, *, proxy):
        return ["ssh", address]


def _runtime(config):
    runtime = _Runtime()
    runtime.config = config
    runtime.control_address = "192.0.2.100"
    runtime.controller_command_address = "10.48.0.1"
    runtime.controller_via_proxy = True
    runtime.osc = SimpleNamespace(
        json=mock.Mock(return_value={}),
        run=mock.Mock(return_value=subprocess.CompletedProcess([], 0, "console", "")),
    )
    runtime.inspect_endpoint_route = mock.Mock()
    return runtime


@pytest.mark.parametrize(
    "stage,started,completed,remote_status",
    [
        ("ssh-command-launched", False, False, None),
        ("remote-command-started", True, False, None),
        ("remote-command-completed", True, True, 1),
    ],
)
def test_ssh_timeout_retains_last_observed_remote_stage(
    config_factory, monkeypatch, stage, started, completed, remote_status
):
    runtime = _runtime(config_factory())
    command = "ping -4 -n -c 3 -W 2 -I 192.0.2.10 192.0.2.11"
    calls = []

    def timeout(args, **kwargs):
        calls.append((args, kwargs))
        marker = re.search(r"NFLUX_SSH_[0-9a-f]+", args[-1])[0]
        stderr = "partial SSH error"
        if started:
            stderr = f"\n{marker}:started\n" + stderr
        if completed:
            stderr += f"\n{marker}:completed:{remote_status}\n"
        raise subprocess.TimeoutExpired(
            args,
            kwargs["timeout"],
            output=b"partial ping output\n",
            stderr=stderr.encode(),
        )

    monkeypatch.setattr("neutron_flux.runtime.probes.run_cancellable", timeout)
    source = endpoint()
    with pytest.raises(SSHExecutionError) as caught:
        runtime.ssh_endpoint(source, command)
    evidence = caught.value.evidence
    assert len(calls) == 1
    assert calls[0][1]["timeout"] == 120
    assert evidence["controller_address"] == runtime.control_address
    assert evidence["command"] == command
    assert evidence["stdout"] == "partial ping output\n"
    assert evidence["stderr"] == "partial SSH error"
    assert evidence["last_observed_stage"] == stage
    assert evidence["remote_command_started"] is started
    assert evidence["remote_command_completed"] is completed
    assert evidence["remote_returncode"] == remote_status
    assert evidence["endpoint"]["server_id"] == source.server_id
    assert evidence["endpoint"]["compute_host"] == source.host


@pytest.mark.parametrize(
    "command,code,stdout,stderr",
    [
        ("printf 'out'; printf 'err' >&2; exit 7", 7, "out", "err"),
        ("set -e; false; printf 'must not run'", 1, "", ""),
        ("cat <<'END'\n$literal `literal`\nEND", 0, "$literal `literal`\n", ""),
        ("printf '\\nline\\n' >&2", 0, "", "\nline\n"),
    ],
)
def test_remote_progress_preserves_command_output_and_exit_status(
    config_factory, command, code, stdout, stderr
):
    runtime = _runtime(config_factory())
    runtime._ssh_base = lambda *args, **kwargs: ["/bin/sh", "-c"]
    result = runtime._run_ssh_command("unused", command, proxy=False)
    assert (result.returncode, result.stdout, result.stderr) == (code, stdout, stderr)


def test_functional_timeout_report_preserves_path_and_command(
    config_factory, monkeypatch
):
    config = config_factory(action="run")
    source = endpoint("source")
    destination = dataclasses.replace(
        endpoint("destination"),
        fixed_ips={"s4": "192.0.2.11"},
        management_ip="10.254.0.11",
        host="compute2",
        availability_zone="az2",
    )
    builder = _runtime(config)
    destination_builder = _runtime(config)
    destination_builder.control_address = "192.0.2.101"
    destination_builder.ssh_endpoint = mock.Mock(
        return_value=subprocess.CompletedProcess([], 0, "destination routes", "")
    )
    builder.runtime_groups = [
        RuntimeGroup(
            SimpleNamespace(id=label), "net", "network", ["s4"], None, [ep], None, {}
        )
        for label, ep in (("source", source), ("destination", destination))
    ]
    command = "ping -4 -n -c 3 -W 2 -I 192.0.2.10 192.0.2.11"
    attempts = []

    def run(args, **kwargs):
        attempts.append((args, kwargs))
        if command in args[-1]:
            marker = re.search(r"NFLUX_SSH_[0-9a-f]+", args[-1])
            stderr = "partial transport error"
            if marker:
                stderr = f"\n{marker[0]}:started\n" + stderr
            raise subprocess.TimeoutExpired(
                args,
                120,
                output=b"PING partial\n",
                stderr=stderr.encode(),
            )
        return subprocess.CompletedProcess(args, 0, "diagnostics", "")

    monkeypatch.setattr("neutron_flux.runtime.probes.run_cancellable", run)
    reporter = Reporter(config, "functional-ssh-timeout")
    try:
        engine = FluxTestEngine(
            config,
            SimpleNamespace(),
            builder,
            reporter,
            diagnostic_builders={destination.server_id: destination_builder},
        )
        spec = dataclasses.replace(
            _spec("CROSS-ZONE-ICMP"),
            protocol="icmp",
            source_subnet_id="s4",
            destination_subnet_id="s4",
        )
        engine.run_specs([spec])
        result = reporter.get_result(spec.id)
        assert result.status == "ERROR"
        assert result.likely_failure == "CONTROL_SSH"
        assert result.source == "source (192.0.2.10)"
        assert result.destination == "destination (192.0.2.11)"
        assert result.details["source_compute_host"] == "compute1"
        assert result.details["destination_compute_host"] == "compute2"
        assert result.details["source_server_id"] == source.server_id
        assert result.details["destination_server_id"] == destination.server_id
        assert result.details["source_management_ip"] == source.management_ip
        assert result.details["probe"]["command"] == command
        assert result.details["probe"]["stdout"] == "PING partial\n"
        error = result.details["execution_error"]
        assert error["stderr"] == "partial transport error"
        assert error["last_observed_stage"] == "remote-command-started"
        facts = {
            item["label"]: item["value"]
            for item in evidence_facts(dataclasses.asdict(result))
        }
        assert (
            facts["Last observed SSH stage"]
            == "Remote command started; completion not observed"
        )
        assert result.message.count("SSH command timed out") == 1
        assert sum(command in args[-1] for args, _ in attempts) == 1
        builder.inspect_endpoint_route.assert_not_called()
        destination_builder.ssh_endpoint.assert_called_once()
        assert destination_builder.ssh_endpoint.call_args.args[0] is destination
        for args, kwargs in attempts:
            if command not in args[-1]:
                assert 0 < kwargs["timeout"] <= 5
        stored = json.loads(
            Path(result.details["execution_diagnostics_file"]).read_text()
        )
        assert stored["endpoints"][destination.server_id]["compute_host"] == "compute2"
    finally:
        reporter.logger.close()


def test_failed_floating_ip_check_keeps_public_destination(config_factory):
    config = config_factory(action="run")
    target = endpoint("target")
    builder = _runtime(config)
    builder.runtime_groups = [
        RuntimeGroup(
            SimpleNamespace(id="destination"),
            "net",
            "network",
            ["s4"],
            None,
            [target],
            None,
            {target.label: {"address": "198.51.100.20"}},
        )
    ]
    reporter = Reporter(config, "functional-fip-timeout")
    try:
        engine = FluxTestEngine(config, SimpleNamespace(), builder, reporter)
        engine._run_spec = mock.Mock(side_effect=SSHExecutionError("SSH timed out"))
        engine.diagnostics = SimpleNamespace(collect=lambda *args: ("CONTROL_SSH", {}))
        spec = dataclasses.replace(_spec("FIP"), operation="fip-baseline")
        engine._run_one(spec)
        result = reporter.get_result(spec.id)
        assert result.destination == "target (198.51.100.20)"
        assert result.details["destination_server_id"] == target.server_id
    finally:
        reporter.logger.close()


def test_missing_runtime_and_cancellation_do_not_invent_endpoint_evidence(
    config_factory,
):
    config = config_factory(action="run")
    builder = _runtime(config)
    builder.runtime_groups = []
    reporter = Reporter(config, "functional-missing-runtime")
    try:
        engine = FluxTestEngine(config, SimpleNamespace(), builder, reporter)
        engine._run_one(_spec("MISSING"))
        result = reporter.get_result("MISSING")
        assert result.status == "ERROR"
        assert result.source is None and result.destination is None
        assert result.details["probe"]["command"] == ""
        assert "runtime group" in result.details["execution_error"]["message"]
        builder.osc.json.assert_not_called()
        engine._run_spec = mock.Mock(side_effect=RunCancelledError("cancelled"))
        with pytest.raises(RunCancelledError):
            engine._run_one(_spec("CANCELLED"))
        assert reporter.get_result("CANCELLED") is None
    finally:
        reporter.logger.close()
