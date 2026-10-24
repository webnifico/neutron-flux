from __future__ import annotations

import signal
from contextlib import nullcontext
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux import cli
from neutron_flux.constants import EXIT_EXECUTION_ERROR, EXIT_UNSUPPORTED_TOPOLOGY
from neutron_flux.errors import SuiteError, UnsupportedTopologyError


class _Logger:
    def __init__(self):
        self.lines = []

    def section(self, message):
        self.lines.append(("section", message))

    def log(self, message, level="INFO"):
        self.lines.append((level, message))


class _StateStore:
    def __init__(self, report_dir):
        self.report_dir = report_dir
        self.saved = []
        self.corrupt_state_files = []

    def save(self, checkpoint):
        self.saved.append(checkpoint)

    def latest(self, **kwargs):
        return SimpleNamespace(run_id="existing-run", action="cleanup", state="FAILED")

    def print_status(self, checkpoint):
        return f"status:{checkpoint.run_id}"

    def lock(self, run_id):
        return nullcontext()

    def cloud_operation_lock(self):
        return nullcontext()


class _Reporter:
    def __init__(self, config, run_id, load_existing=False):
        self.config = config
        self.run_id = run_id
        self.run_dir = config.report_dir / "runs" / run_id
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.run_dir / "manifest.jsonl"
        self.manifest_path.touch()
        self.logger = _Logger()
        self.results = []
        self.setup_failed = False
        self.setup_failures = []
        self.error = None
        self.interrupted = False
        self.cleanup_summary = {
            "attempted": False,
            "complete": None,
            "errors": [],
            "leftovers": [],
        }
        self.finalized_with = None

    def set_error(self, exc):
        self.error = str(exc)

    def finalize(self, code):
        self.finalized_with = code
        return code


class _Suite:
    execute_result = 0
    execute_error = None
    cleanup_result = True
    cleanup_error = None
    instances = []

    def __init__(self, config, reporter, state_store, checkpoint):
        self.config = config
        self.reporter = reporter
        self.state_store = state_store
        self.checkpoint = checkpoint
        self.__class__.instances.append(self)

    def execute(self):
        if self.execute_error:
            raise self.execute_error
        return self.execute_result

    def cleanup_if_required(self, successful):
        self.cleanup_success_argument = successful
        if self.cleanup_error:
            raise self.cleanup_error
        return self.cleanup_result


@pytest.fixture(autouse=True)
def _reset_suite():
    _Suite.execute_result = 0
    _Suite.execute_error = None
    _Suite.cleanup_result = True
    _Suite.cleanup_error = None
    _Suite.instances = []


def _patch_runtime(monkeypatch, config):
    monkeypatch.setattr(cli.Config, "from_args", mock.Mock(return_value=config))
    monkeypatch.setattr(cli, "StateStore", _StateStore)
    monkeypatch.setattr(cli, "Reporter", _Reporter)
    monkeypatch.setattr(cli, "Suite", _Suite)
    monkeypatch.setattr(cli.signal, "signal", lambda *args: None)


def test_cli_status_prints_latest_checkpoint(
    config_factory, tmp_path, monkeypatch, capsys
):
    config = config_factory(action="status", report_dir=tmp_path / "reports")
    _patch_runtime(monkeypatch, config)

    assert cli.main(["status"]) == 0
    assert capsys.readouterr().out.strip() == "status:existing-run"


def test_cli_config_errors_preserve_unsupported_topology_exit(monkeypatch, capsys):
    monkeypatch.setattr(
        cli.Config,
        "from_args",
        mock.Mock(side_effect=UnsupportedTopologyError("unsupported topology")),
    )
    assert cli.main(["plan"]) == EXIT_UNSUPPORTED_TOPOLOGY
    assert "unsupported topology" in capsys.readouterr().err


def test_cli_config_errors_use_execution_exit(monkeypatch):
    monkeypatch.setattr(
        cli.Config,
        "from_args",
        mock.Mock(side_effect=SuiteError("invalid configuration")),
    )
    assert cli.main(["plan"]) == EXIT_EXECUTION_ERROR


def test_cli_plan_success_skips_resource_cleanup(config_factory, tmp_path, monkeypatch):
    config = config_factory(action="plan", report_dir=tmp_path / "reports")
    _patch_runtime(monkeypatch, config)

    assert cli.main(["plan"]) == 0
    instance = _Suite.instances[-1]
    assert not hasattr(instance, "cleanup_success_argument")
    assert instance.checkpoint.state == "COMPLETED"
    launch_line = next(
        message
        for _level, message in instance.reporter.logger.lines
        if message.startswith("Launch inputs:")
    )
    assert "migration=cold-only," in launch_line
    assert "cold-only/block" not in launch_line


def test_cli_run_failure_still_invokes_cleanup(config_factory, tmp_path, monkeypatch):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    _patch_runtime(monkeypatch, config)
    _Suite.execute_error = RuntimeError("run exploded")

    assert cli.main(["run"]) == EXIT_EXECUTION_ERROR
    instance = _Suite.instances[-1]
    assert instance.cleanup_success_argument is False
    assert instance.checkpoint.state == "FAILED"


def test_cli_cleanup_incomplete_overrides_success_exit(
    config_factory, tmp_path, monkeypatch
):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    _patch_runtime(monkeypatch, config)
    _Suite.cleanup_result = False

    assert cli.main(["run"]) == 3
    assert _Suite.instances[-1].checkpoint.cleanup_state == "NOT_STARTED"


def test_cli_cleanup_exception_is_reported_as_incomplete(
    config_factory, tmp_path, monkeypatch
):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    _patch_runtime(monkeypatch, config)
    _Suite.cleanup_error = RuntimeError("cleanup exploded")

    assert cli.main(["run"]) == 3
    instance = _Suite.instances[-1]
    assert instance.reporter.cleanup_summary["complete"] is False
    assert "cleanup exploded" in instance.reporter.cleanup_summary["errors"]
    assert instance.checkpoint.cleanup_state == "INCOMPLETE"


def test_cli_interrupt_returns_130_and_marks_checkpoint(
    config_factory, tmp_path, monkeypatch
):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    _patch_runtime(monkeypatch, config)
    _Suite.execute_error = KeyboardInterrupt("operator interrupted")

    assert cli.main(["run"]) == 130
    instance = _Suite.instances[-1]
    assert instance.reporter.interrupted is True
    assert instance.checkpoint.state == "CANCELLED"


def test_cli_restores_original_signal_handlers(config_factory, tmp_path, monkeypatch):
    config = config_factory(action="plan", report_dir=tmp_path / "reports")
    _patch_runtime(monkeypatch, config)
    originals = {
        signal.SIGINT: object(),
        signal.SIGTERM: object(),
        signal.SIGHUP: object(),
    }
    installed = dict(originals)

    def install(signum, handler):
        previous = installed[signum]
        installed[signum] = handler
        return previous

    monkeypatch.setattr(cli.signal, "getsignal", lambda signum: installed[signum])
    monkeypatch.setattr(cli.signal, "signal", install)

    assert cli.main(["plan"]) == 0
    assert installed == originals
