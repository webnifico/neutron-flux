from __future__ import annotations

import argparse
import re
from pathlib import Path

import pytest

from neutron_flux import cli

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "support/docs/CLI-REFERENCE.md"


def test_every_public_flag_has_a_reference_table_entry():
    text = REFERENCE.read_text()
    cells = re.findall(r"^\| (.*?) \|", text, re.MULTILINE)
    documented = set(re.findall(r"--[a-z][a-z0-9-]*", "\n".join(cells)))
    public = {
        name
        for option in cli.parser()._actions
        if option.help != argparse.SUPPRESS
        for name in option.option_strings
        if name.startswith("--")
    }
    assert documented == public
    assert "`-h`" in text


def test_help_defaults_do_not_expose_argparse_none_placeholders(capsys):
    with pytest.raises(SystemExit):
        cli.parser().parse_args(["run", "--help"])
    output = capsys.readouterr().out
    assert "default: None" not in output
    assert "default: live with cold fallback" in output
    assert "no fixed upper cap" in output
    assert "default: 5" in output
    assert "--volume-type" in output
    assert "--target-host-pairs" in output


def test_global_help_lists_every_command_and_reference(capsys):
    with pytest.raises(SystemExit):
        cli.parser().parse_args(["--help"])
    output = capsys.readouterr().out
    for command in cli._ACTIONS:
        assert command in output
    assert "--version" in output
    assert "support/docs/CLI-REFERENCE.md" in output
