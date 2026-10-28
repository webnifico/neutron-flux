from __future__ import annotations

import os
import pathlib
import subprocess
import textwrap

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]


@pytest.fixture
def run_certification_guard(tmp_path):
    workflow = ROOT / ".github" / "workflows" / "live-certification.yml"
    step = (
        workflow.read_text(encoding="utf-8")
        .split(
            "      - name: Validate destructive authorization and runner inputs\n", 1
        )[1]
        .split("\n      - name:", 1)[0]
    )
    script = textwrap.dedent(step.split("        run: |\n", 1)[1])
    trace = tmp_path / "authentication.log"
    client = tmp_path / "openstack"
    client.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$*" >> "$AUTH_TRACE"\nexit "$AUTH_EXIT_CODE"\n',
        encoding="utf-8",
    )
    client.chmod(0o755)

    def run(*, authentication_exit=0, **overrides):
        environment = {
            "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
            "CONFIRMATION": "DESTROY DISPOSABLE PROJECT",
            "CERTIFICATION_CLI_ARGUMENTS": "--image image --flavor small --storage host --external-networks Public1",
            "EXPECTED_CANDIDATE_SHA256": "a" * 64,
            "AUTH_TRACE": str(trace),
            "AUTH_EXIT_CODE": str(authentication_exit),
            **overrides,
        }
        result = subprocess.run(
            ["bash", "-c", script],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        calls = trace.read_text().splitlines() if trace.exists() else []
        return result, calls

    return run


@pytest.mark.parametrize(
    "credentials",
    [
        {"OS_AUTH_URL": "https://identity.example.invalid/v3"},
        {"OS_CLOUD": "certification-cloud"},
        {},
    ],
    ids=["environment-authentication", "named-cloud-profile", "client-defaults"],
)
def test_certification_guard_accepts_client_verified_authentication(
    run_certification_guard, credentials
):
    result, calls = run_certification_guard(**credentials)

    assert result.returncode == 0, result.stdout + result.stderr
    assert calls == ["token issue -c project_id -f value"]


@pytest.mark.parametrize("authentication_exit", [1, 42])
def test_certification_guard_rejects_failed_authentication(
    run_certification_guard, authentication_exit
):
    result, calls = run_certification_guard(
        authentication_exit=authentication_exit, OS_CLOUD="certification-cloud"
    )

    assert result.returncode != 0
    assert "OpenStack authentication failed" in result.stdout
    assert calls == ["token issue -c project_id -f value"]


def test_certification_guard_requires_confirmation_before_authentication(
    run_certification_guard,
):
    result, calls = run_certification_guard(CONFIRMATION="unconfirmed")

    assert result.returncode != 0
    assert "not explicitly authorized" in result.stdout
    assert calls == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"CERTIFICATION_CLI_ARGUMENTS": ""},
        {"EXPECTED_CANDIDATE_SHA256": "a" * 63},
        {"EXPECTED_CANDIDATE_SHA256": "a" * 65},
        {"EXPECTED_CANDIDATE_SHA256": "z" * 64},
    ],
    ids=["missing-launch-arguments", "short-digest", "long-digest", "nonhex-digest"],
)
def test_certification_guard_rejects_invalid_launch_inputs(
    run_certification_guard, overrides
):
    result, _ = run_certification_guard(**overrides)

    assert result.returncode != 0
