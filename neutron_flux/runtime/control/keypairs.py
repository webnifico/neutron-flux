from __future__ import annotations

import subprocess

# mypy: disable-error-code="attr-defined"
from ...errors import CommandTimeoutError, SuiteError
from ...resource_naming import claim_runtime_resource_name
from ...utils import optional_text, pick


class KeypairRuntimeMixin:
    """Compatibility mixin for this control-plane concern."""

    def _create_ssh_key(self) -> None:
        result = subprocess.run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                self.run_tag,
                "-f",
                str(self.key_path),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise SuiteError(f"ssh-keygen failed: {result.stderr.strip()}")
        self.key_path.chmod(0o600)

    def _create_keypair(self) -> None:
        claim_runtime_resource_name(
            self,
            self.keypair_name,
            resource_type="keypair",
        )
        try:
            data = (
                self.osc.json(
                    "keypair",
                    "create",
                    "--public-key",
                    str(self.public_key_path),
                    self.keypair_name,
                    timeout=min(60, self.config.resource_timeout),
                )
                or {}
            )
        except CommandTimeoutError as exc:
            data = (
                self._recover_created_resource_by_name(
                    "keypair", self.keypair_name, timeout=30
                )
                or {}
            )
            if not data:
                raise SuiteError(
                    f"Keypair creation timed out and {self.keypair_name} did not become visible"
                ) from exc
            self.logger.log(
                f"Recovered keypair {self.keypair_name} by exact name after OpenStackClient timed out",
                "WARNING",
            )
        key_id = (
            optional_text(pick(data, "name", "id", default=self.keypair_name))
            or self.keypair_name
        )
        self.tracker.add(
            "keypair",
            key_id,
            self.keypair_name,
            private_key_path=str(self.key_path),
            public_key_path=str(self.public_key_path),
        )
