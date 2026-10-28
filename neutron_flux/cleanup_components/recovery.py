from __future__ import annotations

import json
import pathlib
import shlex
import tempfile

# mypy: disable-error-code="attr-defined"
from ..constants import TOOL_NAME
from ..errors import SuiteError
from ..models import ResourceRecord
from ..results_io import atomic_write_text


class CleanupRecoveryMixin:
    """Compatibility mixin for this cleanup concern."""

    def _clear_recovery_artifacts(self) -> None:
        removed = False
        for filename in ("recovery.md", "recovery.sh"):
            path = self.reporter.run_dir / filename
            if path.is_symlink() or path.exists():
                path.unlink()
                removed = True
        self.reporter.cleanup_summary.pop("recovery_markdown", None)
        self.reporter.cleanup_summary.pop("recovery_script", None)
        if removed:
            self.logger.log(
                "Removed stale cleanup recovery artifacts after verified final cleanup"
            )

    def _write_recovery_artifacts(self) -> None:
        remaining = [
            item
            for item in self.reporter.resources
            if item.delete_status not in {"deleted", "already-absent"}
        ]
        unresolved = self.reporter.cleanup_summary.get("unresolved_operations") or []
        if not remaining and not unresolved:
            return
        markdown_path = self.reporter.run_dir / "recovery.md"
        shell_path = self.reporter.run_dir / "recovery.sh"
        for path in (markdown_path, shell_path):
            if path.is_symlink():
                raise SuiteError(
                    f"Cleanup recovery artifact must not be a symbolic link: {path}"
                )
        lines = [
            "# Neutron Flux cleanup recovery",
            "",
            "Automatic cleanup did not complete. Review the recorded errors and resource state before retrying.",
            "The commands below use only OpenStack APIs.",
            "",
            "| Type | Name | ID | State | Error |",
            "|---|---|---|---|---|",
        ]
        shell = [
            "#!/usr/bin/env bash",
            "set -u",
            "",
            "# Review current resource IDs and dependencies before retrying.",
            "# These commands continue after errors; verify final resource absence.",
        ]
        if unresolved:
            lines.extend(
                [
                    "",
                    "## Unresolved cloud submissions",
                    "",
                    "An empty resource inventory cannot prove that these requests will not create or change resources later:",
                    *[f"- `{identity}`" for identity in unresolved],
                    "",
                    "Inspect the cloud operation journal and the corresponding OpenStack state. "
                    "Once the requests have reached a verified terminal state, rerun `neutron-flux cleanup --yes`. "
                    "Delete commands are omitted while submission outcomes remain unknown.",
                ]
            )
            shell.append(
                "# Unresolved submissions require terminal-state verification; no delete commands emitted."
            )
        for item in remaining:
            details = self._cleanup_progress_details(item.resource_type, item.id)
            lines.append(
                f"| {item.resource_type} | {item.name} | `{item.id}` | {item.cleanup_state} | {item.cleanup_error or ''} |"
            )
            if details:
                lines.append(
                    f"\n- `{item.id}` details: `{json.dumps(details, sort_keys=True, default=str)}`"
                )
            command = self._recovery_command(item)
            if command and not unresolved:
                shell.append(command)
        atomic_write_text(markdown_path, "\n".join(lines) + "\n")
        atomic_write_text(shell_path, "\n".join(shell) + "\n")
        shell_path.chmod(0o700)
        self.reporter.cleanup_summary["recovery_markdown"] = str(markdown_path)
        self.reporter.cleanup_summary["recovery_script"] = str(shell_path)
        self.logger.log(f"Recovery guide: {markdown_path}", "WARNING")
        self.logger.log(f"Recovery commands: {shell_path}", "WARNING")

    def _recovery_command(self, item: ResourceRecord) -> str | None:
        quoted = shlex.quote(item.id)
        volume_delete = f"openstack volume delete --force {quoted} || true"
        mapping = {
            "floating_ip": f"openstack floating ip delete {quoted} || true",
            "server": f"openstack server delete {quoted} || true",
            "router": f"openstack router delete {quoted} || true",
            "port": f"openstack port delete {quoted} || true",
            "subnet": f"openstack subnet delete {quoted} || true",
            "network": f"openstack network delete {quoted} || true",
            "volume": volume_delete,
            "security_group": f"openstack security group delete {quoted} || true",
            "server_group": f"openstack server group delete {quoted} || true",
            "keypair": f"openstack keypair delete {shlex.quote(item.name)} || true",
        }
        return mapping.get(item.resource_type)

    def _remove_local_keys(self) -> None:
        run_dirs: set[pathlib.Path] = set()
        for resource in self.reporter.resources:
            if resource.resource_type != "keypair":
                continue
            for key in ("private_key_path", "public_key_path", "user_data_path"):
                path_value = resource.metadata.get(key)
                if not path_value:
                    continue
                path = pathlib.Path(path_value)
                if not path.exists() and not path.is_symlink():
                    continue
                run_dir = self._validated_local_key_directory(path)
                run_dirs.add(run_dir)
                if path.is_file() or path.is_symlink():
                    path.unlink()
        # Remove only empty, explicitly recorded per-run temporary directories.
        for run_dir in run_dirs:
            try:
                run_dir.rmdir()
            except OSError:
                pass

    def _validated_local_key_directory(self, path: pathlib.Path) -> pathlib.Path:
        if not path.is_absolute():
            raise SuiteError(f"Refusing relative local key path from manifest: {path}")
        parent = path.parent
        expected_prefix = f"{TOOL_NAME}-{self.reporter.run_id}-"
        if parent.is_symlink() or not parent.name.startswith(expected_prefix):
            raise SuiteError(
                f"Refusing local key path outside the Flux run directory: {path}"
            )
        temporary_root = pathlib.Path(tempfile.gettempdir()).resolve()
        try:
            resolved_parent = parent.resolve(strict=True)
        except OSError as exc:
            raise SuiteError(
                f"Could not verify local key directory {parent}: {exc}"
            ) from exc
        if resolved_parent.parent != temporary_root:
            raise SuiteError(
                f"Refusing local key path outside the system temporary directory: {path}"
            )
        return resolved_parent
