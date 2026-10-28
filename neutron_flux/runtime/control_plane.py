from __future__ import annotations

# mypy: disable-error-code="attr-defined"
from .control.controller import ControllerRuntimeMixin
from .control.keypairs import KeypairRuntimeMixin
from .control.servers import ServerRuntimeMixin
from .control.ssh import SSHRuntimeMixin


class ControlPlaneRuntimeMixin(
    KeypairRuntimeMixin,
    ControllerRuntimeMixin,
    ServerRuntimeMixin,
    SSHRuntimeMixin,
):
    """Composite compatibility façade for control-plane runtime services."""
