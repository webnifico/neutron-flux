from __future__ import annotations

from .migration_execution import MigrationExecutionMixin
from .migration_validation import MigrationValidationMixin


class MigrationRuntimeMixin(MigrationValidationMixin, MigrationExecutionMixin):
    """Compatibility mixin composing migration validation and execution."""
