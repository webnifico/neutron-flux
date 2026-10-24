from __future__ import annotations

VERSION = "1.0.0"

MIGRATION_DOWNTIME_TOLERANCE_NOTE = (
    "These tolerance levels reflect the goal of zero customer downtime. "
    "Exceeding them is an observation when migration completion, placement, "
    "TCP survival and traffic recovery are verified."
)

_VERSION_CORE, _RC_MARKER, _RC_NUMBER = VERSION.partition("rc")
if _RC_MARKER and _VERSION_CORE and _RC_NUMBER.isdigit():
    RELEASE_STAGE = "release candidate"
    RELEASE_REVISION = f"rc{_RC_NUMBER}"
    RELEASE_IDENTIFIER = f"{_VERSION_CORE}-{RELEASE_REVISION}"
else:
    RELEASE_STAGE = "stable"
    RELEASE_REVISION = ""
    RELEASE_IDENTIFIER = VERSION

DISPLAY_VERSION = f"{RELEASE_IDENTIFIER} ({RELEASE_STAGE})"
TOOL_NAME = "neutron-flux"
DEFAULT_REPORT_DIRNAME = "neutron-flux-reports"
MIN_TEST_RAM_MB = 512
RESULT_STATUSES = {
    "PASS",
    "FAIL",
    "SKIP",
    "NOT_APPLICABLE",
    "UNVERIFIED",
    "ERROR",
    "BLOCKED_BY_SETUP_ERROR",
    "BLOCKED_BY_PREREQUISITE",
    "NOT_RUN_CANCELLED",
}
EXIT_SUCCESS = 0
EXIT_TEST_FAILURE = 1
EXIT_EXECUTION_ERROR = 2
EXIT_CLEANUP_INCOMPLETE = 3
EXIT_UNSUPPORTED_TOPOLOGY = 4
