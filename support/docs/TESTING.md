# Development tests and release checks

Install the development dependencies in an isolated environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e '.[test,dev]'
python3 -m pytest
```

Tests live in `support/tests/` and are named for the behavior they verify.
For example, `test_cleanup_fixed_point.py` checks eventual resource visibility,
`test_migration_defaults.py` checks the default migration contract, and
`test_cli_contract.py` checks the public controls. Shared fakes are in `_shared.py`;
pytest fixtures are in `conftest.py`. Test identities and fixture filenames must
not encode a release number. Release-identity assertions derive their expectation
from the package constants and independently check their format and consistency.

`test_resume_preflight.py` covers cleanup before fresh quota checks, scope and
fingerprint protection, and volatile quota evidence. `test_cleanup_uncertainty.py`
covers delayed inventory visibility, unresolved submissions, dry-run semantics
and safe recovery guidance.

`test_cleanup_transaction_concurrency.py` holds accepted topology operations open
while another worker releases a group. It checks both verified completion and
failed absence verification; serial command mocks alone cannot reproduce that
race. `test_controller_access_loss.py` checks controller recovery, early scope
termination, shared diagnostic evidence and SSH failure classification.

JSON fixtures are appropriate when they describe a repeatable input or expected
result. Name them for that scenario. Apart from the documented sample lab report
archive in `support/examples/`, keep generated run reports, validation records,
screenshots, coverage output, old test copies and logs outside the source tree.
Captured regression fixtures use synthetic identifiers and addresses. Numeric
measurements, timings and verdicts are retained; provenance hashes identify the
original captures before anonymization.
Record source history in version control. Keep release history and release-number
annotations out of source, comments, tests and documentation. Package version
metadata remains the authority for build identification.

Run a focused behavior suite while developing:

```sh
python3 -m pytest support/tests/test_cli_contract.py support/tests/test_execution_recovery.py
python3 support/scripts/source-audit.py
```

Before packaging, run the complete offline gate. Save its output outside the
source tree and keep the command's exit status:

```sh
python3 support/scripts/validate-release.py > ../offline-validation.log 2>&1
```

The gate checks compilation, source layout and import structure, OpenStack command
construction, lint and formatting, security scanning, the configured type-checking
boundary, the full test suite and branch coverage. It also builds reproducible
source ZIPs, builds a wheel from the extracted source and exercises the installed
CLI and offline report commands. Only the declared pytest plugins are loaded.

The source audit rejects production modules that cannot be reached from the CLI.
The archive builder rejects release-numbered source/test/fixture names, historical
evidence directories, runtime recovery files, logs and temporary editing files. Caches, coverage files,
build products, package metadata and previous archives are excluded from packaging.
The source ZIP includes the active tests and durable documentation.

```sh
python3 support/scripts/build-release.py --output ../neutron-flux-source.zip
```

The GitHub Actions CI workflow runs this offline release gate on pull requests
and pushes to `main`, using Python 3.12 and the dependencies in `uv.lock`.
Node.js and jsdom enable the report interaction checks. Validation logs and a
coverage XML report are retained as workflow artifacts. The README badge tracks
offline CI; cloud validation uses the separate manual certification workflow.

The audit regression suites exercise the production coordinator and engine against
instrumented cloud and packet boundaries, and run complete generated TCP/UDP
client/server programs on real loopback sockets. The delayed-acknowledgement test
retains the production deadlines and observes one original connection. ICMP tests
exercise parser and capture transport with a synthetic AF_PACKET boundary; actual
raw-socket permissions and NAT traversal remain live-cloud acceptance gates.

Offline tests use controlled cloud responses. Real placement, migrations, network
behavior and cloud cleanup require cloud testing with the exact archive under test. Keep those results alongside the archive checksum,
outside the source tree.

The optional `test_report_browser_workflow` test uses Node.js and `jsdom` to exercise
actual DOM navigation, filter restoration, manual steps, copying and input
validation. Install jsdom in your development environment or set `NODE_PATH` to
its node_modules directory. Run it with `python3 -m pytest
support/tests/test_manual_report.py`. These interaction checks do not constitute
visual browser testing or live-cloud certification.

## Cloud testing

`support/scripts/live-certify.py` runs complete, interrupted and failure-injected
workflows in a disposable project, checks cleanup and records the results. It
uses the same launch arguments as Flux and internal worker snapshots for fault
injection. Authenticate OpenStackClient before starting it:

```sh
export CERTIFICATION_CANDIDATE_ARCHIVE="$(python3 support/scripts/build-release.py)"
export CERTIFICATION_CANDIDATE_SHA256="$(sha256sum "$CERTIFICATION_CANDIDATE_ARCHIVE" | awk '{print $1}')"
python3 support/scripts/live-certify.py --image debian-13 --flavor x1.nano --storage host --external-networks Public1 --output-dir ../certification-reports
```

`SUCCESS_RUNS`, `INTERRUPTED_RUNS`, `INJECTED_RUNS` and `CERTIFICATION_*`
environment settings configure this developer harness. The active workflow is
`.github/workflows/live-certification.yml`; it takes `cli_arguments`, checks the
candidate archive checksum, and requires disposable-project confirmation.
Evidence is written outside the checkout and retained as workflow artifacts.
Keep cloud results with the exact archive checksum; they are not release source.

Successful certification accepts both `PASS` and `PASS WITH WARNINGS`, provided
every approved check has passing or explicitly inapplicable evidence. The harness
checks root and availability-zone checkpoints, complete cleanup, deleted tracked
resources, and unresolved cloud operations; warnings do not excuse missing or
blocked coverage. Injected failures and cancellations must reach the intended
condition and recover verified cleanup.

The interrupted workflow tests cleanup recovery, not execution resume. Its
summary explicitly records resume as untested. Before release, separately
interrupt a representative run, then use `neutron-flux run --resume RUN_ID --output-dir REPORT_DIR` with the
same cloud credentials and report directory. Confirm that unfinished checks
execute, historical results are preserved, the root and zone checkpoints finish,
and cleanup verifies no managed resources remain. Save this evidence with the
exact candidate archive checksum.
