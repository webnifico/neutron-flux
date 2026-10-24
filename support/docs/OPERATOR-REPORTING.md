# Reading and handing off a Flux report

Open `report.html`. **Tests and coverage** shows run status, failures, checks not
run, blocked checks, elapsed time and cleanup. For selected host pairs, a coverage
table separates the initial and opposite placement stages and shows the actual
intra-host or inter-host relation observed in each. Completion and outcomes are reported separately; cancelled or blocked
checks never count as completed coverage.

Test names are the primary headings. Each collapsed group shows outcome counts;
expand it for execution rows with host placement, network/endpoints, IP family,
phase and observed result. Select an evidence button for that execution's full
explanation and bounded evidence. Performance uses the same measurement-name
groups. Technical paths remain available for endpoint investigation. The report
records its generator version separately from the version that collected results.

In **Run summary**, **Why this run needs attention** separates failed checks,
execution errors, missing routing expectations, incomplete measurements, blocked
coverage, cancellations, and passing checks with advisories. Select a reason to
see those exact tests. The recorded PASS/FAIL/UNVERIFIED counts remain unchanged.

Planned checks and supporting evidence records have separate totals. Migration
interruption observations, lower-rate UDP calibrations and performance advisories
are counted separately and may overlap. Completion means execution and cleanup
finished; it does not mean every measurement was free of observations. A disabled
measurement is shown as not run, rather than as a measured zero.

Saved-detail coverage separates traffic endpoints, functional guest route output,
selected performance paths and the runner's SSH connection to the controller.
Standalone performance records do not imply missing functional route evidence.
Missing evidence on an applicable traffic path remains visible as a gap.
Not-applicable checks are reported separately from checks that did not run; they
do not create an execution gap. Path protocol summaries include recorded ICMP,
TCP and UDP outcomes and retain the worst recorded outcome for each protocol.

Execution stage and compute relation are separate. A same-host path may have
been tested before or after a migration. New results save the stage explicitly;
historical reports use saved planner relationships when available. Network type
and MTU come from saved API responses for the exact network UUID. An attribute
that cannot be recovered from the saved record is labelled **Not recorded**.

Every test has an explanation with:

- **What happened:** the recorded observation or the failed probe step.
- **Why this status:** why the result was failed, unverified, blocked, or advisory.
- **Location:** endpoint addresses, observed compute hosts and AZs when recorded,
  requested host pair and general/targeted scope when available.
- **Facts:** attempts, TCP phase, destination port, route lookups, translation
  identity, matching/unmatched measurement counts, and collected diagnostic facts.
- **Evidence limits:** what was not measured or cannot be established.
- **Next check:** a check appropriate to the failed step or missing evidence.

Findings include per-test explanations. A single-test finding opens its explanation
automatically. Longer groups keep the per-test detail under a disclosure. Copy
summary/handoff includes the explanation and recorded facts for use outside Flux.
Raw commands, output, metrics, and guest diagnostics remain under **Evidence and
technical identity**; ordinary diagnosis should start with the explanation above it.

## Different reasons require different actions

| Report explanation | Meaning | Operator action |
| --- | --- | --- |
| TCP connection timed out | The probe did not establish TCP; later steps may not have run | Inspect the exact endpoints/port, repeat the same flow and locate the missing SYN or reply |
| Flux could not complete the check | A probe/API/orchestration error interrupted the check | Resolve the recorded execution error before drawing a network conclusion |
| Routing expectation not declared | Recorded traffic has no declared reachability or isolation requirement | Review topology and address-scope metadata; generate a fresh plan using current discovery and the intended provider-network selection |
| Forward/reverse comparison is incomplete | Requested direction comparisons lack matching eligible measurements | Compare matching packet sizes/rates and repeat unmatched profiles |
| Source rejected the packet before transmission | A local interface/route/PMTU constraint prevented the end-to-end probe | Inspect and refresh the source route/PMTU state, then repeat |
| Check passed with a performance advisory | The grading contract passed, with a recorded advisory condition | Review the threshold/sample facts; endpoint-limited samples are not network-loss proof |
| Check did not run: prerequisite unavailable | Earlier setup or a prerequisite prevented execution | Resolve the named prerequisite first |
| Cleanup is incomplete | Resources or cleanup errors remain | Inspect named resources/dependencies and retry run-scoped cleanup |

A timeout alone does not identify a router, firewall, OVN component, or physical
link as the cause. A single failed attempt does not establish persistence. A
completed migration does not by itself establish uninterrupted traffic. Missing
routing metadata does not prove that traffic must pass or be blocked.

## Diagnostics and portability

New failed probes include a bounded diagnostic snapshot in `results.json`.
It contains collected guest routes/listeners and selected Neutron port/Nova
fields. The HTML embeds useful facts plus bounded guest output. A copied HTML
report can therefore be read without its original logs or an active cloud login.
Complete evidence remains in `results.json` and `failures/`; truncated excerpts
are labelled. No additional cloud request is made merely to render a report.

Diagnostic snapshots are collected **after** the probe. A later ACTIVE port or
listening process is useful evidence, but cannot prove it was healthy during the
failed flow. Missing/failed diagnostic collection is stated explicitly.

When regenerating an older report, keep the run's `failures/` directory beside
`results.json`. Flux reads only matching sibling diagnostic files, verifies the
test identity, bounds file sizes, and does not follow diagnostic symlinks or
stored absolute paths. If those files are absent, the report states the gap.
Historical details, signed path identity, verdicts, and timestamps are retained.

HTML, final text, incident summaries, JUnit failure/error/skipped bodies, and
console attention lines use the same explanation logic. Native structured output
also exposes `operator_report`; original result records remain authoritative.
JUnit preserves its existing CI status mapping. Explanations are included in its
failure/error/skipped body even when optional raw evidence output is disabled.

Unknown or older result shapes retain their recorded message and a status-specific
explanation. Flux does not invent a more specific diagnosis where evidence is
missing.

## Reproducing a check

The manual guide names the source guest, destination guest or OpenStack runner
for every command. Prepare equivalent disposable resources, replace historical
IDs and addresses with current values, then follow the preparation, operation,
comparison and restoration steps. Read-only placement assertions do not require
a migration. Any step changing a router, server, floating IP or security group
must use the disposable resource identified in the guide.

Download the report's Python helper and copy the same file to both guests when
a recipe requires it. It provides the matching TCP echo, peer-identity, UDP,
performance and packet-size programs; an arbitrary listener does not implement
these protocols. Start the named responder first and wait for its readiness
message before running the client. Matching observer tokens, VM identities and
data addresses are required for translation and destination-identity assertions.

Historical commands remain unchanged in a separate disclosure. They are evidence,
not an ordered procedure for current resources. Missing prerequisites and tests
requiring Flux's coordinated load or full continuity monitor are called out;
a standalone probe does not reproduce those complete assertions. Manual checks
and report regeneration never change the original run's verdicts.

## Host-pair scope

`--target-host-pairs` applies to the complete applicable suite. Each A:B pair has
one intra-compute and one inter-compute placement for each cycle, starting where
the verified endpoints are and making one transition. An explicit A:A pair has
one intra-compute placement and no migration.
The report identifies requested placement and observed hosts separately. Shared
controller checks do not belong to a requested pair. After pair-local migration,
both endpoints may legitimately be on one member of the pair; the migration phase
remains distinct from its original placement. See
[the execution contract](HOST-PAIR-EXECUTION.md) for prerequisites, reuse, resume
and migration coverage.
