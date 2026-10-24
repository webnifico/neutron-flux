# Host-pair execution

Each eligible two-VM topology covers **one intra-compute placement and one
inter-compute placement**, with **one planned endpoint transition** between them.
The initial and opposite check slots are reserved before provisioning; their
actual host relation is recorded only after placement is verified.

| Verified starting relation | First checks | Single transition | Second checks |
|---|---|---|---|
| Same host (A/A) | Intra | Move one VM to the other selected host | Inter (A/B) |
| Different hosts (A/B) | Inter | Move one VM onto its peer's host | Intra (A/A) |

A and B identify the selected hosts. Each cycle covers the two placement
relations, without additional same-host locations or a reverse inter-host matrix.
A→B and B→A packet directions are still exercised within each placement; they
do not cause extra migrations.

The cycle ends after the second placement. Independent same-host validation on
both hosts and migration of both VMs are outside one topology lifetime's scope.

Explicit selectors constrain boot hints to the chosen hosts and AZs. The
ordinary scheduler-driven workflow starts from whichever verified relation it
receives. Valid existing endpoints inside the requested pair are not migrated or
recreated just to normalize the start. A VM outside the selected scope or with
unknown placement is not accepted as coverage. An explicit A:A pair has only one
intra-compute stage, since inter-compute is impossible in that scope.

Provider and project networking, fixed IPs, routing, floating IPs, hairpin, NAT,
security, lifecycle, MTU and performance checks retain their applicable
prerequisites, IP families and both traffic directions at the two placements.
Pre-submission safety samples remain supporting evidence, not extra placement
stages. Router/FIP state and resource identities are retained across eligible
migrations. Runner/controller infrastructure is shared.

## Safety, selection and retries

Migration never crosses AZs. Eligibility, shared-aggregate policy, readiness and
ambiguous-operation guards remain in force. Live migration defaults to five
attempts with backoff and a separately guarded cold fallback for recovered
endpoints. These are retry attempts for one transition, not additional planned
placement changes. An already moved VM is not moved again to improve a verdict.
`--migration-mode cold` selects cold migration directly.

Where migration is inapplicable (for example cross-AZ, isolation-only or stable
connectivity coverage), the opposite placement can use explicit endpoint
recreation. It is recorded as recreation, never as surviving live continuity.
Failure to establish a safe initial or opposite placement blocks dependent checks;
there is no hidden third-stage fresh setup after an unsuccessful transition.
Optional `--concurrent-vm-pairs` measurements have their separate resource budget
and run once per intra/inter relation, not per additional same-host location.
The existing concurrent levels (for example `--concurrent-vm-pairs 1,2,4,8`)
and explicit host/pair selectors remain available. Concurrency changes how many
VM pairs send traffic simultaneously, not how many placement combinations each
pair must cover. Additional requested host pairs get the same two-relation
scope; reversed copies of an explicitly selected host pair are deduplicated.

Use `--repeat` to repeat the applicable suite intentionally. Each repeat retains
its own run identity, evidence and cleanup. Estimates include two placements and
one eligible transition per topology/pair/cycle, or one placement for single-host
scopes. Runtime includes setup, functional checks, performance measurements and
cleanup as well as the placement transition.

## Resume and evidence

An interrupted topology resumes on a fresh resource generation. Earlier results
remain visible; rechecks get their own identities with the same approved logical
checks. The resumed generation again has at most one transition, not a migration
back to the old preferred starting host. Prior-version three-placement execution
plans must not be resumed under this policy; use a fresh run. Historical reports
can still be rendered without altering their recorded placements or verdicts.

Reports distinguish initial/opposite stages from their actual intra/inter hosts.
Counts, failure summaries and comparisons use logical checks, with supporting
observations separate. Fixed planned IDs and totals do not change when the
runtime discovers that the initial pair is intra rather than inter.

## Validation

The offline gate checks both starting relations, both host orders, same/cross-group
topologies, one transition, retained endpoint identity, mode/retry safeguards,
fixed totals, opposite-stage blocking, reports and historical compatibility.
Cloud validation must still verify Nova placement, Neutron binding, Cinder
constraints, actual packet paths and final cleanup using the complete archive.
