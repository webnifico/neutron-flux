# Automatic scheduling

Flux overlaps independent work and retains compatible endpoints automatically.
Protocol timeouts, measurement durations, migration policy and resource ownership
still constrain the run.

## Admission and isolation

| Work | Automatic execution policy |
| --- | --- |
| OpenStack read commands | Up to four concurrent read subprocesses across the action. Independent discovery, security-group, AZ, cleanup inventory and migration-port reads are batched. |
| Ordinary ICMP/TCP/UDP probes | Up to eight concurrent probes, subject to prerequisites. Sharing a host or VM does not by itself serialize them. |
| Endpoint creation | Up to two complete endpoint lifecycles across AZs, including routed and cross-network pairs; returned endpoint order remains deterministic. |
| Server, port and volume deletion | Up to two independent deletions, with each dependency phase drained before the next starts. |
| Cloud operation submissions | One paced, journaled command at a time. Lifecycle readiness waits can overlap. |
| MTU, route, security and other stateful batches | An exclusive window preserves lifecycle ordering and prevents another batch from changing the observed state. |
| Performance | One exclusive measurement window. Its intentional bidirectional or loaded submeasurements remain concurrent. |
| Cold migration | Exclusive through baseline, migration, binding verification and recovery. |

These limits bound work the existing plan already requires. They do not increase
the plan's peak instance count. The normal adaptive executor still permits a
controller plus two endpoint VMs. Stable host qualification retains two endpoint
roles per selected host; rolling qualification retains one pair. Existing quota
preflight and exact placement rules still apply.

Stable qualification schedules independent ordinary checks across the selected
pair matrix. With three resident hosts, 1–2, 1–3 and 2–3 can overlap. MTU and
performance work waits for the ordinary checks, and each pair's cycles complete
in order.
Each engine retains its own endpoint view, each cloned prerequisite refers to
the corresponding pair/cycle, and report/checkpoint writes remain coordinated.

Host qualification chooses its endpoint strategy automatically. Exact host-pair
runs retain pair-local migration coverage; ordinary rolling execution cannot
execute pairs whose endpoints are not resident. Independent probes and bounded
endpoint boot/readiness operations can still overlap.

## Settlement and evidence

Settlement is a deadline following the last completed cloud operation. Time already
spent in command quiet periods and readiness checks contributes to that deadline.
Nested port, server and endpoint methods share that deadline instead of
restarting the full wait at each layer. Operation-specific minimum spacing
and fallback quiet windows remain in effect.

The two final clean inventory scans always have a **fresh visibility interval**
between them. Elapsed-time credit cannot remove this interval. Ambiguous
submissions still require reconciliation and can quarantine resources or hosts.
Help/version commands do not create cloud operation records or consume quiet time.
Deterministic policy/input rejections and slow successful API calls do not
automatically increase run-wide backoff; ambiguous/transient acceptance does.

Qualification can reuse successful Nova/Neutron placement evidence for at most
15 seconds within the same cloud operation sequence, with identical verification
requirements. A new cloud operation, expired evidence or a fresh verification request
invalidates that reuse. A failed refresh cannot resurrect an older snapshot.
Evidence is held only in memory and is never restored across resume. Migration
verification retains fresh reads by default.

Independent A/B placement verifications overlap after both endpoints' role,
host and availability-zone constraints pass validation. Both verifiers finish
before placement is published or migration begins. Their nested port reads use
the same process-wide read limit.

Each migration safety observation joins its independent port reads before
validation. The three observations remain sequential, and the final migration
snapshot still performs fresh reads. A failed or cancelled read cannot authorize
a migration.

Cleanup queries independent resource inventories concurrently, then applies
ownership decisions and journal updates in a deterministic order. Router and
network port details are also read in batches; their destructive operations
retain dependency order. The two final absence scans remain separate passes.
A fresh server observation immediately after deletion supplies both the timeout
choice and the first absence poll; later polls still fetch fresh evidence.

If the floating-IP SHOW formatter fails, Flux remembers that client limitation
and uses a fresh LIST query for later identity and association checks. Only an
exact unique ID with the required fields is accepted. A missing LIST row still
requires SHOW to prove absence; the compatibility flag never caches resource
state or supplies SHOW-only fields.

## Endpoint reuse and ordering

Independent ordinary cross-topology batches are ordered to retain endpoints.
Passing prerequisites constrain this order. Stateful batches are fixed barriers;
the scheduler does not move observations across them.

The last compatible group-local batch can retain its endpoints for the first
cross-topology batch. If only one of its endpoints is required, cleanup removes
the surplus side while retaining the other VM and its topology. Groups with
incomplete/failed lifecycle evidence, submitted migration or active floating-IP
state are not retained at that transition. More complex topologies and
incompatible side requirements continue to receive a fresh generation.

Rolling qualification can reuse a compatible pair when migration is enabled but
no migration command was submitted. Outside the coordinated provider handoff
below, a submitted migration requires endpoint release and recreation.
Guest processes, ownership, resource generations and exact placement remain
authoritative. Failure to release a required resource blocks replacement.

Coordinated host-pair runs can order independent provider-only workflows to
retain one verified endpoint between compatible lifetimes. The selected host
pair, cycle, network, subnets and address families must match. Every check in
the completed workflow must pass, cloud operations must be resolved, and
placement and the existing probe service must remain valid. The previous peer
is deleted before the next peer is created. A successfully migrated endpoint
keeps its actual host; it is not moved back to an old boot hint. Each workflow
still tests its initial relation and performs one transition to the opposite
relation. Resume, selective execution, floating-IP and router topologies do not
use this handoff. Failed or uncertain state follows normal cleanup.
An ordinary placement or probe-service readback error declines this optional
reuse; cleanup must prove release before the next lifetime creates fresh VMs.
Cancellation and shared controller failures still stop the lane.

Cross-network endpoint setup prepares its network graphs serially before
starting the independent VM lifecycles together. Every prepared group is tracked
before workers start. Workers join before placement publication or failed-group
cleanup, including when a worker fails or the run is cancelled. No worker holds
a lifecycle slot while waiting for child endpoint workers.
Cancellation reported by a child command also propagates when no process-wide
cancellation flag has been set; partial resources remain tracked for cleanup.

Peak resource estimates remain valid. Lifetime creation/deletion estimates are
conservative because successful reuse can avoid planned rebuilds. Do not infer a
fixed run duration from the worker limits: quota, topology, negative observations,
cloud convergence, migrations and measurement settings still determine runtime.

## Timing reports

The text summary and the HTML Run details page include runtime timing. JSON
contains a top-level `timing` summary and `runtime-timing` events, including:

- OpenStack read/write subprocess time and cloud operation queue time;
- admission and activity-window waits;
- actual elapsed quiet waits;
- endpoint setup and resource cleanup;
- functional checks, baseline performance and concurrent-load measurements.

Elapsed spans can nest. Self time excludes nested spans **on the same thread**.
Concurrent threads overlap, so neither component sum equals run wall time. Read
and write subprocess durations include client startup, authentication and API
time. Historical reports without these events show timing as unavailable.

Performance covers all eligible paths. Scheduling does not reduce coverage
to shorten a run.

## Verification

Run `python support/scripts/validate-release.py` for the offline release gate.
Concurrency regressions use synchronization barriers to verify actual overlap,
dependency ordering, shared-host pair attribution, measurement exclusion,
failure draining, cancellation, cleanup phase ordering and journal integrity.

Measure scheduling performance against a previous run with the same topology,
inputs and coverage. Inspect timing, resource creation counts, completed results
and final cleanup. A cloud staging run is required to measure the effect on
actual Nova, Neutron and Cinder services.
