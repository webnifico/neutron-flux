# Architecture

Flux discovers an OpenStack project, builds an applicable network test plan,
creates disposable resources, records observations and cleans up owned resources.
It uses one administrator workflow and the OpenStack CLI, plus SSH into its VMs.
The [CLI reference](CLI-REFERENCE.md) defines the supported inputs.

## Main components

| Component | Responsibility |
| --- | --- |
| `cli.py`, `config.py`, `configuration/` | CLI validation, run history, resolved settings and resume |
| `discovery.py`, `capability_preflight.py` | Read-only inventory and required service capabilities |
| `planning.py`, `planner_components/`, `check_plan.py` | Applicable topologies, dependencies, resource estimates and planned checks |
| `az_policy.py`, `zones.py`, `multi_zone.py` | Independent service-AZ choices and coordinated zone execution |
| `host_qualification.py`, `pair_suite.py`, `pair_workflow.py` | Requested host matrix and intra/inter-host coverage |
| `executor.py`, `execution/`, `pair_workflow.py`, `pair_placement.py` | Work ordering, endpoint reuse, placement and migration |
| `resources.py`, `runtime/` | Resource creation, readiness, guest access and topology changes |
| `engine.py`, `engine_handlers/`, `probes.py` | Functional probes and stateful lifecycle tests |
| `performance.py`, `performance_*`, `concurrent_load.py` | Measurements and optional simultaneous traffic |
| `cloud_operation*`, `scheduling.py` | Admission limits, command pacing, journals and unresolved-operation barriers |
| `cleanup.py`, `cleanup_components/` | Ownership checks, dependency-ordered deletion and recovery guidance |
| `reporting.py`, `reporting_components/`, `result_contract*` | Structured evidence, verdicts, reports and historical result interpretation |
| `offline_reports.py`, `comparison.py`, `trends.py`, `replay_plan.py` | Offline report regeneration, comparisons and full-suite rerun guidance |

The implementation uses mixins for related runtime and reporting concerns.
`RuntimeContext` and `StateField` provide shared resource state; engine lifecycle
records and operation registries make handler dependencies explicit. Registry
handlers are resolved by name, and dataclass fields are also consumed through
serialization. These uses must be checked before deleting apparently unused code.

## Planning and placement

Fresh runs accept CLI arguments only. Required inputs are image, flavor, storage
and external networks. The planner expands discovered, project-usable subnet
pools across eligible selected gateways and includes independent one-router and
two-router paths. Network service roles and eligible IP families determine coverage.

Compute, Cinder, network and router inventories are independent. Each service
prefers an available match for the compute AZ. A network or router without a
match uses its sole available AZ or Neutron defaults. A root volume without a
type-compatible match uses Cinder defaults. Compute scope and volume type remain
fixed; Nova still enforces attachment policy. An entirely unavailable service
inventory blocks setup. Requested hints and observed placement remain separate.
See [AZ placement](AZ-PLACEMENT.md).

Routers use Neutron's configured gateway addresses and default source-NAT state.
Flux does not set gateway fixed addresses or source-NAT flags. Pool-derived
endpoints remain fixed-IP-only; dedicated private IPv4 topologies exercise
ordinary SNAT and floating-IP behavior. Static IPv6 guest configuration is
verified read-only. [Routing policy](ROUTING-POLICY.md) describes which paths
are requirements and which remain observations.

Ordinary AZ execution does not guarantee every compute host is exercised.
Host selectors build the requested matrix and record actual placement.
Multiple selected AZs include both local and cross-zone paths; migrations remain
within one compute AZ. [Host-pair execution](HOST-PAIR-EXECUTION.md) describes
pair scope and transitions.

## Execution and resource ownership

The runner reaches a probe controller through provider IPv4, using a dedicated
management bastion when needed. Endpoint management access and measured traffic
have distinct roles. Readiness requires usable Nova state, expected Neutron
attachments and guest access. Failed setup blocks dependent work and retains
the evidence needed to identify the shared failure.

Independent reads, probes and endpoint lifecycles overlap within admission
limits. Stateful changes and performance measurements hold exclusive activity
windows. Endpoint reuse preserves resource generations and verified placement.
See [Scheduling](SCHEDULING.md) for concurrency and timing semantics.

Every cloud-changing command is journaled before submission. Accepted but
unresolved operations remain barriers to conflicting provisioning or deletion.
Read-only reconciliation records a confirmed outcome; uncertainty never
authorizes a blind retry. Scope checks use project identity, owned resource
markers and run records. Administrative credentials do not remove ownership
requirements.

Migration requires fresh connectivity checks using the protocols applicable to
each path, an eligible destination, and verified guest/port state. VM-to-VM paths
use ICMP, TCP and UDP; external reachability targets use ICMP. MTU differences
remain advisory. Local-root live
migration uses block transport; volume-backed live migration uses shared
transport. A failed live capability remains a failure even when cold fallback
restores placement. Ambiguous submission stops retrying.

## Persistence, resume and cleanup

Each run writes a checkpoint, immutable plan, resource manifest, operation
journal and reports beneath its run directory. Resume verifies plan identity,
project/network scope and current inventory before provisioning. It reconciles
unfinished operations and resources, refreshes quota headroom, and preserves
completed checks. Repeat passes have distinct run IDs linked by checkpoints.

Historical workload settings and result formats remain readable where they are
needed for resume, cleanup or offline reporting. Retired project execution
contracts cannot resume with administrator semantics; their owned resources
remain eligible for cleanup. Retired file-input provenance is ignored and is
not restored as configuration attributes.

Explicit cleanup discovers owned resources across runs, including active and
orphaned resources. Deletion respects dependencies, operation barriers and
confirmed absence. Two clean inventory scans with a fresh visibility interval
are required before declaring the project clean. A delayed response or an empty
first inventory is not proof of completion.

Interrupted or incomplete cleanup preserves remaining work. `recovery.md` and
`recovery.sh` are runtime artifacts produced only for incomplete final cleanup;
verified completion removes them. They never belong in the source release.

## Reports and development

Planned checks and supporting evidence records have separate counts. Typed
verdicts distinguish failed delivery, probe execution errors, blocked work and
unverified observations. HTML, JSON, text, JUnit and incident summaries consume
the same recorded evidence. Offline regeneration does not execute cloud commands
or change the original observations. Rerun guidance uses supported controls to
repeat the complete suite; it does not promise identical scheduler placement.
See [Operator reports](OPERATOR-REPORTING.md).

Tests live under `support/tests/`; shared fakes and fixtures stay there rather
than in the runtime package. Release gates check source reachability, command
construction, formatting, types, security, tests, coverage and installation from
the packaged source. Generated logs, validation evidence, recovery files,
temporary files and previous build products are excluded or rejected.
[Testing](TESTING.md) covers development and live-cloud checks.
