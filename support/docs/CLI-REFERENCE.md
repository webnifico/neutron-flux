# CLI reference

Flux accepts CLI arguments only. It does not load YAML/JSON configuration files,
`NEUTRON_FLUX_CONFIG`, or implicit configuration paths. OpenStack authentication
still uses the normal OpenStackClient environment or clouds.yaml; that is separate
from Flux configuration. Historical results remain readable.

## Commands

| Command | Purpose |
| --- | --- |
| `plan` | Read-only discovery and complete suite preview. |
| `run` | Functional tests, performance, applicable migrations, reports, cleanup. |
| `status` | Latest checkpoint in the output directory. |
| `cleanup` | Discover and clean all Flux-owned resources in the current project. |
| `report RESULTS.json` | Regenerate HTML, text, JSON, JUnit and evidence reports offline. |
| `compare BASELINE.json CANDIDATE.json` | Compare recorded results offline. |
| `trend RESULTS_OR_DIRECTORY...` | Summarize recorded results offline. |

## All 26 controls

`-h` is an alias of `--help`. There are no hidden legacy aliases.

| Flag | Commands | Meaning |
| --- | --- | --- |
| `-h / --help` | plan, run, status, cleanup, report, compare, trend | show this help message and exit |
| `--version` | plan, run, status, cleanup, report, compare, trend | show program's version number and exit |
| `--output-dir PATH` | plan, run, status, cleanup, report, compare, trend | run history or report output directory |
| `--image IMAGE` | plan, run | required image name or UUID; SSH account is inferred from image metadata/name |
| `--flavor FLAVOR` | plan, run | required flavor name or UUID |
| `--storage host\|volume` | plan, run | required root-disk location; volume size is derived from flavor/image requirements |
| `--volume-type TYPE` | plan, run | Cinder volume type; requires --storage volume |
| `--external-networks NETWORK[,NETWORK...]` | plan, run | required external network names/UUIDs; comma-separated |
| `--zones ZONE[,ZONE...]\|all` | plan, run | compute AZs; multiple AZs include within- and between-AZ coverage; default: automatic single AZ |
| `--target-hosts HOST[,HOST...]` | plan, run | test every unique pair of selected hosts; one host tests same-host placement |
| `--target-aggregates AGGREGATE[,AGGREGATE...]` | plan, run | test all pairs of hosts in selected aggregates |
| `--target-host-pairs HOST:HOST[,HOST:HOST...]` | plan, run | test each selected pair in its verified initial placement and the opposite relation; one intra, one inter, one transition |
| `--repeat N` | plan, run | complete passes through the selected suite (minimum 1; default: 1) |
| `--migration-mode live\|cold` | plan, run | default: live with cold fallback after proven retryable failures; migrations stay inside a compute AZ |
| `--live-attempts N` | plan, run | maximum live submissions per migration, including the first (minimum 1; default: 5; no fixed upper cap) |
| `--shared-aggregate auto\|required\|ignore` | plan, run | migration aggregate-membership policy (default: auto) |
| `--performance-profile standard\|exhaustive` | plan, run | performance sampling depth (default: standard); all eligible paths are measured |
| `--concurrent-vm-pairs N[,N...]` | plan, run | enable simultaneous traffic at these VM-pair counts, e.g. 1,2,4 (each 1-32) |
| `--concurrent-repeats N` | plan, run | measurements per simultaneous-pair count (1-10; default: 2) |
| `--concurrent-duration SECONDS` | plan, run | seconds per simultaneous-traffic measurement (3-120; default: 15) |
| `--ping-target-ipv4 IP` | plan, run | override the external IPv4 ping destination (default: 1.1.1.1) |
| `--ping-target-ipv6 IP` | plan, run | override the external IPv6 ping destination (default: 2606:4700:4700::1111) |
| `--resume RUN_ID` | run | resume an interrupted run using its recorded settings |
| `--keep-resources` | run | retain test resources after success or failure for inspection |
| `--dry-run` | cleanup | cleanup: preview all Flux-owned resources without changing the cloud |
| `--yes` | cleanup | cleanup: delete all Flux-owned resources without prompting, including active runs and orphans |

## Defaults and scope

Cloud operations use administrator credentials scoped to the test project. There
is one execution workflow. Older administrator runs remain resumable; saved runs
from the retired project workflow require a fresh run. Cleanup remains available.

A fresh plan/run requires image, flavor, storage and external networks. Unspecified
zones select one usable compute zone. `--zones all` resolves available zones; two
or more zones include both within-zone and between-zone tests. Migrations remain
within a compute AZ. Root volumes request a matching available Cinder AZ when the
selected volume type supports it; otherwise they use Cinder defaults. Compute
placement and volume type remain fixed, and Nova still enforces attachment policy.

Network and router AZ inventories are discovered separately. Each prefers an
available AZ matching compute, independently of the other service. Otherwise it
uses its sole available AZ or lets Neutron apply its defaults when several remain.
Unavailable matches are recorded and excluded from selection; an entirely
unavailable service inventory blocks setup. Requested and observed placement are
recorded independently. Controller boot fallback cannot reuse a topology when
the next compute candidate needs different network/router hints.

`live` is the migration default. It permits five live submissions, including the
first attempt. Retries wait 10, 20, 30 and 40 seconds; larger configured budgets
cap each wait at 60 seconds. `--live-attempts N` accepts any positive integer.
A failed live move with ports still DOWN can retry after Nova confirms destination
rollback and stable source ownership. The original healthy guest and port identity
remain the validation baseline; port, guest and connectivity checks still apply
after the move. Ambiguous acceptance and unfinished operations block retries.
One cold fallback remains available after ordinary proven failures with full
source recovery; exhausted recovery retries with unverified guest networking stop
without a cold submission. A cold fallback cannot pass live capability. `cold`
skips live attempts.

Performance always runs on every eligible path; standard/exhaustive controls
sampling depth. Concurrent traffic is optional: `--concurrent-vm-pairs 1,2,4`
requests those simultaneous pair counts. Its defaults are two measurements at
each count and 15 seconds per measurement. Pacing and readiness checks are built in.

`--repeat N` executes N complete suite passes, each with its own run ID, reports
and cleanup. A failed network assertion can be followed by the next pass; setup,
cleanup or cancellation failures stop the sequence. Checkpoints link successive
passes, so `--resume RUN_ID` continues the incomplete pass and remaining passes.
Pass totals are recorded in the plan; per-pass quotas are not multiplied.

Resume validates the saved fingerprint and current project/network scope, cleans
up the interrupted run's owned resources, then refreshes discovery and quota
headroom before rebuilding unfinished work. Cleanup also discovers resources
missing from the manifest. Changing quota consumption alone is not plan drift;
quota limits and workload requirements remain checked, and insufficient fresh
headroom still blocks provisioning.

SSH accounts come from image `os_admin_user`/`admin_user` metadata, then recognized
distribution names. Unknown images must carry that metadata. Root volumes use at
least 20 GiB and grow to satisfy flavor disk, image min_disk and image virtual size.

`--ping-target-ipv4` and `--ping-target-ipv6` replace the external destinations,
defaulting to `1.1.1.1` and `2606:4700:4700::1111`. IPv6 checks still depend on the
cloud providing an eligible IPv6 path. Targets must be usable unicast addresses
of the requested family; IPv6 targets must be native IPv6 addresses without an
interface scope.

## Cleanup and recovery

`cleanup --dry-run` inventories resources without cloud writes. Plain `cleanup`
previews and confirms interactively; `cleanup --yes` skips confirmation. Every
form considers all Flux-owned runs, including active runs and orphans. No run ID,
grace interval or include-active switch is needed. Unrelated project resources
are never selected; resources with unprovable ownership are reported for review.
A project-scoped authentication token is required. The local cloud-operation lock
prevents concurrent mutation by another Flux process using the same scope.

Resume and cleanup inspect historical operations automatically and append evidence
when terminal state is proven. They never infer that a timed-out request failed
just because its resource is not yet visible. Unresolved operations remain blocked;
let the operation settle and rerun. If it does not settle, inspect its journal and
recovery.md, repair the actual OpenStack state, then retry. There is no manual
journal-resolution command or arbitrary outcome flag.

A completed Nova migration can still fail Neutron port or guest validation.
Flux keeps that validation failure while recording the cloud operation as settled
only after its terminal state and resource ownership are verified. Cleanup can
also recover older port-validation-only journal entries after three fresh,
matching control-plane observations. Missing evidence or an active operation
keeps cleanup blocked; a port status failure is never rewritten as a passing test.

Cleanup waits for inventory visibility before accepting an empty project and
reports incomplete cleanup while relevant submissions remain unresolved. Recovery
guidance includes those requests even when no resource is visible. Delete commands
are omitted from recovery scripts until their outcomes are known. `--dry-run`
remains a preview even for an empty project and does not resolve journal entries.

Cleanup can wait for accepted router/network cleanup owned by another live worker.
That wait does not waive verification: failed, abandoned or ambiguous operations
still block dependent work. A deletion timeout cannot be recorded as successful
without confirmed resource absence.

When the SSH jump host becomes unreachable, Flux captures its transport, Nova
server, Neutron ports and available console evidence. A recovery check lasts at
most 30 seconds, followed by bounded diagnostic reads if needed. Recovery resumes
endpoint work; persistent loss stops that execution scope before more endpoint
groups are provisioned. Other availability zones can continue. SSH control-path
errors do not establish a failure of the endpoint network being tested.

`--keep-resources` retains resources remaining at the end of a successful or failed
run. Transient probe processes still stop, and resources rotated out during normal
suite execution have already been removed. Explicit `cleanup` removes retained
resources. Resume restores recorded workload settings; only output directory and
keep-resources can accompany it.

## Examples

```sh
python3 neutron-flux.py plan --image debian-13 --flavor x1.nano --storage host --external-networks Public1,Public2 --zones bc-van1,bc-van2,bc-van3
python3 neutron-flux.py run --image debian-13 --flavor x1.nano --storage host --external-networks Public1,Public2 --zones bc-van1,bc-van2,bc-van3 --repeat 3
python3 neutron-flux.py run --image debian-13 --flavor x1.nano --storage volume --volume-type fast --external-networks Public1 --target-host-pairs compute1:compute2 --live-attempts 5
python3 neutron-flux.py run --resume RUN_ID
python3 neutron-flux.py cleanup --dry-run
python3 neutron-flux.py cleanup --yes
python3 neutron-flux.py report neutron-flux-reports/runs/RUN_ID/results.json
```
