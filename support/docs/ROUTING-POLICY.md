# Routing expectations

Flux separates address allocation, the intended routing policy, and measured
connectivity. A subnet pool allocates prefixes. Neither a pool, a public-looking
address nor a guest default route proves that two networks must communicate.
Selecting provider networks declares that they must route between each other.
Probe success never creates its own expectation.

## Default decisions

| Path | Requirement |
|---|---|
| Same subnet with permitted test traffic | Reachable |
| Internal networks connected by Flux's router or installed static routes | Reachable; lifecycle withdrawal/restoration has explicit prerequisites |
| Matching project/external address scopes with a configured router | Direct fixed-IP routing |
| Different scopes, IPv4 outbound | Reachable only after default SNAT is verified enabled |
| Different scopes, reverse fixed IPv4 or IPv6 without translation | Blocked |
| Missing scope metadata, IPv4 outbound | Reachable only after default SNAT is verified enabled |
| Missing scope metadata, reverse IPv4 fixed IP | Omitted; no declared routing expectation |
| Missing scope metadata, pool-derived IPv6 | Omitted in both directions |
| Generated private IPv6 to/from an external network | Omitted unless explicitly declared; internal tests remain |
| Separate selected provider networks | Reachable in both directions with ICMP, TCP and UDP for every shared IP family |
| Different segments of the same routed provider network | Reachable according to the network's declared routed topology |

Private IPv6 addresses can be routed internally. A ULA prefix does not establish
isolation, and a globally unique prefix does not establish an upstream route.
Flux does not infer an underlying fabric implementation from address scopes.

Plans omit paths for which neither reachability nor isolation is established,
with a reason in skipped coverage. They do not enter performance tests. Historical
`observation` results retain their original `UNVERIFIED` verdicts. Execution errors
remain `ERROR`; a valid requirement contradicted by a probe remains `FAIL`.

## Routing policy inputs

Flux derives routing expectations from discovered topology, address scopes and
the selected-provider routability contract. YAML and CLI JSON routing overrides
are not supported. Historical saved reports and immutable resume snapshots can
contain their original resolved contracts; these describe what that run tested.

## Source NAT and floating IPs

Flux preserves the cloud's router settings. It does not enable or disable SNAT.
Dedicated private IPv4 translation topology requires verified SNAT. Other
routers can retain SNAT disabled, including directly routed pool networks.
If a test relies on SNAT but the runtime setting is not verified enabled, its
fixed-IP connectivity is recorded as an observation. Dedicated packet profiles
verify the source address actually seen by the provider endpoint.

Floating-IP translation is tested from a controlled provider endpoint on the
floating-IP subnet, using ICMP, TCP, and UDP. The API-confirmed association and
known source/target subnet establish the local translation requirement before
the probe. Withdrawal/restoration proceeds only after a successful, authoritative
TCP baseline. A blocked local baseline remains a failure.

The runner's ingress attempt is retained separately in
`probe.diagnostics.external_ingress_observation`. Its gateway route is a routing
observation, not proof that upstream routing or firewall policy permits ingress.
A local translation PASS does not certify Internet ingress. When no provider
endpoint is available on the floating-IP subnet, new plans omit that ingress path
and its dependent lifecycle/performance checks with a coverage reason. Outbound source-address, MTU, and
fragmentation tests retain their independent prerequisites.

The IPv4 peer matrix gives both VMs floating IPs on the same external subnet.
It checks both directions behind one router and behind two separate routers,
plus each VM reaching its own floating IP. All probes bind to the private data
address and target the floating address. ICMP tests reachability; TCP/UDP also
validate destination server and service identity. Across separate routers the
observed source must be the source VM's floating IP. Same-router/hairpin paths
record their observed source without prescribing backend-specific hairpin SNAT.
These are functional tests, not additional performance stages. At most two
endpoint VMs and two test floating IPs are needed simultaneously, plus the existing
controller allowance. Flux does not add guest routes or alter SNAT settings.

Internal one-router and two-router fixed-IP tests use disjoint generated private
prefixes when no usable project subnet pools exist. Static-route scenarios still
require the corresponding Neutron extension. A synthetic IPv4 routing-metadata
control is covered by the existing translation topology when their gateway and
SNAT contract match; explicitly configured control prefixes remain separate.

A separate private source with no floating IP also probes a destination floating
IP through router SNAT and DNAT. The source port is checked for absent FIP
associations, and TCP/UDP replies must identify the destination and report the
source router gateway address. Its mappings and fixed endpoints survive eligible
migration checks.

Each migration submission requires fresh ICMP/TCP/UDP checks on the selected
VM-to-VM paths and the applicable external ICMP reachability checks.
Supporting samples display their own position and do not increment logical
check totals. The continuity monitor preserves one TCP connection through
write stalls, records partial writes without replay, and verifies the receiver
byte count. Missing final acknowledgement, resets and incomplete delivery remain
failures. A completed, verified migration with surviving TCP and recovered
traffic passes. ICMP/UDP interruption above tolerance adds `[OBSERVATION]`;
the tolerance levels reflect the goal of zero customer downtime.

## Evidence and upgrade

Project/provider and provider/provider results include `routing_policy` with
expectation, authority, basis, and reason. Historical configured contracts retain
their configuration provenance. JSON, HTML, JUnit, and performance selection consume
the same verdict. Comparing reports from different builds can show expectation changes;
that does not imply the network changed.

Generate a fresh plan using the current defaults. Rebuilding an old report
preserves the recorded expectations and results; it does not silently rewrite
historical failures. Live validation must cover the site's actual routing,
translation, and isolation policies before production use.

## Regression coverage

- Both families, both directions, and matching/different/missing scopes.
- A topology with no IPv6 pool: local IPv6 stays, unsupported external
  assertions disappear, and IPv4 translation coverage remains.
- Unscoped pool-derived IPv6, explicit private IPv6 routing, and internal ULA routing.
- Historical contract compatibility, direction/protocol-specific rules, alias
  conflicts, and provider-to-project selector separation.
- SNAT enabled/disabled/unknown, local floating-IP failure/success, and an
  external failure that cannot override the independent local result.
- Unknown routing paths cannot become performance candidates merely by succeeding.
