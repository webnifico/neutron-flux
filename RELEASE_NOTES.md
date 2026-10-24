# Neutron Flux v1.0.0

First stable release of Neutron Flux: automated OpenStack network validation
using temporary VMs, with detailed reports and verified resource cleanup.

## Coverage

- ICMP, TCP and UDP connectivity over applicable IPv4 and IPv6 paths.
- Same-subnet, project routing, static-route and selected provider-network paths.
- Router SNAT, floating-IP ingress, peer connections and self-hairpin traffic.
- Security-group enforcement and server, router-interface and floating-IP
  lifecycle checks.
- Same-compute and cross-compute placement, with one transition per eligible
  endpoint pair and probes in both placements.
- Live migration completion, established TCP survival, traffic recovery and
  separately reported interruption observations.
- MTU, path MTU discovery, fragmentation, TCP MSS and network performance
  measurements, including optional concurrent VM-pair traffic.

## Reports and operation

- Standalone HTML reports with topology, placement, measurements, diagnostic
  evidence and manual reproduction guidance.
- JSON, text and JUnit outputs, plus saved ownership and operation journals.
- Planning, interrupted-run resume, cleanup previews, verified cleanup, report
  regeneration and saved-run comparisons.
- Planned checks and supporting evidence are counted separately. Missing
  required evidence remains unverified, and advisory measurements remain
  distinct from functional failures.
- Network inventory displays **No AZ hints recorded** when its saved hint list
  is empty. Network scheduling hints and VM compute placement are reported
  separately.

## Scope

A passing run establishes the tested behavior for its recorded endpoints,
placements and time. It does not qualify every host or identify an underlying
network component as the cause of a failure.
