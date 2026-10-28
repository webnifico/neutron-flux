from __future__ import annotations

GLOSSARY = [
    {
        "term": "Path",
        "definition": "One tested source-to-destination direction. The reverse direction is listed separately when Flux tests it independently.",
    },
    {
        "term": "Source IP",
        "definition": "The IP address Flux selected on the endpoint that originated the probe.",
    },
    {
        "term": "Destination IP",
        "definition": "The IP address to which Flux sent the probe.",
    },
    {
        "term": "Intra-compute",
        "definition": "Both endpoint virtual machines were hosted on the same OpenStack compute node.",
    },
    {
        "term": "Inter-compute",
        "definition": "The endpoint virtual machines were hosted on different OpenStack compute nodes.",
    },
    {
        "term": "ICMP",
        "definition": "Internet Control Message Protocol. Flux primarily uses ICMP echo requests and replies for reachability and latency measurements.",
    },
    {
        "term": "TCP",
        "definition": "Transmission Control Protocol. Flux uses TCP for connection validation and throughput measurements.",
    },
    {
        "term": "UDP",
        "definition": "User Datagram Protocol. Flux uses UDP to measure loss, jitter, packet rate, and packet reordering.",
    },
    {
        "term": "MTU",
        "definition": "Maximum Transmission Unit: the largest IP packet the interface or path can carry without fragmentation.",
    },
    {
        "term": "PMTUD",
        "definition": "Path MTU Discovery: the process used to determine the largest packet that can traverse the complete network path without fragmentation.",
    },
    {
        "term": "MSS",
        "definition": "Maximum Segment Size: the largest TCP payload advertised by each endpoint, normally derived from the effective MTU.",
    },
    {
        "term": "p50",
        "definition": "50th percentile, also called the median: half of measured samples were at or below this value.",
    },
    {
        "term": "p95",
        "definition": "95th percentile: 95% of measured samples were at or below this value; the slowest 5% were higher.",
    },
    {
        "term": "p99",
        "definition": "99th percentile: 99% of measured samples were at or below this value; the slowest 1% were higher.",
    },
    {
        "term": "RTT",
        "definition": "Round-trip time: the elapsed time for a packet to reach the destination and for its reply to return.",
    },
    {"term": "PPS", "definition": "Packets per second: the packet processing rate."},
    {
        "term": "Jitter",
        "definition": "Variation in packet delay between samples. Lower and more stable values are generally better.",
    },
    {
        "term": "SNAT",
        "definition": "Source Network Address Translation: rewrites the source address of outbound project-network traffic.",
    },
    {
        "term": "DNAT",
        "definition": "Destination Network Address Translation: rewrites the destination address, such as when a floating IP forwards traffic to a project-network fixed IP.",
    },
    {
        "term": "Floating IP",
        "definition": "A Neutron external address mapped to a project-network fixed IP, normally using destination and source network address translation.",
    },
    {
        "term": "Static route",
        "definition": "An explicitly configured destination prefix and next hop on a router. Neutron exposes these through its extra_routes API field.",
    },
    {
        "term": "Advertised MTU",
        "definition": "The MTU Neutron reports to the guest for the network.",
    },
    {
        "term": "Confirmed no-fragment path MTU",
        "definition": "The largest packet size Flux independently confirmed across the tested source-to-destination path with fragmentation disabled. A cached route PMTU or local interface limit is shown separately and does not become a confirmed path boundary.",
    },
    {
        "term": "Jumbo frame",
        "definition": "An Ethernet/IP packet larger than the common 1500-byte MTU. Flux uses the actual Neutron and guest MTUs, including values such as 9000 bytes.",
    },
    {
        "term": "Fragmentation",
        "definition": "Splitting one oversized IPv4 packet into smaller fragments that fit a narrower path and reassembling them at the destination. Flux reports path capability and does not claim which component fragmented the packet unless direct evidence exists.",
    },
    {
        "term": "No-fragment path MTU",
        "definition": "The largest packet Flux confirmed across the complete source-to-destination path with fragmentation disabled.",
    },
    {
        "term": "Router source NAT",
        "definition": "Outbound project-network traffic translated to a Neutron router external-gateway address when the endpoint has no floating IP.",
    },
    {
        "term": "Floating-IP egress",
        "definition": "Outbound traffic from a fixed IP that is translated to its associated Neutron floating IP.",
    },
    {
        "term": "IPv6 source fragmentation",
        "definition": "IPv6 routers never fragment packets. Only the source may create IPv6 fragments, normally after Path MTU Discovery identifies a smaller path.",
    },
    {
        "term": "Project network",
        "definition": "A Neutron network owned by an OpenStack project. It may be an overlay network, a provider-backed network, shared, routed, or isolated; the dashboard shows the discovered role separately.",
    },
    {
        "term": "Subnet pool",
        "definition": "A managed collection of IP prefixes from which Neutron allocates complete subnet CIDRs. It is different from a subnet allocation pool of individual port addresses.",
    },
    {
        "term": "Port address allocation range",
        "definition": "The range of individual IP addresses Neutron may assign to ports inside one subnet. This is not a subnet pool.",
    },
    {
        "term": "Address scope",
        "definition": "A Neutron addressing and routing domain associated with subnet pools. It provides policy context but does not by itself prove packet connectivity.",
    },
    {
        "term": "95% confidence interval",
        "definition": "A Student-t interval showing uncertainty around the sample mean. Overlapping intervals make a claimed baseline change inconclusive.",
    },
    {
        "term": "Outlier",
        "definition": "A sample outside the Tukey 1.5-IQR fences. Flux keeps these samples visible rather than silently deleting them.",
    },
    {
        "term": "Plan fingerprint",
        "definition": "A SHA-256 identity for the approved configuration, cloud inventory, capabilities, and test plan.",
    },
    {
        "term": "Offered UDP rate",
        "definition": "The traffic rate Flux attempted to send. Achieved rate is reported separately from this requested load.",
    },
]

__all__ = ["GLOSSARY"]
