# Automatic AZ placement

Flux discovers compute and service AZs before creating resources. Each selected
compute AZ remains the target for its controller and test VMs. Network, router
and volume placement are resolved independently.

| Resource | Matching available AZ | No matching available AZ |
| --- | --- | --- |
| Compute | Selected AZ | An explicitly requested unavailable AZ is rejected |
| Created network | Request the compute AZ as a hint | Sole available network AZ; otherwise Neutron defaults |
| Created router | Request the compute AZ as a hint | Sole available router AZ; otherwise Neutron defaults |
| Root volume | Request the compute AZ if the volume type supports it | Omit the AZ constraint and use Cinder defaults with the selected type |

Flux selects network and router availability-zone hints independently, using the
AZs advertised for each resource type. A matching router AZ is requested even
when no matching network AZ is advertised. Network placement follows its own
fallback policy; if network AZ hints are unsupported, Flux omits the network hint.
An absent matching network AZ does not establish that networking is unavailable
in the selected compute AZ.

Unavailable Neutron AZs are excluded from fallback selection and recorded in the
inventory. A service with a visible but entirely unavailable AZ inventory blocks
setup. Missing optional Neutron AZ extensions omit hints. Unobservable Cinder AZ
inventory uses Cinder defaults and records the discovery limitation. A volume
type with no compatible available Cinder AZ blocks setup before provisioning.

Fallback never changes a requested compute AZ or volume type. Nova may reject a
cross-AZ volume attachment; that is reported as a setup failure and the rejected
boot volume is cleaned up. Flux does not override Nova policy or retry by moving
a targeted VM elsewhere. Automatic controller fallback also rejects a candidate
if its required network/router hints differ from the already-created topology;
choose that compute AZ explicitly to build a fresh matching topology. A volume
that fails to honour an explicit matching AZ request is rejected rather than
accepted as fallback.

Requested hints, selection reasons, actual reported AZs and verification status
are saved separately. Hints do not prove physical locality; missing actual
placement remains unverified. Existing external networks, subnet pools, security
groups and keypairs are not moved or assigned invented AZs. Ports and subnets
follow their containing topology where applicable.

Multiple compute zones retain both local and cross-zone network coverage.
Migrations remain within the selected compute zone.

References: [Neutron OVN AZs](https://docs.openstack.org/neutron/latest/admin/ovn/availability_zones.html),
[Cinder volume-type AZs](https://docs.openstack.org/cinder/latest/admin/availability-zone-type.html).
