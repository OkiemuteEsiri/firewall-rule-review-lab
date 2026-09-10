# Example Firewall Rule Review Assessment

> Synthetic portfolio example. No production firewall data is included.

## Executive summary
The sample inventory demonstrates how broad ingress, sensitive-service exposure, unrestricted egress, and weak rule governance can be prioritized together rather than reviewed as isolated configuration defects.

### Highest-priority examples
- **FW-1001 — Public RDP exposure:** critical workload with RDP reachable from `0.0.0.0/0`. Recommended action: restrict to managed access paths and trusted administration sources, then revalidate the effective rule.
- **FW-1003 — Public PostgreSQL exposure:** high-criticality database service reachable from the Internet, with no accountable owner or documented purpose. Recommended action: validate dependency, assign ownership, remove public exposure, and document the approved application path.
- **FW-1002 — Unrestricted egress:** high-criticality workload permits any-protocol outbound access. Recommended action: establish destination/service requirements and reduce egress scope while preserving required application traffic.

## Validation standard
A remediation is not considered complete solely because a ticket is closed. Validation should confirm the effective policy is changed, the excessive network path is removed, approved application traffic continues to function, and ownership/business justification remain current.

## Threat context
ATT&CK techniques are used for risk communication only. Public administrative services can increase opportunity for External Remote Services (T1133) and Remote Services (T1021), while broad egress can weaken controls relevant to Application Layer Protocol (T1071) and Exfiltration Over C2 Channel (T1041). These mappings are not evidence that adversary activity occurred.
