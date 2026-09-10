# Architecture and Methodology

## Purpose
This project demonstrates a defensive, offline firewall-rule governance review workflow. It is designed for synthetic or explicitly authorized configuration exports and does not connect to production firewalls or make network changes.

## Architecture
1. `src/models.py` validates canonical rule and finding records.
2. `src/io.py` performs fail-closed JSON ingestion.
3. `src/analyzer.py` evaluates deterministic controls and produces evidence-preserving findings.
4. `src/reporting.py` calculates governance metrics and renders a prioritized Markdown assessment.
5. `src/cli.py` provides a repeatable offline execution path.
6. `tests/` verifies validation and control behavior.

## Review controls
- **FW-001**: unrestricted public ingress using any protocol.
- **FW-002**: internet exposure of sensitive administrative or data services.
- **FW-003**: unrestricted any-protocol internet egress.
- **FW-004**: missing accountable rule owner.
- **FW-005**: undocumented business purpose.
- **FW-006**: full TCP/UDP port-range allow rules.

## Risk model
Each finding receives a deterministic 0–100 contextual score. The base control risk is increased by destination/workload criticality. Scores are bounded and mapped to Critical, High, Medium, or Low. This is prioritization support, not a replacement for business-impact analysis.

## MITRE ATT&CK context
Relevant threat context includes T1190 (Exploit Public-Facing Application), T1133 (External Remote Services), T1021 (Remote Services), T1210 (Exploitation of Remote Services), T1071 (Application Layer Protocol), and T1041 (Exfiltration Over C2 Channel). ATT&CK mappings explain how weak network policy can increase opportunity; they do not establish compromise.

## Remediation workflow
1. Confirm rule owner and business dependency.
2. Validate observed traffic where available.
3. Reduce source/destination scope.
4. Restrict protocols and ports to minimum required access.
5. Move administrative services behind managed access paths.
6. Apply change control with rollback criteria.
7. Re-run policy review after implementation.
8. Validate application connectivity and confirm the excessive path is closed.

## Governance considerations
A mature firewall review should also include rule age, last-hit data, shadowed rules, object-group expansion, change-ticket linkage, exception expiry, segmentation-zone policy, and recertification evidence. Those controls are roadmap items rather than fabricated capabilities in the current implementation.

## Limitations
The engine evaluates declared rule configuration only. It does not emulate vendor-specific policy ordering, NAT, routing, stateful return traffic, nested object groups, or effective-path behavior. Production decisions require platform-native validation and change governance.
