# Firewall Rule Review Lab

Defensive Network Security / Security Engineering project for reviewing firewall-rule exports, prioritizing risky access paths, and enforcing remediation and revalidation discipline.

## Problem statement
Firewall estates often accumulate broad ingress, unrestricted egress, undocumented rules, missing ownership, and sensitive-service exposure. Manual reviews can become inconsistent when technical exposure, asset criticality, and governance defects are considered separately. This project demonstrates a deterministic, explainable review workflow that turns normalized rule data into prioritized findings and remediation evidence requirements.

## What this project demonstrates
- Defensive firewall policy analysis using Python.
- Fail-closed validation of rule inventories and CIDR/port inputs.
- Deterministic 0–100 contextual risk scoring.
- Prioritization of internet-exposed administrative and data services.
- Governance checks for ownership and business justification.
- Egress-control assessment.
- Evidence-preserving Markdown reporting.
- MITRE ATT&CK-informed risk communication.
- Unit-tested controls and least-privilege CI.
- Remediation and revalidation criteria rather than ticket-closure-only reporting.

## Architecture
```text
Synthetic / authorized JSON rule export
                 |
                 v
          src/io.py
     fail-closed ingestion
                 |
                 v
        src/models.py
      canonical validation
                 |
                 v
       src/analyzer.py
  deterministic controls + risk
                 |
                 v
      src/reporting.py
 metrics + prioritized Markdown
                 |
                 v
          src/cli.py
        offline workflow
```

## Implemented controls
| ID | Control | Security purpose |
|---|---|---|
| FW-001 | Any-protocol public ingress | Identify highly permissive inbound access |
| FW-002 | Internet-exposed sensitive service | Prioritize SSH/RDP/SMB/database exposure |
| FW-003 | Any-protocol unrestricted egress | Identify weak outbound containment |
| FW-004 | Missing accountable owner | Enforce governance and recertification ownership |
| FW-005 | Missing business purpose | Require traceable justification for allow rules |
| FW-006 | Full TCP/UDP port range | Reduce unnecessary service exposure |

## Risk model
Each finding receives a bounded contextual score from **0–100**. The implemented model combines a control-specific base score with workload criticality. This makes a public management path protecting a critical workload rank above the same configuration on a lower-impact system.

Severity bands:
- **Critical:** 85–100
- **High:** 65–84
- **Medium:** 40–64
- **Low:** 0–39

The score is intended for prioritization, not as a substitute for business-impact analysis, flow validation, or formal risk acceptance.

## MITRE ATT&CK context
Where applicable, findings include mappings such as:
- **T1190 — Exploit Public-Facing Application**
- **T1133 — External Remote Services**
- **T1021 — Remote Services**
- **T1210 — Exploitation of Remote Services**
- **T1071 — Application Layer Protocol**
- **T1041 — Exfiltration Over C2 Channel**

ATT&CK mappings provide threat context only; they are **not evidence of compromise**.

## Repository structure
```text
.github/workflows/ci.yml       Least-privilege CI
src/models.py                  Canonical rule/finding models
src/io.py                      JSON ingestion and schema controls
src/analyzer.py                Firewall review engine
src/reporting.py               KPI and Markdown reporting
src/cli.py                     Offline command-line runner
data/synthetic_rules.json      Realistic synthetic rule inventory
tests/test_analyzer.py         Unit tests for validation and controls
docs/architecture-methodology.md
reports/example-assessment.md
```

## Usage
The lab is intentionally offline and operates on synthetic or explicitly authorized exports.

```bash
python -m src.cli data/synthetic_rules.json --output reports/generated-assessment.md
```

Run unit tests:

```bash
python -m unittest discover -s tests -v
```

## Example review workflow
1. Normalize rule exports into the canonical model.
2. Reject malformed CIDRs, unsupported values, duplicate rule IDs, and invalid port ranges.
3. Evaluate exposure and governance controls.
4. Rank findings by contextual risk.
5. Validate ownership and application dependency.
6. Reduce source, destination, protocol, and port scope.
7. Move administrative access behind managed access paths where appropriate.
8. Apply controlled change with rollback criteria.
9. Re-run the assessment.
10. Confirm the excessive path is closed and expected application traffic remains functional.

## Remediation philosophy
A finding is not considered resolved merely because a change ticket is closed. Revalidation should demonstrate that:
- the effective firewall policy has changed;
- the excessive path is no longer permitted;
- approved application traffic still works;
- ownership and justification are documented;
- any exception has explicit scope and review criteria.

## Example dataset
`data/synthetic_rules.json` contains only fictional private/test network values and documentation-range addresses. It includes examples of public RDP, public PostgreSQL, unrestricted egress, a constrained HTTPS rule, and a disabled migration rule.

No employer, client, production, or confidential data is included.

## CI/CD security
GitHub Actions uses read-only repository content permissions and performs:
- Python compilation checks;
- unit-test discovery and execution;
- an offline smoke test against the synthetic dataset.

The presence of this workflow should not be interpreted as proof that a particular commit passed unless its workflow result has been independently verified.

## Design decisions
- **Deterministic findings:** stable SHA-256-derived IDs support remediation tracking.
- **Fail-closed input validation:** malformed policy data is rejected rather than silently normalized into misleading results.
- **Configuration review, not scanning:** the tool does not probe hosts or interact with network infrastructure.
- **Explainable scoring:** every finding retains rationale, remediation, validation criteria, and ATT&CK context.
- **Governance included:** ownership and business purpose are first-class security controls.

## Limitations
The current implementation does not emulate vendor-specific policy precedence, NAT, routing, stateful return traffic, object-group expansion, shadowed-rule behavior, or last-hit telemetry. It therefore cannot establish the true effective path in a production network by itself.

Production use would require platform-native validation, traffic-flow evidence, change governance, and organization-specific control thresholds.

## Skills demonstrated
- Network Security Engineering
- Firewall Policy Review
- Network Segmentation Governance
- Exposure Management
- Python Security Automation
- Risk Prioritization
- MITRE ATT&CK Mapping
- Defensive Security Testing
- Security Metrics and Reporting
- Remediation Validation
- CI/CD Security Controls

## Roadmap
Planned safe extensions include:
- vendor-neutral CSV adapters;
- rule-age and exception-expiry controls;
- shadowed/redundant rule analysis using synthetic policy-order semantics;
- object-group expansion for synthetic inventories;
- last-hit and recertification metrics;
- segmentation-zone policy comparison;
- JSON report export for dashboard ingestion;
- trend reporting across synthetic assessment snapshots.

## Safety and ethical use
This repository is designed for defensive engineering, authorized review, and portfolio demonstration. It contains no exploitation, credential theft, live scanning, firewall modification, persistence, malware, production targeting, or confidential client data.
