import hashlib
from ipaddress import ip_network
from .models import FirewallRule, Finding

SENSITIVE_PORTS = {22: "SSH", 23: "Telnet", 3389: "RDP", 445: "SMB", 1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL"}
SEVERITY_BY_SCORE = ((85, "critical"), (65, "high"), (40, "medium"), (0, "low"))


def _is_any(net: str) -> bool:
    return ip_network(net, strict=False).prefixlen == 0


def _finding(rule: FirewallRule, control: str, score: int, rationale: str, techniques: tuple[str, ...], remediation: str, validation: str) -> Finding:
    score = max(0, min(100, score))
    severity = next(label for threshold, label in SEVERITY_BY_SCORE if score >= threshold)
    fid = hashlib.sha256(f"{rule.rule_id}:{control}".encode()).hexdigest()[:16]
    return Finding(fid, rule.rule_id, control, severity, score, rationale, techniques, remediation, validation)


def assess_rule(rule: FirewallRule) -> list[Finding]:
    if not rule.enabled or rule.action != "allow":
        return []
    findings: list[Finding] = []
    src_any, dst_any = _is_any(rule.source), _is_any(rule.destination)
    criticality = {"low": 0, "medium": 8, "high": 16, "critical": 24}[rule.criticality]

    if rule.direction == "ingress" and src_any and rule.protocol == "any":
        findings.append(_finding(rule, "FW-001", 70 + criticality, "Unrestricted public ingress permits any protocol.", ("T1190", "T1133"), "Restrict source networks and permitted protocols to the minimum business requirement.", "Re-review the effective policy and confirm only approved source ranges/protocols remain."))

    if rule.direction == "ingress" and src_any and rule.protocol in {"tcp", "udp"}:
        exposed = [p for p in SENSITIVE_PORTS if rule.port_start <= p <= rule.port_end]
        if exposed:
            names = ", ".join(SENSITIVE_PORTS[p] for p in exposed)
            findings.append(_finding(rule, "FW-002", 68 + criticality, f"Internet-exposed sensitive service(s): {names}.", ("T1133", "T1021"), "Limit administrative/data services to trusted management networks, VPN, or zero-trust access paths.", "Verify the rule no longer permits untrusted source ranges to reach the sensitive service."))

    if rule.direction == "egress" and dst_any and rule.protocol == "any":
        findings.append(_finding(rule, "FW-003", 48 + criticality, "Unrestricted any-protocol egress reduces containment and monitoring effectiveness.", ("T1071", "T1041"), "Define destination/service allowlists appropriate to the workload and route unavoidable broad egress through monitored controls.", "Confirm effective egress rules are scoped and expected application traffic still functions."))

    if not rule.owner.strip():
        findings.append(_finding(rule, "FW-004", 35 + criticality, "The rule has no accountable owner.", tuple(), "Assign a named service/team owner and establish periodic certification.", "Confirm ownership is recorded and included in the next access-rule review."))

    if not rule.business_purpose.strip():
        findings.append(_finding(rule, "FW-005", 40 + criticality, "No documented business justification exists for the allow rule.", tuple(), "Document the approved business purpose, dependency, requester, and review date or remove the rule.", "Confirm the justification is approved and traceable to the rule identifier."))

    if rule.protocol in {"tcp", "udp"} and rule.port_start == 0 and rule.port_end == 65535:
        findings.append(_finding(rule, "FW-006", 55 + criticality, "The rule permits the full TCP/UDP port range.", ("T1210",), "Replace the full range with explicitly required service ports.", "Validate that only documented application ports are allowed after change."))
    return findings


def assess_rules(rules: list[FirewallRule]) -> list[Finding]:
    seen = set()
    findings: list[Finding] = []
    for rule in rules:
        if rule.rule_id in seen:
            raise ValueError(f"duplicate rule_id: {rule.rule_id}")
        seen.add(rule.rule_id)
        findings.extend(assess_rule(rule))
    return sorted(findings, key=lambda f: (-f.score, f.rule_id, f.control))
