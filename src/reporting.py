from collections import Counter
from .models import Finding, FirewallRule


def metrics(rules: list[FirewallRule], findings: list[Finding]) -> dict:
    enabled = [r for r in rules if r.enabled]
    return {
        "total_rules": len(rules),
        "enabled_rules": len(enabled),
        "findings": len(findings),
        "critical_high": sum(1 for f in findings if f.severity in {"critical", "high"}),
        "highest_score": max((f.score for f in findings), default=0),
        "findings_by_severity": dict(Counter(f.severity for f in findings)),
        "rules_without_owner": sum(1 for r in enabled if not r.owner.strip()),
        "rules_without_purpose": sum(1 for r in enabled if r.action == "allow" and not r.business_purpose.strip()),
    }


def markdown_report(rules: list[FirewallRule], findings: list[Finding]) -> str:
    m = metrics(rules, findings)
    lines = [
        "# Firewall Rule Review Assessment",
        "",
        "## Executive summary",
        f"- Rules assessed: **{m['total_rules']}**",
        f"- Enabled rules: **{m['enabled_rules']}**",
        f"- Findings: **{m['findings']}**",
        f"- Critical/High findings: **{m['critical_high']}**",
        f"- Highest contextual score: **{m['highest_score']}/100**",
        "",
        "## Governance indicators",
        f"- Enabled rules without accountable owner: **{m['rules_without_owner']}**",
        f"- Allow rules without documented purpose: **{m['rules_without_purpose']}**",
        "",
        "## Prioritized findings",
    ]
    if not findings:
        lines.append("No findings were produced by the implemented controls.")
    for f in findings:
        attack = ", ".join(f.attack_techniques) if f.attack_techniques else "Not applicable"
        lines += [
            f"### {f.severity.upper()} — {f.control} — Rule `{f.rule_id}`",
            f"- Score: **{f.score}/100**",
            f"- Rationale: {f.rationale}",
            f"- MITRE ATT&CK context: {attack}",
            f"- Remediation: {f.remediation}",
            f"- Validation: {f.validation}",
            "",
        ]
    lines += [
        "## Interpretation",
        "ATT&CK mappings provide threat context for exposed network paths; they are not evidence of compromise. The assessment is configuration-focused and should be combined with application dependency, flow telemetry, and change-governance evidence before production action.",
    ]
    return "\n".join(lines)
