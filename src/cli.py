import argparse
from pathlib import Path
from .analyzer import assess_rules
from .io import load_rules
from .reporting import markdown_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Review synthetic/authorized firewall rule exports for governance and exposure risks.")
    parser.add_argument("input", help="Path to JSON firewall-rule inventory")
    parser.add_argument("--output", default="reports/generated-assessment.md", help="Markdown report path")
    args = parser.parse_args()
    rules = load_rules(args.input)
    findings = assess_rules(rules)
    report = markdown_report(rules, findings)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
    print(f"Assessed {len(rules)} rules; generated {len(findings)} findings -> {output}")


if __name__ == "__main__":
    main()
