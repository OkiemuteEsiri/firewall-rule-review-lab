import json
from pathlib import Path
from .models import FirewallRule


def load_rules(path: str | Path) -> list[FirewallRule]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("input must be a JSON array")
    rules = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("each rule must be a JSON object")
        required = {"rule_id", "name", "action", "direction", "protocol", "source", "destination", "port_start", "port_end", "owner", "business_purpose"}
        missing = required - set(item)
        if missing:
            raise ValueError(f"missing required field(s): {', '.join(sorted(missing))}")
        rules.append(FirewallRule(**item))
    return rules
