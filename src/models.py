from dataclasses import dataclass
from ipaddress import ip_network
from typing import Optional

VALID_ACTIONS = {"allow", "deny"}
VALID_DIRECTIONS = {"ingress", "egress"}
VALID_PROTOCOLS = {"tcp", "udp", "icmp", "any"}
VALID_CRITICALITY = {"low", "medium", "high", "critical"}

@dataclass(frozen=True)
class FirewallRule:
    rule_id: str
    name: str
    action: str
    direction: str
    protocol: str
    source: str
    destination: str
    port_start: Optional[int]
    port_end: Optional[int]
    owner: str
    business_purpose: str
    criticality: str = "medium"
    enabled: bool = True

    def __post_init__(self):
        if not self.rule_id or not self.name:
            raise ValueError("rule_id and name are required")
        if self.action not in VALID_ACTIONS:
            raise ValueError(f"unsupported action: {self.action}")
        if self.direction not in VALID_DIRECTIONS:
            raise ValueError(f"unsupported direction: {self.direction}")
        if self.protocol not in VALID_PROTOCOLS:
            raise ValueError(f"unsupported protocol: {self.protocol}")
        if self.criticality not in VALID_CRITICALITY:
            raise ValueError(f"unsupported criticality: {self.criticality}")
        ip_network(self.source, strict=False)
        ip_network(self.destination, strict=False)
        if self.protocol in {"tcp", "udp"}:
            if self.port_start is None or self.port_end is None:
                raise ValueError("TCP/UDP rules require a port range")
            if not (0 <= self.port_start <= self.port_end <= 65535):
                raise ValueError("invalid port range")

@dataclass(frozen=True)
class Finding:
    finding_id: str
    rule_id: str
    control: str
    severity: str
    score: int
    rationale: str
    attack_techniques: tuple[str, ...]
    remediation: str
    validation: str
