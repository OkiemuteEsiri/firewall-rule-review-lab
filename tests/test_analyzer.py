import unittest
from src.analyzer import assess_rule, assess_rules
from src.models import FirewallRule


def rule(**overrides):
    base = dict(
        rule_id="R-1", name="Synthetic rule", action="allow", direction="ingress", protocol="tcp",
        source="10.0.0.0/24", destination="10.1.0.10/32", port_start=443, port_end=443,
        owner="Network Team", business_purpose="Approved application path", criticality="medium", enabled=True,
    )
    base.update(overrides)
    return FirewallRule(**base)


class FirewallAnalyzerTests(unittest.TestCase):
    def test_invalid_cidr_rejected(self):
        with self.assertRaises(ValueError):
            rule(source="not-a-cidr")

    def test_invalid_port_range_rejected(self):
        with self.assertRaises(ValueError):
            rule(port_start=5000, port_end=4000)

    def test_public_rdp_flagged(self):
        findings = assess_rule(rule(source="0.0.0.0/0", port_start=3389, port_end=3389, criticality="critical"))
        self.assertTrue(any(f.control == "FW-002" for f in findings))

    def test_any_protocol_public_ingress_flagged(self):
        findings = assess_rule(rule(protocol="any", source="0.0.0.0/0", port_start=None, port_end=None))
        self.assertTrue(any(f.control == "FW-001" for f in findings))

    def test_unrestricted_egress_flagged(self):
        findings = assess_rule(rule(direction="egress", protocol="any", destination="0.0.0.0/0", port_start=None, port_end=None))
        self.assertTrue(any(f.control == "FW-003" for f in findings))

    def test_missing_owner_flagged(self):
        findings = assess_rule(rule(owner=""))
        self.assertTrue(any(f.control == "FW-004" for f in findings))

    def test_missing_purpose_flagged(self):
        findings = assess_rule(rule(business_purpose=""))
        self.assertTrue(any(f.control == "FW-005" for f in findings))

    def test_full_port_range_flagged(self):
        findings = assess_rule(rule(port_start=0, port_end=65535))
        self.assertTrue(any(f.control == "FW-006" for f in findings))

    def test_disabled_rules_ignored(self):
        self.assertEqual(assess_rule(rule(enabled=False)), [])

    def test_duplicate_rule_ids_rejected(self):
        with self.assertRaises(ValueError):
            assess_rules([rule(), rule(name="Duplicate")])


if __name__ == "__main__":
    unittest.main()
