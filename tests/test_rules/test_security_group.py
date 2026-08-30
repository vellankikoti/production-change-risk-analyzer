from __future__ import annotations

import pytest

from src.models.schemas import ChangeType, ResourceChange
from src.rules.security_group import (
    AllTrafficRule,
    PublicSensitivePortRule,
    UnrestrictedIngressRule,
    WidePortRangeRule,
    get_all_sg_rules,
)
from src.parser.cloudformation import diff_templates, parse_template
from src.rules.base import RuleEngine


def _sg_change(ingress_rules: list[dict]) -> ResourceChange:
    return ResourceChange(
        resource_id="TestSG",
        resource_type="AWS::EC2::SecurityGroup",
        change_type=ChangeType.CREATE,
        before={},
        after={"SecurityGroupIngress": ingress_rules},
    )


class TestPublicSensitivePortRule:
    def test_detects_public_postgres(self):
        change = _sg_change([{"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "CidrIp": "0.0.0.0/0"}])
        findings = PublicSensitivePortRule().evaluate(change)
        assert len(findings) == 1
        assert findings[0].severity.value == "CRITICAL"
        assert "5432" in findings[0].finding

    def test_detects_public_ssh(self):
        change = _sg_change([{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"}])
        findings = PublicSensitivePortRule().evaluate(change)
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"

    def test_detects_public_rdp(self):
        change = _sg_change([{"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "CidrIp": "0.0.0.0/0"}])
        findings = PublicSensitivePortRule().evaluate(change)
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"

    def test_detects_ipv6_public(self):
        change = _sg_change([{"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "CidrIpv6": "::/0"}])
        findings = PublicSensitivePortRule().evaluate(change)
        assert len(findings) == 1

    def test_ignores_private_cidr(self):
        change = _sg_change([{"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "CidrIp": "10.0.0.0/16"}])
        findings = PublicSensitivePortRule().evaluate(change)
        assert len(findings) == 0

    def test_detects_sensitive_port_in_range(self):
        change = _sg_change([{"IpProtocol": "tcp", "FromPort": 5400, "ToPort": 5500, "CidrIp": "0.0.0.0/0"}])
        findings = PublicSensitivePortRule().evaluate(change)
        assert any("5432" in f.finding for f in findings)

    def test_detects_multiple_sensitive_ports(self):
        change = _sg_change([{"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535, "CidrIp": "0.0.0.0/0"}])
        findings = PublicSensitivePortRule().evaluate(change)
        assert len(findings) >= 5


class TestAllTrafficRule:
    def test_detects_all_traffic(self):
        change = _sg_change([{"IpProtocol": "-1", "CidrIp": "0.0.0.0/0"}])
        findings = AllTrafficRule().evaluate(change)
        assert len(findings) == 1
        assert findings[0].rule_id == "SG-004"
        assert findings[0].severity.value == "CRITICAL"

    def test_ignores_private_all_traffic(self):
        change = _sg_change([{"IpProtocol": "-1", "CidrIp": "10.0.0.0/8"}])
        findings = AllTrafficRule().evaluate(change)
        assert len(findings) == 0


class TestWidePortRangeRule:
    def test_detects_wide_range(self):
        change = _sg_change([{"IpProtocol": "tcp", "FromPort": 1000, "ToPort": 2000, "CidrIp": "10.0.0.0/16"}])
        findings = WidePortRangeRule().evaluate(change)
        assert len(findings) == 1
        assert findings[0].rule_id == "SG-003"

    def test_ignores_narrow_range(self):
        change = _sg_change([{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIp": "0.0.0.0/0"}])
        findings = WidePortRangeRule().evaluate(change)
        assert len(findings) == 0


class TestSGRulesWithFixtures:
    def test_dangerous_changes_detected(self, secure_baseline, dangerous_changes):
        before = parse_template(secure_baseline)
        after = parse_template(dangerous_changes)
        changes = diff_templates(before, after)
        engine = RuleEngine()
        engine.register_all(get_all_sg_rules())
        findings = engine.evaluate(changes)
        rule_ids = {f.rule_id for f in findings}
        assert "SG-001" in rule_ids
        assert "SG-004" in rule_ids

    def test_minor_changes_no_sg_issues(self, secure_baseline, minor_changes):
        before = parse_template(secure_baseline)
        after = parse_template(minor_changes)
        changes = diff_templates(before, after)
        engine = RuleEngine()
        engine.register_all(get_all_sg_rules())
        findings = engine.evaluate(changes)
        assert len(findings) == 0
