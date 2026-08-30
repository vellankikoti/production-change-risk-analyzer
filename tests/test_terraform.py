"""Tests for Terraform plan JSON parsing and analysis."""
from __future__ import annotations

import json
import os

import pytest

from src.models.schemas import ChangeType, Severity
from src.parser.terraform import is_terraform_plan, parse_terraform_plan


FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "terraform")


def _load_fixture(name: str) -> str:
    with open(os.path.join(FIXTURES_DIR, name)) as f:
        return f.read()


class TestIsTerraformPlan:
    def test_valid_plan(self):
        assert is_terraform_plan(_load_fixture("dangerous_plan.json"))

    def test_safe_plan(self):
        assert is_terraform_plan(_load_fixture("safe_plan.json"))

    def test_cloudformation_yaml(self):
        assert not is_terraform_plan("AWSTemplateFormatVersion: '2010-09-09'\nResources: {}")

    def test_cloudformation_json(self):
        assert not is_terraform_plan('{"AWSTemplateFormatVersion": "2010-09-09", "Resources": {}}')

    def test_changeset_json(self):
        cs = '{"Changes": [{"ResourceChange": {"Action": "Add"}}]}'
        assert not is_terraform_plan(cs)

    def test_empty_string(self):
        assert not is_terraform_plan("")

    def test_invalid_json(self):
        assert not is_terraform_plan("not json at all")


class TestParseTerraformPlan:
    def test_dangerous_plan_parses_all_resources(self):
        changes = parse_terraform_plan(_load_fixture("dangerous_plan.json"))
        assert len(changes) == 6

    def test_dangerous_plan_resource_types(self):
        changes = parse_terraform_plan(_load_fixture("dangerous_plan.json"))
        types = {c.resource_type for c in changes}
        assert "AWS::EC2::SecurityGroup" in types
        assert "AWS::IAM::Role" in types
        assert "AWS::RDS::DBInstance" in types
        assert "AWS::S3::Bucket" in types
        assert "AWS::EC2::Volume" in types

    def test_dangerous_plan_all_creates(self):
        changes = parse_terraform_plan(_load_fixture("dangerous_plan.json"))
        for c in changes:
            assert c.change_type == ChangeType.CREATE

    def test_sg_normalization_dangerous(self):
        changes = parse_terraform_plan(_load_fixture("dangerous_plan.json"))
        sg = next(c for c in changes if c.resource_id == "aws_security_group.database")
        ingress = sg.after.get("SecurityGroupIngress", [])
        assert len(ingress) == 1
        assert ingress[0]["CidrIp"] == "0.0.0.0/0"
        assert ingress[0]["FromPort"] == 5432

    def test_iam_normalization_admin(self):
        changes = parse_terraform_plan(_load_fixture("dangerous_plan.json"))
        role = next(c for c in changes if c.resource_id == "aws_iam_role.admin")
        policies = role.after.get("Policies", [])
        assert len(policies) == 1
        doc = policies[0]["PolicyDocument"]
        assert isinstance(doc, dict)
        stmt = doc["Statement"][0]
        assert stmt["Action"] == "*"
        assert stmt["Resource"] == "*"

    def test_rds_normalization(self):
        changes = parse_terraform_plan(_load_fixture("dangerous_plan.json"))
        rds = next(c for c in changes if c.resource_type == "AWS::RDS::DBInstance")
        assert rds.after["PubliclyAccessible"] is True
        assert rds.after["MultiAZ"] is False
        assert rds.after["StorageEncrypted"] is False
        assert rds.after["BackupRetentionPeriod"] == 0

    def test_ebs_normalization(self):
        changes = parse_terraform_plan(_load_fixture("dangerous_plan.json"))
        ebs = next(c for c in changes if c.resource_type == "AWS::EC2::Volume")
        assert ebs.after["Encrypted"] is False

    def test_safe_plan_skips_noop(self):
        changes = parse_terraform_plan(_load_fixture("safe_plan.json"))
        ids = {c.resource_id for c in changes}
        assert "aws_s3_bucket.data" not in ids

    def test_safe_plan_sg_private(self):
        changes = parse_terraform_plan(_load_fixture("safe_plan.json"))
        sg = next(c for c in changes if c.resource_type == "AWS::EC2::SecurityGroup")
        ingress = sg.after.get("SecurityGroupIngress", [])
        assert len(ingress) == 1
        assert ingress[0]["CidrIp"] == "10.0.0.0/16"

    def test_safe_plan_iam_scoped(self):
        changes = parse_terraform_plan(_load_fixture("safe_plan.json"))
        role = next(c for c in changes if c.resource_type == "AWS::IAM::Role")
        policies = role.after.get("Policies", [])
        doc = policies[0]["PolicyDocument"]
        stmt = doc["Statement"][0]
        assert stmt["Action"] == ["s3:GetObject", "s3:PutObject"]

    def test_resource_ids_use_address(self):
        changes = parse_terraform_plan(_load_fixture("dangerous_plan.json"))
        ids = {c.resource_id for c in changes}
        assert "aws_security_group.database" in ids
        assert "aws_iam_role.admin" in ids


class TestTerraformRuleDetection:
    """Verify the rule engine detects issues in Terraform-parsed resources."""

    @pytest.fixture
    def dangerous_changes(self):
        return parse_terraform_plan(_load_fixture("dangerous_plan.json"))

    @pytest.fixture
    def safe_changes(self):
        return parse_terraform_plan(_load_fixture("safe_plan.json"))

    def test_dangerous_triggers_rules(self, dangerous_changes):
        from src.rules.base import RuleEngine
        from src.rules.iam import get_all_iam_rules
        from src.rules.security_group import get_all_sg_rules
        from src.rules.encryption import get_all_encryption_rules
        from src.rules.availability import get_all_availability_rules
        from src.rules.data import get_all_data_rules

        engine = RuleEngine()
        engine.register_all(get_all_iam_rules())
        engine.register_all(get_all_sg_rules())
        engine.register_all(get_all_encryption_rules())
        engine.register_all(get_all_availability_rules())
        engine.register_all(get_all_data_rules())

        findings = engine.evaluate(dangerous_changes)
        rule_ids = {f.rule_id for f in findings}

        assert any(r.startswith("IAM-") for r in rule_ids), f"Expected IAM rules, got {rule_ids}"
        assert any(r.startswith("SG-") for r in rule_ids), f"Expected SG rules, got {rule_ids}"

    def test_dangerous_has_critical_findings(self, dangerous_changes):
        from src.rules.base import RuleEngine
        from src.rules.iam import get_all_iam_rules
        from src.rules.security_group import get_all_sg_rules

        engine = RuleEngine()
        engine.register_all(get_all_iam_rules())
        engine.register_all(get_all_sg_rules())

        findings = engine.evaluate(dangerous_changes)
        severities = {f.severity for f in findings}
        assert Severity.CRITICAL in severities

    def test_safe_has_fewer_findings(self, safe_changes):
        from src.rules.base import RuleEngine
        from src.rules.iam import get_all_iam_rules
        from src.rules.security_group import get_all_sg_rules
        from src.rules.encryption import get_all_encryption_rules
        from src.rules.availability import get_all_availability_rules

        engine = RuleEngine()
        engine.register_all(get_all_iam_rules())
        engine.register_all(get_all_sg_rules())
        engine.register_all(get_all_encryption_rules())
        engine.register_all(get_all_availability_rules())

        findings = engine.evaluate(safe_changes)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 0, f"Safe plan should have no CRITICAL findings, got: {[f.finding for f in critical]}"


class TestTerraformEndToEnd:
    """Full pipeline: Terraform plan → ChangeAnalyzer → RiskReport."""

    def test_dangerous_plan_blocks(self):
        from src.analyzer.orchestrator import ChangeAnalyzer
        from src.models.schemas import Decision

        analyzer = ChangeAnalyzer(use_ai=False, emit_metrics=False)
        plan = _load_fixture("dangerous_plan.json")
        report = analyzer.analyze(after_template=plan, source="terraform")

        assert report.decision == Decision.BLOCK
        assert report.risk_score >= 80
        assert report.evidence.metadata.get("source") == "terraform"
        assert len(report.evidence.findings) > 0

    def test_safe_plan_approves(self):
        from src.analyzer.orchestrator import ChangeAnalyzer
        from src.models.schemas import Decision

        analyzer = ChangeAnalyzer(use_ai=False, emit_metrics=False)
        plan = _load_fixture("safe_plan.json")
        report = analyzer.analyze(after_template=plan, source="terraform")

        assert report.decision == Decision.APPROVE
        assert report.evidence.metadata.get("source") == "terraform"

    def test_auto_detection(self):
        from src.analyzer.orchestrator import ChangeAnalyzer

        analyzer = ChangeAnalyzer(use_ai=False, emit_metrics=False)
        plan = _load_fixture("dangerous_plan.json")
        report = analyzer.analyze(after_template=plan, source="auto")

        assert report.evidence.metadata.get("source") == "terraform"
