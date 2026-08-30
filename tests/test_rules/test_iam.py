from __future__ import annotations

import pytest

from src.models.schemas import ChangeType, ResourceChange
from src.rules.iam import (
    BroadDataAccessRule,
    CombinedWildcardRule,
    PrivilegeEscalationRule,
    WildcardActionsRule,
    WildcardResourcesRule,
    get_all_iam_rules,
)
from src.parser.cloudformation import diff_templates, parse_template
from src.rules.base import RuleEngine


def _iam_role_change(policies: list[dict]) -> ResourceChange:
    return ResourceChange(
        resource_id="TestRole",
        resource_type="AWS::IAM::Role",
        change_type=ChangeType.CREATE,
        before={},
        after={
            "Policies": [
                {
                    "PolicyName": "TestPolicy",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": policies,
                    },
                }
            ]
        },
    )


class TestWildcardActionsRule:
    def test_detects_wildcard_action(self):
        change = _iam_role_change([{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::bucket"}])
        findings = WildcardActionsRule().evaluate(change)
        assert len(findings) == 1
        assert findings[0].rule_id == "IAM-001"
        assert findings[0].severity.value == "CRITICAL"

    def test_ignores_specific_actions(self):
        change = _iam_role_change([{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}])
        findings = WildcardActionsRule().evaluate(change)
        assert len(findings) == 0

    def test_ignores_deny_statements(self):
        change = _iam_role_change([{"Effect": "Deny", "Action": "*", "Resource": "*"}])
        findings = WildcardActionsRule().evaluate(change)
        assert len(findings) == 0


class TestWildcardResourcesRule:
    def test_detects_wildcard_resource(self):
        change = _iam_role_change([{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}])
        findings = WildcardResourcesRule().evaluate(change)
        assert len(findings) == 1
        assert findings[0].rule_id == "IAM-002"

    def test_ignores_specific_resources(self):
        change = _iam_role_change([{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"}])
        findings = WildcardResourcesRule().evaluate(change)
        assert len(findings) == 0


class TestCombinedWildcardRule:
    def test_detects_full_admin(self):
        change = _iam_role_change([{"Effect": "Allow", "Action": "*", "Resource": "*"}])
        findings = CombinedWildcardRule().evaluate(change)
        assert len(findings) == 1
        assert findings[0].rule_id == "IAM-003"
        assert findings[0].severity.value == "CRITICAL"

    def test_no_finding_for_partial_wildcard(self):
        change = _iam_role_change([{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::bucket"}])
        findings = CombinedWildcardRule().evaluate(change)
        assert len(findings) == 0


class TestPrivilegeEscalationRule:
    def test_detects_escalation_actions(self):
        change = _iam_role_change([{
            "Effect": "Allow",
            "Action": ["iam:CreateUser", "iam:AttachUserPolicy"],
            "Resource": "*",
        }])
        findings = PrivilegeEscalationRule().evaluate(change)
        assert len(findings) == 1
        assert findings[0].rule_id == "IAM-004"

    def test_detects_assume_role_wildcard(self):
        change = _iam_role_change([{
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "*",
        }])
        findings = PrivilegeEscalationRule().evaluate(change)
        assert len(findings) == 1

    def test_ignores_safe_actions(self):
        change = _iam_role_change([{
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::bucket/*",
        }])
        findings = PrivilegeEscalationRule().evaluate(change)
        assert len(findings) == 0


class TestBroadDataAccessRule:
    def test_detects_s3_wildcard(self):
        change = _iam_role_change([{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}])
        findings = BroadDataAccessRule().evaluate(change)
        assert len(findings) == 1
        assert findings[0].rule_id == "IAM-005"

    def test_detects_dynamodb_wildcard(self):
        change = _iam_role_change([{"Effect": "Allow", "Action": "dynamodb:*", "Resource": "*"}])
        findings = BroadDataAccessRule().evaluate(change)
        assert len(findings) == 1


class TestIAMRulesWithFixtures:
    def test_secure_baseline_no_iam_issues(self, secure_baseline, dangerous_changes):
        before = parse_template(secure_baseline)
        after = parse_template(secure_baseline)
        changes = diff_templates(before, after)
        engine = RuleEngine()
        engine.register_all(get_all_iam_rules())
        findings = engine.evaluate(changes)
        assert len(findings) == 0

    def test_dangerous_changes_detected(self, secure_baseline, dangerous_changes):
        before = parse_template(secure_baseline)
        after = parse_template(dangerous_changes)
        changes = diff_templates(before, after)
        engine = RuleEngine()
        engine.register_all(get_all_iam_rules())
        findings = engine.evaluate(changes)
        rule_ids = {f.rule_id for f in findings}
        assert "IAM-003" in rule_ids
