from __future__ import annotations

import pytest

from src.models.schemas import ChangeType, ResourceChange
from src.rules.availability import (
    BackupDisabledRule,
    CriticalResourceDeletionRule,
    DisabledMultiAZRule,
    ReducedDesiredCapacityRule,
    ReducedMinCapacityRule,
    get_all_availability_rules,
)
from src.parser.cloudformation import diff_templates, parse_template
from src.rules.base import RuleEngine


class TestReducedDesiredCapacity:
    def test_detects_reduction(self):
        change = ResourceChange(
            resource_id="ASG",
            resource_type="AWS::AutoScaling::AutoScalingGroup",
            change_type=ChangeType.MODIFY,
            before={"DesiredCapacity": 3},
            after={"DesiredCapacity": 2},
        )
        findings = ReducedDesiredCapacityRule().evaluate(change)
        assert len(findings) == 1
        assert findings[0].rule_id == "AVAIL-001"
        assert findings[0].severity.value == "MEDIUM"

    def test_high_severity_when_reduced_to_one(self):
        change = ResourceChange(
            resource_id="ASG",
            resource_type="AWS::AutoScaling::AutoScalingGroup",
            change_type=ChangeType.MODIFY,
            before={"DesiredCapacity": 3},
            after={"DesiredCapacity": 1},
        )
        findings = ReducedDesiredCapacityRule().evaluate(change)
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"

    def test_ignores_increase(self):
        change = ResourceChange(
            resource_id="ASG",
            resource_type="AWS::AutoScaling::AutoScalingGroup",
            change_type=ChangeType.MODIFY,
            before={"DesiredCapacity": 2},
            after={"DesiredCapacity": 4},
        )
        findings = ReducedDesiredCapacityRule().evaluate(change)
        assert len(findings) == 0


class TestReducedMinCapacity:
    def test_detects_min_below_two(self):
        change = ResourceChange(
            resource_id="ASG",
            resource_type="AWS::AutoScaling::AutoScalingGroup",
            change_type=ChangeType.MODIFY,
            before={"MinSize": 2},
            after={"MinSize": 1},
        )
        findings = ReducedMinCapacityRule().evaluate(change)
        assert len(findings) == 1
        assert findings[0].rule_id == "AVAIL-002"

    def test_ignores_min_at_two(self):
        change = ResourceChange(
            resource_id="ASG",
            resource_type="AWS::AutoScaling::AutoScalingGroup",
            change_type=ChangeType.MODIFY,
            before={"MinSize": 2},
            after={"MinSize": 2},
        )
        findings = ReducedMinCapacityRule().evaluate(change)
        assert len(findings) == 0


class TestDisabledMultiAZ:
    def test_detects_disabling(self):
        change = ResourceChange(
            resource_id="DB",
            resource_type="AWS::RDS::DBInstance",
            change_type=ChangeType.MODIFY,
            before={"MultiAZ": True},
            after={"MultiAZ": False},
        )
        findings = DisabledMultiAZRule().evaluate(change)
        assert len(findings) == 1
        assert findings[0].rule_id == "AVAIL-003"
        assert findings[0].severity.value == "CRITICAL"

    def test_ignores_enabling(self):
        change = ResourceChange(
            resource_id="DB",
            resource_type="AWS::RDS::DBInstance",
            change_type=ChangeType.MODIFY,
            before={"MultiAZ": False},
            after={"MultiAZ": True},
        )
        findings = DisabledMultiAZRule().evaluate(change)
        assert len(findings) == 0


class TestCriticalResourceDeletion:
    def test_detects_rds_deletion(self):
        change = ResourceChange(
            resource_id="Database",
            resource_type="AWS::RDS::DBInstance",
            change_type=ChangeType.DELETE,
            before={"DBInstanceClass": "db.r5.large"},
            after={},
        )
        findings = CriticalResourceDeletionRule().evaluate(change)
        assert len(findings) == 1
        assert findings[0].rule_id == "AVAIL-004"
        assert findings[0].severity.value == "CRITICAL"

    def test_detects_dynamodb_deletion(self):
        change = ResourceChange(
            resource_id="Table",
            resource_type="AWS::DynamoDB::Table",
            change_type=ChangeType.DELETE,
            before={},
            after={},
        )
        findings = CriticalResourceDeletionRule().evaluate(change)
        assert len(findings) == 1

    def test_ignores_non_critical_deletion(self):
        change = ResourceChange(
            resource_id="SomeResource",
            resource_type="AWS::EC2::SecurityGroup",
            change_type=ChangeType.DELETE,
            before={},
            after={},
        )
        rule = CriticalResourceDeletionRule()
        assert not rule.applies_to(change)


class TestBackupDisabled:
    def test_detects_backup_disabled(self):
        change = ResourceChange(
            resource_id="DB",
            resource_type="AWS::RDS::DBInstance",
            change_type=ChangeType.MODIFY,
            before={"BackupRetentionPeriod": 7},
            after={"BackupRetentionPeriod": 0},
        )
        findings = BackupDisabledRule().evaluate(change)
        assert len(findings) == 1
        assert findings[0].rule_id == "AVAIL-005"
        assert findings[0].severity.value == "HIGH"

    def test_ignores_retention_increase(self):
        change = ResourceChange(
            resource_id="DB",
            resource_type="AWS::RDS::DBInstance",
            change_type=ChangeType.MODIFY,
            before={"BackupRetentionPeriod": 7},
            after={"BackupRetentionPeriod": 14},
        )
        findings = BackupDisabledRule().evaluate(change)
        assert len(findings) == 0


class TestAvailabilityRulesWithFixtures:
    def test_dangerous_changes(self, secure_baseline, dangerous_changes):
        before = parse_template(secure_baseline)
        after = parse_template(dangerous_changes)
        changes = diff_templates(before, after)
        engine = RuleEngine()
        engine.register_all(get_all_availability_rules())
        findings = engine.evaluate(changes)
        rule_ids = {f.rule_id for f in findings}
        assert "AVAIL-001" in rule_ids
        assert "AVAIL-003" in rule_ids
        assert "AVAIL-005" in rule_ids
