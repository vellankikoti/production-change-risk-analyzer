from __future__ import annotations

import pytest

from src.analyzer.rollback import _check_replacement, assess_rollback
from src.models.schemas import ChangeType, ResourceChange


def _make_change(
    resource_id: str,
    resource_type: str,
    change_type: ChangeType,
    before: dict | None = None,
    after: dict | None = None,
) -> ResourceChange:
    return ResourceChange(
        resource_id=resource_id,
        resource_type=resource_type,
        change_type=change_type,
        before=before,
        after=after,
    )


class TestCheckReplacement:
    def test_rds_engine_change_triggers_replacement(self):
        change = _make_change(
            "DB", "AWS::RDS::DBInstance", ChangeType.MODIFY,
            before={"Engine": "mysql"}, after={"Engine": "postgres"},
        )
        assert _check_replacement(change) is True

    def test_rds_non_replacement_property(self):
        change = _make_change(
            "DB", "AWS::RDS::DBInstance", ChangeType.MODIFY,
            before={"AllocatedStorage": "20"}, after={"AllocatedStorage": "50"},
        )
        assert _check_replacement(change) is False

    def test_ec2_imageid_change(self):
        change = _make_change(
            "Web", "AWS::EC2::Instance", ChangeType.MODIFY,
            before={"ImageId": "ami-old"}, after={"ImageId": "ami-new"},
        )
        assert _check_replacement(change) is True

    def test_create_never_triggers_replacement(self):
        change = _make_change("New", "AWS::RDS::DBInstance", ChangeType.CREATE)
        assert _check_replacement(change) is False

    def test_unknown_resource_type(self):
        change = _make_change(
            "X", "AWS::Custom::Thing", ChangeType.MODIFY,
            before={"Foo": "a"}, after={"Foo": "b"},
        )
        assert _check_replacement(change) is False


class TestAssessRollback:
    def test_empty_changes(self):
        result = assess_rollback([])
        assert result.overall_risk == "LOW"
        assert result.resource_risks == []

    def test_create_is_low_risk(self):
        changes = [_make_change("NewSG", "AWS::EC2::SecurityGroup", ChangeType.CREATE)]
        result = assess_rollback(changes)
        assert result.overall_risk == "LOW"
        assert result.resource_risks[0].rollback_risk == "LOW"

    def test_delete_critical_resource(self):
        changes = [_make_change("ProdDB", "AWS::RDS::DBInstance", ChangeType.DELETE)]
        result = assess_rollback(changes)
        assert result.overall_risk == "CRITICAL"
        assert result.resource_risks[0].rollback_risk == "CRITICAL"

    def test_delete_non_critical_resource(self):
        changes = [_make_change("OldSG", "AWS::EC2::SecurityGroup", ChangeType.DELETE)]
        result = assess_rollback(changes)
        assert result.overall_risk == "HIGH"
        assert result.resource_risks[0].rollback_risk == "HIGH"

    def test_modify_with_replacement(self):
        changes = [_make_change(
            "DB", "AWS::RDS::DBInstance", ChangeType.MODIFY,
            before={"Engine": "mysql"}, after={"Engine": "postgres"},
        )]
        result = assess_rollback(changes)
        assert result.overall_risk == "CRITICAL"
        assert result.resource_risks[0].may_require_replacement is True

    def test_modify_without_replacement(self):
        changes = [_make_change(
            "DB", "AWS::RDS::DBInstance", ChangeType.MODIFY,
            before={"AllocatedStorage": "20"}, after={"AllocatedStorage": "50"},
        )]
        result = assess_rollback(changes)
        assert result.overall_risk == "LOW"
        assert result.resource_risks[0].may_require_replacement is False

    def test_mixed_changes_picks_highest_risk(self):
        changes = [
            _make_change("NewSG", "AWS::EC2::SecurityGroup", ChangeType.CREATE),
            _make_change("ProdDB", "AWS::RDS::DBInstance", ChangeType.DELETE),
        ]
        result = assess_rollback(changes)
        assert result.overall_risk == "CRITICAL"

    def test_explanation_contains_high_risk_resources(self):
        changes = [_make_change("ProdDB", "AWS::DynamoDB::Table", ChangeType.DELETE)]
        result = assess_rollback(changes)
        assert "ProdDB" in result.explanation
