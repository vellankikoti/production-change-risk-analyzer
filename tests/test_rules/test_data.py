from __future__ import annotations

from src.models.schemas import ChangeType, ResourceChange
from src.rules.data import (
    DeletionProtectionDisabledRule,
    PublicRDSRule,
    PublicS3BucketRule,
    get_all_data_rules,
)


def _make_change(resource_type: str, after: dict, change_type=ChangeType.CREATE) -> ResourceChange:
    return ResourceChange(
        resource_id="TestResource",
        resource_type=resource_type,
        change_type=change_type,
        before={},
        after=after,
    )


class TestPublicS3BucketRule:
    def setup_method(self):
        self.rule = PublicS3BucketRule()

    def test_no_public_access_block(self):
        change = _make_change("AWS::S3::Bucket", {"BucketName": "test"})
        findings = self.rule.evaluate(change)
        assert len(findings) == 1
        assert findings[0].rule_id == "S3-001"
        assert "BlockPublicAcls" in findings[0].evidence["missing_blocks"]

    def test_all_blocked(self):
        change = _make_change("AWS::S3::Bucket", {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "BlockPublicPolicy": True,
                "IgnorePublicAcls": True,
                "RestrictPublicBuckets": True,
            }
        })
        findings = self.rule.evaluate(change)
        assert len(findings) == 0

    def test_partial_block(self):
        change = _make_change("AWS::S3::Bucket", {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "BlockPublicPolicy": False,
                "IgnorePublicAcls": True,
                "RestrictPublicBuckets": True,
            }
        })
        findings = self.rule.evaluate(change)
        assert len(findings) == 1
        assert "BlockPublicPolicy" in findings[0].evidence["missing_blocks"]

    def test_compliance_mapping(self):
        assert "CIS 2.1.5" in self.rule.compliance
        assert "SecurityHub: S3.1" in self.rule.compliance


class TestPublicRDSRule:
    def setup_method(self):
        self.rule = PublicRDSRule()

    def test_publicly_accessible(self):
        change = _make_change("AWS::RDS::DBInstance", {"PubliclyAccessible": True})
        findings = self.rule.evaluate(change)
        assert len(findings) == 1
        assert findings[0].rule_id == "RDS-001"

    def test_not_publicly_accessible(self):
        change = _make_change("AWS::RDS::DBInstance", {"PubliclyAccessible": False})
        findings = self.rule.evaluate(change)
        assert len(findings) == 0

    def test_not_set(self):
        change = _make_change("AWS::RDS::DBInstance", {"Engine": "mysql"})
        findings = self.rule.evaluate(change)
        assert len(findings) == 0


class TestDeletionProtectionDisabledRule:
    def setup_method(self):
        self.rule = DeletionProtectionDisabledRule()

    def test_explicitly_disabled(self):
        change = _make_change("AWS::RDS::DBInstance", {"DeletionProtection": False})
        findings = self.rule.evaluate(change)
        assert len(findings) == 1
        assert findings[0].rule_id == "DEL-001"

    def test_enabled(self):
        change = _make_change("AWS::RDS::DBInstance", {"DeletionProtection": True})
        findings = self.rule.evaluate(change)
        assert len(findings) == 0

    def test_not_set_rds(self):
        change = _make_change("AWS::RDS::DBInstance", {"Engine": "mysql"})
        findings = self.rule.evaluate(change)
        assert len(findings) == 1
        assert findings[0].severity.value == "MEDIUM"

    def test_alb_disabled(self):
        change = _make_change("AWS::ElasticLoadBalancingV2::LoadBalancer", {
            "LoadBalancerAttributes": [
                {"Key": "deletion_protection.enabled", "Value": "false"}
            ]
        })
        findings = self.rule.evaluate(change)
        assert len(findings) == 1

    def test_skip_delete(self):
        change = _make_change("AWS::RDS::DBInstance", {}, ChangeType.DELETE)
        assert not self.rule.applies_to(change)


class TestGetAllDataRules:
    def test_returns_all(self):
        rules = get_all_data_rules()
        ids = {r.rule_id for r in rules}
        assert ids == {"S3-001", "RDS-001", "DEL-001"}
