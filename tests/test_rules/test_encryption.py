from __future__ import annotations

from src.models.schemas import ChangeType, ResourceChange
from src.rules.encryption import (
    UnencryptedEBSRule,
    UnencryptedRDSRule,
    UnencryptedS3Rule,
    get_all_encryption_rules,
)


def _make_change(resource_type: str, after: dict, change_type=ChangeType.CREATE) -> ResourceChange:
    return ResourceChange(
        resource_id="TestResource",
        resource_type=resource_type,
        change_type=change_type,
        before={},
        after=after,
    )


class TestUnencryptedS3Rule:
    def setup_method(self):
        self.rule = UnencryptedS3Rule()

    def test_no_encryption(self):
        change = _make_change("AWS::S3::Bucket", {"BucketName": "test"})
        findings = self.rule.evaluate(change)
        assert len(findings) == 1
        assert findings[0].rule_id == "ENC-001"

    def test_with_encryption(self):
        change = _make_change("AWS::S3::Bucket", {
            "BucketEncryption": {
                "ServerSideEncryptionConfiguration": [{
                    "ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}
                }]
            }
        })
        findings = self.rule.evaluate(change)
        assert len(findings) == 0

    def test_compliance_mapping(self):
        assert "CIS 2.1.1" in self.rule.compliance
        assert "SecurityHub: S3.4" in self.rule.compliance

    def test_skip_delete(self):
        change = _make_change("AWS::S3::Bucket", {}, ChangeType.DELETE)
        assert not self.rule.applies_to(change)


class TestUnencryptedRDSRule:
    def setup_method(self):
        self.rule = UnencryptedRDSRule()

    def test_not_encrypted(self):
        change = _make_change("AWS::RDS::DBInstance", {"StorageEncrypted": False})
        findings = self.rule.evaluate(change)
        assert len(findings) == 1
        assert findings[0].rule_id == "ENC-002"

    def test_encrypted(self):
        change = _make_change("AWS::RDS::DBInstance", {"StorageEncrypted": True})
        findings = self.rule.evaluate(change)
        assert len(findings) == 0

    def test_no_property(self):
        change = _make_change("AWS::RDS::DBInstance", {"Engine": "mysql"})
        findings = self.rule.evaluate(change)
        assert len(findings) == 1

    def test_compliance_mapping(self):
        assert "CIS 2.3.1" in self.rule.compliance


class TestUnencryptedEBSRule:
    def setup_method(self):
        self.rule = UnencryptedEBSRule()

    def test_not_encrypted(self):
        change = _make_change("AWS::EC2::Volume", {"Encrypted": False})
        findings = self.rule.evaluate(change)
        assert len(findings) == 1
        assert findings[0].rule_id == "ENC-003"

    def test_encrypted(self):
        change = _make_change("AWS::EC2::Volume", {"Encrypted": True})
        findings = self.rule.evaluate(change)
        assert len(findings) == 0

    def test_compliance_mapping(self):
        assert "CIS 2.2.1" in self.rule.compliance


class TestGetAllEncryptionRules:
    def test_returns_all(self):
        rules = get_all_encryption_rules()
        ids = {r.rule_id for r in rules}
        assert ids == {"ENC-001", "ENC-002", "ENC-003"}
