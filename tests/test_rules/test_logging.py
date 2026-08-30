from __future__ import annotations

from src.models.schemas import ChangeType, ResourceChange
from src.rules.logging import (
    CloudTrailDeletionRule,
    CloudTrailDisabledRule,
    S3LoggingDisabledRule,
    get_all_logging_rules,
)


def _make_change(resource_type: str, after: dict, change_type=ChangeType.CREATE) -> ResourceChange:
    return ResourceChange(
        resource_id="TestResource",
        resource_type=resource_type,
        change_type=change_type,
        before={},
        after=after,
    )


class TestS3LoggingDisabledRule:
    def setup_method(self):
        self.rule = S3LoggingDisabledRule()

    def test_no_logging(self):
        change = _make_change("AWS::S3::Bucket", {"BucketName": "test"})
        findings = self.rule.evaluate(change)
        assert len(findings) == 1
        assert findings[0].rule_id == "LOG-001"

    def test_with_logging(self):
        change = _make_change("AWS::S3::Bucket", {
            "LoggingConfiguration": {"DestinationBucketName": "log-bucket"}
        })
        findings = self.rule.evaluate(change)
        assert len(findings) == 0

    def test_empty_logging_config(self):
        change = _make_change("AWS::S3::Bucket", {"LoggingConfiguration": {}})
        findings = self.rule.evaluate(change)
        assert len(findings) == 1

    def test_compliance_mapping(self):
        assert "CIS 3.6" in self.rule.compliance


class TestCloudTrailDeletionRule:
    def setup_method(self):
        self.rule = CloudTrailDeletionRule()

    def test_deletion(self):
        change = _make_change("AWS::CloudTrail::Trail", {}, ChangeType.DELETE)
        assert self.rule.applies_to(change)
        findings = self.rule.evaluate(change)
        assert len(findings) == 1
        assert findings[0].rule_id == "LOG-002"

    def test_not_deletion(self):
        change = _make_change("AWS::CloudTrail::Trail", {}, ChangeType.CREATE)
        assert not self.rule.applies_to(change)


class TestCloudTrailDisabledRule:
    def setup_method(self):
        self.rule = CloudTrailDisabledRule()

    def test_logging_disabled(self):
        change = _make_change("AWS::CloudTrail::Trail", {"IsLogging": False})
        findings = self.rule.evaluate(change)
        assert len(findings) == 1
        assert findings[0].rule_id == "LOG-003"

    def test_logging_enabled(self):
        change = _make_change("AWS::CloudTrail::Trail", {"IsLogging": True})
        findings = self.rule.evaluate(change)
        assert len(findings) == 0

    def test_logging_not_set(self):
        change = _make_change("AWS::CloudTrail::Trail", {"TrailName": "test"})
        findings = self.rule.evaluate(change)
        assert len(findings) == 0


class TestGetAllLoggingRules:
    def test_returns_all(self):
        rules = get_all_logging_rules()
        ids = {r.rule_id for r in rules}
        assert ids == {"LOG-001", "LOG-002", "LOG-003"}
