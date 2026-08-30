from __future__ import annotations

from typing import Any

from src.models.schemas import ChangeType, ResourceChange, RuleFinding, Severity
from src.rules.base import Rule


class S3LoggingDisabledRule(Rule):
    rule_id = "LOG-001"
    name = "S3 Bucket Without Access Logging"
    description = "Detects S3 buckets without server access logging or CloudTrail data events"
    severity = Severity.MEDIUM
    compliance = [
        "CIS 3.6",
        "AWS Config: s3-bucket-logging-enabled",
        "SecurityHub: S3.9",
        "Well-Architected: SEC04-BP02",
    ]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type == "AWS::S3::Bucket" and change.change_type != ChangeType.DELETE

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        props = change.after or {}
        logging_config = props.get("LoggingConfiguration", {})

        has_logging = bool(
            isinstance(logging_config, dict) and logging_config.get("DestinationBucketName")
        )

        if not has_logging:
            return [RuleFinding(
                rule_id=self.rule_id,
                severity=self.severity,
                resource=change.resource_id,
                finding="S3 bucket does not have server access logging configured",
                evidence={"logging_configuration": logging_config},
                remediation="Enable server access logging by setting LoggingConfiguration with a DestinationBucketName.",
            )]
        return []


class CloudTrailDeletionRule(Rule):
    rule_id = "LOG-002"
    name = "CloudTrail Deletion"
    description = "Detects deletion of CloudTrail trails"
    severity = Severity.CRITICAL
    compliance = [
        "CIS 3.1",
        "CIS 3.2",
        "AWS Config: cloud-trail-cloud-watch-logs-enabled",
        "SecurityHub: CloudTrail.1",
        "Well-Architected: SEC04-BP01",
    ]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type == "AWS::CloudTrail::Trail" and change.change_type == ChangeType.DELETE

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        return [RuleFinding(
            rule_id=self.rule_id,
            severity=self.severity,
            resource=change.resource_id,
            finding="CloudTrail trail is being deleted — audit logging will be lost",
            evidence={"resource_id": change.resource_id, "change_type": "DELETE"},
            remediation="Do not delete CloudTrail trails. At least one multi-region trail must be active for compliance.",
        )]


class CloudTrailDisabledRule(Rule):
    rule_id = "LOG-003"
    name = "CloudTrail Logging Disabled"
    description = "Detects CloudTrail trails with IsLogging set to false"
    severity = Severity.CRITICAL
    compliance = [
        "CIS 3.1",
        "AWS Config: cloudtrail-enabled",
        "SecurityHub: CloudTrail.1",
        "Well-Architected: SEC04-BP01",
    ]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type == "AWS::CloudTrail::Trail" and change.change_type != ChangeType.DELETE

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        props = change.after or {}
        is_logging = props.get("IsLogging", None)

        if is_logging is not None and str(is_logging).lower() == "false":
            return [RuleFinding(
                rule_id=self.rule_id,
                severity=self.severity,
                resource=change.resource_id,
                finding="CloudTrail trail has IsLogging set to false — audit logging is disabled",
                evidence={"is_logging": is_logging},
                remediation="Set IsLogging: true. CloudTrail must be enabled for security and compliance auditing.",
            )]
        return []


def get_all_logging_rules() -> list[Rule]:
    return [
        S3LoggingDisabledRule(),
        CloudTrailDeletionRule(),
        CloudTrailDisabledRule(),
    ]
