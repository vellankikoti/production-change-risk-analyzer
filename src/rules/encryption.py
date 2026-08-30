from __future__ import annotations

from typing import Any

from src.models.schemas import ChangeType, ResourceChange, RuleFinding, Severity
from src.rules.base import Rule

S3_TYPES = {"AWS::S3::Bucket"}
RDS_TYPES = {"AWS::RDS::DBInstance", "AWS::RDS::DBCluster"}
EBS_TYPES = {"AWS::EC2::Volume"}


class UnencryptedS3Rule(Rule):
    rule_id = "ENC-001"
    name = "Unencrypted S3 Bucket"
    description = "Detects S3 buckets without server-side encryption configured"
    severity = Severity.HIGH
    compliance = [
        "CIS 2.1.1",
        "AWS Config: s3-bucket-server-side-encryption-enabled",
        "SecurityHub: S3.4",
        "Well-Architected: SEC08-BP02",
    ]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type in S3_TYPES and change.change_type != ChangeType.DELETE

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        props = change.after or {}
        encryption = props.get("BucketEncryption", {})
        rules = []
        if isinstance(encryption, dict):
            rules = encryption.get("ServerSideEncryptionConfiguration", [])

        has_encryption = False
        if isinstance(rules, list):
            for rule in rules:
                if isinstance(rule, dict):
                    sse = rule.get("ServerSideEncryptionByDefault", {})
                    if isinstance(sse, dict) and sse.get("SSEAlgorithm"):
                        has_encryption = True
                        break

        if not has_encryption:
            return [RuleFinding(
                rule_id=self.rule_id,
                severity=self.severity,
                resource=change.resource_id,
                finding="S3 bucket does not have server-side encryption configured",
                evidence={"bucket_encryption": encryption},
                remediation="Enable SSE-S3 (AES256) or SSE-KMS encryption on the bucket.",
            )]
        return []


class UnencryptedRDSRule(Rule):
    rule_id = "ENC-002"
    name = "Unencrypted RDS Instance"
    description = "Detects RDS instances without storage encryption"
    severity = Severity.CRITICAL
    compliance = [
        "CIS 2.3.1",
        "AWS Config: rds-storage-encrypted",
        "SecurityHub: RDS.3",
        "Well-Architected: SEC08-BP02",
    ]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type in RDS_TYPES and change.change_type != ChangeType.DELETE

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        props = change.after or {}
        encrypted = props.get("StorageEncrypted", None)
        is_encrypted = str(encrypted).lower() == "true" if encrypted is not None else False

        if not is_encrypted:
            return [RuleFinding(
                rule_id=self.rule_id,
                severity=self.severity,
                resource=change.resource_id,
                finding="RDS instance does not have storage encryption enabled",
                evidence={"storage_encrypted": encrypted},
                remediation="Set StorageEncrypted: true. Note: enabling encryption requires recreating the instance.",
            )]
        return []


class UnencryptedEBSRule(Rule):
    rule_id = "ENC-003"
    name = "Unencrypted EBS Volume"
    description = "Detects EBS volumes without encryption"
    severity = Severity.HIGH
    compliance = [
        "CIS 2.2.1",
        "AWS Config: encrypted-volumes",
        "SecurityHub: EC2.3",
        "Well-Architected: SEC08-BP02",
    ]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type in EBS_TYPES and change.change_type != ChangeType.DELETE

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        props = change.after or {}
        encrypted = props.get("Encrypted", None)
        is_encrypted = str(encrypted).lower() == "true" if encrypted is not None else False

        if not is_encrypted:
            return [RuleFinding(
                rule_id=self.rule_id,
                severity=self.severity,
                resource=change.resource_id,
                finding="EBS volume does not have encryption enabled",
                evidence={"encrypted": encrypted},
                remediation="Set Encrypted: true and specify a KmsKeyId. Enable default EBS encryption in account settings.",
            )]
        return []


def get_all_encryption_rules() -> list[Rule]:
    return [
        UnencryptedS3Rule(),
        UnencryptedRDSRule(),
        UnencryptedEBSRule(),
    ]
