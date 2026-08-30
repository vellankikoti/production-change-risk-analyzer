from __future__ import annotations

from typing import Any

from src.models.schemas import ChangeType, ResourceChange, RuleFinding, Severity
from src.rules.base import Rule


class PublicS3BucketRule(Rule):
    rule_id = "S3-001"
    name = "Public S3 Bucket"
    description = "Detects S3 buckets without public access block"
    severity = Severity.CRITICAL
    compliance = [
        "CIS 2.1.5",
        "AWS Config: s3-bucket-public-read-prohibited",
        "AWS Config: s3-bucket-public-write-prohibited",
        "SecurityHub: S3.1",
        "SecurityHub: S3.2",
        "SecurityHub: S3.3",
        "Well-Architected: SEC08-BP04",
    ]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type == "AWS::S3::Bucket" and change.change_type != ChangeType.DELETE

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        props = change.after or {}
        public_access = props.get("PublicAccessBlockConfiguration", {})

        if not isinstance(public_access, dict):
            public_access = {}

        block_public_acls = str(public_access.get("BlockPublicAcls", "false")).lower() == "true"
        block_public_policy = str(public_access.get("BlockPublicPolicy", "false")).lower() == "true"
        ignore_public_acls = str(public_access.get("IgnorePublicAcls", "false")).lower() == "true"
        restrict_public_buckets = str(public_access.get("RestrictPublicBuckets", "false")).lower() == "true"

        all_blocked = block_public_acls and block_public_policy and ignore_public_acls and restrict_public_buckets

        if not all_blocked:
            missing = []
            if not block_public_acls:
                missing.append("BlockPublicAcls")
            if not block_public_policy:
                missing.append("BlockPublicPolicy")
            if not ignore_public_acls:
                missing.append("IgnorePublicAcls")
            if not restrict_public_buckets:
                missing.append("RestrictPublicBuckets")

            return [RuleFinding(
                rule_id=self.rule_id,
                severity=self.severity,
                resource=change.resource_id,
                finding=f"S3 bucket missing public access blocks: {', '.join(missing)}",
                evidence={"public_access_block": public_access, "missing_blocks": missing},
                remediation="Enable all four PublicAccessBlockConfiguration settings: BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, RestrictPublicBuckets.",
            )]
        return []


class PublicRDSRule(Rule):
    rule_id = "RDS-001"
    name = "Publicly Accessible RDS"
    description = "Detects RDS instances with PubliclyAccessible set to true"
    severity = Severity.CRITICAL
    compliance = [
        "CIS 2.3.2",
        "AWS Config: rds-instance-public-access-check",
        "SecurityHub: RDS.2",
        "Well-Architected: SEC05-BP01",
    ]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type in {"AWS::RDS::DBInstance", "AWS::RDS::DBCluster"} and change.change_type != ChangeType.DELETE

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        props = change.after or {}
        publicly_accessible = props.get("PubliclyAccessible", None)

        if publicly_accessible is not None and str(publicly_accessible).lower() == "true":
            return [RuleFinding(
                rule_id=self.rule_id,
                severity=self.severity,
                resource=change.resource_id,
                finding="RDS instance is publicly accessible",
                evidence={"publicly_accessible": publicly_accessible},
                remediation="Set PubliclyAccessible: false. Place RDS instances in private subnets with no direct internet access.",
            )]
        return []


class DeletionProtectionDisabledRule(Rule):
    rule_id = "DEL-001"
    name = "Deletion Protection Disabled"
    description = "Detects critical resources without deletion protection"
    severity = Severity.HIGH
    compliance = [
        "AWS Config: rds-instance-deletion-protection-enabled",
        "SecurityHub: RDS.8",
        "Well-Architected: REL09-BP01",
    ]

    PROTECTED_TYPES = {
        "AWS::RDS::DBInstance",
        "AWS::RDS::DBCluster",
        "AWS::ElasticLoadBalancingV2::LoadBalancer",
    }

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type in self.PROTECTED_TYPES and change.change_type != ChangeType.DELETE

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        props = change.after or {}

        if change.resource_type in {"AWS::RDS::DBInstance", "AWS::RDS::DBCluster"}:
            protection = props.get("DeletionProtection", None)
        elif change.resource_type == "AWS::ElasticLoadBalancingV2::LoadBalancer":
            attrs = props.get("LoadBalancerAttributes", [])
            protection = None
            if isinstance(attrs, list):
                for attr in attrs:
                    if isinstance(attr, dict) and attr.get("Key") == "deletion_protection.enabled":
                        protection = attr.get("Value")
                        break
        else:
            return []

        if protection is not None and str(protection).lower() == "false":
            return [RuleFinding(
                rule_id=self.rule_id,
                severity=self.severity,
                resource=change.resource_id,
                finding=f"Deletion protection is explicitly disabled on {change.resource_type}",
                evidence={"deletion_protection": protection, "resource_type": change.resource_type},
                remediation="Enable DeletionProtection: true for production resources to prevent accidental deletion.",
            )]

        if protection is None and change.resource_type in {"AWS::RDS::DBInstance", "AWS::RDS::DBCluster"}:
            return [RuleFinding(
                rule_id=self.rule_id,
                severity=Severity.MEDIUM,
                resource=change.resource_id,
                finding=f"Deletion protection not configured on {change.resource_type}",
                evidence={"deletion_protection": None, "resource_type": change.resource_type},
                remediation="Set DeletionProtection: true for production databases.",
            )]
        return []


def get_all_data_rules() -> list[Rule]:
    return [
        PublicS3BucketRule(),
        PublicRDSRule(),
        DeletionProtectionDisabledRule(),
    ]
