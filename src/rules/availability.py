from __future__ import annotations

from typing import Any

from src.models.schemas import ChangeType, ResourceChange, RuleFinding, Severity
from src.rules.base import Rule

CRITICAL_RESOURCE_TYPES = {
    "AWS::RDS::DBInstance",
    "AWS::RDS::DBCluster",
    "AWS::DynamoDB::Table",
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
    "AWS::ElasticLoadBalancing::LoadBalancer",
    "AWS::ECS::Service",
    "AWS::ECS::Cluster",
}

ASG_TYPES = {"AWS::AutoScaling::AutoScalingGroup"}
RDS_TYPES = {"AWS::RDS::DBInstance", "AWS::RDS::DBCluster"}


def _get_int(props: dict[str, Any], key: str, default: int = -1) -> int:
    try:
        return int(props.get(key, default))
    except (ValueError, TypeError):
        return default


class ReducedDesiredCapacityRule(Rule):
    rule_id = "AVAIL-001"
    name = "Reduced Desired Capacity"
    description = "Detects reductions in Auto Scaling Group desired capacity"
    severity = Severity.MEDIUM
    compliance = ["Well-Architected: REL06-BP01", "AWS Config: autoscaling-group-elb-healthcheck-required"]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type in ASG_TYPES and change.change_type == ChangeType.MODIFY

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        before_desired = _get_int(change.before, "DesiredCapacity")
        after_desired = _get_int(change.after, "DesiredCapacity")

        if before_desired > 0 and after_desired >= 0 and after_desired < before_desired:
            sev = Severity.HIGH if after_desired <= 1 else Severity.MEDIUM
            findings.append(RuleFinding(
                rule_id=self.rule_id,
                severity=sev,
                resource=change.resource_id,
                finding=f"Desired capacity reduced from {before_desired} to {after_desired}",
                evidence={"before": before_desired, "after": after_desired},
                remediation="Verify the capacity reduction is intentional and sufficient for current load.",
            ))
        return findings


class ReducedMinCapacityRule(Rule):
    rule_id = "AVAIL-002"
    name = "Reduced Min Capacity Below 2"
    description = "Detects Auto Scaling Group min capacity set below 2"
    severity = Severity.HIGH
    compliance = ["Well-Architected: REL06-BP01", "Well-Architected: REL10-BP01"]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type in ASG_TYPES and change.change_type != ChangeType.DELETE

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        after_min = _get_int(change.after, "MinSize")

        if 0 <= after_min < 2:
            if change.change_type == ChangeType.MODIFY:
                before_min = _get_int(change.before, "MinSize")
                if before_min >= 2:
                    findings.append(RuleFinding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        resource=change.resource_id,
                        finding=f"MinSize reduced from {before_min} to {after_min} — below redundancy threshold",
                        evidence={"before": before_min, "after": after_min},
                        remediation="Maintain MinSize >= 2 for production workloads to ensure redundancy.",
                    ))
            elif change.change_type == ChangeType.CREATE:
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    resource=change.resource_id,
                    finding=f"New ASG with MinSize {after_min} — below redundancy threshold",
                    evidence={"min_size": after_min},
                    remediation="Set MinSize >= 2 for production workloads.",
                ))
        return findings


class DisabledMultiAZRule(Rule):
    rule_id = "AVAIL-003"
    name = "Disabled Multi-AZ on RDS"
    description = "Detects disabling Multi-AZ on RDS instances"
    severity = Severity.CRITICAL
    compliance = ["AWS Config: rds-multi-az-support", "SecurityHub: RDS.5", "Well-Architected: REL10-BP01"]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type in RDS_TYPES and change.change_type == ChangeType.MODIFY

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        before_az = change.before.get("MultiAZ", None)
        after_az = change.after.get("MultiAZ", None)

        before_val = str(before_az).lower() == "true" if before_az is not None else False
        after_val = str(after_az).lower() == "true" if after_az is not None else False

        if before_val and not after_val:
            findings.append(RuleFinding(
                rule_id=self.rule_id,
                severity=self.severity,
                resource=change.resource_id,
                finding="Multi-AZ is being disabled on RDS instance",
                evidence={"before_multi_az": before_val, "after_multi_az": after_val},
                remediation="Keep Multi-AZ enabled for production databases to ensure high availability.",
            ))
        return findings


class CriticalResourceDeletionRule(Rule):
    rule_id = "AVAIL-004"
    name = "Critical Resource Deletion"
    description = "Detects deletion of critical infrastructure resources"
    severity = Severity.CRITICAL
    compliance = ["Well-Architected: REL10-BP01", "Well-Architected: OPS08-BP01"]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type in CRITICAL_RESOURCE_TYPES and change.change_type == ChangeType.DELETE

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        return [RuleFinding(
            rule_id=self.rule_id,
            severity=self.severity,
            resource=change.resource_id,
            finding=f"Critical resource of type {change.resource_type} is being deleted",
            evidence={"resource_type": change.resource_type, "resource_id": change.resource_id},
            remediation="Confirm deletion is intentional. Consider enabling DeletionProtection or taking a final snapshot.",
        )]


class BackupDisabledRule(Rule):
    rule_id = "AVAIL-005"
    name = "Backup Disabled"
    description = "Detects removal or disabling of backups"
    severity = Severity.HIGH
    compliance = ["AWS Config: db-instance-backup-enabled", "SecurityHub: RDS.11", "Well-Architected: REL09-BP01"]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type in RDS_TYPES and change.change_type == ChangeType.MODIFY

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        before_retention = _get_int(change.before, "BackupRetentionPeriod", -1)
        after_retention = _get_int(change.after, "BackupRetentionPeriod", -1)

        if after_retention == 0 and before_retention > 0:
            findings.append(RuleFinding(
                rule_id=self.rule_id,
                severity=self.severity,
                resource=change.resource_id,
                finding=f"Backup retention period changed from {before_retention} days to 0 — backups disabled",
                evidence={"before_retention": before_retention, "after_retention": after_retention},
                remediation="Maintain a backup retention period > 0. AWS minimum recommended for production is 7 days.",
            ))
        return findings


def get_all_availability_rules() -> list[Rule]:
    return [
        ReducedDesiredCapacityRule(),
        ReducedMinCapacityRule(),
        DisabledMultiAZRule(),
        CriticalResourceDeletionRule(),
        BackupDisabledRule(),
    ]
