from __future__ import annotations

from src.models.schemas import ChangeType, ResourceChange, ResourceRollbackRisk, RollbackAssessment

REPLACEMENT_PROPERTIES: dict[str, set[str]] = {
    "AWS::RDS::DBInstance": {
        "Engine", "DBInstanceIdentifier", "DBSubnetGroupName",
        "AvailabilityZone", "DBName", "MasterUsername", "Port",
    },
    "AWS::EC2::Instance": {
        "ImageId", "SubnetId", "AvailabilityZone",
        "PlacementGroupName", "Tenancy",
    },
    "AWS::EC2::SecurityGroup": {
        "GroupName", "VpcId",
    },
    "AWS::S3::Bucket": {
        "BucketName",
    },
    "AWS::AutoScaling::AutoScalingGroup": {
        "LaunchConfigurationName", "LaunchTemplate",
    },
    "AWS::AutoScaling::LaunchConfiguration": {
        "ImageId", "InstanceType", "SecurityGroups",
        "KeyName", "IamInstanceProfile",
    },
    "AWS::DynamoDB::Table": {
        "TableName", "KeySchema", "BillingMode",
    },
    "AWS::ECS::Service": {
        "ServiceName", "Cluster", "LaunchType",
    },
    "AWS::Lambda::Function": {
        "FunctionName", "Runtime",
    },
    "AWS::ElastiCache::CacheCluster": {
        "ClusterName", "Engine", "CacheNodeType",
    },
}

CRITICAL_RESOURCE_TYPES = {
    "AWS::RDS::DBInstance",
    "AWS::DynamoDB::Table",
    "AWS::RDS::DBCluster",
    "AWS::ECS::Service",
    "AWS::EKS::Cluster",
    "AWS::ElastiCache::CacheCluster",
    "AWS::Elasticsearch::Domain",
    "AWS::OpenSearchService::Domain",
}

RISK_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _check_replacement(change: ResourceChange) -> bool:
    """Check if a MODIFY change triggers resource replacement."""
    if change.change_type != ChangeType.MODIFY:
        return False
    replace_props = REPLACEMENT_PROPERTIES.get(change.resource_type, set())
    if not replace_props:
        return False
    before = change.before or {}
    after = change.after or {}
    for prop in replace_props:
        bv = before.get(prop)
        av = after.get(prop)
        if bv != av and (bv is not None or av is not None):
            return True
    return False


def assess_rollback(changes: list[ResourceChange]) -> RollbackAssessment:
    """Assess rollback risk for a set of changes."""
    resource_risks: list[ResourceRollbackRisk] = []

    for change in changes:
        ct = change.change_type.value if isinstance(change.change_type, ChangeType) else change.change_type
        is_critical_type = change.resource_type in CRITICAL_RESOURCE_TYPES

        if change.change_type == ChangeType.DELETE:
            risk = "CRITICAL" if is_critical_type else "HIGH"
            reason = (
                f"{change.resource_type} deletion cannot be automatically rolled back"
                if is_critical_type
                else f"Deleted resource must be recreated manually"
            )
            resource_risks.append(ResourceRollbackRisk(
                resource_id=change.resource_id,
                resource_type=change.resource_type,
                change_type=ct,
                rollback_risk=risk,
                reason=reason,
                may_require_replacement=False,
            ))
        elif change.change_type == ChangeType.MODIFY:
            requires_replacement = _check_replacement(change)
            if requires_replacement:
                risk = "CRITICAL" if is_critical_type else "HIGH"
                reason = f"Property change triggers resource replacement — rollback also requires replacement"
                resource_risks.append(ResourceRollbackRisk(
                    resource_id=change.resource_id,
                    resource_type=change.resource_type,
                    change_type=ct,
                    rollback_risk=risk,
                    reason=reason,
                    may_require_replacement=True,
                ))
            else:
                resource_risks.append(ResourceRollbackRisk(
                    resource_id=change.resource_id,
                    resource_type=change.resource_type,
                    change_type=ct,
                    rollback_risk="LOW",
                    reason="Property changes are reversible",
                    may_require_replacement=False,
                ))
        elif change.change_type == ChangeType.CREATE:
            resource_risks.append(ResourceRollbackRisk(
                resource_id=change.resource_id,
                resource_type=change.resource_type,
                change_type=ct,
                rollback_risk="LOW",
                reason="New resource can be deleted on rollback",
                may_require_replacement=False,
            ))

    if not resource_risks:
        return RollbackAssessment(overall_risk="LOW", resource_risks=[], explanation="No changes to roll back")

    overall = max(resource_risks, key=lambda r: RISK_ORDER.get(r.rollback_risk, 0))
    overall_risk = overall.rollback_risk

    high_risks = [r for r in resource_risks if RISK_ORDER.get(r.rollback_risk, 0) >= 3]
    if high_risks:
        parts = [f"{r.resource_id} ({r.rollback_risk}: {r.reason})" for r in high_risks]
        explanation = f"Rollback risk is {overall_risk} due to: {'; '.join(parts)}"
    else:
        explanation = "All changes are safely reversible"

    return RollbackAssessment(
        overall_risk=overall_risk,
        resource_risks=resource_risks,
        explanation=explanation,
    )
