from __future__ import annotations

import json
from typing import Any

from src.models.schemas import ChangeType, ResourceChange

TERRAFORM_TO_CFN_TYPE = {
    "aws_instance": "AWS::EC2::Instance",
    "aws_security_group": "AWS::EC2::SecurityGroup",
    "aws_security_group_rule": "AWS::EC2::SecurityGroup",
    "aws_db_instance": "AWS::RDS::DBInstance",
    "aws_rds_cluster": "AWS::RDS::DBCluster",
    "aws_s3_bucket": "AWS::S3::Bucket",
    "aws_s3_bucket_server_side_encryption_configuration": "AWS::S3::Bucket",
    "aws_s3_bucket_public_access_block": "AWS::S3::Bucket",
    "aws_s3_bucket_logging": "AWS::S3::Bucket",
    "aws_iam_role": "AWS::IAM::Role",
    "aws_iam_role_policy": "AWS::IAM::Role",
    "aws_iam_policy": "AWS::IAM::ManagedPolicy",
    "aws_autoscaling_group": "AWS::AutoScaling::AutoScalingGroup",
    "aws_launch_configuration": "AWS::AutoScaling::LaunchConfiguration",
    "aws_launch_template": "AWS::EC2::LaunchTemplate",
    "aws_ebs_volume": "AWS::EC2::Volume",
    "aws_cloudtrail": "AWS::CloudTrail::Trail",
    "aws_vpc": "AWS::EC2::VPC",
    "aws_subnet": "AWS::EC2::Subnet",
    "aws_route_table": "AWS::EC2::RouteTable",
    "aws_route_table_association": "AWS::EC2::SubnetRouteTableAssociation",
    "aws_route": "AWS::EC2::Route",
    "aws_nat_gateway": "AWS::EC2::NatGateway",
    "aws_network_acl": "AWS::EC2::NetworkAcl",
    "aws_network_acl_rule": "AWS::EC2::NetworkAcl",
    "aws_lb": "AWS::ElasticLoadBalancingV2::LoadBalancer",
    "aws_alb": "AWS::ElasticLoadBalancingV2::LoadBalancer",
}

_TF_ACTION_MAP = {
    frozenset(["create"]): ChangeType.CREATE,
    frozenset(["delete"]): ChangeType.DELETE,
    frozenset(["update"]): ChangeType.MODIFY,
    frozenset(["create", "delete"]): ChangeType.MODIFY,
    frozenset(["delete", "create"]): ChangeType.MODIFY,
}


def _map_actions(actions: list[str]) -> ChangeType:
    key = frozenset(actions)
    return _TF_ACTION_MAP.get(key, ChangeType.MODIFY)


def _normalize_sg_props(tf_props: dict[str, Any]) -> dict[str, Any]:
    """Convert Terraform security group properties to CloudFormation-equivalent."""
    cfn = {}

    ingress = tf_props.get("ingress") or []
    if ingress:
        cfn_ingress = []
        for rule in ingress:
            base: dict[str, Any] = {
                "IpProtocol": rule.get("protocol", "tcp"),
                "FromPort": rule.get("from_port", 0),
                "ToPort": rule.get("to_port", 0),
            }
            for cidr in rule.get("cidr_blocks") or []:
                entry = dict(base)
                entry["CidrIp"] = cidr
                cfn_ingress.append(entry)
            for cidr in rule.get("ipv6_cidr_blocks") or []:
                entry = dict(base)
                entry["CidrIpv6"] = cidr
                cfn_ingress.append(entry)
            if not rule.get("cidr_blocks") and not rule.get("ipv6_cidr_blocks"):
                cfn_ingress.append(base)
        cfn["SecurityGroupIngress"] = cfn_ingress

    egress = tf_props.get("egress") or []
    if egress:
        cfn_egress = []
        for rule in egress:
            base = {
                "IpProtocol": rule.get("protocol", "tcp"),
                "FromPort": rule.get("from_port", 0),
                "ToPort": rule.get("to_port", 0),
            }
            for cidr in rule.get("cidr_blocks") or []:
                entry = dict(base)
                entry["CidrIp"] = cidr
                cfn_egress.append(entry)
        cfn["SecurityGroupEgress"] = cfn_egress

    if "description" in tf_props:
        cfn["GroupDescription"] = tf_props["description"]
    if "vpc_id" in tf_props:
        cfn["VpcId"] = tf_props["vpc_id"]

    return cfn


def _normalize_sg_rule_props(tf_props: dict[str, Any]) -> dict[str, Any]:
    """Convert aws_security_group_rule to SecurityGroup-like properties."""
    rule_type = tf_props.get("type", "ingress")
    base: dict[str, Any] = {
        "IpProtocol": tf_props.get("protocol", "tcp"),
        "FromPort": tf_props.get("from_port", 0),
        "ToPort": tf_props.get("to_port", 0),
    }
    rules = []
    for cidr in tf_props.get("cidr_blocks") or []:
        entry = dict(base)
        entry["CidrIp"] = cidr
        rules.append(entry)
    for cidr in tf_props.get("ipv6_cidr_blocks") or []:
        entry = dict(base)
        entry["CidrIpv6"] = cidr
        rules.append(entry)
    if not rules:
        rules.append(base)

    key = "SecurityGroupIngress" if rule_type == "ingress" else "SecurityGroupEgress"
    return {key: rules}


def _normalize_rds_props(tf_props: dict[str, Any]) -> dict[str, Any]:
    """Convert Terraform RDS properties to CloudFormation-equivalent."""
    cfn: dict[str, Any] = {}
    mapping = {
        "publicly_accessible": "PubliclyAccessible",
        "multi_az": "MultiAZ",
        "backup_retention_period": "BackupRetentionPeriod",
        "storage_encrypted": "StorageEncrypted",
        "deletion_protection": "DeletionProtection",
        "engine": "Engine",
        "engine_version": "EngineVersion",
        "instance_class": "DBInstanceClass",
        "allocated_storage": "AllocatedStorage",
        "storage_type": "StorageType",
        "username": "MasterUsername",
    }
    for tf_key, cfn_key in mapping.items():
        if tf_key in tf_props and tf_props[tf_key] is not None:
            cfn[cfn_key] = tf_props[tf_key]
    return cfn


def _normalize_iam_role_props(tf_props: dict[str, Any]) -> dict[str, Any]:
    """Convert Terraform IAM role properties to CloudFormation-equivalent."""
    cfn: dict[str, Any] = {}
    if "name" in tf_props:
        cfn["RoleName"] = tf_props["name"]

    assume_policy = tf_props.get("assume_role_policy")
    if assume_policy:
        if isinstance(assume_policy, str):
            try:
                assume_policy = json.loads(assume_policy)
            except (json.JSONDecodeError, TypeError):
                pass
        cfn["AssumeRolePolicyDocument"] = assume_policy

    inline_policy = tf_props.get("inline_policy") or []
    if inline_policy:
        policies = []
        for p in inline_policy:
            policy_doc = p.get("policy", "")
            if isinstance(policy_doc, str):
                try:
                    policy_doc = json.loads(policy_doc)
                except (json.JSONDecodeError, TypeError):
                    pass
            policies.append({
                "PolicyName": p.get("name", "inline"),
                "PolicyDocument": policy_doc,
            })
        cfn["Policies"] = policies

    return cfn


def _normalize_iam_role_policy_props(tf_props: dict[str, Any]) -> dict[str, Any]:
    """Convert aws_iam_role_policy to CloudFormation IAM Role with inline policy."""
    policy_doc = tf_props.get("policy", "")
    if isinstance(policy_doc, str):
        try:
            policy_doc = json.loads(policy_doc)
        except (json.JSONDecodeError, TypeError):
            pass
    return {
        "Policies": [{
            "PolicyName": tf_props.get("name", "inline"),
            "PolicyDocument": policy_doc,
        }],
    }


def _normalize_s3_props(tf_props: dict[str, Any]) -> dict[str, Any]:
    """Convert Terraform S3 bucket properties to CloudFormation-equivalent."""
    cfn: dict[str, Any] = {}
    if "bucket" in tf_props:
        cfn["BucketName"] = tf_props["bucket"]
    return cfn


def _normalize_s3_encryption_props(tf_props: dict[str, Any]) -> dict[str, Any]:
    """Convert aws_s3_bucket_server_side_encryption_configuration."""
    rules = tf_props.get("rule") or []
    if rules:
        sse_configs = []
        for rule in rules:
            sse_default = rule.get("apply_server_side_encryption_by_default", {})
            sse_configs.append({
                "ServerSideEncryptionByDefault": {
                    "SSEAlgorithm": sse_default.get("sse_algorithm", "AES256"),
                },
            })
        return {"BucketEncryption": {"ServerSideEncryptionConfiguration": sse_configs}}
    return {}


def _normalize_s3_public_access_props(tf_props: dict[str, Any]) -> dict[str, Any]:
    """Convert aws_s3_bucket_public_access_block."""
    return {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": tf_props.get("block_public_acls", False),
            "BlockPublicPolicy": tf_props.get("block_public_policy", False),
            "IgnorePublicAcls": tf_props.get("ignore_public_acls", False),
            "RestrictPublicBuckets": tf_props.get("restrict_public_buckets", False),
        },
    }


def _normalize_asg_props(tf_props: dict[str, Any]) -> dict[str, Any]:
    """Convert Terraform ASG properties to CloudFormation-equivalent."""
    cfn: dict[str, Any] = {}
    mapping = {
        "min_size": "MinSize",
        "max_size": "MaxSize",
        "desired_capacity": "DesiredCapacity",
    }
    for tf_key, cfn_key in mapping.items():
        if tf_key in tf_props and tf_props[tf_key] is not None:
            cfn[cfn_key] = tf_props[tf_key]
    return cfn


def _normalize_ebs_props(tf_props: dict[str, Any]) -> dict[str, Any]:
    """Convert Terraform EBS volume properties."""
    cfn: dict[str, Any] = {}
    if "encrypted" in tf_props:
        cfn["Encrypted"] = tf_props["encrypted"]
    if "size" in tf_props:
        cfn["Size"] = tf_props["size"]
    if "type" in tf_props:
        cfn["VolumeType"] = tf_props["type"]
    return cfn


def _normalize_cloudtrail_props(tf_props: dict[str, Any]) -> dict[str, Any]:
    """Convert Terraform CloudTrail properties."""
    cfn: dict[str, Any] = {}
    if "enable_logging" in tf_props:
        cfn["IsLogging"] = tf_props["enable_logging"]
    if "name" in tf_props:
        cfn["TrailName"] = tf_props["name"]
    return cfn


_NORMALIZERS: dict[str, Any] = {
    "aws_security_group": _normalize_sg_props,
    "aws_security_group_rule": _normalize_sg_rule_props,
    "aws_db_instance": _normalize_rds_props,
    "aws_rds_cluster": _normalize_rds_props,
    "aws_iam_role": _normalize_iam_role_props,
    "aws_iam_role_policy": _normalize_iam_role_policy_props,
    "aws_s3_bucket": _normalize_s3_props,
    "aws_s3_bucket_server_side_encryption_configuration": _normalize_s3_encryption_props,
    "aws_s3_bucket_public_access_block": _normalize_s3_public_access_props,
    "aws_autoscaling_group": _normalize_asg_props,
    "aws_ebs_volume": _normalize_ebs_props,
    "aws_cloudtrail": _normalize_cloudtrail_props,
}


def _normalize_props(tf_type: str, tf_props: dict[str, Any] | None) -> dict[str, Any]:
    if not tf_props:
        return {}
    normalizer = _NORMALIZERS.get(tf_type)
    if normalizer:
        return normalizer(tf_props)
    return tf_props


def parse_terraform_plan(plan_json: str) -> list[ResourceChange]:
    """Parse terraform show -json output into ResourceChange list."""
    data = json.loads(plan_json)
    resource_changes = data.get("resource_changes", [])
    changes: list[ResourceChange] = []

    for rc in resource_changes:
        tf_type = rc.get("type", "")
        cfn_type = TERRAFORM_TO_CFN_TYPE.get(tf_type, f"Terraform::{tf_type}")

        actions = rc.get("change", {}).get("actions", [])
        if actions == ["no-op"] or actions == ["read"]:
            continue

        change_type = _map_actions(actions)
        before_raw = rc.get("change", {}).get("before") or {}
        after_raw = rc.get("change", {}).get("after") or {}

        address = rc.get("address", rc.get("name", tf_type))

        before_props = _normalize_props(tf_type, before_raw) if change_type != ChangeType.CREATE else {}
        after_props = _normalize_props(tf_type, after_raw) if change_type != ChangeType.DELETE else {}

        changes.append(ResourceChange(
            resource_id=address,
            resource_type=cfn_type,
            change_type=change_type,
            before=before_props,
            after=after_props,
        ))

    return changes


def is_terraform_plan(content: str) -> bool:
    """Check if the content looks like a Terraform plan JSON."""
    content = content.strip()
    if not content.startswith("{"):
        return False
    try:
        data = json.loads(content)
        return "resource_changes" in data
    except (json.JSONDecodeError, TypeError):
        return False
