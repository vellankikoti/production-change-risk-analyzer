from __future__ import annotations

from typing import Any

from src.models.schemas import ChangeType, ResourceChange, RuleFinding, Severity
from src.rules.base import Rule

IAM_RESOURCE_TYPES = {
    "AWS::IAM::Policy",
    "AWS::IAM::Role",
    "AWS::IAM::ManagedPolicy",
    "AWS::IAM::User",
    "AWS::IAM::Group",
}

PRIVILEGE_ESCALATION_ACTIONS = {
    "iam:CreateUser",
    "iam:AttachUserPolicy",
    "iam:PutUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:CreateRole",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:PassRole",
}

BROAD_DATA_ACTIONS = {"s3:*", "dynamodb:*", "rds:*", "kms:*"}


def _extract_policy_statements(properties: dict[str, Any]) -> list[dict[str, Any]]:
    statements: list[dict[str, Any]] = []

    # Direct PolicyDocument
    doc = properties.get("PolicyDocument", {})
    if isinstance(doc, dict):
        stmts = doc.get("Statement", [])
        if isinstance(stmts, list):
            statements.extend(stmts)

    # Policies list (on Roles/Users/Groups)
    policies = properties.get("Policies", [])
    if isinstance(policies, list):
        for policy in policies:
            if isinstance(policy, dict):
                doc = policy.get("PolicyDocument", {})
                if isinstance(doc, dict):
                    stmts = doc.get("Statement", [])
                    if isinstance(stmts, list):
                        statements.extend(stmts)

    # AssumeRolePolicyDocument (for roles)
    assume_doc = properties.get("AssumeRolePolicyDocument", {})
    if isinstance(assume_doc, dict):
        stmts = assume_doc.get("Statement", [])
        if isinstance(stmts, list):
            statements.extend(stmts)

    return statements


def _normalize_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


class WildcardActionsRule(Rule):
    rule_id = "IAM-001"
    name = "Wildcard Actions"
    description = "Detects IAM policies granting Action: '*'"
    severity = Severity.CRITICAL
    compliance = ["CIS 1.16", "AWS Config: iam-policy-no-statements-with-admin-access", "SecurityHub: IAM.1"]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type in IAM_RESOURCE_TYPES and change.change_type != ChangeType.DELETE

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        props = change.after or {}
        for stmt in _extract_policy_statements(props):
            if stmt.get("Effect", "").lower() != "allow":
                continue
            actions = _normalize_list(stmt.get("Action", []))
            resources = _normalize_list(stmt.get("Resource", []))
            if "*" in actions and "*" not in resources:
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    resource=change.resource_id,
                    finding=f"IAM policy grants wildcard Action '*'",
                    evidence={"actions": actions, "resources": resources, "statement": stmt},
                    remediation="Restrict actions to only the specific API calls required.",
                ))
        return findings


class WildcardResourcesRule(Rule):
    rule_id = "IAM-002"
    name = "Wildcard Resources"
    description = "Detects IAM policies granting Resource: '*'"
    severity = Severity.HIGH
    compliance = ["CIS 1.16", "AWS Config: iam-policy-no-statements-with-admin-access", "SecurityHub: IAM.1", "Well-Architected: SEC03-BP07"]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type in IAM_RESOURCE_TYPES and change.change_type != ChangeType.DELETE

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        props = change.after or {}
        for stmt in _extract_policy_statements(props):
            if stmt.get("Effect", "").lower() != "allow":
                continue
            actions = _normalize_list(stmt.get("Action", []))
            resources = _normalize_list(stmt.get("Resource", []))
            if "*" in resources and "*" not in actions:
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    resource=change.resource_id,
                    finding=f"IAM policy grants wildcard Resource '*'",
                    evidence={"actions": actions, "resources": resources},
                    remediation="Scope resources to specific ARNs or ARN patterns.",
                ))
        return findings


class CombinedWildcardRule(Rule):
    rule_id = "IAM-003"
    name = "Combined Wildcard Action and Resource"
    description = "Detects IAM policies granting Action: '*' and Resource: '*' (full admin)"
    severity = Severity.CRITICAL
    compliance = ["CIS 1.16", "AWS Config: iam-policy-no-statements-with-admin-access", "SecurityHub: IAM.1", "Well-Architected: SEC03-BP07"]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type in IAM_RESOURCE_TYPES and change.change_type != ChangeType.DELETE

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        props = change.after or {}
        for stmt in _extract_policy_statements(props):
            if stmt.get("Effect", "").lower() != "allow":
                continue
            actions = _normalize_list(stmt.get("Action", []))
            resources = _normalize_list(stmt.get("Resource", []))
            if "*" in actions and "*" in resources:
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    resource=change.resource_id,
                    finding="IAM policy grants unrestricted permissions (Action: '*', Resource: '*')",
                    evidence={"actions": actions, "resources": resources},
                    remediation="Replace with least-privilege permissions. No production role should have Action: '*', Resource: '*'.",
                ))
        return findings


class PrivilegeEscalationRule(Rule):
    rule_id = "IAM-004"
    name = "Privilege Escalation Patterns"
    description = "Detects IAM actions that enable privilege escalation"
    severity = Severity.HIGH
    compliance = ["CIS 1.16", "SecurityHub: IAM.1", "Well-Architected: SEC03-BP06"]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type in IAM_RESOURCE_TYPES and change.change_type != ChangeType.DELETE

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        props = change.after or {}
        for stmt in _extract_policy_statements(props):
            if stmt.get("Effect", "").lower() != "allow":
                continue
            actions = _normalize_list(stmt.get("Action", []))
            resources = _normalize_list(stmt.get("Resource", []))
            dangerous = [a for a in actions if a.lower() in {x.lower() for x in PRIVILEGE_ESCALATION_ACTIONS}]
            # Also flag sts:AssumeRole with wildcard resource
            for a in actions:
                if a.lower() == "sts:assumerole" and "*" in resources:
                    if a not in dangerous:
                        dangerous.append(a)
            if dangerous:
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    resource=change.resource_id,
                    finding=f"IAM policy contains privilege escalation actions: {', '.join(dangerous)}",
                    evidence={"dangerous_actions": dangerous, "all_actions": actions, "resources": resources},
                    remediation="Remove privilege escalation actions or restrict resources to specific ARNs with conditions.",
                ))
        return findings


class BroadDataAccessRule(Rule):
    rule_id = "IAM-005"
    name = "Overly Permissive Data Access"
    description = "Detects IAM policies granting broad data service access (s3:*, dynamodb:*, etc.)"
    severity = Severity.MEDIUM
    compliance = ["CIS 1.16", "AWS Config: iam-policy-no-statements-with-admin-access", "Well-Architected: SEC03-BP07"]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type in IAM_RESOURCE_TYPES and change.change_type != ChangeType.DELETE

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        props = change.after or {}
        for stmt in _extract_policy_statements(props):
            if stmt.get("Effect", "").lower() != "allow":
                continue
            actions = _normalize_list(stmt.get("Action", []))
            broad = [a for a in actions if a.lower() in {x.lower() for x in BROAD_DATA_ACTIONS}]
            if broad:
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    resource=change.resource_id,
                    finding=f"IAM policy grants broad data service access: {', '.join(broad)}",
                    evidence={"broad_actions": broad, "all_actions": actions},
                    remediation="Replace service-wide wildcards with specific actions (e.g., s3:GetObject instead of s3:*).",
                ))
        return findings


def get_all_iam_rules() -> list[Rule]:
    return [
        CombinedWildcardRule(),
        WildcardActionsRule(),
        WildcardResourcesRule(),
        PrivilegeEscalationRule(),
        BroadDataAccessRule(),
    ]
