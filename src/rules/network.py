from __future__ import annotations

from typing import Any

from src.models.schemas import ChangeType, ResourceChange, RuleFinding, Severity
from src.rules.base import Rule


class PublicSubnetAssociationRule(Rule):
    rule_id = "NET-001"
    name = "Public Subnet Association for Private Resources"
    description = "Detects subnet route table associations that reference route tables with IGW routes"
    severity = Severity.HIGH
    compliance = ["CIS 5.1", "Well-Architected: SEC05-BP01"]

    def __init__(self) -> None:
        super().__init__()
        self._template_changes: list[ResourceChange] = []

    def set_template_context(self, changes: list[ResourceChange]) -> None:
        self._template_changes = changes

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type == "AWS::EC2::SubnetRouteTableAssociation" and change.change_type != ChangeType.DELETE

    def _route_table_has_igw(self, route_table_ref: Any) -> bool | None:
        rt_id = str(route_table_ref)
        for c in self._template_changes:
            if c.resource_type == "AWS::EC2::Route" and c.change_type != ChangeType.DELETE:
                props = c.after or {}
                gw = props.get("GatewayId", "")
                rt = str(props.get("RouteTableId", ""))
                dest = props.get("DestinationCidrBlock", "")
                if "igw" in str(gw).lower() and dest == "0.0.0.0/0":
                    if rt_id in rt or rt in rt_id:
                        return True
        return None

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        props = change.after or {}
        subnet_id = props.get("SubnetId", "")
        route_table_id = props.get("RouteTableId", "")

        if "private" in str(subnet_id).lower():
            return []

        has_igw = self._route_table_has_igw(route_table_id)

        if has_igw is True:
            return [RuleFinding(
                rule_id=self.rule_id,
                severity=self.severity,
                resource=change.resource_id,
                finding="Subnet associated with a route table that has an Internet Gateway route (0.0.0.0/0 -> IGW)",
                evidence={"subnet_id": subnet_id, "route_table_id": route_table_id},
                remediation="Verify the subnet does not contain databases or internal services that should remain private.",
            )]

        return []


class NATGatewayRemovalRule(Rule):
    rule_id = "NET-002"
    name = "NAT Gateway Removal"
    description = "Detects deletion of NAT Gateways which breaks private subnet internet access"
    severity = Severity.HIGH
    compliance = ["Well-Architected: SEC05-BP01", "Well-Architected: REL02-BP01"]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type == "AWS::EC2::NatGateway" and change.change_type == ChangeType.DELETE

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        return [RuleFinding(
            rule_id=self.rule_id,
            severity=self.severity,
            resource=change.resource_id,
            finding="NAT Gateway is being deleted — private subnet resources will lose internet access",
            evidence={"resource_id": change.resource_id, "change_type": "DELETE"},
            remediation="Ensure private subnet resources do not require outbound internet access, or provision a replacement NAT Gateway.",
        )]


class PermissiveNACLRule(Rule):
    rule_id = "NET-003"
    name = "Overly Permissive NACL"
    description = "Detects NACLs allowing all traffic from 0.0.0.0/0"
    severity = Severity.MEDIUM
    compliance = ["CIS 5.1", "SecurityHub: EC2.21", "Well-Architected: SEC05-BP02"]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type in {"AWS::EC2::NetworkAclEntry", "AWS::EC2::NetworkAcl"} and change.change_type != ChangeType.DELETE

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        props = change.after or {}

        entries = props.get("Entries", [props]) if "Entries" not in props else props.get("Entries", [])
        if not isinstance(entries, list):
            entries = [props]

        for entry in entries:
            cidr = entry.get("CidrBlock", "")
            rule_action = entry.get("RuleAction", "")
            protocol = str(entry.get("Protocol", ""))
            egress = entry.get("Egress", False)

            if cidr == "0.0.0.0/0" and rule_action == "allow" and protocol == "-1" and not egress:
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    resource=change.resource_id,
                    finding="NACL allows all inbound traffic from 0.0.0.0/0",
                    evidence={"cidr": cidr, "rule_action": rule_action, "protocol": protocol},
                    remediation="Restrict NACL rules to specific ports and CIDR ranges.",
                ))
        return findings


class InternetGatewayRouteRule(Rule):
    rule_id = "NET-004"
    name = "Internet Gateway Route for Private Subnets"
    description = "Detects routes to Internet Gateways that may expose private subnets"
    severity = Severity.HIGH
    compliance = ["CIS 5.1", "Well-Architected: SEC05-BP01"]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type == "AWS::EC2::Route" and change.change_type != ChangeType.DELETE

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        props = change.after or {}
        gateway_id = props.get("GatewayId", "")
        destination = props.get("DestinationCidrBlock", "")

        if gateway_id and "igw" in str(gateway_id).lower() and destination == "0.0.0.0/0":
            findings.append(RuleFinding(
                rule_id=self.rule_id,
                severity=self.severity,
                resource=change.resource_id,
                finding="Route sends 0.0.0.0/0 traffic to an Internet Gateway — verify this is a public subnet",
                evidence={"gateway_id": gateway_id, "destination": destination},
                remediation="Ensure this route table is only associated with public subnets. Private subnets should route through NAT Gateways.",
            ))
        return findings


def get_all_network_rules() -> list[Rule]:
    return [
        PublicSubnetAssociationRule(),
        NATGatewayRemovalRule(),
        PermissiveNACLRule(),
        InternetGatewayRouteRule(),
    ]
