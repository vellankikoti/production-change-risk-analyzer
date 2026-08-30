from __future__ import annotations

from typing import Any

from src.models.schemas import ChangeType, ResourceChange, RuleFinding, Severity
from src.rules.base import Rule

SG_RESOURCE_TYPES = {
    "AWS::EC2::SecurityGroup",
    "AWS::EC2::SecurityGroupIngress",
}

PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}

DB_PORTS = {3306, 5432, 1433, 6379, 27017, 9200, 5601}
ADMIN_PORTS = {22, 3389}
SENSITIVE_PORTS = DB_PORTS | ADMIN_PORTS

PORT_NAMES = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    5601: "Kibana",
}


def _extract_ingress_rules(properties: dict[str, Any], resource_type: str) -> list[dict[str, Any]]:
    if resource_type == "AWS::EC2::SecurityGroupIngress":
        return [properties]
    rules = properties.get("SecurityGroupIngress", [])
    if isinstance(rules, list):
        return rules
    return []


def _get_port_range(rule: dict[str, Any]) -> tuple[int, int]:
    from_port = rule.get("FromPort", -1)
    to_port = rule.get("ToPort", -1)
    try:
        return int(from_port), int(to_port)
    except (ValueError, TypeError):
        return -1, -1


def _get_cidrs(rule: dict[str, Any]) -> list[str]:
    cidrs: list[str] = []
    for key in ("CidrIp", "CidrIpv6"):
        val = rule.get(key, "")
        if val:
            cidrs.append(str(val))
    return cidrs


def _is_public(cidrs: list[str]) -> bool:
    return any(c in PUBLIC_CIDRS for c in cidrs)


def _port_in_range(port: int, from_port: int, to_port: int) -> bool:
    if from_port == -1 and to_port == -1:
        return True
    return from_port <= port <= to_port


class PublicSensitivePortRule(Rule):
    rule_id = "SG-001"
    name = "Public Access to Sensitive Ports"
    description = "Detects 0.0.0.0/0 or ::/0 access to sensitive ports"
    severity = Severity.CRITICAL
    compliance = ["CIS 5.2", "CIS 5.3", "AWS Config: restricted-ssh", "AWS Config: restricted-common-ports", "SecurityHub: EC2.19", "Well-Architected: SEC05-BP02"]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type in SG_RESOURCE_TYPES and change.change_type != ChangeType.DELETE

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        props = change.after or {}
        for rule in _extract_ingress_rules(props, change.resource_type):
            ip_protocol = str(rule.get("IpProtocol", ""))
            if ip_protocol == "-1":
                continue  # SG-004 covers all-traffic rules
            cidrs = _get_cidrs(rule)
            if not _is_public(cidrs):
                continue
            from_port, to_port = _get_port_range(rule)
            for port in SENSITIVE_PORTS:
                if _port_in_range(port, from_port, to_port):
                    sev = Severity.CRITICAL if port in DB_PORTS else Severity.HIGH
                    port_name = PORT_NAMES.get(port, str(port))
                    findings.append(RuleFinding(
                        rule_id=self.rule_id,
                        severity=sev,
                        resource=change.resource_id,
                        finding=f"{port_name} port {port} is publicly accessible",
                        evidence={"port": port, "cidr": cidrs, "from_port": from_port, "to_port": to_port},
                        remediation=f"Restrict port {port} access to specific CIDR ranges or security group references.",
                    ))
        return findings


class UnrestrictedIngressRule(Rule):
    rule_id = "SG-002"
    name = "Unrestricted Ingress"
    description = "Detects 0.0.0.0/0 ingress on any port"
    severity = Severity.MEDIUM
    compliance = ["CIS 5.2", "AWS Config: vpc-sg-open-only-to-authorized-ports", "SecurityHub: EC2.18"]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type in SG_RESOURCE_TYPES and change.change_type != ChangeType.DELETE

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        props = change.after or {}
        for rule in _extract_ingress_rules(props, change.resource_type):
            cidrs = _get_cidrs(rule)
            if not _is_public(cidrs):
                continue
            from_port, to_port = _get_port_range(rule)
            # Skip if SG-001 would already cover this (sensitive ports)
            ip_protocol = str(rule.get("IpProtocol", ""))
            if ip_protocol == "-1":
                continue  # SG-004 handles all-traffic
            has_sensitive = any(_port_in_range(p, from_port, to_port) for p in SENSITIVE_PORTS)
            if has_sensitive:
                continue
            findings.append(RuleFinding(
                rule_id=self.rule_id,
                severity=self.severity,
                resource=change.resource_id,
                finding=f"Unrestricted ingress from 0.0.0.0/0 on port range {from_port}-{to_port}",
                evidence={"cidr": cidrs, "from_port": from_port, "to_port": to_port, "protocol": ip_protocol},
                remediation="Restrict ingress to known CIDR ranges or use security group references.",
            ))
        return findings


class WidePortRangeRule(Rule):
    rule_id = "SG-003"
    name = "Wide Port Range"
    description = "Detects security group rules with port ranges wider than 100 ports"
    severity = Severity.MEDIUM
    compliance = ["AWS Config: vpc-sg-open-only-to-authorized-ports", "Well-Architected: SEC05-BP02"]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type in SG_RESOURCE_TYPES and change.change_type != ChangeType.DELETE

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        props = change.after or {}
        for rule in _extract_ingress_rules(props, change.resource_type):
            from_port, to_port = _get_port_range(rule)
            if from_port == -1 and to_port == -1:
                continue
            port_range = to_port - from_port
            if port_range > 100:
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    resource=change.resource_id,
                    finding=f"Security group rule has wide port range: {from_port}-{to_port} ({port_range} ports)",
                    evidence={"from_port": from_port, "to_port": to_port, "range_size": port_range},
                    remediation="Narrow the port range to only the required ports.",
                ))
        return findings


class AllTrafficRule(Rule):
    rule_id = "SG-004"
    name = "All Traffic from Any Source"
    description = "Detects security group rules allowing all traffic (protocol -1) from 0.0.0.0/0"
    severity = Severity.CRITICAL
    compliance = ["CIS 5.2", "CIS 5.3", "AWS Config: restricted-ssh", "AWS Config: restricted-common-ports", "SecurityHub: EC2.19", "Well-Architected: SEC05-BP02"]

    def applies_to(self, change: ResourceChange) -> bool:
        return change.resource_type in SG_RESOURCE_TYPES and change.change_type != ChangeType.DELETE

    def evaluate(self, change: ResourceChange) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        props = change.after or {}
        for rule in _extract_ingress_rules(props, change.resource_type):
            ip_protocol = str(rule.get("IpProtocol", ""))
            if ip_protocol != "-1":
                continue
            cidrs = _get_cidrs(rule)
            if not _is_public(cidrs):
                continue
            findings.append(RuleFinding(
                rule_id=self.rule_id,
                severity=self.severity,
                resource=change.resource_id,
                finding="Security group allows all traffic from any source (protocol -1, 0.0.0.0/0)",
                evidence={"protocol": ip_protocol, "cidr": cidrs},
                remediation="Remove the all-traffic rule. Use specific protocols and port ranges with restricted CIDRs.",
            ))
        return findings


def get_all_sg_rules() -> list[Rule]:
    return [
        AllTrafficRule(),
        PublicSensitivePortRule(),
        UnrestrictedIngressRule(),
        WidePortRangeRule(),
    ]
