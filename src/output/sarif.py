from __future__ import annotations

import json
from typing import Any

from src.models.schemas import RiskReport, RuleFinding, Severity

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
TOOL_NAME = "production-change-risk-analyzer"
TOOL_VERSION = "1.0.0"
TOOL_URI = "https://github.com/vellankikoti/production-change-risk-analyzer"

SEVERITY_TO_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _build_rule_descriptor(finding: RuleFinding) -> dict[str, Any]:
    sev = finding.severity.value if isinstance(finding.severity, Severity) else finding.severity
    desc: dict[str, Any] = {
        "id": finding.rule_id,
        "shortDescription": {"text": finding.finding[:200]},
        "fullDescription": {"text": finding.finding},
        "helpUri": f"{TOOL_URI}#rules",
        "properties": {
            "severity": sev,
        },
    }
    if finding.remediation:
        desc["help"] = {"text": finding.remediation}
    if finding.compliance:
        desc["properties"]["compliance"] = finding.compliance
    return desc


def generate_sarif(report: RiskReport) -> dict[str, Any]:
    seen_rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in report.evidence.findings:
        sev = finding.severity if isinstance(finding.severity, Severity) else Severity(finding.severity)
        level = SEVERITY_TO_LEVEL.get(sev, "note")

        if finding.rule_id not in seen_rules:
            seen_rules[finding.rule_id] = _build_rule_descriptor(finding)

        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": level,
            "message": {"text": finding.finding},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "template.yaml",
                        },
                        "region": {
                            "snippet": {"text": finding.resource},
                        },
                    },
                }
            ],
            "properties": {
                "severity": sev.value,
                "resource": finding.resource,
            },
        }
        if finding.remediation:
            result["properties"]["remediation"] = finding.remediation
        if finding.compliance:
            result["properties"]["compliance"] = finding.compliance

        results.append(result)

    decision = report.decision.value if hasattr(report.decision, "value") else report.decision
    risk_level = report.risk_level.value if hasattr(report.risk_level, "value") else report.risk_level

    sarif: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_URI,
                        "rules": list(seen_rules.values()),
                    },
                },
                "results": results,
                "properties": {
                    "changeId": report.change_id,
                    "riskLevel": risk_level,
                    "riskScore": report.risk_score,
                    "decision": decision,
                    "environment": report.evidence.environment,
                    "timestamp": report.timestamp,
                },
            }
        ],
    }
    return sarif


def write_sarif(report: RiskReport, path: str) -> None:
    sarif = generate_sarif(report)
    with open(path, "w") as f:
        json.dump(sarif, f, indent=2, default=str)
