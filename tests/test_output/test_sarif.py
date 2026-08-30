from __future__ import annotations

import json
import os
import tempfile

import pytest

from src.models.schemas import (
    AIAnalysis,
    ChangeType,
    Decision,
    EvidencePackage,
    ResourceChange,
    RiskLevel,
    RiskReport,
    RuleFinding,
    Severity,
)
from src.output.sarif import generate_sarif, write_sarif


def _make_report(
    findings: list[RuleFinding] | None = None,
    risk_level: RiskLevel = RiskLevel.HIGH,
    decision: Decision = Decision.REVIEW,
    risk_score: int = 65,
) -> RiskReport:
    changes = [
        ResourceChange(
            resource_id="MySecurityGroup",
            resource_type="AWS::EC2::SecurityGroup",
            change_type=ChangeType.MODIFY,
            before={},
            after={},
        )
    ]
    if findings is None:
        findings = [
            RuleFinding(
                rule_id="SG-001",
                severity=Severity.CRITICAL,
                resource="MySecurityGroup",
                finding="Port 5432 open to 0.0.0.0/0",
                evidence={"port": 5432, "cidr": "0.0.0.0/0"},
                remediation="Restrict to known CIDR ranges",
                compliance=["CIS 5.2", "SecurityHub EC2.18"],
            ),
            RuleFinding(
                rule_id="IAM-001",
                severity=Severity.HIGH,
                resource="AdminRole",
                finding="Wildcard action in IAM policy",
                evidence={"action": "*"},
                remediation="Use least-privilege actions",
                compliance=["CIS 1.16"],
            ),
        ]
    evidence = EvidencePackage(
        change_id="CHG-TEST1234",
        timestamp="2026-08-30T12:00:00+00:00",
        environment="production",
        changes=changes,
        findings=findings,
    )
    return RiskReport(
        change_id="CHG-TEST1234",
        timestamp="2026-08-30T12:00:00+00:00",
        risk_level=risk_level,
        risk_score=risk_score,
        decision=decision,
        evidence=evidence,
        ai_analysis=AIAnalysis.empty(),
        reasons=["CRITICAL finding detected"],
    )


class TestGenerateSarif:
    def test_schema_and_version(self):
        sarif = generate_sarif(_make_report())
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert "sarif-schema-2.1.0" in sarif["$schema"]

    def test_single_run(self):
        sarif = generate_sarif(_make_report())
        assert len(sarif["runs"]) == 1

    def test_tool_metadata(self):
        sarif = generate_sarif(_make_report())
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "production-change-risk-analyzer"
        assert "version" in driver
        assert "informationUri" in driver

    def test_rules_match_findings(self):
        sarif = generate_sarif(_make_report())
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        assert rule_ids == {"SG-001", "IAM-001"}

    def test_rule_descriptor_has_compliance(self):
        sarif = generate_sarif(_make_report())
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        sg_rule = next(r for r in rules if r["id"] == "SG-001")
        assert "compliance" in sg_rule["properties"]
        assert "CIS 5.2" in sg_rule["properties"]["compliance"]

    def test_rule_descriptor_has_help(self):
        sarif = generate_sarif(_make_report())
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        sg_rule = next(r for r in rules if r["id"] == "SG-001")
        assert "help" in sg_rule
        assert "Restrict" in sg_rule["help"]["text"]

    def test_results_count(self):
        sarif = generate_sarif(_make_report())
        results = sarif["runs"][0]["results"]
        assert len(results) == 2

    def test_critical_maps_to_error(self):
        sarif = generate_sarif(_make_report())
        results = sarif["runs"][0]["results"]
        sg_result = next(r for r in results if r["ruleId"] == "SG-001")
        assert sg_result["level"] == "error"

    def test_result_has_location(self):
        sarif = generate_sarif(_make_report())
        result = sarif["runs"][0]["results"][0]
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "template.yaml"
        assert "snippet" in loc["region"]

    def test_result_properties(self):
        sarif = generate_sarif(_make_report())
        result = sarif["runs"][0]["results"][0]
        assert "severity" in result["properties"]
        assert "resource" in result["properties"]

    def test_run_properties(self):
        sarif = generate_sarif(_make_report())
        props = sarif["runs"][0]["properties"]
        assert props["changeId"] == "CHG-TEST1234"
        assert props["riskLevel"] == "HIGH"
        assert props["riskScore"] == 65
        assert props["decision"] == "REVIEW"
        assert props["environment"] == "production"

    def test_no_findings_produces_empty_results(self):
        report = _make_report(findings=[], risk_level=RiskLevel.LOW, decision=Decision.APPROVE, risk_score=0)
        sarif = generate_sarif(report)
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []

    def test_deduplicated_rules(self):
        findings = [
            RuleFinding(rule_id="IAM-001", severity=Severity.HIGH, resource="Role1", finding="Wildcard action"),
            RuleFinding(rule_id="IAM-001", severity=Severity.HIGH, resource="Role2", finding="Wildcard action"),
        ]
        report = _make_report(findings=findings)
        sarif = generate_sarif(report)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert len(sarif["runs"][0]["results"]) == 2

    def test_sarif_is_json_serializable(self):
        sarif = generate_sarif(_make_report())
        text = json.dumps(sarif, default=str)
        parsed = json.loads(text)
        assert parsed["version"] == "2.1.0"


class TestWriteSarif:
    def test_write_creates_valid_json_file(self):
        report = _make_report()
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False, mode="w") as f:
            path = f.name
        try:
            write_sarif(report, path)
            with open(path) as f:
                sarif = json.load(f)
            assert sarif["version"] == "2.1.0"
            assert len(sarif["runs"][0]["results"]) == 2
        finally:
            os.unlink(path)
