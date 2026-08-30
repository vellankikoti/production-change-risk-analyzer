from __future__ import annotations

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
from src.output.markdown import generate_markdown, write_markdown


def _make_report(
    findings: list[RuleFinding] | None = None,
    ai: AIAnalysis | None = None,
    risk_level: RiskLevel = RiskLevel.HIGH,
    decision: Decision = Decision.REVIEW,
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
                remediation="Restrict to known CIDR ranges",
                compliance=["CIS 5.2"],
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
        risk_score=75,
        decision=decision,
        evidence=evidence,
        ai_analysis=ai or AIAnalysis.empty(),
        reasons=[],
    )


class TestGenerateMarkdown:
    def test_contains_header(self):
        md = generate_markdown(_make_report())
        assert "Infrastructure Change Risk Report" in md

    def test_contains_change_id(self):
        md = generate_markdown(_make_report())
        assert "CHG-TEST1234" in md

    def test_contains_risk_level(self):
        md = generate_markdown(_make_report())
        assert "HIGH" in md

    def test_contains_decision(self):
        md = generate_markdown(_make_report())
        assert "REVIEW" in md

    def test_contains_resource_changes_table(self):
        md = generate_markdown(_make_report())
        assert "Resource Changes" in md
        assert "MySecurityGroup" in md
        assert "AWS::EC2::SecurityGroup" in md

    def test_contains_findings_table(self):
        md = generate_markdown(_make_report())
        assert "Findings" in md
        assert "SG-001" in md
        assert "Port 5432" in md

    def test_contains_compliance(self):
        md = generate_markdown(_make_report())
        assert "CIS 5.2" in md

    def test_no_findings_omits_table(self):
        report = _make_report(findings=[], risk_level=RiskLevel.LOW, decision=Decision.APPROVE)
        md = generate_markdown(report)
        assert "Findings" not in md

    def test_ai_analysis_included(self):
        ai = AIAnalysis(
            explanation="This change is risky",
            blast_radius="Affects all database connections",
            facts=["Port 5432 is PostgreSQL"],
            inferences=["May impact production traffic"],
        )
        md = generate_markdown(_make_report(ai=ai))
        assert "AI Analysis" in md
        assert "This change is risky" in md
        assert "Blast Radius" in md
        assert "Facts" in md
        assert "Port 5432 is PostgreSQL" in md

    def test_ai_inferences_in_details(self):
        ai = AIAnalysis(
            explanation="Risky",
            facts=["Fact 1"],
            inferences=["Inference 1"],
        )
        md = generate_markdown(_make_report(ai=ai))
        assert "<details>" in md
        assert "Inference 1" in md

    def test_no_ai_omits_section(self):
        md = generate_markdown(_make_report(ai=AIAnalysis.empty()))
        assert "AI Analysis" not in md

    def test_pipe_in_finding_escaped(self):
        findings = [
            RuleFinding(
                rule_id="TEST-001",
                severity=Severity.MEDIUM,
                resource="Res",
                finding="Contains | pipe character",
            ),
        ]
        md = generate_markdown(_make_report(findings=findings))
        assert "\\|" in md

    def test_footer_present(self):
        md = generate_markdown(_make_report())
        assert "production-change-risk-analyzer" in md

    def test_remediation_section(self):
        ai = AIAnalysis(
            explanation="Issue found",
            remediation="Apply least-privilege IAM policies",
        )
        md = generate_markdown(_make_report(ai=ai))
        assert "Remediation" in md
        assert "least-privilege" in md


class TestWriteMarkdown:
    def test_write_creates_file(self):
        report = _make_report()
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False, mode="w") as f:
            path = f.name
        try:
            write_markdown(report, path)
            with open(path) as f:
                content = f.read()
            assert "Infrastructure Change Risk Report" in content
            assert "CHG-TEST1234" in content
        finally:
            os.unlink(path)
