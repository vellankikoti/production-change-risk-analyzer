from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.analyzer.orchestrator import ChangeAnalyzer
from src.models.schemas import AIAnalysis, Decision, RiskLevel


class TestOrchestratorDeterministic:
    """Tests using --no-ai mode so we only test deterministic behavior."""

    def test_dangerous_changes_blocked(self, secure_baseline, dangerous_changes):
        analyzer = ChangeAnalyzer(use_ai=False)
        report = analyzer.analyze(
            after_template=dangerous_changes,
            before_template=secure_baseline,
            environment="production",
        )
        assert report.decision == Decision.BLOCK
        assert report.risk_level == RiskLevel.CRITICAL
        assert report.risk_score >= 80
        rule_ids = {f.rule_id for f in report.evidence.findings}
        assert "IAM-003" in rule_ids
        assert "SG-001" in rule_ids
        assert "AVAIL-003" in rule_ids

    def test_minor_changes_approved(self, secure_baseline, minor_changes):
        analyzer = ChangeAnalyzer(use_ai=False)
        report = analyzer.analyze(
            after_template=minor_changes,
            before_template=secure_baseline,
            environment="production",
        )
        assert report.decision == Decision.APPROVE
        assert report.risk_level == RiskLevel.LOW
        assert report.risk_score < 40

    def test_new_stack_review_or_approve(self, new_stack):
        analyzer = ChangeAnalyzer(use_ai=False)
        report = analyzer.analyze(
            after_template=new_stack,
            environment="staging",
        )
        assert report.decision in (Decision.REVIEW, Decision.APPROVE)
        assert report.risk_level in (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH)

    def test_no_before_template(self, new_stack):
        analyzer = ChangeAnalyzer(use_ai=False)
        report = analyzer.analyze(after_template=new_stack, environment="development")
        assert report.change_id.startswith("CHG-")
        assert report.timestamp
        assert len(report.evidence.changes) > 0

    def test_environment_propagated(self, secure_baseline):
        analyzer = ChangeAnalyzer(use_ai=False)
        report = analyzer.analyze(after_template=secure_baseline, environment="staging")
        assert report.evidence.environment == "staging"


class TestOrchestratorWithMockedAI:
    @patch("src.analyzer.orchestrator.BedrockAnalyzer")
    def test_ai_called_when_findings_exist(self, mock_analyzer_cls, secure_baseline, dangerous_changes):
        mock_instance = MagicMock()
        mock_instance.analyze.return_value = AIAnalysis(
            explanation="This change exposes the database to the public internet.",
            blast_radius="All production database users.",
            operational_impact="Data breach risk.",
            remediation="Restrict the CIDR to the VPC range.",
            confidence="HIGH",
            facts=["Port 5432 is open to 0.0.0.0/0"],
            inferences=["The database could be accessed from the internet"],
        )
        mock_analyzer_cls.return_value = mock_instance

        analyzer = ChangeAnalyzer(use_ai=True)
        report = analyzer.analyze(
            after_template=dangerous_changes,
            before_template=secure_baseline,
            environment="production",
        )

        mock_instance.analyze.assert_called_once()
        assert report.ai_analysis.explanation
        assert report.decision == Decision.BLOCK

    @patch("src.analyzer.orchestrator.BedrockAnalyzer")
    def test_ai_not_called_when_no_findings(self, mock_analyzer_cls, secure_baseline):
        mock_instance = MagicMock()
        mock_analyzer_cls.return_value = mock_instance

        analyzer = ChangeAnalyzer(use_ai=True)
        report = analyzer.analyze(
            after_template=secure_baseline,
            before_template=secure_baseline,
            environment="production",
        )

        mock_instance.analyze.assert_not_called()
        assert report.decision == Decision.APPROVE
