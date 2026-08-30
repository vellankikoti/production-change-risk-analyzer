from __future__ import annotations

import pytest

from src.analyzer.scoring import _categorize_rule, compute_score_breakdown
from src.models.schemas import RuleFinding, Severity


def _make_finding(rule_id: str, severity: Severity, resource: str = "Res") -> RuleFinding:
    return RuleFinding(
        rule_id=rule_id,
        severity=severity,
        resource=resource,
        finding=f"Test finding for {rule_id}",
        evidence={"test": True},
        remediation="Fix it",
        compliance=[],
    )


class TestCategorizeRule:
    def test_iam_prefix(self):
        assert _categorize_rule("IAM-001") == "Identity & Access"

    def test_sg_prefix(self):
        assert _categorize_rule("SG-004") == "Network Security"

    def test_net_prefix(self):
        assert _categorize_rule("NET-001") == "Network Security"

    def test_avail_prefix(self):
        assert _categorize_rule("AVAIL-001") == "Availability"

    def test_enc_prefix(self):
        assert _categorize_rule("ENC-001") == "Encryption"

    def test_log_prefix(self):
        assert _categorize_rule("LOG-001") == "Logging"

    def test_del_prefix(self):
        assert _categorize_rule("DEL-001") == "Data Protection"

    def test_unknown_prefix(self):
        assert _categorize_rule("CUSTOM-001") == "Other"


class TestComputeScoreBreakdown:
    def test_empty_findings(self):
        sb = compute_score_breakdown([], "APPROVE")
        assert sb.total_score == 5
        assert sb.decision == "APPROVE"
        assert sb.contributions == []

    def test_single_critical_finding(self):
        findings = [_make_finding("IAM-003", Severity.CRITICAL)]
        sb = compute_score_breakdown(findings, "BLOCK")
        assert sb.total_score == 25
        assert sb.decision == "BLOCK"
        assert len(sb.contributions) == 1
        assert sb.contributions[0].category == "Identity & Access"
        assert sb.contributions[0].score == 25

    def test_multiple_findings_same_category(self):
        findings = [
            _make_finding("SG-001", Severity.CRITICAL),
            _make_finding("SG-004", Severity.CRITICAL),
        ]
        sb = compute_score_breakdown(findings, "BLOCK")
        assert len(sb.contributions) == 1
        assert sb.contributions[0].category == "Network Security"
        assert sb.contributions[0].score == 30  # 25 base + 5 extra

    def test_multiple_categories(self):
        findings = [
            _make_finding("IAM-003", Severity.CRITICAL),
            _make_finding("SG-001", Severity.HIGH),
            _make_finding("AVAIL-001", Severity.MEDIUM),
        ]
        sb = compute_score_breakdown(findings, "BLOCK")
        assert len(sb.contributions) == 3
        assert sb.contributions[0].score == 25  # IAM CRITICAL
        assert sb.total_score == 25 + 15 + 8

    def test_score_capped_at_100(self):
        findings = [
            _make_finding("IAM-001", Severity.CRITICAL),
            _make_finding("IAM-002", Severity.CRITICAL),
            _make_finding("IAM-003", Severity.CRITICAL),
            _make_finding("SG-001", Severity.CRITICAL),
            _make_finding("SG-002", Severity.CRITICAL),
            _make_finding("AVAIL-001", Severity.CRITICAL),
            _make_finding("ENC-001", Severity.CRITICAL),
        ]
        sb = compute_score_breakdown(findings, "BLOCK")
        assert sb.total_score == 100

    def test_low_severity(self):
        findings = [_make_finding("LOG-001", Severity.LOW)]
        sb = compute_score_breakdown(findings, "APPROVE")
        assert sb.total_score == 3
        assert sb.contributions[0].score == 3

    def test_contributions_sorted_by_score_desc(self):
        findings = [
            _make_finding("LOG-001", Severity.LOW),
            _make_finding("IAM-003", Severity.CRITICAL),
            _make_finding("AVAIL-001", Severity.MEDIUM),
        ]
        sb = compute_score_breakdown(findings, "BLOCK")
        scores = [c.score for c in sb.contributions]
        assert scores == sorted(scores, reverse=True)
