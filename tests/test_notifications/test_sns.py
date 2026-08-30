from __future__ import annotations

import os

import boto3
import pytest
from moto import mock_aws

from src.models.schemas import (
    AIAnalysis,
    Decision,
    EvidencePackage,
    RiskLevel,
    RiskReport,
    RuleFinding,
    Severity,
)
from src.notifications.sns import RiskNotifier


def _create_topic(region: str = "us-east-1") -> str:
    sns = boto3.client("sns", region_name=region)
    response = sns.create_topic(Name="test-risk-alerts")
    return response["TopicArn"]


def _make_report(
    risk_level: RiskLevel = RiskLevel.CRITICAL,
    decision: Decision = Decision.BLOCK,
) -> RiskReport:
    finding = RuleFinding(
        rule_id="IAM-003",
        severity=Severity.CRITICAL,
        resource="AppRole",
        finding="Full admin access detected",
        evidence={"action": "*"},
        remediation="Restrict permissions",
        compliance=["CIS 1.16"],
    )
    evidence = EvidencePackage(
        change_id="CHG-NOTIFY01",
        timestamp="2025-01-15T10:00:00+00:00",
        environment="production",
        changes=[],
        findings=[finding],
        metadata={},
    )
    return RiskReport(
        change_id="CHG-NOTIFY01",
        timestamp="2025-01-15T10:00:00+00:00",
        risk_level=risk_level,
        risk_score=90,
        decision=decision,
        evidence=evidence,
        ai_analysis=AIAnalysis.empty(),
        reasons=["Full admin access detected"],
    )


@pytest.fixture
def sns_notifier():
    with mock_aws():
        os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
        topic_arn = _create_topic()
        yield RiskNotifier(topic_arn=topic_arn, region="us-east-1")


class TestRiskNotifier:
    def test_notify_critical(self, sns_notifier):
        report = _make_report(RiskLevel.CRITICAL, Decision.BLOCK)
        result = sns_notifier.notify(report)
        assert result is True

    def test_notify_high(self, sns_notifier):
        report = _make_report(RiskLevel.HIGH, Decision.REVIEW)
        result = sns_notifier.notify(report)
        assert result is True

    def test_skip_low_risk(self, sns_notifier):
        report = _make_report(RiskLevel.LOW, Decision.APPROVE)
        result = sns_notifier.notify(report)
        assert result is False

    def test_skip_medium_risk(self, sns_notifier):
        report = _make_report(RiskLevel.MEDIUM, Decision.REVIEW)
        result = sns_notifier.notify(report)
        assert result is False

    def test_no_topic_arn(self):
        with mock_aws():
            notifier = RiskNotifier(topic_arn="", region="us-east-1")
            report = _make_report()
            result = notifier.notify(report)
            assert result is False
