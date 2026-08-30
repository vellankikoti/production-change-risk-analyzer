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
from src.storage.dynamodb import RiskReportStore


def _create_table(region: str = "us-east-1", table_name: str = "test-reports"):
    dynamodb = boto3.resource("dynamodb", region_name=region)
    dynamodb.create_table(
        TableName=table_name,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "risk_level", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "risk-level-index",
                "KeySchema": [
                    {"AttributeName": "risk_level", "KeyType": "HASH"},
                    {"AttributeName": "sk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_report(
    change_id: str = "CHG-TEST0001",
    risk_level: RiskLevel = RiskLevel.CRITICAL,
    decision: Decision = Decision.BLOCK,
    environment: str = "production",
    risk_score: int = 90,
) -> RiskReport:
    finding = RuleFinding(
        rule_id="IAM-003",
        severity=Severity.CRITICAL,
        resource="AppRole",
        finding="Full admin access detected",
        evidence={"action": "*", "resource": "*"},
        remediation="Restrict permissions",
        compliance=["CIS 1.16"],
    )
    evidence = EvidencePackage(
        change_id=change_id,
        timestamp="2025-01-15T10:00:00+00:00",
        environment=environment,
        changes=[],
        findings=[finding],
        metadata={"has_before": True, "total_resources": 1},
    )
    return RiskReport(
        change_id=change_id,
        timestamp="2025-01-15T10:00:00+00:00",
        risk_level=risk_level,
        risk_score=risk_score,
        decision=decision,
        evidence=evidence,
        ai_analysis=AIAnalysis.empty(),
        reasons=["Full admin access detected"],
    )


@pytest.fixture
def ddb_store():
    with mock_aws():
        os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
        _create_table(region="us-east-1", table_name="test-reports")
        yield RiskReportStore(table_name="test-reports", region="us-east-1")


class TestRiskReportStore:
    def test_save_and_get_report(self, ddb_store):
        report = _make_report()
        ddb_store.save_report(report)

        retrieved = ddb_store.get_report("CHG-TEST0001")
        assert retrieved is not None
        assert retrieved.change_id == "CHG-TEST0001"
        assert retrieved.risk_level == RiskLevel.CRITICAL
        assert retrieved.decision == Decision.BLOCK
        assert retrieved.risk_score == 90

    def test_get_nonexistent_report(self, ddb_store):
        result = ddb_store.get_report("CHG-NONEXIST")
        assert result is None

    def test_list_reports_all(self, ddb_store):
        ddb_store.save_report(_make_report("CHG-A001"))
        ddb_store.save_report(_make_report("CHG-A002", risk_level=RiskLevel.LOW, decision=Decision.APPROVE, risk_score=10))

        items = ddb_store.list_reports()
        assert len(items) == 2

    def test_list_reports_by_risk_level(self, ddb_store):
        ddb_store.save_report(_make_report("CHG-B001", risk_level=RiskLevel.CRITICAL))
        ddb_store.save_report(_make_report("CHG-B002", risk_level=RiskLevel.LOW, decision=Decision.APPROVE, risk_score=10))

        items = ddb_store.list_reports(risk_level="CRITICAL")
        assert len(items) >= 1
        assert all(i.get("risk_level") == "CRITICAL" for i in items)

    def test_list_reports_by_environment(self, ddb_store):
        ddb_store.save_report(_make_report("CHG-C001", environment="production"))
        ddb_store.save_report(_make_report("CHG-C002", environment="staging"))

        items = ddb_store.list_reports(environment="production")
        assert all(i.get("environment") == "production" for i in items)

    def test_get_blocked_reports(self, ddb_store):
        ddb_store.save_report(_make_report("CHG-D001", decision=Decision.BLOCK))
        ddb_store.save_report(_make_report("CHG-D002", risk_level=RiskLevel.LOW, decision=Decision.APPROVE, risk_score=10))

        blocked = ddb_store.get_blocked_reports()
        assert len(blocked) >= 1
        assert all(i.get("decision") == "BLOCK" for i in blocked)

    def test_save_report_with_float_values(self, ddb_store):
        report = _make_report("CHG-FLOAT01")
        report.evidence.metadata["float_val"] = 3.14
        ddb_store.save_report(report)
        retrieved = ddb_store.get_report("CHG-FLOAT01")
        assert retrieved is not None
