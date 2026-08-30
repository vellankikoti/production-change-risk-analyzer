from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from src.models.schemas import (
    AIAnalysis,
    Decision,
    EvidencePackage,
    RiskLevel,
    RiskReport,
    RuleFinding,
    Severity,
)


def _make_mock_report() -> RiskReport:
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
        change_id="CHG-WEBTEST01",
        timestamp="2025-01-15T10:00:00+00:00",
        environment="production",
        changes=[],
        findings=[finding],
        metadata={},
    )
    return RiskReport(
        change_id="CHG-WEBTEST01",
        timestamp="2025-01-15T10:00:00+00:00",
        risk_level=RiskLevel.CRITICAL,
        risk_score=90,
        decision=Decision.BLOCK,
        evidence=evidence,
        ai_analysis=AIAnalysis.empty(),
        reasons=["Full admin access detected"],
    )


@pytest.fixture
def mock_store():
    store = MagicMock()
    store.list_reports.return_value = [
        {
            "change_id": "CHG-001",
            "timestamp": "2025-01-15T10:00:00+00:00",
            "risk_level": "CRITICAL",
            "risk_score": 90,
            "decision": "BLOCK",
            "environment": "production",
        }
    ]
    store.get_report.return_value = _make_mock_report()
    store.save_report.return_value = None
    return store


@pytest.fixture
def mock_evidence_store():
    store = MagicMock()
    store.save_evidence.return_value = "evidence/key.json"
    store.save_templates.return_value = None
    return store


@pytest.fixture
def mock_notifier():
    notifier = MagicMock()
    notifier.notify.return_value = True
    return notifier


@pytest.fixture
def client(mock_store, mock_evidence_store, mock_notifier):
    import src.web.app as web_app
    web_app._store = mock_store
    web_app._evidence_store = mock_evidence_store
    web_app._notifier = mock_notifier
    return TestClient(web_app.app)


class TestDashboard:
    def test_get_dashboard(self, client, mock_store):
        response = client.get("/")
        assert response.status_code == 200
        assert "Risk Analyzer" in response.text or "risk" in response.text.lower()

    def test_get_analyze_form(self, client):
        response = client.get("/analyze")
        assert response.status_code == 200


class TestAnalyzeEndpoint:
    def test_post_analyze_with_template(self, client):
        template_content = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: test-bucket
"""
        response = client.post(
            "/analyze",
            files={"after_template": ("test.yaml", template_content, "text/yaml")},
            data={"environment": "development", "use_ai": "false"},
        )
        assert response.status_code == 200


class TestAPIEndpoints:
    def test_api_list_reports(self, client, mock_store):
        response = client.get("/api/reports")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_api_get_report(self, client, mock_store):
        response = client.get("/api/reports/CHG-WEBTEST01")
        assert response.status_code == 200
        data = response.json()
        assert data["change_id"] == "CHG-WEBTEST01"

    def test_api_get_report_not_found(self, client, mock_store):
        mock_store.get_report.return_value = None
        response = client.get("/api/reports/CHG-NONEXIST")
        assert response.status_code == 404

    def test_api_stats(self, client, mock_store):
        response = client.get("/api/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "by_risk_level" in data
        assert "by_decision" in data

    def test_api_analyze(self, client):
        template_content = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
"""
        response = client.post(
            "/api/analyze",
            files={"after_template": ("test.yaml", template_content, "text/yaml")},
            data={"environment": "development", "use_ai": "false"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "change_id" in data
        assert "risk_level" in data
        assert "decision" in data


class TestFixtureEndpoint:
    def test_valid_fixture(self, client):
        response = client.get("/api/fixture/secure_baseline")
        assert response.status_code == 200

    def test_invalid_fixture_name_path_traversal(self, client):
        response = client.get("/api/fixture/../../../etc/passwd")
        assert response.status_code in (400, 404, 422)

    def test_invalid_fixture_name_dots(self, client):
        response = client.get("/api/fixture/foo..bar")
        assert response.status_code in (400, 422)

    def test_nonexistent_fixture(self, client):
        response = client.get("/api/fixture/totally_nonexistent_fixture")
        assert response.status_code == 404
