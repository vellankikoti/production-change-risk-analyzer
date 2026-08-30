from __future__ import annotations

import json
import os

import boto3
import pytest
from moto import mock_aws

from src.models.schemas import (
    EvidencePackage,
    ResourceChange,
    ChangeType,
    RuleFinding,
    Severity,
)
from src.storage.s3 import EvidenceStore


def _create_bucket(region: str = "us-east-1", bucket_name: str = "test-evidence"):
    s3 = boto3.client("s3", region_name=region)
    s3.create_bucket(Bucket=bucket_name)


def _make_evidence(change_id: str = "CHG-S3TEST01") -> EvidencePackage:
    return EvidencePackage(
        change_id=change_id,
        timestamp="2025-01-15T10:00:00+00:00",
        environment="production",
        changes=[
            ResourceChange(
                resource_id="AppRole",
                resource_type="AWS::IAM::Role",
                change_type=ChangeType.MODIFY,
                before={"old": "val"},
                after={"new": "val"},
            )
        ],
        findings=[
            RuleFinding(
                rule_id="IAM-003",
                severity=Severity.CRITICAL,
                resource="AppRole",
                finding="Full admin access",
                evidence={"action": "*"},
                remediation="Restrict",
                compliance=["CIS 1.16"],
            )
        ],
        metadata={"has_before": True},
    )


@pytest.fixture
def s3_store():
    with mock_aws():
        os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
        _create_bucket(region="us-east-1", bucket_name="test-evidence")
        yield EvidenceStore(bucket_name="test-evidence", region="us-east-1")


class TestEvidenceStore:
    def test_save_evidence(self, s3_store):
        evidence = _make_evidence()
        key = s3_store.save_evidence(evidence)
        assert key.startswith("evidence/CHG-S3TEST01/")
        assert key.endswith(".json")

    def test_save_and_get_evidence(self, s3_store):
        evidence = _make_evidence("CHG-ROUNDTRIP")
        s3_store.save_evidence(evidence)

        retrieved = s3_store.get_evidence("CHG-ROUNDTRIP")
        assert retrieved is not None
        assert retrieved.change_id == "CHG-ROUNDTRIP"
        assert retrieved.environment == "production"
        assert len(retrieved.findings) == 1
        assert retrieved.findings[0].rule_id == "IAM-003"

    def test_get_nonexistent_evidence(self, s3_store):
        result = s3_store.get_evidence("CHG-NONEXIST")
        assert result is None

    def test_save_templates_both(self, s3_store):
        s3_store.save_templates("CHG-TMPL01", "before: content", "after: content")

        with mock_aws():
            s3 = boto3.client("s3", region_name="us-east-1")
            before_obj = s3.get_object(Bucket="test-evidence", Key="templates/CHG-TMPL01/before.yaml")
            assert before_obj["Body"].read().decode() == "before: content"

    def test_save_templates_after_only(self, s3_store):
        s3_store.save_templates("CHG-TMPL02", None, "after: only")

        with mock_aws():
            s3 = boto3.client("s3", region_name="us-east-1")
            after_obj = s3.get_object(Bucket="test-evidence", Key="templates/CHG-TMPL02/after.yaml")
            assert after_obj["Body"].read().decode() == "after: only"
