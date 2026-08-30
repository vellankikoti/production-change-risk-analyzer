from __future__ import annotations

import os
import tempfile

import pytest
import yaml

from src.policy.engine import Policy, PolicyContext, PolicyEngine, PolicyResult


def _make_context(**kwargs) -> PolicyContext:
    defaults = {
        "environment": "production",
        "resource_types": ["AWS::RDS::DBInstance"],
        "change_types": ["MODIFY"],
        "rules_triggered": ["SG-001"],
        "severity_max": "CRITICAL",
        "risk_score": 85,
        "decision": "BLOCK",
        "finding_count": 3,
        "resource_ids": ["MyDatabase"],
        "timestamp": "2026-08-30T12:00:00Z",
    }
    defaults.update(kwargs)
    return PolicyContext(**defaults)


def _make_policy(**kwargs) -> Policy:
    defaults = {
        "id": "TEST-001",
        "name": "Test Policy",
        "when": {"environment": "production"},
        "decision": "BLOCK",
        "reason": "Test reason",
    }
    defaults.update(kwargs)
    return Policy(**defaults)


class TestPolicyMatching:
    def test_match_environment(self):
        engine = PolicyEngine([_make_policy(when={"environment": "production"})])
        ctx = _make_context(environment="production")
        results = engine.evaluate(ctx)
        assert results[0].matched is True

    def test_no_match_environment(self):
        engine = PolicyEngine([_make_policy(when={"environment": "staging"})])
        ctx = _make_context(environment="production")
        results = engine.evaluate(ctx)
        assert results[0].matched is False

    def test_match_environment_list(self):
        engine = PolicyEngine([_make_policy(when={"environment": ["production", "staging"]})])
        ctx = _make_context(environment="staging")
        results = engine.evaluate(ctx)
        assert results[0].matched is True

    def test_match_resource_type(self):
        engine = PolicyEngine([_make_policy(when={"resource_type": "AWS::RDS::DBInstance"})])
        ctx = _make_context(resource_types=["AWS::RDS::DBInstance", "AWS::EC2::SecurityGroup"])
        results = engine.evaluate(ctx)
        assert results[0].matched is True

    def test_no_match_resource_type(self):
        engine = PolicyEngine([_make_policy(when={"resource_type": "AWS::Lambda::Function"})])
        ctx = _make_context(resource_types=["AWS::RDS::DBInstance"])
        results = engine.evaluate(ctx)
        assert results[0].matched is False

    def test_match_change_type(self):
        engine = PolicyEngine([_make_policy(when={"change_type": "DELETE"})])
        ctx = _make_context(change_types=["DELETE"])
        results = engine.evaluate(ctx)
        assert results[0].matched is True

    def test_match_rules_triggered(self):
        engine = PolicyEngine([_make_policy(when={"rules_triggered": ["SG-001", "SG-004"]})])
        ctx = _make_context(rules_triggered=["SG-001", "IAM-003"])
        results = engine.evaluate(ctx)
        assert results[0].matched is True

    def test_no_match_rules_triggered(self):
        engine = PolicyEngine([_make_policy(when={"rules_triggered": ["NET-001"]})])
        ctx = _make_context(rules_triggered=["SG-001"])
        results = engine.evaluate(ctx)
        assert results[0].matched is False

    def test_match_severity_max(self):
        engine = PolicyEngine([_make_policy(when={"severity_max": "HIGH"}, decision="APPROVE")])
        ctx = _make_context(severity_max="MEDIUM")
        results = engine.evaluate(ctx)
        assert results[0].matched is True

    def test_no_match_severity_max(self):
        engine = PolicyEngine([_make_policy(when={"severity_max": "MEDIUM"}, decision="APPROVE")])
        ctx = _make_context(severity_max="CRITICAL")
        results = engine.evaluate(ctx)
        assert results[0].matched is False

    def test_match_multiple_conditions(self):
        engine = PolicyEngine([_make_policy(when={
            "environment": "production",
            "resource_type": "AWS::RDS::DBInstance",
            "change_type": "DELETE",
        })])
        ctx = _make_context(
            environment="production",
            resource_types=["AWS::RDS::DBInstance"],
            change_types=["DELETE"],
        )
        results = engine.evaluate(ctx)
        assert results[0].matched is True

    def test_no_match_partial_conditions(self):
        engine = PolicyEngine([_make_policy(when={
            "environment": "production",
            "change_type": "DELETE",
        })])
        ctx = _make_context(environment="production", change_types=["MODIFY"])
        results = engine.evaluate(ctx)
        assert results[0].matched is False

    def test_match_empty_conditions(self):
        engine = PolicyEngine([_make_policy(when={})])
        ctx = _make_context()
        results = engine.evaluate(ctx)
        assert results[0].matched is True

    def test_match_risk_score_min(self):
        engine = PolicyEngine([_make_policy(when={"risk_score_min": 80})])
        ctx = _make_context(risk_score=85)
        results = engine.evaluate(ctx)
        assert results[0].matched is True

    def test_match_finding_count_min(self):
        engine = PolicyEngine([_make_policy(when={"finding_count_min": 5})])
        ctx = _make_context(finding_count=7)
        results = engine.evaluate(ctx)
        assert results[0].matched is True

    def test_no_match_finding_count_min(self):
        engine = PolicyEngine([_make_policy(when={"finding_count_min": 5})])
        ctx = _make_context(finding_count=3)
        results = engine.evaluate(ctx)
        assert results[0].matched is False

    def test_match_resource_id_glob(self):
        engine = PolicyEngine([_make_policy(when={"resource_id": "Prod*"})])
        ctx = _make_context(resource_ids=["ProdDatabase", "ProdCache"])
        results = engine.evaluate(ctx)
        assert results[0].matched is True

    def test_no_match_resource_id_glob(self):
        engine = PolicyEngine([_make_policy(when={"resource_id": "Prod*"})])
        ctx = _make_context(resource_ids=["DevDatabase"])
        results = engine.evaluate(ctx)
        assert results[0].matched is False


class TestChangeFreezePolicy:
    def test_within_freeze_window(self):
        engine = PolicyEngine([_make_policy(
            id="FREEZE-001",
            when={
                "after": "2026-08-01T00:00:00Z",
                "before": "2026-09-01T00:00:00Z",
            },
            decision="BLOCK",
            reason="Change freeze",
        )])
        ctx = _make_context(timestamp="2026-08-15T12:00:00Z")
        results = engine.evaluate(ctx)
        assert results[0].matched is True

    def test_outside_freeze_window(self):
        engine = PolicyEngine([_make_policy(
            when={
                "after": "2026-12-20T00:00:00Z",
                "before": "2027-01-02T00:00:00Z",
            },
            decision="BLOCK",
        )])
        ctx = _make_context(timestamp="2026-08-30T12:00:00Z")
        results = engine.evaluate(ctx)
        assert results[0].matched is False


class TestPolicyDecisionOverride:
    def test_block_overrides_review(self):
        engine = PolicyEngine([_make_policy(decision="BLOCK")])
        ctx = _make_context()
        results = engine.evaluate(ctx)
        new_decision, _ = engine.apply_decision(results, "REVIEW")
        assert new_decision == "BLOCK"

    def test_approve_downgrades_review(self):
        engine = PolicyEngine([_make_policy(
            when={"environment": "development"},
            decision="APPROVE",
        )])
        ctx = _make_context(environment="development")
        results = engine.evaluate(ctx)
        new_decision, _ = engine.apply_decision(results, "REVIEW")
        assert new_decision == "APPROVE"

    def test_no_match_keeps_base_decision(self):
        engine = PolicyEngine([_make_policy(when={"environment": "staging"})])
        ctx = _make_context(environment="production")
        results = engine.evaluate(ctx)
        new_decision, _ = engine.apply_decision(results, "REVIEW")
        assert new_decision == "REVIEW"

    def test_most_restrictive_wins(self):
        policies = [
            _make_policy(id="P1", when={"environment": "production"}, decision="APPROVE"),
            _make_policy(id="P2", when={"rules_triggered": ["SG-001"]}, decision="BLOCK"),
        ]
        engine = PolicyEngine(policies)
        ctx = _make_context(environment="production", rules_triggered=["SG-001"])
        results = engine.evaluate(ctx)
        new_decision, _ = engine.apply_decision(results, "REVIEW")
        assert new_decision == "BLOCK"


class TestPolicyFromYAML:
    def test_load_from_yaml(self):
        data = {
            "policies": [
                {
                    "id": "TEST-001",
                    "name": "Test",
                    "when": {"environment": "production"},
                    "decision": "BLOCK",
                    "reason": "Testing",
                },
                {
                    "id": "TEST-002",
                    "name": "Test 2",
                    "when": {"rules_triggered": ["IAM-003"]},
                    "decision": "BLOCK",
                    "reason": "No admin",
                },
            ]
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(data, f)
            path = f.name

        try:
            engine = PolicyEngine.from_yaml(path)
            assert len(engine.policies) == 2
            assert engine.policies[0].id == "TEST-001"
            assert engine.policies[1].decision == "BLOCK"
        finally:
            os.unlink(path)

    def test_load_empty_yaml(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("")
            path = f.name

        try:
            engine = PolicyEngine.from_yaml(path)
            assert len(engine.policies) == 0
        finally:
            os.unlink(path)


class TestPolicyContext:
    def test_from_report(self):
        from src.models.schemas import (
            ChangeType, Decision, EvidencePackage, AIAnalysis,
            ResourceChange, RiskLevel, RiskReport, RuleFinding, Severity,
        )
        evidence = EvidencePackage(
            change_id="CHG-TEST",
            timestamp="2026-08-30T12:00:00Z",
            environment="production",
            changes=[
                ResourceChange("MyDB", "AWS::RDS::DBInstance", ChangeType.DELETE),
            ],
            findings=[
                RuleFinding("AVAIL-004", Severity.CRITICAL, "MyDB", "Deleting database"),
            ],
        )
        report = RiskReport(
            change_id="CHG-TEST",
            timestamp="2026-08-30T12:00:00Z",
            risk_level=RiskLevel.CRITICAL,
            risk_score=85,
            decision=Decision.BLOCK,
            evidence=evidence,
            ai_analysis=AIAnalysis.empty(),
        )
        ctx = PolicyContext.from_report(report)
        assert ctx.environment == "production"
        assert "AWS::RDS::DBInstance" in ctx.resource_types
        assert "DELETE" in ctx.change_types
        assert "AVAIL-004" in ctx.rules_triggered
        assert ctx.severity_max == "CRITICAL"
        assert ctx.risk_score == 85
        assert ctx.finding_count == 1


class TestPolicyResultSerialization:
    def test_to_dict(self):
        r = PolicyResult("P1", "Test Policy", True, "BLOCK", "Because")
        d = r.to_dict()
        assert d["policy_id"] == "P1"
        assert d["matched"] is True

    def test_from_dict(self):
        d = {"policy_id": "P1", "policy_name": "Test", "matched": True, "decision": "BLOCK", "reason": "Why"}
        r = PolicyResult.from_dict(d)
        assert r.policy_id == "P1"
        assert r.matched is True
