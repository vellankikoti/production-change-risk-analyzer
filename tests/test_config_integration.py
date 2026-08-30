from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from src.analyzer.orchestrator import ChangeAnalyzer
from src.config import RiskAnalyzerConfig
from src.models.schemas import Decision, RiskLevel


FIXTURES_DIR = Path(__file__).parent / "fixtures" / "templates"


def _read_fixture(name: str) -> str:
    return (FIXTURES_DIR / name).read_text()


class TestConfigDisablesRules:
    def test_disable_iam003_reduces_findings(self):
        config = RiskAnalyzerConfig.from_dict({
            "disabled_rules": ["IAM-003"],
        })
        analyzer = ChangeAnalyzer(use_ai=False, emit_metrics=False, config=config)
        report = analyzer.analyze(
            after_template=_read_fixture("dangerous_changes.yaml"),
            before_template=_read_fixture("secure_baseline.yaml"),
            environment="production",
        )
        rule_ids = {f.rule_id for f in report.evidence.findings}
        assert "IAM-003" not in rule_ids
        assert len(report.evidence.findings) > 0

    def test_disable_all_sg_rules(self):
        config = RiskAnalyzerConfig.from_dict({
            "disabled_rules": ["SG-001", "SG-002", "SG-003", "SG-004"],
        })
        analyzer = ChangeAnalyzer(use_ai=False, emit_metrics=False, config=config)
        report = analyzer.analyze(
            after_template=_read_fixture("dangerous_changes.yaml"),
            before_template=_read_fixture("secure_baseline.yaml"),
            environment="production",
        )
        rule_ids = {f.rule_id for f in report.evidence.findings}
        assert not any(rid.startswith("SG-") for rid in rule_ids)


class TestConfigSuppressions:
    def test_suppress_specific_resource(self):
        config = RiskAnalyzerConfig.from_dict({
            "suppressions": [
                {
                    "rule_id": "SG-004",
                    "resource_pattern": "AllTrafficSecurityGroup",
                    "reason": "Accepted risk for testing",
                },
            ],
        })
        analyzer = ChangeAnalyzer(use_ai=False, emit_metrics=False, config=config)
        report = analyzer.analyze(
            after_template=_read_fixture("dangerous_changes.yaml"),
            before_template=_read_fixture("secure_baseline.yaml"),
            environment="production",
        )
        sg004_findings = [
            f for f in report.evidence.findings
            if f.rule_id == "SG-004" and f.resource == "AllTrafficSecurityGroup"
        ]
        assert len(sg004_findings) == 0

    def test_expired_suppression_has_no_effect(self):
        config = RiskAnalyzerConfig.from_dict({
            "suppressions": [
                {
                    "rule_id": "IAM-003",
                    "resource_pattern": "*",
                    "reason": "Expired suppression",
                    "expires": "2020-01-01T00:00:00Z",
                },
            ],
        })
        analyzer = ChangeAnalyzer(use_ai=False, emit_metrics=False, config=config)
        report = analyzer.analyze(
            after_template=_read_fixture("dangerous_changes.yaml"),
            before_template=_read_fixture("secure_baseline.yaml"),
            environment="production",
        )
        rule_ids = {f.rule_id for f in report.evidence.findings}
        assert "IAM-003" in rule_ids


class TestConfigSeverityOverrides:
    def test_severity_override_changes_risk_level(self):
        config = RiskAnalyzerConfig.from_dict({
            "rule_overrides": {
                "IAM-003": {"severity": "LOW"},
                "SG-004": {"severity": "LOW"},
                "SG-001": {"severity": "LOW"},
            },
        })
        analyzer = ChangeAnalyzer(use_ai=False, emit_metrics=False, config=config)
        report = analyzer.analyze(
            after_template=_read_fixture("dangerous_changes.yaml"),
            before_template=_read_fixture("secure_baseline.yaml"),
            environment="production",
        )
        for f in report.evidence.findings:
            if f.rule_id in ("IAM-003", "SG-004", "SG-001"):
                assert f.severity.value == "LOW"


class TestConfigEnvironmentOverrides:
    def test_per_environment_rule_disable(self):
        config = RiskAnalyzerConfig.from_dict({
            "environments": {
                "development": {
                    "disabled_rules": ["SG-004"],
                },
            },
        })
        analyzer = ChangeAnalyzer(use_ai=False, emit_metrics=False, config=config)

        report_dev = analyzer.analyze(
            after_template=_read_fixture("dangerous_changes.yaml"),
            before_template=_read_fixture("secure_baseline.yaml"),
            environment="development",
        )
        dev_rule_ids = {f.rule_id for f in report_dev.evidence.findings}
        assert "SG-004" not in dev_rule_ids

        report_prod = analyzer.analyze(
            after_template=_read_fixture("dangerous_changes.yaml"),
            before_template=_read_fixture("secure_baseline.yaml"),
            environment="production",
        )
        prod_rule_ids = {f.rule_id for f in report_prod.evidence.findings}
        assert "SG-004" in prod_rule_ids

    def test_block_on_high(self):
        config = RiskAnalyzerConfig.from_dict({
            "disabled_rules": ["IAM-003", "SG-001", "SG-004"],
            "environments": {
                "production": {
                    "block_on_high": True,
                },
            },
        })
        analyzer = ChangeAnalyzer(use_ai=False, emit_metrics=False, config=config)
        report = analyzer.analyze(
            after_template=_read_fixture("dangerous_changes.yaml"),
            before_template=_read_fixture("secure_baseline.yaml"),
            environment="production",
        )
        if report.risk_level == RiskLevel.HIGH:
            assert report.decision == Decision.BLOCK


class TestConfigNoEffect:
    def test_no_config_matches_baseline(self):
        analyzer_no_config = ChangeAnalyzer(use_ai=False, emit_metrics=False)
        analyzer_empty_config = ChangeAnalyzer(
            use_ai=False, emit_metrics=False,
            config=RiskAnalyzerConfig(),
        )

        report1 = analyzer_no_config.analyze(
            after_template=_read_fixture("minor_changes.yaml"),
            before_template=_read_fixture("secure_baseline.yaml"),
            environment="production",
        )
        report2 = analyzer_empty_config.analyze(
            after_template=_read_fixture("minor_changes.yaml"),
            before_template=_read_fixture("secure_baseline.yaml"),
            environment="production",
        )

        assert report1.risk_level == report2.risk_level
        assert report1.decision == report2.decision
        assert report1.risk_score == report2.risk_score
