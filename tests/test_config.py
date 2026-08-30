from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
import yaml

from src.config import (
    AIConfig,
    EnvironmentOverrides,
    NotificationConfig,
    RiskAnalyzerConfig,
    RuleOverride,
    StorageConfig,
    SuppressionEntry,
    ThresholdConfig,
    load_config,
)


class TestThresholdConfig:
    def test_defaults(self):
        t = ThresholdConfig()
        assert t.critical_min == 80
        assert t.high_min == 60
        assert t.medium_min == 40
        assert t.low_max == 39

    def test_from_dict(self):
        t = ThresholdConfig.from_dict({"critical_min": 70, "high_min": 50})
        assert t.critical_min == 70
        assert t.high_min == 50
        assert t.medium_min == 40

    def test_from_empty_dict(self):
        t = ThresholdConfig.from_dict({})
        assert t.critical_min == 80


class TestAIConfig:
    def test_defaults(self):
        c = AIConfig()
        assert c.enabled is True
        assert c.model_id == "amazon.nova-lite-v1:0"
        assert c.max_tokens == 2048
        assert c.max_retries == 3

    def test_from_dict(self):
        c = AIConfig.from_dict({"enabled": False, "model_id": "custom-model"})
        assert c.enabled is False
        assert c.model_id == "custom-model"


class TestRuleOverride:
    def test_disabled(self):
        r = RuleOverride.from_dict({"enabled": False})
        assert r.enabled is False
        assert r.severity is None

    def test_severity_override(self):
        r = RuleOverride.from_dict({"severity": "MEDIUM"})
        assert r.severity == "MEDIUM"
        assert r.enabled is True


class TestSuppressionEntry:
    def test_from_dict(self):
        s = SuppressionEntry.from_dict({
            "rule_id": "SG-001",
            "resource_pattern": "DevSG",
            "reason": "Accepted risk",
            "expires": "2099-12-31T00:00:00Z",
        })
        assert s.rule_id == "SG-001"
        assert s.resource_pattern == "DevSG"
        assert s.reason == "Accepted risk"
        assert s.expires == "2099-12-31T00:00:00Z"

    def test_defaults(self):
        s = SuppressionEntry.from_dict({"rule_id": "IAM-001"})
        assert s.resource_pattern == "*"
        assert s.reason == ""
        assert s.expires == ""


class TestEnvironmentOverrides:
    def test_with_thresholds(self):
        e = EnvironmentOverrides.from_dict({
            "thresholds": {"critical_min": 70},
            "block_on_high": True,
        })
        assert e.thresholds.critical_min == 70
        assert e.block_on_high is True

    def test_with_disabled_rules(self):
        e = EnvironmentOverrides.from_dict({
            "disabled_rules": ["SG-002", "IAM-005"],
        })
        assert "SG-002" in e.rule_overrides
        assert e.rule_overrides["SG-002"].enabled is False
        assert "IAM-005" in e.rule_overrides

    def test_with_rule_overrides(self):
        e = EnvironmentOverrides.from_dict({
            "rule_overrides": {"IAM-002": {"severity": "MEDIUM"}},
        })
        assert e.rule_overrides["IAM-002"].severity == "MEDIUM"


class TestRiskAnalyzerConfig:
    def test_defaults(self):
        c = RiskAnalyzerConfig()
        assert c.thresholds.critical_min == 80
        assert c.ai.enabled is True
        assert c.suppressions == []
        assert c.rule_overrides == {}
        assert c.output_format == "rich"

    def test_from_dict_full(self):
        data = {
            "thresholds": {"critical_min": 70, "high_min": 50},
            "ai": {"enabled": False, "model_id": "my-model"},
            "disabled_rules": ["SG-003"],
            "suppressions": [
                {"rule_id": "SG-001", "resource_pattern": "DevSG", "reason": "test"},
            ],
            "environments": {
                "production": {
                    "block_on_high": True,
                    "thresholds": {"critical_min": 65},
                },
            },
            "output_format": "json",
        }
        c = RiskAnalyzerConfig.from_dict(data)
        assert c.thresholds.critical_min == 70
        assert c.ai.enabled is False
        assert c.ai.model_id == "my-model"
        assert c.rule_overrides["SG-003"].enabled is False
        assert len(c.suppressions) == 1
        assert c.suppressions[0].rule_id == "SG-001"
        assert "production" in c.environments
        assert c.environments["production"].block_on_high is True
        assert c.output_format == "json"

    def test_from_empty_dict(self):
        c = RiskAnalyzerConfig.from_dict({})
        assert c.thresholds.critical_min == 80
        assert c.ai.enabled is True

    def test_for_environment_existing(self):
        c = RiskAnalyzerConfig.from_dict({
            "environments": {
                "production": {
                    "thresholds": {"critical_min": 65},
                    "rule_overrides": {"IAM-002": {"severity": "MEDIUM"}},
                },
            },
        })
        prod = c.for_environment("production")
        assert prod.thresholds.critical_min == 65
        assert prod.rule_overrides["IAM-002"].severity == "MEDIUM"

    def test_for_environment_nonexistent(self):
        c = RiskAnalyzerConfig()
        same = c.for_environment("staging")
        assert same is c

    def test_is_rule_enabled(self):
        c = RiskAnalyzerConfig.from_dict({
            "disabled_rules": ["SG-003"],
        })
        assert c.is_rule_enabled("SG-003") is False
        assert c.is_rule_enabled("SG-001") is True
        assert c.is_rule_enabled("NONEXISTENT") is True

    def test_is_suppressed_wildcard(self):
        c = RiskAnalyzerConfig.from_dict({
            "suppressions": [
                {"rule_id": "SG-001", "resource_pattern": "*", "reason": "global"},
            ],
        })
        assert c.is_suppressed("SG-001", "AnyResource") is True
        assert c.is_suppressed("SG-002", "AnyResource") is False

    def test_is_suppressed_pattern_match(self):
        c = RiskAnalyzerConfig.from_dict({
            "suppressions": [
                {"rule_id": "SG-001", "resource_pattern": "DevSG", "reason": "dev ok"},
            ],
        })
        assert c.is_suppressed("SG-001", "DevSG") is True
        assert c.is_suppressed("SG-001", "MyDevSGGroup") is True
        assert c.is_suppressed("SG-001", "ProdSG") is False

    def test_is_suppressed_expired(self):
        c = RiskAnalyzerConfig.from_dict({
            "suppressions": [
                {
                    "rule_id": "SG-001",
                    "resource_pattern": "*",
                    "reason": "expired",
                    "expires": "2020-01-01T00:00:00Z",
                },
            ],
        })
        assert c.is_suppressed("SG-001", "AnyResource") is False

    def test_is_suppressed_not_expired(self):
        c = RiskAnalyzerConfig.from_dict({
            "suppressions": [
                {
                    "rule_id": "SG-001",
                    "resource_pattern": "*",
                    "reason": "still valid",
                    "expires": "2099-12-31T00:00:00Z",
                },
            ],
        })
        assert c.is_suppressed("SG-001", "AnyResource") is True


class TestLoadConfig:
    def test_load_from_explicit_path(self, tmp_path):
        config_file = tmp_path / "test-config.yaml"
        config_file.write_text(yaml.dump({
            "thresholds": {"critical_min": 75},
            "ai": {"enabled": False},
        }))
        c = load_config(str(config_file))
        assert c.thresholds.critical_min == 75
        assert c.ai.enabled is False

    def test_load_missing_explicit_path(self):
        c = load_config("/nonexistent/path/config.yaml")
        assert c.thresholds.critical_min == 80

    def test_load_no_path_no_default(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("RISK_ANALYZER_CONFIG", raising=False)
        c = load_config()
        assert c.thresholds.critical_min == 80

    def test_load_from_env_var(self, tmp_path, monkeypatch):
        config_file = tmp_path / "env-config.yaml"
        config_file.write_text(yaml.dump({"ai": {"enabled": False}}))
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        monkeypatch.chdir(subdir)
        monkeypatch.setenv("RISK_ANALYZER_CONFIG", str(config_file))
        c = load_config()
        assert c.ai.enabled is False

    def test_load_empty_yaml(self, tmp_path):
        config_file = tmp_path / "empty.yaml"
        config_file.write_text("")
        c = load_config(str(config_file))
        assert c.thresholds.critical_min == 80
