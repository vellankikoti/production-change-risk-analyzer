from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATHS = [
    "risk-analyzer.yaml",
    "risk-analyzer.yml",
    ".risk-analyzer.yaml",
    ".risk-analyzer.yml",
]


@dataclass
class ThresholdConfig:
    critical_min: int = 80
    high_min: int = 60
    medium_min: int = 40
    low_max: int = 39

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ThresholdConfig:
        return cls(
            critical_min=data.get("critical_min", 80),
            high_min=data.get("high_min", 60),
            medium_min=data.get("medium_min", 40),
            low_max=data.get("low_max", 39),
        )


@dataclass
class AIConfig:
    enabled: bool = True
    model_id: str = "amazon.nova-lite-v1:0"
    max_tokens: int = 2048
    max_retries: int = 3

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AIConfig:
        return cls(
            enabled=data.get("enabled", True),
            model_id=data.get("model_id", "amazon.nova-lite-v1:0"),
            max_tokens=data.get("max_tokens", 2048),
            max_retries=data.get("max_retries", 3),
        )


@dataclass
class NotificationConfig:
    enabled: bool = False
    sns_topic_arn: str = ""
    notify_on: list[str] = field(default_factory=lambda: ["CRITICAL", "HIGH"])

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> NotificationConfig:
        return cls(
            enabled=data.get("enabled", False),
            sns_topic_arn=data.get("sns_topic_arn", ""),
            notify_on=data.get("notify_on", ["CRITICAL", "HIGH"]),
        )


@dataclass
class StorageConfig:
    dynamodb_table: str = ""
    s3_bucket: str = ""
    save_reports: bool = False
    save_evidence: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StorageConfig:
        return cls(
            dynamodb_table=data.get("dynamodb_table", ""),
            s3_bucket=data.get("s3_bucket", ""),
            save_reports=data.get("save_reports", False),
            save_evidence=data.get("save_evidence", False),
        )


@dataclass
class RuleOverride:
    severity: str | None = None
    enabled: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RuleOverride:
        return cls(
            severity=data.get("severity"),
            enabled=data.get("enabled", True),
        )


@dataclass
class SuppressionEntry:
    rule_id: str
    resource_pattern: str = "*"
    reason: str = ""
    expires: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SuppressionEntry:
        return cls(
            rule_id=data["rule_id"],
            resource_pattern=data.get("resource_pattern", "*"),
            reason=data.get("reason", ""),
            expires=data.get("expires", ""),
        )


@dataclass
class EnvironmentOverrides:
    thresholds: ThresholdConfig | None = None
    rule_overrides: dict[str, RuleOverride] = field(default_factory=dict)
    block_on_high: bool = False
    disabled_rules: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EnvironmentOverrides:
        thresholds = ThresholdConfig.from_dict(data["thresholds"]) if "thresholds" in data else None
        rule_overrides = {k: RuleOverride.from_dict(v) for k, v in data.get("rule_overrides", {}).items()}
        for rule_id in data.get("disabled_rules", []):
            rule_overrides[rule_id] = RuleOverride(enabled=False)
        return cls(
            thresholds=thresholds,
            rule_overrides=rule_overrides,
            block_on_high=data.get("block_on_high", False),
            disabled_rules=data.get("disabled_rules", []),
        )


@dataclass
class RiskAnalyzerConfig:
    thresholds: ThresholdConfig = field(default_factory=ThresholdConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    notifications: NotificationConfig = field(default_factory=NotificationConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    rule_overrides: dict[str, RuleOverride] = field(default_factory=dict)
    suppressions: list[SuppressionEntry] = field(default_factory=list)
    environments: dict[str, EnvironmentOverrides] = field(default_factory=dict)
    output_format: str = "rich"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RiskAnalyzerConfig:
        rule_overrides = {k: RuleOverride.from_dict(v) for k, v in data.get("rule_overrides", {}).items()}
        for rule_id in data.get("disabled_rules", []):
            rule_overrides[rule_id] = RuleOverride(enabled=False)
        return cls(
            thresholds=ThresholdConfig.from_dict(data.get("thresholds", {})),
            ai=AIConfig.from_dict(data.get("ai", {})),
            notifications=NotificationConfig.from_dict(data.get("notifications", {})),
            storage=StorageConfig.from_dict(data.get("storage", {})),
            rule_overrides=rule_overrides,
            suppressions=[SuppressionEntry.from_dict(s) for s in data.get("suppressions", [])],
            environments={k: EnvironmentOverrides.from_dict(v) for k, v in data.get("environments", {}).items()},
            output_format=data.get("output_format", "rich"),
        )

    def for_environment(self, environment: str) -> RiskAnalyzerConfig:
        """Return a config with environment-specific overrides applied."""
        if environment not in self.environments:
            return self
        env = self.environments[environment]
        import copy
        cfg = copy.deepcopy(self)
        if env.thresholds:
            cfg.thresholds = env.thresholds
        for rule_id, override in env.rule_overrides.items():
            cfg.rule_overrides[rule_id] = override
        return cfg

    def is_suppressed(self, rule_id: str, resource: str) -> bool:
        """Check if a finding should be suppressed."""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        for s in self.suppressions:
            if s.rule_id != rule_id:
                continue
            if s.expires and s.expires < now:
                continue
            if s.resource_pattern == "*" or s.resource_pattern in resource:
                return True
        return False

    def is_rule_enabled(self, rule_id: str) -> bool:
        override = self.rule_overrides.get(rule_id)
        if override is not None:
            return override.enabled
        return True


def load_config(path: str | None = None) -> RiskAnalyzerConfig:
    if path:
        p = Path(path)
        if p.exists():
            with open(p) as f:
                data = yaml.safe_load(f) or {}
            logger.info("Loaded config from %s", p)
            return RiskAnalyzerConfig.from_dict(data)
        logger.warning("Config file not found: %s — using defaults", path)
        return RiskAnalyzerConfig()

    for candidate in DEFAULT_CONFIG_PATHS:
        p = Path(candidate)
        if p.exists():
            with open(p) as f:
                data = yaml.safe_load(f) or {}
            logger.info("Loaded config from %s", p)
            return RiskAnalyzerConfig.from_dict(data)

    env_path = os.environ.get("RISK_ANALYZER_CONFIG")
    if env_path:
        p = Path(env_path)
        if p.exists():
            with open(p) as f:
                data = yaml.safe_load(f) or {}
            logger.info("Loaded config from %s (via env)", p)
            return RiskAnalyzerConfig.from_dict(data)

    return RiskAnalyzerConfig()
