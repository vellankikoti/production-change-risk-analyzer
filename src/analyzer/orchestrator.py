from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone

from src.ai.bedrock_analyzer import BedrockAnalyzer
from src.config import RiskAnalyzerConfig, load_config

logger = logging.getLogger(__name__)
from src.models.schemas import (
    AIAnalysis,
    Decision,
    EvidencePackage,
    RiskLevel,
    RiskReport,
    RuleFinding,
    Severity,
)
from src.parser.cloudformation import diff_templates, parse_single_template, parse_template
from src.rules.availability import get_all_availability_rules
from src.rules.base import RuleEngine
from src.rules.data import get_all_data_rules
from src.rules.encryption import get_all_encryption_rules
from src.rules.iam import get_all_iam_rules
from src.rules.logging import get_all_logging_rules
from src.rules.network import get_all_network_rules
from src.rules.security_group import get_all_sg_rules


def _build_rule_engine() -> RuleEngine:
    engine = RuleEngine()
    engine.register_all(get_all_iam_rules())
    engine.register_all(get_all_sg_rules())
    engine.register_all(get_all_network_rules())
    engine.register_all(get_all_availability_rules())
    engine.register_all(get_all_encryption_rules())
    engine.register_all(get_all_logging_rules())
    engine.register_all(get_all_data_rules())
    return engine


def _compute_risk(
    findings: list[RuleFinding],
    config: RiskAnalyzerConfig | None = None,
    block_on_high: bool = False,
) -> tuple[RiskLevel, int, Decision, list[str]]:
    if not findings:
        return RiskLevel.LOW, 5, Decision.APPROVE, ["No rule violations detected."]

    thresholds = config.thresholds if config else None
    critical_min = thresholds.critical_min if thresholds else 80
    high_min = thresholds.high_min if thresholds else 60
    medium_min = thresholds.medium_min if thresholds else 40

    severities = {f.severity for f in findings}
    reasons = [f.finding for f in findings]

    if Severity.CRITICAL in severities:
        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        score = min(100, critical_min + critical_count * 5)
        return RiskLevel.CRITICAL, score, Decision.BLOCK, reasons

    if Severity.HIGH in severities:
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        score = min(critical_min - 1, high_min + high_count * 5)
        decision = Decision.BLOCK if block_on_high else Decision.REVIEW
        return RiskLevel.HIGH, score, decision, reasons

    if Severity.MEDIUM in severities:
        medium_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        score = min(high_min - 1, medium_min + medium_count * 5)
        return RiskLevel.MEDIUM, score, Decision.REVIEW, reasons

    low_count = sum(1 for f in findings if f.severity == Severity.LOW)
    score = min(medium_min - 1, 10 + low_count * 5)
    return RiskLevel.LOW, score, Decision.APPROVE, reasons


class ChangeAnalyzer:
    def __init__(
        self,
        use_ai: bool = True,
        model_id: str | None = None,
        emit_metrics: bool = True,
        config: RiskAnalyzerConfig | None = None,
    ) -> None:
        self.config = config
        self.engine = _build_rule_engine()
        self.use_ai = use_ai
        self.emit_metrics = emit_metrics
        effective_model = model_id or (config.ai.model_id if config else None)
        self._analyzer = BedrockAnalyzer(model_id=effective_model) if use_ai else None
        self._metrics = None
        if emit_metrics:
            try:
                from src.observability.metrics import RiskMetrics
                self._metrics = RiskMetrics()
            except Exception:
                logger.debug("CloudWatch metrics unavailable — skipping")

    def analyze(
        self,
        after_template: str,
        before_template: str | None = None,
        environment: str = "development",
    ) -> RiskReport:
        start_time = time.monotonic()
        after_parsed = parse_template(after_template)

        if before_template:
            before_parsed = parse_template(before_template)
            changes = diff_templates(before_parsed, after_parsed)
        else:
            changes = parse_single_template(after_parsed)

        all_findings = self.engine.evaluate(changes)

        env_config = None
        block_on_high = False
        if self.config:
            env_config = self.config.for_environment(environment)
            if environment in self.config.environments:
                block_on_high = self.config.environments[environment].block_on_high

        findings = []
        for f in all_findings:
            cfg = env_config or self.config
            if cfg:
                if not cfg.is_rule_enabled(f.rule_id):
                    logger.debug("Rule %s disabled by config — skipping", f.rule_id)
                    continue
                if cfg.is_suppressed(f.rule_id, f.resource):
                    logger.debug("Finding %s on %s suppressed by config", f.rule_id, f.resource)
                    continue
                override = cfg.rule_overrides.get(f.rule_id)
                if override and override.severity:
                    f = RuleFinding(
                        rule_id=f.rule_id,
                        severity=Severity(override.severity),
                        resource=f.resource,
                        finding=f.finding,
                        evidence=f.evidence,
                        remediation=f.remediation,
                        compliance=f.compliance,
                    )
            findings.append(f)

        evidence = EvidencePackage.create(
            environment=environment,
            changes=changes,
            findings=findings,
            metadata={"has_before": before_template is not None, "total_resources": len(changes)},
        )

        risk_level, risk_score, decision, reasons = _compute_risk(
            findings, config=env_config, block_on_high=block_on_high,
        )

        ai_analysis: AIAnalysis
        if self.use_ai and self._analyzer and findings:
            ai_analysis = self._analyzer.analyze(evidence)
        else:
            ai_analysis = AIAnalysis.empty()

        report = RiskReport(
            change_id=evidence.change_id,
            timestamp=evidence.timestamp,
            risk_level=risk_level,
            risk_score=risk_score,
            decision=decision,
            evidence=evidence,
            ai_analysis=ai_analysis,
            reasons=reasons,
        )

        duration_ms = (time.monotonic() - start_time) * 1000
        if self._metrics:
            try:
                self._metrics.record_analysis(
                    change_id=report.change_id,
                    risk_level=risk_level.value,
                    risk_score=risk_score,
                    decision=decision.value,
                    environment=environment,
                    finding_count=len(findings),
                    duration_ms=duration_ms,
                    ai_used=self.use_ai and bool(findings),
                )
                self._metrics.record_rule_findings(
                    [f.to_dict() for f in findings],
                    environment=environment,
                )
            except Exception:
                logger.debug("Failed to emit metrics — non-critical")

        return report
