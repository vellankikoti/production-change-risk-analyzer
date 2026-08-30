from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone

from src.ai.bedrock_analyzer import BedrockAnalyzer

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
from src.rules.iam import get_all_iam_rules
from src.rules.network import get_all_network_rules
from src.rules.security_group import get_all_sg_rules


def _build_rule_engine() -> RuleEngine:
    engine = RuleEngine()
    engine.register_all(get_all_iam_rules())
    engine.register_all(get_all_sg_rules())
    engine.register_all(get_all_network_rules())
    engine.register_all(get_all_availability_rules())
    return engine


def _compute_risk(findings: list[RuleFinding]) -> tuple[RiskLevel, int, Decision, list[str]]:
    if not findings:
        return RiskLevel.LOW, 5, Decision.APPROVE, ["No rule violations detected."]

    severities = {f.severity for f in findings}
    reasons = [f.finding for f in findings]

    if Severity.CRITICAL in severities:
        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        score = min(100, 80 + critical_count * 5)
        return RiskLevel.CRITICAL, score, Decision.BLOCK, reasons

    if Severity.HIGH in severities:
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        score = min(79, 60 + high_count * 5)
        return RiskLevel.HIGH, score, Decision.REVIEW, reasons

    if Severity.MEDIUM in severities:
        medium_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        score = min(59, 40 + medium_count * 5)
        return RiskLevel.MEDIUM, score, Decision.REVIEW, reasons

    low_count = sum(1 for f in findings if f.severity == Severity.LOW)
    score = min(39, 10 + low_count * 5)
    return RiskLevel.LOW, score, Decision.APPROVE, reasons


class ChangeAnalyzer:
    def __init__(self, use_ai: bool = True, model_id: str | None = None, emit_metrics: bool = True) -> None:
        self.engine = _build_rule_engine()
        self.use_ai = use_ai
        self.emit_metrics = emit_metrics
        self._analyzer = BedrockAnalyzer(model_id=model_id) if use_ai else None
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

        findings = self.engine.evaluate(changes)

        evidence = EvidencePackage.create(
            environment=environment,
            changes=changes,
            findings=findings,
            metadata={"has_before": before_template is not None, "total_resources": len(changes)},
        )

        risk_level, risk_score, decision, reasons = _compute_risk(findings)

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
