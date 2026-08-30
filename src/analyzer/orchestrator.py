from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone

from src.ai.bedrock_analyzer import BedrockAnalyzer
from src.analyzer.blast_radius import compute_blast_radius
from src.analyzer.rollback import assess_rollback
from src.analyzer.scoring import compute_score_breakdown
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
from src.parser.changeset import is_changeset, parse_changeset
from src.parser.cloudformation import diff_templates, parse_single_template, parse_template
from src.parser.terraform import is_terraform_plan, parse_terraform_plan
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


def _determine_decision(
    findings: list[RuleFinding],
    score: int,
    config: RiskAnalyzerConfig | None = None,
    block_on_high: bool = False,
) -> tuple[RiskLevel, Decision, list[str]]:
    """Determine risk level and decision from findings and the category-based score."""
    if not findings:
        return RiskLevel.LOW, Decision.APPROVE, ["No rule violations detected."]

    thresholds = config.thresholds if config else None
    block_threshold = thresholds.critical_min if thresholds else 80
    review_threshold = thresholds.medium_min if thresholds else 40

    severities = {f.severity for f in findings}
    reasons = [f.finding for f in findings]

    if Severity.CRITICAL in severities:
        risk_level = RiskLevel.CRITICAL
    elif Severity.HIGH in severities:
        risk_level = RiskLevel.HIGH
    elif Severity.MEDIUM in severities:
        risk_level = RiskLevel.MEDIUM
    else:
        risk_level = RiskLevel.LOW

    if score >= block_threshold or Severity.CRITICAL in severities:
        decision = Decision.BLOCK
    elif score >= review_threshold or (Severity.HIGH in severities and not block_on_high):
        decision = Decision.REVIEW
    elif Severity.HIGH in severities and block_on_high:
        decision = Decision.BLOCK
    else:
        decision = Decision.APPROVE

    return risk_level, decision, reasons


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

    def _parse_source(
        self,
        after_template: str,
        before_template: str | None,
        source: str,
    ) -> tuple[list, dict, dict | None]:
        """Route to the right parser based on source type. Returns (changes, metadata, parsed_template_or_None)."""
        metadata: dict = {}
        parsed_template = None

        if source == "terraform" or (source == "auto" and is_terraform_plan(after_template)):
            changes = parse_terraform_plan(after_template)
            metadata["source"] = "terraform"
        elif source == "changeset" or (source == "auto" and is_changeset(after_template)):
            changes, cs_meta = parse_changeset(after_template)
            metadata["source"] = "changeset"
            metadata.update(cs_meta)
        else:
            parsed_template = parse_template(after_template)
            if before_template:
                before_parsed = parse_template(before_template)
                changes = diff_templates(before_parsed, parsed_template)
            else:
                changes = parse_single_template(parsed_template)
            metadata["source"] = "cloudformation"
            metadata["has_before"] = before_template is not None

        metadata["total_resources"] = len(changes)
        return changes, metadata, parsed_template

    def analyze(
        self,
        after_template: str,
        before_template: str | None = None,
        environment: str = "development",
        source: str = "auto",
    ) -> RiskReport:
        start_time = time.monotonic()
        changes, source_metadata, parsed_template = self._parse_source(after_template, before_template, source)

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
            metadata=source_metadata,
        )

        score_breakdown = compute_score_breakdown(findings)
        risk_score = score_breakdown.total_score

        risk_level, decision, reasons = _determine_decision(
            findings, risk_score, config=env_config, block_on_high=block_on_high,
        )

        score_breakdown.decision = decision.value

        ai_analysis: AIAnalysis
        if self.use_ai and self._analyzer and findings:
            ai_analysis = self._analyzer.analyze(evidence)
        else:
            ai_analysis = AIAnalysis.empty()

        blast_radius = compute_blast_radius(parsed_template, changes) if parsed_template else None

        rollback = assess_rollback(changes)

        report = RiskReport(
            change_id=evidence.change_id,
            timestamp=evidence.timestamp,
            risk_level=risk_level,
            risk_score=risk_score,
            decision=decision,
            evidence=evidence,
            ai_analysis=ai_analysis,
            reasons=reasons,
            score_breakdown=score_breakdown,
            blast_radius=blast_radius,
            rollback_risk=rollback,
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
